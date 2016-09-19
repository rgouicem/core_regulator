#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/cpu.h>
#include <linux/percpu.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/cdev.h>
#include <asm-generic/delay.h>
//#include <asm-generic/uaccess.h>
#include <linux/spinlock.h>

#ifndef NO_PMU
#include <linux/perf_event.h>
#else
#include <asm-generic/uaccess.h>
#endif

#include "ioctl.h"

MODULE_DESCRIPTION("Core-level regulator");
MODULE_AUTHOR("Redha Gouicem <redha.gouicem@gmail.com>");
MODULE_LICENSE("GPL");

#define PROCFS_DIRNAME "core_regulator"
#define STOP_DURATION_US 1000000
#define DEFAULT_PERIOD_US 1000
#define DEFAULT_NR_SAMPLES 20000
#define DEFAULT_ADAPTIVE_THRESHOLD 50
#define DEFAULT_ADAPTIVE_STEP 5


/****************************************
 * Type definitions
 ***************************************/
enum state {UNKNOWN, RUNNING, PROFILING, CONTROLING,
	    SLOWING_DOWN, SLOWING_DOWN_PROF, STOPPED};
enum event {NONE, REGISTER_APP, START_APP, STOP_APP, UNREGISTER_APP,
	    PROF, RUN, SLOW, STOP, SLOW_INT};

struct sample {
	u64 write;                          /* write count for this period */
	u64 miss;                           /* miss count for this period */
	struct timespec timestamp;          /* sample timestamp */
	enum event event;                   /* event */
	int event_value;                    /* value associated with event */
};

struct core {
	unsigned int id;                    /* core ID */
#ifndef NO_PMU
	struct perf_event *miss;            /* pmc: LLC load misses */
	struct perf_event *write;           /* pmc: LLC write misses */
#endif
	struct hrtimer timer;               /* hrtimer */
	void (*function)(void);             /* timer callback function */
	ktime_t period;                     /* timer period */
	unsigned int slow_rate;             /* slowdown rate (0-100) */
	/* struct hrtimer slowdown_timer;      /\* timer used for HLT slowdown *\/ */
	/* volatile bool stop_hlt;             /\* stop HLT loop for slowdown *\/ */
	struct sample *samples;             /* samples */
	unsigned int cur_id;                /* current sample ID (write) */
	unsigned int read_id;               /* current sample ID (read) */
	spinlock_t samples_lock;            /* spinlock for writes in samples */
	struct proc_dir_entry *proc_entry;  /* procfs entry */
	enum state state;                   /* core's current state */
};

struct process {
	pid_t pid;                          /* process id */
	struct core *core;                  /* core where process runs */
	u64 nr_runs;                        /* number of times process ran */
	enum cmd_type type;                 /* type of check (deadline/value) */
	enum cmd_cmp cmp;                   /* comparison (keep above/under) */
	union ioctl_data value;             /* threshold to compare (deadline/value) */
	struct timespec last_start;         /* time on start (for deadline only) */
	bool slow_enabled;                  /* true if mecanism has started */
};


/****************************************
 * Function prototypes
 ***************************************/
static int proc_open(struct inode *inode, struct file *file);
static void *proc_start(struct seq_file *m, loff_t *pos);
static void proc_stop(struct seq_file *m, void *v);
static void *proc_next(struct seq_file *m, void *v, loff_t *pos);
static int proc_show(struct seq_file *m, void *v);
static void profile(void);
static void stop(void);
static void slowdown(void);
static void slowdown_prof(void);
static void start_hrtimer(void *arg);
static void cancel_hrtimer(void *arg);
static void add_event(void *arg);


/****************************************
 * Global variables
 ***************************************/
static struct core __percpu *core;
static unsigned int period = DEFAULT_PERIOD_US;      /* sampling period in useconds */
static ktime_t kt_period;                            /* period in a ktime_t */
static unsigned int nr_samples = DEFAULT_NR_SAMPLES; /* max number of stored samples */
static struct proc_dir_entry *proc_dir;              /* procfs directory */
static struct file_operations fops_seq = {           /* procfs data structures */
	.owner   = THIS_MODULE,
	.open    = proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};
static struct seq_operations seqops = {
	.start = proc_start,
	.next  = proc_next,
	.stop  = proc_stop,
	.show  = proc_show
};
static char *info_buffer;
static struct file_operations fops_info;
static struct file_operations fops_ctrl;
/* static struct cdev *device;                /\* device for ioctl *\/ */
static int dev_major;                      /* device major number */
static struct file_operations fops_ioctl;  /* fops for ioctl */
static struct process rt_proc;             /* process that has high priority */
static unsigned int adaptive_threshold = DEFAULT_ADAPTIVE_THRESHOLD;
static unsigned int adaptive_step = DEFAULT_ADAPTIVE_STEP;


/****************************************
 * Module parameters
 ***************************************/
module_param(period, uint, 0444);
MODULE_PARM_DESC(period, "Sampling period in usec \
(default: 100)");
module_param(nr_samples, uint, 0444);
MODULE_PARM_DESC(nr_samples, "Maximum number of samples stored in memory \
(default: 100000)");
module_param(adaptive_threshold, uint, 0444);
MODULE_PARM_DESC(adaptive_threshold, "Slowdown applied the first time overhead \
is detected (default: 50)");
module_param(adaptive_step, uint, 0444);
MODULE_PARM_DESC(adaptive_step, "Step used when changing slowdown \
(default: 5)");


/****************************************
 * Code
 ***************************************/

#define state_to_str(state)						\
	(state) == RUNNING ? "RUNNING" :				\
		(state) == PROFILING ? "PROFILING" :			\
		(state) == CONTROLING ? "CONTROLING" :			\
		(state) == SLOWING_DOWN ? "SLOWING_DOWN" :		\
		(state) == SLOWING_DOWN_PROF ? "SLOWING_DOWN_PROF" :	\
		(state) == STOPPED ? "STOPPED" :			\
		"UNKNOWN"

#define str_to_state(str)						      \
	strcmp((str), "RUNNING") == 0 ? RUNNING :			      \
		strcmp((str), "PROFILING") == 0 ? PROFILING :		      \
		strcmp((str), "CONTROLING") == 0 ? CONTROLING :		      \
		strcmp((str), "SLOWING_DOWN") == 0 ? SLOWING_DOWN :	      \
		strcmp((str), "SLOWING_DOWN_PROF") == 0 ? SLOWING_DOWN_PROF : \
		strcmp((str), "STOPPED") == 0 ? STOPPED :		      \
		UNKNOWN

#define event_to_str(event)					\
	(event) == REGISTER_APP ? "REGISTER_APP" :		\
		(event) == START_APP ? "START_APP" :		\
		(event) == STOP_APP ? "STOP_APP" :		\
		(event) == UNREGISTER_APP ? "UNREGISTER_APP" :	\
		(event) == PROF ? "PROF" :			\
		(event) == RUN ? "RUN" :			\
		(event) == SLOW ? "SLOW " :			\
		(event) == SLOW_INT ? "SLOW_INT" :		\
		(event) == STOP ? "STOP" :			\
		""

#define str_to_event(str)						\
	strcmp((str), "REGISTER_APP") == 0 ? REGISTER_APP :		\
		strcmp((str), "START_APP") == 0 ? START_APP :		\
		strcmp((str), "STOP_APP") == 0 ? STOP_APP :		\
		strcmp((str), "UNREGISTER_APP") == 0 ? UNREGISTER_APP :	\
		strcmp((str), "PROF") == 0 ? PROF :			\
		strcmp((str), "RUN") == 0 ? RUN :			\
		strcmp((str), "SLOW") == 0 ? SLOW :			\
		strcmp((str), "STOP") == 0 ? STOP :			\
		NONE

static int proc_open(struct inode *inode, struct file *file)
{
	int ret;
	unsigned long id;
	struct seq_file *sf;

	ret = seq_open(file, &seqops);
	id = file->f_path.dentry->d_iname[4] - '0';
	sf = (struct seq_file *) (file->private_data);
	sf->private = (void *) id;

	return ret;
}

static void *proc_start(struct seq_file *m, loff_t *pos)
{
	unsigned long id;
	struct core *c;

	if (*pos == 0)
		return SEQ_START_TOKEN;

	id = (unsigned long) m->private;
	c = per_cpu_ptr(core, id);

	if (c->cur_id == c->read_id)
		return NULL;

	return &(c->samples[c->read_id]);
}

static void proc_stop(struct seq_file *m, void *v)
{
}

static void *proc_next(struct seq_file *m, void *v, loff_t *pos)
{
	unsigned long id;
	struct core *c;

	id = (unsigned long) m->private;
	c = per_cpu_ptr(core, id);

	*pos = *pos + 1;
	if (likely(*pos != 1)) {
		c->read_id++;
		if (c->read_id >= nr_samples)
			c->read_id = 0;
	}

	if (unlikely(c->read_id == c->cur_id))
		return NULL;
	
	return &(c->samples[c->read_id]);
}

static int proc_show(struct seq_file *m, void *v)
{
	struct sample *s;

	if (unlikely(v == SEQ_START_TOKEN)) {
#ifdef CORE2QUAD
		seq_printf(m, "timestamp ; l2_miss ; l1_miss ; event\n");
#else
		seq_printf(m, "timestamp ; write ; miss ; event\n");
#endif
		return 0;
	}

	s = (struct sample *) v;
	if (s->event == SLOW || s->event == SLOW_INT ||
	    s->event == REGISTER_APP) {
		seq_printf(m, "%ld.%09ld ; %llu ; %llu ; %s %d\n",
			   s->timestamp.tv_sec, s->timestamp.tv_nsec,
			   s->write, s->miss,
			   event_to_str(s->event), s->event_value);
	} else {
		seq_printf(m, "%ld.%09ld ; %llu ; %llu ; %s\n",
			   s->timestamp.tv_sec, s->timestamp.tv_nsec,
			   s->write, s->miss,
			   event_to_str(s->event));
	}

	return 0;
}

static ssize_t read_info_proc(struct file *file, char __user *buffer,
			      size_t count, loff_t *offset)
{
	int cpu, len = 0;
	struct core *c;

	get_online_cpus();
	for_each_online_cpu(cpu) {
		c = per_cpu_ptr(core, cpu);
		len += sprintf(info_buffer + len, "core%d: %s",
			       c->id, state_to_str(c->state));
		if (c->state == SLOWING_DOWN)
			len += sprintf(info_buffer + len, " %u",
				       c->slow_rate);
		len += sprintf(info_buffer + len, "\n");
	}
	put_online_cpus();

	return simple_read_from_buffer(buffer, count, offset, info_buffer,
				       len);
}

void print_cpumask(cpumask_t *mask)
{
	int i;
	char str[nr_cpu_ids + 1];

	for (i = nr_cpu_ids - 1; i >= 0; i--) {
		str[i] = cpumask_test_cpu(nr_cpu_ids - 1 - i, mask) ? '1' : '0';
	}
	str[i] = '\0';
	pr_debug("%s\n", str);
}

static ssize_t write_ctrl_proc(struct file *file, const char __user *buffer,
			       size_t count, loff_t *offset)
{
	int ret, cpu, err;
	char *kbuf, *cpumask_buf;
	int cpumask_len = 10;
	struct core *c;
	cpumask_t mask;
	unsigned int slow_rate, str_padding;
	struct sample s;
	bool prof;
	
	kbuf = kzalloc(count, GFP_KERNEL);
	cpumask_buf = kzalloc(10, GFP_KERNEL);
	if (kbuf == NULL || cpumask_buf == NULL)
		return -EFAULT;

	ret = simple_write_to_buffer(kbuf, count, offset, buffer, count);
	if (IS_ERR_VALUE(ret)) {
		goto err;
	}

	pr_debug("procfs command: '%s'\n", kbuf);
	
	if (strncmp(kbuf, "profile ", strlen("profile ")) == 0) {
		err = cpumask_parse_user(buffer + strlen("profile "), cpumask_len, &mask);
		if (IS_ERR_VALUE(err)) {
			ret = err;
			pr_debug("cpumask_parse failed: '%s'\n",
				 kbuf + strlen("profile "));
			goto err;
		}
		get_online_cpus();
		for_each_cpu_and(cpu, cpu_online_mask, &mask) {
			c = per_cpu_ptr(core, cpu);
			c->function = profile;
			c->period   = kt_period;
			s.miss  = 0;
			s.write = 0;
			s.event = PROF;
			smp_call_function_single(cpu, add_event, &s, 1);
			if (!hrtimer_active(&(c->timer))) {
				pr_debug("start timer %d\n", cpu);
			        smp_call_function_single(cpu, start_hrtimer,
							 NULL, 1);
			}
		}
		put_online_cpus();
	} else if (strncmp(kbuf, "run ", strlen("run ")) == 0) {
		err = cpumask_parse_user(buffer + strlen("run "), cpumask_len, &mask);
		if (IS_ERR_VALUE(err)) {
			ret = err;
			pr_debug("cpumask_parse failed\n");
			goto err;
		}
		get_online_cpus();
		for_each_cpu_and(cpu, cpu_online_mask, &mask) {
			c = per_cpu_ptr(core, cpu);
		        if (hrtimer_active(&(c->timer))) {
				pr_debug("cancel timer %d\n", cpu);
				smp_call_function_single(cpu, cancel_hrtimer,
							 NULL, 1);
			}
			c->function = NULL;
			c->state = RUNNING;
			s.miss  = 0;
			s.write = 0;
			s.event = RUN;
			smp_call_function_single(cpu, add_event, &s, 1);
		}
		put_online_cpus();
	} else if (strncmp(kbuf, "stop ", strlen("stop ")) == 0) {
		err = cpumask_parse_user(buffer + strlen("stop "), cpumask_len, &mask);
		if (IS_ERR_VALUE(err)) {
			ret = err;
			pr_debug("cpumask_parse failed: '%s'\n", kbuf + strlen("stop "));
			goto err;
		}
		get_online_cpus();
		for_each_cpu_and(cpu, cpu_online_mask, &mask) {
			c = per_cpu_ptr(core, cpu);
			c->function = stop;
			c->period   = ktime_set(0, STOP_DURATION_US + 50);
			s.miss  = 0;
			s.write = 0;
			s.event = STOP;
			smp_call_function_single(cpu, add_event, &s, 1);
			if (!hrtimer_active(&(c->timer))) {
				pr_debug("start timer %d\n", cpu);
			        smp_call_function_single(cpu, start_hrtimer, NULL, 1);
			}
		}
		put_online_cpus();
	} else if (strncmp(kbuf, "slow ", strlen("slow ")) == 0) {
		prof = false;
		if (strncmp(kbuf + strlen("slow "), "prof ", strlen("prof ")) == 0)
			prof = true;
		if (prof) {
			pr_debug("slow prof\n");
			ret = sscanf(kbuf, "slow prof %u", &slow_rate);
		} else {
			pr_debug("slow\n");
			ret = sscanf(kbuf, "slow %u", &slow_rate);
		}
		if (ret != 1) {
			ret = -EINVAL;
			pr_warn("wrong slow value\n");
			goto err;
		}
		if (slow_rate < 0 || slow_rate > 100) {
			ret = -EINVAL;
			pr_warn("slow value must be in 0-100\n");
			goto err;
		}
		str_padding = slow_rate < 10 ? 1 :	\
			slow_rate < 100 ? 2 : 3;
		if (prof)
			err = cpumask_parse_user(buffer + strlen("slow prof  ") + str_padding,
						 cpumask_len, &mask);
		else
			err = cpumask_parse_user(buffer + strlen("slow  ") + str_padding,
						 cpumask_len, &mask);
		if (IS_ERR_VALUE(err)) {
			ret = err;
			pr_debug("cpumask_parse failed: '%s'\n",
				 kbuf + strlen("slow "));
			goto err;
		}
		get_online_cpus();
		for_each_cpu_and(cpu, cpu_online_mask, &mask) {
			c = per_cpu_ptr(core, cpu);
			if (prof)
				c->function = slowdown_prof;
			else
				c->function = slowdown;
			c->period    = kt_period;
			c->slow_rate = slow_rate;
			s.miss  = 0;
			s.write = 0;
			s.event = SLOW;
			s.event_value = slow_rate;
			smp_call_function_single(cpu, add_event, &s, 1);
			pr_debug("slowdown delays = %u us\n",
				 (((int)ktime_to_ns(c->period) / 1000) * c->slow_rate) / 100);
			if (!hrtimer_active(&(c->timer))) {
				pr_debug("start timer %d\n", cpu);
			        smp_call_function_single(cpu, start_hrtimer,
							 NULL, 1);
			}
		}
		put_online_cpus();
	} else if (strncmp(kbuf, "", count) == 0) {
		ret = count;
		goto err;
	} else {
		pr_warn("unknown control command: '%s'\n", kbuf);
		ret = -EINVAL;
		goto err;
	}

err:
	kfree(kbuf);
	kfree(cpumask_buf);
	
	return ret;
}

static int setup_procfs(void)
{
	int cpu;
	struct core *c;
	char name[10] = "core0";
	struct proc_dir_entry *info_file, *ctrl_file;

	/* create procfs directory */
	proc_dir = proc_mkdir(PROCFS_DIRNAME, NULL);
	if (proc_dir == NULL)
		goto err;

	/* setup each core's procfs seqfile */
	get_online_cpus();
	for_each_online_cpu(cpu) {
		c = per_cpu_ptr(core, cpu);
		scnprintf(name, 10, "core%d", cpu);
		/* name[4] = '0' + cpu; */
		c->proc_entry = proc_create_data(name, 0444, proc_dir,
						 &fops_seq, NULL);
		if (c->proc_entry == NULL) {
			pr_warn("%s/%s file creation failed\n", PROCFS_DIRNAME,
				name);
		}
	}
	put_online_cpus();

	/* setup info procfile */
	info_buffer = (char *)get_zeroed_page(GFP_KERNEL);
	if (info_buffer == NULL) {
		pr_warn("%s/info file creation failed\n", PROCFS_DIRNAME);
		goto info_alloc_err;
	}
	fops_info.owner = THIS_MODULE;
	fops_info.read  = read_info_proc;
	info_file = proc_create("info", 0444, proc_dir, &fops_info);
	if (info_file == NULL) {
		pr_warn("%s/info file creation failed\n", PROCFS_DIRNAME);
		goto info_create_err;
	}
	
	/* setup ctrl procfile */
	fops_ctrl.owner = THIS_MODULE;
	fops_ctrl.write = write_ctrl_proc;
	ctrl_file = proc_create("control", 0200, proc_dir, &fops_ctrl);
	if (ctrl_file == NULL) {
		pr_warn("%s/control file creation failed\n", PROCFS_DIRNAME);
		goto ctrl_create_err;
	}

	return 0;

info_create_err:
	free_page((unsigned long)info_buffer);
info_alloc_err:
ctrl_create_err:
err:
	return -1;
}

static void cleanup_procfs(void)
{
#ifdef ARM
	int cpu;
	char name[10];

	get_online_cpus();
	for_each_online_cpu(cpu) {
		scnprintf(name, 10, "core%d", cpu);
		remove_proc_entry(name, proc_dir);
	}
	put_online_cpus();
	remove_proc_entry("info", proc_dir);
	remove_proc_entry("control", proc_dir);
	remove_proc_entry(PROCFS_DIRNAME, NULL);
#else
	proc_remove(proc_dir);
#endif
	free_page((unsigned long)info_buffer);
}

static int open_ioctl(struct inode *inode, struct file *filp)
{
	pr_debug("device opened\n");
	return 0;
}

static int release_ioctl(struct inode *inode, struct file *filp)
{
	pr_debug("device closed\n");
	return 0;
}

static inline s64 get_slow_int(int deadline, int value)
{
        s64 overhead;

	overhead = value * 100 / deadline - 100;

	return overhead;
}

static inline s64 get_slow_timespec(struct timespec deadline,
				    struct timespec value)
{
	s64 value_ns, deadline_ns, overhead;

	deadline_ns = timespec_to_ns(&deadline);
	value_ns    = timespec_to_ns(&value);
#ifdef ARM
	overhead    = (long) value_ns * 100 / (long) deadline_ns - 100;
#else
	overhead    = value_ns * 100 / deadline_ns - 100;
#endif

	return overhead;
}

static void adapt_slowdown(union ioctl_data *value)
{
	int cpu;
	struct sample s;
	struct core *c;
	struct timespec *exec;
	int val;
	s64 overhead;

	switch (rt_proc.type) {
	case VALUE:
		val = value->value;
		pr_debug("curValue=%d ; threshold=%d\n",
			 val, rt_proc.value.value);
		if (rt_proc.cmp == ABOVE) {
			overhead = get_slow_int(val, rt_proc.value.value);
		} else if (rt_proc.cmp == UNDER) {
			overhead = get_slow_int(rt_proc.value.value, val);;
		} else
			overhead = 0;
		break;
	case DEADLINE:
		exec = &(value->deadline);
		pr_debug("execTime=%lu.%09lu ; deadline=%lu.%09lu\n",
			 exec->tv_sec, exec->tv_nsec,
			 rt_proc.value.deadline.tv_sec,
			 rt_proc.value.deadline.tv_nsec);
		if (rt_proc.cmp == UNDER) {
			overhead = get_slow_timespec(rt_proc.value.deadline,
						     *exec);
		} else if (rt_proc.cmp == ABOVE) {
			overhead = get_slow_timespec(*exec,
						     rt_proc.value.deadline);
		} else
			overhead = 0;
		break;
	default:
		overhead = 0;
	}
	pr_info("%lld: overhead = %lld %% \n", rt_proc.nr_runs, overhead);

	// now that we have the overhead to apply, let's do it
	if (rt_proc.slow_enabled) {
		get_online_cpus();
		for_each_online_cpu(cpu) {
			if (cpu != rt_proc.core->id) {
				c = per_cpu_ptr(core, cpu);
				if (c->slow_rate + overhead > 95)
					c->slow_rate = 95;
				else if (c->slow_rate + overhead < 0)
					c->slow_rate = 0;
				else
					c->slow_rate += overhead;
				s.event = SLOW;
				s.event_value = c->slow_rate;
				smp_call_function_single(cpu, add_event,
							 &s, 1);
			}
		}
		put_online_cpus();
	} else {
		rt_proc.slow_enabled = true;
		get_online_cpus();
		for_each_online_cpu(cpu) {
			if (cpu != rt_proc.core->id) {
				c = per_cpu_ptr(core, cpu);
				if (overhead > 95)
					c->slow_rate = 95;
				else if (overhead < 0)
					c->slow_rate = 0;
				else
					c->slow_rate = overhead;
				c->period = kt_period;
				c->function = slowdown;
				s.event = SLOW;
				s.event_value = c->slow_rate;
				smp_call_function_single(cpu, add_event,
							 &s, 1);
				if (!hrtimer_active(&(c->timer))) {
					pr_debug("start timer %d\n",
						 cpu);
					smp_call_function_single(cpu,
								 start_hrtimer,
								 NULL,
								 1);
				}
			}
		}
		put_online_cpus();
	}
}

static long ioctl_funcs(struct file *filp, unsigned int ioctl_nr, unsigned long arg)
{
	int ret = 0;
	struct ioctl_cmd *cmd;
	union ioctl_data *data;
	struct ioctl_cmd kcmd;
	union ioctl_data kdata;
	struct timespec end;
	struct pid *pid;
	struct task_struct *task;
	struct sample s;
	struct core *c;
	s64 under_deadline;
	int cpu;

	switch (ioctl_nr) {
	case IOCTL_REGISTER:
		cmd = (struct ioctl_cmd *) arg;
		ret = copy_from_user(&kcmd, cmd,
				     sizeof(struct ioctl_cmd));
		if (ret != 0) {
			pr_warn("copy_from_user() failed: ret = %d\n", ret);
			return -1;
		}
		rt_proc.pid = kcmd.pid;
		rt_proc.type = kcmd.type;
		rt_proc.cmp = kcmd.cmp;
		rt_proc.slow_enabled = false;
		pr_debug("ioctl pid supplied: %d\n", rt_proc.pid);
		/* pr_debug("ioctl deadline supplied: %d\n", rt_proc.deadline); */
		rt_proc.nr_runs = 0;
		rt_proc.last_start = ns_to_timespec(0);
		pid = find_get_pid(rt_proc.pid);
		if (pid == NULL) {
			pr_warn("wrong pid supplied through ioctl\n");
			return -1;
		}
		task = get_pid_task(pid, PIDTYPE_PID);
		if (task == NULL) {
			pr_warn("error handling ioctl\n");
			put_pid(pid);
			return -1;
		}
		rt_proc.core = per_cpu_ptr(core, task_cpu(task));
		put_task_struct(task);
		put_pid(pid);
		s.miss  = 0;
		s.write = 0;
		s.event = REGISTER_APP;
		s.event_value = rt_proc.pid;
		smp_call_function_single(smp_processor_id(), add_event, &s, 1);
		break;
	case IOCTL_UNREGISTER:
		s.miss  = 0;
		s.write = 0;
		s.event = UNREGISTER_APP;
		s.event_value = rt_proc.pid;
		smp_call_function_single(smp_processor_id(), add_event, &s, 1);
		get_online_cpus();
		for_each_online_cpu(cpu) {
			if (cpu != rt_proc.core->id) {
				c = per_cpu_ptr(core, cpu);
				if (hrtimer_active(&(c->timer))) {
					pr_debug("cancel timer %d\n", cpu);
					smp_call_function_single(cpu, cancel_hrtimer,
								 NULL, 1);
				}
				c->function = NULL;
				c->state = RUNNING;
				s.miss  = 0;
				s.write = 0;
				s.event = RUN;
				smp_call_function_single(cpu, add_event, &s, 1);
			}
		}
		put_online_cpus();
		rt_proc.pid = 0;
		rt_proc.core = NULL;
		break;
	case IOCTL_START:
		if (rt_proc.pid < 1) {
			pr_warn("cannot use START if not registered\n");
		        return -1;
		}
		data = (union ioctl_data *) arg;
		ret = copy_from_user(&kdata, data,
				     sizeof(union ioctl_data));
		if (ret != 0) {
			pr_warn("copy_from_user() failed: ret = %d\n", ret);
			return -1;
		}
		switch (rt_proc.type) {
		case DEADLINE:
			under_deadline = ((int)timespec_to_ns(&(kdata.deadline)) * 95) / 100;
			rt_proc.value.deadline = ns_to_timespec(under_deadline);
			getnstimeofday(&(rt_proc.last_start));
			break;
		case VALUE:
			rt_proc.value = kdata;
			break;
		default:
			break;
		}
		rt_proc.nr_runs++;
		s.miss  = 0;
		s.write = 0;
		s.event = START_APP;
		smp_call_function_single(smp_processor_id(), add_event, &s, 1);
		break;
	case IOCTL_STOP:
		if (rt_proc.pid < 1) {
			pr_warn("cannot use STOP if not registered\n");
		        return -1;
		}
		data = (union ioctl_data *) arg;
		switch (rt_proc.type) {
		case DEADLINE:
			getnstimeofday(&end);
			kdata.deadline = timespec_sub(end, rt_proc.last_start);
			ret = copy_to_user(data, &kdata,
					   sizeof(union ioctl_data));
			if (ret != 0) {
				pr_warn("copy_to_user() failed: ret = %d\n",
					ret);
				return -1;
			}
			adapt_slowdown(&kdata);
			break;
		case VALUE:
			ret = copy_from_user(&kdata, data,
					     sizeof(union ioctl_data));
			if (ret != 0) {
				pr_warn("copy_from_user() failed: ret = %d\n",
					ret);
				return -1;
			}
			adapt_slowdown(&kdata);
			break;
		default:
			break;
		}
		s.miss  = 0;
		s.write = 0;
		s.event = STOP_APP;
		smp_call_function_single(smp_processor_id(), add_event, &s, 1);
		break;
	default:
		pr_warn("wrong ioctl command\n");
		ret = -1;
	}

	return ret;
}

static int setup_ioctl(void)
{
	int ret;
	unsigned int major = 225;

	fops_ioctl.owner = THIS_MODULE;
	fops_ioctl.open = open_ioctl;
	fops_ioctl.release = release_ioctl;
	fops_ioctl.unlocked_ioctl = ioctl_funcs;

	ret = __register_chrdev(major, 0, 1, IOCTL_DEVNAME, &fops_ioctl);
	if (ret < 0) {
		pr_err("device allocation failed\n");
		return ret;
	}

	dev_major = (major == 0) ? ret : major;

	pr_info("device major number = %d", dev_major);
	
	return 0;
}

static void cleanup_ioctl(void)
{
	//cdev_del(device);
	//unregister_chrdev_region(dev_major, 1);
	__unregister_chrdev(dev_major, 0, 1, IOCTL_DEVNAME);
}

#ifndef NO_PMU
static struct perf_event *init_counter(int cpu, int event_type, int event_id)
{
	long err;
	struct perf_event *event = NULL;
	struct perf_event_attr event_attr = {
		.type           = event_type,
		.config         = event_id,
		.size           = sizeof(struct perf_event_attr),
		.sample_period  = 0,
		.pinned         = 1,
		.exclude_kernel = 1,
		.disabled       = 0
	};

	event = perf_event_create_kernel_counter(&event_attr, cpu, NULL,
						 NULL, NULL);

	if (event == NULL)
		return NULL;

	if (IS_ERR(event)) {
		err = PTR_ERR(event);
		if (err == -EOPNOTSUPP)
			pr_err("CPU%d not supported\n", cpu);
		else if (err == -ENOENT)
			pr_err("CPU%d unsupported event %d\n",
				cpu, event_id);
		else
			pr_err("CPU%d error creating perf_event: %ld\n",
			       cpu, err);
		return NULL;
	}

	pr_debug("CPU%d counter enabled for event %d\n", cpu, event_id);

	return event;
}

static int init_counters(struct core *c)
{
	long err = 0;

#ifdef CORE2QUAD
	c->miss  = init_counter(c->id, PERF_TYPE_RAW, 0x712E);
#else
	int config;
	/* config   = PERF_COUNT_HW_CACHE_L1D; */
	config   = PERF_COUNT_HW_CACHE_LL;
	config  |= (PERF_COUNT_HW_CACHE_OP_READ << 8);
	config  |= (PERF_COUNT_HW_CACHE_RESULT_MISS << 16);
	c->miss  = init_counter(c->id, PERF_TYPE_HW_CACHE, config);
#endif
	if (c->miss == NULL) {
		err = -1;
		goto err;
	}
#ifdef CORE2QUAD
	c->write = init_counter(c->id, PERF_TYPE_RAW, 0x0F45);
#else
	/* config   = PERF_COUNT_HW_CACHE_L1D; */
	config   = PERF_COUNT_HW_CACHE_LL;
	config  |= (PERF_COUNT_HW_CACHE_OP_WRITE << 8);
	config  |= (PERF_COUNT_HW_CACHE_RESULT_MISS << 16);
	c->write = init_counter(c->id, PERF_TYPE_HW_CACHE, config);
#endif
	if (c->write == NULL) {
		err = -1;
		goto clean;
	}

	return 0;

clean:
	perf_event_release_kernel(c->miss);
err:
	return err;
}

static void __disable_counters(void *arg)
{
	struct core *c = this_cpu_ptr(core);
		
	if (c != NULL) {
		c->miss->pmu->stop(c->miss, PERF_EF_UPDATE);
		c->miss->pmu->del(c->miss, 0);
		c->write->pmu->stop(c->write, PERF_EF_UPDATE);
		c->write->pmu->del(c->write, 0);
	}
}

static void disable_counters(void)
{
	int cpu;
	
	get_online_cpus();
	for_each_online_cpu(cpu) {
		smp_call_function_single(cpu, __disable_counters, NULL, 1);
	}
	put_online_cpus();
}
#endif

static void slowdown_prof(void)
{
	struct core *c = this_cpu_ptr(core);
	u64 delay;

	profile();
	c->state = SLOWING_DOWN;
	delay = (((int)ktime_to_ns(c->period) / 1000) * c->slow_rate) / 100;
	//pr_debug("slowdown delay = %llu ns\n", delay);
	udelay(delay);
}

/* static enum hrtimer_restart stop_hlt(struct hrtimer *timer) */
/* { */
/* 	struct core *c = this_cpu_ptr(core); */

/* 	pr_info("stop HLT on CPU%d\n", c->id); */
/* 	c->stop_hlt = true; */

/* 	return HRTIMER_NORESTART; */
/* } */

static void slowdown(void)
{
	struct core *c = this_cpu_ptr(core);
	u64 delay;

	c->state = SLOWING_DOWN;
	delay = (((int)ktime_to_ns(c->period) / 1000) * c->slow_rate) / 100;
	//pr_debug("slowdown delay = %llu ns\n", delay);
	udelay(delay);
}

static void stop(void)
{
	struct core *c = this_cpu_ptr(core);
	u64 delay = STOP_DURATION_US;

	/* pr_debug("stop interrupt on cpu%d\n", c->id); */
	c->state = STOPPED;
	while (c->state == STOPPED && delay > 0) {
		udelay(19999);
		delay -= 19999;
	}
}

static void profile(void)
{
	struct core *c = this_cpu_ptr(core);
	unsigned long flags;

	spin_lock_irqsave(&(c->samples_lock), flags);
	c->state = PROFILING;

#ifndef NO_PMU
	c->miss->pmu->stop(c->miss, PERF_EF_UPDATE);
	c->write->pmu->stop(c->write, PERF_EF_UPDATE);
#endif

	getnstimeofday(&(c->samples[c->cur_id].timestamp));

#ifndef NO_PMU
	c->samples[c->cur_id].miss  = local64_read(&(c->miss)->count);
	c->samples[c->cur_id].write = local64_read(&(c->write)->count);
#else
	c->samples[c->cur_id].miss = c->cur_id;
	c->samples[c->cur_id].write = c->cur_id + 1;
#endif

	c->samples[c->cur_id].event = NONE;
	c->cur_id++;
	if (c->cur_id >= nr_samples)
		c->cur_id = 0;

#ifndef NO_PMU
	local64_set(&(c->miss)->count, 0);
	local64_set(&(c->write)->count, 0);

	c->miss->pmu->start(c->miss, PERF_EF_RELOAD);
	c->write->pmu->start(c->write, PERF_EF_RELOAD);
#endif

	spin_unlock_irqrestore(&(c->samples_lock), flags);
}

static void add_event(void *arg)
{
	struct core *c = this_cpu_ptr(core);
	struct sample *s = (struct sample *) arg;
	unsigned long flags;

	spin_lock_irqsave(&(c->samples_lock), flags);

	getnstimeofday(&(c->samples[c->cur_id].timestamp));
	c->samples[c->cur_id].miss        = 0;
	c->samples[c->cur_id].write       = 0;
	c->samples[c->cur_id].event       = s->event;
	c->samples[c->cur_id].event_value = s->event_value;
	/* c->cur_id = (c->cur_id + 1) % nr_samples; */
	c->cur_id++;
	if (c->cur_id >= nr_samples)
		c->cur_id = 0;

	spin_unlock_irqrestore(&(c->samples_lock), flags);
}

static enum hrtimer_restart timer_handler(struct hrtimer *timer)
{
	struct core *c = this_cpu_ptr(core);

	if (c->function != NULL) {
		hrtimer_forward_now(timer, c->period);

		c->function();

		return HRTIMER_RESTART;
	}
	return HRTIMER_NORESTART;
}

static void start_hrtimer(void *arg)
{
	struct core *c = this_cpu_ptr(core);
	hrtimer_start(&(c->timer), c->period, HRTIMER_MODE_REL_PINNED);
}

static void init_hrtimer(void *arg)
{
	struct core *c = this_cpu_ptr(core);

	hrtimer_init(&(c->timer), CLOCK_MONOTONIC_RAW,
		     HRTIMER_MODE_REL_PINNED);
	c->timer.function = timer_handler;
	/* hrtimer_init(&(c->slowdown_timer), CLOCK_MONOTONIC_RAW, */
	/* 	     HRTIMER_MODE_REL_PINNED); */
	/* c->slowdown_timer.function = stop_hlt; */
}

static void cancel_hrtimer(void *arg)
{
	struct core *c = this_cpu_ptr(core);

	hrtimer_cancel(&(c->timer));
	/* hrtimer_cancel(&(c->slowdown_timer)); */
}

static void cancel_timers(void)
{
	int cpu;
	struct core *c;

	get_online_cpus();
	for_each_online_cpu(cpu) {
		if (smp_call_function_single(cpu, cancel_hrtimer, NULL, 1) != 0) {
			pr_warn("timer cancellation failed on CPU%d\n", cpu);
		} else {
			c = per_cpu_ptr(core, cpu);
			c->state = RUNNING;
		}
	}
	put_online_cpus();
}

/* static void init_cpuidle(void *arg) */
/* { */
/* 	struct core *c = this_cpu_ptr(core); */

/* 	c->cpuidle_dev = __this_cpu_read(cpuidle_devices); */
/* 	c->cpuidle_drv = cpuidle_get_cpu_driver(c->cpuidle_dev); */
/* } */

int init_module(void)
{
	int cpu;
	long err;
	struct core *c;

	/* Convert uint period to ktime_t period */
	kt_period = ktime_set(0, 1000 * period);

	/* Initialize current rt proc */
	rt_proc.pid = 0;
	rt_proc.core = NULL;
	rt_proc.nr_runs = 0;
	memset(&(rt_proc.value), 0, sizeof(union ioctl_data));
	rt_proc.last_start = ns_to_timespec(0);

	/* Alloc data for each CPU */
	core = alloc_percpu(struct core);

	/* procfs setup */
	err = setup_procfs();
	if (err < 0) {
		pr_err("procfs setup failed: errno = %ld\n", err);
		goto clean_alloc;
	} else
		pr_debug("procfs setup complete\n");

	/* ioctl setup */
	err = setup_ioctl();
	if (err < 0) {
		pr_err("ioctl setup failed: errno = %ld\n", err);
		goto clean_procfs;
	} else
		pr_debug("ioctl setup complete\n");

	/* On each CPU, initialize counters and timers */
	get_online_cpus();
	for_each_online_cpu(cpu) {
		c              = per_cpu_ptr(core, cpu);
		c->id          = cpu;
		c->function    = NULL;
		c->period      = kt_period;
		c->slow_rate   = 0;
#ifndef NO_PMU
		c->miss        = NULL;
		c->write       = NULL;
#endif
		c->cur_id      = 0;
		c->read_id     = 0;
		c->proc_entry  = NULL;
		c->state       = UNKNOWN;
	}
	for_each_online_cpu(cpu) {
		c = per_cpu_ptr(core, cpu);

		/* Allocate memory for samples */
		c->samples = kmalloc(nr_samples * sizeof(struct sample),
				     GFP_KERNEL);
		if (c->samples == NULL) {
			err = -ENOMEM;
			goto err;
		}

		/* Initialize spinlock */
		spin_lock_init(&(c->samples_lock));

#ifndef NO_PMU
		/* Initialize counters */
		if (init_counters(c) != 0) {
			err = -EPERM;
			goto err;
		}
#endif

		/* Initialize timers */
		if (smp_call_function_single(cpu, init_hrtimer, NULL, 1) != 0) {
			pr_warn("timer initialization failed on CPU%d\n", cpu);
		}

		/* /\* Initialize cpuidle driver *\/ */
		/* if (smp_call_function_single(cpu, init_cpuidle, NULL, 1) != 0) { */
		/* 	pr_warn("cpuidle initialization failed on CPU%d\n", cpu); */
		/* } */

		c->state = RUNNING;
	}
	put_online_cpus();

	pr_info("module inserted with success\n");

	return 0;

err:
	for_each_online_cpu(cpu) {
		c = per_cpu_ptr(core, cpu);
		if (c->state != UNKNOWN) {
#ifndef NO_PMU
			if (c->miss != NULL)
				perf_event_release_kernel(c->miss);
			if (c->write != NULL)
				perf_event_release_kernel(c->write);
#endif
			if (smp_call_function_single(cpu, cancel_hrtimer, NULL, 1) != 0) {
				pr_warn("timer cancellation failed on CPU%d\n", cpu);
			}
			kfree(c->samples);
		}
	}
	put_online_cpus();

	cleanup_ioctl();
clean_procfs:
	cleanup_procfs();
clean_alloc:
	free_percpu(core);

	pr_err("module insertion failed!\n");
	
	return err;
}

void cleanup_module(void)
{
	int cpu;
	struct core *c;

	cancel_timers();
#ifndef NO_PMU
	disable_counters();
#endif

	get_online_cpus();
	for_each_online_cpu(cpu) {
		c = per_cpu_ptr(core, cpu);
		if (c != NULL) {
#ifndef NO_PMU
			perf_event_release_kernel(c->miss);
			perf_event_release_kernel(c->write);
#endif
			kfree(c->samples);
		}
	}
	put_online_cpus();

	cleanup_ioctl();

	cleanup_procfs();

	free_percpu(core);

	pr_info("module removed with success\n");
}
