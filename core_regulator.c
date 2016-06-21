#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/cpu.h>
#include <linux/percpu.h>
#include <linux/perf_event.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/timekeeping.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

MODULE_DESCRIPTION("Core-level regulator");
MODULE_AUTHOR("Redha Gouicem <redha.gouicem@gmail.com>");
MODULE_LICENSE("GPL");

#define PROCFS_DIRNAME "core_regulator"


/****************************************
 * Type definitions
 ***************************************/
struct sample {
	u64 write;                 /* write count for this period */
	u64 miss;                  /* miss count for this period */
	struct timespec timestamp; /* sample timestamp */
};

struct core {
	unsigned int id;                    /* core ID */
	struct perf_event *miss;            /* pmc: L1 misses */
	struct perf_event *write;           /* pmc: L1 write requests */
	struct hrtimer timer;               /* hrtimer */
	void (*function)(void);             /* timer callback function */
	struct sample *samples;             /* samples */
	unsigned int cur_id;                /* current sample ID (write) */
	unsigned int read_id;               /* current sample ID (read) */
	struct proc_dir_entry *proc_entry;  /* procfs entry */
};


/****************************************
 * Function prototypes
 ***************************************/
static int proc_open(struct inode *inode, struct file *file);
static void *proc_start(struct seq_file *m, loff_t *pos);
static void proc_stop(struct seq_file *m, void *v);
static void *proc_next(struct seq_file *m, void *v, loff_t *pos);
static int proc_show(struct seq_file *m, void *v);


/****************************************
 * Global variables
 ***************************************/
static struct core __percpu *core;
static unsigned int period = 1000000;   /* sampling period in useconds */
static ktime_t kt_period;               /* period in a ktime_t */
static unsigned int nr_samples = 10000; /* max number of stored samples */
static struct proc_dir_entry *proc_dir; /* procfs directory */
static struct file_operations fops = {  /* procfs data structures */
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


/****************************************
 * Module parameters
 ***************************************/
module_param(period, uint, 0444);
MODULE_PARM_DESC(period, "Sampling period in usec (default: 1000000)");
module_param(nr_samples, uint, 0444);
MODULE_PARM_DESC(nr_samples, "Maximum number of samples stored in memory \
(default: 10000)");


/****************************************
 * Code
 ***************************************/

static int proc_open(struct inode *inode, struct file *file)
{
	int ret;
	u64 id;
	struct seq_file *sf;

	ret = seq_open(file, &seqops);
	id = file->f_path.dentry->d_iname[4] - '0';
	sf = (struct seq_file *) (file->private_data);
	sf->private = (void *) id;

	return ret;
}

static void *proc_start(struct seq_file *m, loff_t *pos)
{
	u64 id;
	struct core *c;

	if (*pos == 0)
		return SEQ_START_TOKEN;

	id = (u64) m->private;
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
	u64 id;
	struct core *c;

	id = (u64) m->private;
	c = per_cpu_ptr(core, id);

	*pos = *pos + 1;
	if (likely(*pos != 1))
		c->read_id = (c->read_id + 1) % nr_samples;

	if (unlikely(c->read_id == c->cur_id))
		return NULL;
	
	return &(c->samples[c->read_id]);
}

static int proc_show(struct seq_file *m, void *v)
{
	struct sample *s;

	if (unlikely(v == SEQ_START_TOKEN)) {
		seq_printf(m, "timestamp (s) ; write ; miss\n");
		return 0;
	}

	s = (struct sample *) v;
	seq_printf(m, "%ld.%9ld ; %llu ; %llu\n",
		   s->timestamp.tv_sec, s->timestamp.tv_nsec,
		   s->write, s->miss);

	return 0;
}

static int setup_procfs(void)
{
	int cpu;
	struct core *c;
	char name[6] = "core0";

	/* create procfs directory */
	proc_dir = proc_mkdir(PROCFS_DIRNAME, NULL);
	if (proc_dir == NULL)
		goto err;

	/* setup each core's procfs seqfile */
	get_online_cpus();
	for_each_online_cpu(cpu) {
		c = per_cpu_ptr(core, cpu);
		name[4] = '0' + cpu;
		c->proc_entry = proc_create_data(name, 0444, proc_dir,
						 &fops, NULL);
		if (c->proc_entry == NULL) {
			pr_warn("%s/%s file creation failed\n", PROCFS_DIRNAME,
				name);
		}
	}
	put_online_cpus();

err:
	return -1;
}

static void cleanup_procfs(void)
{
	proc_remove(proc_dir);
}

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
	int config;
	long err = 0;

	config   = PERF_COUNT_HW_CACHE_L1D;
	config  |= (PERF_COUNT_HW_CACHE_OP_READ << 8);
	config  |= (PERF_COUNT_HW_CACHE_RESULT_MISS << 16);
	c->miss  = init_counter(c->id, PERF_TYPE_HW_CACHE, config);
	if (c->miss == NULL) {
		err = -1;
		goto err;
	}

	config   = PERF_COUNT_HW_CACHE_L1D;
	config  |= (PERF_COUNT_HW_CACHE_OP_WRITE << 8);
	config  |= (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16);
	c->write = init_counter(c->id, PERF_TYPE_HW_CACHE, config);
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

static void profile(void)
{
	struct core *c = this_cpu_ptr(core);

	c->miss->pmu->stop(c->miss, PERF_EF_UPDATE);
	c->write->pmu->stop(c->write, PERF_EF_UPDATE);

	getnstimeofday(&(c->samples[c->cur_id].timestamp));
	c->samples[c->cur_id].miss  = local64_read(&(c->miss)->count);
	c->samples[c->cur_id].write = local64_read(&(c->write)->count);
	c->cur_id = (c->cur_id + 1) % nr_samples;

	c->miss->pmu->start(c->miss, PERF_EF_RELOAD);
	c->write->pmu->start(c->write, PERF_EF_RELOAD);
}

static enum hrtimer_restart timer_handler(struct hrtimer *timer)
{
	struct core *c = this_cpu_ptr(core);

	c->function();
	
	hrtimer_forward_now(timer, kt_period);

	return HRTIMER_RESTART;
	//return HRTIMER_NORESTART;
}

static void init_hrtimer(void *arg)
{
	struct core *c = this_cpu_ptr(core);

	hrtimer_init(&(c->timer), CLOCK_MONOTONIC_RAW,
		     HRTIMER_MODE_REL_PINNED);
	c->timer.function = timer_handler;
	hrtimer_start(&(c->timer), kt_period, HRTIMER_MODE_REL_PINNED);
}

static void cancel_hrtimer(void *arg)
{
	struct core *c = this_cpu_ptr(core);

	hrtimer_cancel(&(c->timer));
}

static void cancel_timers(void)
{
	int cpu;

	get_online_cpus();
	for_each_online_cpu(cpu) {
		if (smp_call_function_single(cpu, cancel_hrtimer, NULL, 1) != 0) {
			pr_warn("timer cancellation failed on CPU%d\n", cpu);
		}
	}
	put_online_cpus();
}

int init_module(void)
{
	int cpu;
	long err;
	struct core *c;

	/* Convert uint period to ktime_t period */
	kt_period = ktime_set(0, 1000 * period);

	/* Alloc data for each CPU */
	core = alloc_percpu(struct core);

	/* procfs setup */
	setup_procfs();

	/* On each CPU, initialize counters and timers */
	get_online_cpus();
	for_each_online_cpu(cpu) {
		c             = per_cpu_ptr(core, cpu);
		c->id         = cpu;
		c->function   = profile;
		c->miss       = NULL;
		c->write      = NULL;
		c->cur_id     = 0;
		c->read_id    = 0;
		c->proc_entry = NULL;
	}
	for_each_online_cpu(cpu) {
		c          = per_cpu_ptr(core, cpu);
		/* Allocate memory for samples */
		c->samples = kmalloc_array(nr_samples, sizeof(struct sample),
					   GFP_KERNEL);
		if (c->samples == NULL) {
			err = -ENOMEM;
			goto err;
		}
		
		/* Initialize counters */
		if (init_counters(c) != 0) {
			err = -EPERM;
			goto err;
		}

		/* Initialize timers */
		if (smp_call_function_single(cpu, init_hrtimer, NULL, 1) != 0) {
			pr_warn("timer initialization failed on CPU%d\n", cpu);
		}
	}
	put_online_cpus();

	pr_info("module inserted with success\n");

	return 0;

err:
	for_each_online_cpu(cpu) {
		c = per_cpu_ptr(core, cpu);
		kfree(c->samples);
		if (c->miss != NULL)
			perf_event_release_kernel(c->miss);
		if (c->write != NULL)
			perf_event_release_kernel(c->write);
		if (smp_call_function_single(cpu, cancel_hrtimer, NULL, 1) != 0) {
			pr_warn("timer cancellation failed on CPU%d\n", cpu);
		}
	}
	put_online_cpus();

	free_percpu(core);

	pr_err("module insertion failed!\n");
	
	return err;
}

void cleanup_module(void)
{
	int cpu;
	struct core *c;

	cancel_timers();
	disable_counters();

	get_online_cpus();
	for_each_online_cpu(cpu) {
		c = per_cpu_ptr(core, cpu);
		if (c != NULL) {
			perf_event_release_kernel(c->miss);
			perf_event_release_kernel(c->write);
		}
		kfree(c->samples);
	}
	put_online_cpus();

	cleanup_procfs();

	free_percpu(core);

	pr_info("module removed with success\n");
}
