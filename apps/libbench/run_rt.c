#define _XOPEN_SOURCE 700

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sched.h>
#include <signal.h>
#include <string.h>

#include "ioctl.h"

static void schedule_fifo()
{
	struct sched_param sched_param = {
		.sched_priority = sched_get_priority_max(SCHED_FIFO)
	};
	if (sched_setscheduler(getpid(), SCHED_FIFO, &sched_param) != 0) {
		perror("sched_setscheduler()");
		exit(EXIT_FAILURE);
	}
}

int fd_ioctl;
int fd_config;
unsigned int nr_iterations = 10, i;

void signal_handler(int sig)
{
	switch (sig) {
	case SIGUSR1:
		// configuration change
		dprintf(fd_config, "%u\n", nr_iterations - i);
		break;
	case SIGINT:
		ioctl(fd_ioctl, IOCTL_UNREGISTER);
		fprintf(stderr, "Received SIGINT\n");
		close(fd_ioctl);
		close(fd_config);
		exit(EXIT_SUCCESS);
	}
}

int main(int argc, char **argv, char *envp[])
{
	int ret = EXIT_SUCCESS;
	int deadline_us;
	pid_t pid;
	struct sigaction act;
	struct ioctl_cmd ioctl_cmd;
	union ioctl_data ioctl_data, ioctl_res;

	if (argc < 4) {
		printf("Usage: %s nr_iter deadline_us command ...\n"
		       "if deadline_us=-1, no adaptive mechanism\n",
		       argv[0]);
		return EXIT_FAILURE;
	}
	nr_iterations = atoi(argv[1]);
	deadline_us = atoi(argv[2]);

	schedule_fifo();

	fd_config = open("config.log", O_CREAT | O_RDWR);
	if (fd_config < 0) {
		perror("opening config.log");
		ret = EXIT_FAILURE;
		goto err;
	}
	dprintf(fd_config, "Iteration;load\n");

	memset(&act, 0, sizeof(struct sigaction));
	act.sa_handler = signal_handler;
	act.sa_flags = SA_RESTART;
	if (sigaction(SIGUSR1, &act, NULL) < 0 ||
	    sigaction(SIGINT, &act, NULL) < 0) {
		ret = EXIT_FAILURE;
		goto err1;
	}

	if (deadline_us == -1) {
		fd_ioctl = open("/dev/"IOCTL_DEVNAME, O_RDWR);
		if (fd_ioctl < 0) {
			perror("opening /dev/"IOCTL_DEVNAME);
			ret = EXIT_FAILURE;
			goto err1;
		}

		ioctl_cmd.pid = getpid();
		ioctl_cmd.type = DEADLINE;
		ioctl_cmd.cmp = UNDER;
		ioctl_data.deadline.tv_sec = deadline_us / 1000000;
		ioctl_data.deadline.tv_nsec = (deadline_us % 1000000) * 1000;

		if (ioctl(fd_ioctl, IOCTL_REGISTER, &ioctl_cmd) < 0) {
			fprintf(stderr, "ioctl register failed\n");
			ret = EXIT_FAILURE;
			goto err2;
		}
	}

	//srand(42);

	printf("Iteration;Time\n");

	i = nr_iterations;
	while (i--) {
		if (deadline_us == -1) {
			if (ioctl(fd_ioctl, IOCTL_START, &ioctl_data) < 0) {
				fprintf(stderr, "ioctl start failed\n");
				ret = EXIT_FAILURE;
				goto err3;
			}
		}

		/* Launch RT command */
		pid = fork();
		if (pid == 0) {
			/* Child process */
			execve(argv[3], argv+3, envp);
			fprintf(stderr, "execve() failed\n");
			ret = EXIT_FAILURE;
			goto err3;
		} else if (pid > 0) {
			/* Parent process */
			waitpid(pid, NULL, 0);
		} else {
			/* Error */
			fprintf(stderr, "fork() failed\n");
			ret = EXIT_FAILURE;
			goto err3;
		}

		if (deadline_us == -1) {
			if (ioctl(fd_ioctl, IOCTL_STOP, &ioctl_res) < 0) {
				fprintf(stderr, "ioctl stop failed\n");
				ret = EXIT_FAILURE;
				goto err3;
			}
		}

		printf("%5u;%lu.%09lu\n",
		       nr_iterations - i,
		       ioctl_res.deadline.tv_sec, ioctl_res.deadline.tv_nsec);
	}

err3:
	if (deadline_us == -1) {
		ioctl(fd_ioctl, IOCTL_UNREGISTER);
err2:
		close(fd_ioctl);
	}
err1:
	close(fd_config);
err:
	return ret;
}
