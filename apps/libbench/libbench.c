#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sched.h>
#include <sys/types.h>
#include <unistd.h>

static struct timespec bench_start, bench_end, bench_duration;

#define START_TIMER clock_gettime(CLOCK_MONOTONIC, &bench_start)
#define STOP_TIMER do {							\
		clock_gettime(CLOCK_MONOTONIC, &bench_end);		\
		timespec_diff(&bench_start, &bench_end, &bench_duration); \
		printf("%ld.%09ld\n",					\
		       bench_duration.tv_sec, bench_duration.tv_nsec);	\
	} while (0)

static void timespec_diff(struct timespec *start, struct timespec *stop,
			  struct timespec *result)
{
	if ((stop->tv_nsec - start->tv_nsec) < 0) {
		result->tv_sec = stop->tv_sec - start->tv_sec - 1;
		result->tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000;
	} else {
		result->tv_sec = stop->tv_sec - start->tv_sec;
		result->tv_nsec = stop->tv_nsec - start->tv_nsec;
	}

	return;
}

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

void __attribute__ ((constructor)) before_hook()
{
	schedule_fifo();
	START_TIMER;
}

void __attribute__ ((destructor)) after_hook()
{
	STOP_TIMER;
}
