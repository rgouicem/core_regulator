#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>

#define LINE_SIZE 64

#define L3_WAYS   12
#define L3_SETS   4096
#define L3_SIZE   LINE_SIZE * L3_WAYS * L3_SETS

#define L2_WAYS   8
#define L2_SETS   512
#define L2_SIZE   LINE_SIZE * L2_WAYS * L2_SETS

#define L1_WAYS   8
#define L1_SETS   64
#define L1_SIZE   LINE_SIZE * L1_WAYS * L1_SETS

#define PERIOD_NS 1000000

/* #define NS_TO_LOOPS(t) (t * 0.056034483 * 2.5) */


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

/* Returns:
 * -1 if ts < ns
 *  0 if ts == ns
 *  1 if ts > ns
 */
static int timespec_cmp_ns(struct timespec *ts, int ns)
{
	int s = ns / 1000000000;

	ns = ns % 1000000000;
	if (s > ts->tv_sec)
		return -1;
	if (s < ts->tv_sec)
		return 1;
	if (ns < ts->tv_nsec)
		return 1;
	if (ns > ts->tv_nsec)
		return -1;
	return 0;
}

extern int Reader (void *ptr);
extern int Writer (void *ptr, unsigned long value);

enum action {READ, WRITE};

/* static inline void do_nothing(void) */
/* { */
/* 	int toto = 42; */
/* 	asm volatile ("mul %0, %0, %0\n" */
/* 		      : "=r" (toto) */
/* 		      : */
/* 		      :); */
/* } */

int main(int argc, char **argv)
{
	int i;
	int slow;
	int nr_periods = 0;
	char *array;
	unsigned long value = 0x1234567689abcdef;
	enum action action;
	struct timespec start, end, duration;
	struct timespec period_start, period_curr, period_end, curr_dur;
	uint slowdown_ns;
	/* uint slowdown_loops, l; */

err_args:
	if (argc < 2 || argc > 3) {
		fprintf(stderr, "Usage: %s w|r [slowdown]\n", argv[0]);
		return EXIT_FAILURE;
	}

	if (strcmp("w", argv[1]) == 0) {
		action = WRITE;
	} else if (strcmp("r", argv[1]) == 0) {
		action = READ;
	} else {
		argc = 1;
		goto err_args;
	}

	if (argc == 3) {
		slow = atoi(argv[2]);
		if (slow < 0)
			slow = 0;
		else if (slow > 100)
			slow = 100;
	} else
		slow = 0;
	slowdown_ns = PERIOD_NS * slow / 100;
	/* printf("PERIOD_NS * slow = %d\n", PERIOD_NS * slow); */
	/* printf("PERIOD_NS * slow / 100 = %d\n", PERIOD_NS * slow / 100); */
	/* slowdown_loops = NS_TO_LOOPS(slowdown_ns); */
	if (slow == 0) {
		curr_dur.tv_sec = 0;
		curr_dur.tv_nsec = PERIOD_NS;
	}
	/* printf("slowdown: %d%%\n", slow); */
	/* printf("slowdown ns = %u\n", slowdown_ns); */
	
	array = malloc(L3_SIZE * 2);

        memset(array, 42, L3_SIZE * 2);

	switch (action) {
	case WRITE:
		while (1) {
			clock_gettime(CLOCK_MONOTONIC, &period_start);
			if (slow != 0) {
				clock_gettime(CLOCK_MONOTONIC, &period_start);
				do {
					/* do_nothing(); */
					clock_gettime(CLOCK_MONOTONIC, &period_curr);
					timespec_diff(&period_start, &period_curr,
						      &curr_dur);
				} while (timespec_cmp_ns(&curr_dur, slowdown_ns) < 0);
				/* printf("slow: %lu.%09lu\n", */
				/*        curr_dur.tv_sec, curr_dur.tv_nsec); */
			}
			do {
				for (i = 0; i < L3_SIZE / 2; i += 256) {
					Writer(array + i, value);
				}
				if (slow != 0) {
					clock_gettime(CLOCK_MONOTONIC, &period_curr);
					timespec_diff(&period_start, &period_curr,
						      &curr_dur);
					if (timespec_cmp_ns(&curr_dur, PERIOD_NS) >= 0)
						break;
				} else {
					curr_dur.tv_sec = 0;
					curr_dur.tv_nsec = PERIOD_NS;
				}
				for (; i < L3_SIZE; i += 256) {
					Writer(array + i, value);
				}
				if (slow != 0) {
					clock_gettime(CLOCK_MONOTONIC, &period_curr);
					timespec_diff(&period_start, &period_curr,
						      &curr_dur);
					if (timespec_cmp_ns(&curr_dur, PERIOD_NS) >= 0)
						break;
				}
				for (; i < 3 * L3_SIZE / 2; i += 256) {
					Writer(array + i, value);
				}
				if (slow != 0) {
					clock_gettime(CLOCK_MONOTONIC, &period_curr);
					timespec_diff(&period_start, &period_curr,
						      &curr_dur);
					if (timespec_cmp_ns(&curr_dur, PERIOD_NS) >= 0)
						break;
				}
				for (; i < 2 * L3_SIZE; i += 256) {
					Writer(array + i, value);
				}
				if (slow != 0) {
					clock_gettime(CLOCK_MONOTONIC, &period_curr);
					timespec_diff(&period_start, &period_curr,
						      &curr_dur);
					if (timespec_cmp_ns(&curr_dur, PERIOD_NS) >= 0)
						break;
				}
			} while (timespec_cmp_ns(&curr_dur, PERIOD_NS) < 0);
			/* printf("period: %lu.%09lu\n", */
			/*        curr_dur.tv_sec, curr_dur.tv_nsec); */
			/* nr_periods++; */
			/* clock_gettime(CLOCK_MONOTONIC, &period_end); */
			/* timespec_diff(&period_start, &period_curr, &curr_dur); */
			/* printf("%lu.%08lu ; ", */
			/*        curr_dur.tv_sec, curr_dur.tv_nsec); */
			/* timespec_diff(&period_curr, &period_end, &curr_dur); */
			/* printf("%lu.%08lu\n", */
			/*        curr_dur.tv_sec, curr_dur.tv_nsec); */
		}
		break;
	case READ:
		while (1) {
			if (slow != 0) {
				clock_gettime(CLOCK_MONOTONIC, &period_start);
				do {
					clock_gettime(CLOCK_MONOTONIC, &period_curr);
					timespec_diff(&period_start, &period_curr,
						      &curr_dur);
				} while (timespec_cmp_ns(&curr_dur, slowdown_ns) < 0);
				/* printf("slow: %lu.%09lu\n", */
				/*        curr_dur.tv_sec, curr_dur.tv_nsec); */
			}
			do {
				for (i = 0; i < L3_SIZE / 2; i += 256) {
					Reader(array + i);
				}
				if (slow != 0) {
					clock_gettime(CLOCK_MONOTONIC, &period_curr);
					timespec_diff(&period_start, &period_curr,
						      &curr_dur);
					if (timespec_cmp_ns(&curr_dur, PERIOD_NS) >= 0)
						break;
				} else {
					curr_dur.tv_sec = 0;
					curr_dur.tv_nsec = PERIOD_NS;
				}
				for (; i < L3_SIZE; i += 256) {
					Reader(array + i);
				}
				if (slow != 0) {
					clock_gettime(CLOCK_MONOTONIC, &period_curr);
					timespec_diff(&period_start, &period_curr,
						      &curr_dur);
					if (timespec_cmp_ns(&curr_dur, PERIOD_NS) >= 0)
						break;
				}
				for (; i < 3 * L3_SIZE / 2; i += 256) {
					Reader(array + i);
				}
				if (slow != 0) {
					clock_gettime(CLOCK_MONOTONIC, &period_curr);
					timespec_diff(&period_start, &period_curr,
						      &curr_dur);
					if (timespec_cmp_ns(&curr_dur, PERIOD_NS) >= 0)
						break;
				}
				for (; i < 2 * L3_SIZE; i += 256) {
					Reader(array + i);
				}
				if (slow != 0) {
					clock_gettime(CLOCK_MONOTONIC, &period_curr);
					timespec_diff(&period_start, &period_curr,
						      &curr_dur);
					if (timespec_cmp_ns(&curr_dur, PERIOD_NS) >= 0)
						break;
				}
			} while (timespec_cmp_ns(&curr_dur, PERIOD_NS) < 0);
			/* printf("period: %lu.%09lu\n", */
			/*        curr_dur.tv_sec, curr_dur.tv_nsec); */
			/* nr_periods++; */
		}
		break;
	}

	free(array);

	return EXIT_SUCCESS;
}
