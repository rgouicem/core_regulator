#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>

#include "ioctl.h"

#define SIZE 200 * 200
#define LOOPS 500

void timespec_diff(struct timespec *start, struct timespec *stop,
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

int main(int argc, char **argv)
{
	int *array = malloc(SIZE * sizeof(int));
	int i, j, k, iter = 1;
	int fd, ret = EXIT_SUCCESS;
	int loops = LOOPS;
	long t;
	struct timespec begin, end, elapsed;
	struct ioctl_data cmd;
	struct ioctl_data *data;

	if (argc > 2) {
		fprintf(stderr, "too many arguments\n");
		return EXIT_FAILURE;
	}
	if (argc == 2)
		iter = atoi(argv[1]);

	data = malloc(iter * sizeof(struct ioctl_data));

	fd = open("/dev/"IOCTL_DEVNAME, O_RDWR);
	if (fd < 0) {
		perror("opening /dev/"IOCTL_DEVNAME);
		goto err;
	}

	cmd.pid = getpid();

	if (ioctl(fd, IOCTL_REGISTER, &cmd) < 0) {
		fprintf(stderr, "ioctl register failed\n");
		goto err2;
	}

	srand(42);

	clock_gettime(CLOCK_MONOTONIC, &begin);
	for (j = 0; j < iter; j++) {
		if (ioctl(fd, IOCTL_START) < 0) {
			fprintf(stderr, "ioctl start failed\n");
			goto err2;
		}
		for (k = 0; k < loops; k++) {
			for (i = 0; i < SIZE; i++) {
				array[i] = rand();
			}
		}
		if (ioctl(fd, IOCTL_STOP, data + j) < 0) {
			fprintf(stderr, "ioctl stop failed\n");
			goto err2;
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &end);

	ioctl(fd, IOCTL_UNREGISTER);

	close(fd);

	printf("iter; times (s)\n");
	for (j = 0; j < iter; j++)
		printf("%d ; %ld.%09ld\n", j,
		       data[j].time.tv_sec, data[j].time.tv_nsec);

	free(array);

	timespec_diff(&begin, &end, &elapsed);

	printf("Total execution time: %ld.%09ld s\n",
	       elapsed.tv_sec, elapsed.tv_nsec);

	return EXIT_SUCCESS;

err2:
	close(fd);
err:
	free(array);
	free(data);
	return EXIT_FAILURE;
}
