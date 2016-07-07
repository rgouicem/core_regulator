#ifndef IOCTL_H_
#define IOCTL_H_

#include <linux/ioctl.h>

struct ioctl_data {
	pid_t pid;
	struct timespec time;
};

#define IOCTL_DEVNAME "core_regulator"

#define IOCTL_MAGIC 'r'

#define IOCTL_REGISTER    _IOW(IOCTL_MAGIC, 0, struct ioctl_data)
#define IOCTL_START       _IO(IOCTL_MAGIC,  1)
#define IOCTL_STOP        _IOR(IOCTL_MAGIC, 2, struct ioctl_data)
#define IOCTL_UNREGISTER  _IO(IOCTL_MAGIC,  3)

#endif
