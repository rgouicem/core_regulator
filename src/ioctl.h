#ifndef IOCTL_H_
#define IOCTL_H_

#include <linux/ioctl.h>

enum cmd_type { DEADLINE, VALUE };
enum cmd_cmp { ABOVE, UNDER };

struct ioctl_cmd {
	pid_t pid;
	enum cmd_type type;
	enum cmd_cmp cmp;
};

union ioctl_data {
	struct timespec deadline;
	int value;
};

#define IOCTL_DEVNAME "core_regulator"

#define IOCTL_MAGIC 'r'

#define IOCTL_REGISTER    _IOW(IOCTL_MAGIC,  0, struct ioctl_cmd)
#define IOCTL_START       _IOW(IOCTL_MAGIC,  1, union ioctl_data)
#define IOCTL_STOP        _IOWR(IOCTL_MAGIC, 2, union ioctl_data)
#define IOCTL_UNREGISTER  _IO(IOCTL_MAGIC,   3)

#endif
