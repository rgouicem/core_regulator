#KERNELDIR ?= /lib/modules/$(shell uname -r)/build
KERNELDIR=/home/redha/m2/nmv/linux-4.2.3
PWD := $(shell pwd)

obj-m := core_regulator.o
#core_regulator-objs := core_regulator.o


all:
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean
	rm -rf *~ *#

send: core_regulator.ko
	scp -P10022 $^ root@localhost:

.PHONY: all clean send
