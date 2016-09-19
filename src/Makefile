KERNELDIR ?= /lib/modules/$(shell uname -r)/build
#KERNELDIR_ARM ?= /home/redha/stageM2/yocto_krogoth-next/fsl-community-bsp/build/tmp/work/imx6qsabrelite-poky-linux-gnueabi/linux-boundary/4.1.15-r0/build
KERNELDIR_ARM ?= /home/redha/stageM2/yocto/fsl-community-bsp/build/tmp/work/imx6qsabrelite-poky-linux-gnueabi/linux-boundary/3.0.35-r0/git/
PWD := $(shell pwd)

obj-m := core_regulator.o

all:
	make -C $(KERNELDIR) M=$(PWD) modules

no_pmu:
	KCFLAGS="-DNO_PMU" make -C $(KERNELDIR) M=$(PWD) modules

arm:
	KCFLAGS="-DARM -DNO_PMU" make CROSS_COMPILE=arm-linux-gnueabihf- ARCH=arm -C $(KERNELDIR_ARM) M=$(PWD) modules

x86:
	KCFLAGS="-DCORE2QUAD -DNO_PMU" make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean
	rm -rf *~ *#

.PHONY: all no_pmu clean arm x86
