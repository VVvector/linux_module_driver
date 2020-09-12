ifneq ($(KERNELRELEASE),)
    obj-m := tty_test.o
else
    PWD  := $(shell pwd)
KDIR := /lib/modules/$(shell uname -r)/build
 
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
 
clean:
	rm -rf .*.cmd *.o *.mod.c *.ko .tmp_versions modules.order Module.symvers *.mod
endif
