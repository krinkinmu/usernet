ifneq ($(KERNELRELEASE),)

obj-m := usernet.o
usernet-y := main.o
CFLAGS_main.o += -DDEBUG

else

KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD

test: test.c
	$(CC) test.c -lpthread -o test

clean:
	rm -rf test *.o *.ko *.order *.symvers *.mod.c

endif
