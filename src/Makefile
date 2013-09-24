obj-m = packet_capture.o
ccflags-y += -std=gnu99 -Wno-declaration-after-statement
KVERSION = $(shell uname -r)
all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
