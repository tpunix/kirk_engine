TARGET = my_npd
OBJS = my_npd.o npeg.o printk.o sceAmctrl_driver.o scePspNpDrm_driver.o

CFLAGS = -O2 -G0 -Wall -I.
LDFLAGS = -mno-crt0 -nostartfiles -L.
LIBS += -lpsppower_driver

BUILD_PRX=1
USE_KERNEL_LIBS=1
USE_KERNEL_LIBC=1

EXTRA_TARGETS = EBOOT.PBP
PSP_EBOOT_TITLE = New Npdecrypt

PSPSDK = $(shell psp-config --pspsdk-path)
include $(PSPSDK)/lib/build.mak

