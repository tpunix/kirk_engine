CC = gcc
CFLAGS = -Wall -I../kirk -I../common
TARGET = pspkg
pspkg_OBJS  = pspkg.o ../common/utils.o

ifeq ($(DEBUG), 1)
CFLAGS+=-g -O0
else
CFLAGS+=-O2
endif

all: $(TARGET)

pspkg: $(pspkg_OBJS)
	$(CC) $(CFLAGS) -o $@ $(pspkg_OBJS) -L ../kirk -lkirk -lz

clean:
	$(RM) *.o $(TARGET) *.exe *.exe.stackdump

