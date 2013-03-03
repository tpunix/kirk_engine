CC = gcc
CFLAGS = -Wall -I../kirk -I../common
TARGET = pspc
OBJS = pspcipher.o prx_decrypt.o ../common/utils.o

ifeq ($(DEBUG), 1)
CFLAGS+=-g -O0
else
CFLAGS+=-O2
endif

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) -L ../kirk -lkirk

clean:
	$(RM) *.o $(TARGET) *.exe *.exe.stackdump
