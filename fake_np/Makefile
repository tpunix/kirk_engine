CC = gcc
CFLAGS = -Wall -I../kirk -I../common
TARGET = fake_np
OBJS = fake_np.o isoreader.o ../common/utils.o ../npdpc/tlzrc.o

ifeq ($(DEBUG), 1)
CFLAGS+=-g -O0
else
CFLAGS+=-O2
endif

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) -L ../kirk -lkirk -lz

clean:
	$(RM) *.o $(TARGET) *.exe *.exe.stackdump
