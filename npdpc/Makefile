CC = gcc
CFLAGS = -Wall -I../kirk -I../common
TARGET = npdpc
OBJS = my_npd.o npeg.o libccc.o tlzrc.o ../common/utils.o

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

