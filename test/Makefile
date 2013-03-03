CC = gcc
CFLAGS = -Wall -g -I../kirk -I../common
TARGET = p_edata
PEDATA_OBJS = edata_ec.o ../common/utils.o


all: $(TARGET)

p_edata: $(PEDATA_OBJS)
	$(CC) $(CFLAGS) -o $@ $(PEDATA_OBJS) -L ../kirk -lkirk

clean:
	$(RM) *.o $(TARGET) *.exe *.exe.stackdump

