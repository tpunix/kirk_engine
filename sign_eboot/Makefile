CC = gcc
CFLAGS = -Wall -g -I../kirk -I../common
TARGET = seboot
OBJS = sign_eboot.o ../common/utils.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) -L ../kirk -lkirk

clean:
	$(RM) *.o $(TARGET) *.exe *.exe.stackdump
