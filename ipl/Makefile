CC = gcc
CFLAGS = -Wall -g -O0 -I../kirk
TARGET = ipld
OBJS = ipl_decrypt.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) -L ../kirk -lkirk

clean:
	$(RM) *.o $(TARGET) *.exe *.exe.stackdump
