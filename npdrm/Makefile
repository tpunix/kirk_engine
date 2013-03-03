CC = gcc
CFLAGS = -Wall -I../kirk -I../common
TARGET = pgdecrypt freedata
OBJS1 = dnas.o pgd.o
OBJS2 = edata.o pgd.o

ifeq ($(DEBUG), 1)
CFLAGS+=-g -O0
else
CFLAGS+=-O2
endif

all: $(TARGET)

pgdecrypt: $(OBJS1)
	$(CC) $(CFLAGS) -o $@ $(OBJS1) -L ../kirk -lkirk -lz

freedata: $(OBJS2)
	$(CC) $(CFLAGS) -o $@ $(OBJS2) -L ../kirk -lkirk -lz

clean:
	$(RM) *.o $(TARGET) *.exe *.exe.stackdump

