CC = gcc
CFLAGS = -Wall -O2 -I.
LDLIBS = -lnetfilter_queue

TARGET = 1m-block
SRC = 1m-block.c
HDR = my_struct.h

all: $(TARGET)

$(TARGET): $(SRC) $(HDR)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDLIBS)

clean:
	rm -f $(TARGET)
