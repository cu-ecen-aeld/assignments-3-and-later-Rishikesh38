CC=$(CROSS_COMPILE)gcc

CFLAGS= -Wall -Werror

TARGET = aesdsocket 

all: $(TARGET)
default: $(TARGET)

aesdsocket: aesdsocket.o
	$(CC) $(CFLAGS) -o aesdsocket aesdsocket.o
clean:
	rm -f *.o $(TARGET)

.PHONY: clean
