CC ?= gcc
CROSS_COMPILE ?=

TARGET = aesdsocket
SRCS = aesdsocket.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CROSS_COMPILE)$(CC) -o $@ $^

%.o: %.c
	$(CROSS_COMPILE)$(CC) -c -o $@ $< -Wall -Werror

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean