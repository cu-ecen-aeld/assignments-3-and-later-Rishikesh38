# Compiler and compiler flags
ifdef CROSS_COMPILE
    CC = $(CROSS_COMPILE)gcc
else
    CC = gcc
endif

CFLAGS = -Wall -Wextra

# Source files and object files
SRCS = writer.c
OBJS = $(SRCS:.c=.o)

# Target executable
TARGET = writer

# Default target: build the writer application
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

# Clean target: remove the writer application and all .o files
clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean




