# Compiler and Cross-Compiler Configuration
CC ?= gcc
CROSS_COMPILE ?=

# Target and Source File Definitions
TARGET = aesdsocket
SRCS = aesdsocket.c
OBJS = $(SRCS:.c=.o)

# Additional linker flags
LDFLAGS = -lpthread -lrt

# Default Target (Build the Executable)
all: $(TARGET)

# Build the Executable
$(TARGET): $(OBJS)
	$(CROSS_COMPILE)$(CC) -o $@ $^ $(LDFLAGS) 

# Compile Each Source File to Object Files
%.o: %.c
	$(CROSS_COMPILE)$(CC) -c -o $@ $< -Wall -Werror

# Clean Up Generated Files
clean:
	rm -f $(OBJS) $(TARGET)

# Declare 'all' and 'clean' as Phony Targets (no actual files with these names)
.PHONY: all clean
