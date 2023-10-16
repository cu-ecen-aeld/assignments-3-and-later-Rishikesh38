# Compiler variable: CC is the compiler, and it is optional. 
# $(CROSS_COMPILE) is a prefix that can be set externally to specify a cross-compiler.
CC ?= $(CROSS_COMPILE)gcc

# Compiler flags: CFLAGS are optional and include debugging information (-g), enable all warnings (-Wall), and treat warnings as errors (-Werror).
CFLAGS ?= -g -Wall -Werror

# Target binary name: TARGET is the name of the output executable.
TARGET ?= aesdsocket

# Linker flags: LDFLAGS specify flags to the linker. In this case, it includes -pthread for threading support and -lrt for real-time POSIX functions.
LDFLAGS ?= -pthread -lrt

# Source file and object file variables
SRC = aesdsocket
OBJ = $(SRC).o

# Default target. When you run 'make', it builds the TARGET binary.
all: $(TARGET)

# Rule to build the TARGET binary. It depends on the object file.
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(TARGET) $(LDFLAGS)

# Rule to compile the source file into an object file.
$(OBJ): $(SRC).c
	$(CC) $(CFLAGS) -c $(SRC).c

# Clean rule to remove object files and the TARGET binary.
clean:
	-rm -f $(OBJ) $(TARGET)