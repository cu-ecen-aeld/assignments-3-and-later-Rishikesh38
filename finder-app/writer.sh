#!/bin/bash

writefile="$1"
writestr="$2"

# Check if writefile is specified
if [ -z "$writefile" ]; then
    echo "Error: writefile not specified."
    exit 1
fi

# Check if writestr is specified
if [ -z "$writestr" ]; then
    echo "Error: writestr not specified."
    exit 1
fi

#print statements if any of the parametersvwere not specified
#Reference manual : https://man7.org/linux/man-pages/man3/stapvars.3stap.html
if [ $# -ne 2 ]; then
    echo "Error: Incorrect usage"
    echo "Correct Usage: $0 <writefile> <writestr>"
    exit 1
fi
# Create the directory path if it doesn't exist
mkdir -p "$(dirname "$writefile")"

# Attempt to write the content to the file
if echo "$writestr" > "$writefile"; then
    echo "Content written to $writefile successfully."
else
    echo "Error: Failed to write content to $writefile."
    exit 1
fi
