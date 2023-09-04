#!/bin/bash

#Take two runtime arguments 
filesdir="$1"
searchstr="$2"

#print statements if any of the parametersvwere not specified
#Reference manual : https://man7.org/linux/man-pages/man3/stapvars.3stap.html
if [ $# -ne 2 ]; then
    echo "Error: Incorrect usage"
    echo "Correct Usage: $0 <filesdir> <searchstr>"
    exit 1
fi

#print statements if filesdir does not represent a directory on the filesystem
#Reference man page : https://www.man7.org/linux/man-pages/man1/bash.1.html#:~:text=precedence%20rules%20above.-,CONDITIONAL%20EXPRESSIONS,-top
if [ ! -d "$filesdir" ]; then
    echo "Error: $filesdir is not a directory. Please enter a valid directory"
    exit 1
fi


# Function to find matching lines in files
find_matching_lines() {
    local dir="$1"
    local str="$2"
    local file_count=0
    local line_count=0

    #Reference: Part of the code is taken from chat GPT, prompt was a point asked in assignment 
    while IFS= read -r -d '' file; do
        if [ -f "$file" ]; then
            file_count=$((file_count + 1))
            while IFS= read -r line; do
                if [[ "$line" == *"$str"* ]]; then
                    line_count=$((line_count + 1))
                fi
            done < "$file"
        fi
    done < <(find "$dir" -type f -print0)

    echo "The number of files are $file_count and the number of matching lines are $line_count"
}

find_matching_lines "$filesdir" "$searchstr"
