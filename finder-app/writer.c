#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

int main(int argc, char *argv[]) {
    // Check the number of command-line arguments
    if (argc != 3) {
        fprintf(stderr, "Error: Incorrect usage\n");
        fprintf(stderr, "Correct Usage: %s <writefile> <writestr>\n", argv[0]);
        return 1;
    }

    // Extract arguments
    const char *writefile = argv[1];
    const char *writestr = argv[2];

    // Open the file for writing
    FILE *file = fopen(writefile, "w");
    if (file == NULL) {
        fprintf(stderr, "Error: Failed to open %s for writing\n", writefile);
        syslog(LOG_ERR, "Failed to open %s for writing", writefile);
        return 1;
    }

    // Write the string to the file
    if (fprintf(file, "%s", writestr) < 0) {
        fprintf(stderr, "Error: Failed to write content to %s\n", writefile);
        syslog(LOG_ERR, "Failed to write content to %s", writefile);
        fclose(file);
        return 1;
    }

    // Close the file
    fclose(file);

    // Log a message with LOG_DEBUG level
    syslog(LOG_DEBUG, "Writing %s to %s", writestr, writefile);

    // Success
    printf("Content written to %s successfully.\n", writefile);

    return 0;
}

