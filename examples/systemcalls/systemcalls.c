#include "systemcalls.h"
#include <stdlib.h> // Include this for the system() function
#include <unistd.h> // Include this for the fork() function and execv() function
#include <sys/wait.h> // Include this for the waitpid() function
#include <fcntl.h> // Include this for the open() function


/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{

    // Check if the command is not NULL
    if (cmd == NULL) 
    {
        return false;
    }
    int result = system(cmd);
    if (result == 0) 
    {
        return true;
    } 
    else 
    {
        return false;
    }
}


/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);

    // Check if the count is valid
    if (count <= 0) 
    {
        va_end(args);
        return false;
    }

    // Create an array to hold the command and its arguments
    char* command[count + 1]; // +1 for the NULL terminator
    for (int i = 0; i < count; i++) 
    {
        command[i] = va_arg(args, char*);
    }
    command[count] = '\0'; // Null-terminate the array

    // Fork a new process
    pid_t child_pid = fork();

    if (child_pid < 0) 
    {
        // Forking failed
        va_end(args);
        return false;
    } 
    else if (child_pid == 0) 
    {
        // This is the child process
        // Execute the command in the child process
        execv(command[0], command);

        // If execv() returns, it means an error occurred
        // Print an error message and exit with failure status
        perror("execv");
        exit(EXIT_FAILURE);
    } 
    else 
    {
        // This is the parent process
        int status;
        // Wait for the child process to complete
        waitpid(child_pid, &status, 0);

        va_end(args);

        // Check if the child process exited successfully
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) 
        {
            return true;
        } 
        else 
        {
            return false;
        }
    }
}


/**
* @param outputfile - The full path to the file to write with command output.
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/
//Credits : Asked GPT to generate the code for this function, the prompt was same as the TODO.
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    va_start(args, count);

    // Check if the count is valid
    if (count <= 0) 
    {
        va_end(args);
        return false;
    }

    // Create an array to hold the command and its arguments
    char* command[count + 1]; // +1 for the NULL terminator
    for (int i = 0; i < count; i++) 
    {
        command[i] = va_arg(args, char*);
    }
    command[count] = '\0'; // Null-terminate the array

    // Fork a new process
    pid_t child_pid = fork();

    if (child_pid < 0) 
    {
        // Forking failed
        va_end(args);
        return false;
    } 
    else if (child_pid == 0) 
    {
        // This is the child process

        // Open the output file for writing, creating it if it doesn't exist
        int output_fd = open(outputfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);

        if (output_fd == -1) 
        {
            // Failed to open the output file
            perror("open");
            exit(EXIT_FAILURE);
        }

        // Redirect stdout to the output file using dup2
        if (dup2(output_fd, STDOUT_FILENO) == -1) 
        {
            // Failed to redirect stdout
            perror("dup2");
            close(output_fd);
            exit(EXIT_FAILURE);
        }

        // Close the output file descriptor
        close(output_fd);

        // Execute the command in the child process
        execv(command[0], command);

        // If execv() returns, it means an error occurred
        perror("execv");
        exit(EXIT_FAILURE);
    } 
    else 
    {
        // This is the parent process
        int status;
        // Wait for the child process to complete
        waitpid(child_pid, &status, 0);

        va_end(args);

        // Check if the child process exited successfully
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) 
        {
            return true;
        } 
        else 
        {
            return false;
        }
    }
}
