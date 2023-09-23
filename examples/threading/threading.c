#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#define MS_TO_US(ms) ((ms) * 1000) // Define the conversion from milliseconds to microseconds

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)



void* threadfunc(void* thread_param)
{
    struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    usleep(MS_TO_US(thread_func_args->obtain_wait_time)); 
    pthread_mutex_lock(thread_func_args->mutex);
    usleep(MS_TO_US(thread_func_args->release_wait_time)); 
    pthread_mutex_unlock(thread_func_args->mutex);
    thread_func_args->thread_complete_success = true;
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    struct thread_data *dynamic_data = (struct thread_data*)malloc(sizeof(struct thread_data));
    if(dynamic_data == NULL)
    {
        //print the error message saying thread cannot be created as there is no memory to malloc
        ERROR_LOG("Thread cannot be created due to memory allocation failure");
        return false;
    }

    dynamic_data->obtain_wait_time = wait_to_obtain_ms;
    dynamic_data->release_wait_time = wait_to_release_ms;
    dynamic_data->mutex = mutex;
    dynamic_data->thread_complete_success = false;
    if(pthread_create(thread,NULL,threadfunc,(void*)dynamic_data) != 0)
    {
        //print a message saying that pthread create function failed
        ERROR_LOG("pthread_create function failed.");
        free(dynamic_data);
        return false;
    }
    return true;
}

