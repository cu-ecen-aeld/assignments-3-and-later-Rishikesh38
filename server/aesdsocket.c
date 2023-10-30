/**
 * @file    aesdsocket.c
 * @brief   This program creates a socket server that listens on port 9000, accepts incoming connections,
 *          and receives data from clients. It stores the received data in a file at "/var/tmp/aesdsocketdata"
 *          and sends back the accumulated data to the clients.
 *			
 * @date    October 13, 2023
 * @author  Rishikesh Sundaragiri
 */
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h> //has the struct addrinfo variable here
#include <syslog.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>	
#include <sys/time.h>
#include "queue.h"

/* Make this zero for regular socket implementation*/
#define USE_AESD_CHAR_DEVICE 1

#define PORT "9000"
#define TIME_STRING_SIZE 100
#define BACKLOG 10
#define ERROR_CODE -1
#if USE_AESD_CHAR_DEVICE
#   define DATA_FILE "/dev/aesdchar"
#else
#   define DATA_FILE "/var/tmp/aesdsocketdata"
#endif




int main_sockfd = 0;
int client_sockfd = 0;
int data_file_fd = 0;
pthread_mutex_t mutex;
#if USE_AESD_CHAR_DEVICE
#else
timer_t timer_id;
#endif
bool exit_flag = false;
int initial_alloc_size = 600;
int size_written = 0;

/*
* Structure that is usefull indicate the data_file_fd. This will be passed as parameter to time_handler
* so that the timestamp can be written in /var/tmp/aesdsocketdata every 10 secs
*/
typedef struct my_data_fd
{
    int fd; 
}my_data_fd;

/*
* This is the structure that is used to send the parameters to pthread_create function whenever a new 
* thread is created so that the thread has the details to perform the read and write. 
*/
typedef struct thread_entries
{
    pthread_t my_thread;
    bool is_thread_finished;
    pthread_mutex_t *my_mutex;
    int fd;
    int client_sock;
    char* d_buf;
    char* send_to_client_buf;
}thread_entries_t;

/*
* Reference : The below slist structure is took from lecture video of sample.c code
*/
typedef struct slist_data_s {
    thread_entries_t thread_values;
    SLIST_ENTRY(slist_data_s) entries;
} slist_data_t;

/*
* Declaration of head of the single linked list 
* Reference : Took from lecture video of sample.c code
*/
slist_data_t *datap = NULL;
SLIST_HEAD(slisthead,slist_data_s) head;


/*
 * Reference : https://beej.us/guide/bgnet/html/#cb47-58
*/
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/*
 *  Executes whenever a  SIGINT or SIGTERM is received
 *  parameter: int sig is the received signal number
 *  NOTE : I had all my cleanup here but as per professors comments in last assignment
 *         and the reference he gave me of the shutdown function is been used here
 * The shutdown function gracefully terminates the server socket after its done doing its task
 */
void sig_handler(int sig)
{
   if(sig == SIGINT || sig == SIGTERM) 
    {
		shutdown(main_sockfd,SHUT_RDWR);
		exit_flag = true;    
    }
}

/*
 * This functions cleans up exiting with -1
 */
void error_handler()
{
    exit_flag = 1;
    close(main_sockfd);
    #if USE_AESD_CHAR_DEVICE
	#else
    close(data_file_fd);
    remove(DATA_FILE);
    #endif

    /*
    * This loop uses the SLIST_FOREACH macro to iterate through a singly-linked list. 
    * For each element in the list, it checks if the associated thread is still running (threadParams.thread_complete is false) 
    * and cancels it using pthread_cancel to ensure proper termination during program exit.
    */
    SLIST_FOREACH(datap,&head,entries)
    {
        if (datap->thread_values.is_thread_finished == false)
        {
            pthread_cancel(datap->thread_values.my_thread);
        }
    }
    
    /*
    * In this while loop we iterate untill we free up the memory of the whole linked list.
    * Get the address of the current head, remove it from list and free the memory of it
    * Repeat it with the next entry(which is new head) untill the list is empty.
    */
    while(!SLIST_EMPTY(&head))
    {
        datap = SLIST_FIRST(&head);
        SLIST_REMOVE_HEAD(&head,entries);
        free(datap);
    }  
    pthread_mutex_destroy(&mutex);    
    #if USE_AESD_CHAR_DEVICE
    #else
    timer_delete(timer_id); 
    #endif
    closelog();                                     
}

/*
* This is the time_handler function which does the job of Append a timestamp in the form “timestamp:time”
* It will be called every secs by the help of itimer
*/
#if USE_AESD_CHAR_DEVICE
#else
void time_handler(union sigval my_param)
{
    my_data_fd* file_des = (my_data_fd*) my_param.sival_ptr;
    char t_buf[TIME_STRING_SIZE];
    time_t current_time;
    struct tm *local_time;
    int characters_written;
    /*
    * The time function takes a single parameter, which is a pointer to a variable of type time_t where it stores the current time. 
    * The time function returns the current time in seconds.
    */
    if(-1 == time(&current_time))
    {
        perror("time()");
        error_handler();
        exit(ERROR_CODE);
    }

    /*
    * The localtime function takes a single parameter, which is a pointer to a time_t variable containing the time you want to convert.
    * The localtime function returns a pointer to a struct tm representing the time in the local timezone.
    */
    local_time = localtime(&current_time);
    if(NULL == local_time)
    {
        perror("localtime()");
        error_handler();
        exit(ERROR_CODE);
    }  

    /*
    * The strftime function has several parameters:
       * A pointer to a character array where the formatted time string is stored.
       * The maximum number of characters to be stored in the character array.
       * A format string that specifies how the time should be formatted:
            * %a : Abbreviated weekday name (e.g., "Sun").
            * %d : Day of the month as a zero-padded decimal number (e.g., "01" for the 1st, "12" for the 12th).
            * %b : Abbreviated month name (e.g., "Jan" for January).
            * %Y : Year with century as a decimal number (e.g., "2023").
            * %T : Time in 24-hour clock format (e.g., "13:45:30").
            * %z : Time zone offset from UTC (e.g., "+0300" for a 3-hour offset from UTC).
            *
       * A pointer to a struct tm representing the time to be formatted.
    * The strftime function returns the number of characters written to the character array, excluding the null-terminating character.
    * Reference : https://pubs.opengroup.org/onlinepubs/009695399/utilities/date.html (POSIX standard for date and time formatting).
    */             
    characters_written = strftime(t_buf,TIME_STRING_SIZE,"timestamp:%a, %d %b %Y %T %z\n",local_time);
    if(0 == characters_written)
    {
        perror("strftime()");
        error_handler();
        exit(ERROR_CODE);
    }

    //Use mutex lock when using the shared resource i.e., when writing to /var/tmp/aesdsocketdata. 
    if(-1 == pthread_mutex_lock(&mutex))
    {
        perror("pthread_mutex_lock()");
        error_handler();
        exit(ERROR_CODE);
    }
    if(-1 == write(file_des->fd,t_buf,characters_written))
    {
        perror("write()");
        error_handler();
        exit(ERROR_CODE);
    }
    //Use mutex unlock after using the shared resource i.e., after writing to /var/tmp/aesdsocketdata. 
    if(-1 == pthread_mutex_unlock(&mutex))
    {
        perror("pthread_mutex_unlock()");
        error_handler();
        exit(ERROR_CODE);
    }
}
#endif

void* thread_routine(void *arg)
{
    int present_location = 0;
    int bytes_read = 0;
    int extra_alloc = 1;
    thread_entries_t *routine_values = (thread_entries_t*)arg;
    data_file_fd=open(DATA_FILE,O_CREAT|O_RDWR|O_APPEND,0644);
	if(data_file_fd == -1)
	{
		perror("error opening file at /var/temp/aesdsocketdata");
		exit(ERROR_CODE);
	}
    routine_values->d_buf = malloc(initial_alloc_size * sizeof(char));
    while((bytes_read = recv(routine_values->client_sock,routine_values->d_buf+present_location,initial_alloc_size,0)) > 0)
    {

        if(-1 == bytes_read)
        {
            perror("resv()");
            error_handler();
            exit(ERROR_CODE);          
        } 
        //If new line is not received, need to keep incrementing the present location to avoid overwritting the previous data received
		present_location+=bytes_read;           
        /*
        * Reference to strchr function : https://man7.org/linux/man-pages/man3/strchr.3.html
        */
        if(strchr(routine_values->d_buf ,'\n') != NULL)
        {
            break;
        }
				
        extra_alloc++;
        routine_values->d_buf = (char*)realloc(routine_values->d_buf,(extra_alloc*initial_alloc_size)*sizeof(char));
		if(NULL == routine_values->d_buf)
		{
			syslog(LOG_ERR,"Error: realloc()");
            //free(routine_values->d_buf);
            error_handler();
            exit(ERROR_CODE);
		}
    }

    //Use mutex lock when using the shared resource i.e., when writing to /var/tmp/aesdsocketdata. 
    if(-1 == pthread_mutex_lock(routine_values->my_mutex))
    {
        perror("pthread_mutex_lock()");
        error_handler();
        exit(ERROR_CODE);
    }

    int wri_var = write(data_file_fd,routine_values->d_buf,present_location);

    if(-1 == wri_var)
    {
        perror("write()");
		error_handler();
		exit(ERROR_CODE);    
    }
    size_written += wri_var;

    if(-1 == pthread_mutex_unlock(routine_values->my_mutex))
    {
        perror("pthread_mutex_unlock()");
        error_handler();
        exit(ERROR_CODE);
    }    

    /*
    * Get the lenght of the file and set the cursor to the start of the file
    */
    lseek(data_file_fd,0,SEEK_END);
    lseek(data_file_fd,0,SEEK_SET);
    routine_values->send_to_client_buf = malloc(size_written * sizeof(char));

    //Use mutex lock when using the shared resource i.e., when writing to /var/tmp/aesdsocketdata. 
    if(-1 == pthread_mutex_lock(routine_values->my_mutex))
    {
        perror("pthread_mutex_lock()");
        error_handler();
        exit(ERROR_CODE);
    }
    /*
    int readings = read(data_file_fd, routine_values->send_to_client_buf,size_written);
    if(-1 == readings)
    {
        perror("read()");
		error_handler();
		exit(ERROR_CODE);  

    }
    if(-1 == send(routine_values->client_sock,routine_values->send_to_client_buf,readings,0)) 
    {
        perror("send()");
		error_handler();
		exit(ERROR_CODE); 
    }
    */
    int readings; 
    int read_location = 0;
    int off_set_send = 0; 
    while((readings = read(data_file_fd,&routine_values->send_to_client_buf[read_location],1)) > 0)
    {
        if(routine_values->send_to_client_buf[read_location] == '\n')
        {
            int s_return = send(routine_values->client_sock,routine_values->send_to_client_buf+off_set_send,read_location- off_set_send + 1, 0);
            if(-1 == s_return)
            {
                perror("send()");
		        error_handler();
            }
            off_set_send = read_location + 1;
        }
        read_location++;
    }
	if(readings<0)
	{
		perror("read():");
		error_handler();
	}
    routine_values->is_thread_finished = true;
    if(-1 == pthread_mutex_unlock(routine_values->my_mutex))
    {
        perror("pthread_mutex_unlock()");
        error_handler();
        exit(ERROR_CODE);
    } 
    
    close(data_file_fd);
    close(routine_values->client_sock);
    free(routine_values->d_buf);
    free(routine_values->send_to_client_buf);
    return arg;
}

int main(int argc, char *argv[])
{
    //Opens a syslog with LOG_USER facility  
	openlog("aesdsocket",0,LOG_USER);
    int error_flag_getaddr = 0;
    int yes = 1;
    struct addrinfo hints;
    struct addrinfo *res;
    struct sockaddr_storage client_addr; // client's address information
    slist_data_t *loop = NULL;
    if(pthread_mutex_init(&mutex,NULL) != 0)
    {
        perror("pthread_mutex_init()");
        error_handler();
        exit(ERROR_CODE);
    } 
    /*
    * This line initializes the head and sets it up for use. It marks the beginning of the list and 
    * ensures that it's in a proper state to add elements to it using the SLIST_INSERT_HEAD macro.
    */
    SLIST_INIT(&head);

    /*
     * Use the signal function to establish a signal handler for specific signals 
     * Returns SIG_ERR on failure. On success - returns the previous signal handler (a function pointer)
     */
    if (SIG_ERR == signal(SIGINT, sig_handler)) 
	{
		fprintf (stderr, "signal() failed for SIGINT\n");
		exit(ERROR_CODE);
	}

	if (SIG_ERR == signal(SIGTERM, sig_handler)) 
	{
		fprintf (stderr, "signal() failed for SIGTERM\n");
		exit(ERROR_CODE);
	} 


    //Create a server socket i.e., main_sockfd
    main_sockfd = socket(AF_INET,SOCK_STREAM,0);
    char ip_addr[INET6_ADDRSTRLEN];
    if(-1 == main_sockfd)
    {
        perror("socket()");
        exit(ERROR_CODE);
    }

    memset(&hints,0,sizeof(hints)); //make sure the struct is 0 first.
    hints.ai_family = AF_INET; 
    hints.ai_socktype = SOCK_STREAM; //TCP based socket
    hints.ai_flags =  AI_PASSIVE; // fill in my IP for me
    error_flag_getaddr = getaddrinfo(NULL,PORT,&hints,&res);

    /*
     *  Reference for gai_strerror : https://pubs.opengroup.org/onlinepubs/9699919799/functions/gai_strerror.html
     */
    if(error_flag_getaddr !=0)
    {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(error_flag_getaddr));
        exit(ERROR_CODE);
    }

    /*
     * Reference for setsockopt : https://beej.us/guide/bgnet/html/#getaddrinfoprepare-to-launch
     * To set options on a socket
     */
	if (-1 == setsockopt(main_sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int))) 
	{	
		perror("setsockopt()");
        exit(ERROR_CODE);
    }

    if(-1 == bind(main_sockfd, res->ai_addr, res->ai_addrlen)) 
    {
        perror("bind()");
        freeaddrinfo(res);
        close(main_sockfd);
        exit(ERROR_CODE);
    }
    freeaddrinfo(res); 

    if(-1 == listen(main_sockfd,BACKLOG)) //backlog assumed 10 i.e, >1
    {
        perror("listen()");
        freeaddrinfo(res);
        close(main_sockfd);
        exit(ERROR_CODE);
    }


         /* The requirement is that the program should fork after ensuring it can bind to port 9000, so doing it right after the bind step
     * Reference : https://learning.oreilly.com/library/view/linux-system-programming/0596009585/ch05.html#daemons
     * Credits : The exact code mentioned in the above book is used here to run in deamon mode
     */
	if(argc==2 && (!strcmp(argv[1], "-d")))
	{
		pid_t pid;
        /* create new process */
		pid = fork();
		if (-1 == pid)
		{
			perror("fork()");
			exit(ERROR_CODE);
		}
		else if (pid != 0 )
		{
			
			exit(EXIT_SUCCESS);
		}

        /* The child process continues execution and performs the following steps to daemonize itself:*/
		/* create new session and process group */
        /* Detaching the process from the controlling terminal and creating a new session leader*/
		if(-1 == setsid()) 
		{
			perror("setsid()");
			exit(ERROR_CODE);
        }

		/* set the working directory to the root directory */
        /* This is done to ensure that the daemon process does not have any specific working directory tied to the terminal */
		if (-1 == chdir("/"))
		{
			exit(ERROR_CODE);
		}

       
        /* It redirects the standard input, output, and error to /dev/null by opening and duplicating file descriptors, 
         * effectively detaching the process from the terminal and eliminating any input or output connections with the daemon.
         */
        /* redirect fd's 0,1,2 to /dev/null */
		open ("/dev/null", O_RDWR);     /* stdin */
        // dup (0);                        /* stdout */
        // dup (0);                        /* stderror */
        // Store the return value
        int stdout_fd = dup(0); /* stdout */
        int stderr_fd = dup(0); /* stderr */

        // Use the duplicated file descriptors or suppress the warning by using them
        (void)stdout_fd; // To suppress the "unused variable" warning
        (void)stderr_fd; // To suppress the "unused variable" warning

	}   
	#if USE_AESD_CHAR_DEVICE
	#else
    //Setting here so that the data file fd can be passed as a parameter to time_handler
    my_data_fd timer_data;
    timer_data.fd = data_file_fd;
    /*
    * struct sigevent is a predefined C structure used for specifying event notification when a timer expires.
    */
    struct sigevent my_timer_event;
    memset(&my_timer_event,0,sizeof(struct sigevent));
    my_timer_event.sigev_notify = SIGEV_THREAD;
    my_timer_event.sigev_value.sival_ptr = &timer_data;
    my_timer_event.sigev_notify_function = time_handler;
    
    if(timer_create(CLOCK_MONOTONIC,&my_timer_event,&timer_id) != 0 ) 
    {
        perror("timer_create()");
    }
    
    if(clock_gettime(CLOCK_MONOTONIC,&start_time) != 0 ) 
    {
        perror("clock_gettime()");
    } 

    //timer calls the handler for every 10secs
    itimer.it_value.tv_sec = 10;
    itimer.it_value.tv_nsec = 0;
    itimer.it_interval.tv_sec = 10;
    itimer.it_interval.tv_nsec = 0;  

    
    if(timer_settime(timer_id, TIMER_ABSTIME, &itimer, NULL ) != 0 ) 
    {
        perror("settime error");
    } 
    #endif
    while(1)
    {
        socklen_t client_len = sizeof(client_addr);
        client_sockfd = accept(main_sockfd,(struct sockaddr*)&client_addr,&client_len);

        if (-1 == client_sockfd) 
        {
            perror("accept()");
            error_handler();
            exit(ERROR_CODE);
        }

        if(exit_flag)
        {
            break;
        }

        /*
         *  Reference for  inet_ntop : https://man7.org/linux/man-pages/man3/inet_ntop.3.html
         */ 
        if(NULL == inet_ntop(AF_INET, get_in_addr((struct sockaddr*)&client_addr),ip_addr, sizeof(ip_addr)))
        {
            perror("inet_ntop()");
            error_handler();
            exit(ERROR_CODE);
        }
        else
        {
            syslog(LOG_DEBUG,"Accepted connection from %s", ip_addr);
        }

        //set the members of single linked list
        datap = (slist_data_t*)malloc(sizeof(slist_data_t));
        SLIST_INSERT_HEAD(&head,datap,entries);
        datap->thread_values.is_thread_finished = false;
        datap->thread_values.my_mutex = &mutex;
        //datap->thread_values.fd = data_file_fd;
        datap->thread_values.client_sock = client_sockfd;

        //create the thread
        if(pthread_create(&(datap->thread_values.my_thread),NULL,&thread_routine,(void*)&(datap->thread_values)) != 0)
        {
            perror("pthread_create()");
            error_handler();
            exit(ERROR_CODE);
        }

        /*
        * it iterates through a singly-linked list using SLIST_FOREACH_SAFE, and for each element in the list, 
        * it waits for the associated thread (referenced by my_thread) to finish using pthread_join. 
        * If the thread has completed (as indicated by is_thread_finished), it removes the element from the list and frees the associated memory.
        */
        SLIST_FOREACH_SAFE(datap,&head,entries,loop)
		{
            if(pthread_join(datap->thread_values.my_thread,NULL) !=0)
            {
                perror("pthread_join()");
                error_handler();
                exit(ERROR_CODE);
            }
			if (true == datap->thread_values.is_thread_finished)
			{
				SLIST_REMOVE(&head,datap,slist_data_s,entries);
				free(datap);
				datap=NULL;
			}
		}
	
    }
    error_handler();
    return 0;
}

