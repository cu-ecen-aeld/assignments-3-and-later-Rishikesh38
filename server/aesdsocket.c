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

#define PORT "9000"
#define BACKLOG 10
#define ERROR_CODE -1
#define DATA_FILE "/var/tmp/aesdsocketdata"

static bool signal_received = false;
int main_sockfd = 0;
int client_sockfd = 0;
int data_file_fd = 0;

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
 */
void sig_handler(int sig)
{
    signal_received = true;
}

/*
 * This functions cleans up exiting with -1
 */
void error_handler()
{
    close(main_sockfd);
    close(client_sockfd);
    close(data_file_fd);
    closelog();
    remove(DATA_FILE);
}
int main(int argc, char *argv[])
{
    //Opens a syslog with LOG_USER facility  
	openlog("aesdsocket",0,LOG_USER);
    int extra_alloc = 1;
    int initial_alloc_size = 500;
    int present_location = 0;
    int error_flag_getaddr = 0;
    int bytes_read = 0;
    int total_data_len = 0;
    int yes = 1;
    struct addrinfo hints;
    struct addrinfo *res;
    struct sockaddr_storage client_addr; // client's address information

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

    /*
     * A variable sock_set of type sigset_t, which is a data structure used to represent a set of signals.
     * sigemptyset : Used to initialize an empty signal set. It clears all signals from the set.
     * sigaddset : Used to add specific signals (SIGINT and SIGTERM) to the signal set 
     */
    sigset_t sock_set;
    if(sigemptyset(&sock_set) != 0)
    {
		perror("sigemptyset()");
		exit(ERROR_CODE);        
    }
    if(sigaddset(&sock_set,SIGINT) != 0)
    {
		perror("sigaddset(): SIGINT ");
		exit(ERROR_CODE);          
    }
    if(sigaddset(&sock_set,SIGTERM) != 0)
    {
		perror("sigaddset(): SIGTERM ");
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
    hints.ai_family = AF_UNSPEC; //Don't care IPv4 or IPv6
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
    freeaddrinfo(res); // all done with this structure
    
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
			
			exit(ERROR_CODE);
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
        dup (0);                        /* stdout */
        dup (0);                        /* stderror */
	}    

    //Create file to push data to /var/tmp/aesdsocketdata
    data_file_fd = open(DATA_FILE,O_CREAT|O_RDWR,0666);
	if(-1 == data_file_fd)
	{
	    perror("Error: Couldn't open the file at /var/temp/aesdsocketdata");
		exit(ERROR_CODE);
	}

    if(-1 == listen(main_sockfd,BACKLOG)) //backlog assumed 10 i.e, >1
    {
        perror("listen()");
        freeaddrinfo(res);
        close(main_sockfd);
        exit(ERROR_CODE);
    }

    //freeaddrinfo(res); // all done with this structure

    /*
     *    Need a while(1) so that we can accept many client requests and handle them. 
     */
    while(1)
    {
        if(signal_received)
        {
            if(-1 == close(main_sockfd))
            {
              	perror("close(main_sockfd)");
                exit(ERROR_CODE);  
            }
            if(-1 == close(data_file_fd))
            {
              	perror("close(data_file_fd)");
                exit(ERROR_CODE);                 
            }

            syslog(LOG_DEBUG,"Caught signal, exiting");
            closelog();

            if(-1 == remove(DATA_FILE))
            {
                perror("remove(DATA_FILE)");
            }

        }
        socklen_t client_len = sizeof(client_addr);
        client_sockfd = accept(main_sockfd,(struct sockaddr*)&client_addr,&client_len);

        if (-1 == client_sockfd) 
        {
            perror("accept()");
            continue; //go back to accepting a client request
        }

        /*
         *  Reference for  inet_ntop : https://man7.org/linux/man-pages/man3/inet_ntop.3.html
         */ 
        if(NULL == inet_ntop(AF_INET, get_in_addr((struct sockaddr*)&client_addr),ip_addr, sizeof(ip_addr)))
        {
            perror("inet_ntop()");
            close(client_sockfd);
            continue;
        }
        else
        {
            syslog(LOG_DEBUG,"Accepted connection from %s", ip_addr);
        }

        char *data_buf = (char*)malloc(initial_alloc_size*sizeof(char));
        if(NULL == data_buf)
        {
            perror("malloc()");
            error_handler();
            exit(ERROR_CODE);
        }

        /*
         * For completing any open connection operations i.e., resv() and send(), need to block the signal using sigprocmask()
         * Blocking doesn't mean we miss the signal, the signal waits until its unblocked and gets serviced by kernel. 
         */
		if( -1 == sigprocmask(SIG_BLOCK, &sock_set, NULL))
        {
			perror("sigprocmask()");
			error_handler();
			exit(ERROR_CODE);
        }

        while((bytes_read = recv(client_sockfd,data_buf+present_location,initial_alloc_size,0)) > 0)
        {
            /*
             * Reference to strchr function : https://man7.org/linux/man-pages/man3/strchr.3.html
            */
            if(strchr(data_buf ,'\n') != NULL)
            {
                break;
            }
				
			//If new line is not received, need to keep incrementing the present location to avoid overwritting the previous data received
			present_location+=bytes_read;
            extra_alloc++;
            data_buf = (char*)realloc(data_buf,(extra_alloc*initial_alloc_size)*sizeof(char));
			if(NULL == data_buf)
			{
				syslog(LOG_ERR,"Error: realloc()");
                free(data_buf);
                error_handler();
                exit(ERROR_CODE);
			}
        }
        if(-1 == bytes_read)
        {
            perror("resv()");
            error_handler();
            exit(ERROR_CODE);          
        }

        //Write the data to /var/tmp/aesdsocketdata
        if(-1 == write(data_file_fd,data_buf,strlen(data_buf)))
        {
			perror("write()");
			error_handler();
			exit(ERROR_CODE);           
        }

        //Need total data because we need to send back the whole data received till now
        total_data_len += strlen(data_buf);
        //To make sure we sent the data from start of the file
        //Move the cursor to start
        lseek(data_file_fd, 0, SEEK_SET);

        //create a buffer to send data with total size available at /var/tmp/aesdsocketdata
        char *send_to_client_buf = (char*)malloc(total_data_len*sizeof(char));
        if(-1 == read(data_file_fd,send_to_client_buf,total_data_len))
        {
			perror("read()");
			error_handler();
			exit(ERROR_CODE);              
        }

        if(-1 == send(client_sockfd,send_to_client_buf,total_data_len, 0))
        {
			perror("send()");
			error_handler();
			exit(ERROR_CODE);              
        }

        free(send_to_client_buf);
        free(data_buf);
        syslog(LOG_DEBUG,"Closed connection from %s", ip_addr);

		if(-1 == sigprocmask(SIG_UNBLOCK, &sock_set, NULL))
		{
			perror("sigprocmask()");
			error_handler();
			exit(ERROR_CODE); 
		}
    }
}
