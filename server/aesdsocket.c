#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <syslog.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <errno.h>


#define PORT "9000"
#define BACKLOG 10
#define CHUNK_SIZE 400
#define TEST_FILE  "/var/tmp/aesdsocketdata"

int serv_sock_fd,client_sock_fd,output_file_fd, total_length,len,capacity,counter=1,close_err;
struct sockaddr_in conn_addr;
char IP_addr[INET6_ADDRSTRLEN];
		

//Below function referenced from https://beej.us/guide/bgnet/html/
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

//Function handles all open files when there is an error
void close_all()
{
	//Functions called due to an error, hence close files errno not 
	//checked in this function
	//All close errors handled in signal handler when no error occured
	close(client_sock_fd);
	//Close server socket fd
	close(serv_sock_fd);
	//Close regular file - output file fd
	close(output_file_fd);
	
	//After completing above procedure successfuly, exit logged
	syslog(LOG_DEBUG,"Caught signal, exiting");
	
	//Close the syslog once all of logging is complete
	closelog();
	
	//Delete and unlink the file
	remove(TEST_FILE);

}
	
//Signal handler for Signals SIGTERM and SIGINT
static void signal_handler(int signo)
{
	close_err=close(client_sock_fd);
	if(close_err == -1)
	{
		close_all();
		perror("close client socket error");
		exit(-1);
	}

	//Close server socket fd
	close_err=close(serv_sock_fd);
	if(close_err == -1)
	{
		close_all();
		perror("close server socket error");
		exit(-1);
	}
	
	//Close regular file - output file fd
	close_err=close(output_file_fd);
	if(close_err == -1)
	{
		close_all();
		perror("close output file error");
		exit(-1);
	}
	//Once connection closed, logs status
	syslog(LOG_DEBUG, "Closed connection from %s",IP_addr);
	//After completing above procedure successfuly, exit logged
	syslog(LOG_DEBUG,"Caught signal, exiting");
	
	//Close the syslog once all of logging is complete
	closelog();
	
	//Delete and unlink the file
	if(remove(TEST_FILE) == -1)
	{
		perror("file remove error");
	}
}
int main(int argc, char *argv[])
{
	//Opens a connection with facility as LOG_USER to Syslog.
	openlog("aesdsocket",0,LOG_USER);
	
	//Registering signal_handler as the handler for the signals SIGTERM 
	//and SIGINT
	//Reference: Ch 10 signals, Textbook: Linux System Programming
	if (signal(SIGINT, signal_handler) == SIG_ERR) 
	{
		fprintf (stderr, "Cannot handle SIGINT\n");
		exit (EXIT_FAILURE);
	}
	
	if (signal(SIGTERM, signal_handler) == SIG_ERR) 
	{
		fprintf (stderr, "Cannot handle SIGTERM\n");
		exit (EXIT_FAILURE);
	}
	
		//Adding only signals SIGINT and SIGTERM to an empty set to enable only them
	sigset_t socket_set;
	int rc = sigemptyset(&socket_set);
	if(rc !=0)
	{
		perror("signal empty set error");
		exit(-1);
	}
	rc = sigaddset(&socket_set,SIGINT);
	if(rc !=0)
	{
		perror("error adding signal SIGINT to set");
		exit(-1);
	}
	rc = sigaddset(&socket_set,SIGTERM);
	if(rc !=0)
	{
		perror("error adding signal SIGTERM to set");
		exit(-1);
	}
	
	//With node as null and ai_flags as AI_PASSIVE, the socket address 
	//will be suitable for binding a socket that will accept connections
	struct addrinfo hints;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	struct addrinfo *res;
	
	
	//Node NULL and service set with port number as 9000, the pointer to
	//linked list returned and stored in res
	if (getaddrinfo(NULL, PORT , &hints, &res) != 0) 
	{
		perror("getaddrinfo error");
		exit(-1);
	}


    
    //Creating an end point for communication with type = SOCK_STREAM(connection oriented)
	//and protocol =0 which allows to use appropriate protocol (TCP) here
	serv_sock_fd=socket(res->ai_family,res->ai_socktype,res->ai_protocol);
	if(serv_sock_fd==-1)
	{
		perror("socket error");
		exit(-1);
	}
	
		
	//Set options on socket to prevent binding errors from ocurring
	int dummie =1;
	if (setsockopt(serv_sock_fd, SOL_SOCKET, SO_REUSEADDR, &dummie, sizeof(int)) == -1) 
	{	
		
		perror("setsockopt error");
    }
    
	//Assign address to the socket created
	rc=bind(serv_sock_fd, res->ai_addr, res->ai_addrlen);
	if(rc==-1)
	{
		perror("bind error");
		exit(-1);
	}
	
	//Below conditional check referenced from https://stackoverflow.com/questions/803776/help-comparing-an-argv-string
	if(argc==2 && (!strcmp(argv[1], "-d")))
	{
		//Below code reference from chapter 5 of textbook reference
		//Child forked to create a daemon custom named customd
		pid_t customd;
		customd = fork();
		if (customd == -1)
		{
			perror("fork error");
			exit(-1);
		}
		else if (customd != 0 )
		{
			//Exit parent, to make child get reparented to init_parent
			exit (EXIT_SUCCESS);
		}

		//Create new session and process group
		if(setsid() == -1) 
		{
			perror("setsid");
			exit(-1);
		}
		

		//Set working to root directory
		if (chdir("/") == -1)
		{
			exit(-1);
		}
		
		//Should close if any open files, skipping that helre
		//Redirect Stdin,stdout,stderr to /dev/null
		open ("/dev/null", O_RDWR); 
		dup (0); 
		dup (0); 
	}
	
	//If bind passes, open a new file to store the packet that will be read
	output_file_fd=open(TEST_FILE,O_CREAT|O_RDWR,0644);
	if(output_file_fd == -1)
	{
		perror("error opening file at /var/temp/aesdsocketdata");
		exit(-1);
	}
	
	//Post binding, the server is running on the port 9000, so now
	//remote connections (client) can listen to server
	//Backlog - queue of incoming connections before being accepted to send/recv 
	//backlog set as 4, can be reduced to a lower number since we get only 1 connection
	if(listen(serv_sock_fd,BACKLOG)==-1)
	{
		perror("error listening");
		exit(-1);
	}
	freeaddrinfo(res);
	while(1)
	{
		
		socklen_t conn_addr_len=sizeof(conn_addr);
		//Accept an incoming connection
		client_sock_fd = accept(serv_sock_fd, (struct sockaddr *)&conn_addr, &conn_addr_len);
		if(client_sock_fd ==-1)
		{
			//If no incoming connection, graceful termination done
			close_all();
			exit(-1);
		}
		
		//Below line of code reference: https://beej.us/guide/bgnet/html/
		//Check if the connection address family is IPv4 or IPv6 and retrieve accordingly
		//Convert the binary to text before logging 
		inet_ntop(AF_INET, get_in_addr((struct sockaddr *)&conn_addr), IP_addr, sizeof(IP_addr));
        syslog(LOG_DEBUG,"Accepted connection from %s", IP_addr);   
			
		//Allocates buffer and initializes value to 0, same as malloc
		char *buf_data=calloc(CHUNK_SIZE,sizeof(char));
		if(buf_data==NULL)
		{
			syslog(LOG_ERR,"Error: malloc failed");
			close_all();
			exit(-1);
		}
		int loc=0;

		//block the signals before recieving packets and sending back
		int merr=sigprocmask(SIG_BLOCK, &socket_set, NULL);
		if(merr == -1)
		{
			perror("sigprocmask block error");
			close_all();
			exit(-1);
		}
		//Recieve the data and store in updated location always if available
		while((len=recv(client_sock_fd , buf_data + loc , CHUNK_SIZE , 0))>0)
		{
			if(len == -1)
			{
				perror("recv error");
				close_all();
				exit(-1);
			}
			
			if(strchr(buf_data ,'\n') != NULL)
				break;
			//Update the current location if newline not found
			loc+=len;
			
			//if no new line character, need to add more memory and dynamically
			//reallocate with an extra chunk
			counter++;
			buf_data=(char*)realloc(buf_data,((counter*CHUNK_SIZE)*sizeof(char)));
			if(buf_data==NULL)
			{
				syslog(LOG_ERR,"Error: realloc failed");
				close_all();
				exit(-1);
			}
		}

			
		//Write to file and position is updated
		int werr = write(output_file_fd,buf_data,strlen(buf_data));
		if (werr == -1)
		{
			perror("write error");
			close_all();
			exit(-1);
		}
		

		
		//Store last position of file
		//int last_position = lseek(output_file_fd, 0, SEEK_CUR);
		total_length += (strlen(buf_data));
		//Place position ot beginnging
		lseek(output_file_fd, 0, SEEK_SET);
		char * send_data_buf=calloc(total_length,sizeof(char));
		
		
		int rerr=read(output_file_fd,send_data_buf,total_length);
		syslog(LOG_DEBUG,"%d",total_length);
		if (rerr == -1)
		{
			perror("read error");
			close_all();
			exit(-1);
		}
		
		syslog(LOG_DEBUG,"%s",send_data_buf);
		//Send contents of buffer to client back
		int serr=send(client_sock_fd,send_data_buf,total_length, 0);
		if(serr == -1)
		{
			close_all();
			perror("send error");
			exit(-1);
		}

		//Once complete, buffer cleared
		free(buf_data);
		free(send_data_buf);
		
		//Unblock the set of signals once complete
		merr=sigprocmask(SIG_UNBLOCK, &socket_set, NULL);
		if(merr == -1)
		{
			perror("sigprocmask unblock error");
			close_all();
			exit(-1);
		}
    }
	return 0;
}	