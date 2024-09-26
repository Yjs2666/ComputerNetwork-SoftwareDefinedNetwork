#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <errno.h>

#define QUEUE_LENGTH 10
#define RECV_BUFFER_SIZE 2048

void sigchld_handler(int s){ 
    int saved_errno = errno;    
    while(waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa){
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }
  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int server(char *server_port) {
    int sockfd_server, new_fd_client;  
    int rv; //return value
    int true_add=1;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage client_addr; // client's address
    socklen_t sin_size;
    char writeFILE[RECV_BUFFER_SIZE];
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, server_port, &hints, &servinfo)) != 0) {          
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd_server = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }
        if (setsockopt(sockfd_server, SOL_SOCKET, SO_REUSEADDR, &true_add, sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }
        if (bind(sockfd_server, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd_server);
            perror("server: bind");
            continue;
        }
        break;
    }

    freeaddrinfo(servinfo); 

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd_server, QUEUE_LENGTH) == -1) {       //!!! backlog to QueLen
        perror("listen");
        exit(1);
    }

    printf("server: waiting for connections...\n");

    while(1) {   // main accept() loop
        sin_size = sizeof client_addr;
        new_fd_client = accept(sockfd_server, (struct sockaddr *)&client_addr, &sin_size);
        if (new_fd_client == -1) {
            perror("error");
            close(sockfd_server);        ////////////////////////
            exit(1);
        }

        long recv_content;
        while((recv_content = recv(new_fd_client, writeFILE, sizeof(writeFILE), 0)) > 0){
            write(1, writeFILE, recv_content);
        }
        // recv() returns the number of bytes read into the buffer
        // -1 on error.
        // 0 means remote side has closed the connection on you! 
        if(recv_content == 0){
          // Connection closed
        }
        else if(recv_content == -1){
          perror("recv");
        }
        else if(recv_content > 0){
          write(1, writeFILE, recv_content);
        }

        close(new_fd_client);
    }
  close(sockfd_server);
  return 0;
}

/*
 * main():
 * command-line arguments and call server function
*/
int main(int argc, char **argv) {
  char *server_port;

  if (argc != 2) {
    fprintf(stderr, "Usage: ./server-c [server port]\n");
    exit(EXIT_FAILURE);
  }

  server_port = argv[1];
  return server(server_port);
}
