
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

#define SEND_BUFFER_SIZE 2048


// COMMAND TO TESTOUT LOCALLY
// gcc server.c -o server 
// ./server 8082 > server_output

// gcc client.c -o server 
// ./client 10.0.0.188 8082 <test.txt
// ./client 10.203.33.39 8086 <test.txt
//

/* TODO: client()
 * Open socket and send message from stdin.
 * Return 0 on success, non-zero on failure
*/

int client(char *server_ip, char *server_port) {
    int sockfd, numbytes;  
    char buf[SEND_BUFFER_SIZE];
    struct addrinfo hints, *servinfo, *p;
    int rv; //return value

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(server_ip, server_port, &hints, &servinfo)) != 0) {
       fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
       return 1; 
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
    }

    if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
        close(sockfd);
        perror("client: connect");
        continue;
    }
    break;
}

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        return 2;
    }

    // printf("client: connecting");
    freeaddrinfo(servinfo);  

    // read then send stdin to server
    long send_content;
    while ((send_content = read(STDIN_FILENO, buf, SEND_BUFFER_SIZE)) > 0) {
        if (send(sockfd, buf, send_content, 0) == -1) {
            perror("Error: send failed");
            exit(1);
        }
    }
    if (send_content == -1) {
        perror("Error: stdin failed");
        exit(1);
    }

    close(sockfd);
    return 0;
}

/*
 * main()
 * Parse command-line arguments and call client function
*/
int main(int argc, char **argv) {
  char *server_ip;
  char *server_port;

  if (argc != 3) {
    fprintf(stderr, "Usage: ./client-c [server IP] [server port] < [message]\n");
    exit(EXIT_FAILURE);
  }

  server_ip = argv[1];
  server_port = argv[2];
  return client(server_ip, server_port);
}