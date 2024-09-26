#include "proxy_parse.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/wait.h>

#define QUEUE_LENGTH 10
#define RECV_BUFFER_SIZE 2048

void sigchld_handler(int s) {
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int proxy(char *proxy_port) {
    int sockfd_server, new_fd_client;
    int rv;
    int true_add = 1;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage client_addr;
    socklen_t sin_size;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(NULL, proxy_port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
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

    if (p == NULL) {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd_server, QUEUE_LENGTH) == -1) {
        perror("listen");
        exit(1);
    }

    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    while (1) {
        sin_size = sizeof client_addr;
        new_fd_client = accept(sockfd_server, (struct sockaddr *)&client_addr, &sin_size);
        if (new_fd_client == -1) {
            perror("error");
            continue;
        }

        pid_t pid = fork();
        if (pid == -1) {
            perror("fork error");
            close(new_fd_client);
            continue;
        } 
        
        if (pid == 0) {
            close(sockfd_server);

            char recv_buffer[RECV_BUFFER_SIZE];
            ssize_t num_bytes_recv;
            struct ParsedRequest *request = ParsedRequest_create();
            // num_bytes_recv = recv(new_fd_client, recv_buffer, sizeof(recv_buffer), 0);
            char *end_of_request = "\r\n\r\n";
            char *ptr;
            size_t bytes_received = 0;
            while ((ptr = strstr(recv_buffer, end_of_request)) == NULL) {
                num_bytes_recv = recv(new_fd_client, recv_buffer + bytes_received, sizeof(recv_buffer) - bytes_received, 0);
                if (num_bytes_recv <= 0) {
                    perror("recv");
                    close(new_fd_client);
                    ParsedRequest_destroy(request);
                    exit(0);
                }
                bytes_received += num_bytes_recv;
                recv_buffer[bytes_received] = '\0';
            }

            if (ParsedRequest_parse(request, recv_buffer, bytes_received) < 0) {
                char *res = "HTTP/1.0 400 Bad Request\r\n\r\n";
                send(new_fd_client, res, strlen(res), 0);
                close(new_fd_client);
                ParsedRequest_destroy(request);
                exit(1);
            }

                char *host = request->host;
                char *port = request->port ? request->port : "80";
                char *path = request->path ? request->path : "/";


                if (strcmp(request->method, "GET") != 0) {
                    char *res = "HTTP/1.0 501 Not Implemented\r\n\r\n";
                    send(new_fd_client, res, strlen(res), 0);
                    close(new_fd_client);
                    ParsedRequest_destroy(request);
                    exit(0);
                }
                char request_to_server[RECV_BUFFER_SIZE];
                sprintf(request_to_server, "GET %s HTTP/1.0\r\nHost: %s:%s\r\nConnection: close\r\n\r\n", path, host, port);

                int sockfd_remote;
                struct addrinfo *res;
                if (getaddrinfo(host, port, &hints, &res) != 0) {
                    perror("getaddrinfo");
                    close(new_fd_client);
                    ParsedRequest_destroy(request);
                    exit(1);
                }
                sockfd_remote = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
                if (sockfd_remote == -1) {
                    perror("socket");
                    close(new_fd_client);
                    ParsedRequest_destroy(request);
                    exit(1);
                }
                if (connect(sockfd_remote, res->ai_addr, res->ai_addrlen) == -1) {
                    perror("connect");
                    close(new_fd_client);
                    close(sockfd_remote);
                    ParsedRequest_destroy(request);
                    exit(1);
                }

                //send
                if (send(sockfd_remote, request_to_server, strlen(request_to_server), 0) == -1) {
                    perror("send");
                    close(new_fd_client);
                    close(sockfd_remote);
                    ParsedRequest_destroy(request);
                    exit(1);
                }

                // back to client
                ssize_t num_bytes_sent;
                while ((num_bytes_recv = recv(sockfd_remote, recv_buffer, sizeof(recv_buffer), 0)) > 0) {
                    num_bytes_sent = send(new_fd_client, recv_buffer, num_bytes_recv, 0);
                    if (num_bytes_sent == -1) {
                        perror("send");
                        close(new_fd_client);
                        close(sockfd_remote);
                        ParsedRequest_destroy(request);
                        exit(1);
                    }
                }
                if (num_bytes_recv == 0) {
                    //
                } 
                else if (num_bytes_recv == -1) {
                    perror("recv");
                    close(new_fd_client);
                    close(sockfd_remote);
                    ParsedRequest_destroy(request);
                    exit(1);
                }

                close(sockfd_remote);
                ParsedRequest_destroy(request);
                close(new_fd_client);
                exit(0);
        }
        close(new_fd_client);
    } 
    return 0;
}

    
int main(int argc, char * argv[]) {
    char *proxy_port;

    if (argc != 2) {
        fprintf(stderr, "Usage: ./proxy <port>\n");
        exit(EXIT_FAILURE);
    }

    proxy_port = argv[1];
    return proxy(proxy_port);
}