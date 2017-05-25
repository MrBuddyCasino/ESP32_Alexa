/*
 * asio_socket.c
 *
 *  Created on: 23.05.2017
 *      Author: michaelboeckling
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

#include "network.h"

#define SOCKET             int
#define INVALID_SOCKET     (-1)


int asio_socket_connect(const char *host, uint16_t n_port, bool verbose)
{
    struct addrinfo hints, *si, *p;
    SOCKET fd;
    int err;

    /* port to string */
    const char port[6];
    itoa(n_port, (char*) &port, 10);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    err = getaddrinfo(host, port, &hints, &si);
    if (err != 0) {
        fprintf(stderr, "ERROR: getaddrinfo(): %d\n", err);
        return INVALID_SOCKET;
    }
    fd = INVALID_SOCKET;
    for (p = si; p != NULL; p = p->ai_next) {
        if (verbose) {
            struct sockaddr *sa;
            void *addr;
            char tmp[INET6_ADDRSTRLEN + 50];

            sa = (struct sockaddr *)p->ai_addr;
            if (sa->sa_family == AF_INET) {
                addr = &((struct sockaddr_in *)sa)->sin_addr;
            } else if (sa->sa_family == AF_INET6) {
                addr = &((struct sockaddr_in6 *)sa)->sin6_addr;
            } else {
                addr = NULL;
            }
            if (addr != NULL) {
                if (!inet_ntop(p->ai_family, addr,
                    tmp, sizeof tmp))
                {
                    strcpy(tmp, "<invalid>");
                }
            } else {
                sprintf(tmp, "<unknown family: %d>",
                    (int)sa->sa_family);
            }
            fprintf(stderr, "connecting to: %s\n", tmp);
        }
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd == INVALID_SOCKET) {
            if (verbose) {
                perror("socket()");
            }
            continue;
        }
        if (connect(fd, p->ai_addr, p->ai_addrlen) == INVALID_SOCKET) {
            if (verbose) {
                perror("connect()");
            }

            close(fd);

            continue;
        }
        break;
    }
    if (p == NULL) {
        freeaddrinfo(si);
        fprintf(stderr, "ERROR: failed to connect\n");
        return INVALID_SOCKET;
    }
    freeaddrinfo(si);
    if (verbose) {
        fprintf(stderr, "connected.\n");
    }

    /*
     * We make the socket non-blocking, since we are going to use
     * poll() or select() to organise I/O.
     */
    fcntl(fd, F_SETFL, O_NONBLOCK);

    return fd;
}
