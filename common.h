#ifndef COMMON_H
#define COMMON_H
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <ctype.h>


#define MAXLINE 8192
#define MAX_FD  1024

#define VERBOSE(x...)  fprintf(stdout, "\x1B[1;34m" x)
#define ERRORS(x...)   fprintf(stderr, "\x1B[1;31m" x)
#define DEFAULT(x...)  fprintf(stdout, "\x1B[0m" x)


// Error code table
#define USER_NAME_TAKEN       00
#define USER_NOT_AVAILABLE    01
#define BAD_PASSWORD          02
#define INTERNAL_SERVER_ERROR 100


int checkMsgNum(char *buf, char *needle); //check msg number receive
// the length of body should be enough
int wrap_message(char *verb, char *body, int v_flag);
int unwrap_message(char *verb, char *body, int v_flag);
int send_message(int fd, char *message);
int recv_message(int fd, char *message);
int wrap_send_message(int fd, char *verb, char *body, int v_flag);
int recv_unwrap_message(int fd, char *verb, char *body, int v_flag);

#endif // COMMON_H
