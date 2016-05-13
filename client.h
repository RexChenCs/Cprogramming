#ifndef CLIENT_H
#define CLIENT_H

void print_usage();
void argv_handler();
void message_handler(int sockfd);
void input_handler(int sockfd);
void print_client_command_usage();
void getTime(char *buf);

#endif  //CLIENT_H
