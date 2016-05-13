#include "common.h"


// check msg number in one receive action
int checkMsgNum(char *buf, char *needle){
	int count = 0;
	char *p;
	p = strstr(buf,needle);
	while(p != NULL){
		count++;
		p = p + strlen(needle);
		p = strstr(p,needle);
	}

	return count;
}

// the length of body should be enough
int wrap_message(char *verb, char *body, int v_flag) {
	if (verb == NULL || body == NULL) {
		ERRORS("bad parameter in wrap");
		DEFAULT("\n");
		return -1;
	}
	char temp[MAXLINE];
	bzero(temp, sizeof(temp));
	strcat(temp, verb);
	if (strlen(body) != 0) {
		strcat(temp, " ");
		strcat(temp, body);
	}
	strcat(temp, " \r\n\r\n");
	bzero(body, strlen(body)); // test
	strcpy(body, temp);
	if(v_flag == 1)  printf("OUT:%s",body);
	return 0;
}

int unwrap_message(char *verb, char *body, int v_flag) {
	
	if (verb == NULL || body == NULL) {
		ERRORS("bad parameter in unwrap");
		DEFAULT("\n");
		return -1;
	}
	if (strncmp(verb, body, strlen(verb)) != 0) {
		return -1;
	}

	if(v_flag == 1)  printf(" IN:%s",body);

	char *p = body + strlen(verb);
	char *tail = strstr(p, " \r\n\r\n");
	if (tail == NULL) {
		ERRORS("protocol error in unwrap");
		DEFAULT("\n");
		return -1;
	}
	*tail = '\0';
	if (p[0] == ' ') {
		p = p + 1;
	}
	strcpy(body, p);
	return 0;
}

int send_message(int fd, char *message) {
	if (write(fd, message, strlen(message)) == -1) {
		ERRORS("send message failed %s", strerror(errno));
		DEFAULT("\n");
		return -1;
	}
	return 0;
}

int recv_message(int fd, char *message) {
	fd_set rset;
	FD_ZERO(&rset);
	FD_SET(fd, &rset);

	int ret = read(fd, message, MAXLINE);
	if (ret == -1) {
		ERRORS("recv message failed %s", strerror(errno));
		DEFAULT("\n");
		return -1;
	}
	if (ret == 0) {
		VERBOSE("peer terminated fd:%d", fd);
		DEFAULT("\n");
		return -1;
	}
	return 0;
}

int wrap_send_message(int fd, char *verb, char *body, int v_flag) {
	if (wrap_message(verb, body, v_flag) == -1) {
		return -1;
	}
	if (send_message(fd, body) == -1) {
		return -1;
	}
	return 0;
}

int recv_unwrap_message(int fd, char *verb, char *body, int v_flag) {
	if (recv_message(fd, body) == -1) {
		return -1;
	}
	if (unwrap_message(verb, body, v_flag) == -1) {
		return -1;
	}
	return 0;
}
