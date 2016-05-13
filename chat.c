#include "common.h"
#include <time.h>
#include <sys/file.h>
#include "sfwrite.h"

static int chatfd = -1;
static int peer_logout = 0;

static int file_fd = -1;
static FILE *logfile = NULL;
static char *username = NULL;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static char Time[18] = {'\0'};

void getTime(char *timebuf){
   time_t rawtime;
   struct tm *timeinfo;
   time( &rawtime );
   char tbuf[18];
   timeinfo = localtime(&rawtime);
   strftime(tbuf,18,"%x-%I:%M%p", timeinfo);
   strcpy(timebuf,tbuf);
   bzero(tbuf,strlen(tbuf));
}

void input_handler() {
	char buf[MAXLINE] = {'\0'};
	if (fgets(buf, MAXLINE, stdin) == NULL) {
		return;
	}
	buf[strlen(buf)-1] = '\0';
	if (strncmp(buf, "/close", strlen(buf)-1) == 0) {
		/*************hw6 audit*******************/
		getTime(Time);
		flock(file_fd,LOCK_EX);
		sfwrite(lock,logfile,"%s, %s, CMD, /close, sucess, chat\n",Time,username);
		flock(file_fd,LOCK_UN);
		bzero(Time,18);
		/*************hw6 audit*******************/	
		close(chatfd);
		exit(EXIT_SUCCESS);
	}
	if (peer_logout) {
		exit(EXIT_SUCCESS);
	}
	if (write(chatfd, buf, strlen(buf)) == -1) {
		ERRORS("write error:%s\n", strerror(errno));
	}
}

void output_handler() {
	char buf[MAXLINE] = {'\0'};
	if (read(chatfd, buf, sizeof(buf)) == -1) {
		ERRORS("read error:%s\n", strerror(errno));
		return;
	}
	if (buf[0] != '<' && buf[0] != '>') {
		peer_logout = 1;
	}
	DEFAULT("%s", buf);
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		ERRORS("Bad argv, should be ./chat [fd].\n");
		exit(EXIT_FAILURE);
	}

	chatfd = atoi(argv[1]);
	/**********hw6 audit**************/
	file_fd = atoi(argv[2]);
	username = argv[3];
	logfile = fdopen(file_fd, "a+");
	/**********hw6 audit**************/

	int maxfd;
	fd_set rset;
	while (1) {
		FD_SET(chatfd, &rset);
		FD_SET(fileno(stdin), &rset);
		maxfd = chatfd;
		select(maxfd + 1, &rset, NULL, NULL, NULL);
		if (FD_ISSET(fileno(stdin), &rset)) {
			input_handler();
		}
		if (FD_ISSET(chatfd, &rset)) {
			output_handler();
		}
	}
	return 0;
}
