#include "common.h"
#include "client.h"
#include "sfwrite.h"
// get time and flock
#include <time.h>
#include <sys/file.h>


int opt;
int c_flag = 0;
int v_flag = 0;
int a_flag=0;
int file_fd = -1;
static char* server_ip;
static char motd[MAXLINE]={'\0'};
int server_port;
static FILE *logfile=NULL;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct PEER {
	const char *username;
	int fd;
	pid_t pid;
	struct PEER *next;
} PEER;

static char *username = NULL;
static PEER *peer_list_head = NULL;


void getTime(char *buf){
   time_t rawtime;
   struct tm *timeinfo;
   time( &rawtime );
   char tbuf[18];
   timeinfo = localtime(&rawtime);
   strftime(tbuf,18,"%x-%I:%M%p", timeinfo);
   strcpy(buf,tbuf);
   bzero(tbuf,strlen(tbuf));
}



void delete_peer1(const char *username1){
	PEER *tmp_user=peer_list_head;
	PEER *prev_user=NULL;
	PEER *del_user=NULL;

	while(tmp_user!=NULL){
		/*find user*/
		if(strcmp(tmp_user->username,username1)==0){
			del_user=tmp_user;
			break;
		}

		prev_user=tmp_user;
		tmp_user=tmp_user->next;
	}

	/*delete user*/
	if(del_user!=NULL){
		if(prev_user==NULL){
			peer_list_head=del_user->next;
		}
		else{
			prev_user->next=del_user->next;
		}
		free(del_user);
	}

}

void free_all_peer(PEER *user_list_head1){
	PEER *user_temp=user_list_head1;
	if(user_temp==NULL){
		return;
	}
	else{
		free_all_peer(user_temp->next);
		delete_peer1(user_temp->username);
		return;
	}
}



void print_usage() {
	printf("./client [-hcv] [-a FILE] NAME SERVER_IP SERVER_PORT\n");
	printf("-a FILE       Path to the audit log file.\n");
	printf("-h            Displays help menu & returns EXIT_SUCCESS.\n");
	printf("-c            Requests to server to create a new user\n");
	printf("-v            Verbose print all incoming and outgoing protocol verbs & content.\n");
	printf("NAME          The username to display when chatting.\n");
	printf("SERVER_IP     The ipaddress of server to connect to.\n");
	printf("SERVER_PORT   The port to connect to.\n");
}

void print_client_command_usage(){
	printf("%s\n", "/time");
	printf("%s\n", "/help");
	printf("%s\n", "/logout");
	printf("%s\n", "/listu");
	printf("%s\n", "/chat <to> <msg>");
	printf("%s\n", "/audit");
}

void message_handler(int fd) {
	char buf[MAXLINE] = { '\0' };
	if (recv_message(fd, buf) == -1) {
		close(fd);
		exit(EXIT_FAILURE);
	}

	if(unwrap_message("INTERNAL SERVER ERROR",buf, v_flag) == 0){ 
		ERRORS("Internet server error!");
		close(fd);

		/*************hw6 audit*******************/
		char Time[16];
		getTime(Time);
		flock(file_fd,LOCK_EX);
		sfwrite(lock,logfile,"%s, %s, LOGOUT, error: internal server error\n",Time,username);
		flock(file_fd,LOCK_UN);
		bzero(Time,18);
		/*************hw6 audit*******************/
		exit(EXIT_FAILURE);
	}

	if (unwrap_message("BYE", buf, v_flag) == 0) {
		close(fd);

		/*************hw6 audit*******************/
		char Time[16];
		getTime(Time);
		flock(file_fd,LOCK_EX);
		sfwrite(lock,logfile,"%s, %s, LOGOUT, intentional\n",Time,username);
		flock(file_fd,LOCK_UN);
		bzero(Time,18);
		/*************hw6 audit*******************/
		exit(EXIT_SUCCESS);
	}

	if (unwrap_message("ERR 01 USER NOT AVAILABLE",buf, v_flag) == 0){
		ERRORS("This user is not available!");
		DEFAULT("\n");
		bzero(buf, sizeof(buf));
		return;
	}
	
	if (unwrap_message("UOFF", buf, v_flag) == 0) {
		char *peer_name = strdup(buf);
		PEER *temp = peer_list_head;
		while (temp != NULL) {
			if (strcmp(temp->username, buf) == 0) {
				bzero(buf, sizeof(buf));
				strcat(buf, peer_name);
				strcat(buf, " has been logged off, press any press to exit.");
				write(temp->fd, buf, strlen(buf));
				close(temp->fd);
				temp->fd = -1;
				break;
			}
			temp = temp->next;
		}
		bzero(buf, sizeof(buf));
		return;
	}

	if (unwrap_message("MSG", buf, v_flag) == 0) {		
		char *p = strtok(buf, " ");
		char *to, *from, *msg;
		if (p == NULL) {
			return;
		}
		to = strdup(p);
		p = strtok(NULL," ");
		if (p == NULL) {
			return;
		}
		from = strdup(p);
		p = strtok(NULL, ""); 
		msg = strdup(p);
		char *peername;
		if (strncmp(to, username, strlen(username)) == 0) {
			peername = from;

		} else {
			peername = to;
		}
		PEER *temp = peer_list_head;
		while (temp != NULL) {
			if (strcmp(temp->username, peername) == 0) {
				break;
			}
			temp = temp->next;
		}
		// peername not found
		if (temp == NULL) {
			temp = malloc( sizeof(PEER));
			temp->username = peername;
			temp->fd = -1;
			if (peer_list_head == NULL) {
				temp->next = NULL;
			} else {
				temp->next = peer_list_head;
			}
			peer_list_head = temp;
		}
		if (temp->fd == -1) {
			int pairs[2];
			if (socketpair(AF_UNIX, SOCK_STREAM, 0, pairs) == -1) {
				ERRORS("socketpair failed!%s", strerror(errno));
				DEFAULT("\n");
				return;
			}
			temp->fd = pairs[1];
			pid_t fpid = fork();
			temp->pid = fpid;
			if(fpid != 0) printf("pid: %d process is created....\n",fpid);//modify
			if (fpid == 0) {
				close(pairs[1]);
				char fdstr[16];
				sprintf(fdstr, "%d", pairs[0]);
				/**********hw6 audit************/
				char auditfd[16];
				sprintf(auditfd,"%d", file_fd);
				/**********hw6 audit************/

				if (execlp("xterm", "xterm", "-geometry", "45x35", "-T", peername,
						"-e", "./chat", fdstr, auditfd,username,NULL) == -1) {
					ERRORS("execv failed!%s", strerror(errno));
					DEFAULT("\n");
				}
			}
			close(pairs[0]);
		}
		char Time[16];
		bzero(buf, sizeof(buf));
		if (strncmp(from, username, strlen(username)) == 0) {
			/*************hw6 audit*******************/
			getTime(Time);
			flock(file_fd,LOCK_EX);
			sfwrite(lock,logfile,"%s, %s, MSG, to, %s, %s\n",Time,username,peername,msg);
			flock(file_fd,LOCK_UN);
			bzero(Time,18);
		   /*************hw6 audit*******************/
			strcat(buf, "< ");
			strcat(buf, msg);
			strcat(buf, "\n");

		} else {
			/*************hw6 audit*******************/
			getTime(Time);
			flock(file_fd,LOCK_EX);
			sfwrite(lock,logfile,"%s, %s, MSG, from, %s, %s\n",Time,username,peername,msg);
			flock(file_fd,LOCK_UN);
			bzero(Time,18);
			/*************hw6 audit*******************/
			strcat(buf, "> ");
			strcat(buf, msg);
			strcat(buf, "\n"); 

		}
		write(temp->fd, buf, strlen(buf));
		bzero(buf, sizeof(buf));		
	}
}

void input_handler(int fd) {
	char buf[MAXLINE] = { '\0' };

	if (fgets(buf, MAXLINE, stdin) == NULL) {
		return;
	}
	buf[strlen(buf)-1] = '\0';

	if(strcmp(buf,"\0")==0){
		return;
	}
	
	if (strncmp(buf, "/time", strlen("/time")) == 0) {
		bzero(buf, sizeof(buf));
		if (wrap_send_message(fd, "TIME", buf, v_flag) == -1) {
			return;
		}
		bzero(buf, sizeof(buf));
		if (recv_unwrap_message(fd, "EMIT", buf, v_flag) == -1) {
			return;
		}
		int hour = 0;
		int minute = 0;
		int second = atoi(buf);
		int temp = 0;
		hour = second/3600;
		temp = second%3600;
		minute = temp/60;
		second = temp%60;
		VERBOSE("connected for %d hour(s), %d minute(s), and %d second(s).\n", hour,minute,second);
		DEFAULT("\n");

		/*************hw6 audit*******************/
		char Time[16];
		getTime(Time);
		flock(file_fd,LOCK_EX);
		sfwrite(lock,logfile,"%s, %s, CMD, /time, sucess, client\n",Time,username);
		flock(file_fd,LOCK_UN);
		bzero(Time,18);
		/*************hw6 audit*******************/


		return;
	}

	if (strncmp(buf, "/help", strlen("/help")) == 0) {
		bzero(buf, sizeof(buf));
		VERBOSE("Command Menu: \n");
		print_client_command_usage();
		DEFAULT("\n");

		/*************hw6 audit*******************/
		char Time[16];
		getTime(Time);
		flock(file_fd,LOCK_EX);
		sfwrite(lock,logfile,"%s, %s, CMD, /help, sucess, client\n",Time,username);
		flock(file_fd,LOCK_UN);
		bzero(Time,18);
		/*************hw6 audit*******************/
		return;
	}

	if (strncmp(buf, "/logout", strlen("/logout")) == 0) {
		bzero(buf, sizeof(buf));
		if (wrap_send_message(fd, "BYE", buf, v_flag) == -1) {
			return;
		}
		bzero(buf, sizeof(buf));
		if (recv_unwrap_message(fd, "BYE", buf, v_flag) == -1) {
			return;
		}
		PEER *temp = peer_list_head;
		while (temp != NULL) {
			if (temp->pid > 0) {
				kill(temp->pid, 9);
			}
			temp = temp->next;
		}
		close(fd);
		free_all_peer(peer_list_head);

		/*************hw6 audit*******************/
		char Time[16];
		getTime(Time);
		flock(file_fd,LOCK_EX);
		sfwrite(lock,logfile,"%s, %s, CMD, /logout, sucess, client\n",Time,username);
		flock(file_fd,LOCK_UN);
		bzero(Time,18);
		/*************hw6 audit*******************/
		/*************hw6 audit*******************/
		getTime(Time);
		flock(file_fd,LOCK_EX);
		sfwrite(lock,logfile,"%s, %s, LOGOUT, intentional\n",Time,username);
		flock(file_fd,LOCK_UN);
		bzero(Time,18);
		/*************hw6 audit*******************/

		exit(EXIT_SUCCESS);
	}

	if (strncmp(buf, "/listu", strlen("/listu")) == 0) {
		bzero(buf, sizeof(buf));
		if (wrap_send_message(fd, "LISTU", buf, v_flag) == -1) {
			return;
		}
		if (recv_unwrap_message(fd, "UTSIL", buf, v_flag) == -1) {
			return;
		}
		VERBOSE("Current users:\n%s", buf);
		DEFAULT("\n");

		/*************hw6 audit*******************/
		char Time[16];
		getTime(Time);
		flock(file_fd,LOCK_EX);
		sfwrite(lock,logfile,"%s, %s, CMD, /listu, success, client\n",Time,username);
		flock(file_fd,LOCK_UN);
		bzero(Time,18);
		/*************hw6 audit*******************/
		return;
	}

	if (strncmp(buf, "/chat", strlen("/chat")) == 0) {
		char temp[MAXLINE]={'\0'};
		strcpy(buf, buf + strlen("/chat "));

		char *p = strtok(buf, " ");
		if (p == NULL) {
			ERRORS("Invalid command,please format: /chat <to> <msg>");
			DEFAULT("\n");
			bzero(buf, sizeof(buf));
			return;
		}

		strcat(temp, p);
		strcat(temp, " ");
		strcat(temp, username);
		strcat(temp, " ");
		p = strtok(NULL, " ");
		if(p == NULL){
			ERRORS("Invalid command,please format: /chat <to> <msg>");
			DEFAULT("\n");
			bzero(buf, sizeof(buf));
			return;
		}
		while (p != NULL) {
			strcat(temp, p);
			strcat(temp, " ");
			p = strtok(NULL, " ");
		}
		if (strlen(temp) == 0) {
			print_client_command_usage();
			bzero(buf, sizeof(buf));
			return;
		}	

		if (wrap_send_message(fd, "MSG", temp, v_flag) == -1) {
			return;
		}
		
		/*************hw6 audit*******************/
		char Time[16];
		getTime(Time);
		flock(file_fd,LOCK_EX);
		sfwrite(lock,logfile,"%s, %s, CMD, /chat, sucess, client\n",Time,username);
		flock(file_fd,LOCK_UN);
		bzero(Time,18);
		/*************hw6 audit*******************/
		return;
	}

	if (strncmp(buf, "/audit", strlen("/audit")) == 0) {
		
		/*************hw6 audit*******************/
		flock(file_fd,LOCK_EX);
		Read_Audit(logfile);
		flock(file_fd,LOCK_UN);
		/*************hw6 audit*******************/	
		bzero(buf, sizeof(buf));
		return;
	}

	
	ERRORS("%s:Invalid Command!\n",buf);
	VERBOSE("Command Menu:\n");
	print_client_command_usage();
	DEFAULT("\n");

	/*************hw6 audit*******************/
	char Time[16];
	getTime(Time);
	flock(file_fd,LOCK_EX);
	sfwrite(lock,logfile,"%s, %s, CMD, %s, fail, client\n",Time,username,buf);
	flock(file_fd,LOCK_UN);
	bzero(Time,18);
	/*************hw6 audit*******************/
	return;
}

void chat_handler(int socket, int fd, const char *peername) {
	char buf[MAXLINE] = { '\0' };
	bzero(buf, sizeof(buf));
	int ret = read(fd, buf, sizeof(buf));

	if (ret == -1) {
		ERRORS("read failed! error:%s", strerror(errno));
		DEFAULT("\n");
		bzero(buf, sizeof(buf));
		return;
	}


	if(ret == 0){
		ERRORS("chat peer closed!");
		DEFAULT("\n");
		PEER *peer = peer_list_head;
		while (peer != NULL) {
			if (peer->fd == fd) {
				peer->fd = -1;
				if(kill(peer->pid,9) == 0){
					printf("%d: process was kill.\n",peer->pid);
				}
			}
			peer = peer->next;
		}
		bzero(buf, sizeof(buf));
		return;
	}


	char *msg = strdup(buf);
	bzero(buf, sizeof(buf));
	strcat(buf, peername);
	strcat(buf, " ");
	strcat(buf, username);
	strcat(buf, " ");
	strcat(buf, msg);
	if (wrap_send_message(socket, "MSG", buf, v_flag) == -1) {
		return;
	}
	bzero(buf, sizeof(buf));
	return;
}

int login_process(int fd, char *username) {
	char buf[MAXLINE] = { '\0' };
	if (wrap_send_message(fd, "WOLFIE", buf, v_flag) == -1) {
		return -1;
	}
	bzero(buf, sizeof(buf));
	if (recv_unwrap_message(fd, "EIFLOW", buf, v_flag) == -1) {
		return -1;
	}
	bzero(buf, sizeof(buf));
	if (c_flag) {
		strcpy(buf, username);
		if (wrap_send_message(fd, "IAMNEW", buf, v_flag) == -1) {
			return -1;
		}
		bzero(buf, sizeof(buf));
		if (recv_message(fd, buf) == -1) {
			return -1;
		}
		// login failed
		int checkMsg = checkMsgNum(buf,"\r\n\r\n");
		if(checkMsg == 2){
			char *msg1;
			char *tem;
			msg1 = strstr(buf,"\r\n\r\n");
	   		msg1 = msg1+4;
	    	tem = strndup(buf, strlen(buf) - strlen(msg1)); //get msg1
			if (unwrap_message("ERR 00 USERNAME TAKEN", tem, v_flag) == -1) {
				return -1;
			}
			if(unwrap_message("BYE",msg1,v_flag) == -1){
				return -1;
			}
			bzero(buf, sizeof(buf));
			close(fd);
			ERRORS("Failed login, username not avaliable.");
			DEFAULT("\n");
			
			/*************hw6 audit*******************/
			char Time[16];
			getTime(Time);
			flock(file_fd,LOCK_EX);
			sfwrite(lock,logfile,"%s, %s, LOGIN, %s:%d, fail, ERR 00 USERNAME TAKEN\n",Time,username,server_ip,server_port);
			flock(file_fd,LOCK_UN);
			bzero(Time,16);
			fclose(logfile);
			/*************hw6 audit*******************/	
			return -1; 
		}

		if (unwrap_message("ERR 00 USERNAME TAKEN", buf, v_flag) == 0) {
			bzero(buf, sizeof(buf));
			recv_unwrap_message(fd, "BYE", buf, v_flag);
			close(fd);
			ERRORS("Failed login, account already exist.");
			DEFAULT("\n");
			/*************hw6 audit*******************/
			char Time[16];
			getTime(Time);
			flock(file_fd,LOCK_EX);
			sfwrite(lock,logfile,"%s, %s, LOGIN, %s:%d, fial, ERR 00 USERNAME TAKEN\n",Time,username,server_ip,server_port);
			flock(file_fd,LOCK_UN);
			bzero(Time,16);
			fclose(logfile);
			/*************hw6 audit*******************/	
			return -1;
		} else if (unwrap_message("HINEW", buf, v_flag) == -1) {
			return -1;
		}
		bzero(buf, sizeof(buf));
		char *pass = getpass("Please enter new password: ");

		if (wrap_send_message(fd, "NEWPASS", pass, v_flag) == -1) {
			return -1;
		}

		bzero(buf, sizeof(buf));

		if (recv_message(fd, buf) == -1) {
			return -1;
		}

		// check msg number 
		char *msg1,*msg2,*msg3;
		char *tem;
		msg1 = strstr(buf,"\r\n\r\n");
    	msg1 = msg1+4;
    	tem = strndup(buf, strlen(buf) - strlen(msg1)); //get msg1

		if (unwrap_message("ERR 02 BAD PASSWORD", tem, v_flag) == 0) {
			bzero(buf, sizeof(buf));
			recv_unwrap_message(fd, "BYE", buf, v_flag);
			close(fd);
			ERRORS("Failed login, bad password.");
			DEFAULT("\n");
			bzero(buf, sizeof(buf));
			/*************hw6 audit*******************/
			char Time[16];
			getTime(Time);
			flock(file_fd,LOCK_EX);
			sfwrite(lock,logfile,"%s, %s, LOGIN, %s:%d, fial, ERR 02 BAD PASSWORD\n",Time,username,server_ip,server_port);
			flock(file_fd,LOCK_UN);
			bzero(Time,16);
			fclose(logfile);
			/*************hw6 audit*******************/	
			return -1;
		} else if (unwrap_message("SSAPWEN", tem, v_flag) == -1) {
			return -1;
		}

    	msg2 = strstr(msg1,"\r\n\r\n");
    	if(msg2 != NULL){  // second msg come with it
    		msg2 = msg2+4;
			tem = strndup(msg1,strlen(msg1) - strlen(msg2)); //get msg2
			if (unwrap_message("HI", tem, v_flag) == -1) {
				return -1;
			}

			msg3 = strstr(msg2,"\r\n\r\n");
			if(msg3 != NULL){  // third msg come with it
				msg3 = msg3 + 4;
				tem = strndup(msg2,strlen(msg2) - strlen(msg3)); //get msg3

				if (unwrap_message("MOTD", tem, v_flag) == -1) {
					return -1;
				}
				/*********add global motd***********/
				strcpy(motd,tem);				
				/*********add global motd***********/
				VERBOSE("MOTD: %s", tem);
				DEFAULT("\n");
				return 0;

			}else{ //third msg NOT exit
				bzero(buf, sizeof(buf));
				if (recv_unwrap_message(fd, "MOTD", buf, v_flag) == -1) {
					return -1;
				}
				VERBOSE("MOTD: %s", buf);
				DEFAULT("\n");
				/*********add global motd***********/
				strcpy(motd,buf);				
				/*********add global motd***********/
				return 0;
			}
    	}else{  // second msg NOT exit
    		bzero(buf, sizeof(buf));	
    		if (recv_message(fd, buf) == -1) {
				return -1;
			}
			msg1 = strstr(buf, "\r\n\r\n");
			msg1 = msg1+4;
			tem = strndup(buf,strlen(buf) - strlen(msg1)); //get msg2
			if (unwrap_message("HI", tem, v_flag) == -1) {
				return -1;
			}
			msg2 = strstr(msg1, "\r\n\r\n");
			if(msg2 != NULL){  //third msg exit
				msg2 = msg2+4;
				tem = strndup(msg1,strlen(msg1) - strlen(msg2)); //get msg3
				if (unwrap_message("MOTD", tem, v_flag) == -1) {
					return -1;
				}
				VERBOSE("MOTD: %s", tem);
				DEFAULT("\n");
				/*********add global motd***********/
				strcpy(motd,tem);				
				/*********add global motd***********/
				return 0;
			}else{
				bzero(buf, sizeof(buf));
				if (recv_unwrap_message(fd, "MOTD", buf, v_flag) == -1) {
					return -1;
				}
				VERBOSE("MOTD: %s", buf);
				DEFAULT("\n");
				/*********add global motd***********/
				strcpy(motd,buf);				
				/*********add global motd***********/
				return 0;
			}

    	}

	}

	strcpy(buf, username);
	if (wrap_send_message(fd, "IAM", buf, v_flag) == -1) {
		return -1;
	}
	bzero(buf, sizeof(buf));
	if (recv_message(fd, buf) == -1) {
		return -1;
	}

	int checkMsg = checkMsgNum(buf,"\r\n\r\n");
	if(checkMsg == 2){
		char *msg1;
		char *tem;
		msg1 = strstr(buf,"\r\n\r\n");
   		msg1 = msg1+4;
    	tem = strndup(buf, strlen(buf) - strlen(msg1)); //get msg1
		if (unwrap_message("ERR 01 USER NOT AVAILABLE", tem, v_flag) == -1) {
			return -1;
		}
		if(unwrap_message("BYE",msg1,v_flag) == -1){
			return -1;
		}
		bzero(buf, sizeof(buf));
		close(fd);
		ERRORS("Failed login, username not avaliable.");
		DEFAULT("\n");
		/*************hw6 audit*******************/
		char Time[16];
		getTime(Time);
		flock(file_fd,LOCK_EX);
		sfwrite(lock,logfile,"%s, %s, LOGIN, %s:%d, fial, ERR 01 USER NOT AVAILABLE\n",Time,username,server_ip,server_port);
		flock(file_fd,LOCK_UN);
		bzero(Time,16);
		fclose(logfile);
		/*************hw6 audit*******************/	
		return -1; 
	}
	// login failed
	if (unwrap_message("ERR 00 USERNAME TAKEN", buf, v_flag) == 0) {
		bzero(buf, sizeof(buf));
		recv_unwrap_message(fd, "BYE", buf, v_flag);
		wrap_send_message(fd, "BYE", buf, v_flag);
		close(fd);
		ERRORS("Failed login, username already exist.");
		DEFAULT("\n");
		/*************hw6 audit*******************/
		char Time[16];
		getTime(Time);
		flock(file_fd,LOCK_EX);
		sfwrite(lock,logfile,"%s, %s, LOGIN, %s:%d, fial, ERR 00 USERNAME TAKEN\n",Time,username,server_ip,server_port);
		flock(file_fd,LOCK_UN);
		bzero(Time,16);
		fclose(logfile);
		/*************hw6 audit*******************/	
		return -1;
	} else if (unwrap_message("ERR 01 USER NOT AVAILABLE", buf, v_flag) == 0) {
		bzero(buf, sizeof(buf));
		if(recv_unwrap_message(fd, "BYE", buf, v_flag) == -1){
			return -1;
		}	
		close(fd);
		ERRORS("Failed login, username not avaliable.");
		DEFAULT("\n");
		/*************hw6 audit*******************/
		char Time[16];
		getTime(Time);
		flock(file_fd,LOCK_EX);
		sfwrite(lock,logfile,"%s, %s, LOGIN, %s:%d, fial, ERR 01 USER NOT AVAILABLE\n",Time,username,server_ip,server_port);
		flock(file_fd,LOCK_UN);
		bzero(Time,16);
		fclose(logfile);
		/*************hw6 audit*******************/	
		return -1;
	}  else if (unwrap_message("AUTH", buf, v_flag) == -1) {
		return -1;
	}

	char *pass = getpass("Please input your password: ");

	if (wrap_send_message(fd, "PASS", pass, v_flag) == -1) {
		return -1;
	}

	bzero(buf, sizeof(buf));
	if (recv_message(fd, buf) == -1) {
		return -1;
	}


	// check msg number 
	char *msg1,*msg2,*msg3;
	char *tem;
	msg1 = strstr(buf,"\r\n\r\n");
    msg1 = msg1+4;
    tem = strndup(buf, strlen(buf) - strlen(msg1)); //get msg1

	if (unwrap_message("ERR 02 BAD PASSWORD", tem, v_flag) == 0) {
		bzero(buf, sizeof(buf));
		recv_unwrap_message(fd, "BYE", buf, v_flag);
		close(fd);
		ERRORS("Failed login, bad password.");
		DEFAULT("\n");
		bzero(buf, sizeof(buf));
		/*************hw6 audit*******************/
		char Time[16];
		getTime(Time);
		flock(file_fd,LOCK_EX);
		sfwrite(lock,logfile,"%s, %s, LOGIN, %s:%d, fial, ERR 02 BAD PASSWORD\n",Time,username,server_ip,server_port);
		flock(file_fd,LOCK_UN);
		bzero(Time,16);
		fclose(logfile);
		/*************hw6 audit*******************/	
		return -1;
	} else if (unwrap_message("SSAP", tem, v_flag) == -1) {
		return -1;
	}

	msg2 = strstr(msg1,"\r\n\r\n");
	if(msg2 != NULL){  // second msg come with it
		msg2 = msg2+4;
		tem = strndup(msg1,strlen(msg1) - strlen(msg2)); //get msg2
		if (unwrap_message("HI", tem, v_flag) == -1) {
			return -1;
		}

		msg3 = strstr(msg2,"\r\n\r\n");
		if(msg3 != NULL){  // third msg come with it
			
			msg3 = msg3 + 4;
			tem = strndup(msg2,strlen(msg2) - strlen(msg3)); //get msg3
			if (unwrap_message("MOTD", tem, v_flag) == -1) {
				return -1;
			}

			VERBOSE("MOTD: %s", tem);
			DEFAULT("\n");
			/*********add global motd***********/
			strcpy(motd,tem);				
			/*********add global motd***********/
			return 0;

		}else{ //third msg NOT exit
			bzero(buf, sizeof(buf));
			if (recv_unwrap_message(fd, "MOTD", buf, v_flag) == -1) {
				return -1;
			}
			VERBOSE("MOTD: %s", buf);
			DEFAULT("\n");
			/*********add global motd***********/
			strcpy(motd,buf);				
			/*********add global motd***********/
			return 0;
		}
	}else{  // second msg NOT exit
		bzero(buf, sizeof(buf));	
		if (recv_message(fd, buf) == -1) {
			return -1;
		}
		msg1 = strstr(buf, "\r\n\r\n");
		msg1 = msg1+4;
		tem = strndup(buf,strlen(buf) - strlen(msg1)); //get msg2
		if (unwrap_message("HI", tem, v_flag) == -1) {
			return -1;
		}
		msg2 = strstr(msg1, "\r\n\r\n");
		if(msg2 != NULL){  //third msg exit

			msg2 = msg2+4;
			tem = strndup(msg1,strlen(msg1) - strlen(msg2)); //get msg3
			if (unwrap_message("MOTD", tem, v_flag) == -1) {
				return -1;
			}
			VERBOSE("MOTD: %s", tem);
			DEFAULT("\n");
			/*********add global motd***********/
			strcpy(motd,tem);				
			/*********add global motd***********/
			return 0;
		}else{
			bzero(buf, sizeof(buf));
			if (recv_unwrap_message(fd, "MOTD", buf, v_flag) == -1) {
				return -1;
			}
			VERBOSE("MOTD: %s", buf);
			DEFAULT("\n");
			/*********add global motd***********/
			strcpy(motd,buf);				
			/*********add global motd***********/
			return 0;
		}

	}
}

int main(int argc, char* argv[]) {
	char log_file_path[1024];
	while ((opt = getopt(argc, argv, "hcva:")) != -1) {
		switch (opt) {
		case 'h':
			print_usage();
			exit(EXIT_SUCCESS);
			break;
		case 'c':
			c_flag = 1;
			break;
		case 'v':
			v_flag = 1;
			break;
		case 'a':
            a_flag=1;
            strcpy(log_file_path,optarg);
            break;
		case '?':
		default:
			print_usage();
			exit(EXIT_FAILURE);
			break;
		}
	}


	// check number of argv
	if ((argc - optind + 1) != 4) {
		if ((argc - optind) < 3) {
			fprintf(stderr, "%s\n",
					"ERROR: The number of argument(s) given should not be less than 3.");
		} else if ((argc - optind) > 3) {
			fprintf(stderr, "%s\n",
					"ERROR: The number of arguments given should not be greater than 3.");
		}
		print_usage();
		exit(EXIT_FAILURE);
	}
	// check validation of port number
	char *endptr;
	strtol(argv[argc - 1], &endptr, 10);
	if (*endptr != '\0') {
		fprintf(stderr, "ERROR:%s is an invalid port number.\n",
				argv[argc - 2]);
		exit(EXIT_FAILURE);
	}


	if(a_flag==1){//input path
		logfile=fopen(log_file_path,"a+");
	}
	else{//default path: current dir
		logfile=fopen("audit.log","a+");
	}
	if(logfile==NULL){
		fprintf(stderr, "%s\n", "ERROR: fopen return NULL when open the log file");
		exit(EXIT_FAILURE);
	}

	file_fd = fileno(logfile);
	username = argv[argc - 3];
	server_ip = argv[argc - 2];
	server_port = atoi(argv[argc - 1]);

	int sockfd;
	struct sockaddr_in servaddr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(server_port);
	inet_pton(AF_INET, server_ip, &servaddr.sin_addr);

	if (connect(sockfd, (struct sockaddr*) &servaddr, sizeof(servaddr)) == -1) {
		printf("error in connect %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (login_process(sockfd, username) == -1) {
		close(sockfd);
		return 0;
	}

	/*************hw6 audit*******************/
	char Time[16];
	getTime(Time);
	flock(file_fd,LOCK_EX);
	sfwrite(lock,logfile,"%s, %s, LOGIN, %s:%d, success, %s\n",Time,username,server_ip,server_port, motd);
	flock(file_fd,LOCK_UN);
	bzero(Time,16);
	/*************hw6 audit*******************/	

	int maxfd;
	fd_set rset;
	/*************hw6 time inteval*****************/
	struct timeval tv;
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	/*************hw6 time inteval*****************/

	while (1) {
		FD_SET(fileno(stdin), &rset);
		FD_SET(sockfd, &rset);
		if (sockfd > maxfd) {
			maxfd = sockfd;
		}
		PEER *temp = peer_list_head;
		while (temp != NULL) {
			if (temp->fd > 0) {
				FD_SET(temp->fd, &rset);
				if (temp->fd > maxfd) {
					maxfd = temp->fd;
				}
			}
			temp = temp->next;
		}

		select(maxfd + 1, &rset, NULL, NULL, &tv);

		// socket is readable
		if (FD_ISSET(sockfd, &rset)) {
			message_handler(sockfd);
		}

		// stdin is readable
		if (FD_ISSET(fileno(stdin), &rset)) {
			input_handler(sockfd);
		}

		// chat socketpair fd is readable
		temp = peer_list_head;
		while (temp != NULL) {
			if (temp->fd > 0 && FD_ISSET(temp->fd, &rset)) {
				chat_handler(sockfd, temp->fd, temp->username);
			}
			temp = temp->next;
		}
	}
	fclose(logfile);
	return 0;
}
