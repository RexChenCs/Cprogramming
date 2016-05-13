#include "common.h"
#include "server.h"
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sqlite3.h>
#include "sfwrite.h"

#include <semaphore.h>

int listenfd =-1;

typedef struct LOGIN_REQUEST{
	int connfd;
	struct LOGIN_REQUEST *prev;
} LOGIN_REQUEST;

struct LOGIN_REQUEST *login_request_list_end=NULL;
pthread_mutex_t Q_lock = PTHREAD_MUTEX_INITIALIZER;
sem_t items_sem;
char ACCOUNT_FILE_temp[1024]; 
int v_flag = 0;

static char* motd = NULL;

typedef struct USER {
	const char *username;
	time_t login_time;
	int fd;
	int active;
	struct USER *next;
} USER;

typedef struct ACCOUNT {
	char username[1024];
	char hash[1100];
	char salt[2];
	struct ACCOUNT *next;
} ACCOUNT;


static USER *user_list_head = NULL;
struct ACCOUNT *account_list_head = NULL;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t lock1 = PTHREAD_MUTEX_INITIALIZER;
static pthread_t comm_tid;

sqlite3 *database=NULL;
int is_there_account_return_from_select=0;
char username_temp1[1024];
char hash_temp1[1100];
char salt_temp1[2];

int open_database(char *database_name);
int create_table();
int drop_table();
void close_database();
int insert_into_table(char *username1,char *hash1,char *salt1);
int select_from_table(char *username1);
int print_all_from_table();
int callback(void *d,int argc,char **argv,char **azColName);
int callback2(void *d,int argc,char **argv,char **azColName);
int callback3(void *d,int argc,char **argv,char **azColName);
int table_to_list();
void hash_password(char *password1,char *hash_buf,char *salt_buf);
int is_same_password(char *password1,char *hash_temp,char *salt_temp);
ACCOUNT *add_account1(char *username1,char *hash1,char *salt1);
int load_accounts_file(char *accounts_file_name1);
int save_accounts_file(ACCOUNT *account_list_header1);
void save_helper(FILE *accounts_file,ACCOUNT *account_list_header1);

void decode(char *in,int len,char *out);
void encode(char *in,int len,char *out);


LOGIN_REQUEST *add_login_request(int connfd1){
	/*malloc space for the new request*/
	LOGIN_REQUEST *n_request=malloc(sizeof(struct LOGIN_REQUEST));
	if(n_request==NULL){
		fprintf(stderr, "%s\n", "ERROR: malloc return NULL");
		exit(EXIT_FAILURE);
	}
	/*add data for the new request*/
	n_request->connfd=connfd1;
	n_request->prev=login_request_list_end;

	/*put the new request at the end of the request list and return the new request*/
	login_request_list_end=n_request;
	return n_request;
}

int remove_login_request(){
	LOGIN_REQUEST *tmp_request=login_request_list_end;
	LOGIN_REQUEST *next_request=NULL;
	LOGIN_REQUEST *del_request=NULL;
	int connfd_temp=-1;
	while(tmp_request!=NULL){
		if(tmp_request->prev==NULL){
			del_request=tmp_request;
			break;
		}
		next_request=tmp_request;
		tmp_request=tmp_request->prev;
	}

	if(del_request!=NULL){
		connfd_temp=del_request->connfd;
		if(next_request==NULL){
			login_request_list_end=NULL;
		}
		else{
			next_request->prev=NULL;
		}
		free(del_request);
	}

	return connfd_temp;
}


void print_all_login_request(LOGIN_REQUEST *login_request_list_end1){
	LOGIN_REQUEST *request_temp=login_request_list_end1;
	if(request_temp==NULL){
		return;
	}
	else{
		print_all_login_request(request_temp->prev);
		printf("%d\n", request_temp->connfd);
		return;
	}
}


void free_all_login_request(){
	while(login_request_list_end!=NULL){

		int fd=remove_login_request();
		close(fd);

	}
}



void hash_password(char *password1,char *hash_buf,char *salt_buf){
	char password1_temp[1100];
	strcpy(password1_temp,password1);
	RAND_bytes((unsigned char *)salt_buf,1);
	strcat(password1_temp,salt_buf);
	SHA256((const unsigned char *)password1_temp, strlen(password1_temp),(unsigned char *)hash_buf);
}


/*return -1 if not same     1 if same*/
int is_same_password(char *password1,char *hash_temp,char *salt_temp){
	char password1_temp[1100];
	strcpy(password1_temp,password1);
	strcat(password1_temp,salt_temp);
	char hash_buf[1100];
	SHA256((const unsigned char *)password1_temp, strlen(password1_temp),(unsigned char *)hash_buf);
	if(strcmp(hash_buf,hash_temp)==0){
		return 1;
	}
	else{
		return -1;
	}

}


ACCOUNT *add_account1(char *username1,char *hash1,char *salt1){
	/*malloc space for the new account*/
	ACCOUNT *n_account=malloc(sizeof(struct ACCOUNT));
	if(n_account==NULL){
		fprintf(stderr, "%s\n", "ERROR: malloc return NULL");
		exit(EXIT_FAILURE);
	}
	/*add data for the new account*/
	strcpy(n_account->username,username1);
	strcpy(n_account->hash,hash1);
	strcpy(n_account->salt,salt1);
	n_account->next=account_list_head;

	/*put the new account at the begining of the account list and return the new account*/
	account_list_head=n_account;
	return n_account;

}


/*return -1 if fail   0 if success*/
int load_accounts_file(char *accounts_file_name1){
	char buf[1024];
	if(accounts_file_name1==NULL){
		fprintf(stderr, "%s\n", "ERROR: The account file name provided is NULL");
		return -1;
	}
	
	FILE *accounts_file = fopen(accounts_file_name1,"r"); 
	if(accounts_file==NULL){
		fprintf(stderr, "%s\n", "ERROR: fopen return NULL");
		return -1;
	}

	int count=0;
	char buf2[1024];
	char buf3[1024];
	//int ct=0;
	while(fgets(buf,1024,accounts_file)!=NULL){
		int len=strlen(buf);
		buf[len-1]='\0';
		if(count==0){
			strcpy(buf2,buf);
			count=1;
		}
		else if(count==1){
			strcpy(buf3,buf);
			count=2;
		}
		else if(count==2){
			add_account1(buf2,buf3,buf);
			count=0;
		}		
	}
	fclose(accounts_file);
	return 0;
}


/*return -1 if fail   0 if success*/
int save_accounts_file(ACCOUNT *account_list_header1){
	ACCOUNT *account_temp=account_list_header1;
	FILE *accounts_file = fopen("hw6.txt","w"); 
	if(accounts_file==NULL){
		fprintf(stderr, "%s\n", "ERROR: fopen return NULL");
		return -1;
	}

	save_helper(accounts_file,account_temp);
	fclose(accounts_file);
	return 0;
}

void save_helper(FILE *accounts_file,ACCOUNT *account_list_header1){
	ACCOUNT *account_temp=account_list_header1;
	if(account_temp==NULL){
		return;
	}
	else{
		save_helper(accounts_file,account_temp->next);
		fputs(account_temp->username,accounts_file);
		fputs("\n",accounts_file);
		fputs(account_temp->hash,accounts_file);
		fputs("\n",accounts_file);
		fputs(account_temp->salt,accounts_file);
		fputs("\n",accounts_file);
		return;
	}
}

void delete_user1(const char *username1){
	USER *tmp_user=user_list_head;
	USER *prev_user=NULL;
	USER *del_user=NULL;

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
			user_list_head=del_user->next;
		}
		else{
			prev_user->next=del_user->next;
		}
		free(del_user);
	}

}


void free_all_user(USER *user_list_head1){
	USER *user_temp=user_list_head1;
	if(user_temp==NULL){
		return;
	}
	else{
		free_all_user(user_temp->next);
		delete_user1(user_temp->username);
		return;
	}
}


void delete_account1(char *username1){
	ACCOUNT *tmp_account=account_list_head;
	ACCOUNT *prev_account=NULL;
	ACCOUNT *del_account=NULL;

	while(tmp_account!=NULL){
		/*find user*/
		if(strcmp(tmp_account->username,username1)==0){
			del_account=tmp_account;
			break;
		}

		prev_account=tmp_account;
		tmp_account=tmp_account->next;
	}

	/*delete user*/
	if(del_account!=NULL){
		if(prev_account==NULL){
			account_list_head=del_account->next;
		}
		else{
			prev_account->next=del_account->next;
		}
		free(del_account);
	}

}


int find_account1(char *username1){
	ACCOUNT *tmp_account=account_list_head;
	ACCOUNT *find_account=NULL;
	while(tmp_account!=NULL){
		/*find user*/
		if(strcmp(tmp_account->username,username1)==0){
			find_account=tmp_account;
			break;
		}
		tmp_account=tmp_account->next;
	}
	if(find_account==NULL){
		return -1;
	}
	else{
		return 1;
	}
}



void free_all_account(ACCOUNT *account_list_header1){
	ACCOUNT *account_temp=account_list_header1;
	if(account_temp==NULL){
		return;
	}
	else{
		free_all_account(account_temp->next);
		delete_account1(account_temp->username);
		return;
	}
}


int open_database(char *database_name){
	int database_re_code;
	database_re_code=sqlite3_open(database_name,&database);//"hw5.db"
	if(database_re_code!=SQLITE_OK){
		fprintf(stderr, "%s\n", "DATABASE ERROR: Cannnot open the database");
		return -1;
	}

	return 1;
}

int create_table(){
	int database_re_code;
	char *database_error=0;
	char *query="CREATE TABLE IF NOT EXISTS ACCOUNT("
				"USERNAME VARCHAR(1024)	PRIMARY KEY NOT NULL,"
				"HASH VARCHAR(1100)		NOT NULL,"
				"SALT VARCHAR(1)		NOT NULL"
				")";
	database_re_code=sqlite3_exec(database,query,0,0,&database_error);
	if(database_re_code!=SQLITE_OK){
		fprintf(stderr, "DATABASE ERROR: %s\n",database_error);
		sqlite3_free(database_error);
		return -1;
	}
	return 1;
}


int drop_table(){
	int database_re_code;
	char *database_error=0;
	char *query="DROP TABLE IF EXISTS ACCOUNT";
	database_re_code=sqlite3_exec(database,query,0,0,&database_error);
	if(database_re_code!=SQLITE_OK){
		fprintf(stderr, "DATABASE ERROR: %s\n",database_error);
		sqlite3_free(database_error);
		return -1;
	}
	return 1;
}



void close_database(){
	sqlite3_close(database);
}

int insert_into_table(char *username1,char *hash1,char *salt1){
	int database_re_code;
	char *database_error=0;
	char *query;
	char out1[1100];
	encode(hash1,strlen(hash1)+1,out1);
	query=sqlite3_mprintf("INSERT INTO ACCOUNT (USERNAME,HASH,SALT) VALUES ('%s','%s','%s');",username1,out1,salt1);
	database_re_code=sqlite3_exec(database,query,0,0,&database_error);
	sqlite3_free(query);
	if(database_re_code!=SQLITE_OK){
		fprintf(stderr, "DATABASE ERROR: %s\n",database_error);
		sqlite3_free(database_error);
		return -1;
	}
	return 1;
}

int select_from_table(char *username1){
	int database_re_code;
	char *database_error=0;
	char *query;
	query=sqlite3_mprintf("SELECT * FROM ACCOUNT WHERE USERNAME='%s';",username1);
	is_there_account_return_from_select=0;
	database_re_code=sqlite3_exec(database,query,callback,0,&database_error);
	sqlite3_free(query);
	if(database_re_code!=SQLITE_OK){
		fprintf(stderr, "DATABASE ERROR: %s\n",database_error);
		sqlite3_free(database_error);
		return -1;
	}

	return 1;
}

int callback(void *d,int argc,char **argv,char **azColName){
	is_there_account_return_from_select=1;
	strcpy(username_temp1,argv[0]);
	strcpy(hash_temp1,argv[1]);
	strcpy(salt_temp1,argv[2]);
	return 0;
}

int print_all_from_table(){
	int database_re_code;
	char *database_error=0;
	char *query="SELECT * FROM ACCOUNT;";
	database_re_code=sqlite3_exec(database,query,callback2,0,&database_error);
	if(database_re_code!=SQLITE_OK){
		fprintf(stderr, "DATABASE ERROR: %s\n",database_error);
		sqlite3_free(database_error);
		return -1;
	}

	return 1;
}

int callback2(void *d,int argc,char **argv,char **azColName){
	int i;
	for(i=0;i<argc;i++){
		printf("%s: %s\n", azColName[i], argv[i]);
	}
	printf("\n");
	return 0;
}


void save_account_database(ACCOUNT *account_list_header1){
	ACCOUNT *account_temp=account_list_header1;
	if(account_temp==NULL){
		return;
	}
	else{
		save_account_database(account_temp->next);
		select_from_table(account_temp->username);
		if(is_there_account_return_from_select==0){
			insert_into_table(account_temp->username,account_temp->hash,account_temp->salt);
		}
		return;
	}
}



int callback3(void *d,int argc,char **argv,char **azColName){
	char out1[1100];
	decode(argv[1],strlen(argv[1]),out1);
	add_account1(argv[0],out1,argv[2]);
	return 0;
}

int table_to_list(){
	int database_re_code;
	char *database_error=0;
	char *query="SELECT * FROM ACCOUNT;";
	database_re_code=sqlite3_exec(database,query,callback3,0,&database_error);
	if(database_re_code!=SQLITE_OK){
		fprintf(stderr, "DATABASE ERROR: %s\n",database_error);
		sqlite3_free(database_error);
		return -1;
	}

	return 1;
}

void encode(char *in,int len,char *out){
	BIO *b_temp,*b_one;
	b_one = BIO_new(BIO_f_base64());
	b_temp = BIO_new(BIO_s_mem());
	b_one = BIO_push(b_one,b_temp);

	BIO_write(b_one, in, len);
  	BIO_flush(b_one);

  	BUF_MEM *temp;
  	BIO_get_mem_ptr(b_one,&temp);

  	strcpy(out,temp->data);
  	BIO_free_all(b_one);
}

void decode(char *in,int len,char *out){
	char s[len];
	BIO *b_temp,*b_one;
	b_one = BIO_new(BIO_f_base64());
	b_temp = BIO_new_mem_buf(in, len);
	b_temp = BIO_push(b_one, b_temp);
	BIO_read(b_temp, s, len);

	strcpy(out,s);
	BIO_free_all(b_temp);
}


void print_usage() {
	printf("./server [-hv] [-t THREAD_COUNT] PORT_NUMBER MOTD [ACCOUNTS_FILE]\n");
	printf("-h                Displays help menu & returns EXIT_SUCCESS.\n");
	printf("-t THREAD_COUNT   The number of threads used for the login queue..\n");
	printf("-v                Verbose print all incoming and outgoing protocol verbs & content.\n");
	printf("PORT_NUMBER       Port number to listen on.\n");
	printf("MOTD              Message to display to the client when they connect.\n");
	printf("ACCOUNTS_FILE     File containing username and password data to be loaded upon execution.\n");
}

void *communication_thread(void *arg) {
	while (1) {
		USER *temp = user_list_head;
		fd_set allset;
		FD_ZERO(&allset);
		int maxfd = -1;
		while (temp != NULL) {
			if (temp->active) {
				FD_SET(temp->fd, &allset);
				if (temp->fd > maxfd) {
					maxfd = temp->fd;
				}
			}
			temp = temp->next;
		}
		struct timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 100;
		if (select(maxfd + 1, &allset, NULL, NULL, &timeout) > 0) {
			temp = user_list_head;
			while (temp != NULL) {
				if (FD_ISSET(temp->fd, &allset)) {
					if (message_handler(temp->fd) == -1) {
						close(temp->fd);
						temp->fd = -1;
						temp->active = 0;
					}
				}
				temp = temp->next;
			}
		}
	}
	return NULL;
}

void *login_thread(void *arg) {

	while(1){
		int fd;
		sem_wait(&items_sem);
		pthread_mutex_lock(&Q_lock);
		fd=remove_login_request();
		pthread_mutex_unlock(&Q_lock);

	char buf[MAXLINE] = {'\0'};
	if (recv_unwrap_message(fd, "WOLFIE", buf, v_flag) == -1) {
		close(fd);
		//return NULL;
		goto LOOP_END;
	}
	bzero(buf, sizeof(buf)); 
	if (wrap_send_message(fd, "EIFLOW", buf, v_flag) == -1) {
		close(fd);
		//return NULL;
		goto LOOP_END;
	}
	bzero(buf, sizeof(buf));
	if (recv_message(fd, buf) == -1) {
		close(fd);
		//return NULL;
		goto LOOP_END;
	}

	char *username = NULL;
	int new_account = 0;

	if (unwrap_message("IAMNEW", buf, v_flag) == 0) {
		new_account = 1;
		username = strdup(buf);
		ACCOUNT *atemp = account_list_head;
		while (atemp != NULL) {
			if (strcmp(atemp->username, username) == 0) {
				bzero(buf, sizeof(buf));
				if (wrap_send_message(fd, "ERR 00 USERNAME TAKEN", buf, v_flag) == -1) {
					close(fd);
					//return NULL;
					goto LOOP_END;
				}
				bzero(buf, sizeof(buf));
				if (wrap_send_message(fd, "BYE", buf, v_flag) == -1) {
					close(fd);
					//return NULL;
					goto LOOP_END;
				}
				close(fd);
				//return NULL;
				goto LOOP_END;
			}
			atemp = atemp->next;
		}

		strcpy(buf, username);
		if (wrap_send_message(fd, "HINEW", buf, v_flag) == -1) {
			//return NULL;
			goto LOOP_END;
		}
		bzero(buf, sizeof(buf));
		read(fd, buf, MAXLINE); 
		if (unwrap_message("NEWPASS", buf, v_flag) == -1) {
			close(fd);
			//return NULL;
			goto LOOP_END;
		}

		char *pass = strdup(buf);
		if (is_valid_password(pass) < 0) {
			bzero(buf, sizeof(buf));
			wrap_send_message(fd, "ERR 02 BAD PASSWORD", buf, v_flag);
			bzero(buf, sizeof(buf));
			wrap_send_message(fd, "BYE", buf, v_flag);
			close(fd);
			//return NULL;
			goto LOOP_END;
		}

		ACCOUNT *account = (ACCOUNT*)malloc(sizeof(ACCOUNT));
		
		strcpy(account->username,username);
		char hash1[1100];
		char salt1[2];
		hash_password(pass,hash1,salt1);
		strcpy(account->hash,hash1);
		strcpy(account->salt,salt1);

		pthread_mutex_lock(&lock);
		if(find_account1(username)==1){
			close(fd);
			free(account);
			goto LOOP_END;
		}
		if (account_list_head == NULL) {
			account_list_head = account;
		} else {
			account->next = account_list_head;
			account_list_head = account;
		}
		pthread_mutex_unlock(&lock);

		bzero(buf, sizeof(buf));
		if (wrap_send_message(fd, "SSAPWEN", buf, v_flag) == -1) {
			//return NULL;
			goto LOOP_END;
		}
		bzero(buf, sizeof(buf)); 
	} else if (unwrap_message("IAM", buf, v_flag) == -1) {
		close(fd);
		//return NULL;
		goto LOOP_END;
	}

	if (username == NULL) {
		username = strdup(buf);
	}

	if (new_account != 1) {
		ACCOUNT *atemp = account_list_head;
		while (atemp != NULL) {
			if (strcmp(atemp->username, username) == 0) {
				break;
			}
			atemp = atemp->next;
		}
		if (atemp == NULL) {
			bzero(buf, sizeof(buf));
			wrap_send_message(fd, "ERR 01 USER NOT AVAILABLE", buf, v_flag);
			bzero(buf, sizeof(buf));
			wrap_send_message(fd, "BYE", buf, v_flag);
			close(fd);
			//return NULL;
			goto LOOP_END;
		}
		bzero(buf, sizeof(buf));
		strcpy(buf, username);
		if (wrap_send_message(fd, "AUTH", buf, v_flag) == -1) {
			close(fd);
			//return NULL;
			goto LOOP_END;
		}

		bzero(buf, sizeof(buf));
		read(fd, buf, MAXLINE); 
		if (unwrap_message("PASS", buf, v_flag) == -1) {
			close(fd);
			//return NULL;
			goto LOOP_END;
		}

		char *password_temp1 = strdup(buf);
		char hash_temp[1100];
		char salt_temp[2];
		strcpy(hash_temp,atemp->hash);
		strcpy(salt_temp,atemp->salt);
		int t2=is_same_password(password_temp1,hash_temp,salt_temp);	
		if (t2<0) {
			bzero(buf, sizeof(buf));
			wrap_send_message(fd, "ERR 02 BAD PASSWORD", buf, v_flag);
			bzero(buf, sizeof(buf));
			wrap_send_message(fd, "BYE", buf, v_flag);
			close(fd);
			//return NULL;
			goto LOOP_END;
		}

		bzero(buf, sizeof(buf));
		if (wrap_send_message(fd, "SSAP", buf, v_flag) == -1) {
			//return NULL;
			goto LOOP_END;
		}
	}
    bzero(buf, sizeof(buf));
	// check if this user has already login
	USER *temp = user_list_head;
	int already_login = 0;
	int new_user = 1;
	while (temp != NULL) {
		if (strcmp(temp->username, username) == 0) {
			// if thie user has already login
			if (temp->active == 1) {
				already_login = 1;
			// if this user is an old user
			} else {
				new_user = 0;
				temp->login_time = time(NULL);
				temp->fd = fd;
				temp->active = 1;
			}
			break;
		}
		temp = temp->next;
	}

	if (already_login) {
		bzero(buf, sizeof(buf));
		if (wrap_send_message(fd, "ERR 00 USERNAME TAKEN", buf, v_flag) == -1) {
			close(fd);
			//return NULL;
			goto LOOP_END;
		}
		bzero(buf, sizeof(buf));
		if (wrap_send_message(fd, "BYE", buf, v_flag) == -1) {
			close(fd);
			//return NULL;
			goto LOOP_END;
		}
		bzero(buf, sizeof(buf));
		if (recv_unwrap_message(fd, "BYE", buf, v_flag) == -1) {
			close(fd);
			//return NULL;
			goto LOOP_END;
		}
		close(fd);
		//return NULL;
		goto LOOP_END;
	}

	VERBOSE("User %s login.", username);
	DEFAULT("\n");

	bzero(buf, sizeof(buf));
	strcpy(buf, username);
	if (wrap_send_message(fd, "HI", buf, v_flag) == -1) {
		//return NULL;
		goto LOOP_END;
	}

	if (new_user) {
		USER *user = (USER*)malloc(sizeof(USER));
		user->username = username;
		user->login_time = time(NULL);
		user->fd = fd;
		user->active = 1;
		pthread_mutex_lock(&lock1);
		if (user_list_head == NULL) {
			user_list_head = user;
			pthread_create(&comm_tid, NULL, &communication_thread, NULL);
			pthread_setname_np(comm_tid,"COMM");
		} else {
			user->next = user_list_head;
			user_list_head = user;
		}

		pthread_mutex_unlock(&lock1);
	}

	bzero(buf, sizeof(buf));
	strcpy(buf, motd);
	if (wrap_send_message(fd, "MOTD", buf, v_flag) == -1) {
		//return NULL;
		goto LOOP_END;
	}
LOOP_END:
	fd = -1;
	}
	return NULL;
}

int message_handler(int fd) {
	char buf[MAXLINE];

	if (recv_message(fd, buf) == -1) {
		return -1;
	}
	if (unwrap_message("TIME", buf, v_flag) == 0) {
		bzero(buf, sizeof(buf));
		USER *temp = user_list_head;
		while (temp != NULL) {
			if (temp->fd == fd) {
				time_t current = time(NULL);
				int login_time = current - temp->login_time;
				sprintf(buf, "%d", login_time);
				if (wrap_send_message(fd, "EMIT", buf, v_flag) == -1) {
					return -1;
				}
				bzero(buf, sizeof(buf));
				return 0;	
			}
			temp = temp->next;
		}
		bzero(buf, sizeof(buf));
	}
	if (unwrap_message("LISTU", buf, v_flag) == 0) {
		USER *temp = user_list_head;
		while (temp != NULL) {
			if (temp->fd == fd) {
				bzero(buf, sizeof(buf));
				temp = user_list_head;
				while (temp != NULL) {
					if (temp->active) {
						strcat(buf, temp->username);
						strcat(buf, "\r\n");
					}
					temp = temp->next;
				}

				if (wrap_send_message(fd, "UTSIL", buf, v_flag) == -1) {
					return -1;
				}
				bzero(buf, sizeof(buf));
				return 0;
			}
			temp = temp->next;
		}
	}
	if (unwrap_message("BYE", buf, v_flag) == 0) {
		USER *temp = user_list_head;
		char *username;
		while (temp != NULL) {
			if (temp->fd == fd) {
				bzero(buf, sizeof(buf));
				wrap_send_message(fd, "BYE", buf, v_flag);
				close(fd);
				temp->fd = -1;
				temp->active = 0;
				username = strdup(temp->username);
				break;
			}
			temp = temp->next;
		}
		temp = user_list_head;
		while (temp != NULL) {
			if (temp->active == 1) {
				bzero(buf, sizeof(buf));
				strcat(buf, username);
				wrap_send_message(temp->fd, "UOFF", buf, v_flag);
			}
			temp = temp->next;
		}
		bzero(buf, sizeof(buf));
	}
	if (unwrap_message("MSG", buf, v_flag) == 0) {
		char *msg = strdup(buf);
		char *p = strtok(buf, " ");
		if (p == NULL) {
			return -1;
		}
		char *from = strdup(p);
		p = strtok(NULL, " ");
		if (p == NULL) {
			return -1;
		}
		char *to = strdup(p);
		USER *temp = user_list_head;


		int to_exit = 0;
		int from_exit = 0;

		if (wrap_message("MSG", msg, v_flag) == -1) {
			return -1;
		}

		int tofd = -1, fromfd = -1;

		while (temp != NULL) {
			if (temp->active && strcmp(temp->username, to) == 0) {
				tofd = temp->fd;
				to_exit=1;
			}
			if (temp->active && strcmp(temp->username, from) == 0) {
				fromfd = temp->fd;
				from_exit = 1;
			}
			temp = temp->next;
		}
		
		if(to_exit == 0 || from_exit==0){
			bzero(buf, sizeof(buf));
			if (wrap_message("ERR 01 USER NOT AVAILABLE", buf, v_flag) == -1) {
				return -1;
			}
			if (send_message(fd, buf) == -1) {
				return -1;
			}	
		}

		if (tofd != -1 && fromfd != -1) {
			printf("%s",msg);
			if (send_message(tofd, msg) == -1) {
				return -1;
			}
			if (send_message(fromfd, msg) == -1) {
				return -1;
			}
		}


		bzero(buf, sizeof(buf));
	}
	bzero(buf, sizeof(buf));
	return 0;
}

void input_handler() {

	char buf[MAXLINE] = {'\0'};
	if (fgets(buf, MAXLINE, stdin) == NULL) {
		return;
	}
	if (strncmp(buf, "/users", strlen("/users")) == 0) {
		bzero(buf, sizeof(buf));
		USER *temp = user_list_head;
		while (temp != NULL) {
			if (temp->active) {
				strcat(buf, temp->username);
				strcat(buf, "\r\n");
			}
			temp = temp->next;
		}
		VERBOSE("USERS:\n%s", buf);
		DEFAULT("\n");
		bzero(buf, sizeof(buf));
		return;
	}
	if (strncmp(buf, "/accts", strlen("/accts")) == 0) {
		bzero(buf, sizeof(buf));
		ACCOUNT *temp = account_list_head;
		while (temp != NULL) {
			strcat(buf, temp->username);
			strcat(buf, "\r\n");
			temp = temp->next;
		}
		VERBOSE("ACCTS:\n%s", buf);
		DEFAULT("\n");
		bzero(buf, sizeof(buf));
		return;
	}
	if (strncmp(buf, "/help", strlen("/help")) == 0) {
		VERBOSE("Command Menu: \n");
		print_server_command_usage();
		DEFAULT("\n");
		return;
	}
	if (strncmp(buf, "/shutdown", strlen("/shutdown")) == 0) {
		bzero(buf, sizeof(buf));
		USER *temp = user_list_head;
		while (temp != NULL) {
			if (temp->active) {
				if (wrap_send_message(temp->fd, "BYE", buf, v_flag) == -1) {
					return;
				}
				bzero(buf, sizeof(buf));
				close(temp->fd);
				temp->fd = -1;
				temp->active = 0;
			}
			temp = temp->next;
		}


		save_accounts_file(account_list_head);
		free_all_user(user_list_head);
		free_all_account(account_list_head);
		free_all_login_request();
		close(listenfd);
		exit(EXIT_SUCCESS);
	}
	
	ERRORS("Invalid Command!\n");
	VERBOSE("Command Menu:\n");
	print_server_command_usage();
	DEFAULT("\n");
	return;
}

int main(int argc, char* argv[]) {
	int opt;
	int port;
	int t_flag=0;
	int thread_count=2;
	while((opt = getopt(argc, argv, "hvt:")) != -1) {
        switch(opt) {
            case 'h':
                print_usage();
                exit(EXIT_SUCCESS);
                break;
            case 'v':
            	v_flag = 1;
            	break;
            case 't':
            	t_flag=1;
            	t_flag=t_flag+0;
            	char *end1;
            	thread_count=strtol(optarg,&end1,10);
            	if(*end1!='\0'){
            		fprintf(stderr,"ERROR: Invalid THREAD_COUNT.\n");
    				exit(EXIT_FAILURE);
            	}
            	if(thread_count<1){
            		fprintf(stderr,"ERROR: The given THREAD_COUNT is less than 1.\n");
    				exit(EXIT_FAILURE);
            	}
            	break;
            case '?':
            default:
                print_usage();
                exit(EXIT_FAILURE);
                break;
        }
    }


    if(argc-optind == 2){
    	char *endptr;
    	strtol(argv[argc - 2], &endptr, 10);    	
    	if(*endptr != '\0'){
    		fprintf(stderr,"ERROR:%s is an invalid port number.\n",argv[argc - 2]);
    		exit(EXIT_FAILURE);
    	}
		port = atoi(argv[argc - 2]);
		motd = argv[argc -1];
	}
	else if(argc-optind==3){
		char *endptr;
    	strtol(argv[argc - 3], &endptr, 10);    	
    	if(*endptr != '\0'){
    		fprintf(stderr,"ERROR:%s is an invalid port number.\n",argv[argc - 2]);
    		exit(EXIT_FAILURE);
    	}
		port = atoi(argv[argc - 3]);
		motd = argv[argc -2];

		char *file = argv[argc -1];
		int t3=load_accounts_file(file);
		if(t3<0){
			exit(EXIT_FAILURE);
		}
	}
	else if(argc-optind<2){
		ERRORS("The number of argument given should not be less than 2.");
		DEFAULT("\n");
		print_usage();
		exit(EXIT_FAILURE);
	}
	else {
		ERRORS("The number of argument given should not be greater than 3.");
		DEFAULT("\n");
		print_usage();
		exit(EXIT_FAILURE);
	}


	DEFAULT("Currently listening on port %d\n", port);

	int connfd;
	socklen_t clilen;
	struct sockaddr_in cliaddr, servaddr;

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(port);

	if (bind(listenfd, (struct sockaddr*) &servaddr, sizeof(servaddr)) == -1) {
		ERRORS("error in bind %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (listen(listenfd, 128) == -1) {  //backlog = 128
		ERRORS("error in listen %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	int maxfd = listenfd;
	fd_set rset;
	pthread_t tid;
	sem_init(&items_sem, 0, 0);
	int t1;
	for(t1=0;t1<thread_count;t1++){
		pthread_create(&tid, NULL, &login_thread, NULL);
		pthread_setname_np(tid,"LOGIN");
	}

	while (1) {
		FD_ZERO(&rset);
		FD_SET(fileno(stdin), &rset);
		FD_SET(listenfd, &rset);
		select(maxfd + 1, &rset, NULL, NULL, NULL);
		// add all incoming connection to allset
		if (FD_ISSET(listenfd, &rset)) {
			clilen = sizeof(cliaddr);
			if ((connfd = accept(listenfd, (struct sockaddr*) &cliaddr, &clilen)) == -1) {
				printf("error in accept %s\n", strerror(errno));
				exit(EXIT_FAILURE);
			}

			pthread_mutex_lock(&Q_lock);
			add_login_request(connfd);
			pthread_mutex_unlock(&Q_lock);
			sem_post(&items_sem);
		}
		// stdin is readable
		if (FD_ISSET(fileno(stdin), &rset)) {
			input_handler();
		}
	}

	close(listenfd);
	return 0;
}
