struct user{
	time_t login_time;
	int socket;
	char username[1024];
	int ip_address;
	struct user *next;
};

struct account{
	char username[1024];
	char password[1024];
	struct account *next;
};


struct user *add_user(int socket1,char *username1,int ip_address1,struct user *current_login_user_list_header);
struct user *find_user(char *username1,struct user *current_login_user_list_header);
void delete_user(char *username1,struct user *current_login_user_list_header);
struct account *add_account(char *username1,char *password1,struct account *account_list_header);
struct account *find_account(char *username1,struct account *account_list_header);
void delete_account(char *username1,struct account *account_list_header);
int is_valid_password(char *n1);
void print_server_command_usage();
void print_current_login_user_list(struct user *current_login_user_list_header1);
void print_account_list(struct account *account_list_header1);
int server_command_check(char **command,int number_of_tokens,struct user *current_login_user_list_header1,struct account *account_list_header1);
/*haozhi 4/16*/
char** divide_command(char *command,int *number_of_tokens);
/*haozhi 4/16*/

void print_usage();
int message_handler(int sockfd);
void input_handler();
