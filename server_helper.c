#include "common.h"
#include "server.h"


int is_valid_password(char *n1){
	int re_code=0;
	int is_at_least_five=0;
	int is_at_least_upper=0;
	int is_at_least_symbol=0;
	int is_at_least_number=0;

	if(strlen(n1)>=5){
		is_at_least_five=1;
	}
	else{
		return -1;
	}

	char *n2;
	for(n2=n1;*n2!='\0';n2++){
		if(isupper(*n2)!=0){
			is_at_least_upper=1;
			break;
		}
	}
	if(is_at_least_upper==0){
		return -2;
	}


	for(n2=n1;*n2!='\0';n2++){
		if(!(isupper(*n2)||islower(*n2)||isdigit(*n2))){
			is_at_least_symbol=1;
			break;
		}
	}
	if(is_at_least_symbol==0){
		return -3;
	}


	for(n2=n1;*n2!='\0';n2++){
		if(isdigit(*n2)!=0){
			is_at_least_number=1;
			break;
		}
	}
	if(is_at_least_number==0){
		return -4;
	}

	if(is_at_least_number&&is_at_least_symbol&&is_at_least_upper&&is_at_least_five){
		re_code=1;
	}

	return re_code;
}


void print_server_command_usage(){
	printf("%s\n", "/users");
	printf("%s\n", "/help");
	printf("%s\n", "/shutdown");
	printf("%s\n", "/accts");
}




void print_current_login_user_list(struct user *current_login_user_list_header1){
	struct user *user_temp=current_login_user_list_header1;
	if(user_temp==NULL){
		return;
	}
	else{
		print_current_login_user_list(user_temp->next);
		printf("Username: %s\n", user_temp->username);/*need to change later!!!!!!!!!!!!!!!!!!*/
		return;
	}
}



void print_account_list(struct account *account_list_header1){
	struct account *account_temp=account_list_header1;
	if(account_temp==NULL){
		return;
	}
	else{
		print_account_list(account_temp->next);
		printf("Username: %s\n", account_temp->username);/*need to change later!!!!!!!!!!!!!!!!!!*/
		return;
	}
}



/*return -1 fail   1 success*/
int server_command_check(char **command,int number_of_tokens,struct user *current_login_user_list_header1,struct account *account_list_header1){
	int re_code=-1;
	if(number_of_tokens==1){
		/*one tokens for the command*/
		if(strcmp(command[0],"/users")==0){
			print_current_login_user_list(current_login_user_list_header1);
			re_code=1;
		}
		if(strcmp(command[0],"/help")==0){
			print_server_command_usage();
			re_code=1;
		}
		if(strcmp(command[0],"/shutdown")==0){

			re_code=1;
		}
		if(strcmp(command[0],"/accts")==0){
			print_account_list(account_list_header1);
			re_code=1;
		}
	}
	else{
		/*more than one tokens for the command*/
		fprintf(stderr, "%s\n", "ERROR: You enter a invalid command.");
		/*print usage????????*/
		re_code=-1;
	}
	return re_code;
}

/*free the memory*/
char** divide_command(char *command,int *number_of_tokens){
	char cmd_temp[1024];
	strcpy(cmd_temp,command);
	int size=50;
	
	char **tks=malloc(size*sizeof(char*));
	if(tks==NULL){
		fprintf(stderr, "%s\n", "ERROR: malloc return NULL");
		exit(EXIT_FAILURE);
	}

	int index=0;
	char *s_ptr;
	char *tk;
	tk = strtok_r(cmd_temp," \n",&s_ptr);
	while(tk!=NULL){
		tks[index]=tk;
		index++;
		if(index>=size){
			size = size+50;
			tks=realloc(tks, size*sizeof(char*));
			if(tks==NULL){
				fprintf(stderr, "%s\n", "ERROR: realloc return NULL");
				exit(EXIT_FAILURE);
			}
		}
		tk=strtok_r(NULL," \n",&s_ptr);
	}

	*number_of_tokens=index;
	return tks;
}
/*haozhi 4/16*/


