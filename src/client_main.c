// client_main.c
//
// This is the main routine for the pictstor client program.
//
// The program is run as pictstor <server ip address> <server port> to
// run the program interactively.
//
// Use pictstor <server ip address> <server port> "put|get filename
// to put or get a single file and exit
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <openssl/evp.h>

#include "socket_funcs.h"
#include "pictstor.h"
#include "cli.h"
#include "authorization.h"

#define MAX_ARGS 12
#define MAX_LINE 256

void usage();
void help_cmd();
int stress_test();
int process_input(int num_args, char *args[]);
int get_cmd(int *num_args, char *args[]);

int main(int argc, char *argv[])
{
  int port;
  char *host_name;
  int error = 0;
  char *cmd_args[MAX_ARGS];
  int num_args;
  int i;
  char line[MAX_LINE];
  
  // expect at least the server ip address and port
  if (argc < 3) {
    usage();
    return 1;
  }
  host_name = argv[1];
  port = atoi(argv[2]);
  if (port <= 0) {
    fprintf(stderr,"Invalid port %d\n",port);
    return 1;
  }

  // attempt to connect to the server
  error = connect_to_server(host_name, port);
  if (error < 0) {
    return 1;
  }
    
  debug_print("Connected\n");

  OpenSSL_add_all_algorithms();
  
  error = get_rand_iv();
  if (error) {
  	perror("Failed to create IV");
	return error;
  } 

  error = PKE_client();
  if (error) {
    fprintf(stderr,"key exchanged failed\n");
    return error;
  }
  
  AuthorizationContext auth_ctx;
  error = authorization_initialize("data", "user", False, &auth_ctx);
  if(error == AUTHORIZATION_FAILURE)
	  goto exit;

  error = user_authentication_client(&auth_ctx);
  if(error == AUTHORIZATION_FAILURE)
	  goto exit;

  debug_print("\n*** Client Authorization and Authentication Complete ***\n\n");

  // Get my user name from my certificate
  char my_name[64];
  X509 *p_my_cert = authorization_get_my_cert(&auth_ctx);
  if(p_my_cert == NULL) {
	  goto exit;
  }

  if(get_name_from_cert(p_my_cert, my_name, 64) == AUTHORIZATION_FAILURE) {
	  goto exit;
  } else {
	  debug_print("My name is %s\n", my_name);
	  // set_user_name_client("alice@somewhere.com");
	  set_user_name_client(my_name);
  }

  /**
   ******* Example Code for Getting Keys *******
   */

  // Example for retrieving my private key
  EVP_PKEY *p_my_private_key = get_my_private_key(&auth_ctx);
  if(p_my_private_key == NULL) {
	  goto exit;
  }

  // Example to get server public key
  X509 *p_server_cert = authorization_get_server_cert(&auth_ctx);
  if(p_server_cert == NULL) {
	  goto exit;
  }

  EVP_PKEY *p_server_public_key = X509_get_pubkey(p_server_cert);
  if(p_server_public_key == NULL) {
	  goto exit;
  }

  /**
   ******* End of example code *******
   */


  if (argc > 3) {
    for (i=0;i<argc-3 && i<MAX_ARGS;++i) {
      cmd_args[i] = argv[i+3];
    }
    num_args = i;
    debug_print("num_args: %d\n",num_args);
    for (i=0;i<num_args;++i) {
      debug_print("%s\n",cmd_args[i]);
    }
    error = process_input(num_args,cmd_args);
    return error;
  }
  else {
    while (get_cmd(&num_args,cmd_args) == 0) {
      if (strcmp(cmd_args[0],"quit") == 0)
	  break;
      error = process_input(num_args,cmd_args);
    }
  }

exit:

  // close the socket to the server before exiting
  close_socket();

  EVP_cleanup();

  authorization_clean_up(&auth_ctx);

  return 0;
}

// print the usage message to stderr
void usage()
{
  printf("pictstor <server ip address> <server port>\n");
  printf("pictstor <server ip address> <server port> command\n");
  printf("supported commands are:\n");
  help_cmd();
}

void help_cmd()
{
  printf("put <file name>         - puts a file to the server\n");
  printf("get <file name>         - gets a file and its signature file"
	                            "from the server\n");
  printf("verify <file name>      - verifies a file with its signature file\n");
  printf("ls                      - list the files in the server's "
                                    "current directory\n");
  printf("rm <file name>          - remove a file on the server\n");
  printf("mkdir <directory>       - create a directory on the server\n");
  printf("cd <directory>          - change the current directory on "
	                            "the server\n");
  printf("rmdir <directory>       - remove a directory on the server\n");
  printf("lls <args>              - list the files in the local directory\n");
  printf("lcd                     - change the local directory\n");
  printf("quit                    - exit the program\n");
  printf("help                    - show this text\n");
}

int stress_test()
{
  int error = 0;
  while(1) {
    error = put_cmd_client("testfile.1");
    if (error) {
      fprintf(stderr,"failed sending testfile.1\n");
      return error;
    }
    error = put_cmd_client("testfile.2");
    if (error) {
      fprintf(stderr,"failed sending testfile.2\n");
      return error;
    }
    error = put_cmd_client("testfile.3");
    if (error) {
      fprintf(stderr,"failed sending testfile.3\n");
      return error;
    }
    error = get_cmd_client("testfile.1");
    if (error) {
      fprintf(stderr,"failed getting testfile.1\n");
      return error;
    }
    error = get_cmd_client("testfile.2");
    if (error) {
      fprintf(stderr,"failed getting testfile.2\n");
      return error;
    }
    error = get_cmd_client("testfile.3");
    if (error) {
      fprintf(stderr,"failed getting testfile.3\n");
      return error;
    }
  }
}

int process_input(int num_args, char *args[])
{
  int error = 0;
  char *p;;
  
  // put cmd in lower case
  for (p=args[0];*p;p++) {
    *p = tolower(*p);
  }
  
  if (strcmp("put",args[0]) == 0) {
    if (num_args < 2) {
      printf("missing file name\n");
      error = -1;
    }
    else {      
      error = put_cmd_client(args[1]);
    }
  }
  else if (strcmp("get",args[0]) == 0)
    if (num_args < 2) {
      printf("missing file name\n");
      error = -1;
    }
    else {      
      error = get_cmd_client(args[1]);
    }
  else if (strcmp("stresstest",args[0]) == 0)
    error = stress_test();
  else if (strcmp("ls",args[0]) == 0)
    error = ls_cmd_client();
  else if (strcmp("rm",args[0]) == 0)
    if (num_args < 2) {
      printf("missing file name\n");
      error = -1;
    }
    else {      
      error = rm_cmd_client(args[1]);
    }
  else if (strcmp("cd",args[0]) == 0)
    if (num_args < 2) {
      printf("missing directory name\n");
      error = -1;
    }
    else {      
      error = cd_cmd_client(args[1]);
    }
  else if (strcmp("mkdir",args[0]) == 0)
    if (num_args < 2) {
      printf("missing directory name\n");
      error = -1;
    }
    else {      
      error = mkdir_cmd_client(args[1]);
    }
  else if (strcmp("rmdir",args[0]) == 0)
    if (num_args < 2) {
      printf("missing directory name\n");
      error = -1;
    }
    else {      
      error = rmdir_cmd_client(args[1]);
    }
  else if (strcmp("verify",args[0]) == 0)
    if (num_args < 2) {
      printf("missing file name\n");
      error = -1;
    }
    else {
      error = verify_file_hash(args[1]);
    }
  else if (strcmp("lls",args[0]) == 0) 
    if (num_args == 1) {
      error = lls_cmd_client(NULL);
    }
    else {
      error = lls_cmd_client(args[1]);
    }
  else if (strcmp("lcd",args[0]) == 0)
    if (num_args < 2) {
      printf("missing directory name\n");
      error = -1;
    }
    else {
      error = lcd_cmd_client(args[1]);
    }
  else if (strcmp("help",args[0]) == 0) {
    help_cmd();
    error = 0;
  }
  else {
    fprintf(stderr,"unknown command\n");
    error = -1;
  }
  return error;
}

int get_cmd(int *return_num_args, char *args[])
{
  char *line = NULL;
  size_t size;
  size_t i;
  int num_args = 0;

  printf("> ");
  if (getline(&line,&size,stdin) > 0) {
    i = 0;
    while(i<size && line[i]) {
      while (line[i] && isspace(line[i]) && i<size) {
	line[i] = '\0';
	++i;
      }
      if (line[i]) {
	args[num_args] = &line[i];
	num_args++;
	if (num_args >= MAX_ARGS) {
	  break;
	}
	while (line[i] && !isspace(line[i]) && i<size)
	  ++i;
      }
    }
  }
  if (num_args > 0) {
    *return_num_args = num_args;
    return 0;
  }
  else {
    return -1;
  }
}
