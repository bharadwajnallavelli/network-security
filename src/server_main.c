// server_main.c
//
// This is the main routine for the pictstord server program.
//
// the program is run as pictstord <port>
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "socket_funcs.h"
#include "pictstor.h"
#include "authorization.h"

void usage();
void wait_child(int signal);
int process_client();

int main(int argc, char *argv[])
{
  int port;
  struct sockaddr_in client_addr;
  int sock;
  int connected_sock;
  socklen_t client_addr_len;
  int result;

  // handle sinal to clean up children
  signal(SIGCHLD,wait_child);
  
  // expect one command line parameter, the port
  if (argc < 2) {
    usage();
    return 1;
  }
  port = atoi(argv[1]);
  if (port <= 0) {
    fprintf(stderr,"Invalid port %d\n",port);
    return 1;
  }

  if (argc < 3) {
    set_root_dir(".");
  }
  else {
    set_root_dir(argv[2]);
  }

  // create the server socket
  sock = create_server_socket(port);
  if (sock < 0) {
    return 1;
  }
    
  client_addr_len = sizeof(client_addr);
  while (1) {
    // wait for a client to connect
    connected_sock = accept(sock,(struct sockaddr *) &client_addr,
			 &client_addr_len);
    if (connected_sock == -1) {
      if (errno == EINTR)
	continue;
      perror("accept failed: ");
      return 1;
    }

    result = 0;
    // fork a new process to handle the client
    // for easy debugging comment out the call to fork
    result = fork();
    
    if (result == -1) {
      perror("fork failed: ");
      return 1;
    }
    else if (result == 0) {
      // this is the child
      close(sock);
      set_client_socket(connected_sock);
      debug_print("client connected\n");
      process_client();
      debug_print("client disconnected\n");
      close_socket();
      break;
    }
    else {
      // this is the parent
      close(connected_sock);
    }
  }

  EVP_cleanup();
  return 0;
}

// print the usage message to stderr
void usage()
{
  fprintf(stderr,"Usage: pictstord <portnum> [<root dir>]\n");
}

// clena up a child after it exits
void wait_child(int signal)
{
  int status;
  wait(&status);
}

// handle the interaction for one client
int process_client()
{
  int error = 0;
  command cmd;
  long tmp;
  long bytes_read;
  char client_name[64];

  OpenSSL_add_all_algorithms();

   error = PKE_server();
   if (error) {
     fprintf(stderr,"key exchange failed\n");
     return error;
   }

  AuthorizationContext auth_ctx;
  error = authorization_initialize("data", "server", True, &auth_ctx);
  if(error == AUTHORIZATION_FAILURE)
	  goto exit;

  error = user_authentication_server(&auth_ctx, client_name);
  if(error == AUTHORIZATION_FAILURE)
	  goto exit;
	   
  printf("Name of caller: %s\n", client_name); 
  debug_print("\n*** Client Authorization and Authentication Complete ***\n\n");

  set_user_name_server(client_name);
  
  while (1) {
    // get a command from the client (in network format)
    error = encrypted_recv(COMMAND, &tmp,sizeof(tmp),&bytes_read);
    if (error < 0) {
      return error;
    }
    if (bytes_read == 0) {
      // socket closed
      return 0;
    }

    // convert the command to host format
    cmd = (command) ntohl(tmp);
    debug_print("received command %d\n",cmd);

    // perform the command
    switch (cmd) {
    case PUT_FILE:
      error = put_cmd_server();
      break;
    case GET_FILE:
      error = get_cmd_server();
      break;
    case LS:
      error = ls_cmd_server();
      break;
    case RM:
      error = rm_cmd_server();
      break;
    case CD:
      error = cd_cmd_server();
      break;
    case MKDIR:
      error = mkdir_cmd_server();
      break;
    case RMDIR:
      error = rmdir_cmd_server();
      break;
    default:
      fprintf(stderr,"unexpected command received: %d\n",cmd);
      error = -1;
      break;
    }
    if (error)
      return error;
  }

exit:
  authorization_clean_up(&auth_ctx);

  return error;
}
