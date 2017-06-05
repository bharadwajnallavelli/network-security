// file_cmds.c
//
// This file includes the routines used for file commands cd, ls, and del
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>

#include "pictstor.h"

// sends the LS command to the server and prints the response messages
// The sequence of messages is
//    client                 server
//  send the LS command
//                         for each file send an ls_item_msg with valid == 1
//                         send an ls_item_msg with valid == 0
int ls_cmd_client()
{
  long cmd;
  int error = 0;
  int done = 0;
  ls_item_msg msg;
  long bytes_read;

  // send the command to the server
  cmd = htonl(LS);
  error = encrypted_send(COMMAND,&cmd,sizeof(cmd));
  if (error) {
    fprintf(stderr,"Failed to send command to server\n");
    return error;
  }

  while (!done) {
    // receive a response message
    error = encrypted_recv(LS_ITEM,&msg,sizeof(msg),&bytes_read);
    if (error) {
      fprintf(stderr,"Failed to receive ls response\n");
      return error;
    }

    // transform to host format
    msg.valid = ntohl(msg.valid);
    msg.file_size = ntohl(msg.file_size);
    if (msg.valid) {
      printf("%s %8ld %s\n",msg.timestamp,msg.file_size,msg.name);
    }
    else {
      done = 1;
    }
  }
  return error;
}

// processes the LS command on the server
// The sequence of messages is
//    client                 server
//  send the LS command
//                         for each file send an ls_item_msg with valid == 1
//                         send an ls_item_msg with valid == 0
int ls_cmd_server()
{
  int error = 0;
  int i;
  ls_item_msg msg;
  DIR *dir;
  struct dirent *dir_entry;
  struct stat file_info;
  char *sig_ext = ".sig";
  
  dir = opendir(".");
  if (dir != NULL) {
    while ((dir_entry = readdir(dir)) != NULL) {
      if (strlen(dir_entry->d_name) > strlen(sig_ext)) {
	if (strcmp(dir_entry->d_name +
		   strlen(dir_entry->d_name) - strlen(sig_ext),
		   sig_ext) == 0) {
	  // skip .sig files
	  continue;
	}
      }
      if (dir_entry->d_name[0] == '.') {
	// skip . files
	continue;
      }
      if (stat(dir_entry->d_name,&file_info) == -1)
	continue;
      if (!(S_ISREG(file_info.st_mode) || S_ISDIR(file_info.st_mode))) {
	// include only regular files and directories
	continue;
      }
      memset(&msg,0,sizeof(msg));
      strncpy(msg.name,dir_entry->d_name,FILE_NAME_LEN);
      if (S_ISDIR(file_info.st_mode)) {
	strcat(msg.name,"/");
      }
      msg.file_size = htonl(file_info.st_size);
      strftime(msg.timestamp,FILE_TIMESTAMP_LEN,
	       "%b %d %Y %H:%M",localtime(&file_info.st_mtime));
      msg.valid = htonl(1);
      error = encrypted_send(LS_ITEM,&msg,sizeof(msg));
      if (error ) {
	fprintf(stderr,"Failed sending ls response\n");
	closedir(dir);
	return -1;
      }
    }
    closedir(dir);
  }

  // send one more message with valid set to 0
  memset(&msg,0,sizeof(msg));
  msg.valid = htonl(0);
  error = encrypted_send(LS_ITEM,&msg,sizeof(msg));
  if (error ) {
    fprintf(stderr,"Failed sending final ls item\n");
    return -1;
  }
  return error;
}

// sends the rm command to the server to delete a file
// The sequence of messages is
//    client                 server
//  send the rm command
//                         send acknowledge_msg
int rm_cmd_client(const char* fname)
{
  long cmd;
  long error;
  acknowledge_msg ack;

  // send the command to the server
  cmd = htonl(RM);
  error = encrypted_send(COMMAND,&cmd,sizeof(cmd));
  if (error) {
    fprintf(stderr,"Failed to send command to server\n");
    return error;
  }

  // send the file name
  error = encrypted_send(FILE_NAME,fname,strlen(fname)+1);
  if (error) {
    fprintf(stderr,"Failed to send file name\n");
    return error;
  }

  get_acknowledge(&ack,ENCRYPTED);
  if (!ack.success) {
    fprintf(stderr,"rm failed: %s\n",ack.msg);
    return -1;
  }
  return 0;
}

// Processes the rm command on the server. Responds with an acknowledge
// message to indicate success or failure.
// The sequence of messages is
//    client                 server
//  send the RM command
//                         send acknowledge_msg
int rm_cmd_server() {
  long error;
  char file_name[FILE_NAME_LEN];
  long bytes_read;

  error = encrypted_recv(FILE_NAME,file_name,FILE_NAME_LEN,&bytes_read);
  if (error) {
    fprintf(stderr,"Failed to receive file name\n");
    return -1;
  }

  if (unlink(file_name) == 0) {
    strncat(file_name,".sig",FILE_NAME_LEN);
    if (unlink(file_name) == 0) {
      send_success(ENCRYPTED);
    }
    else {
      send_failure("Failed to remove .sig file",ENCRYPTED);
    }
  }
  else {
    send_failure(strerror(errno),ENCRYPTED);
  }
}

// Sends the cd command to the server.
// The sequence of messages is
//    client                 server
//  send the CD command
//                         send acknowledge_msg
int cd_cmd_client(const char* fname)
{
  long cmd;
  long error;
  acknowledge_msg ack;

  // send the command to the server
  cmd = htonl(CD);
  error = encrypted_send(COMMAND,&cmd,sizeof(cmd));
  if (error) {
    fprintf(stderr,"Failed to send command to server\n");
    return error;
  }

  // send the file name
  error = encrypted_send(FILE_NAME,fname,strlen(fname)+1);
  if (error) {
    fprintf(stderr,"Failed to send file name\n");
    return error;
  }

  get_acknowledge(&ack,ENCRYPTED);
  if (!ack.success) {
    fprintf(stderr,"cd failed: %s\n",ack.msg);
    return -1;
  }
  return 0;
}

// Processes the cd command on the server. Responds with an acknowledge
// message to indicate success or failure.
// The sequence of messages is
//    client                 server
//  send the CD command
//                         send acknowledge_msg
int cd_cmd_server()
{
  long error;
  char file_name[FILE_NAME_LEN];
  long bytes_read;

  error = encrypted_recv(FILE_NAME,file_name,FILE_NAME_LEN,&bytes_read);
  if (error) {
    fprintf(stderr,"Failed to receive file name\n");
    return -1;
  }

  if (chdir(file_name) == 0) {
    send_success(ENCRYPTED);
  }
  else {
    send_failure(strerror(errno),ENCRYPTED);
  }
}

// Sends the mkdir command to the server.
// The sequence of messages is
//    client                 server
//  send the MKDIR command
//                         send acknowledge_msg
int mkdir_cmd_client(const char* fname)
{
  long cmd;
  long error;
  acknowledge_msg ack;

  // send the command to the server
  cmd = htonl(MKDIR);
  error = encrypted_send(COMMAND,&cmd,sizeof(cmd));
  if (error) {
    fprintf(stderr,"Failed to send command to server\n");
    return error;
  }

  // send the file name
  error = encrypted_send(FILE_NAME,fname,strlen(fname)+1);
  if (error) {
    fprintf(stderr,"Failed to send file name\n");
    return error;
  }

  get_acknowledge(&ack,ENCRYPTED);
  if (!ack.success) {
    fprintf(stderr,"mkdir failed: %s\n",ack.msg);
    return -1;
  }
  return 0;
}

// Processes the mkdir command on the server. Responds with an acknowledge
// message to indicate success or failure.
// The sequence of messages is
//    client                 server
//  send the MKDIR command
//                         send acknowledge_msg
int mkdir_cmd_server()
{
  long error;
  char file_name[FILE_NAME_LEN];
  long bytes_read;

  error = encrypted_recv(FILE_NAME,file_name,FILE_NAME_LEN,&bytes_read);
  if (error) {
    fprintf(stderr,"Failed to receive file name\n");
    return -1;
  }

  if (mkdir(file_name,S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == 0) {
    send_success(ENCRYPTED);
  }
  else {
    send_failure(strerror(errno),ENCRYPTED);
  }
}

// Sends the rmdir command to the server.
// The sequence of messages is
//    client                 server
//  send the RMDIR command
//                         send acknowledge_msg
int rmdir_cmd_client(const char* fname)
{
  long cmd;
  long error;
  acknowledge_msg ack;

  // send the command to the server
  cmd = htonl(RMDIR);
  error = encrypted_send(COMMAND,&cmd,sizeof(cmd));
  if (error) {
    fprintf(stderr,"Failed to send command to server\n");
    return error;
  }

  // send the file name
  error = encrypted_send(FILE_NAME,fname,strlen(fname)+1);
  if (error) {
    fprintf(stderr,"Failed to send file name\n");
    return error;
  }

  get_acknowledge(&ack,ENCRYPTED);
  if (!ack.success) {
    fprintf(stderr,"rmdir failed: %s\n",ack.msg);
    return -1;
  }
  return 0;
}

// Processes the rmdir command on the server. Responds with an acknowledge
// message to indicate success or failure.
// The sequence of messages is
//    client                 server
//  send the RMDIR command
//                         send acknowledge_msg
int rmdir_cmd_server()
{
  long error;
  char file_name[FILE_NAME_LEN];
  long bytes_read;

  error = encrypted_recv(FILE_NAME,file_name,FILE_NAME_LEN,&bytes_read);
  if (error) {
    fprintf(stderr,"Failed to receive file name\n");
    return -1;
  }

  if (rmdir(file_name) == 0) {
    send_success(ENCRYPTED);
  }
  else {
    send_failure(strerror(errno),ENCRYPTED);
  }
}

// Run the system ls command locally
int lls_cmd_client(const char *args)
{
  char cmd[1024];

  strcpy(cmd,"ls ");
  if (args != NULL) {
    strncat(cmd, args, 1024);
  }
  system(cmd);
  return 0;
}

// local cd command
int lcd_cmd_client(const char *dname)
{
  int error = 0;

  error = chdir(dname);
  if (error) {
    perror("cd failed: ");
    return error;
  }
  return 0;
}

