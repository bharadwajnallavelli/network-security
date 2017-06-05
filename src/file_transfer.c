// file_transfer.c
//
// This file includes the routines used to handle the put and get
// commands.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <openssl/sha.h>


#include "pictstor.h"
#include "socket_funcs.h"

#define BUF_SIZE 4096  // size of the buffer used to transfer the file

static char transfer_buf[BUF_SIZE]; // buffer for file transfer

int send_file(int fd, const char *fname);
int receive_file(char *fname);
int gen_file_hash(const char *fname, const char *user_name,
		  const char *timestamp, unsigned char *hash);


typedef struct {
  char user_name[USER_NAME_LEN_MAX];
  char timestamp[FILE_TIMESTAMP_LEN];
  unsigned char hash[SHA256_DIGEST_LENGTH];
} file_sig;
		 
// implements the put command for the client given the file name
// send the PUT_FILE command and then calls send_file to
// send the file to the server
int put_cmd_client(const char *fname)
{
  long cmd;
  int fd;
  int error = 0;
  unsigned char *sig;
  long sig_len;
  long tmp;
  acknowledge_msg ack;

  // make sure file can be opened.
  fd = open(fname, O_RDONLY);
  if (fd < 0) {
    perror("Error opening file: ");
    return -1;
  }

  // send the command (in network format)
  debug_print("sending PUT_FILE command %d\n",PUT_FILE);
  cmd = htonl( PUT_FILE );
  error = encrypted_send(COMMAND,&cmd,sizeof(cmd));
  if (error) {
    close(fd);
    return error;
  }
    
  // send the file
  error = send_file(fd, fname);
  close(fd);

  debug_print("creating file hash\n");
  error = create_file_hash(fname,&sig,&sig_len);
  if (error) {
    send_failure("Failed to create file hash\n",ENCRYPTED);
    return error;
  }
  send_success(ENCRYPTED);
  tmp = htonl(sig_len);
  debug_print("sending sig length\n");
  error = encrypted_send(FILE_SIZE,&tmp,sizeof(tmp));
  if (error) {
    fprintf(stderr,"Failed to send signature length\n");
    free(sig);
    return error;
  }
  debug_print("sending sig data\n");
  error = encrypted_send(FILE_SIG,sig,sig_len);
  if (error) {
    fprintf(stderr,"Failed to send signature\n");
    free(sig);
    return error;
  }
  free(sig);

  debug_print("getting ack\n");
  get_acknowledge(&ack,ENCRYPTED);
  if (!ack.success) {
    fprintf(stderr,"Failed writing signature: %s\n",ack.msg);
    return -1;
  }

  debug_print("file send complete\n");
  return error;
}

// implements the put command for the server
// Calls receive_file to do the work
int put_cmd_server()
{
  long error = 0;
  acknowledge_msg ack;
  unsigned char *sig;
  long sig_len;
  char *file_name;
  long bytes_read;
  int fd;

  file_name = malloc(PATH_MAX);
  
  error = receive_file(file_name);
  if (error) {
    free(file_name);
    fprintf(stderr,"Failed to receive file\n");
    return error;
  }

  get_acknowledge(&ack,ENCRYPTED);
  if (!ack.success) {
    fprintf(stderr,"Error getting ack before file signature: %s\n",
	    ack.msg);
    free(file_name);
    return -1;
  }
  error = encrypted_recv(FILE_SIZE,&sig_len,sizeof(sig_len),&bytes_read);
  if (error) {
    fprintf(stderr,"Error getting signature length\n");
    free(file_name);
    return error;
  }
  sig_len = ntohl(sig_len);
  debug_print("receive sig file size: %ld\n",sig_len);
  sig = malloc(sig_len);
  error = encrypted_recv(FILE_SIG,sig,sig_len,&bytes_read);
  if (error) {
    fprintf(stderr,"Error getting file signature\n");
    free(file_name);
    free(sig);
    return error;
  }
  debug_print("received sig file data\n");
  if (strlen(file_name) + 4 >= PATH_MAX) {
    send_failure("file name too long",ENCRYPTED);
    unlink(file_name);
    free(sig);
    free(file_name);
  }

  strncat(file_name,".sig",PATH_MAX);
  fd = open(file_name,O_RDWR | O_CREAT | O_TRUNC, 0666);
  if (fd < 0) {
    perror("Error opening file: ");
    debug_print("sending failure ack\n");
    send_failure("Error opening file",ENCRYPTED);
    unlink(file_name);
    free(sig);
    free(file_name);
    return -1;
  }

  if (write(fd,sig,sig_len) != sig_len) {
    perror("Error writing signature file: ");
    send_failure("Error writing signature file",ENCRYPTED);
    unlink(file_name);
    free(sig);
    free(file_name);
  }
  debug_print("wrote sig file\n");
  send_success(ENCRYPTED);
  
  close(fd);
  free(sig);
  free(file_name);
  return error;
}

// implements the get command for the client given the file name
// Sends the GET_FILE command and the filename and then
// calls receive_file to receive the file from the server
int get_cmd_client(const char *fname)
{
  long cmd;
  int error = 0;

  // send the command (in network format)
  debug_print("sending GET_FILE command %d\n",GET_FILE);
  cmd = htonl( GET_FILE );
  error = encrypted_send(COMMAND,&cmd,sizeof(cmd));
  if (error) 
    return error;

  // send file name
  debug_print("sending file name %s\n",fname);
  error = encrypted_send(FILE_NAME,fname,strlen(fname)+1);
  if (error) {
    fprintf(stderr,"send_file failed to send file name\n");
    return error;
  }

  // recieve the file
  error = receive_file(NULL);

  // receive the signature file
  error = receive_file(NULL);
  
  return error;
}

// implements the get command for the server
// Receives the file name from the client then calls
// send_file to transfer the file.
int get_cmd_server()
{
  long error = 0;
  int fd;
  long bytes_read;
  char *sig_file_name;
  
  // receive file name
  error = encrypted_recv(FILE_NAME,transfer_buf,BUF_SIZE,&bytes_read);
  if (error) {
    fprintf(stderr,"receive_file, failed to receive file name\n");
    return error;
  }
  debug_print("received file name %s\n",transfer_buf);
  sig_file_name = malloc(strlen(transfer_buf)+5);
  strcpy(sig_file_name,transfer_buf);
  strcat(sig_file_name,".sig");
  // make sure file can be opened.
  fd = open(transfer_buf, O_RDONLY);
  if (fd < 0) {
    perror("Error opening file: ");
    free(sig_file_name);
    return -1;
  }

  // send the file
  error = send_file(fd, transfer_buf);
  close(fd);

  // make sure signature file can be opened.
  fd = open(sig_file_name, O_RDONLY);
  if (fd < 0) {
    perror("Error opening signature file: ");
    free(sig_file_name);
    return -1;
  }

  // send the signature file
  error = send_file(fd, sig_file_name);
  
  free(sig_file_name);
  close(fd);
  return error;
}

// sends a file over the socket.
//  fd is the (already open) file descriptor to the file
//  fname is the name of the file
//
// This routine is used by both the client and the server, depending
// on which side is sending the file. The other side will use receive_file.
//
// Acknowledge messages are used to detect errors from the other side.
//
// The sequence of messages to transfer a file is
//    sender                        receiver
//  send the file name
//                              receive the file name
//                              send acknowledgement
//  receive acknowledgement
//  send file length
//                              receive file length
//  send file data blocks (repeat)
//                              receive file data blocks
//                              send acknowledgement
//  receive acknowledgement
int send_file(int fd, const char *fname)
{
  ssize_t result;
  long filesize;
  off_t pos;
  int error = 0;
  acknowledge_msg ack;
  long bytes_read;
  int i;

  // send file name
  debug_print("sending file name %s\n",fname);
  error = encrypted_send(FILE_NAME,fname,strlen(fname)+1);
  if (error) {
    fprintf(stderr,"send_file failed to send file name\n");
    return error;
  }

  // receive ack from receiver. Could fail if the file cannot
  // be opened.
  debug_print("receiving ack\n");
  get_acknowledge(&ack,ENCRYPTED);
  if (!ack.success) {
    fprintf(stderr,"send failed: %s\n",ack.msg);
    return -1;
  }
  
  // get file length. remember to seek back to beginning.
  if ((pos = lseek(fd,0,SEEK_END)) < 0) {
    perror("send_file, lseek failed: ");
    
    return -1;
  }
  lseek(fd,0,SEEK_SET);
  
  debug_print("sending file size %ld\n",pos);
  // send file length (in network format)
  filesize = htonl(pos);

  error = encrypted_send(FILE_SIZE,&filesize,sizeof(filesize));
  if (error) {
    fprintf(stderr,"send_file failed to send filesize");
    return error;
  }

  // receive ack from receiver
  debug_print("receiving ack\n");
  get_acknowledge(&ack,ENCRYPTED);
  if (!ack.success) {
    fprintf(stderr,"send failed: %s\n",ack.msg);
    return -1;
  }

  // send to file in blocks of BUF_SIZE
  i = 0;
  printf("sending file blocks ... ");
  while ((result = read(fd, transfer_buf, BUF_SIZE)) > 0) {
    i++;
    if (i % 10 == 0)
      printf("#");
    error = encrypted_send(FILE_TRANSFER,transfer_buf,result);
    if (error) {
      fprintf(stderr,"send_file failed sending file block");
      return error;
    }
  }
  printf("\n");        
  if (result < 0) {
    perror("send_file, read failed: ");
    return -1;
  }


  // receive ack from receiver. Could fail if the file cannot
  // be written.

  debug_print("send_file receiving ack\n");
  get_acknowledge(&ack,ENCRYPTED);
  if (!ack.success) {
    fprintf(stderr,"send failed: %s\n",ack.msg);
    return -1;
  }
  printf("send_file done\n");
  return 0;
}

// receives a file over the socket. The name of the file will be sent
// first.
// This routine is used by both the client and the server, depending
// on which side is sending the file. The other side will use receive_file.
//
// Acknowledge messages are used to detect errors from the other side.
//
// The sequence of messages to transfer a file is
//    sender                        receiver
//  send the file name
//                              receive the file name
//                              send acknowledgement
//  receive acknowledgement
//  send file length
//                              receive file length
//  send file data blocks (repeat)
//                              receive file data blocks
//                              send acknowledgement
//  receive acknowledgement
int receive_file(char *fname_buf)
{
  long filesize;
  int error = 0;
  long bytes_read;
  int fd;
  char *error_msg = "";
  int i;
  
  // receive file name
  error = encrypted_recv(FILE_NAME,transfer_buf,BUF_SIZE,&bytes_read);
  if (error) {
    fprintf(stderr,"receive_file, failed to receive file name\n");
    return error;
  }

  if (fname_buf != NULL) {
    memcpy(fname_buf,transfer_buf,bytes_read);
  }
  // open or create the file. Send an acknowledge message.
  debug_print("received file name %s\n",transfer_buf);
  fd = open(transfer_buf,O_RDWR | O_CREAT | O_TRUNC, 0666);
  if (fd < 0) {
    perror("Error opening file: ");
    debug_print("sending failure ack\n");
    send_failure("Error opening file",ENCRYPTED);
    return -1;
  }
  else {
    debug_print("sending ack\n");
    send_success(ENCRYPTED);
  }

  // receive the length of the file and covert to host format.
  error = encrypted_recv(FILE_SIZE,&filesize,sizeof(filesize),&bytes_read);
  if (error) {
    fprintf(stderr,"receive_file, failed to receive file length\n");
    send_failure("failed to receive file length",ENCRYPTED);
    return error;
  }
  else {
    debug_print("sending ack\n");
    send_success(ENCRYPTED);
  }
    
  filesize = ntohl(filesize);
  debug_print("received file size %ld\n",filesize);

  // read data in blocks and write to the file.
  i = 0;
  printf("receiving file blocks ... ");
  while (filesize > 0) {
    i++;
    if (i % 10 == 0)
      printf("#");
    error = encrypted_recv(FILE_TRANSFER,transfer_buf,BUF_SIZE,&bytes_read);
    if (error < 0) {
      fprintf(stderr,"receive_file failed to receive file block\n");
      error_msg = "failed to receive file block";
      break;
    }
    else {
      error = write(fd,transfer_buf,bytes_read);
      if (error < 0) {
	perror("receive_file write failed: ");
	error_msg = "failed to write to file";
	break;
      }
    } 
    
    filesize -= bytes_read;
  }
  printf("\n");     
  close(fd);

  debug_print("receive file sending ack\n");
  // send an acknowledge message
  if (error < 0) {
    send_failure(error_msg,ENCRYPTED);
  }
  else {
    send_success(ENCRYPTED);
  }
  printf("receive file done\n");
  return 0;
}

int create_file_hash(const char *fname,
		     unsigned char **buf,
		     long *len)
{
  file_sig *sig;
  time_t now = time(NULL);
  int error;

  sig = malloc(sizeof(file_sig));
  strncpy(sig->user_name,get_user_name(),USER_NAME_LEN_MAX);
  sig->user_name[USER_NAME_LEN_MAX-1] = '\0';
  strncpy(sig->timestamp,ctime(&now),FILE_TIMESTAMP_LEN);
  sig->timestamp[FILE_TIMESTAMP_LEN-1] = '\0';
  // remove trailing \n from timestamp
  sig->timestamp[strlen(sig->timestamp)-1] = '\0';
  error = gen_file_hash(fname,sig->user_name,sig->timestamp,sig->hash);
  if (error) {
    fprintf(stderr,"Failed to create file hash\n");
    free(sig);
    return error;
  }
  *buf = (unsigned char *)sig;
  *len = sizeof(file_sig);
  return 0;
}

int verify_file_hash(const char *fname)
{
  char sig_file_name[PATH_MAX];
  file_sig sig;
  int fp;
  ssize_t len;
  unsigned char hash[SHA256_DIGEST_LENGTH];
  int error = 0;
  
  strncpy(sig_file_name,fname,PATH_MAX-5);
  strncat(sig_file_name,".sig",PATH_MAX);

  fp = open(sig_file_name,O_RDONLY);
  if (fp == -1) {
    printf("Verify failed. Error opening .sig file.\n");
    return -1;
  }
  len = read(fp,&sig,sizeof(sig));
  if (len != sizeof(sig)) {
    printf("Verify failed. .sig file too short.\n");
    return -1;
  }
  // null terminate strings just to be sure
  sig.user_name[USER_NAME_LEN_MAX-1] = '\0';
  sig.timestamp[FILE_TIMESTAMP_LEN-1] = '\0';
  error = gen_file_hash(fname,sig.user_name,sig.timestamp,hash);
  if (error) {
    printf("Verify failed. Failed to create hash value.\n");
    return -1;
  }
  if (memcmp(hash,sig.hash,SHA256_DIGEST_LENGTH) != 0) {
    printf("Verify failed. Hashes do not match.\n");
    return -1;
  }
  printf("File verified. Uploaded by %s on %s\n",
	 sig.user_name,sig.timestamp);
  return 0;
}
