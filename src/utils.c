// utils.c
//
// This file contains utility routines used throughout the pictstor
// project.
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>


#include "pictstor.h"
#include "socket_funcs.h"
#include "authorization.h"

unsigned char cipher_buf[CIPHER_BUF_SIZE];

static char root_dir[PATH_MAX];
static char root_file_store_dir[PATH_MAX];
static char user_name[USER_NAME_LEN_MAX];
static char user_dir[PATH_MAX];
static char config_dir[PATH_MAX];
static char config_file_buf[PATH_MAX];

int user_authentication_client(AuthorizationContext *p_auth_ctx)
{
  unsigned char my_challenge[CHALLENGE_DATA_LEN];
  unsigned char server_challenge[CHALLENGE_DATA_LEN];

  // Client sends an authorization request to the server
  if(client_send_authorization_request(my_challenge, p_auth_ctx) != AUTHORIZATION_SUCCESS) {
	  printf("Client failed to send an authorization request to the server\n");
  } else {
	  // debug_print("Client sent authorization request to the server\n");
  }

  // Receive a challenge from the server
  // Verify the server's certificate
  // Verify the signature of the client's challenge that it sent to the server with the server's public key
  if(client_receive_authorization_challenge(server_challenge, my_challenge, p_auth_ctx) != AUTHORIZATION_SUCCESS) {
	  printf("Client failed to receive a server challenge\n");
  } else {
	  // debug_print("Client received a server challenge and verified the server's identity\n");
  }

  // Client sends a challege response back to the server
  // Generates a signature for the server challenge data using the client's private key
  if(client_send_server_response(server_challenge, p_auth_ctx) != AUTHORIZATION_SUCCESS) {
	  printf("Client failed to send a server challenge response\n");
  } else {
	  // debug_print("Client sent a server challenge response\n");
  }

  // Client receives a response from the server indicating whether it has been authorized and authenthicated
  if(client_receive_authorization_response(p_auth_ctx) != AUTHORIZATION_SUCCESS) {
	  printf("Client failed to receive a server response\n");
  } else {
	  // debug_print("Client received a server response and it has been authenticated and authorized\n");
  }

  return 0;
}

int user_authentication_server(AuthorizationContext *p_auth_ctx, char *clientId)
{
  X509 *p_client_cert;
  char client_name[64];
  unsigned char client_challenge[CHALLENGE_DATA_LEN];
  unsigned char my_challenge[CHALLENGE_DATA_LEN];

  // Receive client's request to authenticate
  if (server_receive_authorization_request(client_challenge, client_name, 64, p_auth_ctx) != AUTHORIZATION_SUCCESS) {
	  printf("Error processing client's authorization request");
	  return 1;
  }

  // Check if the user is authorized
  if(is_user_authorized(client_name, p_auth_ctx) != AUTHORIZATION_SUCCESS) {
	  printf("  Client %s is not authorized\n", client_name);
	  return 1;
  } else {
	  debug_print("  Client %s is authorized\n", client_name);
  }

  // Send the server challenge back to the client
  if(server_send_client_challenge(client_challenge, my_challenge, p_auth_ctx) != AUTHORIZATION_SUCCESS) {
	  printf("Failed to send server challenge to the client\n");
	  return 1;
  } else {
	  // debug_print("Sent server challenge to the client\n");
  }

  // Receive authorization challenge response from the client
  int is_authenticated = 0;
  if(server_receive_client_response(my_challenge, p_auth_ctx) != AUTHORIZATION_SUCCESS) {
	  printf("Failed to send receive server challenge response from the client\n");
	  return 1;
  } else {
	  // debug_print("Successfully received server challenge response from the client\n");
	  is_authenticated = 1;
  }

  if(server_send_client_response(is_authenticated, p_auth_ctx) != AUTHORIZATION_SUCCESS) {
	  printf("Failed to send server authorization response to the client\n");
	  return 1;
  } else {
	  // debug_print("Successfully sent server authorization response to the client\n");
	  strncpy(clientId, client_name, 64);
  }

  return 0;
}

int encrypted_send(long msg_type, const void *buf, long len)
{
  cipher_header_msg header_msg;
  cipher_block_header_msg block_header_msg;
  long ciphertext_len;
  long blocks;
  int error = 0;
  int i;
  long plaintext_len;
  long bytes_sent = 0;
  long tmp;
  
  blocks = len / PLAINTEXT_BUF_SIZE;
  if (blocks * PLAINTEXT_BUF_SIZE < len) {
    blocks++;
  }
  
  // fill in transfer header 
  header_msg.msg_type = htonl(msg_type);
  header_msg.blocks = htonl(blocks);
  header_msg.len = htonl(len);

  // encrypt the header
  ciphertext_len = encrypt((unsigned char *)&header_msg, sizeof(header_msg),
			     (unsigned char*)get_shared_key(),iv,cipher_buf);
  if (ciphertext_len > CIPHER_BUF_SIZE) {
    fprintf(stderr,"Ciphertext overran buffer!! "
	    "Got %ld bytes, max is %d\n",
	    ciphertext_len,CIPHER_BUF_SIZE);
    return -1;
  }

  // send the length
  tmp = htonl(ciphertext_len);
  error = raw_send(&tmp,sizeof(tmp));
  if (error) {
    fprintf(stderr,"Failed in encrypted send sending header length\n");
    return -1;
  }

  // send the encrypted header
  error = raw_send(cipher_buf,ciphertext_len);
  if (error) {
    fprintf(stderr,"Failed in encrypted send sending header\n");
    return -1;
  }
  
  for (i=0;i<blocks;++i) {
    plaintext_len = len - bytes_sent;
    if (plaintext_len > PLAINTEXT_BUF_SIZE) {
      plaintext_len = PLAINTEXT_BUF_SIZE;
    }

    // fill in the header
    block_header_msg.block_num = htonl(i+1);
    block_header_msg.plaintext_len = htonl(plaintext_len);

    // encrypt the header
    ciphertext_len = encrypt((unsigned char *)&block_header_msg,
			     sizeof(block_header_msg),
			     (unsigned char *)get_shared_key(),iv,
			     cipher_buf);
    if (ciphertext_len > CIPHER_BUF_SIZE) {
      fprintf(stderr,"Ciphertext overran buffer!! "
	      "Got %ld bytes, max is %d\n",
	      ciphertext_len,CIPHER_BUF_SIZE);
      return -1;
    }

    // send the length
    tmp = htonl(ciphertext_len);
    error = raw_send(&tmp,sizeof(tmp));    
    if (error) {
      fprintf(stderr,"Failed in encrypted sending block header length\n");
      return -1;
    }
    error = raw_send(cipher_buf,ciphertext_len);
    if (error) {
      fprintf(stderr,"Failed in encrypted sending block header\n");
      return -1;
    }

    // encrypt the data
    ciphertext_len = encrypt((unsigned char*)buf,plaintext_len,
			     (unsigned char*)get_shared_key(),iv,cipher_buf);
    if (ciphertext_len > CIPHER_BUF_SIZE) {
      fprintf(stderr,"Ciphertext overran buffer!! "
	      "Got %ld bytes, max is %d\n",
	      ciphertext_len,CIPHER_BUF_SIZE);
      return -1;
    }

    // send the length
    tmp = htonl(ciphertext_len);
    error = raw_send(&tmp,sizeof(tmp));    
    if (error) {
      fprintf(stderr,"Failed in encrypted sending cipher data length\n");
      return -1;
    }
    
    // send cipher block
    error = raw_send(cipher_buf,ciphertext_len);
    if (error) {
      fprintf(stderr,"Failed in encrypted send sending cipher data\n");
      return -1;
    }

    // update pointer and byte count
    bytes_sent += plaintext_len;
    buf += plaintext_len;
  }

  return 0;
}

int encrypted_recv(long msg_type, void *buf, long maxlen,
		   long *bytes_read_return)
{
  cipher_header_msg header_msg;
  cipher_block_header_msg block_header_msg;
  long ciphertext_len;
  long blocks;
  int error = 0;
  int i;
  long plaintext_len;
  long bytes_read = 0;
  long total_bytes_read;
  

  total_bytes_read = 0;
  
  // receive the length of the encrypted header
  error = raw_recv(&ciphertext_len,sizeof(ciphertext_len));
  if (error) {
    if (error != CONNECTION_CLOSED_ERROR) {
      fprintf(stderr,"Failed in encrypted recv receiving header length\n");
    }
    return error;
  }
  ciphertext_len = ntohl(ciphertext_len);

  // receive the encrypted header and decrypt
  error = raw_recv(cipher_buf,ciphertext_len);
  if (error) {
    fprintf(stderr,"Failed in encrypted recv receiving header\n");
    return error;
  }
  plaintext_len = decrypt(cipher_buf,ciphertext_len,
			  (unsigned char*)get_shared_key(),iv,
			  (unsigned char*)&header_msg);
  if (plaintext_len != sizeof(header_msg)) {
    fprintf(stderr,"Decrypted wrong size for header\n");
    return -1;
  }
  
  // translate values to host format
  header_msg.msg_type = ntohl(header_msg.msg_type);
  header_msg.blocks = ntohl(header_msg.blocks);
  header_msg.len = ntohl(header_msg.len);

  // some error checking to make sure both sides are expecting
  // the same message type
  if (msg_type != header_msg.msg_type) {
    fprintf(stderr,"Got wrong message type in encrpyted_recv. "
	    "Expected %ld got %ld\n",msg_type,header_msg.msg_type);
    return -1;
  }
  if (maxlen < header_msg.len) {
    fprintf(stderr,"Buffer too small in encrpyted_recv. "
	    "Expected %ld got %ld\n",maxlen,header_msg.len);
    return -1;
  }

  for (i=0;i<header_msg.blocks;++i) {
    // receive the encrypted block header length
    error = raw_recv(&ciphertext_len,sizeof(ciphertext_len));
    if (error) {
      fprintf(stderr,
	      "Failed in encrypted recv receiving block header length\n");
      return error;
    }
    ciphertext_len = ntohl(ciphertext_len);

    // receive the encrypted block header and decrypt
    error = raw_recv(cipher_buf,ciphertext_len);
    if (error) {
      fprintf(stderr,"Failed in encrypted recv receiving block header\n");
      return error;
    }
    plaintext_len = decrypt(cipher_buf,ciphertext_len,
			    (unsigned char*)get_shared_key(),iv,
			    (unsigned char*)&block_header_msg);
    if (plaintext_len != sizeof(block_header_msg)) {
      fprintf(stderr,"Decrypted wrong size for block header\n");
      return -1;
    }

    // translate value to host format
    block_header_msg.block_num = ntohl(block_header_msg.block_num);
    block_header_msg.plaintext_len = ntohl(block_header_msg.plaintext_len);

    // receive the cipher data length
    error = raw_recv(&ciphertext_len,sizeof(ciphertext_len));
    if (error) {
      fprintf(stderr,"Failed in encrypted recv receiving cipher data length\n");
      return error;
    }
    ciphertext_len = ntohl(ciphertext_len);

    // receive the cipher data
    error = raw_recv(cipher_buf,ciphertext_len);
    if (error) {
      fprintf(stderr,"Failed in encrypted receiving cipher data\n");
      return -1;
    }

    // decrypt cipher data
    plaintext_len = decrypt(cipher_buf,ciphertext_len,
			    (unsigned char*)get_shared_key(),iv,buf);

    if ((plaintext_len + total_bytes_read) > maxlen) {
      fprintf(stderr,"plaintext_len = %ld, total_bytes_read = %ld\n",
	      plaintext_len,total_bytes_read);
      fprintf(stderr,"plaintext overran buffer!! "
	      "Got %ld bytes, max is %ld\n",
	      plaintext_len + total_bytes_read,
	      maxlen);
      return -1;
    }

    // update pointer and byte count
    total_bytes_read += plaintext_len;
    buf += plaintext_len;
  }

  // return the bytes read if space is provided
  if (bytes_read_return != NULL) {
    *bytes_read_return = total_bytes_read;
  }
  
  return 0;
}

// send a failure ACKNOWLEDGE message
//   msg is the failure description
//   encrypted is ENCYPTED to use the encrpyted send, UNENCRYPTED to
//      use the unencrypted send. After the initial key exchange all
//      communications should be encrypted
// 0 is returned on success, non-0 on failure
int send_failure(const char *msg, int encrypted) {
  acknowledge_msg msg_buf;
  int error = 0;

  memset(&msg_buf,0,sizeof(msg_buf));
  
  msg_buf.success = htonl(0);
  strncpy(msg_buf.msg, msg, FAILURE_MSG_LEN);
  msg_buf.msg[FAILURE_MSG_LEN-1] = '\0';
  if (encrypted) {
    error = encrypted_send(ACKNOWLEDGE,&msg_buf, sizeof(msg_buf));
  }
  else {
    error = unencrypted_send(ACKNOWLEDGE,&msg_buf, sizeof(msg_buf));
  }
    
  if (error) {
    fprintf(stderr,"unencypted send failed in send_unencrypted_failure\n");
  }
  return error;
}

// send a success ACKNOWLEDGE message
//   encrypted is ENCYPTED to use the encrpyted send, UNENCRYPTED to
//      use the unencrypted send. After the initial key exchange all
//      communications should be encrypted
// 0 is returned on success, non-0 on failure
int send_success(int encrypted) {
  acknowledge_msg msg_buf;
  int error = 0;
  
  memset(&msg_buf,0,sizeof(msg_buf));

  msg_buf.success = htonl(1);
  msg_buf.msg[0] = '\0';

  if (encrypted) {
    error = encrypted_send(ACKNOWLEDGE,&msg_buf, sizeof(msg_buf));
  }
  else {
    error = unencrypted_send(ACKNOWLEDGE,&msg_buf, sizeof(msg_buf));
  }
    
  if (error) {
    fprintf(stderr,"unencypted send failed in send_unencrypted_failure\n");
  }
  return error;
}

// receive an ACKNOWLEDGE message
// An error receiving the message is treated as a failed ack, so this
// routine always returns 0.
//   msg is a pointer to a acknowledge_msg struct to receive the message
//   encrypted is ENCYPTED to use the encrpyted send, UNENCRYPTED to
//      use the unencrypted send. After the initial key exchange all
//      communications should be encrypted
int get_acknowledge(acknowledge_msg *msg, int encrypted)
{
  int error = 0;
  long bytes_read;

  // zero out the message buffer
  memset(msg,0,sizeof(acknowledge_msg));

  // receive the message over the socket
  if (encrypted) {
    error = encrypted_recv(ACKNOWLEDGE,msg,
			   sizeof(acknowledge_msg),&bytes_read);
  }
  else {
    error = unencrypted_recv(ACKNOWLEDGE,msg,
			     sizeof(acknowledge_msg),&bytes_read);
  }
  
  // if the receive failed then treat it as a failed ack
  if (error) {
    msg->success = 0;
    strncpy(msg->msg,"Failed to receive ACKNOWLEDGE message",FAILURE_MSG_LEN);
    return 0;
  }

  // transform the success member to host format
  msg->success = ntohl(msg->success);
  return 0;
}

const char* get_root_dir()
{
  return root_dir;
}

int set_root_dir(const char *dir)
{
  int error = 0;
  struct stat dir_stat;
  
  realpath(dir,root_dir);
  root_dir[PATH_MAX] = '\0';
  debug_print("root_dir set to %s\n",root_dir);
  strncpy(root_file_store_dir,root_dir,PATH_MAX);
  strncat(root_file_store_dir,"/file_store",PATH_MAX);
  debug_print("root_file_store_dir set to %s\n",root_file_store_dir);
  // does the root file_store exist?
  if (!(stat(root_file_store_dir, &dir_stat) == 0 &&
	S_ISDIR(dir_stat.st_mode))) {
    debug_print("creating root_file_store_dir\n");
    error = mkdir(root_file_store_dir,S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    if (error) {
      perror("Failed to create file_store dir: ");
      return error;
    }
  }
  strncpy(config_dir,root_dir,PATH_MAX);
  strncat(config_dir,"/data",PATH_MAX);
  debug_print("config_dir set to %s\n",config_dir);
  // does the config dir exist?
  if (!(stat(config_dir,&dir_stat) == 0 &&
	S_ISDIR(dir_stat.st_mode))) {
    debug_print("creating config_dir\n");
    error = mkdir(config_dir,S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    if (error) {
      perror("Failed to create config dir: ");
      return error;
    }
  }
  return 0;
}

const char* get_user_name()
{
  return user_name;
}

int set_user_name_client(const char *name)
{
  strncpy(user_name,name,USER_NAME_LEN_MAX);
  user_name[USER_NAME_LEN_MAX-1] = '\0';
  debug_print("user_name set to %s\n",user_name);
}

int set_user_name_server(const char *name)
{
  struct stat dir_stat;
  int error = 0;
  
  strncpy(user_name,name,USER_NAME_LEN_MAX);
  user_name[USER_NAME_LEN_MAX-1] = '\0';
  debug_print("user_name set to %s\n",user_name);
  strncpy(user_dir,root_file_store_dir,PATH_MAX);
  strncat(user_dir,"/",PATH_MAX);
  strncat(user_dir,user_name,PATH_MAX);
  debug_print("user_dir set to %s\n",user_dir);
  if (!(stat(user_dir, &dir_stat) == 0 &&
	S_ISDIR(dir_stat.st_mode))) {
    debug_print("creating user_dir\n");
    error = mkdir(user_dir,S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    if (error) {
      perror("Failed to create user dir: ");
      return error;
    }
  }
  chdir(user_dir);
  return 0;
}

const char* get_user_dir()
{
  return user_dir;
}

const char* get_config_dir()
{
  return config_dir;
}

const char* get_config_file_path(const char *fname)
{
  strncpy(config_file_buf,config_dir,PATH_MAX);
  strncat(config_file_buf,"/",PATH_MAX);
  strncat(config_file_buf,fname,PATH_MAX);
  return config_file_buf;
}

void debug_print(const char *fmt, ...)
{
  if (DEBUG_PRINT) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr,fmt,args);
    va_end(args);
  }
}
