// pictstor.h
// This file contains definitions used throughout the pictstor project

#ifndef PICTSTOR_H_
#define PICTSTOR_H_

#include <limits.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#include "authorization.h"

#define SHARED_KEY_LEN 32

#define ENCRYPTED 1
#define UNENCRYPTED 0

#define BUF_SIZE 4096
#define PLAINTEXT_BUF_SIZE 2048
#define CIPHER_BUF_SIZE (PLAINTEXT_BUF_SIZE + 1024)
#define DH_PARAM_LEN 1024
#define AUTHORIZATION_BUF_SIZE 4096
#define USER_NAME_LEN_MAX 64

#define CONNECTION_CLOSED_ERROR (-42)

#define DEBUG_PRINT 0
void debug_print(const char *fmt, ...);

// Initialization vector. 16 bytes for AES 256
static unsigned char iv[16];

// List of supported commands
typedef enum {
  GET_FILE,
  PUT_FILE,
  CD,
  RM,
  LS,
  MKDIR,
  RMDIR,
} command;

typedef enum {
  ACKNOWLEDGE = 1,
  COMMAND,
  FILE_TRANSFER,
  FILE_NAME,
  FILE_SIZE,
  FILE_SIG,
  DH_PARAMS,
  DH_KEY_EXCHANGE,
  CIPHERTEXT_HEADER,
  CIPHERTEXT_BLOCK_HEADER,
  CIPHERTEXT_DATA,
  LS_ITEM,
  CLIENT_AUTH_REQ,
  SERVER_AUTH_CHALLENGE,
  CLIENT_AUTH_RESPONSE,
  SERVER_AUTH_RESPONSE,
} message_type;

#define FAILURE_MSG_LEN 1024
typedef struct  {
  int success;
  char msg[FAILURE_MSG_LEN];
} acknowledge_msg;

#define MAX_DH_KEY_LEN 1024
typedef struct {
  int key_len;
  unsigned char key[MAX_DH_KEY_LEN];
} key_exchange_msg;

typedef struct {
  long msg_type;
  long blocks;
  long len;
} cipher_header_msg;

typedef struct {
  long block_num;
  long plaintext_len;
} cipher_block_header_msg;

#define FILE_NAME_LEN (PATH_MAX+1)
#define FILE_TIMESTAMP_LEN 48
typedef struct {
  long valid;
  long file_size;
  char name[FILE_NAME_LEN];
  char timestamp[FILE_TIMESTAMP_LEN];
} ls_item_msg;

// forward declaractions

/**
 * Authorization Messages and Global Structures
 */
typedef struct __attribute__((__packed__)){
	unsigned char client_challenge[CHALLENGE_DATA_LEN];
	unsigned char client_cert[MAX_CERT_LENGTH];
	int cert_len;
}client_auth_req_msg;

typedef struct __attribute__((__packed__)){
	unsigned char server_challenge[CHALLENGE_DATA_LEN];
	unsigned char client_challenge_signature[MAX_SIGNATURE_LEN];
	int           client_signature_len;
	unsigned char server_cert[MAX_CERT_LENGTH];
	int           cert_len;
}server_auth_challeng_msg;

typedef struct __attribute__((__packed__)){
	unsigned char server_challenge_signature[MAX_SIGNATURE_LEN];
	int           server_signature_len;
}client_auth_resp_msg;

typedef struct __attribute__((__packed__)){
	int is_authenticated;
}server_auth_resp_msg;

int PKE_client();
int PKE_server();

int user_authentication_client(AuthorizationContext *p_auth_ctx);
int user_authentication_server(AuthorizationContext *p_auth_ctx, char clientId[64]);
int get_rand_iv();

int put_cmd_client(const char *fname);
int get_cmd_client(const char *fname);
int put_cmd_server();
int get_cmd_server();
int ls_cmd_client();
int ls_cmd_server();
int rm_cmd_client();
int rm_cmd_server();
int cd_cmd_client();
int cd_cmd_server();
int mkdir_cmd_client(const char* fname);
int mkdir_cmd_server();
int rmdir_cmd_client(const char* fname);
int rmdir_cmd_server();
int lls_cmd_client(const char *args);
int lcd_cmd_client(const char *dname);

int unencrypted_send(long msg_type, const void *buf, long len);
int unencrypted_recv(long msg_type, void *buf, long maxlen, long *bytes_read);

int encrypted_send(long msg_type, const void *buf, long len);
int encrypted_recv(long msg_type, void *buf, long maxlen, long *bytes_read);

int raw_send(const void *buf, long len);
int raw_recv(void *buf, long len);

int send_failure(const char *msg, int encrypted);
int send_success(int encrypted);
int get_acknowledge(acknowledge_msg *msg, int encrypted);

const char* get_root_dir();
int set_root_dir(const char *dir);
const char* get_user_name();
int set_user_name_client(const char *name);
int set_user_name_server(const char *name);
const char* get_user_dir();
const char* get_config_dir();
const char* get_config_file_path(const char *fname);

const unsigned char* get_shared_key();

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	    unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	    unsigned char *iv, unsigned char *plaintext);

int create_file_hash(const char *fname,
		     unsigned char **buf,
		     long *len);
int verify_file_hash();


#endif // PICTSTOR_H_
