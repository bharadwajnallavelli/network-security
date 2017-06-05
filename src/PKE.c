// PKE.c
// This file contains the Diffie-Hellman public key exchange logic
// for the client and server
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/dh.h>
#include <openssl/pem.h>

#include "pictstor.h"
#include "socket_funcs.h"
#include "openssl_utils.h"

// file containing the Diffie-Hellman parameters
const char* params_filename = "dh_params.pem";

static unsigned char shared_key[SHARED_KEY_LEN];

int read_params(const char* filename,DH *dh);
void set_shared_key();

// Server side of the Diffie-Hellman key exchange. At the
// end of this routine the shared key is set. Other routines can get
// the key using get_shared_key().
//
// This routine uses unencrypted_send/recv. All communication after this
// routine should used encrypted_send/recv.
//
// The sequence of messages for exchanging keys with the client is:
//    server                    client
//   send DH params
//                            receive DH params
//   send public key
//                            receive server's public key
//                            send public key
//   receive client's public key
int PKE_server()
{
  int error = 0;
  DH *dh;
  char *err_msg;
  unsigned char encoded_params[DH_PARAM_LEN];
  int encoded_len;
  unsigned char *tmp;
  int key_bytes;
  key_exchange_msg key_exchange;
  BIGNUM *client_key;
  unsigned char shared_key[MAX_DH_KEY_LEN];
  long bytes_read;
  
  dh = DH_new();
  if (dh == NULL) {
    fprintf(stderr,"DH_new failed: %s\n",get_openssl_error());
    return -1;
  }

  // read DH parameters from the file. Generating the parameters takes
  // too long to do at runtime.
  error = read_params(get_config_file_path(params_filename),dh);
  if (error) {
    // try in the current directory
    fprintf(stderr,"Didn't find %s in the config directory, trying "
	    "the program directory.",params_filename);
    error = read_params(params_filename,dh);
  }
  if (error) {
    send_failure("server failed to read Diffie-Hellman params",UNENCRYPTED);
    return error;
  }

  // encode the parameters for sending to the client. i2d_DHparams changes
  // the buffer pointer so a temporary is needed.
  tmp = encoded_params;
  encoded_len = i2d_DHparams(dh,&tmp);
  if (encoded_len < 0) {
    fprintf(stderr,"i2d_DHparams failed: %s\n",get_openssl_error());
    return -1;
  }
  
  // send parameters to client
  error = unencrypted_send(DH_PARAMS,encoded_params,encoded_len);
  if (error) {
    fprintf(stderr,"Failed sending Diffie-Hellman params.\n");
    return error;
  }

  // generate public/private key pair
  if (DH_generate_key(dh) == 0) {
    fprintf(stderr,"Diffie-Hellman key generation failed: %s\n",
	    get_openssl_error());
    return -1;
  }

  // make sure buffer is large enough to send the public key
  key_bytes = BN_num_bytes(dh->pub_key);
  if (key_bytes > MAX_DH_KEY_LEN) {
    fprintf(stderr,"Generated public key too long\n");
    return -1;
  }

  // encode the public key in host independent format and send to client
  key_exchange.key_len = BN_bn2bin(dh->pub_key,key_exchange.key);
  error = unencrypted_send(DH_KEY_EXCHANGE,&key_exchange,sizeof(key_exchange));
  if (error) {
    fprintf(stderr,"failed to send public key to client\n");
    return error;
  }

  // receive and decode the client's public key
  error = unencrypted_recv(DH_KEY_EXCHANGE,&key_exchange,
			   sizeof(key_exchange),&bytes_read);
  if (error) {
    fprintf(stderr,"Failed to receive public key from client\n");
    return error;
  }
  client_key = BN_bin2bn(key_exchange.key,key_exchange.key_len,NULL);
  if (client_key == NULL) {
    fprintf(stderr,"Failed to decode public key from client\n");
  }

  // make sure the key is big enough
  key_bytes = DH_size(dh);
  if (key_bytes < SHARED_KEY_LEN) {
    fprintf(stderr,
	    "Diffie-Hellman parameters too small to generate %d-bit key\n",
	    SHARED_KEY_LEN * 8);
    return -1;
  }

  // compute the shared key
  if (DH_compute_key(shared_key,client_key,dh) == 0) {
    fprintf(stderr,"Failed to generate shared key: %s\n",
	    get_openssl_error());
    return -1;
  }

  // set the shared key so other routines can use it
  set_shared_key(shared_key,key_bytes);

  return 0;
}

// Read the Diffie-Hellman parameters from a file
// The file is expected to contain the DH structure written using
// PEM_write_DHparams.
int read_params(const char* filename,DH *dh)
{
  FILE *fp;

  fp = fopen(filename,"r");
  if (fp == NULL) {
    perror("Error opening dh_params file: ");
    return -1;
  }

  if (PEM_read_DHparams(fp,&dh,NULL,NULL) == NULL) {
    fprintf(stderr,"Failed to read Diffie-Hillman params: %s\n",
	    get_openssl_error());
    return -1;
  }
  
  fclose(fp);
  return 0;
}

// Client side of the Diffie-Hellman key exchange. At the
// end of this routine the shared key is set. Other routines can get
// the key using get_shared_key().
//
// This routine uses unencrypted_send/recv. All communication after this
// routine should used encrypted_send/recv.
//
// The sequence of messages for exchanging keys with the client is:
//    server                    client
//   send DH params
//                            receive DH params
//   send public key
//                            receive server's public key
//                            send public key
//   receive client's public key
int PKE_client()
{
  int error = 0;
  DH *dh;
  unsigned char encoded_params[DH_PARAM_LEN];
  long encoded_len;
  unsigned char *tmp;
  int dh_check_codes = 0;
  int key_bytes;
  key_exchange_msg key_exchange;
  BIGNUM *server_key = NULL;
  unsigned char shared_key[MAX_DH_KEY_LEN];  
  long bytes_read;
  
  dh = DH_new();
  if (dh == NULL) {
    fprintf(stderr,"DH_new failed: %s\n",get_openssl_error());
    return -1;
  }

  // receive and decode the Diffie-Hellman parameters from the server.
  error = unencrypted_recv(DH_PARAMS,encoded_params,DH_PARAM_LEN,&encoded_len);
  if (error) {
    fprintf(stderr,"Failed to receive Diffie-Hellman params.\n");
    return error;
  }

  // d2i_DHparams changes the buffer parameter so a temporary is needed.
  tmp = encoded_params;
  if (d2i_DHparams(&dh,(const unsigned char**)&tmp,encoded_len) == NULL) {
    fprintf(stderr,"Error decoding Diffie-Hellman params: %s.\n",
	    get_openssl_error());
    return -1;
  }

  // check the parameters just to be sure
  if (DH_check(dh,&dh_check_codes) != 1 ||
      dh_check_codes != 0) {
    fprintf(stderr,"Diffie-Hellman params failed check.\n");
    return -1;
  }

  // generate public/private key pair
  if (DH_generate_key(dh) == 0) {
    fprintf(stderr,"Diffie-Hellman key generation failed: %s\n",
	    get_openssl_error());
    return -1;
  }

  // receive and decode the server's public key
  error = unencrypted_recv(DH_KEY_EXCHANGE,&key_exchange,
			   sizeof(key_exchange),&bytes_read);
  if (error) {
    fprintf(stderr,"Failed to receive public key from server\n");
    return error;
  }
  server_key = BN_bin2bn(key_exchange.key,key_exchange.key_len,NULL);
  if (server_key == NULL) {
    fprintf(stderr,"Failed to decode public key from server\n");
  }

  // make sure buffer is large enough to send the public key
  key_bytes = BN_num_bytes(dh->pub_key);
  if (key_bytes > MAX_DH_KEY_LEN) {
    fprintf(stderr,"Generated public key too long\n");
    return -1;
  }

  // encode the public key in host independent format and send to server
  key_exchange.key_len = BN_bn2bin(dh->pub_key,key_exchange.key);
  error = unencrypted_send(DH_KEY_EXCHANGE,&key_exchange,sizeof(key_exchange));
  if (error) {
    fprintf(stderr,"failed to send public key to server\n");
    return error;
  }

  // make sure the key is big enough
  key_bytes = DH_size(dh);
  if (key_bytes < SHARED_KEY_LEN) {
    fprintf(stderr,
	    "Diffie-Hellman parameters too small to generate %d-bit key\n",
	    SHARED_KEY_LEN * 8);
    return -1;
  }

  // compute the shared key
  if (DH_compute_key(shared_key,server_key,dh) == 0) {
    fprintf(stderr,"Failed to generate shared key: %s\n",
	    get_openssl_error());
    return -1;
  }

  // set the shared key so other routines can use it
  set_shared_key(shared_key,key_bytes);

  return 0;
}

// return the shared key from the Diffie-Hellman key exchange
const unsigned char* get_shared_key() {
  return shared_key;
}

// set the shared key from the Diffie-Hellman key exchange
void set_shared_key(unsigned char *key, int len) {
  int i;
  
  memset(shared_key,0,SHARED_KEY_LEN);
  memcpy(shared_key,key,len < SHARED_KEY_LEN ? len : SHARED_KEY_LEN);


  debug_print("shared key: ");
  for (i=0;i<SHARED_KEY_LEN;++i) {
    debug_print("%02X",shared_key[i]);
  }
  debug_print("\n");
}


