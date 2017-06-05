// gen_dh_params.c
//
// This program generates the Diffie-Hellman opensll parameters and
// writes them to a file.
//
// The pictstor server will read these parameters from the file and
// send the to the client so that both programs are using the same
// parameters.
//
// The parameters are generated and stored in a file instead of being generated
// at run time because the man page for DH_generate_parameters_ex states
// that the call "may run for several hours before finding a suitable prime".
//
// The program is run as gen_dh_params <filename>
//
// The pictstor server will load a file named dh_params.pem

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/dh.h>
#include <openssl/pem.h>

#include "openssl_utils.h"

#define PRIME_LEN 2048
#define OPENSSL_ERROR_LEN 256

void usage();

int main(int argc, char **argv)
{
  int result;
  DH *dh;
  unsigned long dh_error;
  unsigned char openssl_error[OPENSSL_ERROR_LEN];
  unsigned char output_buf[1024];
  int len;
  unsigned char *tmp;
  FILE *fp;

  // expect one parameter, the output file name
  if (argc != 2) {
    usage();
    return -1;
  }

  dh = DH_new();
  if (dh == NULL) {
    fprintf(stderr,"DH_new failed: %s\n",get_openssl_error());
    return -1;
  }

  // generate parameters
  result = DH_generate_parameters_ex(dh,PRIME_LEN,DH_GENERATOR_2,NULL);
  if (result == 0) {
    fprintf(stderr,"DH_generate_parameters_ex failed: %s\n",
	    get_openssl_error());
    return -1;
  }

  fp = fopen(argv[1],"w");
  if (fp == NULL) {
    perror("Error opening file: ");
    return -1;
  }
  if (PEM_write_DHparams(fp,dh) == 0) {
    fprintf(stderr,"Failed to write Diffie-Hellman params: %s\n",
	    get_openssl_error());
    return -1;
  }
  fclose(fp);
  
  return 0;
}

void usage()
{
  fprintf(stderr,"gen_dh_params <file name>\n");
}
