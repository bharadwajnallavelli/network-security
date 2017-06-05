// openssl_utils.c
//
// This file contains utility functions for use with openssl

#include <openssl/err.h>

#include "openssl_utils.h"

// returns a pointer to a buffer containing the last openssl error
char *get_openssl_error()
{
  static int first_call = 1;

  // load the strings the first time this routine is called
  if (first_call) {
    ERR_load_crypto_strings();
    first_call = 0;
  }

  // return the string for the last error 
  return ERR_error_string(ERR_get_error(),NULL);
}
