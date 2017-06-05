#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#include "pictstor.h"

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;
  
  int tmplen;
  int ciphertext_len;
  
  unsigned char *read_buf = malloc(BUF_SIZE);  
  unsigned char *cipher_buf;
  unsigned blocksize; 

  /* Create and initialise the context */

  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialize the encryption operation. */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  // prevent buffer overflow  
  blocksize = EVP_CIPHER_CTX_block_size(ctx);
  cipher_buf = malloc(BUF_SIZE + blocksize);
  
  /* Provide the message to be encrypted, and obtain the encrypted output */
  memcpy(read_buf,plaintext,plaintext_len);  
  
  if(1 != EVP_EncryptUpdate(ctx, cipher_buf, &tmplen, read_buf, plaintext_len)) handleErrors();  
  ciphertext_len = tmplen;  
    
  /* Finalise the encryption. */
  if(1 != EVP_EncryptFinal_ex(ctx, cipher_buf + ciphertext_len, &tmplen)) handleErrors();
  ciphertext_len += tmplen;
  
  memcpy(ciphertext,cipher_buf,ciphertext_len);

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  free(cipher_buf);
  free(read_buf);    

  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int tmplen;
  int plaintext_len;
  
  unsigned char *read_buf = malloc(BUF_SIZE);
  unsigned char *cipher_buf;
  unsigned blocksize;  

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();
  
  blocksize = EVP_CIPHER_CTX_block_size(ctx);
  cipher_buf = malloc(BUF_SIZE + blocksize);  

  /* Provide the message to be decrypted, and obtain the plaintext output. */
  memcpy(read_buf,ciphertext,ciphertext_len);
  
  if(1 != EVP_DecryptUpdate(ctx, cipher_buf, &tmplen, read_buf, ciphertext_len)) handleErrors();
  plaintext_len = tmplen;

//   if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
//     handleErrors();

  /* Finalise the decryption. */
  if(1 != EVP_DecryptFinal_ex(ctx, cipher_buf + plaintext_len, &tmplen)) handleErrors();
  plaintext_len += tmplen;
  
  memcpy(plaintext,cipher_buf,plaintext_len);

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  free(cipher_buf);
  free(read_buf);  

  return plaintext_len;
}



