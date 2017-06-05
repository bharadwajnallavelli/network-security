#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#include <stdio.h>
#include <stdlib.h>

const unsigned BUFSIZE=4096;
  
void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}
  
int encrypt(FILE *ifp, unsigned char *key, unsigned char *iv, FILE *ofp)  
{
  unsigned char *read_buf = malloc(BUFSIZE);
  unsigned char *cipher_buf;
  unsigned blocksize;
  int out_len;
      
  EVP_CIPHER_CTX *ctx;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();
    
  blocksize = EVP_CIPHER_CTX_block_size(ctx);
  cipher_buf = malloc(BUFSIZE + blocksize);

  while (1) {
   
	  /* Provide the message to be encrypted, and obtain the encrypted output.
	   * EVP_EncryptUpdate can be called multiple times if necessary
	   */
  
	  int numRead = fread(read_buf, sizeof(unsigned char), BUFSIZE, ifp);    
	  if(1 != EVP_EncryptUpdate(ctx, cipher_buf, &out_len, read_buf, numRead)) handleErrors();
	  fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);
	  if (numRead < BUFSIZE) { // EOF
		break;
	  }  

   } 

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, cipher_buf, &out_len)) handleErrors();
  fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  free(cipher_buf);
  free(read_buf);  

  return out_len; // TODO ?
}

int decrypt(FILE *ifp, unsigned char *key, unsigned char *iv, FILE *ofp) 
{

  unsigned char *read_buf = malloc(BUFSIZE);
  unsigned char *cipher_buf;
  unsigned blocksize;
  int out_len;

  EVP_CIPHER_CTX *ctx;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();
  
  blocksize = EVP_CIPHER_CTX_block_size(ctx);
  cipher_buf = malloc(BUFSIZE + blocksize);
  
  while (1) {
   
	  /* Provide the message to be decrypted, and obtain the plaintext output.
	   * EVP_DecryptUpdate can be called multiple times if necessary
	   */  
	  int numRead = fread(read_buf, sizeof(unsigned char), BUFSIZE, ifp);    
	  if(1 != EVP_DecryptUpdate(ctx, cipher_buf, &out_len, read_buf, numRead)) handleErrors();
	  fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);
	  if (numRead < BUFSIZE) { // EOF
		break;
	  }  
	  
   } 


  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, cipher_buf, &out_len)) handleErrors();
  fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  free(cipher_buf);
  free(read_buf);  

  return out_len; // TODO ?
  
}

int main(int argc, char *argv[])
{
  int decryptedtext_len, ciphertext_len;
  FILE *fIN, *fOUT;
  char inputFilename[255];
  char cypherFilename[255];  
  char outputFilename[255];

  
  /* Set up the key and iv.  */

  /* A 256 bit key */
  unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

  /* A 128 bit IV */
  unsigned char *iv = (unsigned char *)"0123456789012345";
  
  
  if (argc != 2) {
        printf("Usage: <executable> <cleartext-file>");
        return -1;
  } else {
		strcpy(inputFilename, argv[1]);
		strcpy(cypherFilename, "encrypted_");
		strcpy(outputFilename, "decrypted_");
		strcat(cypherFilename,  argv[1]);
		strcat(outputFilename, argv[1]);
  }


  fIN = fopen(inputFilename, "rb"); //File to be encrypted; plain text
  fOUT = fopen(cypherFilename, "wb"); //File to be written; cipher text

  /* Initialise the library */
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
//   OPENSSL_config(NULL);

  /* Encrypt the plaintext */
  ciphertext_len = encrypt (fIN, key, iv, fOUT);           
                            
  fclose(fIN);
  fclose(fOUT);                              

  fIN = fopen(cypherFilename, "rb");  //File to be read; cipher text
  fOUT = fopen(outputFilename, "wb"); //File to be written; plain text
 
//   /* Decrypt the ciphertext */
  decryptedtext_len = decrypt(fIN, key, iv, fOUT);

  fclose(fIN);
  fclose(fOUT);

  /* Clean up */
  EVP_cleanup();
  ERR_free_strings();

  return 0;
}


