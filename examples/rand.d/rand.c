#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>

typedef unsigned char byte;

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int main (void)
{
	/* A 128 bit IV */
	unsigned char iv[16];
	int i;
    unsigned long err = 0;
    int rc = 0;	

	/* set default random method */
	const RAND_METHOD* rm = RAND_get_rand_method();
	if(rm == RAND_SSLeay())
	{
		printf("Using default generator\n");
	}

    /* Get random values */
	rc = RAND_bytes(iv, sizeof(iv));
	err = ERR_get_error();

	if(rc != 1) {
		fprintf(stderr, "RAND_bytes failed, err = 0x%lx\n", err);
	} else {	
		printf("RAND_bytes succeded, iv = %8x\n", iv);
	}
    
}


