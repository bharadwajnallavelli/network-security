#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>

#include "pictstor.h"

typedef unsigned char byte;

int get_rand_iv(void)
{
	/* A 128 bit IV */
	unsigned char iv[16];
	int i, error, rc = 0;
    unsigned long err = 0;

	/* set default random method */
	const RAND_METHOD* rm = RAND_get_rand_method();
	if(rm == RAND_SSLeay())
	{
		debug_print("Using default generator\n");
	}

    /* Get random values */
	rc = RAND_bytes(iv, sizeof(iv));
	err = ERR_get_error();
	
	if(rc != 1) {
		fprintf(stderr, "RAND_bytes failed, err = 0x%lx\n", err);
	} else {	
		// printf("RAND_bytes succeded, iv = %8x\n", iv);
		error = 0;
	}
        
    return error;    
}
