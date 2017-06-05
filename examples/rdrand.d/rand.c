#include <linux/random.h>
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

    ENGINE_load_rdrand();

    ENGINE* eng = ENGINE_by_id("rdrand");
    err = ERR_get_error();

    if(NULL == eng) {
        fprintf(stderr, "ENGINE_load_rdrand failed, err = 0x%lx\n", err);
        abort(); /* failed */
    }

    rc = ENGINE_init(eng);
    err = ERR_get_error();

    if(0 == rc) {
        fprintf(stderr, "ENGINE_init failed, err = 0x%lx\n", err);
        abort(); /* failed */
    }
  
    rc = ENGINE_set_default(eng, ENGINE_METHOD_RAND);
    err = ERR_get_error();

    if(0 == rc) {
        fprintf(stderr, "ENGINE_set_default failed, err = 0x%lx\n", err);
        abort(); /* failed */
    }

    // Get random values
	rc = RAND_bytes(iv, sizeof(iv));
	err = ERR_get_error();

	if(rc != 1) {
		fprintf(stderr, "RAND_bytes failed, err = 0x%lx\n", err);
	} else {	
		printf("RAND_bytes succeded, iv = %8x\n", iv);
	}
    
    // Cleanup
    ENGINE_finish(eng);
    ENGINE_free(eng);
    ENGINE_cleanup();


}


