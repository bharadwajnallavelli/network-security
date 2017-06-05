/*
 * compile with:
 * cc test.c -lcrypto
 * author : Bharadwaj
 */
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

int gen_file_hash(const char *fname, const char *user_name,
		  const char *timestamp, unsigned char *hash)
{
	unsigned char buffer[BUFSIZ];
	FILE *f;
	SHA256_CTX ctx;
	size_t len;

	f = fopen(fname, "r");
	if (!f) {
		fprintf(stderr, "couldn't open %s\n", fname);
		return 1;
	}
	SHA256_Init(&ctx);
	SHA256_Update(&ctx,fname,strlen(fname));
	SHA256_Update(&ctx,timestamp,strlen(timestamp));
	do {
		len = fread(buffer, 1, BUFSIZ, f);
		SHA256_Update(&ctx, buffer, len);
	} while (len == BUFSIZ);
	SHA256_Final(buffer, &ctx);
	fclose(f);
	memcpy(hash,buffer,SHA256_DIGEST_LENGTH);
	return 0;
}
