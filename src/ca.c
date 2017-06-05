/*
 * ca.c
 *
 *  Created on: Apr 2, 2017
 *      Author: bill
 */

#include <stdio.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

static int verify(const char* certfile, const char* CAfile);
static X509 *load_cert(const char *file);
static int check(X509_STORE *ctx, const char *file);

void ca_initialize()
{

	int res = verify("data/user1_cert.pem", "data/CA_cert.pem");
	if(res > 0) {
		printf("Certificate is verified\n");
	} else {
		printf("Certificate is invalid\n");
	}

}

int verify(const char* certfile, const char* CAfile)
{
    int ret=0;
    X509_STORE *cert_ctx=NULL;
    X509_LOOKUP *lookup=NULL;

    cert_ctx=X509_STORE_new();
    if (cert_ctx == NULL) goto end;

    OpenSSL_add_all_algorithms();

    lookup=X509_STORE_add_lookup(cert_ctx,X509_LOOKUP_file());
    if (lookup == NULL)
        goto end;

    if(!X509_LOOKUP_load_file(lookup,CAfile,X509_FILETYPE_PEM))
        goto end;

    lookup=X509_STORE_add_lookup(cert_ctx,X509_LOOKUP_hash_dir());
    if (lookup == NULL)
        goto end;

    X509_LOOKUP_add_dir(lookup,NULL,X509_FILETYPE_DEFAULT);

    ret = check(cert_ctx, certfile);
end:
    if (cert_ctx != NULL) X509_STORE_free(cert_ctx);

    return ret;
}

static X509 *load_cert(const char *file)
{
    X509 *x=NULL;
    BIO *cert;

    if ((cert=BIO_new(BIO_s_file())) == NULL)
        goto end;

    if (BIO_read_filename(cert,file) <= 0)
        goto end;

    x = PEM_read_bio_X509_AUX(cert,NULL, NULL, NULL);

end:
    if (cert != NULL)
    	BIO_free(cert);

    return(x);
}

static int check(X509_STORE *ctx, const char *file)
{
    X509 *x=NULL;
    int i=0,ret=0;
    X509_STORE_CTX *csc;

    x = load_cert(file);
    if (x == NULL)
        goto end;

    csc = X509_STORE_CTX_new();
    if (csc == NULL)
        goto end;
    X509_STORE_set_flags(ctx, 0);
    if(!X509_STORE_CTX_init(csc,ctx,x,0))
        goto end;
    i=X509_verify_cert(csc);
    X509_STORE_CTX_free(csc);

    ret=0;
end:
    ret = (i > 0);
    if (x != NULL)
        X509_free(x);

    return(ret);
}
