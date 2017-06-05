/*
 * authorization.c
 *
 *  Created on: Apr 11, 2017
 *      Author: bill
 */

#include "pictstor.h"
#include "authorization.h"
#include "string.h"
#include <arpa/inet.h>
#include "openssl_utils.h"


#define FULL_PATH_LEN 128
#define CA_CERT_NAME "CA"
#define MAX_AUTHORIZATION_MSG_LEN 4096
#define AUTHORIZATION_FILE_NAME "authorized.txt"

/**
 * Structures
 */

/**
 * Local functions
 */
static char *generate_pem_file_path(const char *p_id, const char *p_pem_name, char *full_path, AuthorizationContext *p_auth_ctx);
static int read_my_private_key(char *file, EVP_PKEY *p_private_key);
static X509 *load_cert(const char *file);
static int verify_certificate(X509 *p_cert, AuthorizationContext *p_auth_ctx);
static void print_buffer(char *p_name, unsigned char *p_buf, int buf_len);
static void generate_challenge(unsigned char *p_challenge);
static int generate_hmac(unsigned char *p_data, int data_len, EVP_PKEY *p_signing_key, unsigned char *p_signature, size_t *p_sig_len);
static int verify_hmac(unsigned char *p_data, int data_len, EVP_PKEY *p_verifying_key, unsigned char *p_signature, size_t sig_len);

int authorization_initialize(const char *dir_path, const char *name, BOOL is_server_in, AuthorizationContext *p_auth_ctx)
{
	char filename[FULL_PATH_LEN];
	char ca_filename[FULL_PATH_LEN];

	memset(p_auth_ctx, 0, sizeof(*p_auth_ctx));

	p_auth_ctx->cert_ctx = NULL;
	p_auth_ctx->lookup = NULL;

	p_auth_ctx->p_my_cert = NULL;
	p_auth_ctx->p_ca_cert = NULL;
	p_auth_ctx->p_client_cert = NULL;

	debug_print("\n**** Initializing Authorization ****\n");
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	// ERR_load_crypto_strings();

	p_auth_ctx->server_flag = is_server_in;
	strncpy(p_auth_ctx->key_dir_path, dir_path, sizeof(p_auth_ctx->key_dir_path));
	// debug_print("Directory is %s\n", p_auth_ctx->key_dir_path);

	// Load the CA certificate
	generate_pem_file_path(CA_CERT_NAME, "_cert", ca_filename, p_auth_ctx);
	p_auth_ctx->p_ca_cert = load_cert(ca_filename);
	if (p_auth_ctx->p_ca_cert == NULL) {
		printf("Unable to load CA cert %s\n", ca_filename);
		return AUTHORIZATION_FAILURE;
	} else {
		debug_print("  Loaded the CA certificate from file %s\n", ca_filename);
	}

	// Create the certificate context with the CA certificate to use to verify certificates
	p_auth_ctx->cert_ctx=X509_STORE_new();
    if (p_auth_ctx->cert_ctx == NULL) {
    	printf("Unable to create certificate store\n");
    	return AUTHORIZATION_FAILURE;
    }

    p_auth_ctx->lookup=X509_STORE_add_lookup(p_auth_ctx->cert_ctx, X509_LOOKUP_file());
    if (p_auth_ctx->lookup == NULL) {
    	printf("Unable to create lookup\n");
    	return AUTHORIZATION_FAILURE;
    }

    if(!X509_LOOKUP_load_file(p_auth_ctx->lookup, ca_filename,X509_FILETYPE_PEM)) {
    	printf("Unable to load CA certificate from file %s\n", ca_filename);
    	return AUTHORIZATION_FAILURE;
    }

    p_auth_ctx->lookup=X509_STORE_add_lookup(p_auth_ctx->cert_ctx, X509_LOOKUP_hash_dir());
    if (p_auth_ctx->lookup == NULL) {
    	printf("Unable to add lookup\n");
    	return AUTHORIZATION_FAILURE;
    }

    X509_LOOKUP_add_dir(p_auth_ctx->lookup, NULL,X509_FILETYPE_DEFAULT);

	// Load my certificate
	generate_pem_file_path(name, "_cert", filename, p_auth_ctx);
	p_auth_ctx->p_my_cert = load_cert(filename);
	if (p_auth_ctx->p_my_cert == NULL) {
		printf("Unable to load cert %s\n", filename);
		return AUTHORIZATION_FAILURE;
	} else {
		debug_print("  Loaded my certificate from file %s\n", filename);
	}

    if (verify_certificate(p_auth_ctx->p_my_cert, p_auth_ctx) != AUTHORIZATION_SUCCESS) {
		printf("Unable to load cert %s\n", filename);
		return AUTHORIZATION_FAILURE;
    } else {
    	debug_print("  Verified my certificate\n");
    }

	char client_name[64];
	if (get_name_from_cert(p_auth_ctx->p_my_cert, client_name, 64) == AUTHORIZATION_SUCCESS){
		debug_print("  My certificate has name %s\n", client_name);
	}

	if(is_server)
		p_auth_ctx->p_server_cert = p_auth_ctx->p_my_cert;
	else
		p_auth_ctx->p_client_cert = p_auth_ctx->p_my_cert;

/*
	// Extract my public key
	EVP_PKEY *p_key = X509_get_pubkey(p_auth_ctx->p_my_cert);
	if(p_key == NULL) {
		printf("Could not retrieve my public key from my certificate\n");
		EVP_PKEY_free(p_key);
		return AUTHORIZATION_FAILURE;
	} else {
		debug_print("My public key is %d bits\n", EVP_PKEY_bits(p_key));
	}
*/

	// Load my private key
	p_auth_ctx->p_my_private_key = EVP_PKEY_new();
	generate_pem_file_path(name, "", filename, p_auth_ctx);
	if(read_my_private_key(filename, p_auth_ctx->p_my_private_key) != AUTHORIZATION_SUCCESS) {
		printf("Unable to load my private key %s\n", filename);
		return AUTHORIZATION_FAILURE;
	} else {
		debug_print("  Loaded my private key from file %s\n", filename);
	}

    /**
     * Test
     */
/*
    unsigned char challenge[512];
    memset(challenge, 1, 512);
	generate_challenge(challenge);

	unsigned char gen_signature[MAX_SIGNATURE_LEN];
	size_t gen_sig_len;
	if (generate_hmac(challenge, 512, p_auth_ctx->p_my_private_key, gen_signature, &gen_sig_len) != AUTHORIZATION_SUCCESS) {
		printf("Failed to generate HMAC\n");
		// return AUTHORIZATION_FAILURE;
	} else {
		debug_print("Generated HMAC signature of length %d\n", (int)gen_sig_len);
	}

	print_buffer("Signature", gen_signature, (int)gen_sig_len);

	if (verify_hmac(challenge, 512, p_key, gen_signature, gen_sig_len) != AUTHORIZATION_SUCCESS) {
		printf("Failed to generate Verify HMAC\n");
		EVP_PKEY_free(p_key);
		p_key = NULL;
		// return AUTHORIZATION_FAILURE;
	}
	else {
		debug_print("Verified HMAC signature\n");
	}

	if(p_key)
		EVP_PKEY_free(p_key);
*/

	return AUTHORIZATION_SUCCESS;
}

int authorization_clean_up(AuthorizationContext *p_auth_ctx)
{
	if (p_auth_ctx->p_my_cert != NULL)
		X509_free(p_auth_ctx->p_my_cert);

	if (p_auth_ctx->p_ca_cert != NULL)
		X509_free(p_auth_ctx->p_ca_cert);

	if (p_auth_ctx->cert_ctx != NULL)
		X509_STORE_free(p_auth_ctx->cert_ctx);

	if (p_auth_ctx->p_client_cert != NULL)
		X509_free(p_auth_ctx->p_client_cert);

	if (p_auth_ctx->p_my_private_key != NULL)
		EVP_PKEY_free(p_auth_ctx->p_my_private_key);

	return AUTHORIZATION_SUCCESS;
}

BOOL is_server(AuthorizationContext *p_auth_ctx)
{
	return p_auth_ctx->server_flag;
}

EVP_PKEY *get_my_private_key(AuthorizationContext *p_auth_ctx)
{
	return p_auth_ctx->p_my_private_key;
}

X509 *authorization_get_ca_cert(AuthorizationContext *p_auth_ctx)
{
	return p_auth_ctx->p_ca_cert;
}

X509 *authorization_get_my_cert(AuthorizationContext *p_auth_ctx)
{
	return p_auth_ctx->p_my_cert;
}

X509 *authorization_get_server_cert(AuthorizationContext *p_auth_ctx)
{
	return p_auth_ctx->p_server_cert;
}

X509 *authorization_get_client_cert(AuthorizationContext *p_auth_ctx)
{
	return p_auth_ctx->p_client_cert;
}

int authorization_verify_x509_cert(X509 *p_cert, AuthorizationContext *p_auth_ctx)
{
	if(verify_certificate(p_cert, p_auth_ctx) > 0) {
		debug_print("Verified Certificate\n");
		return AUTHORIZATION_SUCCESS;
	} else {
		printf("Failed to verify Certificate\n");
		return AUTHORIZATION_FAILURE;
	}
}

int get_name_from_cert(X509 *p_cert, char *p_name, int len)
{

	X509_NAME *p_subj = X509_get_subject_name(p_cert);
	if (p_subj == NULL) {
		printf("Could not retrieve cert subject\n");
		return AUTHORIZATION_FAILURE;
	}

	if(X509_NAME_get_text_by_NID(p_subj, NID_commonName, p_name, len) < 0) {
		printf("Could not retrieve cert name entry\n");
		return AUTHORIZATION_FAILURE;
	}

	return AUTHORIZATION_SUCCESS;
}

/**
 ************* Public Client Functions *******************
 */
int client_send_authorization_request(unsigned char *p_my_challenge_data, AuthorizationContext *p_auth_ctx)
{
	int error;
	client_auth_req_msg msg;
	unsigned char *p;
	X509 *p_cert = NULL;
	int result = AUTHORIZATION_SUCCESS;

	debug_print("\n<<<< Client sending authorization request to server\n");

	// Generate the challenge data and copy it so it can be referenced later
	debug_print("  Generate challenge for the server of length %d\n",CHALLENGE_DATA_LEN);
	generate_challenge(msg.client_challenge);
	memcpy(p_my_challenge_data, msg.client_challenge, CHALLENGE_DATA_LEN);

	int len;
	len = i2d_X509(p_auth_ctx->p_my_cert, NULL);

	if(len > MAX_CERT_LENGTH) {
		printf("Binary certificate is too long, %d, for the message\n", len);
		result = AUTHORIZATION_FAILURE;
		goto exit;
	}

	// debug_print("Binary certificate length is %d\n", len);
	debug_print("  Adding my certificate\n");
	p = msg.client_cert;
	len = i2d_X509(p_auth_ctx->p_my_cert, &p);
	if (len <= 0) {
		printf("Error converting client cert to binary - %s\n", get_openssl_error());
		result = AUTHORIZATION_FAILURE;
		goto exit;
	}
	msg.cert_len = htonl(len);

	// debug_print("Sending Client Authorization Request of Length %lu\n", sizeof(msg));
	error = encrypted_send(CLIENT_AUTH_REQ, &msg, sizeof(msg));
	if (error) {
		fprintf(stderr,"Failed sending client authorization request\n");
		result = AUTHORIZATION_FAILURE;
		goto exit;
	}

exit:
	return result;
}

int client_receive_authorization_challenge(unsigned char *p_server_challenge_data, unsigned char *p_my_challenge_data, AuthorizationContext *p_auth_ctx)
{
	int error;
	long encoded_len;
	int cert_len;
	unsigned char encoded_params[MAX_AUTHORIZATION_MSG_LEN];
	server_auth_challeng_msg *p_msg;
	unsigned char *p;
	char server_name[64];
	int result = AUTHORIZATION_SUCCESS;

	debug_print("\n>>>> Waiting to receive the server challenge\n");

	error = unencrypted_recv(SERVER_AUTH_CHALLENGE, encoded_params, AUTHORIZATION_BUF_SIZE, &encoded_len);
	if (error) {
		fprintf(stderr,"Failed to receive server authorization challenge\n");
		result = AUTHORIZATION_FAILURE;
		goto exit;
	}

	debug_print("  Client received server authorization challenge of length %lu\n", encoded_len);

	p_msg = (server_auth_challeng_msg *)encoded_params;

	// Get the challenge data
	memcpy(p_server_challenge_data, p_msg->server_challenge, CHALLENGE_DATA_LEN);

	// Get the server's certificate
	debug_print("  Getting the server's certificate\n");
	cert_len = ntohl(p_msg->cert_len);
	// debug_print("Length of server cert data is %d\n", cert_len);
	p = &p_msg->server_cert[0];
	p_auth_ctx->p_server_cert = d2i_X509_AUX(NULL, (const unsigned char **)&p, cert_len);
	if(p_auth_ctx->p_server_cert == NULL) {
		printf("Failed to convert server certificate\n");
		result = AUTHORIZATION_FAILURE;
		goto exit;
	}

	// Verify the server's certificate
	debug_print("  Verifying the server's certificate\n");
    if (verify_certificate(p_auth_ctx->p_server_cert, p_auth_ctx) != AUTHORIZATION_SUCCESS) {
    	printf("Failed to verify the server's certificate\n");
		result = AUTHORIZATION_FAILURE;
		goto exit;
    } else {
    	// debug_print("Verified the server's certificate\n");
    }

	if (get_name_from_cert(p_auth_ctx->p_server_cert, server_name, 64) == AUTHORIZATION_SUCCESS){
		debug_print("  Server's name is %s\n", server_name);
	}

	// Get the server's public key
	debug_print("  Extracting the server's public key from its certificate\n");
	EVP_PKEY *p_key = X509_get_pubkey(p_auth_ctx->p_server_cert);
	if(p_key == NULL) {
		printf("Could not retrieve a valid public key from server's certificate\n");
		result = AUTHORIZATION_FAILURE;
		goto exit;
	} else {
		// debug_print("Got the server public key - %d bits long\n", EVP_PKEY_bits(p_key));
	}

	// Get the signature for the challenge we sent to the server
	debug_print("  Verifying the server's signing of our challenge\n");
	int sig_len = ntohl(p_msg->client_signature_len);

	// Verify signature
	if (verify_hmac(p_my_challenge_data, CHALLENGE_DATA_LEN, p_key, p_msg->client_challenge_signature, sig_len) != AUTHORIZATION_SUCCESS) {
		printf("Failed to verify the server's signature of my challenge\n");
		result = AUTHORIZATION_FAILURE;
		goto exit;
	}
	else {
		// debug_print("Verified the server's signature of my challenge\n");
	}

exit:
	if(p_key)
		EVP_PKEY_free(p_key);
	return result;
}

int client_send_server_response(unsigned char *p_challenge_data, AuthorizationContext *p_auth_ctx)
{
	client_auth_resp_msg msg;
	int error;
	size_t gen_sig_len;
	int result = AUTHORIZATION_SUCCESS;

	debug_print("\n<<<< Client sending response to the server challenge\n");

	// Generate a signature for the server's challenge
	debug_print("  Signing the challenge sent the server sent to us\n");
	if (generate_hmac(p_challenge_data, CHALLENGE_DATA_LEN, p_auth_ctx->p_my_private_key, msg.server_challenge_signature, &gen_sig_len) != AUTHORIZATION_SUCCESS) {
		printf("Failed to generate signature for server's challenge\n");
		result = AUTHORIZATION_FAILURE;
		goto exit;
	} else {
		// debug_print("Generated signature of length %d\n", (int)gen_sig_len);
	}

	msg.server_signature_len = htonl(gen_sig_len);

	// Send the response
	// debug_print("Sending Client response to Server challenge of Length %lu\n", sizeof(msg));
	error = unencrypted_send(CLIENT_AUTH_RESPONSE, &msg, sizeof(msg));
	if (error) {
		fprintf(stderr,"Failed sending client response to server challenge\n");
		result = AUTHORIZATION_FAILURE;
		goto exit;
	}

exit:
	return result;
}

int client_receive_authorization_response(AuthorizationContext *p_auth_ctx)
{
	int error;
	long encoded_len;
	int cert_len;
	unsigned char encoded_params[MAX_AUTHORIZATION_MSG_LEN];
	server_auth_resp_msg *p_msg;
	unsigned char *p;
	char server_name[64];
	unsigned char signature[MAX_SIGNATURE_LEN];
	int result = AUTHORIZATION_SUCCESS;

	error = unencrypted_recv(SERVER_AUTH_RESPONSE, encoded_params, AUTHORIZATION_BUF_SIZE, &encoded_len);
	if (error) {
		fprintf(stderr,"Failed to receive server authorization response\n");
		result = AUTHORIZATION_FAILURE;
		goto exit;
	}

	debug_print("\n>>>> Client received server authorization response of length %lu\n", encoded_len);

	p_msg = (server_auth_resp_msg *)encoded_params;

	// Get the authorization response
	int is_authenticated = ntohl(p_msg->is_authenticated);
	if (is_authenticated) {
		debug_print("  Server accepted our authentication request\n");
		result = AUTHORIZATION_SUCCESS;
	} else {
		printf("  Server refused our authentication request!\n");
		result = AUTHORIZATION_FAILURE;
		goto exit;
	}

exit:
	return result;
}

/**
 ************* Public Server Functions *******************
 */
int is_user_authorized(char *p_username, AuthorizationContext *p_auth_ctx)
{
	  FILE *fp;
	  char full_path[FULL_PATH_LEN];
	  int is_authorized = AUTHORIZATION_FAILURE;
	  unsigned int i;
	  char line[128];
	  char *p_auth_name;

	  snprintf(full_path, FULL_PATH_LEN, "%s/%s", p_auth_ctx->key_dir_path, AUTHORIZATION_FILE_NAME);
	  // debug_print("Full Path: %s\n", full_path);

	  fp = fopen(full_path, "r");
	  if(fp == NULL) {
		  printf("Unable to open authorization file %s\n", full_path);
		  return AUTHORIZATION_FAILURE;
	  }

	  while (fgets(line, sizeof(line), fp)) {
		  p_auth_name = strtok(line, "\n");
		  // debug_print("Comparing %s and %s\n", p_username, p_auth_name);
		  if (strcmp(p_auth_name, p_username) == 0) {
			  is_authorized = AUTHORIZATION_SUCCESS;
			  break;
		  }
	  }

	  fclose(fp);

	  return is_authorized;
}

int server_receive_authorization_request(unsigned char *p_client_challenge, char *p_user_name, int max_name_len, AuthorizationContext *p_auth_ctx)
{
	int error;
	long encoded_len;
	int cert_len;
	unsigned char encoded_params[MAX_AUTHORIZATION_MSG_LEN];
	client_auth_req_msg *p_msg;
	unsigned char *p;
	int result = AUTHORIZATION_SUCCESS;

	error = encrypted_recv(CLIENT_AUTH_REQ, encoded_params, AUTHORIZATION_BUF_SIZE, &encoded_len);
	if (error) {
		fprintf(stderr,"Failed to receive client authorization request\n");
		result = AUTHORIZATION_FAILURE;
		goto exit;
	}

	debug_print("\n>>>> Server received client authorization request of length %lu\n", encoded_len);

	debug_print("  Getting client's challenge to us\n");

	p_msg = (client_auth_req_msg *)encoded_params;
	// print_buffer("Client Challenge Received on Server", p_msg->client_challenge, CHALLENGE_DATA_LEN);

	memcpy(p_client_challenge, p_msg->client_challenge, CHALLENGE_DATA_LEN);
	// debug_print("Length of challenge data is %ld\n", sizeof(p_msg->client_challenge));

	debug_print("  Getting client's certificate\n");
	cert_len = ntohl(p_msg->cert_len);
	// debug_print("Length of client cert data is %d\n", cert_len);
	p = &p_msg->client_cert[0];
	p_auth_ctx->p_client_cert = d2i_X509_AUX(NULL, (const unsigned char **)&p, cert_len);
	if(p_auth_ctx->p_client_cert == NULL) {
		printf("Failed to convert client certificate\n");
		result = AUTHORIZATION_FAILURE;
		goto exit;
	}

	// Validate the User's public key certificate
	debug_print("  Validating the client's certificate\n");
	if(verify_certificate(p_auth_ctx->p_client_cert, p_auth_ctx) != AUTHORIZATION_SUCCESS) {
		printf("Client %s key certificate is not valid\n", p_user_name);
		result = AUTHORIZATION_FAILURE;
		goto exit;
	} else {
		//debug_print("Client %s key certificate is valid\n", p_user_name);
	}

	// Get the client's name from its certificate
	if (get_name_from_cert(p_auth_ctx->p_client_cert, p_user_name, max_name_len) == AUTHORIZATION_SUCCESS){
		debug_print("  Client's name is %s\n", p_user_name);
	} else {
		printf("Could not retrieve the client name from client's certificate\n");
		result = AUTHORIZATION_FAILURE;
		goto exit;
	}

/*
	// Get the client's public key from its certificate
	debug_print("  Extracting the the client's public key from its certificate\n");
	EVP_PKEY *p_key = X509_get_pubkey(p_auth_ctx->p_client_cert);
	if(p_key == NULL) {
		printf("Could not retrieve a public key from the client's certificate\n");
		result = AUTHORIZATION_FAILURE;
		EVP_PKEY_free(p_key);
		goto exit;
	} else {
		// debug_print("Got the client public key - %d bits long\n", EVP_PKEY_bits(p_key));
		EVP_PKEY_free(p_key);
	}
*/

exit:
	return result;
}

int server_send_client_challenge(unsigned char *p_client_challenge_data, unsigned char *p_my_challenge_data, AuthorizationContext *p_auth_ctx)
{
	server_auth_challeng_msg msg;
	int error;
	size_t gen_sig_len;
	unsigned char *p;
	X509 *p_cert = NULL;
	int cert_len;
	int result = AUTHORIZATION_SUCCESS;

	debug_print("\n<<<< Server sending challenge to client\n");

	// Generate a signature for the client's challenge
	debug_print("  Signing the client's challenge to us\n");
	if (generate_hmac(p_client_challenge_data, CHALLENGE_DATA_LEN, p_auth_ctx->p_my_private_key, msg.client_challenge_signature, &gen_sig_len) != AUTHORIZATION_SUCCESS) {
		printf("Failed to generate HMAC\n");
		result = AUTHORIZATION_FAILURE;
		goto exit;
	} else {
		// debug_print("Generated signature of length %d\n", (int)gen_sig_len);
	}

	msg.client_signature_len = htonl(gen_sig_len);

	// Generate the server challenge to the client
	debug_print("  Generating a challenge string for the client\n");
	generate_challenge(p_my_challenge_data);
	memcpy(msg.server_challenge, p_my_challenge_data, CHALLENGE_DATA_LEN);

	// Send our certificate
	debug_print("  Adding our certificate\n");
	cert_len = i2d_X509(p_auth_ctx->p_my_cert, NULL);
	// debug_print("Binary certificate length will be %d\n", cert_len);

	if(cert_len > MAX_CERT_LENGTH) {
		debug_print("Binary certificate is too long, %d, for the message\n", cert_len);
		result = AUTHORIZATION_FAILURE;
		goto exit;
	}

	p = msg.server_cert;
	cert_len = i2d_X509(p_auth_ctx->p_my_cert, &p);
	if (cert_len <= 0) {
		printf("Error converting server cert to binary - %s\n", get_openssl_error());
		result = AUTHORIZATION_FAILURE;
		goto exit;
	}
	// debug_print("Binary certificate length is %d\n", cert_len);
	msg.cert_len = htonl(cert_len);

	error = unencrypted_send(SERVER_AUTH_CHALLENGE, &msg, sizeof(msg));
	if (error) {
		fprintf(stderr,"Failed sending server authorization challenge\n");
		return AUTHORIZATION_FAILURE;
	}

exit:
	return result;
}

int server_receive_client_response(unsigned char *p_my_challenge_data, AuthorizationContext *p_auth_ctx)
{
	int error;
	long encoded_len;
	unsigned char encoded_params[MAX_AUTHORIZATION_MSG_LEN];
	client_auth_resp_msg *p_msg;
	unsigned char signature[MAX_SIGNATURE_LEN];
	int result = AUTHORIZATION_SUCCESS;

	error = unencrypted_recv(CLIENT_AUTH_RESPONSE, encoded_params, AUTHORIZATION_BUF_SIZE, &encoded_len);
	if (error) {
		fprintf(stderr,"Failed to receive client challenge response\n");
		result = AUTHORIZATION_FAILURE;
		goto exit;
	}

	debug_print("\n>>>> Server received challenge response from client of length %lu\n", encoded_len);

	p_msg = (client_auth_resp_msg *)encoded_params;

	// Get the signature for the challenge we sent to the client
	debug_print("  Verifying the client's signing of our challenge\n");
	int sig_len = ntohl(p_msg->server_signature_len);
	// debug_print("Received signature with length %d\n", sig_len);
	memcpy(signature, p_msg->server_challenge_signature, sig_len);

	// Verify signature
	EVP_PKEY *p_key = X509_get_pubkey(p_auth_ctx->p_client_cert);
	if (verify_hmac(p_my_challenge_data, CHALLENGE_DATA_LEN, p_key, signature, sig_len) != AUTHORIZATION_SUCCESS) {
		printf("Failed to verify the server's signature of my challenge\n");
		result = AUTHORIZATION_FAILURE;
		goto exit;
	}
	else {
		// debug_print("Verified the server's signature of my challenge\n");
	}

exit:
	if(p_key)
		EVP_PKEY_free(p_key);
	return result;
}

int server_send_client_response(int is_authenticated, AuthorizationContext *p_auth_ctx)
{
	server_auth_resp_msg msg;
	int error;
	int result = AUTHORIZATION_SUCCESS;

	debug_print("\n<<<< Server sending response to Client of Length %lu\n", sizeof(msg));
	if(is_authenticated)
		debug_print("  Client is now authorized\n");
	else
		printf("  Client is NOT authorized\n");

	msg.is_authenticated = ntohl(is_authenticated);

	error = unencrypted_send(SERVER_AUTH_RESPONSE, &msg, sizeof(msg));
	if (error) {
		fprintf(stderr,"Failed sending server authorization response to client\n");
		result = AUTHORIZATION_FAILURE;
		goto exit;
	}

exit:
	return result;
}

/**
 * Local Functions
 */
static int validate_rsa_key_in_evp(EVP_PKEY *p_evp_key)
{
	RSA *p_rsa_key;

	p_rsa_key = EVP_PKEY_get1_RSA(p_evp_key);

	if(RSA_check_key(p_rsa_key)) {
		// debug_print("RSA key is valid\n");
	}
	else {
		printf("RSA key is invalid\n");
		return AUTHORIZATION_FAILURE;
	}

	// RSA_print_fp(stdout, p_rsa_key, 3);

	return AUTHORIZATION_SUCCESS;
}

static char *generate_pem_file_path(const char *p_id, const char *p_pem_name, char *full_path, AuthorizationContext *p_auth_ctx)
{
	snprintf(full_path, FULL_PATH_LEN, "%s/%s%s.pem", p_auth_ctx->key_dir_path, p_id, p_pem_name);
	// debug_print("Full Path: %s\n", full_path);

	return full_path;
}

static int read_my_private_key(char *file, EVP_PKEY *p_private_key)
{
	FILE *fp;
	RSA *p_rsa_key;

	fp = fopen(file,"r");
	if (fp == NULL) {
		printf("Unable to open private key file %s", file);
		return AUTHORIZATION_FAILURE;
	}

	PEM_read_PrivateKey(fp, &p_private_key, NULL, NULL);
	fclose(fp);

	if(validate_rsa_key_in_evp(p_private_key) != AUTHORIZATION_SUCCESS) {
		return AUTHORIZATION_FAILURE;
	}

	// debug_print("My private key is %d bits from file %s\n", EVP_PKEY_bits(p_private_key), file);

	return AUTHORIZATION_SUCCESS;
}

static X509 *load_cert(const char *file)
{
    X509 *x = NULL;
    BIO *cert;

    if ((cert=BIO_new(BIO_s_file())) == NULL) {
    	printf("Failed new BIO file\n");
        goto end;
    }

    if (BIO_read_filename(cert,file) <= 0) {
        printf("Failed to read certificate from file %s", file);
        goto end;
    }

    x = PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL);
    if (x == NULL) {
    	printf("Failed to get X509 from cert file\n");
        goto end;
    }

end:
/*
    if (cert != NULL)
    	BIO_free(cert);
*/

    return(x);
}

static int verify_certificate(X509 *p_cert, AuthorizationContext *p_auth_ctx)
{
    int verified = 1;
    X509_STORE_CTX *csc;

    csc = X509_STORE_CTX_new();
    if (csc == NULL) {
    	printf("Unable to create context\n");
    	return AUTHORIZATION_FAILURE;
    }

    X509_STORE_set_flags(p_auth_ctx->cert_ctx, 0);
    if(!X509_STORE_CTX_init(csc, p_auth_ctx->cert_ctx, p_cert, 0)) {
    	printf ("Unable to initialize the cert context for cert");
    	X509_STORE_CTX_free(csc);
    	return AUTHORIZATION_FAILURE;
    }

    verified = X509_verify_cert(csc);
    X509_STORE_CTX_free(csc);

    if (verified > 0) {
    	// debug_print("Certificate is valid\n");
    	return AUTHORIZATION_SUCCESS;
    } else {
    	// printf("Certificate is invalid\n");
    	return AUTHORIZATION_FAILURE;
    }
}

static void print_buffer(char *p_name, unsigned char *p_buf, int buf_len)
{
	unsigned int i;

	if(p_buf == NULL) {
		printf("Cannot print out buffer %s because the buffer pointer is NULL\n", p_name);
		return;
	}

	printf("%s:\n", p_name);
	for(i = 0; i < buf_len; i++) {
		printf("%02x", p_buf[i]);
		if((i % 32) == 0 && i != 0)
			printf("\n");
	}
	printf("\n");
}

static void generate_challenge(unsigned char *p_challenge)
{
	unsigned int i;

	for(i = 0; i < CHALLENGE_DATA_LEN; i++) {
		p_challenge[i] = (unsigned char)(i % 256);
	}
}

static int generate_hmac(unsigned char *p_data, int data_len, EVP_PKEY *p_signing_key, unsigned char *p_signature, size_t *p_sig_len)
{
	int result = AUTHORIZATION_SUCCESS;
	int req = 0;

	// debug_print ("Starting signing operation - Data Length: %d, Key Length: %d\n", data_len, EVP_PKEY_bits(p_signing_key));

    EVP_MD_CTX *mdctx = NULL;

    if(!(mdctx = EVP_MD_CTX_create())) {
    	printf("Could not create context for signing\n");
    	result = AUTHORIZATION_FAILURE;
    	goto exit;
    }

    EVP_MD_CTX_init(mdctx);

    if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, p_signing_key)) {
    	printf("Could not initialize digest for signing - %s\n", get_openssl_error());
    	result = AUTHORIZATION_FAILURE;
    	goto exit;
    }

    if(1 != EVP_DigestSignUpdate(mdctx, p_data, data_len)) {
    	printf("Could not update  hmac context for signing\n");
    	result = AUTHORIZATION_FAILURE;
    	goto exit;
    }

    if(1 != EVP_DigestSignFinal(mdctx, NULL, p_sig_len)) {
    	printf("Could not sign final to find signature length for signing\n");
    	result = AUTHORIZATION_FAILURE;
    	goto exit;
    }

    size_t sig_len = *p_sig_len;
    if(p_signature == NULL || sig_len > MAX_SIGNATURE_LEN) {
    	printf("Could not malloc signature for signing\n");
    	result = AUTHORIZATION_FAILURE;
    	goto exit;
    }

    if(1 != EVP_DigestSignFinal(mdctx, p_signature, p_sig_len)) {
    	printf("Could not generate signature for signing\n");
    	result = AUTHORIZATION_FAILURE;
    	goto exit;
    }

	// debug_print("Generated a signature of length %d\n", (int)(sig_len));
    result = AUTHORIZATION_SUCCESS;

exit:
    if(mdctx) {
    	EVP_MD_CTX_cleanup(mdctx);
    }

    return result;

}

static int verify_hmac(unsigned char *p_data, int data_len, EVP_PKEY *p_verifying_key, unsigned char *p_signature, size_t sig_len)
{
	int result = AUTHORIZATION_SUCCESS;
	int verify_result;

	// debug_print ("Starting signing verification - Data Len: %d, Signature Len: %d, Key Length: %d\n",
	//		data_len, (int) sig_len, EVP_PKEY_bits(p_verifying_key));

	// return AUTHORIZATION_SUCCESS;

	EVP_MD_CTX *mdctx = NULL;

    if(!(mdctx = EVP_MD_CTX_create())) {
    	printf("Could not create context for verifying\n");
    	result = AUTHORIZATION_FAILURE;
    	goto exit;
    }

    EVP_MD_CTX_init(mdctx);

    if(1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, p_verifying_key)) {
    	printf("Could not initialize  digest for verifying\n");
    	result = AUTHORIZATION_FAILURE;
    	goto exit;
    }

	if(1 != EVP_DigestVerifyUpdate(mdctx, p_data, (size_t)data_len)) {
    	printf("Could not update  hmac context for verifying\n");
    	result = AUTHORIZATION_FAILURE;
    	goto exit;
    }

	verify_result = EVP_DigestVerifyFinal(mdctx, p_signature, sig_len);
	if(1 == verify_result) {
		// debug_print("Successfully verified signature\n");
		result = AUTHORIZATION_SUCCESS;
	} else {
		printf("Failed to verify the signature with error %s\n", get_openssl_error());
		result = AUTHORIZATION_FAILURE;
	}

exit:

	if(mdctx) {
		EVP_MD_CTX_cleanup(mdctx);
	}

	return result;
}
