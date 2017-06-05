/*
 * authorization.h
 *
 *  Created on: Apr 11, 2017
 *      Author: bill
 */

#ifndef SRC_AUTHORIZATION_H_
#define SRC_AUTHORIZATION_H_

#include <stdio.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

/**
 * Public Defines
 */
#define AUTHORIZATION_SUCCESS 0
#define AUTHORIZATION_FAILURE 1
#define CHALLENGE_DATA_LEN 128
#define MAX_CERT_LENGTH 1600
#define MAX_SIGNATURE_LEN 512


/**
 * Public Structures
 */
typedef enum BOOL {
	False = 0,
	True = 1
}BOOL;

typedef struct AuthorizationContext {
	BOOL server_flag;
	char key_dir_path[64];
	X509 *p_my_cert;
	X509 *p_ca_cert;
	X509 *p_client_cert; // Client certificate on the server
	X509 *p_server_cert; // Server certificate on the client
	EVP_PKEY *p_my_private_key;
	X509_STORE *cert_ctx;
	X509_LOOKUP *lookup;
}AuthorizationContext;

/**
 * Public API for both Client and Server
 */
int authorization_initialize(const char *dir_path, const char *name, BOOL is_server_in, AuthorizationContext *p_auth_ctx);
int authorization_clean_up(AuthorizationContext *p_auth_ctx);
BOOL is_server(AuthorizationContext *p_auth_ctx);
int authorization_verify_x509_cert(X509 *p_cert, AuthorizationContext *p_auth_ctx);
X509 *authorization_get_ca_cert(AuthorizationContext *p_auth_ctx);
X509 *authorization_get_my_cert(AuthorizationContext *p_auth_ctx);
X509 *authorization_get_server_cert(AuthorizationContext *p_auth_ctx);
X509 *authorization_get_client_cert(AuthorizationContext *p_auth_ctx);
int get_name_from_cert(X509 *p_cert, char *p_name, int len);
EVP_PKEY *get_my_private_key(AuthorizationContext *p_auth_ctx);
X509 *authorization_get_my_cert(AuthorizationContext *p_auth_ctx);
X509 *authorization_get_server_cert(AuthorizationContext *p_auth_ctx);
X509 *authorization_get_client_cert(AuthorizationContext *p_auth_ctx);

/**
 * Client Public API
 */
int client_send_authorization_request(unsigned char *p_my_challenge_data, AuthorizationContext *p_auth_ctx);
int client_receive_authorization_challenge(unsigned char *p_server_challenge_data, unsigned char *p_my_challenge_data, AuthorizationContext *p_auth_ctx);
int client_send_server_response(unsigned char *p_challenge_data, AuthorizationContext *p_auth_ctx);
int client_receive_authorization_response(AuthorizationContext *p_auth_ctx);

/**
 * Server Public API
 */
int server_receive_authorization_request(unsigned char *p_client_challenge, char *p_user_name, int max_name_len, AuthorizationContext *p_auth_ctx);
int server_send_client_challenge(unsigned char *p_client_challenge_data, unsigned char *p_my_challenge_data, AuthorizationContext *p_auth_ctx);
int server_receive_client_response(unsigned char *p_my_challenge_data, AuthorizationContext *p_auth_ctx);
int server_send_client_response(int is_authorized, AuthorizationContext *p_auth_ctx);
int is_user_authorized(char *p_username, AuthorizationContext *p_auth_ctx);

/**
 * Public Data structures
 */

#endif /* SRC_AUTHORIZATION_H_ */
