// socket_funcs.h
// This file contains the socket routines used by the client and server
// programs.

#ifndef SOCKET_FUNCS_H_
#define SOCKET_FUNCS_H_


int connect_to_server(const char *host_name, int port);
int create_server_socket(int port);
void set_client_socket(int sock);
void close_socket();


#endif // SOCKET_FUNCS_H_

