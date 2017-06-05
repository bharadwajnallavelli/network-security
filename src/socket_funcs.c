#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>

#include "socket_funcs.h"
#include "pictstor.h"

#define BACKLOG 10

static int socket_fd;  // socket file descriptor for the socket connecting
                       // the server to a client. This is used by
                       // the send/recv calls

// The client calls this routine to connect to the server. On success
// socket_fd will be set to the connected socket. The client should
// call close_socket() before exiting
int connect_to_server(const char *host_name, int port)
{
  struct hostent *host_addr;
  struct sockaddr_in server_addr;
  struct protoent *tcpproto;
  int sock;

  // get the host ip address from the name
  host_addr = gethostbyname(host_name);
  if (host_addr == NULL) {
    fprintf(stderr,"Invalid host %s\n",host_name);
    return -1;
  }

  // setup the address structure
  memset(&server_addr,0,sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons((u_short)port);
  memcpy(&server_addr.sin_addr, host_addr->h_addr, host_addr->h_length);
  
  // get the tcp protocol number
  if ((tcpproto = getprotobyname("tcp")) == NULL) {
    fprintf(stderr,"Failed to get tcp protocol number");
    return -1;
  }

  sock = socket(AF_INET,SOCK_STREAM,tcpproto->p_proto);
  if (sock < 0) {
    perror("Failed to create socket: ");
    return -1;
  }

  // connect to the server
  if (connect(sock, (struct sockaddr*)&server_addr,sizeof(server_addr)) < 0) {
    perror("connect failed: ");
    return -1;
  }

  // save the socket file descriptor
  socket_fd = sock;
  return 0;
}

// This routine is used by the server to set the socket file descriptor
// to the client returned by the accept call.
void set_client_socket(int sock)
{
  socket_fd = sock;
}

// Closes the socket
void close_socket()
{
  close(socket_fd);
  socket_fd = -1;
}

// The server calls this routine to set up the socket for client connections.
int create_server_socket(int port)
{
  struct sockaddr_in server_addr;
  struct sockaddr_in client_addr;
  struct protoent *tcpproto;
  int sock;

  // setup the server address structure
  memset(&server_addr,0,sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons((u_short)port);

  // get the tcp protocol number
  if ((tcpproto = getprotobyname("tcp")) == NULL) {
    fprintf(stderr,"Failed to get tcp protocol number");
    return -1;
  }

  // create the socket
  sock = socket(AF_INET,SOCK_STREAM,tcpproto->p_proto);
  if (sock < 0) {
    perror("Failed to create socket: ");
    return -1;
  }

  if (bind(sock, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
    perror("Failed to bind socket: ");
    return -1;
  }
  
  if (listen(sock, BACKLOG) < 0) {
    perror("listen failed");
    return -1;
  }

  return sock;
}

// Sends a block of data over the socket. First the message tpye
// and length is sent, followed by the data.
int unencrypted_send(long msg_type, const void *buf, long len)
{
  int error = 0;
  long network_len = htonl(len);
  long network_msg_type = htonl(msg_type);

  // send the message type in network format
  error = raw_send(&network_msg_type, sizeof(network_msg_type));
  if (error < 0) {
    perror("Error sending length: ");
    return error;
  }

  // send the length in network format
  error = raw_send(&network_len, sizeof(network_len));
  if (error < 0) {
    perror("Error sending length: ");
    return error;
  }

  // send the data 
  error = raw_send(buf, len);
  if (error < 0) {
    perror("Error sending data: ");
    return error;
  }
  return 0;
}

// Receives a block of data over the socket. The other side will send
// the message type and length of the data first, followed by the data.
// The number of bytes read will be returned in bytes_read.
int unencrypted_recv(long msg_type, void *buf, long maxlen, long *bytes_read)
{
  int error = 0;
  long len;
  long received_msg_type;

  // receive the message type and convert to host format
  error = raw_recv(&received_msg_type,sizeof(received_msg_type));
  if (error) {
    return error;
  }
  received_msg_type = ntohl(received_msg_type);
  if (received_msg_type != msg_type) {
    fprintf(stderr,"Received incorrect message type, "
	    "expected %ld, received %ld\n",
	    msg_type,received_msg_type);
    return -1;
  }

  // receive the length and convert to host format
  error = raw_recv(&len,sizeof(len));
  if (error)
    return error;
  len = ntohl(len);
  if (len <= 0) {
    fprintf(stderr,"Invalid packet length %ld\n",len);
    return -1;
  }

  // make sure the buffer is large enough
  if (len > maxlen) {
    fprintf(stderr,"buffer too small, len = %ld maxlen = %ld\n",
	    len,maxlen);
    return -1;
  }

  // receive the data
  error = raw_recv(buf,len);
  if (error) {
    return error;
  }

  // return the number of bytes read.
  *bytes_read = len;
  return 0;
}

// Receives a data packet of the given length over the socket. The
// routine keeps reading data until the number of bytes requested
// are read.
int raw_send(const void *buf, long len)
{
  int error = 0;

  if (send(socket_fd,buf,len,0) != len) {
    perror("send failed in raw_send: ");
    error = errno;
  }
  return error;
}

int raw_recv(void *buf, long len)
{
  ssize_t result;
  char *p = (char *) buf;

  while (len > 0) {
    // 
    result = recv(socket_fd, p, len, 0);
    if (result < 0) {
      if (errno == EINTR) {
	fprintf(stderr,"recv returned EINT\n");
	// call returned because of an interrupt, retry
	continue;
      }
      perror("error receiving packet\n");
      return -1;
    }
    if (result == 0) {
      // no data, socket closed
      return CONNECTION_CLOSED_ERROR;
    }
    // result is the number of bytes just read
    len -= result;
    p += result;
  }
  return 0;
}


  
