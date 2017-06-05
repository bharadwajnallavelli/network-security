CC = gcc
CFLAGS = -g -c -I. -I/usr/local/include -I/usr/include -I/usr/include/openssl
## CXX_CFLAGS = -I.
LDFLAGS= -L/usr/local/lib -lssl -lcrypto

PICTSTORD_SOURCES = server_main.c socket_funcs.c utils.c file_transfer.c openssl_utils.c PKE.c EVP.c file_cmds.c authorization.c sha256.c

PICTSTOR_SOURCES = client_main.c socket_funcs.c utils.c file_transfer.c openssl_utils.c PKE.c EVP.c file_cmds.c authorization.c rand.c sha256.c

GEN_DH_PARAMS_SOURCES = gen_dh_params.c openssl_utils.c

PICTSTORD_OBJECTS = $(PICTSTORD_SOURCES:.c=.o)

PICTSTOR_OBJECTS = $(PICTSTOR_SOURCES:.c=.o)

GEN_DH_PARAMS_OBJECTS = $(GEN_DH_PARAMS_SOURCES:.c=.o)

all: pictstord pictstor gen_dh_params

pictstord: $(PICTSTORD_OBJECTS)
	$(CC) $(PICTSTORD_OBJECTS) $(LDFLAGS) -o $@ 

pictstor: $(PICTSTOR_OBJECTS)
	$(CC) $(PICTSTOR_OBJECTS) $(LDFLAGS) -o $@ 

gen_dh_params: $(GEN_DH_PARAMS_OBJECTS)
	$(CC) $(GEN_DH_PARAMS_OBJECTS) $(LDFLAGS) -o $@ 

.c.o:
	$(CC) $(CFLAGS) $< -o $@ 

clean:
	rm -f *.o pictstord pictstor gen_dh_params
