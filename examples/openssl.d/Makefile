CC = gcc
CFLAGS = -g -c -I. -I/usr/local/include -I/usr/include
## CXX_CFLAGS = -I.
LDFLAGS= -L/usr/local/lib -L/usr/lib64 -lssl -lcrypto

OBJECTS = $(SOURCES:.c=.o)


all: clean serv cli

cli:  cli.o
	$(CC) $(LDFLAGS) cli.o -o $@ 

serv:  serv.o
	$(CC) $(LDFLAGS) serv.o -o $@ 

.c.o:
	$(CC) $(CFLAGS) $< -o $@ 

clean:
	rm -f *.o cli serv
