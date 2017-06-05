CC = gcc
CFLAGS = -g -c -I. -I/usr/local/include -I/usr/include
## CXX_CFLAGS = -I.
LDFLAGS= -L/usr/local/lib -lcrypto

SOURCES = EVP.c 

OBJECTS = $(SOURCES:.c=.o)
EXECUTABLE = a.exe


all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@ 

.c.o:
	$(CC) $(CFLAGS) $< -o $@ $(CXX_CFLAGS)

clean:
	rm -f *.o $(EXECUTABLE)
