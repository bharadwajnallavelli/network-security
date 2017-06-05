CC = gcc
CFLAGS = -g -c -I. -I/usr/local/include -I/usr/include
LDFLAGS= -L/usr/local/lib -L/usr/lib64 -lcrypto -lssl

SOURCES = rand.c 

OBJECTS = $(SOURCES:.c=.o)
EXECUTABLE = a.exe

all: clean $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@ 

.c.o:
	$(CC) $(CFLAGS) $< -o $@ $(CXX_CFLAGS)

clean:
	rm -f *.o $(EXECUTABLE)
