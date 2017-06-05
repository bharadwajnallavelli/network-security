


all: ftp_client ftp_server
	gcc -o ftp_client ftp_client.o ftp_util.o
	gcc -o ftp_server ftp_server.o ftp_util.o
ftp_client: ftp_client.o ftp_util.o
	gcc -o ftp_client ftp_client.o ftp_util.o
ftp_server: ftp_server.o ftp_util.o
	gcc -o ftp_server ftp_server.o ftp_util.o
ftp_client.o: ftp_client.c ftp.h
	gcc -c ftp_client.c
ftp_server.o: ftp_server.c ftp.h
	gcc -c ftp_server.c
ftp_util.o: ftp_util.c ftp.h
	gcc -c ftp_util.c
clean:
	rm -f ftp_client ftp_server *.o
