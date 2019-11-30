all : client.o server.o server_select.o helpers.o
	gcc -o client client.o helpers.o
	gcc -o server server.o helpers.o
	gcc -o server_select server_select.o helpers.o

server_select.o : server_select.c
	gcc -c -o server_select.o server_select.c

server.o : server.c
	gcc -c -o server.o server.c

client.o : client.c
	gcc -c -o client.o client.c

helpers.o : helpers.c
	gcc -c -o helpers.o helpers.c

clean :
	rm client server server_select *.o
