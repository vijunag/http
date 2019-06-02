all: http-server http-client

http-server: http-server.c
	gcc -g -O0 http-server.c -o http-server -levent -static

http-client: http-client.c
	gcc -g -O0 http-client.c -o http-client -levent

clean:
	rm -rf http-server http-client
