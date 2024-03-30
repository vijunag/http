#Author: Vijay Nag

CC := gcc
LD := gcc
CFLAGS := -I/usr/local/octave/3.8.0/include/ -g -O0 -c -I. -I 3rdparty/include/ -Wno-deprecated-declarations
LDFLAGS := -L3rdparty/results/lib -levent -lcrypto -lssl  -lpthread -ldl
SRCS := $(filter-out http-server.c, $(filter-out http_stub.c, $(wildcard *.c)))
OBJS := $(filter-out ssl-client.o, $(filter-out ssl-server.o, $(patsubst %.c,%.o,$(SRCS))))

all: http-client
server: http-server

%.o: %.c
	$(CC) $(CFLAGS) $^ -o $@

http-client: $(OBJS)
	$(LD) $^ -o $@ $(LDFLAGS)

http-server:
	$(LD) -g -O0 http-server.c -o http-server $(LDFLAGS)

test: $(OBJS)
	$(LD) -g -O0 http_stub.c -o http_stub $(filter-out http-client.o, $(OBJS)) $(LDFLAGS)
	@./http_stub || true

ssl:
	gcc -g -I 3rdparty/include/ ssl-client.c -L3rdparty/openssl-master/ -lcrypto -lssl -o ssl-client
	gcc -g -I 3rdparty/include/ ssl-server.c -L3rdparty/openssl-master/ -lcrypto -lssl -o ssl-server

clean:
	rm -rf *.o
	rm -rf http-client http-server http-stub ssl-client ssl-server
