#Author: Vijay Nag

CC := gcc
LD := gcc
ROOT_DIR :=../
CFLAGS := -g -O0 -c -I. -I $(ROOT_DIR)3rdparty/results/include/ -Wno-deprecated-declarations
LDFLAGS := $(ROOT_DIR)3rdparty/results/lib/libevent.a -lcrypto -lssl  -lpthread -ldl
SRCS := $(filter-out http-server.c, $(filter-out http_stub.c, $(wildcard *.c)))
OBJS := $(filter-out ssl-client.o, $(filter-out ssl-server.o, $(patsubst %.c,%.o,$(SRCS))))

all: http-client
server: http-server

%.o: %.c
	$(CC) $(CFLAGS) $^ -o $@

http-client: $(OBJS)
	$(LD) $^ -o $@ $(LDFLAGS)

http-server:
	$(LD) -g -O2 -I. -I$(ROOT_DIR)3rdparty/results/include  http-server.c -o http-server $(LDFLAGS)

test: $(OBJS)
	$(LD) -g -O0 http_stub.c -o http_stub $(filter-out http-client.o, $(OBJS)) $(LDFLAGS)
	@./http_stub || true

ssl:
	gcc -g -I 3rdparty/include/ ssl-client.c -L3rdparty/openssl-master/ -lcrypto -lssl -o ssl-client
	gcc -g -I 3rdparty/include/ ssl-server.c -L3rdparty/openssl-master/ -lcrypto -lssl -o ssl-server

clean:
	rm -rf *.o
	rm -rf http-client http-server http-stub ssl-client ssl-server
