#Author: Vijay Nag

CC := gcc
LD := gcc
RESULTSDIR := ../3rdparty/results/
CFLAGS := -g -O0 -c -I. -I$(RESULTSDIR)/include/
LDFLAGS := -L$(RESULTSDIR)/lib/ -levent
SRCS := $(filter-out http-server.c, $(filter-out http_stub.c, $(wildcard *.c)))
OBJS := $(patsubst %.c,%.o,$(SRCS))

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

clean:
	rm -rf *.o
	rm -rf http-client http-server http-stub
