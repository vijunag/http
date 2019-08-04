
all: src/http-client src/http-server

LIBDIR := $(shell pwd)/3rdparty/results/
INC := 3rdparty/results/include/
LIBS := $(LIBDIR)/lib/libevent.a

.PHONY: docks

docks: src/http-client src/http-server
	docker build -t localhost:5000/http-server .
	docker tag localhost:5000/http-server localhost:5000/http-server:latest

#assumes you are running docker registry at
#at port 5000. If no, please run the below
#command
#docker run -d -p 5000:5000 --restart=always --name registry registry:2

push:
	docker push localhost:5000/http-server

3rdparty/libevent-master/configure:
	@cd 3rdparty/libevent-master/autogen.sh

$(LIBDIR)/lib/libevent.a: 3rdparty/libevent-master/configure
	@mkdir -p $(LIBDIR)
	@cd 3rdparty/libevent-master/ && ./configure --prefix=$(LIBDIR)/ && make install

src/http-client: $(LIBS)
	make -C src/

src/http-server: $(LIBS)
	make -C src/ server

clean:
	make -C src/ clean

