
all: src/http-client src/http-server

.PHONY: docks

docks: src/http-client src/http-server
	docker build -t localhost:5000/http .

#assumes you are running docker registry at
#at port 5000. If no, please run the below
#command
#docker run -d -p 5000:5000 --restart=always --name registry registry:2

push:
	docker push localhost:5000/http

src/http-client:
	make -C src/

src/http-server:
	make -C src/ server

clean:
	make -C src/ clean

