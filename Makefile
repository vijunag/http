
all: src/http-client src/http-server

.PHONY: docks

docks: src/http-client src/http-server
	docker build -t localhost:5000/http

push:
	docker push localhost:5000/http

src/http-client:
	make -C src/

src/http-server:
	make -C src/ server

clean:
	make -C src/ clean

