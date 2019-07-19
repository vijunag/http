FROM ubuntu:14.04

ADD src/http-server /http-server
ADD src/http-client /http-client
ADD root /root/
CMD ["/http-server", "0.0.0.0", "80", "1", "/root"]

