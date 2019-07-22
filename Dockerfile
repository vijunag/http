FROM ubuntu:14.04

CMD apt-get install libevent-dev
ADD src/http-server /http-server
ADD src/http-client /http-client
ADD 3rdparty/results/lib/libevent-2.2.so.1.0.0 /usr/lib/x86_64-linux-gnu/libevent-2.2.so.1
ENV LD_LIBRARY_PATH "/usr/lib/x86_64-linux-gnu/"
ADD root /root/
CMD ["/http-server", "0.0.0.0", "80", "1", "/root"]

