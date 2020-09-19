#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <malloc.h>
#include <string.h>
#include <poll.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL    -1
SSL_CTX *ctx;

int OpenConnection(const char *hostname, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    fcntl(sd, F_SETFL, fcntl(sd, F_GETFL, 0) | O_NONBLOCK);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if (connect(sd, (struct sockaddr*)&addr, sizeof(addr))==-1) {
      if (EINPROGRESS != errno) {
        close(sd);
        perror(hostname);
        abort();
      }
    }
    return sd;
}

SSL_CTX* InitCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = TLSv1_2_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */

    if ( ctx == NULL ) {
      ERR_print_errors_fp(stderr);
      abort();
    }
    return ctx;
}

void ShowCerts(SSL* ssl)
{
  X509 *cert;
  char *line;

  cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
  if ( cert != NULL ) {
   printf("Server certificates:\n");
   line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
   printf("Subject: %s\n", line);
   free(line);       /* free the malloc'ed string */
   line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
   printf("Issuer: %s\n", line);
   free(line);       /* free the malloc'ed string */
   X509_free(cert);     /* free the malloc'ed certificate copy */
  } else {
   printf("Info: No client certificates configured.\n");
  }
}

SSL *ssl;
typedef enum State {
  INVALID,
  CONNECTING,
  CONNECTED
} State;

State clientState;
typedef int  (*event_callback)(int fd, short flags, void *ud);
event_callback write_cb;
event_callback read_cb;
BIO *rbio, *wbio;

static int tx_handler(int fd, short flags, void *ud);

static int cnxn_handler(int fd, short flags, void *ud)
{
  int rval;
  static char buf[1025];

  printf("%s() fired\n", __func__);

  rval = SSL_connect(ssl);
  if (rval < 0) {
    int ssl_error = SSL_get_error(ssl,rval);
    switch(ssl_error) {
    case SSL_ERROR_WANT_WRITE:
      printf("SSL needs write\n");
      break;
    case SSL_ERROR_WANT_READ: {
//      int len = recv(fd, buf, sizeof(buf),0);
//      BIO_write(rbio,buf,len);
      printf("SSL needs read\n");
      break;
    }
     default: {
      long error = ERR_get_error();
      const char* error_string = ERR_error_string(error, NULL);
      printf("could not SSL_connect %s\n", error_string);
      break;
     }
    }
    return rval;
  }
  printf("Socket connected\n");
  clientState = CONNECTED;
  return 0;
}

static int rx_handler(int fd, short flags, void *ud)
{
  static char buff[1024];

  int rval = SSL_read(ssl, buff, sizeof(buff));
  if (rval < 0) {
   int ssl_error = SSL_get_error(ssl,rval);
   switch(ssl_error) {
   case SSL_ERROR_WANT_WRITE:
     printf("SSL needs write in rx_handler\n");
     break;
   case SSL_ERROR_WANT_READ:
     printf("SSL needs read in rx_handler\n");
     break;
    default: {
     long error = ERR_get_error();
     const char* error_string = ERR_error_string(error, NULL);
     printf("could not SSL_read %s\n", error_string);
     break;
    }
   }
   return rval;
  }
  printf("%s() fired\n", __func__);
}

static int tx_handler(int fd, short flags, void *ud)
{
  static char buff[1024];

  int rval = SSL_write(ssl, buff, sizeof(buff));
  int ssl_error = SSL_get_error(ssl,rval);
  switch(ssl_error) {
  case SSL_ERROR_WANT_WRITE:
    printf("SSL needs write in tx_handler\n");
    break;
  case SSL_ERROR_WANT_READ:
    printf("SSL needs read in tx_handler\n");
    break;
   default: {
    long error = ERR_get_error();
    const char* error_string = ERR_error_string(error, NULL);
    printf("could not SSL_write %s\n", error_string);
    break;
   }
   return rval;
  }
  printf("%s() fired\n", __func__);
}

int main(int count, char *strings[])
{
   int server;
   char buf[1024];
   int rval;
   char acClientRequest[1024] ={0};
   int bytes;
   char *hostname, *portnum;
   struct pollfd pollfds[8192];

    if ( count != 3 ) {
      printf("usage: %s <hostname> <portnum>\n", strings[0]);
      exit(0);
    }

    SSL_library_init();
    hostname=strings[1];
    portnum=strings[2];

    ctx = InitCTX();
    server = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());

    clientState = CONNECTING;
    write_cb = cnxn_handler; //initially set it to cnxn_handler
    read_cb  = rx_handler; //read handler always

    pollfds[0].fd = server;
    pollfds[0].events = POLLOUT | POLLERR | POLLHUP;

    while (1) {
      int i=0;
      int revents = poll(pollfds, 1, -1);
      for (i=0;i<revents;++i) {
        if (pollfds[i].revents&POLLIN) {
          read_cb(pollfds[i].fd, POLLIN, NULL);
        }
        if (pollfds[i].revents&POLLOUT) {
          int res = write_cb(pollfds[i].fd, POLLOUT, NULL);
          if (res >= 0) {
            pollfds[i].events &= ~POLLOUT;
            pollfds[i].events |= POLLIN;
          }
        } else {
          //error
        }
      }
    }

    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
     else {

        char acUsername[16] ={0};
 char acPassword[16] ={0};
     const char *cpRequestMessage = "<Body>\
                              <UserName>%s<UserName>\
 <Password>%s<Password>\
 <\Body>";

        printf("Enter the User Name : ");
 scanf("%s",acUsername);

 printf("\n\nEnter the Password : ");
 scanf("%s",acPassword);

        sprintf(acClientRequest, cpRequestMessage, acUsername,acPassword);   /* construct reply */

        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* get any certs */
        SSL_write(ssl,acClientRequest, strlen(acClientRequest));   /* encrypt & send message */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
        buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);
        SSL_free(ssl);        /* release connection state */
    }
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    return 0;
}
