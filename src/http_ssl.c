#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include "http_ssl.h"

Http_ssl_ctx global_ctx;
static int http_ssl_readcb(void *ud, char *buf, size_t len);
static int http_ssl_writecb(void *ud, char *buf, size_t len);

void* http_init_openssl(void)
{
  SSL_CTX *ctx;

  SSL_library_init(); //init it only if ssl is enabled
  OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
  SSL_load_error_strings();   /* Bring in and register error messages */
  global_ctx.method = TLSv1_2_client_method();  /* Create new client-method instance */

  ctx = SSL_CTX_new(global_ctx.method);   /* Create new context */
  if (ctx == NULL) {
    ERR_print_errors_fp(stderr);
    abort();
  }

  global_ctx.readcb = http_ssl_readcb;
  global_ctx.writecb = http_ssl_writecb;
  global_ctx.ctx = ctx;
  return ctx;
}

void http_cleanup_openssl(void)
{
  EVP_cleanup();
}

static void http_print_certificate(SSL *ssl)
{
  X509 *cert;
  char *line;

  cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
  if (cert != NULL) {
    printf("Server certificates:\n");
    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    printf("Subject: %s\n", line);
    free(line);       /* free the malloc'ed string */
    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
    printf("Issuer: %s\n", line);
    free(line);       /* free the malloc'ed string */
    X509_free(cert);     /* free the malloc'ed certificate copy */
  }
}

int http_init_ctx(http_sslclient_ctxt *hctxt, int fd)
{
  int rval;
  SSL *ssl = hctxt->ssl;

  if (!ssl) {
    ssl = SSL_new(global_ctx.ctx);
    SSL_set_fd(ssl,fd);
    SSL_set_connect_state(ssl);
    hctxt->ssl = ssl;
    hctxt->state = SSL_STATE_CONNECTING;
    hctxt->fd = fd;
  }

  rval = SSL_connect(ssl);
  if (rval < 0) {
    int ssl_error = SSL_get_error(ssl,rval);
    switch(ssl_error) {
     case SSL_ERROR_WANT_WRITE:
     case SSL_ERROR_WANT_READ:
       break;
     default: {
       long error = ERR_get_error();
       const char* error_string = ERR_error_string(error, NULL);
       printf("could not SSL_connect %s\n", error_string);
       hctxt->state = SSL_STATE_CONNECTING;
       break;
     }
    }
    return rval;
  }
  hctxt->state = SSL_STATE_CONNECTED;
  http_print_certificate(hctxt->ssl);
  return 0;
}

int http_ssl_read(http_sslclient_ctxt *ctx, char *buff, int len)
{
  int bytes;

  bytes=SSL_read(ctx->ssl,buff,len);
  if (bytes < 0) {
    int ssl_error = SSL_get_error(ctx->ssl,bytes);
    switch(ssl_error) {
     case SSL_ERROR_WANT_WRITE:
     case SSL_ERROR_WANT_READ:
       break;
     default: {
       long error = ERR_get_error();
       const char* error_string = ERR_error_string(error, NULL);
       printf("could not SSL_connect %s\n", error_string);
       break;
     }
    }
    return bytes;
  }

  buff[bytes]=0;
  return bytes;
}

int http_ssl_write(http_sslclient_ctxt *ctx, char *buff, int len)
{
  int bytes;

  bytes=SSL_write(ctx->ssl,buff,len);
  if (bytes < 0) {
    int ssl_error = SSL_get_error(ctx->ssl,bytes);
    switch(ssl_error) {
     case SSL_ERROR_WANT_WRITE:
     case SSL_ERROR_WANT_READ:
       break;
     default: {
       long error = ERR_get_error();
       const char* error_string = ERR_error_string(error, NULL);
       printf("could not SSL_connect %s\n", error_string);
       break;
     }
    }
    return bytes;
  }
  buff[bytes]=0;
  return bytes;
}

static int http_ssl_readcb(void *ud, char *buf, size_t len)
{
  static char rbuf[1024];
  http_sslclient_ctxt *ctx = (http_sslclient_ctxt*)ud;

  int rval = recv(ctx->fd, rbuf, sizeof(rbuf), 0);
  if (rval > 0) {
    rval = BIO_write(ctx->rbio, rbuf, len);
    if (rval > 0) {
      rval = http_ssl_read(ctx,buf,len);
      return rval;
    }
  }
}

static int http_ssl_writecb(void *ud, char *buf, size_t len)
{
  static char wbuf[1024];
  int l=0,rval;

  http_sslclient_ctxt *ctx = (http_sslclient_ctxt*)ud;

  rval = http_ssl_write(ctx,buf+ctx->writeidx,len);

  do {
    rval = BIO_read(ctx->wbio,wbuf,sizeof(wbuf));
    l=send(ctx->fd,wbuf,rval,0);
    ctx->writeidx +=l;
  } while (rval>0);
}
