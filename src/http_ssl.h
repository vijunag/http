#ifndef __HTTP_SSL_H__
#define __HTTP_SSL_H__

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

typedef enum HttpSslState {
  SSL_STATE_INVALID,
  SSL_STATE_CONNECTING,
  SSL_STATE_CONNECTED,
  SSL_STATE_SHUTDOWN
} HttpSslState;

typedef int (*http_ssl_callback)(void *ud, char *buf, size_t len);
typedef struct Http_ssl_ctx {
  SSL_CTX *ctx;
  SSL_METHOD *method;
  http_ssl_callback readcb;
  http_ssl_callback writecb;
} Http_ssl_ctx;

typedef struct http_sslclient_ctxt {
  int fd;
  HttpSslState state;
  SSL *ssl;
  BIO *rbio; //SSL_read after writing to rbio
  BIO *wbio; //SSL_write after reading into wbio
  int writeidx; //idx into http_get_req
} http_sslclient_ctxt;

extern void* http_init_openssl(void);
extern void http_cleanup_openssl(void);
int http_init_ctx(http_sslclient_ctxt *hctxt, int fd);
int http_ssl_read(http_sslclient_ctxt *ctx, char *buff, int len);
int http_ssl_write(http_sslclient_ctxt *ctx, char *buff, int len);

#endif /*__HTTP_SSL_H__*/
