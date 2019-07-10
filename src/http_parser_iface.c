/* Author: Vijay Nag
 * Interface file with the NodeJS Parser
 * Parser agnostic interface to facilitate
 * any parser in future
 */
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h> /* rand */
#include <string.h>
#include <stdarg.h>
#include <inttypes.h>
#include "http_parser_iface.h"

/*compile time only knob for now*/
#define DEBUG_PARSER(fmt,...)            \
  if (http_log_enable) {                 \
    fprintf(stderr,fmt,__VA_ARGS__);     \
  }                                      \

#define STRINGIZE(x) \
  #x
#define STRCONCAT(x,y) \
  STRINGIZE(x##y)
#define TMPL(str) \
  STRCONCAT(HTTP_EV_TYPE_,str),

const char *HttpEventStr[HTTP_EV_TYPE_MAX+1] = {
  TMPL_LIST
#undef TMPL
};
static int http_log_enable;

void HttpLogEnable(void)
{
  http_log_enable=1;
}

static int message_begin_cb (http_parser *p)
{
  HttpParserHandle *this = p->data;
  DEBUG_PARSER("%s():%d called\n",__func__,__LINE__);
  this->cb(HTTP_EV_TYPE_MSG_BEGIN,this->ud);
  return 0;
}

static int header_field_cb(http_parser *p, const char *buf, size_t len)
{
  HttpParserHandle *this = p->data;
  DEBUG_PARSER("%s():%d called\n",__func__,__LINE__);
  this->cb(HTTP_EV_TYPE_HDR_FIELD,this->ud);
  return 0;
}

static int header_value_cb(http_parser *p, const char *buf, size_t len)
{
  HttpParserHandle *this = p->data;
  DEBUG_PARSER("%s():%d called\n",__func__,__LINE__);
  this->cb(HTTP_EV_TYPE_HDR_VALUE,this->ud);
  return 0;
}

static int request_url_cb(http_parser *p, const char *buf, size_t len)
{
  HttpParserHandle *this = p->data;
  DEBUG_PARSER("%s():%d called\n",__func__,__LINE__);
  this->cb(HTTP_EV_TYPE_REQ_URL,this->ud);
  return 0;
}

static int response_status_cb(http_parser *p, const char *buf, size_t len)
{
  HttpParserHandle *this = p->data;
  DEBUG_PARSER("%s():%d called\n",__func__,__LINE__);
  this->cb(HTTP_EV_TYPE_RSP_STATUS,this->ud);
  return 0;
}

static int body_cb(http_parser *p, const char *buf, size_t len)
{
  HttpParserHandle *this = p->data;
  DEBUG_PARSER("%s():%d called\n",__func__,__LINE__);
  this->cb(HTTP_EV_TYPE_BODY,this->ud);
  return 0;
}

static int header_complete_cb(http_parser *p, const char *buf, size_t len)
{
  HttpParserHandle *this = p->data;
  DEBUG_PARSER("%s():%d called\n",__func__,__LINE__);
  this->cb(HTTP_EV_TYPE_HDR_COMPLETE,this->ud);
  return 0;
}

static int headers_complete_cb(http_parser *p)
{
  HttpParserHandle *this = p->data;
  DEBUG_PARSER("%s():%d called\n",__func__,__LINE__);
  this->cb(HTTP_EV_TYPE_HDR_COMPLETE,this->ud);
  return 0;
}

static int message_complete_cb(http_parser *p)
{
  HttpParserHandle *this = p->data;
  DEBUG_PARSER("%s():%d called\n",__func__,__LINE__);
  this->cb(HTTP_EV_TYPE_MSG_COMPLETE,this->ud);
  return 0;
}

static int chunk_header_cb(http_parser *p)
{
  HttpParserHandle *this = p->data;
  DEBUG_PARSER("%s():%d called\n",__func__,__LINE__);
  this->cb(HTTP_EV_TYPE_CHUNK_HEADER,this->ud);
  return 0;
}

static int chunk_complete_cb(http_parser *p)
{
  HttpParserHandle *this = p->data;
  DEBUG_PARSER("%s():%d called\n",__func__,__LINE__);
  this->cb(HTTP_EV_TYPE_CHUNK_COMPLETE,this->ud);
  return 0;
}

static http_parser_settings settings =
  {.on_message_begin = message_begin_cb
  ,.on_header_field = header_field_cb
  ,.on_header_value = header_value_cb
  ,.on_url = request_url_cb
  ,.on_status = response_status_cb
  ,.on_body = body_cb
  ,.on_headers_complete = headers_complete_cb
  ,.on_message_complete = message_complete_cb
  ,.on_chunk_header = chunk_header_cb
  ,.on_chunk_complete = chunk_complete_cb
  };

void HttpParserInit(HttpParserHandle *h, http_callback cb, void *ud)
{
  if (h->init)
    return;

  http_parser_init(&h->parser, HTTP_BOTH);
  h->ud=ud;
  h->init=1;
  h->cb=cb;
  h->parser.data=h;//this
  return;
}

size_t HttpParse(HttpParserHandle *h, const char *buf, size_t len)
{
  size_t nparsed;
  nparsed = http_parser_execute(&h->parser, &settings, buf, len);
  return nparsed;
}

int HttpStatusCode(HttpParserHandle *h)
{
  return h->parser.status_code;
}

const char *HttpStatusStr(int code)
{
  return http_status_str((enum http_status)code);
}

void HttpPrintStats(HttpStats *stats)
{
  int fmt=20;

#define PRINTF(str,val) \
  printf("%*s:              %"PRId64"\n",-fmt,str,val)

  PRINTF("Http Requests  Sent",stats->reqs);
  PRINTF("Http Responses Rcvd",stats->rsps);

#define xx(c,e,s) \
  if (stats->http_rsp_code_##c)  \
  PRINTF(STRCONCAT(HTTP_RSP_CODE_,c),stats->http_rsp_code_##c);

  HTTP_STATUS_MAP(xx)
#undef xx
}
