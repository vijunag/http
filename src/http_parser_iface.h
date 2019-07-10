/* Author: Vijay Nag
 * Simple and an easy to use HTTP-client
 */
#ifndef __HTTP_PARSER_IFACE_H__
#define __HTTP_PARSER_IFACE_H__

#include "http_parser.h"

#define TMPL(str) \
  HTTP_EV_TYPE_##str,

#define TMPL_LIST \
  TMPL(MSG_BEGIN) \
  TMPL(REQ_URL) \
  TMPL(RSP_STATUS) \
  TMPL(BODY) \
  TMPL(HDR_FIELD) \
  TMPL(HDR_COMPLETE) \
  TMPL(HDR_VALUE) \
  TMPL(MSG_COMPLETE) \
  TMPL(CHUNK_HEADER) \
  TMPL(CHUNK_COMPLETE)

typedef enum HttpEventType {
  HTTP_EV_TYPE_INVALID=-1,
  TMPL_LIST
#undef TMPL
  HTTP_EV_TYPE_MAX
} HttpEventType;

#define MAX_LATENCIES 1000000 //1000 buckets, reasonable default
typedef struct HttpLatencyDistArray {
  uint64_t *latency;
  int cur_idx;
  int idx;
} HttpLatencyDistArray;

typedef struct HttpStats {
  HttpLatencyDistArray latency;
  uint64_t reqs; //reqs sent
  uint64_t rsps; //rsps received
#define xx(c,e,s) uint64_t http_rsp_code_##c;
  HTTP_STATUS_MAP(xx)
#undef xx
} HttpStats;

#define xx(c,e,s)                 \
  if (_code == HTTP_STATUS_##e)   \
    val=&stat->http_rsp_code_##c; \

static inline uint64_t* http_stat_cntr(HttpStats *stat, int _code)
{
  uint64_t *val = NULL;

  HTTP_STATUS_MAP(xx);
#undef xx
  return val;
}

#define HTTP_INCR_RSP_CODES(_stat,_code)      \
({                                            \
    uint64_t *val=http_stat_cntr(_stat,_code);\
    (*val)++;                                 \
})                                            \

extern const char *HttpEventStr[HTTP_EV_TYPE_MAX+1];
typedef int (*http_callback)(HttpEventType event, void *userdata);

typedef struct HttpParserHandle {
  char init:1; //is inited already ?
  http_parser parser; //the http parser handle
  void *ud;
  http_callback cb;
} HttpParserHandle;

void HttpParserInit(HttpParserHandle *h, http_callback cb, void *userdata);
size_t HttpParse(HttpParserHandle *h, const char *buf, size_t len);
int HttpStatusCode(HttpParserHandle *h);
const char *HttpStatusStr(int code);
void HttpPrintStats(HttpStats *stats);
void HttpLogEnable(void);

#endif /*__HTTP_PARSER_IFACE_H__*/
