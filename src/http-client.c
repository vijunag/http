/* Author: Vijay Nag
 * Simple and an easy to use HTTP-client
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/event_compat.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>
#include <dirent.h>
#include <netdb.h>
#include <getopt.h>
#include <time.h>
#include <http_parser_iface.h>
#include <http_time.h>
#include <http_ssl.h>

#define MAXSRVRENDPOINTS 4096
#define MAXREQSZ (8192*2)
#define MAXIPLEN 128
#define MAXFILELEN 256

#define SYSCALL_ERR_EXIT(syscall)                                                \
({                                                                               \
  int rval = syscall;                                                            \
    if ( 0 > rval) {                                                             \
       fprintf(stderr, "%s:%d:%s::%s failed with errno = %s(%d)\n",              \
            __FILE__,__LINE__, __func__,#syscall, strerror(errno), errno);       \
    }                                                                            \
    rval;                                                                        \
})

#define DEBUG_LOG(level,fmt,...) \
  if (level<=g_log_enabled) \
    printf("[%s:%s ]- "fmt,#level,http_get_timestamp(),##__VA_ARGS__);

typedef enum HttpLogLevels {
  LOG_LEVEL_INVALID,
  LOG_LEVEL_INFO,
  LOG_LEVEL_TRACE,
  LOG_LEVEL_CRITICAL,
  LOG_LEVEL_ERROR,
  LOG_LEVEL_DEBUG,
  LOG_LEVEL_MAX,
} HttpLogLevels;

typedef void (*timer_cb)(int,short,void*);

typedef struct EndPoint {
  struct in_addr ip;
  uint16_t port;
} EndPoint;

typedef struct ClientCfg {
  int ssl; //is ssl enabled
  EndPoint client_ip;
  EndPoint srvs[MAXSRVRENDPOINTS];
  int srvcount;
  uint16_t tot_srvs; //<=MAXPORT
  char httpfile[MAXFILELEN];
  int reqs; //reqs per client
  int client_count; //client count
  int rps;
  int persist;
  unsigned long cpu_mask;
} ClientCfg;

ClientCfg gclientcfg;

#define INCR_COUNTER(ctr) (ctr++)

#define START_LATENCY_TICKS(cinfo) \
({ \
   HttpLatencyDistArray *latency = &cinfo->stats.latency;  \
   START_TICK(latency->latency[latency->idx]);             \
   latency->idx++;                                         \
})

#define STOP_LATENCY_TICKS(cinfo) \
({ \
   HttpLatencyDistArray *latency = &cinfo->stats.latency;                               \
   latency->latency[latency->cur_idx]=STOP_TICK(latency->latency[latency->cur_idx]) ;   \
   latency->cur_idx++;                                                                  \
})

typedef enum ClientState {
  CLIENT_STATE_INVALID,
  CLIENT_STATE_CONNECTED,
  CLIENT_STATE_RBLOCK,
  CLIENT_STATE_WBLOCK,
  CLIENT_STATE_DISCONNECTED,
  CLIENT_STATE_MAX
} ClientState;

typedef struct ClientInfo {
  int fd;
  int idx;
  int bufidx; //incomplete bufidx
  ClientState state;
  const char *ip;
  uint16_t port;
  struct event rev;
  struct event wev;
  int rev_assigned;
  int wev_assigned;
  HttpParserHandle h;
  HttpStats stats;
  u64bits tick;
  http_sslclient_ctxt ssl;
} ClientInfo;

ClientInfo *clientInfo;

typedef struct RpsCtxt {
  int idx; //client idx
  int rps; //request per second
  int pending_clients;
  int tot_req_to_send;
  int tot_req_sent;
} RpsCtxt;
RpsCtxt rps_ctxt;

struct timer_ev_info {
  struct event *cnxn_timer;
  struct event *rps_timer;
  struct timeval timeout;
} g_timer_ev;

struct ConnectionInfo {
  int cnxns;
} cnxninfo;

extern void start_timer(struct event **ev, timer_cb cb);
extern void stop_timer(struct event **ev);
static void tx_handler(int fd, short flags, void *udata);
static void create_new_cnxn(int cnxn_id);

struct event_base *base;

const char *def_http_get_req = "GET / HTTP/1.1\r\nHost: http-client\r\nUser-Agent: http-client\r\nAccept:*/*\r\n\r\n";
int reqlen;
char http_get_req[MAXREQSZ];
int g_log_enabled;

static inline EndPoint *get_nxt_server_endpt(void)
{
  static int idx=0;
  int cur_idx = idx;
  idx = (idx+1)%(gclientcfg.tot_srvs);
  return &gclientcfg.srvs[cur_idx];
}

static inline const char *http_get_timestamp(void)
{
  struct timeval tv;
  time_t nowtime;
  struct tm *nowtm;
  static char tmbuf[64];

  gettimeofday(&tv, NULL);
  nowtime = tv.tv_sec;
  nowtm = (struct tm*)localtime(&nowtime);
  strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", nowtm);
  return tmbuf;
}

static int send_get_request(ClientInfo *cinfo,int start,int len)
{
  int rval;

  if (cinfo->fd == -1)
    return 0;

#define EVENT_FREE_WRITE(cinfo) \
  if (cinfo->wev_assigned) {    \
    event_del(&cinfo->wev);     \
    cinfo->wev_assigned = 0;    \
  }

  if (gclientcfg.ssl) {
    rval=http_ssl_write(&cinfo->ssl,http_get_req+start,len);
  } else {
    rval=send(cinfo->fd,http_get_req+start,len,0);
  }
  if (rval == len) {
   START_LATENCY_TICKS(cinfo); //time to last byte
   INCR_COUNTER(cinfo->stats.reqs);
   INCR_COUNTER(rps_ctxt.tot_req_sent);
   EVENT_FREE_WRITE(cinfo);
   cinfo->state = CLIENT_STATE_CONNECTED;
  } else if (rval > 0) {
   cinfo->bufidx = start+rval;
   cinfo->state = CLIENT_STATE_WBLOCK;
   event_assign(&cinfo->wev, base, cinfo->fd, EV_WRITE | EV_PERSIST, tx_handler, (void*)cinfo);
   event_add(&cinfo->wev, NULL);
   cinfo->wev_assigned = 1;
  } else if (rval == 0) {
   cinfo->bufidx = 0;
   cinfo->state = CLIENT_STATE_CONNECTED;
   EVENT_FREE_WRITE(cinfo);
  }
  return rval;
}

static void http_client_deregister(ClientInfo *cinfo)
{
  if (cinfo->fd == -1)
    return;

  if (cinfo->rev_assigned) {
    event_del(&cinfo->rev);
    cinfo->rev_assigned = 0;
  }

  if (cinfo->wev_assigned) {
    event_del(&cinfo->wev);
    cinfo->wev_assigned = 0;
  }

  close(cinfo->fd);
  cinfo->fd = -1;
  cinfo->state = CLIENT_STATE_DISCONNECTED;

  if (gclientcfg.persist) {
      create_new_cnxn(cinfo->idx);
  }
}

static int http_parse_cb(HttpEventType event, void *ud)
{
  ClientInfo *cinfo = (ClientInfo*)ud;
  int status;

  switch (event) {
    case HTTP_EV_TYPE_MSG_BEGIN:
      DEBUG_LOG(LOG_LEVEL_TRACE,"Begin of Http msg\n");
      break;
    case HTTP_EV_TYPE_RSP_STATUS:
      status=HttpStatusCode(&cinfo->h);
      DEBUG_LOG(LOG_LEVEL_TRACE,"Received HTTP-Status code=%d\n", status);
      break;
    case HTTP_EV_TYPE_MSG_COMPLETE:
      status=HttpStatusCode(&cinfo->h);
      STOP_LATENCY_TICKS(cinfo);
      INCR_COUNTER(cinfo->stats.rsps);
      HTTP_INCR_RSP_CODES(&cinfo->stats,status);
      DEBUG_LOG(LOG_LEVEL_TRACE,"End of msg\n");
      break;
    default:
      break;
  }
  return 0;
}

static int uint64_comparer(const void *l, const void *r)
{
  uint64_t lhs = *(uint64_t*)l;
  uint64_t rhs = *(uint64_t*)r;

  if (lhs == rhs) return 0;
  return lhs > rhs;
}

static void http_print_stats(ClientInfo *cinfo)
{
  int fmt=10;

#define PERCENTILE(x)                                     \
({                                                        \
 int idx = (x*cinfo->stats.latency.idx)/100;              \
 (cinfo->stats.latency.latency[idx]/1000000000.0);        \
})

  printf("ClientInfo stats for client with id=%d\n", cinfo->idx);
  HttpPrintStats(&cinfo->stats);

  qsort(cinfo->stats.latency.latency,
        cinfo->stats.latency.idx,sizeof(uint64_t),
        uint64_comparer);

  printf("Latency Distribution in seconds\n");
#define PRINT_PERCENTILE(x) \
  printf("P%d                   :%*.6f\n",x,fmt,PERCENTILE(x));

  PRINT_PERCENTILE(10);
  PRINT_PERCENTILE(20);
  PRINT_PERCENTILE(30);
  PRINT_PERCENTILE(40);
  PRINT_PERCENTILE(50);
  PRINT_PERCENTILE(60);
  PRINT_PERCENTILE(90);
  PRINT_PERCENTILE(95);
  PRINT_PERCENTILE(99);
}

static void http_stat_summary(void)
{
  int i=0;

  for(i=0;i<gclientcfg.client_count;++i) {
    http_print_stats(&clientInfo[i]);
  }
}

static void rx_handler(int fd, short flags, void *udata)
{
  int len=0;
  char buff[8192];
  ClientInfo *cinfo = (ClientInfo*)udata;

  len=recv(fd, buff, sizeof(buff), 0);
  buff[len] = 0;

  if (!len || len < 0) {
    DEBUG_LOG(LOG_LEVEL_CRITICAL,"recv() failed with %s\n", strerror(errno));
    goto finish;
  }

  HttpParse(&cinfo->h,buff,len);
  DEBUG_LOG(LOG_LEVEL_DEBUG,"Received resp for client-id %d of len %d\n", cinfo->idx, len);
  DEBUG_LOG(LOG_LEVEL_DEBUG,"\n%s\n", buff);
  if (cinfo->stats.rsps == gclientcfg.reqs)
    goto finish;
  return;

finish:
  http_client_deregister(cinfo);
  rps_ctxt.pending_clients--;
}

static void http_req_handler(int fd, short event, void *ud)
{
  int i=0;
  ClientInfo *cinfo=NULL;
  int reqs_sent=0;

  /*No clients to send the data on*/
  if (!rps_ctxt.pending_clients) {
    stop_timer(&g_timer_ev.rps_timer);
    return;
  }

  /*Check if we've sent the reqd reqs/client*/
  if (!gclientcfg.persist && rps_ctxt.tot_req_to_send ==
      rps_ctxt.tot_req_sent) {
    stop_timer(&g_timer_ev.rps_timer);
    return;
  }

  for(i=0;i<rps_ctxt.rps;++i) {
    cinfo = &clientInfo[rps_ctxt.idx];
    rps_ctxt.idx = (rps_ctxt.idx+1)%gclientcfg.client_count;
    if (cinfo->state == CLIENT_STATE_INVALID ||
        cinfo->state == CLIENT_STATE_WBLOCK ||
        cinfo->state == CLIENT_STATE_DISCONNECTED) //no writes until further rsp
       continue;
    if (cinfo->stats.reqs < gclientcfg.reqs) {
      DEBUG_LOG(LOG_LEVEL_TRACE, "\n%s\n",http_get_req);
      if (!send_get_request(cinfo,0,reqlen)) {
        goto finish;
      }
      reqs_sent++;
    }
  }

  if (reqs_sent) {
    DEBUG_LOG(LOG_LEVEL_INFO,"sent %d reqs\n",
           reqs_sent);
  }
  return;

finish:
  if (cinfo) {
    http_client_deregister(cinfo);
    rps_ctxt.pending_clients--;
  }
  return;
}

static void tx_handler(int fd, short flags, void *udata)
{
  int rval;
  ClientInfo *cinfo = (ClientInfo*)udata;

  send_get_request(cinfo,cinfo->bufidx,(reqlen-cinfo->bufidx));
}

static void cnxn_handler(int fd, short flags, void *udata)
{
  ClientInfo *cinfo = (ClientInfo*)udata;
  static struct timeval timeout = {1,0};

  /* We have atleast one client to
   * do the RPS timer
   */
  rps_ctxt.pending_clients++;
  if (rps_ctxt.pending_clients == 1) {
    start_timer(&g_timer_ev.rps_timer,http_req_handler);
  }

  event_del(&cinfo->wev);
  cinfo->wev_assigned = 0;
  event_assign(&cinfo->rev, base, fd, EV_READ|EV_PERSIST,rx_handler,(void*)cinfo);
  cinfo->rev_assigned = 1;
  cinfo->state = CLIENT_STATE_CONNECTED;
  event_add(&cinfo->rev, NULL);
}

static void ssl_rx_handler(int fd, short flags, void *udata)
{
  int len;
  char buff[8192];
  ClientInfo *cinfo = (ClientInfo*)udata;

  len=http_ssl_read(&cinfo->ssl, buff, sizeof(buff));
  buff[len]=0;

  HttpParse(&cinfo->h,buff,len);
  DEBUG_LOG(LOG_LEVEL_DEBUG,"Received resp for client-id %d of len %d\n", cinfo->idx, len);
  DEBUG_LOG(LOG_LEVEL_DEBUG,"\n%s\n", buff);
  if (cinfo->stats.rsps == gclientcfg.reqs)
    goto finish;
  return;

finish:
  http_client_deregister(cinfo);
  rps_ctxt.pending_clients--;
}

static void ssl_tx_handler(int fd, short flags, void *udata)
{
  ClientInfo *cinfo = (ClientInfo*)udata;
}

static void ssl_cnxn_handler(int fd, short flags, void *udata)
{
  ClientInfo *cinfo = (ClientInfo*)udata;
  int rval;

  if ((rval = http_init_ctx(&cinfo->ssl, fd))<0) {
    /*SSL layer not up yet*/
    return;
  }

  rps_ctxt.pending_clients++;
  if (rps_ctxt.pending_clients == 1) {
    start_timer(&g_timer_ev.rps_timer,http_req_handler);
  }
  event_del(&cinfo->wev);
  cinfo->wev_assigned = 0;
  event_assign(&cinfo->rev, base, fd, EV_READ|EV_PERSIST,ssl_rx_handler,(void*)cinfo);
  cinfo->rev_assigned = 1;
  cinfo->state = CLIENT_STATE_CONNECTED;
  event_add(&cinfo->rev, NULL);
}

static void create_new_cnxn(int cnxn_id)
{
  struct sockaddr_in addr;
  ClientInfo *cinfo = &clientInfo[cnxn_id];
  cinfo->idx = cnxn_id;
  int fd = -1;
  EndPoint *ep = NULL;
  short flags;

  cinfo->stats.latency.latency = calloc(sizeof(uint64_t)*MAX_LATENCIES,1);
  if (!cinfo->stats.latency.latency) {
    DEBUG_LOG(LOG_LEVEL_INFO,"create_new_cnxn():malloc failed\n");
    exit(-1);
  }

  /*Init the HTTP Parser module*/
  HttpParserInit(&cinfo->h,http_parse_cb,cinfo);

  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < -1) {
    DEBUG_LOG(LOG_LEVEL_ERROR,"Error opening socket\n");
    return;
  }
  cinfo->fd = fd;

  /*set the socket to be non-blocking*/
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

  flags = EV_WRITE | (gclientcfg.ssl ? EV_PERSIST : EV_WRITE);
  event_assign(&cinfo->wev, base,fd,flags,
               gclientcfg.ssl ? ssl_cnxn_handler : cnxn_handler,
               (void*)cinfo);
  cinfo->wev_assigned = 1;
  event_add(&cinfo->wev, NULL);

  memset((void*)&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = 0; //ntohs(35664);
  if (gclientcfg.client_ip.ip.s_addr) {
    addr.sin_addr.s_addr = gclientcfg.client_ip.ip.s_addr;
  }
  SYSCALL_ERR_EXIT(bind(fd, (struct sockaddr*)&addr, sizeof(addr)));

  ep = get_nxt_server_endpt();
  memset((void*)&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr = ep->ip;
  addr.sin_port = htons(ep->port);
  connect(fd, (struct sockaddr*)&addr, sizeof(addr));
}

static void timer_handler(int fd, short event, void *arg)
{
  int burst_count = 200;
  int cnt = 0;

  if (cnxninfo.cnxns < gclientcfg.client_count) {
    DEBUG_LOG(LOG_LEVEL_INFO,"Starting cnxns from id : %d\n", cnxninfo.cnxns);
    int cnxns = MIN(burst_count,(gclientcfg.client_count - cnxninfo.cnxns));
    while (cnt < cnxns) {
      create_new_cnxn(cnxninfo.cnxns);
      cnxninfo.cnxns++;
      cnt++;
    }
  } else {
    DEBUG_LOG(LOG_LEVEL_INFO,"Finished creating %d cnxns\n", cnxninfo.cnxns);
    stop_timer(&g_timer_ev.cnxn_timer);
  }
}

void start_timer(struct event **ev, timer_cb cb)
{
  struct timeval timeout;
  timeout.tv_sec = 1;
  timeout.tv_usec = 0;

  if (*ev == NULL) {
    *ev = event_new(base,0,EV_PERSIST,cb,NULL);
     event_add(*ev, &timeout);
  }
}

void stop_timer(struct event **ev)
{
  event_free(*ev);
  *ev=NULL;
}

void exit_handler(void)
{
  int i = 3;
  for (i = 3; i < 65535; ++i)
    close(i);
}

static inline int http_parse_client_ip_addr(const char *ip)
{
    unsigned char buf[sizeof(struct in6_addr)];
    char str[INET_ADDRSTRLEN];

    if (inet_pton(AF_INET, ip, (void*)buf) <= 0) {
        //lets try ipv6 once
        if (inet_pton(AF_INET6, ip, (void*)buf) <=0) {
            return -1;
        }
    }
    gclientcfg.client_ip.ip = *(struct in_addr*)buf;
    return 0;
}

static inline void http_set_server_ip_port(const char *ip, uint16_t port)
{
  unsigned char buf[sizeof(struct in6_addr)];
  char str[INET_ADDRSTRLEN];
  if (inet_pton(AF_INET,ip,(void*)buf) <= 0) {
    struct hostent *h;
    h=gethostbyname(ip);
    if (h == NULL) {
      DEBUG_LOG(LOG_LEVEL_ERROR,"Invalid host %s:%s\n",ip,strerror(errno));
      exit(-1);
    }
    gclientcfg.srvs[gclientcfg.srvcount].ip=*(struct in_addr*)h->h_addr_list[0];
    inet_ntop(AF_INET,(void*)&gclientcfg.srvs[gclientcfg.srvcount].ip,str,INET_ADDRSTRLEN);
    DEBUG_LOG(LOG_LEVEL_INFO,"Server located at address: %s\n",str);
  } else {
    gclientcfg.srvs[gclientcfg.srvcount].ip=*(struct in_addr*)buf;
  }
  gclientcfg.srvs[gclientcfg.srvcount].port = port;
  gclientcfg.srvcount++;
}

static const char *optString ="hc:n:i:r:s:p:l:f:d:k:ogm:";
static const struct option longOpts[] = {
  {"help", no_argument, NULL, 0 },
  {"client-ip", required_argument, NULL, 0 },
  {"num-client", required_argument, NULL, 0 },
  {"req-client", required_argument, NULL, 0 },
  {"rps", required_argument, NULL, 0 },
  {"server-ip", required_argument, NULL, 0 },
  {"server-port-start", required_argument, NULL, 0 },
  {"num-srvs", required_argument, NULL, 0 },
  {"file", required_argument, NULL,0},
  {"dest-file", required_argument, NULL, 0},
  {"debug-log", required_argument, NULL,0},
  {"https-clients", no_argument, NULL,0},
  {"keep-going", no_argument, NULL, 0},
  {"cpu-mask", required_argument, NULL, 0},
  { NULL, no_argument, NULL, 0}
};

static void print_usage(void)
{
  printf("http-client - Easy to use HTTP Client\n");
  printf("Allowed options: \n");
  printf("-h [ --help ]                         Display this message\n");
  printf("-c [ --client-ip ]                    Http Client ip\n");
  printf("-n [ --num-client ]                   No. of Clients\n");
  printf("-i [ --req-client ]                   Requests per client\n");
  printf("-r [ --rps ]                          Requests per second\n");
  printf("-s [ --server-ip ]                    Http Server Ip\n");
  printf("-p [ --server-port-start ]            Http Server port start\n");
  printf("-l [ --num-srvs ]                     Http Server port range\n");
  printf("-d [ --dest-file ]                    Read Http Dest Endpoint from file\n");
  printf("-f [ --file ]                         Http Request template\n");
  printf("-k [--debug-log ]                     Print Debug logs\n");
  printf("-o [--https-clients]                  Use Https Client\n");
}

static void http_prepare_req_file(void)
{
  int c;
  int i=0;

  /*No filename specified, use the default*/
  if (!gclientcfg.httpfile[0])
    goto def;

  FILE *fp = fopen(gclientcfg.httpfile, "rb");
  if (!fp) {
    printf("Cannot open file %s:%s\n",
            gclientcfg.httpfile,strerror(errno));
    goto def;
  }

  while ((c = fgetc(fp)) != EOF) {
    http_get_req[i++]=c;
    if (i>MAXREQSZ) {
      printf("Request template greater than 16048 bytes\n");
      fclose(fp);
      goto def;
    }
  }
  reqlen=i;
  return;

def:
    printf("Using default GET Template\n");
    strncpy(http_get_req,def_http_get_req,sizeof(http_get_req));
    reqlen=strlen(http_get_req);
    return;
}

static int http_set_server_ip_port_from_file(const char *file)
{
  char line[200];
  char ipAddr[MAXIPLEN];
  char port[6];
  FILE *fp = fopen(file, "rb");

  while(fgets(line,sizeof(line),fp)!=NULL) {
    char *next;
    int s;
    int l=strchr(line,' ')-line;
    strncpy(ipAddr,line,l);
    ipAddr[l]=0;
    next=line+l+1;
    l=strrchr(line,'\n')-next;
    strncpy(port,next,l);
    port[l]=0;
    http_set_server_ip_port(ipAddr,atoi(port));
    gclientcfg.tot_srvs++; //adjust total servers depending on number of lines in the client spec file
  }
  return 0;
}

static void http_parse_args(int argc, char **argv)
{
  int retval = -1, opt = -1, longIndex, i=0;
  char srvIpAddr[MAXIPLEN], clientIpAddr[MAXIPLEN] = {0};
  uint16_t startPort=80;
  char dstFile[MAXFILELEN] = {0};

  opt = getopt_long(argc, argv, optString, longOpts, &longIndex);
  while(opt!=-1) {
    switch(opt) {
     case 'h': print_usage(); break;
     case 'c': strncpy(clientIpAddr,optarg,MAXIPLEN); break;
     case 'n': gclientcfg.client_count = atoi(optarg); break;
     case 'i': gclientcfg.reqs = atoi(optarg); break;
     case 'r': rps_ctxt.rps = atoi(optarg); break;
     case 's': strncpy(srvIpAddr,optarg,MAXIPLEN); break;
     case 'p': startPort=atoi(optarg); break;
     case 'l': gclientcfg.tot_srvs=atoi(optarg); break;
     case 'f': strncpy(gclientcfg.httpfile,optarg,sizeof(gclientcfg.httpfile)); break;
     case 'd': strncpy(dstFile, optarg, sizeof(dstFile)); break;
     case 'k': g_log_enabled=atoi(optarg); break;
     case 'o': gclientcfg.ssl = 1; break;
     case 'g': gclientcfg.persist = 1; break;
     case 'm': gclientcfg.cpu_mask = atol(optarg); break;
     case 0:
       if (!strcmp("client-ip",longOpts[longIndex].name)) {
         strncpy(clientIpAddr,optarg,MAXIPLEN);
       } else if (!strcmp("num-client",longOpts[longIndex].name)) {
         gclientcfg.client_count = atoi(optarg);
       } else if (!strcmp("req-client",longOpts[longIndex].name)) {
         gclientcfg.reqs = atoi(optarg);
       } else if (!strcmp("rps",longOpts[longIndex].name)) {
         rps_ctxt.rps = atoi(optarg);
       } else if (!strcmp("server-ip",longOpts[longIndex].name)) {
         strncpy(srvIpAddr,optarg,MAXIPLEN);
       } else if (!strcmp("server-port-start",longOpts[longIndex].name)) {
         startPort=atoi(optarg);
       } else if (!strcmp("num-srvs",longOpts[longIndex].name)) {
         gclientcfg.tot_srvs = atoi(optarg);
       } else if (!strcmp("file",longOpts[longIndex].name)) {
         strncpy(gclientcfg.httpfile,optarg,sizeof(gclientcfg.httpfile));
       } else if (!strcmp("dest-file",longOpts[longIndex].name)) {
         strncpy(dstFile,optarg,sizeof(dstFile));
       } else if (!strcmp("debug-log",longOpts[longIndex].name)) {
         g_log_enabled=atoi(optarg);
       } else if (!strcmp("help", longOpts[longIndex].name)) {
         print_usage();
         exit(0);
       } else if (!strcmp("https-clients", longOpts[longIndex].name)) {
         gclientcfg.ssl = 1;
       } else if (!strcmp("keep-going", longOpts[longIndex].name)) {
         gclientcfg.persist = 1;
       } else if (!strcmp("cpu-mask", longOpts[longIndex].name)) {
         gclientcfg.cpu_mask = atol(optarg); 
       }
    default:
       print_usage();
       exit(0);
       break;
   }
   opt = getopt_long(argc, argv, optString, longOpts, &longIndex);
  }

#define VALIDATE_CFG(cond,str) \
  if ((cond)) { \
    printf("%s is mandatory parameter\n",str); \
    print_usage(); \
    exit(-1); \
  }

  /*Thorough validation*/
//  VALIDATE_CFG(gclientcfg.client_ip[0]==0,"--client-ip");
  VALIDATE_CFG(!dstFile[0] && srvIpAddr[0]==0,"--server-ip");
  VALIDATE_CFG(!dstFile[0] && startPort==0,"--server-port-start");
#undef VALIDATE_CFG

#define SET_DFLT(var, val) \
  if (!var) {   \
    (var) = (val); \
    printf("Setting default value %s:%d\n",#var,val); \
  }
  /*Configure defaults*/
  SET_DFLT(gclientcfg.client_count,1);
  SET_DFLT(gclientcfg.reqs,1);
  SET_DFLT(rps_ctxt.rps,1);
  SET_DFLT(gclientcfg.tot_srvs,1);
  SET_DFLT(gclientcfg.persist, 0);
#undef SET_DFLT

  if (clientIpAddr[0]) {
      int rval = http_parse_client_ip_addr(clientIpAddr);
      if (rval < 0) {
          printf("Invalid IP address: %s\n", clientIpAddr);
          print_usage();
          exit(-1);
      }
  }

  if (g_log_enabled > LOG_LEVEL_MAX)
    g_log_enabled = LOG_LEVEL_DEBUG;
  printf("Setting LOG level to %d\n",g_log_enabled);

  /*configure server ip list*/
  if (dstFile[0]) {
    http_set_server_ip_port_from_file(dstFile);
  } else {
    for (i=0;i<gclientcfg.tot_srvs;++i) {
      http_set_server_ip_port(srvIpAddr,startPort++);
    }
  }

  clientInfo = calloc(1,gclientcfg.client_count*sizeof(*clientInfo));
  if (!clientInfo) {
    printf("Cannot allocate memory for clientInfo\n");
    exit(-1);
  }

  if (gclientcfg.ssl) {
    http_init_openssl();
  }
  /*Read the request template from the file*/
  http_prepare_req_file();
}

int main(int argc, char **argv)
{
  int cnt = 0;
  struct timeval timeout;
  int num;

  atexit(exit_handler); //close all fds

  signal(SIGPIPE, SIG_IGN); //spurious SIG_IGN

  InitRdtsc(gclientcfg.cpu_mask); //Initialize timer library

  http_parse_args(argc,argv); //Parse args

  base = event_base_new(); //Initialize libevent

  start_timer(&g_timer_ev.cnxn_timer, timer_handler); //start timer

  event_base_dispatch(base); //release control to never return

  http_stat_summary(); //Print stats while exiting
}
