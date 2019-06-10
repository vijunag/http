/*Author: Vijay Nag
 * Simple and an easy to use HTTP-client
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#define MAXSRVRENDPOINTS 4096
#define MAXREQSZ (8192*2)
#define MAXIPLEN 128
#define MAXFILELEN 256
#define MAX_CLIENTS 8192

#define SYSCALL_ERR_EXIT(syscall)                                                \
({                                                                               \
  int rval = syscall;                                                            \
    if ( 0 > rval) {                                                             \
       fprintf(stderr, "%s:%d:%s::%s failed with errno = %s(%d)\n",              \
            __FILE__,__LINE__, __func__,#syscall, strerror(errno), errno);       \
    }                                                                            \
    rval;                                                                        \
})

#define MIN(a,b) (a) < (b) ? (a) : (b)

typedef void (*timer_cb)(int,short,void*);

typedef struct EndPoint {
  struct in_addr ip;
  uint16_t port;
} EndPoint;

typedef struct ClientCfg {
  char client_ip[MAXIPLEN];
  EndPoint srvs[MAXSRVRENDPOINTS];
  int srvcount;
  uint16_t tot_srvs; //<=MAXPORT
  char httpfile[MAXFILELEN];
  int reqs; //reqs per client
  int client_count; //client count
  int rps;
} ClientCfg;

ClientCfg gclientcfg;

typedef struct ClientInfo {
  int fd;
  int idx;
  const char *ip;
  struct event *rev;
  struct event *wev;
  uint16_t port;
  uint64_t reqs;
  uint64_t rsps;
} ClientInfo;

ClientInfo clientInfo[MAX_CLIENTS];

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

struct event_base *base;

const char *def_http_get_req = "GET / HTTP/1.1\r\nHost: helloworld-svc\r\nUser-Agent: http-client\r\nAccept:*/*\r\n\r\n";
char http_get_req[MAXREQSZ];

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

static int send_get_request(ClientInfo *cinfo)
{
  int rval;
  static int len = 0;

  if (cinfo->fd == -1)
    return 0;

  if (!len)
    len=strlen(http_get_req);

  rval = send(cinfo->fd, http_get_req, len, 0);
  if (rval) {
   cinfo->reqs++;
   rps_ctxt.tot_req_sent++;
  }

  return rval;
}

static void http_client_deregister(ClientInfo *cinfo)
{
  if (cinfo->fd == -1)
    return

  event_free(cinfo->rev);
  event_free(cinfo->wev);
  close(cinfo->fd);

  cinfo->fd = -1;
  cinfo->wev = NULL;
  cinfo->rev = NULL;
}

static void rx_handler(int fd, short flags, void *udata)
{
  char buff[8192];
  ClientInfo *cinfo = (ClientInfo*)udata;

  cinfo->rsps++;

  int len = recv(fd, buff, sizeof(buff), 0);
  buff[len] = 0;

  if (!len || len < 0) {
    printf("recv() failed with %s\n", strerror(errno));
    goto finish;
  }

  printf("Received resp for client-id %d of len %d\n", cinfo->idx, len);
  printf("%s\n", buff);
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
  if (rps_ctxt.tot_req_to_send ==
      rps_ctxt.tot_req_sent) {
    stop_timer(&g_timer_ev.rps_timer);
    return;
  }

  for(i=0;i<rps_ctxt.rps;++i) {
    cinfo = &clientInfo[rps_ctxt.idx];
    rps_ctxt.idx = (rps_ctxt.idx+1)%gclientcfg.client_count;
    if (cinfo->reqs < gclientcfg.reqs) {
      if (!send_get_request(cinfo)) {
        goto finish;
      }
      reqs_sent++;
    }
  }

  if (reqs_sent) {
    printf("[%s]: sent %d reqs\n",
           http_get_timestamp(),
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
  char buff[1024];
  ClientInfo *cinfo = (ClientInfo*)udata;
  static struct timeval timeout = {1,0};

  /* We have atleast one client to
   * do the RPS timer
   */
  rps_ctxt.pending_clients++;
  if (rps_ctxt.pending_clients == 1) {
    start_timer(&g_timer_ev.rps_timer,http_req_handler);
  }
  cinfo->rev = event_new(base, fd, EV_READ|EV_PERSIST,rx_handler,(void*)cinfo);
  event_add(cinfo->rev, NULL);
}

static void create_new_cnxn(int cnxn_id)
{
  struct sockaddr_in addr;
  ClientInfo *cinfo = &clientInfo[cnxn_id];
  cinfo->idx = cnxn_id;
  int fd = -1;
  EndPoint *ep = NULL;

  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < -1) {
    printf("Error opening socket\n");
    return;
  }
  cinfo->fd = fd;

  /*set the socket to be non-blocking*/
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
  cinfo->wev = event_new(base, fd, EV_WRITE,tx_handler, (void*)cinfo);
  event_add(cinfo->wev, NULL);

  memset((void*)&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = 0; //ntohs(35664);
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
  int burst_count = 100;
  int cnt = 0;

  if (cnxninfo.cnxns < gclientcfg.client_count) {
    printf("Starting cnxns from id : %d\n", cnxninfo.cnxns);
    int cnxns = MIN(burst_count,(gclientcfg.client_count - cnxninfo.cnxns));
    while (cnt < cnxns) {
      create_new_cnxn(cnxninfo.cnxns);
      cnxninfo.cnxns++;
      cnt++;
    }
  } else {
    printf("Finished creating %d cnxns\n", cnxninfo.cnxns);
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
  for (i = 3; i < 8192; ++i)
    close(i);
}

void signal_handler(int signo)
{
  printf("SIGPIPE received\n");
  return;
}

static inline void http_set_server_ip_port(const char *ip, uint16_t port)
{
  unsigned char buf[sizeof(struct in6_addr)];
  char str[INET_ADDRSTRLEN];
  if (inet_pton(AF_INET,ip,(void*)buf) <= 0) {
    struct hostent *h;
    h=gethostbyname(ip);
    if (h == NULL) {
      printf("Invalid host %s:%s\n",ip,strerror(errno));
      exit(-1);
    }
    gclientcfg.srvs[gclientcfg.srvcount].ip=*(struct in_addr*)h->h_addr_list[0];
    inet_ntop(AF_INET,(void*)&gclientcfg.srvs[gclientcfg.srvcount].ip,str,INET_ADDRSTRLEN);
    printf("Server located at address: %s\n",str);
  } else {
    gclientcfg.srvs[gclientcfg.srvcount].ip=*(struct in_addr*)buf;
  }
  gclientcfg.srvs[gclientcfg.srvcount].port = port;
  gclientcfg.srvcount++;
}

static const char *optString ="hc:n:i:r:s:p:l:f:d:";
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
  return;

def:
    printf("Using default GET Template\n");
    strncpy(http_get_req,def_http_get_req,sizeof(http_get_req));
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
}

static void http_parse_args(int argc, char **argv)
{
  int retval = -1, opt = -1, longIndex, i=0;
  char srvIpAddr[MAXIPLEN];
  uint16_t startPort=0;
  char dstFile[MAXFILELEN] = {0};

  opt = getopt_long(argc, argv, optString, longOpts, &longIndex);
  while(opt!=-1) {
    switch(opt) {
     case 'h': print_usage(); break;
     case 'c': strncpy(gclientcfg.client_ip,optarg,MAXIPLEN); break;
     case 'n': gclientcfg.client_count = atoi(optarg); break;
     case 'i': gclientcfg.reqs = atoi(optarg); break;
     case 'r': rps_ctxt.rps = atoi(optarg); break;
     case 's': strncpy(srvIpAddr,optarg,MAXIPLEN); break;
     case 'p': startPort=atoi(optarg); break;
     case 'l': gclientcfg.tot_srvs=atoi(optarg); break;
     case 'f': strncpy(gclientcfg.httpfile,optarg,sizeof(gclientcfg.httpfile)); break;
     case 'd': strncpy(dstFile, optarg, sizeof(dstFile)); break;
     case 0:
       if (!strcmp("client-ip",longOpts[longIndex].name)) {
         strncpy(gclientcfg.client_ip,optarg,MAXIPLEN);
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
       } else if (!strcmp("help", longOpts[longIndex].name)) {
         print_usage();
         exit(0);
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
  VALIDATE_CFG(gclientcfg.client_ip[0]==0,"--client-ip");
  VALIDATE_CFG(!dstFile[0] && srvIpAddr==0,"--server-ip");
  VALIDATE_CFG(!dstFile[0] && startPort==0,"--server-port-start");
#undef VALIDATE_CFG

  /*configure server ip list*/
  if (dstFile[0]) {
    http_set_server_ip_port_from_file(dstFile);
  } else {
    for (i=0;i<gclientcfg.tot_srvs;++i) {
      http_set_server_ip_port(srvIpAddr,startPort++);
    }
  }

  /*Read the request template from the file*/
  http_prepare_req_file();

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
  SET_DFLT(rps_ctxt.tot_req_to_send,
           (gclientcfg.client_count*gclientcfg.reqs));
#undef SET_DFLT
}

int main(int argc, char **argv)
{
  int cnt = 0;
  struct timeval timeout;
  int num;

  atexit(exit_handler);
  signal(SIGPIPE, signal_handler);

  http_parse_args(argc,argv);

  base = event_base_new();

  start_timer(&g_timer_ev.cnxn_timer, timer_handler);

  event_base_dispatch(base);
}
