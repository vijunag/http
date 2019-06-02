/*Author: Vijay Nag
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>
#include <dirent.h>

#define SYSCALL_ERR_EXIT(syscall)                                                \
({                                                                               \
  int rval = syscall;                                                            \
    if ( 0 > rval) {                                                             \
       fprintf(stderr, "%s:%d:%s::%s failed with errno = %s(%d)\n",              \
            __FILE__,__LINE__, __func__,#syscall, strerror(errno), errno);       \
     exit(-1);                                                                   \
    }                                                                            \
    rval;                                                                        \
})

char uri_root[512];

static const struct table_entry {
	const char *extension;
	const char *content_type;
} content_type_table[] = {
	{ "txt", "text/plain" },
	{ "c", "text/plain" },
	{ "h", "text/plain" },
	{ "html", "text/html" },
	{ "htm", "text/htm" },
	{ "css", "text/css" },
	{ "gif", "image/gif" },
	{ "jpg", "image/jpeg" },
	{ "jpeg", "image/jpeg" },
	{ "png", "image/png" },
	{ "pdf", "application/pdf" },
	{ "ps", "application/postscript" },
	{ NULL, NULL },
};

struct HttpCfg {
    int numsrvs;
    uint16_t startport;
#define MAXIPLEN 128
    char httpserverip[MAXIPLEN];
#define MAXPATHLEN 256
    char rootdoc[MAXPATHLEN];
} ghttpcfg;

struct Server {
    const char *ip;
    uint16_t port;
    int srvid;
    int reqs;
    int rsps;
    struct evhttp_bound_socket *handle;
    struct evhttp *http;
};

/* Try to guess a good content-type for 'path' */
static const char *guess_content_type(const char *path)
{
	const char *last_period, *extension;
	const struct table_entry *ent;
	last_period = strrchr(path, '.');
	if (!last_period || strchr(last_period, '/'))
		goto not_found; /* no exension */
	extension = last_period + 1;
	for (ent = &content_type_table[0]; ent->extension; ++ent) {
		if (!evutil_ascii_strcasecmp(ent->extension, extension))
			return ent->content_type;
	}

not_found:
	return "application/misc";
}

/* Callback used for the /dump URI, and for every non-GET request:
 * dumps all information to stdout and gives back a trivial 200 ok */
static void dump_request_cb(struct evhttp_request *req, void *arg)
{
	const char *cmdtype;
	struct evkeyvalq *headers;
	struct evkeyval *header;
	struct evbuffer *buf;

	switch (evhttp_request_get_command(req)) {
	case EVHTTP_REQ_GET: cmdtype = "GET"; break;
	case EVHTTP_REQ_POST: cmdtype = "POST"; break;
	case EVHTTP_REQ_HEAD: cmdtype = "HEAD"; break;
	case EVHTTP_REQ_PUT: cmdtype = "PUT"; break;
	case EVHTTP_REQ_DELETE: cmdtype = "DELETE"; break;
	case EVHTTP_REQ_OPTIONS: cmdtype = "OPTIONS"; break;
	case EVHTTP_REQ_TRACE: cmdtype = "TRACE"; break;
	case EVHTTP_REQ_CONNECT: cmdtype = "CONNECT"; break;
	case EVHTTP_REQ_PATCH: cmdtype = "PATCH"; break;
	default: cmdtype = "unknown"; break;
	}

	printf("Received a %s request for %s\nHeaders:\n",
	    cmdtype, evhttp_request_get_uri(req));

	headers = evhttp_request_get_input_headers(req);
	for (header = headers->tqh_first; header;
	    header = header->next.tqe_next) {
		printf("  %s: %s\n", header->key, header->value);
	}

	buf = evhttp_request_get_input_buffer(req);
	puts("Input data: <<<");
	while (evbuffer_get_length(buf)) {
		int n;
		char cbuf[128];
		n = evbuffer_remove(buf, cbuf, sizeof(cbuf));
		if (n > 0)
			(void) fwrite(cbuf, 1, n, stdout);
	}
	puts(">>>");

	evhttp_send_reply(req, 200, "OK", NULL);
}

/* This callback gets invoked when we get any http request that doesn't match
 * any other callback.  Like any evhttp server callback, it has a simple job:
 * it must eventually call evhttp_send_error() or evhttp_send_reply().
 */
static void send_document_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *evb = NULL;
	const char *docroot = ghttpcfg.rootdoc;
	const char *uri = evhttp_request_get_uri(req);
	struct evhttp_uri *decoded = NULL;
	const char *path;
	char *decoded_path;
	char *whole_path = NULL;
	size_t len;
	int fd = -1;
	struct stat st;
    struct Server *srv= (struct Server*)arg;

	if (evhttp_request_get_command(req) != EVHTTP_REQ_GET) {
		dump_request_cb(req, arg);
		return;
	}

	printf("Server-%d got GET request for <%s>\n",  srv->srvid,uri);

	/* Decode the URI */
	decoded = evhttp_uri_parse(uri);
	if (!decoded) {
		printf("It's not a good URI. Sending BADREQUEST\n");
		evhttp_send_error(req, HTTP_BADREQUEST, 0);
		return;
	}

	/* Let's see what path the user asked for. */
	path = evhttp_uri_get_path(decoded);
	if (!path) path = "/";

	/* We need to decode it, to see what path the user really wanted. */
	decoded_path = evhttp_uridecode(path, 0, NULL);
	if (decoded_path == NULL)
		goto err;
	/* Don't allow any ".."s in the path, to avoid exposing stuff outside
	 * of the docroot.  This test is both overzealous and underzealous:
	 * it forbids aceptable paths like "/this/one..here", but it doesn't
	 * do anything to prevent symlink following." */
	if (strstr(decoded_path, ".."))
		goto err;

	len = strlen(decoded_path)+strlen(docroot)+2;
	if (!(whole_path = malloc(len))) {
		perror("malloc");
		goto err;
	}
	evutil_snprintf(whole_path, len, "%s/%s", docroot, decoded_path);

	if (stat(whole_path, &st)<0) {
		goto err;
	}

	/* This holds the content we're sending. */
	evb = evbuffer_new();

	if (S_ISDIR(st.st_mode)) {
		DIR *d;
		struct dirent *ent;
		const char *trailing_slash = "";

		if (!strlen(path) || path[strlen(path)-1] != '/')
			trailing_slash = "/";

		if (!(d = opendir(whole_path)))
			goto err;

		evbuffer_add_printf(evb,
                    "<!DOCTYPE html>\n"
                    "<html>\n <head>\n"
                    "  <meta charset='utf-8'>\n"
		    "  <title>%s</title>\n"
		    "  <base href='%s%s'>\n"
		    " </head>\n"
		    " <body>\n"
		    "  <h1>%s</h1>\n"
		    "  <ul>\n",
		    decoded_path, /* XXX html-escape this. */
		    path, /* XXX html-escape this? */
		    trailing_slash,
		    decoded_path /* XXX html-escape this */);
		while ((ent = readdir(d))) {
			const char *name = ent->d_name;

			evbuffer_add_printf(evb,
			    "    <li><a href=\"%s\">%s</a>\n",
			    name, name);/* XXX escape this */
		}
		evbuffer_add_printf(evb, "</ul></body></html>\n");
		closedir(d);
		evhttp_add_header(evhttp_request_get_output_headers(req),
		    "Content-Type", "text/html");
	} else {
		/* Otherwise it's a file; add it to the buffer to get
		 * sent via sendfile */
		const char *type = guess_content_type(decoded_path);
		if ((fd = open(whole_path, O_RDONLY)) < 0) {
			perror("open");
			goto err;
		}

		if (fstat(fd, &st)<0) {
			/* Make sure the length still matches, now that we
			 * opened the file :/ */
			perror("fstat");
			goto err;
		}
		evhttp_add_header(evhttp_request_get_output_headers(req),
		    "Content-Type", type);
		evbuffer_add_file(evb, fd, 0, st.st_size);
	}

	evhttp_send_reply(req, 200, "OK", evb);
	goto done;
err:
	evhttp_send_error(req, 404, "Document was not found");
	if (fd>=0)
		close(fd);
done:
	if (decoded)
		evhttp_uri_free(decoded);
	if (decoded_path)
		free(decoded_path);
	if (whole_path)
		free(whole_path);
	if (evb)
		evbuffer_free(evb);
}

static void syntax(void)
{
	fprintf(stdout, "Syntax: http-server <docroot>\n");
}

#define LOG_MSG(msg, ...) \
    fprintf(stderr, msg, ##__VA_ARGS__);

void exit_handler(void)
{
  int i = 3;
    for (i = 3; i < 8192; ++i) {
        close(i);
    }
}

static int emit_http_srv_cfg(struct Server *srv)
{
    struct sockaddr_storage ss;
    evutil_socket_t fd;
    static int ffd = -1;
    ev_socklen_t socklen = sizeof(ss);
    char addrbuf[128];
    void *inaddr;
    const char *addr;
    int got_port = -1;

    if (-1==ffd) {
        ffd=open("ns.cfg", O_CREAT|O_RDWR, 777);
        if (-1==ffd) {
            printf("cannot create ns.cfg file\n");
            exit(-1);
        }
    }

    fd = evhttp_bound_socket_get_fd(srv->handle);
    memset(&ss, 0, sizeof(ss));
    if (getsockname(fd, (struct sockaddr *)&ss, &socklen)) {
        perror("getsockname() failed");
        return 1;
    }
    if (ss.ss_family == AF_INET) {
        got_port = ntohs(((struct sockaddr_in*)&ss)->sin_port);
        inaddr = &((struct sockaddr_in*)&ss)->sin_addr;
    } else if (ss.ss_family == AF_INET6) {
        got_port = ntohs(((struct sockaddr_in6*)&ss)->sin6_port);
        inaddr = &((struct sockaddr_in6*)&ss)->sin6_addr;
    } else {
        fprintf(stderr, "Weird address family %d\n",
            ss.ss_family);
        return 1;
    }
    addr = evutil_inet_ntop(ss.ss_family, inaddr, addrbuf,
        sizeof(addrbuf));
    if (addr) {
        if (getenv("CPX")) {
          int len=0;
          printf("add service s%d %s HTTP %d\n",srv->srvid,srv->ip,srv->port);
          evutil_snprintf(uri_root, sizeof(uri_root),
              "http://%s:%d",addr,got_port);
          printf("Url: %s\n", uri_root);
          len=evutil_snprintf(uri_root,sizeof(uri_root),
                  "add service s%d %s HTTP %d\n", srv->srvid, srv->ip, srv->port);
          uri_root[len]=0;
          write(ffd, uri_root, len);
          len=evutil_snprintf(uri_root,sizeof(uri_root),
                  "bind lb vserver v1 s%d\n", srv->srvid);
          uri_root[len]=0;
          write(ffd, uri_root, len);
        } else if (getenv("ENVOY")) {
          int len = 0;
          printf("- socket_address:\n");
          printf("    address: %s\n",srv->ip);
          printf("    port_value: %d\n", srv->port);
          len = evutil_snprintf(uri_root,sizeof(uri_root),
              "- socket_address:\n");
          uri_root[len] = 0;
          write(ffd, uri_root, len);
          len = evutil_snprintf(uri_root, sizeof(uri_root),
              "    address: %s\n", srv->ip);
          uri_root[len] = 0;
          write(ffd, uri_root, len);
          len = evutil_snprintf(uri_root, sizeof(uri_root),
              "    port_value: %d\n", srv->port);
          uri_root[len] = 0;
          write(ffd, uri_root, len);
          evutil_snprintf(uri_root, sizeof(uri_root),
              "http://%s:%d",addr,got_port);
          printf("Url: %s\n", uri_root);
      } else if (getenv("haproxy")) {
          int len = 0;
          len = evutil_snprintf(uri_root, sizeof(uri_root), " server server%d %s:%d check\n",
                                srv->srvid, srv->ip, srv->port);
         uri_root[len] = 0;
         write(ffd, uri_root, len);
      } else if (getenv("ngnix")) {
        int len = 0;
        len = evutil_snprintf(uri_root, sizeof(uri_root), "server %s:%d;\n",srv->ip,srv->port);
        uri_root[len] = 0;
        write(ffd, uri_root, len);
      } else {
        fprintf(stderr, "evutil_inet_ntop failed\n");
        return 1;
      }
    }
}

struct SrvIps {
  char ipAddr[20];
} gSrvIps[10000];
int gIdx;

int http_read_srvr_ips(const char *file)
{
  char ipAddr[20];
  FILE *fp = fopen(file, "rb");

  while(fgets(ipAddr,sizeof(ipAddr),fp)!=NULL) {
    int l=strrchr(ipAddr,'\n') - ipAddr;
    strncpy(gSrvIps[gIdx].ipAddr,ipAddr,l);
    gSrvIps[gIdx++].ipAddr[l]=0;
  }
}

int main(int argc, char **argv)
{
    int cnt=0;
	  struct event_base *base;
	  struct evhttp *http;
	  struct evhttp_bound_socket *handle;
    uint16_t sport=0;
    int numSrvs=0;

    if (argc < 5) {
        printf("Usage: %s <ipaddr> <startport> <numsrvs> <docroot>\n",argv[0]);
        exit(-1);
    }

    atexit(exit_handler);
    ghttpcfg.startport=atoi(argv[2]);
    ghttpcfg.numsrvs=atoi(argv[3]);
    strncpy(ghttpcfg.httpserverip, argv[1], MAXIPLEN);
    strncpy(ghttpcfg.rootdoc, argv[4], sizeof(ghttpcfg.rootdoc));
    numSrvs = ghttpcfg.numsrvs;

    if (argc==6) {
      http_read_srvr_ips(argv[5]);
      numSrvs=gIdx;
    }

    base = event_base_new();
    if (!base) {
      fprintf(stderr, "Couldn't create an event_base: exiting\n");
      return 1;
    }

    sport=ghttpcfg.startport;
    while (cnt < numSrvs) {
      struct Server *srv = malloc(sizeof(struct Server));
      int i=0;
      if (gIdx) {
        srv->ip=gSrvIps[cnt].ipAddr;
      } else {
        srv->ip=ghttpcfg.httpserverip;
      }
      http = evhttp_new(base);
      if (!http) {
          fprintf(stderr, "couldn't create evhttp. Exiting.\n");
          return 1;
      }
      srv->http=http;
      while (i < 5) {
         struct evhttp_bound_socket *handle=evhttp_bind_socket_with_handle(http,\
                 srv->ip,sport);
         if (handle)  {
           srv->handle=handle;
           break;
         }
         sport++;
         i++;
      }
      if (gIdx) {
        srv->port=ghttpcfg.startport;
      } else {
        srv->port=sport;
      }
      srv->srvid=cnt;
      cnt++;
	    evhttp_set_gencb(http, send_document_cb, (void*)srv);
      emit_http_srv_cfg(srv);
    }
    event_base_dispatch(base);
}
