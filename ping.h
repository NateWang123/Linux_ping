#include 	<netinet/in_systm.h>
#include	<netinet/ip.h>
#include	<netinet/ip_icmp.h>
#include	<netinet/icmp6.h>
#include	<netinet/ip6.h>
#include	<sys/types.h>	/* basic system data types */
#include	<sys/socket.h>	/* basic socket definitions */
#include	<sys/time.h>	/* timeval{} for select() */
#include	<time.h>		/* timespec{} for pselect() */
#include	<netinet/in.h>	/* sockaddr_in{} and other Internet defns */
#include	<arpa/inet.h>	/* inet(3) functions */
#include	<netdb.h>
#include	<signal.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>
#include 	<pwd.h>
#include	<unistd.h>
#include	<sys/un.h>		/* for Unix domain sockets */
#include	<sys/ioctl.h>
#include	<net/if.h>
#include <stdarg.h>
#include <syslog.h>
#ifdef  HAVE_SOCKADDR_DL_STRUCT
#include       <net/if_dl.h>
#endif

#define IPV6

#define BUFSIZE	 1500
#define MAXLINE     4096
#define MAXPACKET   (65536 - 60 - 8)
 
/*功能常量列表*/
#define F_BROADCAST 0x1
#define F_INTERVAL  0x2
#define F_QUIET	0x4
#define F_TTL 0x8
#define F_VERBOSE 0x10
#define F_IP_TOS  0x20 
#define F_SO_DEBUG 0x40
#define F_SO_DONTROUTE  0x80         

/* globals */
char	 recvbuf[BUFSIZE];
char	 sendbuf[BUFSIZE];

int    datalen = 56;	/* #bytes of data, following ICMP header */
char	*host;
int nreceived;
int	 nsent;			/* add 1 for each sendto() */
pid_t pid;			/* our PID */
int	 sockfd;
int  daemon_proc;            /* set nonzero by daemon_init() */

int option;
int npackets;
int interval;
int broadcast;
int ttl;
int tos;
int preload;
int dontroute;
int debug;
double min_time=0;
double max_time=0;
double sum_time=0;

/* function prototypes */
void	proc_v4(char *, ssize_t, struct timeval *);
void	proc_v6(char *, ssize_t, struct timeval *);
void	send_v4(void);
void	send_v6(void);
void	readloop(void);
void	sig_alrm(int);
void	tv_sub(struct timeval *, struct timeval *);
void    usage();
void    result(int signo);

char * Sock_ntop_host(const struct sockaddr *sa, socklen_t salen);
struct addrinfo* host_serv(const char *host, const char *serv, int family, int socktype);
static void err_doit(int errnoflag, int level, const char *fmt, va_list ap);
void err_quit(const char *fmt, ...);
void err_sys(const char *fmt, ...);

struct proto {
  void	 (*fproc)(char *, ssize_t, struct timeval *);
  void	 (*fsend)(void);
  struct sockaddr  *sasend;	/* sockaddr{} for send, from getaddrinfo */
  struct sockaddr  *sarecv;	/* sockaddr{} for receiving */
  socklen_t	    salen;		/* length of sockaddr{}s */
  int	   	    icmpproto;	/* IPPROTO_xxx value for ICMP */
} *pr;

