#include "ping.h"            

struct proto	proto_v4 = { proc_v4, send_v4, NULL, NULL, 0, IPPROTO_ICMP };

#ifdef	IPV6
struct proto	proto_v6 = { proc_v6, send_v6, NULL, NULL, 0, IPPROTO_ICMPV6 };
#endif

int
main(int argc, char **argv)
{
    extern char *optarg;
	int	c;
	struct addrinfo	*ai;
	char *e;
	opterr = 0;		/* don't want getopt() writing to stderr */
	interval=1;
	nsent=0;
	preload=0;
	npackets=MAXPACKET;
	
	while ( (c = getopt(argc, argv, "bc:dfhi:l:np:Q:qrRs:t:v")) != -1) {
        /*在这里进行添加功能指令操作*/
		switch (c) {
		case 'b':  /*允许ping一个广播地址，只用于IPv4*/
			option |= F_BROADCAST;
			broadcast = 1;
			break;
		case 'c':  /*数目  在发送指定数目的包后停止。*/
			npackets = strtol(optarg,&e,10);
			if(npackets <= 0 || *optarg == '\0' || *e != '\0')
				errx(1,"illegal number of packets -- %s",optarg);
			break;
		case 'd': /*使用Socket的SO_DEBUG功能。*/
			option |= F_SO_DEBUG;
			debug = 1;
			break;
		case 'h':  /*显示帮助信息*/
			usage();
			exit(1);
			break;
		case 'i':  /*秒数  设定间隔几秒送一个网络封包给一台机器，预设值是一秒送一次。*/
			interval = strtol(optarg,&e,10);
			if(interval <= 0 || *optarg == '\0' || *e != '\0')
				errx(1,"illegal timing inerval -- %s",optarg);
			option |= F_INTERVAL;
			break;
		case 'l':	/*前置载入  设置在送出要求信息之前，先行发出的数据包。*/
			preload = strtol(optarg, &e, 10); 
            if (preload < 0 || *optarg =='\0' || *e != '\0'||preload>65536) 
				errx(1, "illegal preload value -- %s", optarg); 
            break; 
		case 'q':  /*不显示任何传送包的信息，只显示最后的结果。*/
			option |= F_QUIET;
			break;
		case 'Q':
			tos = strtol(optarg,&e,10);
			option |= F_IP_TOS;
			break;
		case 'r':	/*忽略普通的RoutingTable，直接将数据包送到远端主机上。通常是查看本机的网络接口是否有问题。*/
			option |= F_SO_DONTROUTE; 
			dontroute = 1;
			break;
		case 's':  /*字节数  指定发送的数据字节数，预设值是56，加上8字节的ICMP头，一共是64ICMP数据字节。*/
			datalen = strtol(optarg,&e,10);
			if(datalen <= 0 || *optarg == '\0' || *e != '\0')
				errx(1,"illegal datalen value -- %s",optarg);
			if(datalen > MAXPACKET)
				errx(1,"datalen value too large,maxinum is %d ",MAXPACKET);
			break;
		case 't':  /*存活数值  设置存活数值TTL的大小。*/
			ttl = strtol(optarg,&e,10);
			if(ttl <= 0 || *optarg == '\0' || *e != '\0')
				errx(1,"illegal ttl value -- %s",optarg);
			option |= F_TTL;
			break;
		case 'v':  /*详细显示指令的执行过程。*/
			option |= F_VERBOSE;
			break;
		case '?':
			err_quit("unrecognized option: %c", c);
		default:
			usage();
		}
	}

	if (optind != argc-1)
		usage();
	host = argv[optind];

	pid = getpid();
	signal(SIGALRM, sig_alrm);
	signal(SIGINT,result);
	ai = host_serv(host, NULL, 0, 0);

	if(option & F_BROADCAST)
		printf("WARNING: ping broadcast address \n");
	
	printf("ping %s (%s): %d data bytes\n", ai->ai_canonname,
		   Sock_ntop_host(ai->ai_addr, ai->ai_addrlen), datalen);

		/* 4initialize according to protocol */
	if (ai->ai_family == AF_INET) {
		pr = &proto_v4;
#ifdef	IPV6
	} else if (ai->ai_family == AF_INET6) {
		pr = &proto_v6;
		if (IN6_IS_ADDR_V4MAPPED(&(((struct sockaddr_in6 *)
								 ai->ai_addr)->sin6_addr)))
			err_quit("cannot ping IPv4-mapped IPv6 address");
#endif
	} else
		err_quit("unknown address family %d", ai->ai_family);

	pr->sasend = ai->ai_addr;
	pr->sarecv = calloc(1, ai->ai_addrlen);
	pr->salen = ai->ai_addrlen;
	pr->icmpproto = IPPROTO_ICMP;
	
	if(preload!=0)
	{
		int w=0;
		char			recvbuf[BUFSIZE];
		socklen_t		len;
		ssize_t			n;
		struct timeval	tval;
		sockfd = socket(pr->sasend->sa_family, SOCK_RAW, pr->icmpproto);
		setuid(getuid());		/* don't need special permissions any more */

		int size = 60 * 1024;		/* OK if setsockopt fails */
		setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
		while(w < preload)
		{	
			send_v4();
			w++;
		}
		while(nreceived < preload)
		{
			n = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, pr->sarecv, &pr->salen);
			gettimeofday(&tval, NULL);
			(*pr->fproc)(recvbuf, n, &tval);
		}
		preload=0;
		printf("\n");
	}
	
	readloop();
	result(SIGALRM);
	exit(0);
}

void
proc_v4(char *ptr, ssize_t len, struct timeval *tvrecv)
{
	int				hlen1, icmplen;
	double			rtt;
	struct ip		*ip;
	struct icmp		*icmp;
	struct timeval	*tvsend;

	ip = (struct ip *) ptr;		/* start of IP header */
	hlen1 = ip->ip_hl << 2;		/* length of IP header */

	icmp = (struct icmp *) (ptr + hlen1);	/* start of ICMP header */
	if ( (icmplen = len - hlen1) < 8)
		err_quit("icmplen (%d) < 8", icmplen);

	if (icmp->icmp_type == ICMP_ECHOREPLY) {
		if (icmp->icmp_id != pid)
			return;			/* not a response to our ECHO_REQUEST */
		if (icmplen < 16)
			err_quit("icmplen (%d) < 16", icmplen);

		tvsend = (struct timeval *) icmp->icmp_data;
		tv_sub(tvrecv, tvsend);
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;
		if(max_time<rtt)
		      max_time=rtt;
	       if(min_time>rtt)
		      min_time=rtt;
	       sum_time+=rtt;	
             
		nreceived++;
		if(option & F_QUIET)
			return;
		
		if (!(option & F_VERBOSE))
		printf("%d bytes from %s: seq= %u, ttl= %d, rtt= %.3f ms\n",
				icmplen, Sock_ntop_host(pr->sarecv, pr->salen),
				icmp->icmp_seq, ip->ip_ttl, rtt);

		else
		printf("%d bytes from %s: type = %d, code = %d\n",
				icmplen, Sock_ntop_host(pr->sarecv, pr->salen),
				icmp->icmp_type, icmp->icmp_code);	
	} 
}

void
proc_v6(char *ptr, ssize_t len, struct timeval* tvrecv)
{
#ifdef	IPV6
	int					hlen1, icmp6len;
	double				rtt;
	struct ip6_hdr		*ip6;
	struct icmp6_hdr	*icmp6;
	struct timeval		*tvsend;

	/*
	ip6 = (struct ip6_hdr *) ptr;		// start of IPv6 header 
	hlen1 = sizeof(struct ip6_hdr);
	if (ip6->ip6_nxt != IPPROTO_ICMPV6)
		err_quit("next header not IPPROTO_ICMPV6");

	icmp6 = (struct icmp6_hdr *) (ptr + hlen1);
	if ( (icmp6len = len - hlen1) < 8)
		err_quit("icmp6len (%d) < 8", icmp6len);
	*/        

        icmp6=(struct icmp6_hdr *)ptr;  
        if((icmp6len=len)<8)                    //len-40
		err_quit("icmp6len (%d) < 8", icmp6len);


	if (icmp6->icmp6_type == ICMP6_ECHO_REPLY) {
		if (icmp6->icmp6_id != pid)
			return;			/* not a response to our ECHO_REQUEST */
		if (icmp6len < 16)
			err_quit("icmp6len (%d) < 16", icmp6len);

		tvsend = (struct timeval *) (icmp6 + 1);
		tv_sub(tvrecv, tvsend);
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;
		if(max_time<rtt)
		      max_time=rtt;
	       if(min_time>rtt)
		      min_time=rtt;
	       sum_time+=rtt;	
		nreceived++;
		if(option & F_QUIET)
			return;
		printf("%d bytes from %s: seq= %u, hlim= %d, rtt= %.3f ms\n",
				icmp6len, Sock_ntop_host(pr->sarecv, pr->salen),
				icmp6->icmp6_seq, ip6->ip6_hlim, rtt);

	} else if (option & F_VERBOSE) {
		if(option & F_QUIET)
			return;
		printf("  %d bytes from %s: type = %d, code = %d\n",
				icmp6len, Sock_ntop_host(pr->sarecv, pr->salen),
				icmp6->icmp6_type, icmp6->icmp6_code);
	}
#endif	/* IPV6 */
}

unsigned short
in_cksum(unsigned short *addr, int len)
{
        int                             nleft = len;
        int                             sum = 0;
        unsigned short  *w = addr;
        unsigned short  answer = 0;

        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

                /* 4mop up an odd byte, if necessary */
        if (nleft == 1) {
                *(unsigned char *)(&answer) = *(unsigned char *)w ;
                sum += answer;
        }

                /* 4add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return(answer);
}

void
send_v4(void)
{
	int			len;
	struct icmp	*icmp;

	icmp = (struct icmp *) sendbuf;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_id = pid;
	icmp->icmp_seq = nsent++;
	gettimeofday((struct timeval *) icmp->icmp_data, NULL);

	len = 8 + datalen;		/* checksum ICMP header and data */
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = in_cksum((u_short *) icmp, len);
	
	sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
}

void
send_v6()
{
#ifdef	IPV6
	int					len;
	struct icmp6_hdr	*icmp6;

	icmp6 = (struct icmp6_hdr *) sendbuf;
	icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6->icmp6_code = 0;
	icmp6->icmp6_id = pid;
	icmp6->icmp6_seq = nsent++;
	gettimeofday((struct timeval *) (icmp6 + 1), NULL);

	len = 8 + datalen;		/* 8-byte ICMPv6 header */

	sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
		/* kernel calculates and stores checksum for us */
#endif	/* IPV6 */
}

void
readloop(void)
{
	int				size;
	char			recvbuf[BUFSIZE];
	socklen_t		len;
	ssize_t			n;
	struct timeval	tval;
	
	sockfd = socket(pr->sasend->sa_family, SOCK_RAW, pr->icmpproto);
	setuid(getuid());		/* don't need special permissions any more */

	size = 60 * 1024;		/* OK if setsockopt fails */
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

	/*指令操作*/
	if(option & F_IP_TOS)
		setsockopt(sockfd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
	if(option & F_TTL)
		setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
	if(option & F_SO_DEBUG)
		setsockopt(sockfd, SOL_SOCKET, SO_DEBUG, &debug, sizeof(debug));
	if(option & F_BROADCAST)
		setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
	if(option & F_SO_DONTROUTE)
		setsockopt(sockfd, SOL_SOCKET,SO_DONTROUTE, &dontroute, sizeof(dontroute));
	
	sig_alrm(SIGALRM);		/* send first packet */

	for ( ; ; ) {
		len = pr->salen;
		n = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, pr->sarecv, &len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			else
				err_sys("recvfrom error");
		}
		
		gettimeofday(&tval, NULL);
		(*pr->fproc)(recvbuf, n, &tval);
		
		if(npackets && nreceived >= npackets)
			break;
	}
	
}

void usage(){
	err_quit("Usage:ping [-hbdqrvQ] [-c count] [-i interval] \n \
	   [-l behind] [-s packetsize]  \n \
          [-t ttl] [host ip]\n");
}

void result(int signo){
	double lost = (nsent-nreceived)*100/(double)nsent;
	struct addrinfo * ai_ping = host_serv(host, NULL, 0, 0);

	printf("\n--- %s (%s)  ping statistics ---\n",ai_ping->ai_canonname,Sock_ntop_host(ai_ping->ai_addr, ai_ping->ai_addrlen));
	printf("%ld packages transmitted,%ld received, %.3f%% lost, time= %.3fs\n",nsent,nreceived,lost,sum_time+(nsent-1)*interval);
	printf("rtt min/avg/max = %.3f/ %.3f/ %.3f \n",min_time,sum_time/nreceived,max_time);
	close(sockfd);
	exit(1);
}

void
sig_alrm(int signo)
{
        (*pr->fsend)();
		alarm(interval);
        return;         /* probably interrupts recvfrom() */
}

void
tv_sub(struct timeval *out, struct timeval *in)
{
	if ( (out->tv_usec -= in->tv_usec) < 0) {	/* out -= in */
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

char *
sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
    static char str[128];               /* Unix domain is largest */

        switch (sa->sa_family) {
        case AF_INET: {
                struct sockaddr_in      *sin = (struct sockaddr_in *) sa;

                if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
                        return(NULL);
                return(str);
        }

#ifdef  IPV6
        case AF_INET6: {
                struct sockaddr_in6     *sin6 = (struct sockaddr_in6 *) sa;

                if (inet_ntop(AF_INET6, &sin6->sin6_addr, str, sizeof(str)) == NULL)
                        return(NULL);
                return(str);
        }
#endif

#ifdef  HAVE_SOCKADDR_DL_STRUCT
        case AF_LINK: {
                struct sockaddr_dl      *sdl = (struct sockaddr_dl *) sa;

                if (sdl->sdl_nlen > 0)
                        snprintf(str, sizeof(str), "%*s",
                                         sdl->sdl_nlen, &sdl->sdl_data[0]);
                else
                        snprintf(str, sizeof(str), "AF_LINK, index=%d", sdl->sdl_index);
                return(str);
        }
#endif
        default:
                snprintf(str, sizeof(str), "sock_ntop_host: unknown AF_xxx: %d, len %d",
                                 sa->sa_family, salen);
                return(str);
        }
    return (NULL);
}

char *
Sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
        char    *ptr;

        if ( (ptr = sock_ntop_host(sa, salen)) == NULL)
                err_sys("sock_ntop_host error");        /* inet_ntop() sets errno */
        return(ptr);
}

struct addrinfo *
host_serv(const char *host, const char *serv, int family, int socktype)
{
        int                             n;
        struct addrinfo hints, *res;

        bzero(&hints, sizeof(struct addrinfo));
        hints.ai_flags = AI_CANONNAME;  /* always return canonical name */
        hints.ai_family = family;               /* AF_UNSPEC, AF_INET, AF_INET6, etc. */
        hints.ai_socktype = socktype;   /* 0, SOCK_STREAM, SOCK_DGRAM, etc. */

        if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0)
                return(NULL);

        return(res);    /* return pointer to first on linked list */
}
/* end host_serv */

static void
err_doit(int errnoflag, int level, const char *fmt, va_list ap)
{
        int             errno_save, n;
        char    buf[MAXLINE];

        errno_save = errno;             /* value caller might want printed */
#ifdef  HAVE_VSNPRINTF
        vsnprintf(buf, sizeof(buf), fmt, ap);   /* this is safe */
#else
        vsprintf(buf, fmt, ap);                                 /* this is not safe */
#endif
        n = strlen(buf);
        if (errnoflag)
                snprintf(buf+n, sizeof(buf)-n, ": %s", strerror(errno_save));
        strcat(buf, "\n");

        if (daemon_proc) {
                syslog(level, buf);
        } else {
                fflush(stdout);         /* in case stdout and stderr are the same */
                fputs(buf, stderr);
                fflush(stderr);
        }
        return;
}


/* Fatal error unrelated to a system call.
 * Print a message and terminate. */

void
err_quit(const char *fmt, ...)
{
        va_list         ap;

        va_start(ap, fmt);
        err_doit(0, LOG_ERR, fmt, ap);
        va_end(ap);
        exit(1);
}

/* Fatal error related to a system call.
 * Print a message and terminate. */

void
err_sys(const char *fmt, ...)
{
        va_list         ap;

        va_start(ap, fmt);
        err_doit(1, LOG_ERR, fmt, ap);
        va_end(ap);
        exit(1);
}
