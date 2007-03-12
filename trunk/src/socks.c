/*
3APA3A simpliest proxy server
(c) 2002-2006 by ZARAZA <3APA3A@security.nnov.ru>

please read License Agreement

$Id: socks.c,v 1.24 2006/07/07 21:24:57 vlad Exp $
*/

#include "proxy.h"

#define SOCKSTRACE 1

#define NOPORTMAP
#define WITHMAIN

#define RETURN(xxx) { param->res = xxx; goto CLEANRET; }

unsigned char * commands[] = {(unsigned char *)"UNKNOWN", (unsigned char *)"CONNECT", (unsigned char *)"BIND", (unsigned char *)"UDPMAP"};

struct datatable socks_table = {
	STRINGTABLE,
	sizeof(commands)/sizeof(unsigned char *),
	(void *)commands
};

#define BUFSIZE 1024
#define LARGEBUFSIZE 67000

#define param ((struct clientparam*)data)

void * sockschild(void * data) {
	int res;
	unsigned i=0;
	SOCKET s;
	unsigned size;
	SASIZETYPE sasize;
	unsigned char * buf=NULL;
	unsigned char c;
	unsigned char command=0;
	struct in_addr reqaddr;
	struct pollfd fds[3];
	int ver=0;
	int havepass = 0;
	struct sockaddr_in sin;
	int len;

	reqaddr.s_addr = 0;
	param->service = S_SOCKS;

	if(!(buf = myalloc(BUFSIZE))) {	RETURN(21);	}

	memset(buf, 0, BUFSIZE);
	if ((ver = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_L], 0)) != 5 && ver != 4) {
		RETURN(401);
	} /* version */
	param->service = ver;
	if(ver == 5){
		if ((i = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(441);} /* nmethods */
		for (; i; i--) {
			if ((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(442);}
			if (res == 2) {
				havepass = res;
			}
		}
		buf[0] = 5;
		buf[1] = havepass;
		if(socksend(param->clisock, buf, 2, conf.timeouts[STRING_S])!=2){RETURN(402);}
		if (havepass) {
			if (((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_L], 0))) != 1) {
				RETURN(412);
			}
			if ((i = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(443);}
			if (i && (unsigned)(res = sockgetlinebuf(param, CLIENT, buf, i, 0, conf.timeouts[STRING_S])) != i){RETURN(444);};
			buf[i] = 0;
			if(!param->username)param->username = (unsigned char *)mystrdup((char *)buf);
			if ((i = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(445);}
			if (i && (unsigned)(res = sockgetlinebuf(param, CLIENT, buf, i, 0, conf.timeouts[STRING_S])) != i){RETURN(446);};
			buf[i] = 0;
			if(!param->password)param->password = (unsigned char *)mystrdup((char *)buf);
			buf[0] = 1;
			buf[1] = 0;
			if(socksend(param->clisock, buf, 2, conf.timeouts[STRING_S])!=2){RETURN(402);}
		}
		if ((c = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_L], 0)) != 5) {
			RETURN(421);
		} /* version */
	}
	if( (command = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) < 1 || command > 3){command = 0; RETURN(407);} /* command */
	if(ver == 5){
		if (sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0) == EOF) {RETURN(447);} /* reserved */
		c = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0); /* atype */
	}
	else {
		if ((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(448);}
		buf[0] = (unsigned char) res;
		if ((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(449);}
		buf[1] = (unsigned char) res;
		param->sins.sin_port = param->reqport = *(unsigned short*)buf;
		c = 1;
	}

	switch(c) {
	case 1:
		for (i = 0; i<4; i++){
			if ((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(450);}
			buf[i] = (unsigned char)res;
		}
		param->sins.sin_addr.s_addr = reqaddr.s_addr = *(unsigned long *)buf;
		if(command==1 && !reqaddr.s_addr) {
			RETURN(422);
		}
		myinet_ntoa(param->sins.sin_addr, (char *)buf);
		break;
	case 3:
		if ((size = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(451);} /* nmethods */
		for (i=0; i<size; i++){ /* size < 256 */
			if ((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(452);}
			buf[i] = (unsigned char)res;
		}
		buf[i] = 0;
		param->sins.sin_addr.s_addr = reqaddr.s_addr = getip(buf);
		if(command==1 && !reqaddr.s_addr) {
			RETURN(423);
		}
		break;
	default:
		RETURN(998);
	}
	if(param->hostname)
		myfree(param->hostname);
	param->hostname = (unsigned char *)mystrdup((char *)buf);
	if (ver == 5) {
		if ((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(453);}
		buf[0] = (unsigned char) res;
		if ((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(454);}
		buf[1] = (unsigned char) res;
		param->sins.sin_port = param->reqport = *(unsigned short*)buf;
	}
	else {
		sockgetlinebuf(param, CLIENT, buf, BUFSIZE - 1, 0, conf.timeouts[STRING_S]);
		buf[127] = 0;
		if(*buf && !param->username)param->username = (unsigned char *)mystrdup((char *)buf);
		if(param->sins.sin_addr.s_addr && ntohl(param->sins.sin_addr.s_addr)<256){
			param->service = S_SOCKS45;
			sockgetlinebuf(param, CLIENT, buf, BUFSIZE - 1, 0, conf.timeouts[STRING_S]);
			buf[127] = 0;
			if(param->hostname)myfree(param->hostname);
			param->hostname = (unsigned char *)mystrdup((char *)buf);
			param->sins.sin_addr.s_addr = reqaddr.s_addr = getip(buf);
		}
	}

	/* we have the command and param from the socks client,
	   send that across the link to do the actuall connection */

	/* assign this CLI connection an identifier, param->clisock might work */

	/* send the command across the link */

	/* listen on the link for results */

	/* this code is on other side of the link */
	if(command == 1 && !param->reqport) {RETURN(424);}
	param->sins.sin_family = AF_INET;
	switch(command) { 
	case 1:
		param->operation = CONNECT;
		break;
	case 2:
		param->sins.sin_addr.s_addr = param->extip;
		param->sins.sin_port = param->extport?param->extport:param->reqport;
		if ((param->remsock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {RETURN (11);}
		param->operation = BIND;
		break;
	case 3:
		param->sins.sin_port = param->extport?param->extport:param->reqport;
		param->sins.sin_addr.s_addr = param->extip;
		if ((param->remsock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET) {RETURN (11);}
		param->operation = UDPASSOC;
		break;
	default:
		RETURN(997);
	}

	if((res = (*param->authfunc)(param))) {RETURN(res);}

	if(command > 1) {
		if(bind(param->remsock,(struct sockaddr *)&param->sins,sizeof(param->sins))) {
			param->sins.sin_port = 0;
			if(bind(param->remsock,(struct sockaddr *)&param->sins,sizeof(param->sins)))RETURN (12);
#if SOCKSTRACE > 0
			fprintf(stderr, "%s:%hu binded to communicate with server\n",
				inet_ntoa(param->sins.sin_addr),
				ntohs(param->sins.sin_port)
				);
			fflush(stderr);
#endif
		}
		sasize = sizeof(struct sockaddr_in);
		getsockname(param->remsock, (struct sockaddr *)&param->sins,  &sasize);
		if(command == 3) {
			param->ctrlsock = param->clisock;
			param->clisock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if(param->clisock == INVALID_SOCKET) {RETURN(11);}
			sin.sin_family = AF_INET;
			sin.sin_addr.s_addr = param->intip;
			sin.sin_port = htons(0);
			if(bind(param->clisock,(struct sockaddr *)&sin,sizeof(struct sockaddr_in))) {RETURN (12);}
#if SOCKSTRACE > 0
			fprintf(stderr, "%s:%hu binded to communicate with client\n",
				inet_ntoa(sin.sin_addr),
				ntohs(sin.sin_port)
				);
			fflush(stderr);
#endif
		}
	}
	param->res = 0;

CLEANRET:

	if(param->clisock != INVALID_SOCKET){
		sasize = sizeof(struct sockaddr_in);
		if(command != 3) getsockname(param->remsock, (struct sockaddr *)&sin,  &sasize);
		else getsockname(param->clisock, (struct sockaddr *)&sin,  &sasize);
#if SOCKSTRACE > 0
		fprintf(stderr, "Sending confirmation to client with code %d for %s with %s:%hu\n",
			param->res,
			commands[command],
			inet_ntoa(sin.sin_addr),
			ntohs(sin.sin_port)
			);
		fflush(stderr);
#endif
		if(ver == 5){
			buf[0] = 5;
			buf[1] = param->res%10;
			buf[2] = 0;
			buf[3] = 1;
			memcpy(buf+4, &sin.sin_addr.s_addr, 4);
			memcpy(buf+8, &sin.sin_port, 2);
			socksend((command == 3)?param->ctrlsock:param->clisock, buf, 10, conf.timeouts[STRING_S]);
		}
		else{
			buf[0] = 0;
			buf[1] = 90 + (param->res%10);
			memcpy(buf+2, &sin.sin_port, 2);
			memcpy(buf+4, &sin.sin_addr.s_addr, 4);
			socksend(param->clisock, buf, 8, conf.timeouts[STRING_S]);
		}

		if (param->res == 0) {
			switch(command) {
			case 1:
				if(param->redirectfunc){
					if(buf)myfree(buf);
					return (*param->redirectfunc)(param);
				}
				param->res = sockmap(param, conf.timeouts[CONNECTION_L]);
				break;
			case 2:
				listen (param->remsock, 1);

				fds[0].fd = param->remsock;
				fds[1].fd = param->clisock;
				fds[0].events = fds[1].events = POLLIN;
				res = poll(fds, 2, conf.timeouts[(reqaddr.s_addr)?CONNECTION_S:CONNECTION_L] * 1000);
				if (res < 1 || fds[1].revents) {
					res = 460;
					break;
				}
				sasize = sizeof(param->sins);
				s = accept(param->remsock, (struct sockaddr *)&param->sins, &sasize);
				shutdown(param->remsock, SHUT_RDWR);
				closesocket(param->remsock);
				param->remsock = s;
				if(s == INVALID_SOCKET) {
					param->res = 462;
					break;
				}
				if(reqaddr.s_addr && reqaddr.s_addr != param->sins.sin_addr.s_addr) {
					param->res = 470;
					break;
				}
#if SOCKSTRACE > 0
				fprintf(stderr, "Sending incoming connection to client with code %d for %s with %s:%hu\n",
					param->res,
					commands[command],
					inet_ntoa(param->sins.sin_addr),
					ntohs(param->sins.sin_port)
					);
				fflush(stderr);
#endif
				if(ver == 5){
					memcpy (buf+4, &param->sins.sin_addr, 4);
					memcpy (buf+8, &param->sins.sin_port, 2);
					socksend(param->clisock, buf, 10, conf.timeouts[STRING_S]);
				}
				else {
					memcpy (buf+2, &param->sins.sin_port, 2);
					memcpy (buf+4, &param->sins.sin_addr, 4);
					socksend(param->clisock, buf, 8, conf.timeouts[STRING_S]);
				}

				param->res = sockmap(param, conf.timeouts[CONNECTION_S]);
				break;
			case 3:
				param->sins.sin_addr.s_addr = reqaddr.s_addr;
				param->sins.sin_port = param->reqport;
				myfree(buf);
				if(!(buf = myalloc(LARGEBUFSIZE))) {RETURN(21);}

				for(;;){
					fds[0].fd = param->remsock;
					fds[1].fd = param->clisock;
					fds[2].fd = param->ctrlsock;
					fds[2].events = fds[1].events = fds[0].events = POLLIN;

					res = poll(fds, 3, conf.timeouts[CONNECTION_L]*1000);
					if(res <= 0) {
						param->res = 463;
						break;
					}
					if (fds[2].revents) {
						param->res = 0;
						break;
					}
					if (fds[1].revents) {
						sasize = sizeof(struct sockaddr_in);
						if((len = recvfrom(param->clisock, buf, 65535, 0, (struct sockaddr *)&sin, &sasize)) <= 10) {
							param->res = 464;
							break;
						}
						if(sin.sin_addr.s_addr != param->sinc.sin_addr.s_addr){
							param->res = 465;
							break;
						}
						if(buf[0] || buf[1] || buf[2]) {
							param->res = 466;
							break;
						}
						switch(buf[3]) {
							case 1:
								i = 8;
								memcpy(&param->sins.sin_addr.s_addr, buf+4, 4);
								break;
							case 3:
								size = buf[4];
								for (i=4; size; i++, size--){
									buf[i] = buf[i+1];
								}
								buf[i++] = 0;
								param->sins.sin_addr.s_addr = getip(buf+4);
								break;
							default:
								RETURN(996);
						}

						memcpy(&param->sins.sin_port, buf+i, 2);
						i+=2;

						sasize = sizeof(param->sins);
						if(len > (int)i){
							if(socksendto(param->remsock, &param->sins, buf+i, len - i, conf.timeouts[SINGLEBYTE_L]*1000) <= 0){
								param->res = 467;
								break;
							}
							param->statscli+=(len - i);
#if SOCKSTRACE > 1
							fprintf(stderr, "UDP packet relayed from client to %s:%hu size %d, header %d\n",
								inet_ntoa(param->sins.sin_addr),
								ntohs(param->sins.sin_port),
								(len - i),
								i
								);
							fprintf(stderr, "client address is assumed to be %s:%hu\n",
								inet_ntoa(sin.sin_addr),
								ntohs(sin.sin_port)
								);
							fflush(stderr);
#endif
						}

					}
					if (fds[0].revents) {
						struct sockaddr_in tsin;
						sasize = sizeof(tsin);
						buf[0]=buf[1]=buf[2]=0;
						buf[3]=1;
						if((len = recvfrom(param->remsock, buf+10, 65535 - 10, 0, (struct sockaddr *)&tsin, &sasize)) <= 0) {
							param->res = 468;
							break;
						}
						param->statssrv+=len;
						memcpy(buf+4, &tsin.sin_addr.s_addr, 4);
						memcpy(buf+8, &tsin.sin_port, 2);
						sasize = sizeof(param->sins);
						if(socksendto(param->clisock, &sin, buf, len + 10, conf.timeouts[SINGLEBYTE_L]*1000) <=0){
							param->res = 469;
							break;
						}
#if SOCKSTRACE > 1
						fprintf(stderr, "UDP packet relayed to client from %s:%hu size %d\n",
							inet_ntoa(tsin.sin_addr),
							ntohs(tsin.sin_port),
							len
							);
						fflush(stderr);
#endif

					}
				}
				break;
			default:
				param->res = 417;
				break;
			}
		}
	}

	if(command > 3) command = 0;
	if(buf){
		sprintf((char *)buf, "%s ", commands[command]);
		if(param->hostname){
			sprintf((char *)buf + strlen((char *)buf), "%.265s", param->hostname);
		}
		else myinet_ntoa(reqaddr, (char *)buf+strlen((char *)buf));
		sprintf((char *)buf+strlen((char *)buf), ":%hu", ntohs(param->reqport));
		(*param->logfunc)(param, buf);
		myfree(buf);
	}
	freeparam(data);
	return (NULL);
}

struct proxydef childdef = {
	sockschild,
	1080,
	0,
	S_SOCKS,
	""
};

/*
3APA3A simpliest proxy server
(c) 2002-2006 by ZARAZA <3APA3A@security.nnov.ru>

please read License Agreement

$Id: proxymain.c,v 1.36 2006/03/10 19:25:51 vlad Exp $
*/

int main (int argc, char** argv){

	SOCKET sock = INVALID_SOCKET;
	int i=0;
	SASIZETYPE size;
	pthread_t thread;
	struct clientparam defparam;
	int demon=0;
	struct clientparam * newparam;
	char *s;
	int error = 0;
	unsigned sleeptime;
	struct extparam myconf;
	unsigned char buf[256];
	struct pollfd fds;
	int opt = 1;
	PROXYFUNC pf;
	FILE *fp = NULL;
	int maxchild;
	int silent = 0;
	int nlog = 5000;
	char loghelp[] =
		" -d go to background (daemon)\n"
		" -fFORMAT logging format (see documentation)\n"
		" -l log to stderr\n"
		" -lFILENAME log to FILENAME\n"
		" -bBUFSIZE size of network buffer (default 4096 for TCP, 16384 for UDP)\n"
#ifndef _WIN32
		" -l@IDENT log to syslog IDENT\n"
#endif
		" -t be silenT (do not log service start/stop)\n"
		" -iIP ip address or internal interface (clients are expected to connect)\n"
		" -eIP ip address or external interface (outgoing connection will have this)\n";

	int childcount=0;
	pthread_mutex_t counter_mutex;


#ifdef _WIN32
	unsigned long ul;
#endif
	int new_sock = INVALID_SOCKET;
	struct linger lg;
#ifdef _WIN32
	HANDLE h;
#endif
#ifdef _WIN32
	WSADATA wd;
	WSAStartup(MAKEWORD( 1, 1 ), &wd);
#else
	signal(SIGPIPE, SIG_IGN);

	pthread_attr_init(&pa);
	pthread_attr_setstacksize(&pa,PTHREAD_STACK_MIN + 16384);
	pthread_attr_setdetachstate(&pa,PTHREAD_CREATE_DETACHED);
#endif


	pf = childdef.pf;
	memcpy(&myconf, &conf, sizeof(myconf));
	memset(&defparam, 0, sizeof(struct clientparam));
	defparam.version = paused;
	defparam.childcount = &childcount;
	defparam.logfunc = myconf.logfunc;
	defparam.authfunc = myconf.authfunc;
	defparam.aclnum = myconf.aclnum;
	defparam.service = childdef.service;
	defparam.usentlm = 1;
	defparam.stdlog = NULL;
	defparam.time_start = time(NULL);
	maxchild = myconf.maxchild;

	pthread_mutex_init(defparam.counter_mutex = &counter_mutex, NULL);

	for (i=1; i<argc; i++) {
		if(*argv[i]=='-') {
			switch(argv[i][1]) {
		 case 'd': 
			 if(!demon)daemonize();
			 demon = 1;
			 break;
		 case 'l':
			 defparam.logfunc = logstdout;
			 defparam.logtarget = (unsigned char*)mystrdup(argv[i]);
			 if(argv[i][2]) {
				 if(argv[i][2]=='@'){
#ifndef _WIN32
					 openlog(argv[i]+3, LOG_PID, LOG_DAEMON);
					 defparam.logfunc = logsyslog;
#endif
				 }
				 else 
				 {
					 fp = fopen(argv[i] + 2, "a");
					 if (fp) {
						 defparam.stdlog = fp;
						 fseek(fp, 0L, SEEK_END);
					 }
				 }

			 }
			 break;
		 case 'i':
			 myconf.intip = getip((unsigned char *)argv[i]+2);
			 break;
		 case 'e':
			 myconf.extip = getip((unsigned char *)argv[i]+2);
			 break;
		 case 'p':
			 myconf.intport = atoi(argv[i]+2);
			 break;
		 case 'b':
			 myconf.bufsize = atoi(argv[i]+2);
			 break;
		 case 'n':
			 defparam.usentlm = 0;
			 break;
		 case 'f':
			 defparam.logformat = (unsigned char *)argv[i] + 2;
			 break;
		 case 't':
			 silent = 1;
			 break;
		 case 's':
		 case 'a':
			 myconf.singlepacket = 1 + atoi(argv[i]+2);
			 break;
		 default:
			 error = 1;
			 break;
			}
		}
		else break;
	}

	if (error || i!=argc) {
		fprintf(stderr, "Usage: %s options\n"
			"Available options are:\n"
			"%s"
			" -pPORT - service port to accept connections\n"
			"%s"
			"\tExample: %s -i127.0.0.1\n\n"
			"%s", 
			argv[0], loghelp, childdef.helpmessage, argv[0],
			copyright
			);

		return (1);
	}

	if(!defparam.logformat){
		defparam.logformat = myconf.logformat;
	}
	if(defparam.logformat){
		if(*defparam.logformat == '-' && (s = strchr((char *)defparam.logformat + 1, '+')) && s[1]){
			*s = 0;
			defparam.nonprintable = (unsigned char *)mystrdup((char *)defparam.logformat + 1);
			defparam.replace = s[1];
			defparam.logformat = (unsigned char *)mystrdup(s + 2);
			*s = '+';
		}
		else defparam.logformat = (unsigned char *)mystrdup((char *)defparam.logformat);
	}
	defparam.sinc.sin_addr.s_addr = defparam.intip = myconf.intip;
	if(!myconf.intport)myconf.intport = childdef.port;
	defparam.sinc.sin_port = defparam.intport = htons(myconf.intport);
	defparam.sins.sin_addr.s_addr = defparam.extip = myconf.extip;
	defparam.sins.sin_port = defparam.extport = htons(myconf.extport);
	defparam.remsock = defparam.clisock = defparam.ctrlsock = INVALID_SOCKET;
	defparam.sins.sin_family = defparam.sinc.sin_family = AF_INET;
	defparam.singlepacket = myconf.singlepacket;
	defparam.bufsize = myconf.bufsize;

	lg.l_onoff = 1;
	lg.l_linger = conf.timeouts[STRING_L];
	if( (sock=socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
		perror("socket()");
		return -2;
	}
#ifdef _WIN32
	ioctlsocket(sock, FIONBIO, &ul);
#else
	fcntl(sock,F_SETFL,O_NONBLOCK);
#endif
	defparam.srvsock = sock;
	if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (unsigned char *)&opt, sizeof(int)))perror("setsockopt()");

	size = sizeof(defparam.sinc);
	for(sleeptime = SLEEPTIME * 100; bind(sock, (struct sockaddr*)&defparam.sinc, size)==-1; usleep(sleeptime)) {
		sprintf((char *)buf, "bind(): %s", strerror(errno));
		(*defparam.logfunc)(&defparam, buf);	
		sleeptime = (sleeptime<<1);	
		if(!sleeptime) {
			closesocket(sock);
			return -3;
		}
	}
	if(listen (sock, 1 + (maxchild>>4))==-1) {
		sprintf((char *)buf, "listen(): %s", strerror(errno));
		(*defparam.logfunc)(&defparam, buf);
		return -4;
	}

	defparam.threadid = (unsigned)pthread_self();
	if(!silent){
		sprintf((char *)buf, "Accepting connections [%u/%u]", (unsigned)getpid(), (unsigned)pthread_self());
		(*defparam.logfunc)(&defparam, buf);
	}
	defparam.sinc.sin_addr.s_addr = defparam.sins.sin_addr.s_addr = 0;
	defparam.sinc.sin_port = defparam.sins.sin_port = 0;

	fds.fd = sock;
	fds.events = POLLIN;


	for (;;) {
		for(;;){
			while((paused == defparam.version && childcount >= myconf.maxchild)){
				nlog++;			
				if(nlog > 5000) {
					sprintf((char *)buf, "Warning: too many connected clients (%d/%d)", childcount, myconf.maxchild);
					(*defparam.logfunc)(&defparam, buf);
					nlog = 0;
				}
				usleep(SLEEPTIME);
			}
			if (paused != defparam.version) break;
			if (fds.events & POLLIN) {
				error = poll(&fds, 1, 1000);
			}
			else {
				usleep(SLEEPTIME);
				continue;
			}
			if (error >= 1) break;
			if (error == 0) continue;
			sprintf((char *)buf, "poll(): %s/%d", strerror(errno), errno);
			(*defparam.logfunc)(&defparam, buf);
			if(errno != EAGAIN) break;
			continue;
		}
		if(paused != defparam.version) break;
		size = sizeof(defparam.sinc);
		new_sock = accept(sock, (struct sockaddr*)&defparam.sinc, &size);
		if(new_sock == INVALID_SOCKET){
			sprintf((char *)buf, "accept(): %s", strerror(errno));
			(*defparam.logfunc)(&defparam, buf);
			continue;
		}
#ifdef _WIN32
		ioctlsocket(new_sock, FIONBIO, &ul);
#else
		fcntl(new_sock,F_SETFL,O_NONBLOCK);
#endif

		setsockopt(new_sock, SOL_SOCKET, SO_LINGER, (unsigned char *)&lg, sizeof(lg));
		setsockopt(new_sock, SOL_SOCKET, SO_OOBINLINE, (unsigned char *)&opt, sizeof(int));
		if(! (newparam = myalloc (sizeof(defparam)))){
			closesocket(new_sock);
			defparam.res = 21;
			(*defparam.logfunc)(&defparam, (unsigned char *)"Memory Allocation Failed");
			usleep(SLEEPTIME);
			continue;
		};
		memcpy(newparam, &defparam, sizeof(defparam));
		clearstat(newparam);
		newparam->clisock = new_sock;
		newparam->child = newparam->prev = newparam->next = NULL;
		newparam->parent = &defparam;
		pthread_mutex_lock(&counter_mutex);
		if(!defparam.child)defparam.child = newparam;
		else {
			newparam->next = defparam.child;
			defparam.child = defparam.child->prev = newparam;
		}
#ifdef _WIN32
		h = CreateThread((LPSECURITY_ATTRIBUTES )NULL, 16384, (LPTHREAD_START_ROUTINE)pf, (void *) newparam, (DWORD)0, &thread);
		newparam->threadid = (unsigned)thread;
		if (h) {
			childcount++;
			CloseHandle(h);
		}
		else {
			myfree(newparam);
		}
#else
		if((error = pthread_create(&thread, &pa, pf, (void *)newparam))){
			sprintf((char *)buf, "pthread_create(): %s", strerror(error));
			(*defparam.logfunc)(&defparam, buf);
			freeparam(newparam);
		}
		else {
			childcount++;
			newparam->threadid = (unsigned)thread;
		}
#endif
		pthread_mutex_unlock(&counter_mutex);
		memset(&defparam.sinc, 0, sizeof(defparam.sinc));
	}
	if(defparam.srvsock != INVALID_SOCKET) closesocket(defparam.srvsock);
	if(!silent) defparam.logfunc(&defparam, (unsigned char *)"Exiting thread");
	defparam.service = S_ZOMBIE;
	while(defparam.child) usleep(SLEEPTIME * 100);
	defparam.threadid = 0;
	if(fp) fclose(fp);
	if(defparam.target) myfree(defparam.target);
	if(defparam.logtarget) myfree(defparam.logtarget);
	if(defparam.logformat) myfree(defparam.logformat);
	if(defparam.nonprintable) myfree(defparam.nonprintable);
	pthread_mutex_destroy(&counter_mutex);
	return 0;
}

