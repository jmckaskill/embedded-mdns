#ifdef _WIN32
#include <winsock2.h>
#include <IPHlpApi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#include <windows.h>
#else
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#endif

#include "../emdns.h"
#include <stdio.h>
#include <inttypes.h>
#include <string.h>

#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif

static void on_service(void *udata, const char *name, int namesz, const struct sockaddr *sa, const char *txt, int txtsz) {
	char buf[64];
	if (!sa) {
		printf("- %.*s\n", namesz, name);
	} else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sa6 = (struct sockaddr_in6*) sa;
		inet_ntop(AF_INET6, (void*) &sa6->sin6_addr, buf, sizeof(buf));
		printf("+ %.*s IP %s PORT %d\n", namesz, name, buf, ntohs(sa6->sin6_port));
	} else {
		struct sockaddr_in *sa4 = (struct sockaddr_in*) sa;
		inet_ntop(AF_INET, (void*) &sa4->sin_addr, buf, sizeof(buf));
		printf("+ %.*s IP %s PORT %d\n", namesz, name, buf, ntohs(sa4->sin_port));
	}
}

#ifdef __MACH__
#include <mach/mach_time.h>
static mach_timebase_info_data_t g_timebase_info;
#endif

emdns_time tick() {
#if defined WIN32
	return (emdns_time) GetTickCount64();
#elif defined __MACH__
	uint64_t ticks = mach_absolute_time();
	if (g_timebase_info.denom == 0) {
		mach_timebase_info(&g_timebase_info);
	}
    double ns = ((double)ticks * g_timebase_info.numer) / g_timebase_info.denom;
	return (emdns_time)(ns / 1e6);
#else
	struct timespec tv;
	clock_gettime(CLOCK_MONOTONIC, &tv);
    return (emdns_time)(tv.tv_nsec / 1000 / 1000) + ((emdns_time)tv.tv_sec * 1000);
#endif
}

int main(int argc, char *argv[]) {
	char buf2[256];
	if_indextoname(3, buf2);
	if (argc < 3) {
		fprintf(stderr, "usage: mdns-scan [interface] [service]\n"
			"\tservice is the service to search for e.g. _http._tcp.local.)\n"
			"\tinterface is the name of the interface to search on e.g. eth0 or \"Ethernet 2\"\n"
			);
		return 2;
	}


	int interface_id = if_nametoindex(argv[1]);
	if (!interface_id) {
		fprintf(stderr, "%s is not a valid interface\n", argv[1]);
		return 2;
	}

	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	struct ifreq ifr;
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, argv[1], IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);

	struct sockaddr_in *ifsa = (struct sockaddr_in *) &ifr.ifr_addr;
	char buf[64];
	inet_ntop(AF_INET, (void*) &ifsa->sin_addr, buf, sizeof(buf));
	fprintf(stderr, "idx %d IP %s %x\n", interface_id, buf, ntohl(ifsa->sin_addr.s_addr));
	close(fd);

	struct sockaddr_in6 send6;
	struct sockaddr_in send4;

	int fd6 = emdns_bind6(interface_id, &send6);

	int fd4 = emdns_bind4(ifsa->sin_addr, &send4);

#ifdef _WIN32
	long nonblock = 1;
	ioctlsocket(fd4, FIONBIO, &nonblock);
	ioctlsocket(fd6, FIONBIO, &nonblock);
#else
	fcntl(fd4, F_SETFL, O_NONBLOCK);
	fcntl(fd6, F_SETFL, O_NONBLOCK);
#endif

	struct emdns *m = emdns_new("");
	emdns_scan(m, tick(), argv[2], NULL, &on_service);

	for (;;) {
		char buf[1024];
		struct timeval tv;

		for (;;) {
			emdns_time now = tick();
			emdns_time next = now;
			int w = emdns_next(m, &next, buf, sizeof(buf));
			if (w == EMDNS_PENDING) {
				next -= now;
				tv.tv_sec = (long) (next / 1000);
				tv.tv_usec = (long) ((next % 1000) * 1000);
				break;
			} else if (w >= 0) {
				sendto(fd4, buf, w, 0, (struct sockaddr*) &send4, sizeof(send4));
				sendto(fd6, buf, w, 0, (struct sockaddr*) &send6, sizeof(send6));
			} else {
				return 2;
			}
		}

		fd_set read;
		FD_ZERO(&read);
		FD_SET(fd4, &read);
		FD_SET(fd6, &read);
		int ret = select(max(fd4,fd6)+1, &read, NULL, NULL, &tv);

		if (ret < 0) {
			return 2;
		}

		if (FD_ISSET(fd4, &read)) {
			for (;;) {
				int r = recv(fd4, buf, sizeof(buf), 0);
				if (r >= 0) {
					emdns_process(m, tick(), buf, r);
				} else {
					break;
				}
			}
		}

		if (FD_ISSET(fd6, &read)) {
			for (;;) {
				int r = recv(fd6, buf, sizeof(buf), 0);
				if (r >= 0) {
					emdns_process(m, tick(), buf, r);
				} else {
					break;
				}
			}
		}
	}
}
