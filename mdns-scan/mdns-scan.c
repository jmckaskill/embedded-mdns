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

static void on_service(void *udata, const char *name, int namesz, const struct sockaddr *sa, int sasz, const char *txt, int txtsz) {
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

static int g_interface_id = -1;
static struct in_addr g_interface_ip;

static int on_interface(void *udata, const struct emdns_interface *iface) {
#ifdef _WIN32
	if (!wcscmp((wchar_t*)udata, iface->name)) {
#else
	if (!strcmp((char*) udata, iface->name)) {
#endif
		if (!iface->ip4) {
			fprintf(stderr, "interface does not have ip4 enabled\n");
			return 2;
		}
		if (!iface->ip6_num) {
			fprintf(stderr, "interface does not have ip6 enabled\n");
			return 3;
		}
		g_interface_id = iface->id;
		g_interface_ip = *iface->ip4;
	}
	return 0;
}

#ifdef _WIN32
int wmain(int argc, wchar_t *argv[]) {
#else
int main(int argc, char *argv[]) {
#endif
	if (argc < 3) {
		fprintf(stderr, "usage: mdns-scan [interface] [service]\n"
			"\tservice is the service to search for e.g. _http._tcp.local.)\n"
			"\tinterface is the name of the interface to search on e.g. eth0 or \"Local Area Connection 2\"\n"
			);
		return 1;
	}

	if (emdns_lookup_interfaces(argv[1], &on_interface) || g_interface_id < 0) {
		fprintf(stderr, "could not find interface\n");
		return 4;
	}

	struct sockaddr_in6 send6;
	struct sockaddr_in send4;

	int fd6 = emdns_bind6(g_interface_id, &send6);
	int fd4 = emdns_bind4(g_interface_ip, &send4);

#ifdef _WIN32
	char svc[64];
	WideCharToMultiByte(CP_UTF8, 0, argv[2], -1, svc, sizeof(svc), NULL, NULL);
	long nonblock = 1;
	ioctlsocket(fd4, FIONBIO, &nonblock);
	ioctlsocket(fd6, FIONBIO, &nonblock);
#else
	char *svc = argv[2];
	fcntl(fd4, F_SETFL, O_NONBLOCK);
	fcntl(fd6, F_SETFL, O_NONBLOCK);
#endif

	struct emdns *m = emdns_new("");
	emdns_scan(m, tick(), svc, NULL, &on_service);

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
