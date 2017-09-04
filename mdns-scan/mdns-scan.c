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
#define closesocket(fd) close(fd)
#endif

#include "../emdns.h"
#include <stdio.h>

static void on_service(void *udata, const char *name, int namesz, const struct sockaddr_in6 *sa, const char *txt, int txtsz) {
	if (sa) {
		char buf[64];
		inet_ntop(AF_INET6, (void*) &sa->sin6_addr, buf, sizeof(buf));
		printf("+ %.*s IP %s PORT %d\n", namesz, name, buf, ntohs(sa->sin6_port));
	} else {
		printf("- %.*s\n", namesz, name);
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
    return (emdns_time)(ns * 1e3);
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

	struct sockaddr_in6 send_addr;
	int fd = emdns_bind6(interface_id, &send_addr);

#ifdef _WIN32
	long nonblock;
	ioctlsocket(fd, FIONBIO, &nonblock);
#else
	fcntl(fd, F_SETFL, O_NONBLOCK);
#endif

	struct emdns *m = emdns_new("");
	emdns_scan_ip6(m, (emdns_time) GetTickCount64(), argv[2], NULL, &on_service);

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
				sendto(fd, buf, w, 0, (struct sockaddr*) &send_addr, sizeof(send_addr));
			} else {
				return 2;
			}
		}

		fd_set read;
		FD_ZERO(&read);
		FD_SET(fd, &read);
		int ret = select(fd+1, &read, NULL, NULL, &tv);

		if (ret == 1) {
			for (;;) {
				int r = recv(fd, buf, sizeof(buf), 0);
				if (r >= 0) {
					emdns_process(m, tick(), buf, r);
				} else {
					break;
				}
			}
		} else if (ret != 0) {
			return 2;
		}
	}
}
