#include "../simple-emdns.h"
#include "../emdns.h"
#include <stdio.h>

#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif

static int g_interface_id = -1;
static struct in_addr g_interface_ip4;
static struct in6_addr g_interface_ip6;

static int on_interface(void *udata, const struct emdns_interface *iface) {
#ifdef _WIN32
	if (!wcscmp((wchar_t*) udata, iface->name)) {
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
		g_interface_ip4 = *iface->ip4;
		for (int i = 0; i < iface->ip6_num; i++) {
			if (!memcmp(iface->ip6+i, "\xFE\x80", 2)) {
				memcpy(&g_interface_ip6, iface->ip6 + i, 16);
			}
		}
	}
	return 0;
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
	double ns = ((double) ticks * g_timebase_info.numer) / g_timebase_info.denom;
	return (emdns_time) (ns / 1e6);
#else
	struct timespec tv;
	clock_gettime(CLOCK_MONOTONIC, &tv);
	return (emdns_time) (tv.tv_nsec / 1000 / 1000) + ((emdns_time) tv.tv_sec * 1000);
#endif
}

static struct emdns_service g_services[] = {
	EMDNS_SERVICE("\x05_http\x04_tcp\x05local\0", "\0", 80),
};

static struct emdns_responder g_responder = {
	&g_interface_ip4, 1,
	&g_interface_ip6, 1,
	g_services, sizeof(g_services) / sizeof(g_services[0]),
	NULL, 0,
	NULL, 0,
};

static char *new_utf8(const wchar_t *u16) {
	size_t u8len = WideCharToMultiByte(CP_UTF8, 0, u16, -1, NULL, 0, NULL, NULL);
	char *ret = (char*) malloc(u8len + 1);
	WideCharToMultiByte(CP_UTF8, 0, u16, -1, ret, u8len, NULL, NULL);
	ret[u8len] = 0;
	return ret;
}

#ifdef _WIN32
int wmain(int argc, wchar_t *wargv[]) {
#else
int main(int argc, char *argv[]) {
#endif
	if (argc < 4) {
		fprintf(stderr, "usage: mdns-scan [interface] [hostname] [svcname]\n"
			"\tinterface is the name of the interface to search on e.g. eth0 or \"Local Area Connection 2\"\n"
		);
		return 1;
	}

#ifdef _WIN32
	wchar_t *iface = wargv[1];
	char *hostname = new_utf8(wargv[2]);
	char *svcname = new_utf8(wargv[3]);
#else
	char *iface = argv[1];
	char *hostname = argv[2]
	char *svcname = argv[3];
#endif


	if (emdns_lookup_interfaces(iface, &on_interface) || g_interface_id < 0) {
		fprintf(stderr, "could not find interface\n");
		return 4;
	}

	size_t hostsz = strlen(hostname);
	size_t labelsz = strlen(svcname);

	if (hostsz > 63 || labelsz > 63) {
		fprintf(stderr, "overlong name\n");
		return 5;
	}

	uint8_t host[80];
	host[0] = (uint8_t) hostsz;
	memcpy(&host[1], hostname, hostsz);
	memcpy(&host[1+hostsz], "\5local\0", 7);

	g_responder.label = svcname;
	g_responder.labelsz = labelsz;

	g_responder.host = host;
	g_responder.hostsz = 1 + hostsz + 7;

	char sendbuf[1024];
	int sendsz = emdns_build_response(&g_responder, sendbuf, sizeof(sendbuf));

	struct sockaddr_in6 send6;
	struct sockaddr_in send4;

	int fd6 = emdns_bind6(g_interface_id, &send6);
	int fd4 = emdns_bind4(g_interface_ip4, &send4);

#ifdef _WIN32
	long nonblock = 1;
	ioctlsocket(fd4, FIONBIO, &nonblock);
	ioctlsocket(fd6, FIONBIO, &nonblock);
#else
	char *svc = argv[2];
	fcntl(fd4, F_SETFL, O_NONBLOCK);
	fcntl(fd6, F_SETFL, O_NONBLOCK);
#endif

	sendto(fd4, sendbuf, sendsz, 0, (struct sockaddr*) &send4, sizeof(send4));
	sendto(fd6, sendbuf, sendsz, 0, (struct sockaddr*) &send6, sizeof(send6));

	struct timeval tv = {1, 0};
	select(0, NULL, NULL, NULL, &tv);

	sendto(fd4, sendbuf, sendsz, 0, (struct sockaddr*) &send4, sizeof(send4));
	sendto(fd6, sendbuf, sendsz, 0, (struct sockaddr*) &send6, sizeof(send6));

	emdns_time last4 = tick();
	emdns_time last6 = last4;

	for (;;) {
		fd_set read;
		FD_ZERO(&read);
		FD_SET(fd4, &read);
		FD_SET(fd6, &read);

		int ret = select(max(fd4, fd6), &read, NULL, NULL, NULL);

		char buf[1024];
		if (FD_ISSET(fd4, &read)) {
			for (;;) {
				int r = recv(fd4, buf, sizeof(buf), 0);
				if (r < 0) {
					break;
				}
				emdns_time now = tick();
				if (now - last4 > 1000 && emdns_should_respond(&g_responder, buf, r) == EMDNS_RESPOND) {
					sendto(fd4, sendbuf, sendsz, 0, (struct sockaddr*) &send4, sizeof(send4));
					last4 = now;
				}
			}
		}

		if (FD_ISSET(fd6, &read)) {
			for (;;) {
				int r = recv(fd6, buf, sizeof(buf), 0);
				if (r < 0) {
					break;
				}
				emdns_time now = tick();
				if (now - last6 > 1000 && emdns_should_respond(&g_responder, buf, r) == EMDNS_RESPOND) {
					sendto(fd6, sendbuf, sendsz, 0, (struct sockaddr*) &send6, sizeof(send6));
					last6 = now;
				}
			}
		}
	}

}
