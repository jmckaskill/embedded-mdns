#ifdef _WIN32
#include <winsock2.h>
#include <IPHlpApi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#define closesocket(fd) close(fd)
#endif

#include "mdns.h"
#include <stdio.h>

int main(int argc, char *argv[]) {
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

	int fd = emdns_bind6(interface_id);

	struct emdns m = {0};
	//emdns_scan(&m, 0, MDNS_AAAA, argv[2], NULL, NULL, NULL);

	char buf[512];
	int w = emdns_next(&m, NULL, buf, sizeof(buf));
	send(fd, buf, w, 0);

	closesocket(fd);

	return 0;
}
