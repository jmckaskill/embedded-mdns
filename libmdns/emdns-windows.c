#include "../emdns.h"
#ifdef _WIN32

#include <winsock2.h>
#include <WS2tcpip.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define MDNS_PORT 5353
static unsigned char g_ipv6_mcast[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFB};

int emdns_bind6(int interface_id, struct sockaddr_in6 *send_addr) {
	WSADATA wsa_data;
	WSAStartup(MAKEWORD(2,2), &wsa_data);

	int fd = (int) socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		return -1;
	}

	DWORD reuseaddr = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*) &reuseaddr, sizeof(reuseaddr))) {
		goto err;
	}

	DWORD v6only = 1;
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char*) &v6only, sizeof(v6only))) {
		goto err;
	}

	DWORD hops = 255;
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char*) &hops, sizeof(hops))) {
		goto err;
	}

	DWORD loopback = 0;
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (char*) &loopback, sizeof(loopback))) {
		goto err;
	}

	struct sockaddr_in6 sab = {0};
	sab.sin6_family = AF_INET6;
	sab.sin6_port = ntohs(MDNS_PORT);
	memcpy(&sab.sin6_addr, &in6addr_any, sizeof(sab.sin6_addr));

	if (bind(fd, (struct sockaddr*) &sab, sizeof(sab))) {
		goto err;
	}

	struct ipv6_mreq req = {0};
	req.ipv6mr_interface = interface_id;
	memcpy(&req.ipv6mr_multiaddr, &g_ipv6_mcast, sizeof(g_ipv6_mcast));
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char*) &req, sizeof(req))) {
		goto err;
	}

	DWORD dwinterface = interface_id;
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, (char*) &dwinterface, sizeof(dwinterface))) {
		goto err;
	}

	memset(send_addr, 0, sizeof(*send_addr));
	send_addr->sin6_family = AF_INET6;
	send_addr->sin6_port = htons(MDNS_PORT);
	memcpy(&send_addr->sin6_addr, &g_ipv6_mcast, sizeof(g_ipv6_mcast));
	
	return fd;

err:
	closesocket(fd);
	return -1;
}

#endif
