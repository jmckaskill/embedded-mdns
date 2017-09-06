#include "../emdns.h"
#ifdef _WIN32

#include <winsock2.h>
#include <IPHlpApi.h>
#include <WS2tcpip.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define MDNS_PORT 5353
#define IPV4_MCAST 0xE00000FB
static unsigned char g_ipv6_mcast[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFB};

int emdns_bind4(struct in_addr interface_addr, struct sockaddr_in *send_addr) {
	WSADATA wsa_data;
	WSAStartup(MAKEWORD(2, 2), &wsa_data);

	int fd = (int) socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		return -1;
	}

	DWORD reuseaddr = 1;
	DWORD hops = 255;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*) &reuseaddr, sizeof(reuseaddr))) {
		goto err;
	}
	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, (char*) &hops, sizeof(hops))) {
		goto err;
	}

	struct sockaddr_in sab = {0};
	sab.sin_family = AF_INET;
	sab.sin_port = ntohs(MDNS_PORT);
	sab.sin_addr.s_addr = ntohl(INADDR_ANY);

	if (bind(fd, (struct sockaddr*) &sab, sizeof(sab))) {
		goto err;
	}

	struct ip_mreq req = {0};
	req.imr_multiaddr.s_addr = htonl(IPV4_MCAST);
	req.imr_interface = interface_addr;
	if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*) &req, sizeof(req))) {
		goto err;
	}

	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, (char*) &interface_addr, sizeof(interface_addr))) {
		goto err;
	}

	memset(send_addr, 0, sizeof(*send_addr));
	send_addr->sin_family = AF_INET;
	send_addr->sin_port = htons(MDNS_PORT);
	send_addr->sin_addr.s_addr = htonl(IPV4_MCAST);

	return fd;

err:
	closesocket(fd);
	return -1;
}

int emdns_bind6(int interface_id, struct sockaddr_in6 *send_addr) {
	WSADATA wsa_data;
	WSAStartup(MAKEWORD(2,2), &wsa_data);

	int fd = (int) socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		return -1;
	}

	DWORD reuseaddr = 1;
	DWORD v6only = 1;
	DWORD hops = 255;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*) &reuseaddr, sizeof(reuseaddr))) {
		goto err;
	}
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char*) &v6only, sizeof(v6only))) {
		goto err;
	}
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char*) &hops, sizeof(hops))) {
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

#define MAX_IP6 16

int emdns_lookup_interfaces(void *udata, emdns_ifcb cb) {
	struct in6_addr ip6[MAX_IP6];
	int ret = 0;
	unsigned long bufsz = 256 * 1024;
	IP_ADAPTER_ADDRESSES *buf = (IP_ADAPTER_ADDRESSES*) malloc(bufsz);
	if (GetAdaptersAddresses(AF_UNSPEC, 0, 0, buf, &bufsz)) {
		ret = -1;
	}

	for (IP_ADAPTER_ADDRESSES *addr = buf; addr != NULL && !ret; addr = addr->Next) {
		switch (addr->IfType) {
		case IF_TYPE_ETHERNET_CSMACD:
		case IF_TYPE_PPP:
		case IF_TYPE_SOFTWARE_LOOPBACK:
		case IF_TYPE_IEEE80211: {
				struct emdns_interface iface = {0};
				for (IP_ADAPTER_UNICAST_ADDRESS *a = addr->FirstUnicastAddress; a != NULL; a = a->Next) {
					switch (a->Address.lpSockaddr->sa_family) {
					case AF_INET: {
							struct sockaddr_in *sa = (struct sockaddr_in*) a->Address.lpSockaddr;
							iface.ip4 = &sa->sin_addr;
						}
						break;
					case AF_INET6: 
						if (iface.ip6_num < MAX_IP6) {
							struct sockaddr_in6 *sa = (struct sockaddr_in6*) a->Address.lpSockaddr;
							memcpy(&ip6[iface.ip6_num++], &sa->sin6_addr, sizeof(sa->sin6_addr));
						}
						break;
					}
				}
				iface.name = addr->FriendlyName;
				iface.description = addr->Description;
				iface.id = addr->IfIndex;
				iface.ip6 = ip6;
				ret = cb(udata, &iface);
			}
			break;
		}
	}

	free(buf);
	return ret;
}

#endif
