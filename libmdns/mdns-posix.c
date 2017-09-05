#include "../emdns.h"

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

int emdns_bind4(struct in_addr interface_addr, struct sockaddr_in *send_addr) {
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		return -1;
	}

	int enable = 1;
	int hops = 255;

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable))) {
		goto err;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable))) {
		goto err;
    }
	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &hops, sizeof(hops))) {
		goto err;
	}
	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &interface_addr, sizeof(interface_addr))) {
		goto err;
	}

	struct ip_mreq mreq;
	mreq.imr_multiaddr.s_addr = htonl(0xE00000FB);
	mreq.imr_interface = interface_addr;
	if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) {
		goto err;
	}

	struct sockaddr_in sa = {0};
	sa.sin_family = AF_INET;
	sa.sin_port = ntohs(5353);
	sa.sin_addr.s_addr = INADDR_ANY;

	if (bind(fd, (struct sockaddr*) &sa, sizeof(sa))) {
		goto err;
	}

	send_addr->sin_family = AF_INET;
	send_addr->sin_addr.s_addr = mreq.imr_multiaddr.s_addr;
	send_addr->sin_port = ntohs(5353);

	return fd;

err:
	close(fd);
	return -1;
}

int emdns_bind6(int interface_id, struct sockaddr_in6* send_addr) {
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		return -1;
	}

	int enable = 1;
	int hops = 255;

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable))) {
		goto err;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable))) {
		goto err;
    }
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &enable, sizeof(enable))) {
		goto err;
	}
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops))) {
		goto err;
	}
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &interface_id, sizeof(interface_id))) {
		goto err;
	}
    
	unsigned char addr[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFB};
	struct ipv6_mreq req = {0};
	req.ipv6mr_interface = interface_id;
	memcpy(&req.ipv6mr_multiaddr, addr, sizeof(addr));
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &req, sizeof(req))) {
		goto err;
	}

	struct sockaddr_in6 sa = {0};
	sa.sin6_family = AF_INET6;
	sa.sin6_port = ntohs(5353);
	memcpy(&sa.sin6_addr, &in6addr_any, sizeof(sa.sin6_addr));

	if (bind(fd, (struct sockaddr*) &sa, sizeof(sa))) {
		goto err;
	}

	send_addr->sin6_family = AF_INET6;
	memcpy(&send_addr->sin6_addr, addr, sizeof(addr));
	send_addr->sin6_port = ntohs(5353);

	return fd;

err:
	close(fd);
	return -1;
}
#endif
