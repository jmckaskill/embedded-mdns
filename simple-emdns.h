#pragma once
#include <stdint.h>

struct emdns_service {
	const uint8_t *name;
	size_t namesz;
	const uint8_t *txt;
	size_t txtsz;
	uint16_t port;
	unsigned respond; // internal
};

#define EMDNS_SERVICE(name, txt, port) {name, sizeof(name)-1, txt, sizeof(txt)-1, port, 0}

struct emdns_responder {
	struct in_addr *ip4v;
	size_t ip4n;
	struct in6_addr *ip6v;
	size_t ip6n;
	struct emdns_service *svcv;
	size_t svcn;
	const char *label;
	size_t labelsz;
	const uint8_t *host;
	size_t hostsz;
};

int emdns_should_respond(struct emdns_responder *r, const void *msg, int sz);
int emdns_build_response(struct emdns_responder *r, char *buf, int sz);
