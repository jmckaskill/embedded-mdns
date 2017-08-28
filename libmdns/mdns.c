#include "mdns.h"
#include <assert.h>
#include <string.h>

#define MIN_MESSAGE_SIZE 512
#define RCLASS_IN 1

static void put_big_16(uint8_t *u, uint16_t v) {
	u[0] = (uint8_t) (v >> 8);
	u[1] = (uint8_t) v;
}

int mdns_next(struct mdns *m, mdns_time *time, void *buf, int sz) {
	assert(sz >= MIN_MESSAGE_SIZE);
	uint8_t *u = (uint8_t*) buf;
	put_big_16(u, 0); // transaction ID
	put_big_16(u+2, 0); // flags
	put_big_16(u+4, m->request_num); // questions
	put_big_16(u+6, 0); // answers
	put_big_16(u+8, 0); // authority
	put_big_16(u+10, 0); // additional
	u += 12;

	for (int i = 0; i < MDNS_MAX_REQUESTS; i++) {
		struct mdns_request *r = &m->requestv[i];
		if (r->valid) {
			memcpy(u, r->name, r->namesz);
			u += r->namesz;
			put_big_16(u, (uint16_t) r->type);
			put_big_16(u+2, RCLASS_IN);
			u += 4;
		}
	}

	assert(u <= (uint8_t*) buf + sz);
	return u - (uint8_t*) buf;
}

int mdns_process(struct mdns *m, mdns_time time, const struct sockaddr *sa, int sasz, const void *msg, int sz) {
	return -1;
}

// copies a double null-terminated string into dns form
// returns length of new list or -ve on error
// buf must be 256 bytes long
static int copy_to_dns_name(uint8_t *buf, const char *src) {
	int total = 0;

	for (;;) {
		char *dot = strchr(src, '.');
		if (dot == src || !dot) {
			break;
		}
		size_t len = dot - src;
		if (len > 63) {
			return -1;
		}

		total += 1 + len;
		// check against 255 so we always have room for the trailing root
		if (total > 255) {
			return -1;
		}

		buf[0] = (uint8_t) len;
		memcpy(buf+1, src, len);

		buf += 1 + len;
		src += len + 1;
	}

	// add the trailing root
	*(buf++) = 0;
	total++;

	return total;
}

int mdns_scan(struct mdns *m, mdns_time time, enum mdns_rtype type, const char *name, void *udata, mdns_cb add, mdns_cb remove) {
	int id;
	for (id = 0; id < MDNS_MAX_REQUESTS; id++) {
		if (!m->requestv[id].valid) {
			break;
		}
	}

	if (id == MDNS_MAX_REQUESTS) {
		return MDNS_TOO_MANY;
	}

	struct mdns_request *r = &m->requestv[id];
	int sz = copy_to_dns_name(r->name, name);
	if (sz < 0) {
		return MDNS_MALFORMED;
	}

	r->valid = 1;
	r->query = 0;
	r->udata = udata;
	r->add = add;
	r->remove = remove;
	r->namesz = (uint8_t) sz;
	r->type = type;
	m->request_num++;
	return id;
}

