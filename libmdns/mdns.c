#include "mdns.h"
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <limits.h>

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
// for htons
#endif

#ifdef _MSC_VER
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#endif

#ifndef container_of
#define container_of(ptr, type, member) ((type*) ((char*) (ptr) - offsetof(type, member)))
#endif

#define MIN_MESSAGE_SIZE 512

#define RCLASS_IN 1
#define RCLASS_IN_FLUSH 0x8001

#define RTYPE_AAAA 28
#define RTYPE_SRV 33
#define RTYPE_TXT 16
#define RTYPE_PTR 12
#define RTYPE_NSEC 47

#define LABEL_MASK 0xC0
#define LABEL_NORMAL 0x00
#define LABEL_PTR 0xC0
#define LABEL_PTR16 0xC000

#define FLAG_RESPONSE 0x8000
#define FLAG_AUTHORITY 0x0400

#define TTL_DEFAULT 120
#define PRIORITY_DEFAULT 0
#define WEIGHT_DEFAULT 0

static void put_big_16(uint8_t *u, uint16_t v) {
	u[0] = (uint8_t) (v >> 8);
	u[1] = (uint8_t) v;
}

static void put_big_32(uint8_t *u, uint32_t v) {
	u[0] = (uint8_t) (v >> 24);
	u[1] = (uint8_t) (v >> 16);
	u[2] = (uint8_t) (v >> 8);
	u[3] = (uint8_t) (v);
}

static uint16_t big_16(uint8_t *u) {
	return ((uint16_t) u[0] << 8) | ((uint16_t) u[1]);
}

static uint32_t big_32(uint8_t *u) {
	return ((uint32_t) u[0] << 24)
		|  ((uint32_t) u[1] << 16)
		|  ((uint32_t) u[2] << 8)
		|  ((uint32_t) u[3]);
}

static int random_wait(int minms, int maxms) {
	return minms + (rand() % (maxms - minms));
}

static int compare_publish(const struct heap_node *a, const struct heap_node *b) {
	struct emdns_publish *ap = container_of(a, struct emdns_publish, hn);
	struct emdns_publish *bp = container_of(b, struct emdns_publish, hn);
	return ap->next_announce < bp->next_announce;
}

static int compare_request(const struct heap_node *a, const struct heap_node *b) {
	struct emdns_request *ap = container_of(a, struct emdns_request, hn);
	struct emdns_request *bp = container_of(b, struct emdns_request, hn);
	return ap->next_request < bp->next_request;
}

static struct emdns_answer *new_answer(struct emdns *m) {
	if (m->free_answer) {
		struct emdns_answer *a = m->free_answer;
		m->free_answer = a->next;
		a->next = NULL;
		return a;
	}

	if (m->answers_used < EMDNS_MAX_ANSWERS) {
		return &m->answerv[m->answers_used++];
	}

	return NULL;
}

#if 0
static void free_answer(struct emdns *m, struct emdns_answer *a) {
	assert(a->subrequest == NULL);
	a->next = m->free_answer;
	m->free_answer = a;
}
#endif

static struct emdns_request *new_request(struct emdns *m) {
	if (m->free_request) {
		struct emdns_request *r = m->free_request;
		m->free_request = r->next;
		r->next = NULL;
		return r;
	}

	if (m->requests_used < EMDNS_MAX_REQUESTS) {
		return &m->requestv[m->requests_used++];
	}

	return NULL;
}

static void free_request(struct emdns *m, struct emdns_request *r) {
	assert(r->answers == NULL);
	r->next = m->free_request;
	m->free_request = r;
	if (r->type) {
		heap_remove(&m->request_heap, &r->hn, &compare_request);
		r->type = 0;
	}
}

static struct emdns_publish *new_publish(struct emdns *m) {
	if (m->free_publish) {
		struct emdns_publish *r = m->free_publish;
		m->free_publish = r->next;
		r->next = NULL;
		return r;
	}

	if (m->publish_used < EMDNS_MAX_PUBLISH) {
		return &m->publishv[m->publish_used++];
	}

	return NULL;
}

static void free_publish(struct emdns *m, struct emdns_publish *r) {
	r->next = m->free_publish;
	m->free_publish = r;
	heap_remove(&m->publish_heap, &r->hn, &compare_publish);
}

// copies a dot separated string into dns form
// returns length of new list or -ve on error
// buf must be 256 bytes long
static int encode_dns_name(uint8_t *buf, const char *src) {
	int total = 0;

	for (;;) {
		const char *dot = strchr(src, '.');
		if (!dot) {
			dot = src + strlen(src);
		}
		if (dot == src) {
			break;
		}
		size_t len = dot - src;
		if (len > 63) {
			return -1;
		}

		total += 1 + (int) len;
		// check against 255 so we always have room for the trailing root
		if (total > 255) {
			return -1;
		}

		buf[0] = (uint8_t) len;
		memcpy(buf + 1, src, len);

		buf += 1 + len;
		src += len;

		if (*src == '.') {
			src++;
		}
	}

	// add the trailing root
	*(buf++) = 0;
	total++;

	return total;
}

#define MAX_LABEL_REDIRECTS 5

// decodes a dns name from an incoming message, decompressing as we go
// buf must be 256 bytes long
// poff points to the current offset into the message
// it is updated to the offset of the next field after the name
static int decode_dns_name(uint8_t *buf, const void *msg, int sz, uint16_t *poff) {
	int redirects = 0;
	int w = 0;
	uint16_t off = *poff;
	uint8_t *u = (uint8_t*) msg;

	for (;;) {
		if (off >= sz) {
			return -1;
		}

		uint8_t labelsz = u[off++];

		switch (labelsz & LABEL_MASK) {
		case LABEL_PTR:
			if (off == sz || ++redirects >= MAX_LABEL_REDIRECTS) {
				return -1;
			}
			if (poff) {
				*poff = off+1;
				poff = NULL;
			}
			off = (uint16_t) ((labelsz &~LABEL_MASK) << 8) | (uint16_t) u[off];
			break;
		case LABEL_NORMAL:
			if (labelsz == 0) {
				buf[w++] = 0;
				if (poff) {
					*poff = off;
				}
				return w;
			}

			off--;
			if (off + 1 + labelsz > sz || w + 1 + labelsz > 255) {
				return -1;
			}

			memcpy(buf + w, u + off, 1 + labelsz);
			off += 1+ labelsz;
			w += 1 + labelsz;

			if (poff) {
				*poff = off;
			}
			break;
		default:
			return -1;
		}
	}
}

static int compare_dns_name(const uint8_t *a, const uint8_t *b) {
	for (;;) {
		uint8_t alen = *(a++);
		uint8_t blen = *(b++);
		if (alen != blen) {
			return alen - blen;
		}
		if (!alen) {
			return 0;
		}
		int diff = strncasecmp((char*) a, (char*) b, alen);
		if (diff) {
			return diff;
		}
		a += alen;
		b += blen;
	}
}

static int encode_txt(uint8_t *buf, const char *txt) {
	int off = 0;
	for (;;) {
		size_t keysz = strlen(txt);
		if (!keysz) {
			return off;
		}

		if (off + 1 + keysz > EMDNS_MAX_TXT_SIZE || keysz > 256) {
			return -1;
		}

		buf[off] = (uint8_t) keysz;
		memcpy(buf+off+1, txt, keysz);

		off += 1 + keysz;
		txt += keysz + 1;
	}
}

static int decode_txt(uint8_t *buf, const uint8_t *txt, size_t len) {
	int off = 0;
	const uint8_t *end = txt + len;
	while (txt < end) {
		uint8_t keysz = *txt;
		if (!keysz) {
			break;
		}
		if (off + keysz + 1 + 1 > EMDNS_MAX_TXT_SIZE || txt + 1 + keysz > end) {
			return -1;
		}

		memcpy(buf+off, txt + 1, keysz);
		buf[off+keysz] = '\0';

		off += keysz + 1;
		txt += 1 + keysz;
	}

	buf[off] = '\0';
	return off;
}

int emdns_set_host(struct emdns *m, const char *name) {
	int sz = encode_dns_name(m->host, name);
	if (sz < 0) {
		return EMDNS_MALFORMED;
	}
	m->hostsz = sz;
	return 0;
}

int emdns_publish_ip6(struct emdns *m, emdns_time now, const struct in6_addr *addr) {
	struct emdns_publish *p = new_publish(m);
	if (!p) {
		return EMDNS_TOO_MANY;
	}
	p->next = m->publish_ips;
	m->publish_ips = p;

	p->next_announce = now + random_wait(1, 250);
	p->last_publish = 0;
	p->wait_duration = 1000;
	p->type = EMDNS_PUBLISH_AAAA;
	memcpy(&p->data.ip6, addr, sizeof(*addr));

	heap_insert(&m->publish_heap, &p->hn, &compare_publish);

	return (int) (p - m->publishv);
}

int emdns_publish_service(struct emdns *m, emdns_time now, const char *svc, const char *txt, uint16_t port) {
	struct emdns_publish *p = new_publish(m);
	if (!p) {
		return EMDNS_TOO_MANY;
	}

	int txtsz = encode_txt(p->data.svc.txt, txt);
	if (txtsz < 0) {
		return EMDNS_MALFORMED;
	}

	int namesz = encode_dns_name(p->data.svc.name, svc);
	if (namesz <= 0) {
		free_publish(m, p);
		return EMDNS_MALFORMED;
	}

	p->next_announce = now + random_wait(1, 250);
	p->last_publish = 0;
	p->wait_duration = 1000;
	p->type = EMDNS_PUBLISH_SERVICE;
	p->data.svc.port = port;
	p->data.svc.namesz = namesz;
	p->data.svc.txtsz = txtsz;

	heap_insert(&m->publish_heap, &p->hn, &compare_publish);

	return (int) (p - m->publishv);
}

static int encode_service(struct emdns *m, struct emdns_publish *r, uint8_t *u, int *poff, int sz) {
	// SRV
	int reqsz = r->data.svc.namesz + 2 /*type*/ + 2 /*class*/ + 4 /*ttl*/ + 2 /*datasz*/ + 2 /*pri*/ + 2 /*weight*/ + 2 /*port*/ + m->hostsz;
	// TXT
	reqsz += 2 /*name*/ + 2 /*type*/ + 2 /*class*/ + 4 /*ttl*/ + 2 /*datasz*/ + r->data.svc.txtsz;
	// PTR
	reqsz += 2 /*name*/ + 2 /*type*/ + 2 /*class*/ + 4 /*ttl*/ + 2 /*datasz*/ + 2 /*srv name*/;

	if (*poff + reqsz > sz) {
		return -1;
	}

	// SRV
	uint8_t *p = u + *poff;
	uint16_t nameoff = (uint16_t) *poff;
	uint16_t svcoff = nameoff + r->data.svc.name[0] + 1;
	memcpy(p, r->data.svc.name, r->data.svc.namesz);
	p += r->data.svc.namesz;
	put_big_16(p, RTYPE_SRV);
	put_big_16(p + 2, RCLASS_IN_FLUSH);
	put_big_32(p + 4, TTL_DEFAULT);
	put_big_16(p + 8, 2 + 2 + 2 + m->hostsz);
	put_big_16(p + 10, PRIORITY_DEFAULT);
	put_big_16(p + 12, WEIGHT_DEFAULT);
	put_big_16(p + 14, r->data.svc.port);
	p += 16;
	memcpy(p, m->host, m->hostsz);
	p += m->hostsz;

	// TXT
	put_big_16(p, LABEL_PTR16 | nameoff);
	put_big_16(p + 2, RTYPE_TXT);
	put_big_16(p + 4, RCLASS_IN_FLUSH);
	put_big_32(p + 6, TTL_DEFAULT);
	put_big_16(p + 10, r->data.svc.txtsz);
	p += 12;
	memcpy(p, r->data.svc.txt, r->data.svc.txtsz);
	p += r->data.svc.txtsz;

	// PTR
	put_big_16(p, LABEL_PTR16 | svcoff);
	put_big_16(p + 2, RTYPE_PTR);
	put_big_16(p + 4, RCLASS_IN);
	put_big_32(p + 6, TTL_DEFAULT);
	put_big_16(p + 10, 2); /*datasz*/
	put_big_16(p + 12, LABEL_PTR16 | nameoff);
	p += 14;

	*poff += reqsz;
	assert(u + *poff == p);
	return 0;
}

static int encode_ip6(struct emdns *m, struct emdns_publish *r, uint8_t *u, int *poff, int sz) {
	int reqsz = m->hostsz + 2 /*type*/ + 2 /*class*/ + 4 /*ttl*/ + 2 /*datasz*/ + 16 /*ip*/;

	if (*poff + reqsz > sz) {
		return -1;
	}

	uint8_t *p = u + *poff;
	memcpy(p, m->host, m->hostsz);
	p += m->hostsz;
	put_big_16(p, RTYPE_AAAA);
	put_big_16(p + 2, RCLASS_IN_FLUSH);
	put_big_32(p + 4, TTL_DEFAULT);
	put_big_16(p + 8, 16); // datasz
	p += 10;
	memcpy(p, &r->data.ip6, sizeof(r->data.ip6));
	p += sizeof(r->data.ip6);

	*poff = (int) (p - u);
	return 0;
}

static void update_publish_time(struct emdns *m, struct emdns_publish *r, emdns_time now) {
	heap_remove(&m->publish_heap, &r->hn, &compare_publish);
	r->last_publish = now;
	if (r->wait_duration < 8000) {
		r->next_announce = now + r->wait_duration;
		r->wait_duration *= 2;
	} else {
		r->next_announce = INT64_MAX;
	}
	heap_insert(&m->publish_heap, &r->hn, &compare_publish);
}

static void update_request_time(struct emdns *m, struct emdns_request *r, emdns_time now) {
	heap_remove(&m->request_heap, &r->hn, &compare_request);
	r->next_request = now + r->wait_duration;
	if (r->wait_duration < 60 * 60 * 1000) {
		r->wait_duration *= 2;
	}
	heap_insert(&m->request_heap, &r->hn, &compare_request);
}

int emdns_next(struct emdns *m, emdns_time *time, void *buf, int sz) {
	assert(sz >= MIN_MESSAGE_SIZE);
	uint8_t *u = (uint8_t*) buf;
	uint16_t num_publish = 0;
	bool do_publish = false;
	emdns_time next_publish = INT64_MAX;
	emdns_time next_request = INT64_MAX;

	int off = 12;

	for (;;) {
		struct heap_node *hn = heap_min(&m->publish_heap);
		if (!hn) {
			break;
		}

		struct emdns_publish *r = container_of(hn, struct emdns_publish, hn);
		if (r->next_announce > *time) {
			next_publish = r->next_announce;
			break;
		}

		if (r->type == EMDNS_PUBLISH_SERVICE) {
			if (encode_service(m, r, u, &off, sz)) {
				break;
			}
			num_publish++;
		}

		update_publish_time(m, r, *time);
		do_publish = true;
	}

	assert(off <= sz);

	if (do_publish) {
		for (struct emdns_publish *r = m->publish_ips; r != NULL; r = r->next) {
			if (encode_ip6(m, r, u, &off, sz)) {
				break;
			}
			if (r->last_publish != *time) {
				update_publish_time(m, r, *time);
			}
			num_publish++;
		}

		put_big_16(u, 0); // transaction ID
		put_big_16(u + 2, FLAG_RESPONSE | FLAG_AUTHORITY); // flags
		put_big_16(u + 4, 0); // questions
		put_big_16(u + 6, num_publish); // answers
		put_big_16(u + 8, 0); // authority
		put_big_16(u + 10, 0); // additional

		return off;
	}

	struct emdns_request *scan_list = NULL;
	uint16_t num_questions = 0;

	for (;;) {
		struct heap_node *hn = heap_min(&m->request_heap);
		if (!hn) {
			break;
		}

		struct emdns_request *r = container_of(hn, struct emdns_request, hn);
		if (r->next_request > *time) {
			next_request = r->next_request;
			break;
		}

		int reqsz = r->namesz + 4;
		if (r->type == EMDNS_QUERY_TXT_SRV) {
			reqsz += 6;
		}

		if (off + reqsz > sz) {
			// too many questions. we'll ask more in the next message
			break;
		}

		r->requestoff = off;
		uint8_t *p = u + off;
		memcpy(p, r->name, r->namesz);
		p += r->namesz;

		switch (r->type) {
		case EMDNS_QUERY_AAAA:
			put_big_16(p, RTYPE_AAAA);
			put_big_16(p + 2, RCLASS_IN);
			p += 4;
			break;
		case EMDNS_QUERY_TXT_SRV:
			// this is actually two questions using the same name
			num_questions++;
			put_big_16(p, RTYPE_TXT);
			put_big_16(p + 2, RCLASS_IN);
			put_big_16(p + 4, LABEL_PTR16 | off);
			put_big_16(p + 6, RTYPE_SRV);
			put_big_16(p + 8, RCLASS_IN);
			p += 10;
			break;
		case EMDNS_SCAN_PTR:
			put_big_16(p, RTYPE_PTR);
			put_big_16(p + 2, RCLASS_IN);
			p += 4;
			r->next = scan_list;
			scan_list = r;
			break;
		case EMDNS_NO_REQUEST:
			assert(0);
			break;
		}

		off += reqsz;
		assert((int) (p - u) == off);
		update_request_time(m, r, *time);
		num_questions++;
	}

	uint16_t num_answer = 0;

	// now add known answers for PTR scans
	for (struct emdns_request *r = scan_list; r != NULL; r = r->next) {
		for (struct emdns_answer *a = r->answers; a != NULL; a = a->next) {
			// PTR
			int reqsz = 13 + a->labelsz + 2;
			if (off + reqsz > sz) {
				// TODO set truncation bit
				break;
			}

			uint8_t *p = u + off;
			put_big_16(p, LABEL_PTR16 | r->requestoff);
			put_big_16(p + 2, RTYPE_PTR);
			put_big_16(p + 4, RCLASS_IN);
			put_big_32(p + 6, (uint32_t) ((a->expiry - *time) / 1000));
			put_big_16(p + 10, 1 + a->labelsz + 2); /*datasz*/
			p[12] = a->labelsz;
			p += 13;
			memcpy(p, a->label, a->labelsz);
			p += a->labelsz;
			put_big_16(p, LABEL_PTR16 | r->requestoff);
			p += 2;
			off += reqsz;
			assert((int) (p - u) == off);
			num_answer++;
		}
	}

	assert(off <= sz);

	if (num_questions) {
		put_big_16(u, 0); // transaction ID
		put_big_16(u+2, 0); // flags
		put_big_16(u+4, num_questions);
		put_big_16(u+6, num_answer); // answers
		put_big_16(u+8, 0); // authority
		put_big_16(u+10, 0); // additional

		return off;
	}

	*time = next_request < next_publish ? next_request : next_publish;
	return EMDNS_PENDING;
}

static void reschedule_publish(struct emdns *m, struct emdns_publish *r, emdns_time time) {
	heap_remove(&m->publish_heap, &r->hn, &compare_publish);
	r->next_announce = time;
	heap_insert(&m->publish_heap, &r->hn, &compare_publish);
}

static struct emdns_answer *find_answer(struct emdns_request *r, const char *label, uint8_t labelsz) {
	for (struct emdns_answer *a = r->answers; a != NULL; a = a->next) {
		if (a->labelsz == labelsz && !strncasecmp(a->label, label, labelsz)) {
			return a;
		}
	}
	return NULL;
}

static struct emdns_answer *create_answer(struct emdns *m, struct emdns_request *r, const char *label, uint8_t labelsz) {
	struct emdns_answer *a = find_answer(r, label, labelsz);
	if (a) {
		return a;
	}

	a = new_answer(m);
	if (!a) {
		return NULL;
	}

	a->subrequest = NULL;
	a->owner = r;
	a->have_txt = 0;
	a->have_srv = 0;
	a->have_aaaa = 0;
	a->hostsz = 0;
	a->txtsz = 0;
	a->labelsz = labelsz;
	memcpy(a->label, label, labelsz);
	a->label[labelsz] = '\0';

	a->next = r->answers;
	r->answers = a;

	return a;
}

static void publish_answer(struct emdns_answer *a) {
	if (a->have_txt && a->have_srv && a->have_aaaa) {
		a->owner->callbacks.service(a->owner->udata, (char*) a->label, &a->sa, (char*) a->txt);
	}
}

int emdns_process(struct emdns *m, emdns_time now, const void *msg, int sz) {
	if (sz < 12) {
		return EMDNS_MALFORMED;
	}
	uint8_t *u = (uint8_t*) msg;
	uint16_t flags = big_16(u+2);
	uint16_t question_num = big_16(u+4);
	uint16_t answer_num = big_16(u+6);
	uint16_t auth_num = big_16(u+8);
	uint16_t additional_num = big_16(u+10);
	uint16_t off = 12;

	// process answers and additionals in the same loop
	answer_num += additional_num;
	if (auth_num) {
		return EMDNS_MALFORMED;
	}

	// use the send time for any responses from this incoming message
	// that way they all go out in the same response
	emdns_time sendtime = now + random_wait(20, 120);

	while (question_num--) {
		uint8_t name[256];
		int namesz = decode_dns_name(name, u, sz, &off);
		if (namesz < 0 || off + 4 > sz) {
			return EMDNS_MALFORMED;
		}

		uint16_t rtype = big_16(u+off);
		uint16_t rclass = big_16(u+off+2);
		off += 4;

		// per the rfc only questions in request messages should be processed
		if ((flags & FLAG_RESPONSE) != 0 && rclass != RCLASS_IN) {
			continue;
		}

		switch (rtype) {
		case RTYPE_AAAA:
			if (m->hostsz != namesz || compare_dns_name(name, m->host)) {
				continue;
			}

			// see if any of the AAAA records need to go out
			// note that we always send all if we send any, so just need to find the first one
			for (struct emdns_publish *r = m->publish_ips; r != NULL; r = r->next) {
				if (now - r->last_publish >= 1000) {
					reschedule_publish(m, r, sendtime);
					break;
				}
			}
			break;

		case RTYPE_SRV:
		case RTYPE_TXT:
			for (int i = 0; i < m->publish_used; i++) {
				struct emdns_publish *r = &m->publishv[i];
				if (r->type == EMDNS_PUBLISH_SERVICE
					&& now - r->last_publish > 1000
					&& off + r->data.svc.namesz <= sz
					&& !memcmp(u + off, r->data.svc.name, r->data.svc.namesz)) {
					reschedule_publish(m, r, sendtime);
				}
			}
			break;
		case RTYPE_PTR:
			for (int i = 0; i < m->publish_used; i++) {
				struct emdns_publish *r = &m->publishv[i];
				int svcoff = r->data.svc.name[0] + 1;
				int svcsz = r->data.svc.namesz - svcoff;
				uint8_t *svc = r->data.svc.name + svcoff;

				if (r->type == EMDNS_PUBLISH_SERVICE
					&& now - r->last_publish > 1000
					&& off + svcsz <= sz
					&& !memcmp(u + off, svc, svcsz)) {
					reschedule_publish(m, r, sendtime);
				}
			}
			break;
		}
	}

	while (answer_num--) {
		uint8_t name[256];
		int namesz = decode_dns_name(name, u, sz, &off);
		if (namesz < 0 || off + 10 > sz) {
			return EMDNS_MALFORMED;
		}

		uint16_t rtype = big_16(u+off);
		uint16_t rclass = big_16(u+off+2);
		uint32_t ttl = big_32(u+off+4);
		uint16_t datasz = big_16(u+off+8);
		uint8_t *data = u + off + 10;
		uint16_t dataoff = off + 10;
		off += 10 + datasz;

		if (off > sz) {
			return EMDNS_MALFORMED;
		}

		if (rclass != RCLASS_IN && rclass != RCLASS_IN_FLUSH) {
			continue;
		}

		if ((flags & FLAG_RESPONSE) == 0 && rtype == RTYPE_PTR) {
			// we have a known address field
			// check to see if it's ours and remove the publish
			// TODO
		}


		if (flags & FLAG_RESPONSE) {
			switch (rtype) {
			case RTYPE_PTR:
			{
				uint8_t svchost[256];
				int svchsz = decode_dns_name(svchost, msg, sz, &dataoff);
				uint8_t labelsz = svchost[0];

				if (svchsz < 0 || dataoff != off || labelsz + 1 >= svchsz) {
					break;
				}

				for (int id = 0; id < m->requests_used; id++) {
					struct emdns_request *r = &m->requestv[id];
					if (r->type != EMDNS_SCAN_PTR
						|| namesz != r->namesz
						|| compare_dns_name(name, r->name)) {
						continue;
					}

					struct emdns_answer *a = create_answer(m, r, (char*) svchost + 1, labelsz);
					if (!a) {
						break;
					}

					a->expiry = now + ((emdns_time) ttl * 1000);
					break;
				}
			}
			break;
			case RTYPE_TXT:
			case RTYPE_SRV:
			{
				uint8_t labelsz = name[0];
				if (labelsz + 1 >= namesz) {
					break;
				}

				uint8_t *svc = name + 1 + labelsz;
				int svcsz = namesz - labelsz - 1;

				for (int id = 0; id < m->requests_used; id++) {
					struct emdns_request *r = &m->requestv[id];
					if (r->type != EMDNS_SCAN_PTR
						|| svcsz != r->namesz
						|| compare_dns_name(svc, r->name)) {
						continue;
					}

					struct emdns_answer *a = find_answer(r, (char*) name + 1, labelsz);
					if (!a) {
						break;
					}

					if (rtype == RTYPE_TXT) {
						int txtsz = decode_txt(a->txt, data, datasz);
						if (txtsz != datasz) {
							break;
						}

						a->txtsz = (uint16_t) txtsz;
						a->have_txt = 1;
					} else {
						// srv
						if (datasz < 7) {
							break;
						}

						uint16_t priority = big_16(data);
						uint16_t weight = big_16(data + 2);
						uint16_t port = big_16(data + 4);

						dataoff += 6;
						int hostsz = decode_dns_name(a->host, msg, sz, &dataoff);
						if (hostsz < 0 || dataoff != off) {
							break;
						}

						a->hostsz = (uint8_t) hostsz;
						a->sa.sin6_port = htons(port);
						a->have_srv = 1;

						(void) priority;
						(void) weight;
					}

					publish_answer(a);
					break;
				}
			}
			break;
			case RTYPE_AAAA:
				if (datasz != 16) {
					break;
				}

				for (int id = 0; id < m->answers_used; id++) {
					struct emdns_answer *a = &m->answerv[id];
					if (!a->have_srv || a->hostsz != namesz || compare_dns_name(a->host, name)) {
						continue;
					}

					memcpy(&a->sa.sin6_addr, data, 16);
					a->have_aaaa = 1;
					publish_answer(a);
				}

				for (int id = 0; id < m->requests_used; id++) {
					struct emdns_request *r = &m->requestv[id];
					if (r->type == EMDNS_QUERY_AAAA
						&& r->namesz == namesz
						&& !compare_dns_name(r->name, name)) {
						r->callbacks.ip6(r->udata, (struct in6_addr*) data);
						free_request(m, r);
					}
				}
				break;
			}
		}
	}

	return 0;
}

int emdns_query_ip6(struct emdns *m, emdns_time now, const char *name, void *udata, emdns_ip6cb cb) {
	struct emdns_request *r = new_request(m);
	if (r == NULL) {
		return EMDNS_TOO_MANY;
	}

	int sz = encode_dns_name(r->name, name);
	if (sz < 0) {
		free_request(m, r);
		return EMDNS_MALFORMED;
	}

	r->type = EMDNS_QUERY_AAAA;
	r->callbacks.ip6 = cb;
	r->udata = udata;
	r->namesz = (uint8_t) sz;
	r->next_request = now;
	r->wait_duration = 1000;

	heap_insert(&m->request_heap, &r->hn, &compare_request);

	return (int) (r - m->requestv);
}

int emdns_scan_ip6(struct emdns *m, emdns_time now, const char *name, void *udata, emdns_svccb cb) {
	struct emdns_request *r = new_request(m);
	if (r == NULL) {
		return EMDNS_TOO_MANY;
	}

	int sz = encode_dns_name(r->name, name);
	if (sz < 0) {
		free_request(m, r);
		return EMDNS_MALFORMED;
	}

	assert(r->answers == NULL);

	r->type = EMDNS_SCAN_PTR;
	r->callbacks.service = cb;
	r->udata = udata;
	r->namesz = (uint8_t) sz;
	r->next_request = now;
	r->wait_duration = 1000;

	heap_insert(&m->request_heap, &r->hn, &compare_request);

	return (int) (r - m->requestv);
}

