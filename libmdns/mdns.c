#include "mdns.h"
#include <assert.h>
#include <string.h>

#ifndef container_of
#define container_of(ptr, type, member) ((type*) ((char*) (ptr) - offsetof(type, member)))
#endif

#define MIN_MESSAGE_SIZE 512
#define RCLASS_IN 1
#define RTYPE_AAAA 28
#define RTYPE_SRV 33
#define RTYPE_TXT 16
#define RTYPE_PTR 12
#define RTYPE_NSEC 47
#define LABEL_MASK 0xC0
#define LABEL_NORMAL 0x00
#define LABEL_PTR 0xC0
#define FLAG_RESPONSE 0x80

static void put_big_16(uint8_t *u, uint16_t v) {
	u[0] = (uint8_t) (v >> 8);
	u[1] = (uint8_t) v;
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

static void free_answer(struct emdns *m, struct emdns_answer *a) {
	assert(a->subrequest == NULL);
	a->next = m->free_answer;
	m->free_answer = a;
}

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
	assert(r->rtype);
	r->rtype = 0;
	r->next = m->free_publish;
	m->free_publish = r;
	heap_remove(&m->publish_heap, &r->hn, &compare_publish);
}

int emdns_next(struct emdns *m, emdns_time *time, void *buf, int sz) {
	assert(sz >= MIN_MESSAGE_SIZE);
	uint8_t *u = (uint8_t*) buf;
	put_big_16(u, 0); // transaction ID
	put_big_16(u+2, 0); // flags
	// will fill out questions later
	put_big_16(u+6, 0); // answers
	put_big_16(u+8, 0); // authority
	put_big_16(u+10, 0); // additional

	uint8_t *p = u + 12;
	uint16_t num_questions = 0;

	for (;;) {
		struct heap_node *hn = heap_min(&m->request_heap);
		struct emdns_request *r = container_of(hn, struct emdns_request, hn);
		if (r->next_request > *time) {
			*time = r->next_request;
			break;
		}

		int reqsz = r->namesz + 4;
		if (r->type == EMDNS_QUERY_TXT_SRV) {
			reqsz += 6;
		}

		if (p + reqsz > u + sz) {
			// too many questions. we'll ask more in the next message
			break;
		}

		r->next_request = *time + r->duration;
		if (r->duration < 60 * 60 * 1000) {
			// cap the exponential increase at an hour per the rfc
			r->duration *= 2;
		}

		r->nameoff = (uint16_t) (p - u);
		num_questions++;
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
			put_big_16(p + 4, COMPRESSED_NAME_FLAG | r->nameoff);
			put_big_16(p + 6, RTYPE_SRV);
			put_big_16(p + 8, RCLASS_IN);
			p += 10;
			break;
		case EMDNS_SCAN_PTR:
			put_big_16(p, RTYPE_PTR);
			put_big_16(p + 2, RCLASS_IN);
			p += 4;
			break;
		}
	}

	put_big_16(u + 4, num_questions);
	assert(p - u <= sz);
	if (num_questions) {
		return (int) (p - u);
	}

	return EMDNS_PENDING;
}

#define MAX_LABEL_REDIRECTS 5

// buf must be 256 bytes long to allow for the trailing 0 length label
static int decode_dns_name(uint8_t *buf, const uint8_t* *msg, int sz, int *poff) {
	int redirects = 0;
	int w = 0;
	int off = *poff;

	for (;;) {
		if (off >= sz) {
			return -1;
		}
		
		int type = msg[off] & LABEL_MASK;

		switch (type) {
		case LABEL_PTR: {
				if (off + 3 > sz || ++redirects >= MAX_LABEL_REDIRECTS) {
					return -1;
				}
				off = (int) big_16(off+1);
				redirects++;
				if (poff) {
					*poff += 3;
					poff = NULL;
				}
			}
			break;
		case LABEL_NORMAL: {
				int labelsz = msg[off];

				if (labelsz == 0) {
					buf[w++] = 0;
					if (poff) {
						(*poff)++;
					}
					return w;
				}

				if (off + 1 + labelsz > sz || w + 1 + labelsz > 255) {
					return -1;
				}

				memcpy(buf+w, msg+off, 1+labelsz);
				off += 1 + labelsz;
				w += 1 + labelsz;

				if (poff) {
					*poff = off;
				}
			}
			break;
		default:
			return -1;
		}
	}
}

int emdns_process(struct emdns *m, emdns_time time, const void *msg, int sz) {
	if (sz < 12) {
		return EMDNS_MALFORMED;
	}
	uint8_t *u = (uint8_t*) msg;
	uint16_t flags = big_16(u+2);
	uint16_t question_num = big_16(u+4);
	uint16_t answer_num = big_16(u+6);
	uint16_t auth_num = big_16(u+8);
	uint16_t additional_num = big_16(u+10);
	int off = 12;

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
		if ((flags & FLAG_RESPONSE) == 0 && rclass == RCLASS_IN && rtype) {
			for (int i = 0; i < m->publish_used; i++) {
				struct mdns_publish *p = &m->publishv[i];
				// p->rtype == 0 for a no longer used publish
				// we've already checked that rtype != 0 above
				// per the mdns rfc don't publish more than once a second
				if (p->rtype == rtype && time - p->last_publish > 1000) {
					heap_remove(&m->publish_heap, &p->hn, &compare_publish);
					m->next_announce = time;
					heap_insert(&m->publish_heap, &p->hn, &compare_publish);
				}
			}
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
		off += 10;

		if (off + datasz > sz) {
			return EMDNS_MALFORMED;
		}

		if ((flags & FLAG_RESPONSE) == 0) && rclass == RCLASS_IN && rtype == RTYPE_PTR) {
			// we have a known address field
			// check to see if it's ours and remove the publish
		}
	}
}

// copies a dot separated string into dns form
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

		total += 1 + (int) len;
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

#if 0
int emdns_scan(struct mdns *m, mdns_time time, enum mdns_rtype type, const char *name, void *udata, mdns_cb add, mdns_cb remove) {
	int id;
	for (id = 0; id < EMDNS_MAX_REQUESTS; id++) {
		if (!m->requestv[id].valid) {
			break;
		}
	}

	if (id == EMDNS_MAX_REQUESTS) {
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
#endif

int emdns_query_aaaa(struct emdns *m, const char *name, void *udata, emdns_addcb cb) {
	struct emdns_request *r = new_request(m);
	if (r == NULL) {
		return EMDNS_TOO_MANY;
	}

	int sz = copy_to_dns_name(r->name, name);
	if (sz < 0) {
		free_request(m, r);
		return EMDNS_MALFORMED;
	}

	r->type = EMDNS_QUERY_AAAA;
	r->add = cb;
	r->remove = NULL;
	r->udata = udata;
	r->namesz = sz;
	r->next_request = 0; // forces an immediate send
	r->duration = 1000;

	heap_insert(&m->request_heap, &r->hn, &compare_request);

	return (int) (r - m->requestv);
}

