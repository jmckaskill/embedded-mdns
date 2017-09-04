#include "emdns-impl.h"
#include <assert.h>

#ifdef _WIN32
// for ntohs
#pragma comment(lib, "ws2_32.lib")
#endif

/////////////////////////////////
// HELPERS
/////////////////////////////////

static struct timeout *min_timeout(struct timeout *a, struct timeout *b, struct timeout *c) {
    if (a->next < b->next) {
        return c->next < a->next ? c : a;
    } else {
        return c->next < b->next ? c : b;
    }
}

static inline void put_big_16(uint8_t *u, uint16_t v) {
	u[0] = (uint8_t) (v >> 8);
	u[1] = (uint8_t) v;
}

static inline void put_big_32(uint8_t *u, uint32_t v) {
	u[0] = (uint8_t) (v >> 24);
	u[1] = (uint8_t) (v >> 16);
	u[2] = (uint8_t) (v >> 8);
	u[3] = (uint8_t) (v);
}

static inline uint16_t big_16(const uint8_t *u) {
	return ((uint16_t) u[0] << 8) | ((uint16_t) u[1]);
}

static inline uint32_t big_32(const uint8_t *u) {
	return ((uint32_t) u[0] << 24)
		|  ((uint32_t) u[1] << 16)
		|  ((uint32_t) u[2] << 8)
		|  ((uint32_t) u[3]);
}

static int get_ttl(const uint8_t *u) {
    uint32_t ret = big_32(u);
    if (ret > MAX_TTL) {
        return MAX_TTL;
    }
    return (int) ret;
}

static int random_wait(int minms, int maxms) {
	return minms + (rand() % (maxms - minms));
}

static int compare_publish(const struct heap_node *a, const struct heap_node *b) {
	struct publish *ap = container_of(a, struct publish, hn);
	struct publish *bp = container_of(b, struct publish, hn);
	return ap->next_publish < bp->next_publish;
}

static int compare_record(const struct heap_node *a, const struct heap_node *b) {
	struct record *ac = container_of(a, struct record, hn);
	struct record *bc = container_of(b, struct record, hn);
	return ac->t.next < bc->t.next;
}

static void hash_key(struct key *r) {
    uint32_t h = 0;
    uint8_t *s = r->name;
	for (;;) {
        uint32_t len = *(s++);
        h = (h << 5) - h + len;
        if (!len) {
            break;
        }
		for (uint32_t i = 0; i < len; i++) {
            uint32_t ch = *(s++);
            if ('a' <= ch && ch <= 'z') {
                ch -= 'a' - 'A';
            }
			h = (h << 5) - h + ch;
		}
    }
    r->hash = h;
}

static bool equals_dns_name(const uint8_t *a, const uint8_t *b) {
    for (;;) {
		uint8_t alen = *(a++);
		uint8_t blen = *(b++);
		if (alen != blen) {
			return false;
		}
		if (!alen) {
			return true;
		}
		if (strncasecmp((char*) a, (char*) b, alen)) {
			return false;
		}
		a += alen;
		b += blen;
	}
}

static bool key_equal(const struct key *a, const struct key *b) {
    return a->hash == b->hash 
        && a->namesz == b->namesz
        && equals_dns_name(a->name, b->name);
}

static uint32_t key_hash(const struct key *a) {
    return a->hash;
}

__KHASH_IMPL(cache, static klib_unused, const struct key*, struct record*, 1, key_hash, key_equal)


////////////////
// DATA DECODERS
////////////////

// copies a dot separated string into dns form
// returns -ve on error
// returns length on success
static int encode_dns_name(uint8_t *buf, const char *src) {
    int w = 0;

	for (;;) {
		const char *dot = strchr(src, '.');
		if (!dot) {
			dot = src + strlen(src);
		}
		if (dot == src) {
			break;
		}
		size_t len = dot - src;
		if (len > MAX_LABEL_SIZE) {
			return -1;
		}

		if (w + 1 + (int) len > MAX_HOST_SIZE) {
			return -1;
		}

        buf[w++] = (uint8_t) len;

		memcpy(buf + w, src, len);
        w += len;
        src += len;
		
		if (*src == '.') {
			src++;
		}
	}

    // add the trailing root
    buf[w++] = 0;
	return w;
}

#define MAX_LABEL_REDIRECTS 5

// decodes a dns name from an incoming message, decompressing as we go
// poff points to the current offset into the message
// it is updated to the offset of the next field after the name
// returns -ve on error
// returns length on success
static int decode_dns_name(uint8_t *buf, const void *msg, int sz, int *poff) {
	int redirects = 0;
	int off = *poff;
    uint8_t *u = (uint8_t*) msg;
    
	int w = 0;

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
                goto end;
			}

			off--;
			if (off + 1 + labelsz > sz || w + 1 + labelsz + 1 > MAX_HOST_SIZE) {
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

end:
    if (poff) {
        *poff = off;
    }
    buf[w++] = 0;
    assert(w <= MAX_HOST_SIZE);

    return w;
}


////////////////////
// MEMORY MANAGEMENT
////////////////////

struct emdns *emdns_new(const char *hostname) {
    struct emdns *m = NEW(struct emdns);
    int hostsz = encode_dns_name(m->hostname.name, hostname);
    if (hostsz < 0) {
        emdns_mem_free(m);
        return NULL;
    }
    m->hostname.namesz = (uint8_t) hostsz;
    return m;
}

void emdns_free(struct emdns *m) {
    if (m) {
        // don't try and remove stuff from the heaps or tables
        // just find all the allocated memory and free it
        for (khint_t idx = kh_begin(&m->results); idx != kh_end(&m->results); idx++) {
            if (kh_exist(&m->results, idx)) {
                struct result *r = (struct result*) m->results.vals[idx];
                emdns_mem_free(r->txt);
                emdns_mem_free(r);
            }
        }
        for (khint_t idx = kh_begin(&m->scans); idx != kh_end(&m->scans); idx++) {
            if (kh_exist(&m->scans, idx)) {
                emdns_mem_free(m->scans.vals[idx]);
            }
        }
        for (khint_t idx = kh_begin(&m->addrs); idx != kh_end(&m->addrs); idx++) {
            if (kh_exist(&m->addrs, idx)) {
                emdns_mem_free(m->addrs.vals[idx]);
            }
        }
        for (int id = 0; id < MAX_IPS; id++) {
            emdns_mem_free(m->user_ips[id]);
        }
        for (int id = 0; id < MAX_SERVICES; id++) {
            if (m->user_services[id]) {
                emdns_mem_free(m->user_services[id]->txt);
                emdns_mem_free(m->user_services[id]);
            }
        }
        kh_destroy(cache, &m->results);
        kh_destroy(cache, &m->scans);
        kh_destroy(cache, &m->addrs);
        emdns_mem_free(m);
    }
}

static void remove_srv(struct emdns *m, struct result *r) {
    struct addr *a = r->srv;
    if (!a) {
        return;
    }
    if (r->srv_next) {
        r->srv_next->srv_prev = r->srv_prev;
    }
    if (r->srv_prev) {
        r->srv_prev->srv_next = r->srv_next;
    }
    if (a->results == r) {
        a->results = r->srv_next;
    }
    r->srv = NULL;
    r->have_addr = false;
    r->published = false;

    if (a->results || a->cb) {
        return;
    }

    // no one wants to watch this address anymore
    khint_t idx = kh_get(cache, &m->addrs, &a->h.key);
    assert(idx != kh_end(&m->addrs));
    kh_del(cache, &m->addrs, idx);

    heap_remove(&m->cache_heap, &a->h.hn, &compare_record);
    emdns_mem_free(a);
}

static void init_record(struct record *r, const struct key *k, enum record_type type) {
    r->type = type;
    r->key.hash = k->hash;
    r->key.namesz = k->namesz;
    memcpy(r->key.name, k->name, k->namesz);
}

static void delete_record(struct emdns *m, struct record *r, khash_t(cache) *h) {
    khint_t idx = kh_get(cache, h, &r->key);
    assert(idx != kh_end(h));
    kh_del(cache, h, idx);
    heap_remove(&m->cache_heap, &r->hn, &compare_record);
    emdns_mem_free(r);
}

static void publish_result(struct result *r) {
    bool all = r->have_srv && r->have_ptr && r->have_txt && r->have_addr;
    uint8_t labelsz = r->h.key.name[0];
    char *label = (char*) r->h.key.name + 1 + labelsz;

    if (r->published && !all) {
        r->scan->cb(r->scan->udata, label, labelsz, NULL, NULL, 0);
        r->published = false;
    }

    if (all && (!r->published || r->dirty)) {
        r->scan->cb(r->scan->udata, label, labelsz, &r->sa, r->txt, r->txtsz);
        r->published = true;
    }

    r->dirty = false;
}

static void expire_result(struct emdns *m, struct result *r) {
    remove_srv(m, r);

    if (r->scan) {
        r->have_srv = false;
        r->have_ptr = false;
        r->have_txt = false;
        r->dirty = true;
        publish_result(r);

        if (r->scan_next) {
            r->scan_next->scan_prev = r->scan_prev;
        }
        if (r->scan_prev) {
            r->scan_prev->scan_next = r->scan_next;
        }
        if (r->scan->results == r) {
            r->scan->results = r->scan_next;
        }
    }
    
    emdns_mem_free(r->txt);
    delete_record(m, &r->h, &m->results);
}

static void expire_addr(struct emdns *m, struct addr *a) {
    // give up on any results that are tied to this address
    for (struct result *r = a->results; r != NULL;) {
        assert(r->srv == a);
        // clear srv so expiring the result doesn't try and expire the address back again
        // no need to clear srv_next & srv_prev as expire_result will free the result
        struct result *rn = r->srv_next;
        r->srv = NULL;
        expire_result(m, r);
        r = rn;
    }

    if (a->userid) {
        a->cb(a->udata, NULL);
        m->user_addrs[a->userid - ID_ADDR] = NULL;
    }

    delete_record(m, &a->h, &m->addrs);
}

static void remove_scan(struct emdns *m, struct scan *s) {
    for (struct result *r = s->results; r != NULL;) {
        // unset scan so that expire_result doesn't modify the list or call the callback
        struct result *rn = r->scan_next;
        s->results->scan = NULL;
        expire_result(m, s->results);
        r = rn;
    }

    if (s->userid) {
        m->user_scans[s->userid - ID_ADDR] = NULL;
    }

    delete_record(m, &s->h, &m->scans);
}

int emdns_stop(struct emdns *m, int userid) {
    if (userid >= ID_LAST) {
        goto err;

    } else if (userid >= ID_SERVICE) {
        struct pub_service *p = m->user_services[userid - ID_SERVICE];
        if (!p) {
            goto err;
        }
        heap_remove(&m->publish_heap, &p->h.hn, &compare_publish);
        m->user_ips[userid - ID_IP] = NULL;
        emdns_mem_free(p->txt);
        emdns_mem_free(p);

    } else if (userid >= ID_IP) {
        struct pub_ip *p = m->user_ips[userid - ID_IP];
        if (!p) {
            goto err;
        }
        heap_remove(&m->publish_heap, &p->h.hn, &compare_publish);
        m->user_ips[userid - ID_IP] = NULL;
        emdns_mem_free(p);
    
    } else if (userid >= ID_SCAN) {
        struct scan *s = m->user_scans[userid - ID_SCAN];
        if (!s) {
            goto err;
        }
        remove_scan(m, s);

    } else if (userid >= ID_ADDR) {
        struct addr *a = m->user_addrs[userid - ID_ADDR];
        if (!a) {
            goto err;
        }
        a->userid = 0;
        expire_addr(m, a);
        m->user_addrs[userid - ID_ADDR] = NULL;

    } else {
        goto err;
    }

    return 0;
err:
    return EMDNS_MALFORMED;
}

/////////////////////
// TIMEOUT MANAGEMENT
/////////////////////

static void schedule_request(struct emdns *m, struct record *r, struct timeout time) {
    if (r->t.next) {
        heap_remove(&m->cache_heap, &r->hn, &compare_record);
    }
    r->t = time;
    heap_insert(&m->cache_heap, &r->hn, &compare_record);
}

static void increment_timeout(struct emdns *m, struct record *r, emdns_time now) {
    assert(r->t.next);
    heap_remove(&m->cache_heap, &r->hn, &compare_record);
    r->t.next = now + r->t.step;
    if (r->t.next > r->t.expiry) {
        r->t.next = r->t.expiry;
    }
    if (r->t.step < 60 * 3600 * 1000) {
        r->t.step *= 2;
    }
    heap_insert(&m->cache_heap, &r->hn, &compare_record);
}

static void reschedule_publish(struct emdns *m, struct publish *p, emdns_time time) {
    heap_remove(&m->publish_heap, &p->hn, &compare_publish);
    p->next_publish = time;
    heap_insert(&m->publish_heap, &p->hn, &compare_publish);
}

static void increment_publish_timeout(struct emdns *m, struct publish *p, emdns_time now) {
    heap_remove(&m->publish_heap, &p->hn, &compare_publish);
    p->next_publish = now + p->publish_wait;
    if (p->publish_wait > 8 * 1000) {
        p->next_publish = INT64_MAX;
    } else {
        p->publish_wait *= 2;
    }
    heap_insert(&m->publish_heap, &p->hn, &compare_publish);
}

////////////////
// USER REQUESTS
////////////////

static struct addr *create_addr(struct emdns *m, const struct key *k, emdns_time now) {
    int res;
    khint_t idx = kh_put(cache, &m->addrs, k, &res);
    if (res <= 0) {
        return NULL;
    }

    struct addr *a = NEW(struct addr);
    if (!a) {
        kh_del(cache, &m->addrs, idx);
        return NULL;
    }

    struct timeout time;
    time.next = now + random_wait(20, 120);
    time.expiry = now + 6000;
    time.step = 1000;

    init_record(&a->h, k, ADDR_RECORD);
    schedule_request(m, &a->h, time);

    return a;
}

int emdns_query_ip6(struct emdns *m, emdns_time now, const char *name, void *udata, emdns_ip6cb cb) {
    struct key k;
    int keysz = encode_dns_name(k.name, name);
    if (keysz < 0) {
        return EMDNS_MALFORMED;
    }
    
    k.namesz = (uint8_t) keysz;
    hash_key(&k);
    
    int id = 0;
    while (id < MAX_ADDRS && m->user_addrs[id]) {
        id++;
    }
    if (id == MAX_ADDRS) {
        return EMDNS_TOO_MANY;
    }

    struct addr *a;
    khint_t idx = kh_get(cache, &m->addrs, &k);
    if (idx != kh_end(&m->addrs)) {
        a = (struct addr*) m->addrs.vals[idx];
        if (a->cb) {
            return EMDNS_DUPLICATE;
        } else if (a->have_addr) {
            cb(udata, &a->addr);
            return EMDNS_FINISHED;
        }
    } else {
        a = create_addr(m, &k, now);
        if (!a) {
            return EMDNS_TOO_MANY;
        }
    }

    a->cb = cb;
    a->udata = udata;

    a->userid = id + ID_ADDR;
    m->user_addrs[id] = a;
    return a->userid;
}

int emdns_scan_ip6(struct emdns *m, emdns_time now, const char *name, void *udata, emdns_svccb cb) {
    struct key k;
    int keysz = encode_dns_name(k.name, name);
    if (keysz < 0) {
        EMDNS_MALFORMED;
    }

    k.namesz = (uint8_t) keysz;
    hash_key(&k);

    int id = 0;
    while (id < MAX_ADDRS && m->user_addrs[id]) {
        id++;
    }
    if (id == MAX_ADDRS) {
        return EMDNS_TOO_MANY;
    }

    int added;
    khint_t idx = kh_put(cache, &m->scans, &k, &added);
    if (added <= 0) {
        return EMDNS_DUPLICATE;
    }

    struct scan *s = NEW(struct scan);
    if (!s) {
        kh_del(cache, &m->scans, idx);
        return EMDNS_TOO_MANY;
    }

    struct timeout time;
    time.next = now;
    time.expiry = INT64_MAX;
    time.step = 1000;

    init_record(&s->h, &k, SCAN_RECORD);
    schedule_request(m, &s->h, time);
    
    s->cb = cb;
    s->udata = udata;
    m->scans.keys[idx] = &s->h.key;
    m->scans.vals[idx] = &s->h;

	s->userid = id + ID_SCAN;
    m->user_scans[id] = s;
    return s->userid;
}

static void init_publish(struct emdns *m, struct publish *p, emdns_time now, enum publish_type type) {
    p->next_publish = now;
    p->last_publish = now - 2000;
    p->publish_wait = 1000;
    p->type = type;
    heap_insert(&m->publish_heap, &p->hn, &compare_publish);
}

int emdns_publish_ip6(struct emdns *m, emdns_time now, const struct in6_addr *addr) {
    int id = 0;
    while (id < MAX_IPS && m->user_ips[id]) {
        id++;
    }
    if (id == MAX_IPS) {
        return EMDNS_TOO_MANY;
    }

    struct pub_ip *p = NEW(struct pub_ip);
    if (!p) {
        return EMDNS_TOO_MANY;
    }

    init_publish(m, &p->h, now, PUBLISH_AAAA);
    memcpy(&p->addr, addr, sizeof(*addr));

	m->user_ips[id] = p;
    return id + ID_IP;
}

///////////////////////////
// INCOMING DATA PROCESSING
///////////////////////////


static int process_srv(struct emdns *m, emdns_time now, struct result *r, struct key *pk, uint16_t port) {
    struct addr *a = r->srv;
    if (a && (a->h.key.namesz != pk->namesz || !equals_dns_name(a->h.key.name, pk->name))) {
        remove_srv(m, r);
    }

    if (!r->srv) {
        hash_key(pk);
        khint_t pidx = kh_get(cache, &m->addrs, pk);

        if (pidx != kh_end(&m->addrs)) {
            r->srv = (struct addr*) m->addrs.vals[pidx];
        } else {
            r->srv = create_addr(m, pk, now);
            if (!r->srv) {
                return -1;
            }
        }

        // add ourselves to the result
        r->srv_next = r->srv->results;
        r->srv->results = r;

        if (r->srv_next) {
            r->srv_next->srv_prev = r;
        }

        // we've changed address, the previous publish if any is invalid
        r->published = false;
        r->have_addr = r->srv->have_addr;
        memcpy(&r->sa.sin6_addr, &r->srv->addr, sizeof(r->srv->addr));
    }

    port = ntohs(port);
    if (!r->have_srv || r->sa.sin6_port != port) {
        r->published = false; // we've changed port
        r->sa.sin6_port = port;
    }

    r->have_srv = true;
    return 0;
}

static int process_result(struct emdns *m, emdns_time now, struct key *k, uint16_t rtype, const uint8_t *u, int sz, int off) {
    int ttl = get_ttl(u + off);
    uint16_t datasz = big_16(u + off + 4);
    int dataoff = off + 6;
    struct key k2, *sk;
    off = dataoff + datasz;

    if (off > sz) {
        return EMDNS_MALFORMED;
    }

    // lookup the scan first to see if we are interested in this record
    // most incoming records we won't be interested in, so do this first

    if (rtype == RTYPE_PTR) {
        sk = k;
    } else {
        uint8_t labelsz = k->name[0];
        k2.namesz = k->namesz - 1 - labelsz;
        memcpy(k2.name, k->name + 1 + labelsz, k2.namesz);
        sk = &k2;
    }
    
    hash_key(sk);
    khint_t sidx = kh_get(cache, &m->scans, sk);
    if (sidx == kh_end(&m->scans)) {
        // we're not interested in this record
        return off;
    }
    struct scan *s = (struct scan*) m->scans.vals[sidx];

    // now lookup the result to see if it's an update to an existing result
    // or a new result

    if (rtype == RTYPE_PTR) {
        // for pointers use the target name for the result lookup
        int tgtsz = decode_dns_name(k->name, u, sz, &dataoff);
        if (tgtsz < 0 || dataoff != off) {
            return EMDNS_MALFORMED;
        }
        k->namesz = (uint8_t) tgtsz;
    }

    hash_key(k);
    khint_t ridx = kh_get(cache, &m->results, k);
    struct result *r;
    bool added = false;

    // do we need to create the result?
    
    if (ridx != kh_end(&m->results)) {
        r = (struct result*) m->results.vals[ridx];
    } else {
        // result doesn't exist, try and create one
        r = NEW(struct result);
        if (r == NULL) {
            goto alloc_error;
        }
        
        // init result
        init_record(&r->h, k, RESULT_RECORD);
        r->sa.sin6_family = AF_INET6;
        
        // adding new records to the scan and table is delayed
        // until we've successfully decoded the new data
        // that way if we get an error during decode it's easier to clean up
        added = 1;
    }
    
    struct timeout time;

    if (ttl) {
        time.next = now + random_wait(0, 20 * ttl) + (800 * ttl); // 80% of ttl + 2% random
        time.step = 50 * ttl; // 5% of ttl
        time.expiry = now + (1000 * ttl);
    } else {
        // goaway
        time.next = now + 1000;
        time.expiry = now + 1000;
        time.step = 0;
    }
    
    // decode the data and add to the result

    switch (rtype) {
    case RTYPE_PTR:
        r->time_ptr = time;
        r->have_ptr = true;
        break;
    case RTYPE_TXT:
        if (!r->have_txt || r->txtsz != datasz || memcmp(r->txt, u+dataoff, datasz)) {
            // the text data has changed
            r->published = false;
            r->txt = emdns_mem_realloc(r->txt, datasz);
            if (!r->txt) {
                goto alloc_error;
            }
            memcpy(r->txt, u+dataoff, datasz);
            r->txtsz = datasz;
        }
        r->time_txt = time;
        r->have_txt = true;
        break;
    case RTYPE_SRV:
        if (datasz < 6) {
            goto data_error;
        } else {
            uint16_t port = big_16(u + dataoff + 4);
            dataoff += 6;

            struct key pk;
            int tgtsz = decode_dns_name(pk.name, u, sz, &dataoff);
            if (tgtsz < 0 || dataoff != off) {
                goto data_error;
            }
            pk.namesz = (uint8_t) tgtsz;

            if (process_srv(m, now, r, &pk, port)) {
                goto alloc_error;
            }
        }
        break;
    }

    // we have successfully decoded the incoming data and allocated
    // any subresources. Let's hook things up
    
    if (added) {
        int res;
        ridx = kh_put(cache, &m->results, k, &res);
        if (res <= 0) {
            // this can still happen if we get an allocation error
            goto alloc_error;
        }
    
        // add to table
        m->results.keys[ridx] = &r->h.key;
        m->results.vals[ridx] = &r->h;
        
        // add to scan
        r->scan = s;
        r->scan_next = s->results;
        s->results = r;

        if (r->scan_next) {
            r->scan_next->scan_prev = r;
        }
    }

    struct timeout *next = min_timeout(&r->time_srv, &r->time_ptr, &r->time_txt);
    if (next->next != r->h.t.next) {
        schedule_request(m, &r->h, *next);
    }
    
    publish_result(r);
    return off;

alloc_error:
    if (added) {
        emdns_mem_free(r);
    }
    return off;

data_error:
    if (added) {
        emdns_mem_free(r);
    }
    return EMDNS_MALFORMED;
}

static int process_addr(struct emdns *m, emdns_time now, struct key *k, uint8_t *u, int sz, int off) {
    int ttl = get_ttl(u + off);
    uint16_t datasz = big_16(u + off + 4);
    int dataoff = off + 6;
    off = dataoff + datasz;

    if (off > sz || datasz != sizeof(struct in6_addr)) {
        return EMDNS_MALFORMED;
    }

    hash_key(k);
    khint_t idx = kh_get(cache, &m->addrs, k);
    if (idx == kh_end(&m->addrs)) {
        return off;
    }

    struct addr *r = (struct addr*) m->addrs.vals[idx];
    bool changed = r->have_addr && memcmp(&r->addr, u+dataoff, sizeof(r->addr));

    memcpy(&r->addr, u+dataoff, sizeof(r->addr));
    
    if (r->userid) {
        r->cb(r->udata, &r->addr);
        m->user_addrs[r->userid - ID_ADDR] = NULL;
        r->userid = 0;
    }
    
    if (!r->results) {
        // no one wants us any more
        heap_remove(&m->cache_heap, &r->h.hn, &compare_record);
        kh_del(cache, &m->addrs, idx);
        emdns_mem_free(r);
        return off;
    }
    
    struct timeout time;
    if (ttl) {
        time.next = now + (800 * ttl) + random_wait(0, 20 * ttl);
        time.expiry = now + (1000 * ttl);
        time.step = 50 * ttl;
    } else {
        // goaway
        time.next = now + 1000;
        time.expiry = now + 1000;
        time.step = 0;
    }

    schedule_request(m, &r->h, time);

    for (struct result *q = r->results; q != NULL; q = q->srv_next) {
        memcpy(&q->sa.sin6_addr, &r->addr, sizeof(r->addr));
        q->have_addr = 1;
        if (changed) {
            q->dirty = true;
        }
        publish_result(q);
    }

    return off;
}

static int process_other(uint8_t *u, int sz, int off) {
    // skip ttl - 4 bytes
    uint16_t datasz = big_16(u + off + 4);
    off += 6 + datasz;
    return off > sz ? EMDNS_MALFORMED : off;
}

static int process_response(struct emdns *m, emdns_time now, uint8_t *u, int sz, int record_num) {
    int off = 12;

    while (--record_num) {
        struct key k;
        int namesz = decode_dns_name(k.name, u, sz, &off);
        if (namesz < 0 || off + 2 /*rtype*/ + 2 /*rclass*/ + 4 /*ttl*/ + 2 /*datasz*/ > sz) {
            return EMDNS_MALFORMED;
        }
        
        uint16_t rtype = big_16(u + off);
        uint16_t rclass = big_16(u + off + 2) & RCLASS_MASK;
        off += 4;

        if (rclass == RCLASS_IN && rtype == RTYPE_AAAA) {
            off = process_addr(m, now, &k, u, sz, off);
        } else if (rclass == RCLASS_IN && (rtype == RTYPE_PTR || rtype == RTYPE_SRV || rtype == RTYPE_TXT)) {
            off = process_result(m, now, &k, rtype, u, sz, off);
        } else {
            off = process_other(u, sz, off);
        }

        if (off < 0) {
            return off;
        }
    }

    return 0;
}

static int process_request(struct emdns *m, emdns_time now, uint8_t *u, int sz, int question_num, int answer_num) {
    int off = 12;
    struct pub_service *answers = NULL;
    emdns_time pub_time = now + random_wait(20, 120);

    while (--question_num) {
        uint8_t name[MAX_HOST_SIZE];
        int namesz = decode_dns_name(name, u, sz, &off);
        if (namesz < 0 || off + 4 > sz) {
            return EMDNS_MALFORMED;
        }
        
        uint16_t rtype = big_16(u + off);
        uint16_t rclass = big_16(u + off + 2);
        
        if (rclass != RCLASS_IN || rtype > RTYPE_MAX) {
            continue;
        }

        switch (rtype) {
        case RTYPE_AAAA:
            if (namesz == m->hostname.namesz && equals_dns_name(name, m->hostname.name)) {
                for (int id = 0; id < MAX_IPS; id++) {
                    struct pub_ip *r = m->user_ips[id];
                    if (now - r->h.last_publish >= 1000) {
                        reschedule_publish(m, &r->h, pub_time);
                    }
                }
            }
            break;
        case RTYPE_SRV:
        case RTYPE_TXT:
            for (int id = 0; id < MAX_SERVICES; id++) {
                struct pub_service *r = m->user_services[id];
                if (now - r->h.last_publish >= 1000 && namesz == r->name.namesz && equals_dns_name(name, r->name.name)) {
                    reschedule_publish(m, &r->h, pub_time);
                }
            }
            break;
        case RTYPE_PTR:
            for (int id = 0; id < MAX_SERVICES; id++) {
                struct pub_service *r = m->user_services[id];
                uint8_t labelsz = r->name.name[0];
                uint8_t *svc = r->name.name + 1 + labelsz;
                uint8_t svcsz = r->name.namesz - 1 - labelsz;
                if (now - r->h.last_publish >= 1000 && svcsz == namesz && equals_dns_name(name, svc)) {
                    // don't immediately schedule. we need to check that it's not
                    // in the known answer list
                    r->next_answer = answers;
                    answers = r;
                }
            }
            break;
        }
    }

    // process known answers
    
    while (--answer_num) {
        uint8_t svc[MAX_HOST_SIZE];
        int svcsz = decode_dns_name(svc, u, sz, &off);
        if (svcsz < 0 || off + 10 > sz) {
            return EMDNS_MALFORMED;
        }
        
        uint16_t rtype = big_16(u + off);
        uint16_t rclass = big_16(u + off + 2);
        uint32_t ttl = big_32(u + off + 4);
        uint16_t datasz = big_16(u + off + 8);
        int dataoff = off + 10;
        off += 10 + datasz;

        (void) ttl; // TODO check ttl

        if (off > sz) {
            return EMDNS_MALFORMED;
        }

        if (rclass != RCLASS_IN || rtype != RTYPE_PTR) {
            continue;
        }
        
        uint8_t name[MAX_HOST_SIZE];
        int namesz = decode_dns_name(name, u, sz, &dataoff);
        if (namesz < 0 || dataoff != off) {
            return EMDNS_MALFORMED;
        }

        // search through the list and remove the item if it's there
        struct pub_service *prev = NULL;
        struct pub_service *r = answers;
        while (r != NULL) {
            if (namesz != r->name.namesz || !equals_dns_name(name, r->name.name)) {
                prev = r;
                r = r->next_answer;
            } else if (prev) {
                r = prev->next_answer = r->next_answer;
            } else {
                r = answers = r->next_answer;
            }
        }
    }

    // now publish PTRs that weren't in the known answer list
    for (struct pub_service *r = answers; r != NULL; r = r->next_answer) {
        reschedule_publish(m, &r->h, pub_time);
    }

    return 0;
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

    if (flags & FLAG_RESPONSE) {
        if (question_num || auth_num) {
            return EMDNS_MALFORMED;
        }
        return process_response(m, now, u, sz, answer_num + additional_num);
    } else {
        if (auth_num || additional_num) {
            return EMDNS_MALFORMED;
        }
        return process_request(m, now, u, sz, question_num, answer_num);
    }
}


///////////
// ENCODERS
///////////

// encode functions take the following form
// buf/sz give the full message buffer
// off contains the current offset
// and is updated with the new offset
// returns nonzero on error

static int encode_query(const struct key *k, uint8_t rtype, uint8_t *buf, int sz, int *off) {
    int reqsz = 4 + k->namesz;
    if (*off + reqsz > sz) {
        return -1;
    }

    uint8_t *p = buf + *off;
    memcpy(p, k->name, k->namesz);
	p += k->namesz;
	put_big_16(p, rtype);
    put_big_16(p + 2, RCLASS_IN);
    p += 4;

    *off += reqsz;
    assert(p - buf == *off);
    return 0;
}

static int encode_result_query(const struct key *k, uint8_t *buf, int sz, int *off) {
    int reqsz = 10 + k->namesz;
    if (*off + reqsz > sz) {
        return -1;
    }

    uint8_t *p = buf + *off;
    memcpy(p, k->name, k->namesz);
	p += k->namesz;
	put_big_16(p, RTYPE_SRV);
    put_big_16(p + 2, RCLASS_IN);
    put_big_16(p + 4, LABEL_PTR16 | *off);
    put_big_16(p + 6, RTYPE_TXT);
    put_big_16(p + 7, RCLASS_IN);
    p += 10;

    *off += reqsz;
    assert(p - buf == *off);
    return 0;
}

static int encode_result(struct result *r, emdns_time now, uint8_t *buf, int sz, int *off) {
    int reqsz = 2 /*name*/ + 2 /*type*/ + 2 /*class*/ + 4 /*ttl*/ + 2 /*datasz*/ + r->h.key.namesz;
    if (*off + reqsz > sz) {
        return -1;
    }

    uint8_t labelsz = r->h.key.name[0];
    uint16_t svcoff = *off + 2 /*name*/ + 2 /*type*/ + 2 /*class*/ + 4 /*ttl*/ + 2 /*datasz*/ + 1 /*labelsz*/ + labelsz; 
    uint32_t ttl = (uint32_t) ((r->h.t.expiry - now) / 1000);

    uint8_t *p = buf + *off;
    put_big_16(p, LABEL_PTR16 | svcoff);
    put_big_16(p + 2, RTYPE_PTR);
    put_big_16(p + 4, RCLASS_IN);
    put_big_32(p + 6, ttl);
    put_big_16(p + 10, r->h.key.namesz);
    p += 12;
    memcpy(p, r->h.key.name, r->h.key.namesz);
    p += r->h.key.namesz;

    *off += reqsz;
    assert(p - buf == *off);
    return 0;
}

static int encode_local_addr(struct emdns *m, struct pub_ip *s, uint8_t *buf, int sz, int *off) {
    int datasz = 16;
    int reqsz = m->hostname.namesz + 2 /*type*/ + 2 /*class*/ + 4 /*ttl*/ + 2 /*datasz*/ + datasz;

	if (*off + reqsz > sz) {
		return -1;
	}

	uint8_t *p = buf + *off;
    memcpy(p, m->hostname.name, m->hostname.namesz);
    p += m->hostname.namesz;
	put_big_16(p, RTYPE_AAAA);
	put_big_16(p + 2, RCLASS_IN_FLUSH);
	put_big_32(p + 4, TTL_DEFAULT);
	put_big_16(p + 8, datasz);
	p += 10;
	memcpy(p, &s->addr, 16);
	p += 16;

	*off += reqsz;
	assert(p - buf == *off);
	return 0;
}

static int encode_service(struct pub_service *s, const struct key *host, uint8_t *u, int sz, int *poff) {
	// SRV
	int reqsz = s->name.namesz + 2 /*type*/ + 2 /*class*/ + 4 /*ttl*/ + 2 /*datasz*/ + 2 /*pri*/ + 2 /*weight*/ + 2 /*port*/ + host->namesz;
	// TXT
	reqsz += 2 /*name*/ + 2 /*type*/ + 2 /*class*/ + 4 /*ttl*/ + 2 /*datasz*/ + s->txtsz;
	// PTR
	reqsz += 2 /*name*/ + 2 /*type*/ + 2 /*class*/ + 4 /*ttl*/ + 2 /*datasz*/ + 2 /*srv name*/;

	if (*poff + reqsz > sz) {
		return -1;
	}

	// SRV
	uint8_t *p = u + *poff;
	uint16_t nameoff = (uint16_t) *poff;
	uint16_t svcoff = nameoff + s->name.name[0] + 1;
	memcpy(p, s->name.name, s->name.namesz);
	p += s->name.namesz;
	put_big_16(p, RTYPE_SRV);
	put_big_16(p + 2, RCLASS_IN_FLUSH);
	put_big_32(p + 4, TTL_DEFAULT);
	put_big_16(p + 8, 2 + 2 + 2 + host->namesz);
	put_big_16(p + 10, PRIORITY_DEFAULT);
	put_big_16(p + 12, WEIGHT_DEFAULT);
	put_big_16(p + 14, s->port);
	p += 16;
	memcpy(p, host->name, host->namesz);
	p += host->namesz;

	// TXT
	put_big_16(p, LABEL_PTR16 | nameoff);
	put_big_16(p + 2, RTYPE_TXT);
	put_big_16(p + 4, RCLASS_IN_FLUSH);
	put_big_32(p + 6, TTL_DEFAULT);
	put_big_16(p + 10, (uint16_t) s->txtsz);
    p += 12;
	memcpy(p, s->txt, s->txtsz);
	p += s->txtsz;

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

////////////////////////////
// OUTGOING MESSAGE CREATION
////////////////////////////


static int get_next_publish(struct emdns *m, emdns_time *time, uint8_t *u, int sz) {
    emdns_time now = *time;
	bool do_publish = false;
	int num_publish = 0;
	int off = 12;

	for (;;) {
		struct heap_node *hn = heap_min(&m->publish_heap);
		if (!hn) {
			break;
		}

		struct publish *r = container_of(hn, struct publish, hn);
		if (r->next_publish > now) {
			*time = r->next_publish;
			break;
		}

		if (r->type == PUBLISH_SERVICE) {
            struct pub_service *s = (struct pub_service*) r;
			if (encode_service(s, &m->hostname, u, sz, &off)) {
				break;
			}
			num_publish++;
		}

		increment_publish_timeout(m, r, now);
		do_publish = true;
	}

	assert(off <= sz);

	if (!do_publish) {
		return EMDNS_PENDING;
    }
    
    // if we are publishing something, then we should publish all local addresses

    for (int id = 0; id < MAX_IPS; id++) {
        struct pub_ip *r = m->user_ips[id];
		if (encode_local_addr(m, r, u, sz, &off)) {
			break;
		}
		if (r->h.last_publish != now) {
			increment_publish_timeout(m, &r->h, now);
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


static int get_next_request(struct emdns *m, emdns_time *time, uint8_t *u, int sz) {
    emdns_time now = *time;
    struct scan *scans = NULL;
    uint16_t num_questions = 0;
    uint16_t num_answers = 0;
    int off = 12;

	for (;;) {
		struct heap_node *hn = heap_min(&m->cache_heap);
		if (!hn) {
			break;
		}

		struct record *r = container_of(hn, struct record, hn);
		if (r->t.next > *time) {
			*time = r->t.next;
			break;
        }
        
        if (now >= r->t.expiry) {
            switch (r->type) {
            case RESULT_RECORD:
                expire_result(m, (struct result*) r);
                break;
            case ADDR_RECORD:
                expire_addr(m, (struct addr*) r);
                break;
            case SCAN_RECORD:
                assert(0);
            }
            continue;
        }

        switch (r->type) {
        case RESULT_RECORD:
            if (encode_result_query(&r->key, u, sz, &off)) {
                goto out_of_space;
            }
            break;
        case ADDR_RECORD:
            if (encode_query(&r->key, RTYPE_AAAA, u, sz, &off)) {
                goto out_of_space;
            }
            break;
        case SCAN_RECORD:
            if (encode_query(&r->key, RTYPE_PTR, u, sz, &off)) {
                goto out_of_space;
            } else {
                // add it to our list to add known answers below
                struct scan *s = (struct scan*) r;
                s->next_scan = scans;
                scans = s;
            }
            break;
        }

		increment_timeout(m, r, now);
		num_questions++;
	}

	// now add known answers for PTR scans
    
	for (struct scan *s = scans; s != NULL; s = s->next_scan) {
        for (struct result *r = s->results; r != NULL; r = r->scan_next) {
            if (encode_result(r, now, u, sz, &off)) {
                goto out_of_space;
            }
            num_answers++;
		}
	}

    // TODO handle truncation
out_of_space:
    assert(off <= sz);
    if (!num_questions) {
        return EMDNS_PENDING;
    }

    put_big_16(u, 0); // transaction ID
    put_big_16(u+2, 0); // flags
    put_big_16(u+4, num_questions);
    put_big_16(u+6, num_answers); // answers
    put_big_16(u+8, 0); // authority
    put_big_16(u+10, 0); // additional

    return off;
}

int emdns_next(struct emdns *m, emdns_time *now, void *buf, int sz) {
    if (sz < MIN_MESSAGE_SIZE) {
        return EMDNS_MALFORMED;
    }

    emdns_time next_publish = *now;
    emdns_time next_request = *now;

    int ret = get_next_publish(m, &next_publish, (uint8_t*) buf, sz);
    if (ret >= 0) {
        return ret;
    }

    ret = get_next_request(m, &next_request, (uint8_t*) buf, sz);
    if (ret >= 0) {
        return ret;
    }

    *now = next_publish < next_request ? next_publish : next_request;
    return EMDNS_PENDING;
}
