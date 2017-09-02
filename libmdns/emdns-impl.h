#pragma once

#include "../emdns.h"

#define krealloc(data,newsz) emdns_realloc(data,newsz)
#define kfree(data) emdns_free(data)
void *emdns_calloc(size_t newsz);
void *emdns_realloc(void *data, size_t newsz);
void emdns_free(void *data);

#include "heap-inl.h"
#include "khash.h"

struct emdns_entry;
struct emdns_request;
struct emdns;

KHASH_DECLARE(entry, const uint8_t*, struct emdns_entry*);

struct emdns_entry_list {
	struct emdns_entry_list *next, *prev;
	struct emdns_request *owner;
	struct emdns_entry *entry;
};

struct emdns_entry {
	struct heap_node hn;
	emdns_time next_request;
	emdns_time expiry;
	int next_wait_duration;

	uint8_t rtype;
	struct emdns_entry_list owners_list;

	uint8_t name[EMDNS_MAX_HOST_SIZE];

	union {
		char txt[EMDNS_MAX_TXT_SIZE];
		struct {
			uint16_t port;
			uint8_t tgt[EMDNS_MAX_HOST_SIZE];
		} srv;
		struct in6_addr aaaa;
	} u;
};

enum emdns_request_type {
	EMDNS_QUERY_AAAA,
	EMDNS_SCAN_PTR,
	EMDNS_SCAN_RESULT,
};

struct emdns_request {
	struct emdns_request *next, *prev;

	enum emdns_request_type type;
	union {
		emdns_ip6cb ip6;
		emdns_svccb scan;
	} callbacks;

    void *udata;
	uint16_t requestoff;

	union {
		struct {
			struct emdns_entry_list aaaa;
			uint8_t namesz;
			uint8_t name[256];
		} query;

		struct {
			struct emdns_entry_list ptr;
			struct emdns_request *result_list;
			uint8_t namesz;
			uint8_t name[256];
		} scan_ptr;

		struct {
			struct emdns_entry_list txt;
			struct emdns_entry_list aaaa;
			struct emdns_entry_list srv;
			struct emdns_entry_list ptr;
		} scan_result;
	} u;
};

enum emdns_publish_type {
	EMDNS_NO_PUBLISH,
	EMDNS_PUBLISH_AAAA,
	EMDNS_PUBLISH_SERVICE,
};

struct emdns_publish {
    struct heap_node hn;
	struct emdns_publish *next;
	emdns_time next_announce;
    emdns_time last_publish;
	int wait_duration;
	enum emdns_publish_type type;
    union {
        struct in6_addr ip6;
        struct {
            uint16_t port;
			uint16_t txtsz;
			uint8_t namesz;
			uint8_t name[256];
			uint8_t txt[EMDNS_MAX_TXT_SIZE];
        } svc;
    } data;
};

struct emdns {
	void *udata;
	emdns_realloc realloc;

	struct heap publish_heap;
	struct heap request_heap;

	struct emdns_publish *publish_ip_list;
	struct emdns_publish *publish_svc_list;

	struct emdns_reque emdns_request *user_requests;ostsz;
	uint8_t host[256];
};
