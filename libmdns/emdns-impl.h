#pragma once

#include "../emdns.h"
#include <stdbool.h>

#define krealloc(data,newsz) emdns_mem_realloc(data,newsz)
#define kmalloc(newsz) emdns_mem_realloc(NULL,newsz)
#define kfree(data) emdns_mem_free(data)
void *emdns_mem_calloc(size_t newsz);
void *emdns_mem_realloc(void *data, size_t newsz);
void emdns_mem_free(void *data);

#include "heap-inl.h"
#include "khash.h"

#ifdef _MSC_VER
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#endif

#ifndef container_of
#define container_of(ptr, type, member) ((type*) ((char*) (ptr) - offsetof(type, member)))
#endif

#define NEW(type) ((type*) emdns_mem_calloc(sizeof(type)))

#define MIN_MESSAGE_SIZE 512

#define RCLASS_IN 1
#define RCLASS_IN_FLUSH 0x8001
#define RCLASS_MASK 0x7FFF

#define RTYPE_A 1
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
#define MAX_TTL (10*24*3600)
#define PRIORITY_DEFAULT 0
#define WEIGHT_DEFAULT 0

#define MAX_ADDRS 5
#define MAX_SCANS 5
#define MAX_IPS 5
#define MAX_SERVICES 5

#define ID_ADDR 1
#define ID_SCAN (ID_ADDR + MAX_ADDRS)
#define ID_IP (ID_SCAN + MAX_SCANS)
#define ID_SERVICE (ID_IP + MAX_IPS)
#define ID_LAST (ID_SERVICE + MAX_SERVICES)

#define MAX_LABEL_SIZE 63
#define MAX_HOST_SIZE 255

// general organization
// emdns is the root structure
// - has a hash table of cache entries
// - a timeout heap of cache entries
// - a list of publish_ip
// - a list of publish_svc
//
// the hash tables are used for incoming questions and answers and cleanup
// the heaps are used for tracking timeouts
// the list is used so that we send all ips when we send any
// 
// each cache entry represents a given type, name pair that is being tracked
// only internet class items are supported
// for scan results we have a cache entry for both resource name (used for
// rerequests of the root) and for the pointed to items (used for cache
// management of the scan results)
// for everything else the name is the resource name
// the cache entry is created as soon as a request expresses
// and is evicted once there are no longer any outstanding requests
// entries can be marked as ours
// for ip results we only store the most relevant (ie ipv6 link-local address
// with the latest expiry)
//
// a request represents a something interested in cache entries
// there are a few types types:
// 1. Straight query - this tracks a single cache entry
//    struct query_request
// 2. Scan request - struct scan_request
//    this contains a list of scan_result
// 3. Scan result - struct scan_result
//    the result tracks 4 cache entries
// 4. Publish IP - struct pub_ip
//    tracks a single cache entry
// 5. Publish service - struct pub_service
//    tracks entries for the SRV, TXT, and PTR records
//
// cache entries keep a list of owners via the entry_owner helper
// that way we can walk back up to the callbacks when they get updated or evicted

struct record;
struct emdns;

struct key {
	uint32_t hash;
	uint8_t namesz;
	uint8_t name[MAX_HOST_SIZE];
};

__KHASH_TYPE(cache, const struct key*, struct record*)

enum record_type {
	RESULT_RECORD,
	ADDR_RECORD,
	SCAN_RECORD,
};

struct timeout {
	emdns_time next;
	emdns_time expiry;
	int step;
};

struct record {
	struct heap_node hn;
	emdns_time next;
	struct key key;
	enum record_type type;
#ifndef NDEBUG
	unsigned scheduled : 1;
#endif
};

struct result {
	struct record h;

	bool have_srv;
	bool have_ptr;
	bool have_txt;
	bool have_addr;
	bool published;
	bool dirty;

	struct timeout time_srv;
	struct timeout time_ptr;
	struct timeout time_txt;
	emdns_time known_timeout;

	struct scan *scan;
	struct result *scan_next, *scan_prev;

	struct addr *srv;
	struct result *srv_next, *srv_prev;

	char *txt; // heap allocated
	uint16_t txtsz;
	uint16_t port;
};

// IP address categories from lowest priority to highest
enum addr_type {
	INVALID_ADDRESS,
	LINK_LOCAL_IP4,
	GLOBAL_IP4,
	GLOBAL_IP6,
	SITE_LOCAL_IP6,
	LINK_LOCAL_IP6,
};

struct addr {
	struct record h;
	struct timeout t;
	union {
		struct sockaddr h;
		struct sockaddr_in6 ip6;
		struct sockaddr_in ip4;
	} sa;
	bool have_addr;
	enum addr_type addr_type;
	emdns_query_cb cb;
	void *udata;
	int userid;
	struct result *results;
	
	// temporaries used for addr priority resolution
	bool in_list;
	struct addr *next;
};

struct scan {
	struct record h;
	struct timeout t;
	struct result *results;
	emdns_scan_cb cb;
	void *udata;
	int userid;

	// temporaries used for generating known answers
	struct scan *next_scan;
	int svcoff;
};

enum publish_type {
	PUBLISH_AAAA,
	PUBLISH_SERVICE,
};

struct publish {
	struct heap_node hn;
	emdns_time next_publish;
	emdns_time last_publish;
	int publish_wait;
	enum publish_type type;
};

struct pub_ip {
	struct publish h;
	int family;
	uint8_t addr[16];
};

struct pub_service {
	struct publish h;
	struct pub_service *next_answer; // temp member used for known answer processing
	struct key name;
	uint8_t *txt; // heap allocated
	uint16_t txtsz;
	uint16_t port;
};

struct emdns {
	struct heap cache_heap;
	khash_t(cache) results;
	khash_t(cache) scans;
	khash_t(cache) addrs;
	
	struct heap publish_heap;

	struct key hostname;

	struct pub_ip *user_ips[MAX_IPS];
	struct pub_service *user_services[MAX_SERVICES];
	struct addr *user_addrs[MAX_ADDRS];
	struct scan *user_scans[MAX_SCANS];

	// temporary used for processing prioritized addresses
	struct addr *dist_addrs;
};
