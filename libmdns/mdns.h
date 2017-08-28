#pragma once

#include <stdint.h>
#include "heap-inl.h"

struct sockaddr;

// maximum concurrent queries and scans
#define EMDNS_MAX_REQUESTS 16

// maximum number of entries to publish
#define EMDNS_MAX_PUBLISH 8

#define EMDNS_MAX_ANSWERS 32

// main structure for the library
// should be zero initialized
// contains no dynamically allocated data so can be thrown away on cleanup
struct mdns;

// common monotonic clock in milliseconds
typedef int64_t emdns_time;

// error values
#define EMDNS_PENDING -1
#define EMDNS_TOO_MANY -2
#define EMDNS_MALFORMED -3

// emdns_next returns the next message to be sent
// sz is the size of the provided buffer and should correspond
// to the maximum mtu the app wants to send
// time is an inout param. on input it indicates the current time
// on output it indicates the time to wait until
// returns >=0 if there is a next message
// or MDNS_PENDING if we need to wait
int emdns_next(struct emdns *m, emdns_time *time, void *buf, int sz);

// emdns_process processes a received multicast message
// this may generate messages to be sent which should be retrieved with emdns_next
// time is the current time using the same monontonic clock as emdns_next
int emdns_process(struct emdns *m, emdns_time time, const struct sockaddr *sa, int sasz, const void *msg, int sz);

// emdns_publish starts publishing the requested record
// buf is the buffer containing the raw record
// for AAAA records this holds the IP address as a string
// for SRV records
// the record will be continually published until stopped using emdns_stop
// returns a reference to use with emdns_stop
int emdns_publish(struct emdns *m, const struct emdns_record *rec);

// emdns_cb is the callback type used by emdns_scan and emdns_query
// the provided record uses temporary memory
// the application should copy it and the member variable strings out if required
typedef void (*emdns_addcb)(void *udata, const char *name, const struct sockaddr_in6 *sa, const char *txt);
typedef void (*emdns_rmcb)(void *udata, const char *name);

// emdns_query starts a one-shot DNS query
// the callback will be called with the first valid response or on timeout
// the call will continue until a response is found or the call times out
// the user can cancel the request before completion by using emdns_stop
// but emdns_stop must not be used once the callback has been called as the ref id
// may be reused
// the return value is:
// -ve -> error
// >=0 -> reference ID used for emdns_stop
// possible errors include:
// MDNS_TOO_MANY - too many concurrent requests
// MDNS_MALFORMED - malformed request record
int emdns_query_aaaa(struct emdns *m, const char *name, void *udata, emdns_addcb cb);

// emdns_scan starts a continuous scan
// add will be called as results are found
// remove will be called as previously found results then go stale and timeout
// the scan will continue until explicitely stopped using emdns_stop
// the return value is:
// -ve -> error
// >=0 -> reference ID used for emdns_stop
// possible errors include:
// MDNS_TOO_MANY - too many concurrent requests
// MDNS_MALFORMED - malformed request record
int emdns_scan(struct emdns *m, const char *name, void *udata, emdns_addcb add, emdns_rmcb remove);

// emdns_stop stops a pending scan, query or publish
int emdns_stop(struct emdns *m, int ref);

// emdns_bind6 creates and binds an IPv6 socket bound to the correct port
// with the request multicast address setup.
// sa returns the address packets should be sent to/from
// the socket is bound to the interface specified
// this is only implemented for mainstream operating systems
int emdns_bind6(int interface_id);

// internal implementation

enum emdns_request_type {
	EMDNS_NO_REQUEST,
	EMDNS_QUERY_AAAA,
	EMDNS_QUERY_TXT_SRV,
	EMDNS_SCAN_PTR,
};

struct emdns_request;

struct emdns_answer {
	struct emdns_answer *next;
	struct emdns_request *subrequest;
	emdns_time ttl;
	uint8_t namesz;
	uint8_t name[64];
};

struct emdns_request {
    struct heap_node hn;
	struct emdns_request *next;
    emdns_time next_request;
	emdns_time duration;
	enum emdns_request_type type;
    emdns_addcb add;
    emdns_rmcb remove;
    void *udata;
	struct emdns_answer *answers;
	uint16_t nameoff;
	uint8_t namesz;
	uint8_t name[256];
};

struct emdns_publish {
    struct heap_node hn;
	struct emdns_publish *next;
	emdns_time next_announce;
	emdns_time last_publish;
	uint8_t rtype;
    uint8_t namesz, datasz;
    uint8_t name[256];
    uint8_t data[256];
};

struct emdns {
    struct emdns_request requestv[EMDNS_MAX_REQUESTS];
    struct emdns_publish publishv[EMDNS_MAX_PUBLISH];
	struct emdns_answer answerv[EMDNS_MAX_ANSWERS];
    struct emdns_request *to_publish;
    struct emdns_request *to_republish;
    struct emdns_request *free_request;
    struct emdns_answer *free_answer;
	struct emdns_publish *free_publish;
    int answers_used;
    int requests_used;
	int publish_used;
	struct heap publish_heap;
	struct heap request_heap;
};
