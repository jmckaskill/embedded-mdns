#pragma once

#include <stdint.h>

// maximum concurrent queries and scans
#define MDNS_MAX_REQUESTS 16

// maximum number of entries to publish
#define MDNS_MAX_PUBLISH 16

// main structure for the library
// should be zero initialized
// contains no dynamically allocated data so can be thrown away on cleanup
struct mdns;

// common monotonic clock in milliseconds
typedef int64_t mdns_time;

// error values
#define MDNS_PENDING -1
#define MDNS_TOO_MANY -2
#define MDNS_MALFORMED -3

// mdns_next returns the next message to be sent
// sz is the size of the provided buffer and should correspond
// to the maximum mtu the app wants to send
// time is an inout param. on input it indicates the current time
// on output it indicates the time to wait until
// returns 0 if there is a next message
// or MDNS_PENDING if we need to wait
int mdns_next(struct mdns *m, mdns_time *time, void *buf, int sz);

// mdns_process processes a received multicast message
// this may generate messages to be sent which should be retrieved with mdns_next
// time is the current time using the same monontonic clock as mdns_next
int mdns_process(struct mdns *m, mdns_time time, const struct sockaddr *sa, int sasz, const void *msg, int sz);

enum mdns_rtype {
    MDNS_AAAA = 28,
    MDNS_SRV = 33,
    MDNS_TXT = 16,
    MDNS_PTR = 12,
    MDNS_ANY = 255,
};

struct mdns_record {
    unsigned authoritative : 1;
    unsigned found : 1;
    enum mdns_rtype type;
    const char *name; // double null-terminated host name
    union {
        const char *AAAA; // hostname
        struct {
            const char *host; // double null-terminated fully qualified host name 
            uint16_t port;
            int priority;
            int weight;
        } SRV;
        const char *TXT; // double null-terminated list of strings e.g. "txtvers=1\0path=/\0"
        const char *PTR;
    } u;
};


// mdns_publish starts publishing the requested record
// buf is the buffer containing the raw record
// for AAAA records this holds the IP address as a string
// for SRV records
// the record will be continually published until stopped using mdns_stop
// returns a reference to use with mdns_stop
int mdns_publish(struct mdns *m, mdns_time time, const struct mdns_record *rec);

// mdns_cb is the callback type used by mdns_scan and mdns_query
// the provided record uses temporary memory
// the application should copy it and the member variable strings out if required
typedef void (*mdns_cb)(void *udata, const struct mdns_record*);

// mdns_query starts a one-shot DNS query
// the callback will be called with the first valid response or on timeout
// the call will continue until a response is found or the call times out
// the user can cancel the request before completion by using mdns_stop
// but mdns_stop must not be used once the callback has been called as the ref id
// may be reused
// the return value is:
// -ve -> error
// >=0 -> reference ID used for mdns_stop
// possible errors include:
// MDNS_TOO_MANY - too many concurrent requests
// MDNS_MALFORMED - malformed request record
int mdns_query(struct mdns *m, mdns_time time, enum mdns_rtype type, const char *name, void *udata, mdns_cb cb);

// mdns_scan starts a continuous scan
// add will be called as results are found
// remove will be called as previously found results then go stale and timeout
// the scan will continue until explicitely stopped using mdns_stop
// the return value is:
// -ve -> error
// >=0 -> reference ID used for mdns_stop
// possible errors include:
// MDNS_TOO_MANY - too many concurrent requests
// MDNS_MALFORMED - malformed request record
int mdns_scan(struct mdns *m, mdns_time time, enum mdns_rtype type, const char *name, void *udata, mdns_cb add, mdns_cb remove);

// mdns_stop stops a pending scan, query or publish
int mdns_stop(struct mdns *m, int ref);

// mdns_bind6 creates and binds an IPv6 socket bound to the correct port
// with the request multicast address setup.
// sa returns the address packets should be sent to/from
// the socket is bound to the interface specified
// this is only implemented for mainstream operating systems
int mdns_bind6(int interface_id);

// internal implementation

struct mdns_request {
    struct mdns_request *next_to_start;
	enum mdns_type type;
    mdns_cb add;
    mdns_cb remove;
    void *udata;
    int64_t next;
    unsigned valid : 1;
    unsigned query : 1;
	uint8_t namesz;
	uint8_t name[256];
};

struct mdns_publish {
    struct mdns_record rec;
    int64_t next;
    unsigned valid : 1;
    unsigned published : 1;
};

struct mdns {
    struct mdns_request requestv[MDNS_MAX_REQUESTS];
    struct mdns_publish publishv[MDNS_MAX_PUBLISH];
    unsigned new_to_publish : 1;
	int request_num;
	int publish_num;
};
