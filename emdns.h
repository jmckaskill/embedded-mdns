#pragma once

#ifdef _WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <stdint.h>


struct emdns;

// common monotonic clock in milliseconds
typedef int64_t emdns_time;

// error values
#define EMDNS_FINISHED 0
#define EMDNS_PENDING -1
#define EMDNS_TOO_MANY -2
#define EMDNS_MALFORMED -3
#define EMDNS_DUPLICATE -4

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
int emdns_process(struct emdns *m, emdns_time time, const void *msg, int sz);

struct emdns *emdns_new(const char *hostname);
void emdns_free(struct emdns *m);

int emdns_publish_ip6(struct emdns *m, emdns_time now, const struct in6_addr *addr);
int emdns_publish_service(struct emdns *m, emdns_time now, const char *svc, const char *txt, uint16_t port);

typedef void(*emdns_ip6cb)(void *udata, const struct in6_addr *addr);
typedef void(*emdns_svccb)(void *udata, const char *name, size_t namesz, const struct sockaddr_in6 *sa, const char *txt, size_t txtsz);

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
int emdns_query_ip6(struct emdns *m, emdns_time now, const char *name, void *udata, emdns_ip6cb cb);

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
int emdns_scan_ip6(struct emdns *m, emdns_time now, const char *name, void *udata, emdns_svccb cb);

// emdns_stop stops a pending scan, query or publish
int emdns_stop(struct emdns *m, int id);

// emdns_bind6 creates and binds an IPv6 socket bound to the correct port
// with the request multicast address setup.
// sa returns the address packets should be sent to/from
// the socket is bound to the interface specified
// this is only implemented for mainstream operating systems
int emdns_bind6(int interface_id, struct sockaddr_in6 *send_addr);
