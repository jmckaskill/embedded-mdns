#include "tests.h"

int test_publish_ip6() {
	int err = 0;
	fprintf(stderr, "test_publish_ip6\n");

	struct emdns *m = emdns_new("test.local");
	check_not_null(&err, m, "new emdns");

	const char test_addr[16] = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10";
	struct in6_addr a;
	memcpy(&a, test_addr, 16);
	emdns_time now = 1000;
	check_range(&err, emdns_publish_ip(m, now, AF_INET6, &a), 0, INT_MAX, "emdns_publish_ip ID");

	char buf[1024];
	now = 1000;
	check(&err, emdns_next(m, &now, buf, sizeof(buf)), EMDNS_PENDING, "wait for first publish");
	check_range(&err, now, 1000, 1250, "length of time to wait for first publish");

	now = 2000;
	const char publish_msg[] =
		"\0\0" // transaction ID
		"\x84\0" // flags - response & authoritative
		"\0\0" // questions
		"\0\x02" // answers - AAAA & NSEC
		"\0\0" // authority
		"\0\0" // additional
		"\x04" "test" "\x05" "local" "\0" // test.local.
		"\0\x1C" // 28 - AAAA record
		"\x80\x01" // internet class with the cache bit set
		"\0\0\0\x78" // TTL - 0x78 = 120 seconds
		"\0\x10" // data length 16 bytes
		"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10" // IP address
		"\xC0\x0C" // redir to aaaa name
		"\0\x2F" // 47 - NSEC
		"\x80\x01" // internet class with the cache bit set
		"\0\0\0\x78" // TTL - 0x78 = 120 seconds
		"\0\x08" // data length 8 bytes
		"\xC0\x0C" // next domain name -> redir to AAAA name
		"\0\x04" // bitmap size
		"\0\0\0\x08"; // bitmap

	check(&err, emdns_next(m, &now, buf, sizeof(buf)), sizeof(publish_msg) - 1, "initial message size");
	check_data(&err, buf, publish_msg, sizeof(publish_msg) - 1, "initial message data");
	
	check(&err, emdns_next(m, &now, buf, sizeof(buf)), EMDNS_PENDING, "only one initial message");
	check(&err, now, 3000, "wait 1 second until resend");

	now = 2999;
	check(&err, emdns_next(m, &now, buf, sizeof(buf)), EMDNS_PENDING, "wait stays consistent");
	check(&err, now, 3000, "wait 1 second stays consistent");

	now = 3500;
	check(&err, emdns_next(m, &now, buf, sizeof(buf)), sizeof(publish_msg) - 1, "resend message size");
	check_data(&err, buf, publish_msg, sizeof(publish_msg) - 1, "resend message data");

	check(&err, emdns_next(m, &now, buf, sizeof(buf)), EMDNS_PENDING, "second resend wait");
	check(&err, now, 5500, "second resend grows exponentially");

	// now see how we respond to requests
	const char request_msg[] =
		"\0\0" // transaction ID
		"\0\0" // flags - request
		"\0\x01" // questions - 1 question
		"\0\0" // answers
		"\0\0" // authority
		"\0\0" // additional
		"\x04" "test" "\x05" "local" "\0" // test.local.
		"\0\x1C" // 28 - AAAA record
		"\0\x01"; // internet class - QU not set

	// test that we correctly detect invalid messages with extra bytes at the end
	now = 4499;
	check(&err, emdns_process(m, now, request_msg, sizeof(request_msg)), EMDNS_MALFORMED, "detect requests with extra data");
	check(&err, emdns_process(m, now, request_msg, sizeof(request_msg) - 1), 0, "process request shortly after send");
	
	// now check that we don't want to send a response
	check(&err, emdns_next(m, &now, buf, sizeof(buf)), EMDNS_PENDING, "don't want to send shortly after send");
	check(&err, now, 5500, "resend stays the same");

	now = 4500;
	check(&err, emdns_process(m, now, request_msg, sizeof(request_msg) - 1), 0, "process request 1 second after last send");

	// now we should want to send a reply 20-120 ms later
	check(&err, emdns_next(m, &now, buf, sizeof(buf)), EMDNS_PENDING, "wait a bit until sending the response");
	check_range(&err, now, 4520, 4750, "wait a bit");

	now = 5000;
	check(&err, emdns_next(m, &now, buf, sizeof(buf)), sizeof(publish_msg) - 1, "response message size");
	check_data(&err, buf, publish_msg, sizeof(publish_msg) - 1, "response message data");

	// now the next standard publish should be pushed out
	check(&err, emdns_next(m, &now, buf, sizeof(buf)), EMDNS_PENDING, "wait for fourth announce");
	check(&err, now, 9000, "fourth announcement time");

	// check that we stop unsolicited announcements after the fourth
	check(&err, emdns_next(m, &now, buf, sizeof(buf)), sizeof(publish_msg) - 1, "fourth announcement size");
	check_data(&err, buf, publish_msg, sizeof(publish_msg) - 1, "fourth announcement data");
	check(&err, emdns_next(m, &now, buf, sizeof(buf)), EMDNS_PENDING, "no more announcements");
	check(&err, now, INT64_MAX, "wait is infinite");

	// request with different case, string checking should be case insensitive for the ascii alphabet

	const char request_uppercase[] =
		"\0\0" // transaction ID
		"\0\0" // flags - request
		"\0\x01" // questions - 1 question
		"\0\0" // answers
		"\0\0" // authority
		"\0\0" // additional
		"\x04" "TEST" "\x05" "local" "\0" // TEST.local.
		"\0\x1C" // 28 - AAAA record
		"\0\x01"; // internet class - QU not set

	now = 20000;
	check(&err, emdns_process(m, now, request_uppercase, sizeof(request_uppercase) - 1), 0, "process uppercase request");
	now = 20500;
	check(&err, emdns_next(m, &now, buf, sizeof(buf)), sizeof(publish_msg) - 1, "uppercase response");

	// check that we don't have any more sends planned
	now = 20500;
	check(&err, emdns_next(m, &now, buf, sizeof(buf)), EMDNS_PENDING, "wait after response");
	check(&err, now, INT64_MAX, "wait is infinite");

	emdns_free(m);
	return err;
}

int test_publish_service() {
	int err = 0;
	fprintf(stderr, "test_publish_service\n");

	struct emdns *m = emdns_new("test.local");
	check_not_null(&err, m, "init emdns");

	const char test_addr[16] = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10";
	struct in6_addr a;
	memcpy(&a, test_addr, 16);
	emdns_time now = 1000;
	emdns_publish_ip(m, now, AF_INET6, &a);

	emdns_free(m);
	return err;
}

