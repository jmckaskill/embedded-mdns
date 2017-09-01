#include "tests.h"

static int my_udata;
static int err;
static int callback_called;

static void ip6_callback(void *udata, const struct in6_addr *addr) {
	static const uint8_t expected_ip[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

	check(&err, (intptr_t) udata, (intptr_t) &my_udata, "correct user data in callback");
	check_data(&err, (char*) addr, expected_ip, 16, "check service ip address");

	callback_called = 1;
}

int test_query() {
	char buf[1024];
	err = 0;
	callback_called = 0;
	fprintf(stderr, "test_query\n");

	struct emdns m = {0};

	emdns_time now = 0;
	check(&err, emdns_query_ip6(&m, now, "test.local", &my_udata, &ip6_callback), 0, "add ip6 query");

	static const char request_msg[] =
		"\0\0" // transaction ID
		"\0\0" // flags - request
		"\0\x01" // questions - one question
		"\0\0" // answers
		"\0\0" // authority
		"\0\0" // additional
		"\x04" "test" "\x05" "local" "\0" // test.local.
		"\0\x1C" // 28 - AAAA record
		"\0\x01"; // internet class - QU not set

	check(&err, emdns_next(&m, &now, buf, sizeof(buf)), sizeof(request_msg) - 1, "query message size");
	check_data(&err, buf, request_msg, sizeof(request_msg) - 1, "query message data");
	check(&err, emdns_next(&m, &now, buf, sizeof(buf)), EMDNS_PENDING, "wait to send next query");
	check(&err, now, 1000, "next query is a second later");

	now = 1000;
	check(&err, emdns_next(&m, &now, buf, sizeof(buf)), sizeof(request_msg) - 1, "next query size");
	check_data(&err, buf, request_msg, sizeof(request_msg) - 1, "next query data");

	static const char response_msg[] = 
		"\0\0" // transaction ID
		"\x84\0" // flags - response & authoritative
		"\0\0" // questions
		"\0\x01" // answers - one record
		"\0\0" // authority
		"\0\0" // additional
		"\x04" "test" "\x05" "local" "\0" // test.local.
		"\0\x1C" // 28 - AAAA record
		"\x80\x01" // internet class with the cache bit set
		"\0\0\0\x78" // TTL - 0x78 = 120 seconds
		"\0\x10" // data length 16 bytes
		"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"; // IP address

	now = 2000;
	check(&err, callback_called, 0, "callback not called yet");
	check(&err, emdns_process(&m, now, response_msg, sizeof(response_msg) - 1), 0, "process response");
	check(&err, callback_called, 1, "callback called");

	check(&err, emdns_next(&m, &now, buf, sizeof(buf)), EMDNS_PENDING, "no further sends");
	check(&err, now, INT64_MAX, "wait is infinite");

	now = 3000;
	callback_called = 0;
	check(&err, emdns_process(&m, now, response_msg, sizeof(response_msg) - 1), 0, "process second response");
	check(&err, callback_called, 0, "further responses are ignored");

	return err;
}
