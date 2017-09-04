#include "tests.h"

static int my_udata;
static int err;
static int callback_called;

static void service_callback(void *udata, const char *name, size_t namesz, const struct sockaddr_in6 *sa, const char *txt, size_t txtsz) {
	static const char expected_name[] = "Mr. Service";
	static const char expected_ip[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
	static const char expected_txt[] = "\x0bkey1=value1\x0bkey2=value2";
	uint16_t port = 12345;

	check(&err, (intptr_t) udata, (intptr_t) &my_udata, "correct user data in callback");
	check(&err, namesz, strlen(expected_name), "check service name length");
	check_data(&err, name, expected_name, strlen(expected_name), "check service name");
	check_data(&err, (char*) &sa->sin6_addr, expected_ip, 16, "check service ip address");
	check(&err, ntohs(sa->sin6_port), port, "check service port");
	check(&err, txtsz, sizeof(expected_txt) - 1, "check text size");
	check_data(&err, txt, expected_txt, sizeof(expected_txt), "check text data");

	callback_called = 1;
}

int test_scan() {
	char buf[1024];
	err = 0;
	callback_called = 0;
	fprintf(stderr, "test_scan\n");

	struct emdns *m = emdns_new("");
	check_not_null(&err, m, "new emdns");

	emdns_time now = 0;

	check(&err, emdns_scan_ip6(m, now, "_http._tcp.local", &my_udata, &service_callback), 0, "setup scan");

	static const char request_msg[] =
		"\0\0" // transaction ID
		"\0\0" // flags - request
		"\0\x01" // questions - one question
		"\0\0" // answers
		"\0\0" // authority
		"\0\0" // additional
		"\x05" "_http" "\x04" "_tcp" "\x05" "local" "\0" // _http._tcp.local.
		"\0\x0C" // 12 - PTR record
		"\0\x01"; // internet class - QU not set

	check(&err, emdns_next(m, &now, buf, sizeof(buf)), sizeof(request_msg) - 1, "initial scan request");
	check(&err, emdns_next(m, &now, buf, sizeof(buf)), EMDNS_PENDING, "wait before second request");
	check(&err, now, 1000, "send next request one second later");

	now = 1000;
	check(&err, emdns_next(m, &now, buf, sizeof(buf)), sizeof(request_msg) - 1, "second scan request");
	check(&err, emdns_next(m, &now, buf, sizeof(buf)), EMDNS_PENDING, "wait before third request");
	check(&err, now, 3000, "send next request two seconds later");

	static const char response_msg[] =
		"\0\0" // transaction ID
		"\x84\0" // flags - authoritative response
		"\0\0" // questions
		"\0\x01" // answers - 1 answer - the PTR record
		"\0\0" // authority
		"\0\x03" // additional - 3 records (AAAA, SRV & TXT)
		// PTR answer
		"\x05" "_http" "\x04" "_Tcp" "\x05" "local" "\0" // _http._tcp.local.
		"\0\x0C" // 12 - PTR record
		"\0\x01" // internet class - flush not set
		"\0\0\0\x78" // TTL - 0x78 = 120 seconds
		"\0\x0E" // 14 data bytes
		"\x0B" "Mr. Service" "\xC0" "\x0C" // Mr. Service.<redir to ptr answer>
		// SRV additional
		"\x0B" "Mr. Service" "\x05" "_Http" "\x04" "_tcp" "\x05" "local" "\0" // Mr. Service._http._tcp.local
		"\0\x21" // 33 - SRV record
		"\x80\x01" // internet class with flush
		"\0\0\0\x78" // TTL - 120 seconds
		"\0\x12" // data length
		"\0\0" // priority - 0
		"\0\0" // weight - 0
		"\x30\x39" // port - 12345
		"\x04" "test" "\x05" "local" "\0" // target - test.local
		// TXT additional
		"\x0B" "Mr. service" "\x05" "_http" "\x04" "_tcp" "\x05" "local" "\0" // Mr. Service._http._tcp.local
		"\0\x10" // 16 - TXT record
		"\x80\x01" // internet class with flush
		"\0\0\0\x78" // TTL - 120 seconds
		"\0\x18" // data length
		"\x0B" "key1=value1" "\x0B" "key2=value2" // txt data
		// AAAA additional
		"\x04" "tEst" "\x05" "local" "\0" // test.local
		"\0\x1C" // 28 - AAAA record
		"\x80\x01" // internet class with flush
		"\0\0\0\x78" // TTL - 120 seconds
		"\0\x10" // data length
		"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"; // IP address

	now = 2000;
	check(&err, callback_called, 0, "callback not called yet");
	check(&err, emdns_process(m, now, response_msg, sizeof(response_msg) - 1), 0, "process scan response");
	check(&err, callback_called, 1, "callback called");

	check(&err, emdns_next(m, &now, buf, sizeof(buf)), EMDNS_PENDING, "wait until next request");
	check(&err, now, 3000, "wait until next request");

	static const char known_answer[] =
		"\0\0" // transaction ID
		"\0\0" // flags - request
		"\0\x01" // questions - one question
		"\0\x01" // answers - one known answer
		"\0\0" // authority
		"\0\0" // additional
		"\x05" "_http" "\x04" "_tcp" "\x05" "local" "\0" // _http._tcp.local.
		"\0\x0C" // 12 - PTR record
		"\0\x01" // internet class - QU not set
		"\xC0" "\x0C" // <redir to ptr question>
		"\0\x0C" // 12 - PTR record
		"\0\x01" // internet class without flush
		"\0\0\0\x77" // TTL - 119 seconds - one second has passed since we got the original response
		"\0\x0E" // data length of 14 bytes
		"\x0B" "Mr. Service" "\xC0" "\x0C"; // Mr. Service.<redir to ptr question>

	now = 3000;
	check(&err, emdns_next(m, &now, buf, sizeof(buf)), sizeof(known_answer) - 1, "next scan with known answer");
	check_data(&err, buf, known_answer, sizeof(known_answer) - 1, "next scan data");

	check(&err, emdns_next(m, &now, buf, sizeof(buf)), EMDNS_PENDING, "wait for next scan");
	check(&err, now, 7000, "wait until next scan");
		

	emdns_free(m);
	return err;
}
