#include "tests.h"

static int my_udata;
static int err;
static int callback_called;

static const char *expected_name;
static const char *expected_ip;
static const char *expected_txt;
static uint16_t expected_port;

static void service_callback(void *udata, const char *name, int namesz, const struct sockaddr *sa, const char *txt, int txtsz) {
	struct sockaddr_in6 *sa6 = (struct sockaddr_in6*) sa;
	
	check(&err, (intptr_t) udata, (intptr_t) &my_udata, "correct user data in callback");
	check(&err, namesz, strlen(expected_name), "check service name length");
	check_data(&err, name, expected_name, strlen(expected_name), "check service name");
	if (expected_ip) {
		check(&err, sa->sa_family, AF_INET6, "check ipv6");
		check_data(&err, (char*) &sa6->sin6_addr, expected_ip, 16, "check service ip address");
		check(&err, ntohs(sa6->sin6_port), expected_port, "check service port");
		check(&err, txtsz, strlen(expected_txt), "check text size");
		check_data(&err, txt, expected_txt, strlen(expected_txt), "check text data");
	} else {
		check_null(&err, sa, "check no ip given");
		check_null(&err, txt, "check no txt given");
		check(&err, txtsz, 0, "check txt size");
	}

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

	check_range(&err, emdns_scan(m, now, "_http._tcp.local", &my_udata, &service_callback), 0, INT_MAX, "setup scan");

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

	check(&err, emdns_next(m, &now, buf, sizeof(buf)), sizeof(request_msg) - 1, "initial scan request size");
	check_data(&err, buf, request_msg, sizeof(request_msg) - 1, "initial scan request data");
	check(&err, emdns_next(m, &now, buf, sizeof(buf)), EMDNS_PENDING, "wait before second request");
	check(&err, now, 1000, "send next request one second later");

	now = 1000;
	check(&err, emdns_next(m, &now, buf, sizeof(buf)), sizeof(request_msg) - 1, "second scan request size");
	check_data(&err, buf, request_msg, sizeof(request_msg) - 1, "second scan request data");
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
		"\xFE\x80\0\0\0\0\0\0\x01\x02\x03\x04\x05\x06\x07\x08"; // IP address

	expected_name = "Mr. Service";
	expected_ip = "\xFE\x80\0\0\0\0\0\0\x01\x02\x03\x04\x05\x06\x07\x08";
	expected_txt = "\x0bkey1=value1\x0bkey2=value2";
	expected_port = 12345;

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

	// now try a response that doesn't come all in one message and out of order

	static const char response_part1[] =
		"\0\0" // transaction ID
		"\x84\0" // flags - authoritative response
		"\0\0" // questions
		"\0\x01" // answers - SRV
		"\0\0" // authority
		"\0\0" // additional
		// SRV additional
		"\x0E" "Second.Service" "\x05" "_Http" "\x04" "_tcp" "\x05" "local" "\0" // Mr. Service._http._tcp.local
		"\0\x21" // 33 - SRV record
		"\x80\x01" // internet class with flush
		"\0\0\0\x78" // TTL - 120 seconds
		"\0\x12" // data length
		"\0\0" // priority - 0
		"\0\0" // weight - 0
		"\x23\x7D" // port - 9085
		"\x04" "test" "\x05" "local" "\0"; // target - test.local

	static const char request_part1[] =
		"\0\0" // transaction ID
		"\0\0" // flags - request
		"\0\x03" // questions - SRV, TXT, & PTR
		"\0\x01" // answers - Mr. Service
		"\0\0" // authority
		"\0\0" // additional
		// SRV question
		"\x0E" "Second.Service" "\x05" "_http" "\x04" "_tcp" "\x05" "local" "\0"
		"\0\x21" // 33 - SRV record
		"\0\x01" // internet class - QU not set
		// TXT question
		"\xC0" "\x0C"
		"\0\x10" // 16 - TXT record
		"\0\x01" // internet class - QU not set
		// PTR question
		"\x05" "_http" "\x04" "_tcp" "\x05" "local" "\0" // _http._tcp.local.
		"\0\x0C" // 12 - PTR record
		"\0\x01" // internet class - QU not set
		// known answer
		"\xC0" "\x37" // <redir to ptr question>
		"\0\x0C" // 12 - PTR record
		"\0\x01" // internet class without flush
		"\0\0\0\x73" // TTL - 115 seconds - original response was at 2000, we are now at 7000
		"\0\x0E" // data length of 14 bytes
		"\x0B" "Mr. Service" "\xC0" "\x37"; // Mr. Service.<redir to ptr question>

	callback_called = 0;
	now = 5000;
	check(&err, emdns_process(m, now, response_part1, sizeof(response_part1) - 1), 0, "process part1");

	// jump forward to when we expect both the scan request and the request for the TXT
	now = 7000;
	check(&err, emdns_next(m, &now, buf, sizeof(buf)), sizeof(request_part1) - 1, "request part1 size");
	check_data(&err, buf, request_part1, sizeof(request_part1) - 1, "request part1 data");

	check(&err, emdns_next(m, &now, buf, sizeof(buf)), EMDNS_PENDING, "response part1 wait");
	check(&err, now, 8000, "resend service request in a second");

	static const char response_part2[] =
		"\0\0" // transaction ID
		"\x84\0" // flags - authoritative response
		"\0\0" // questions
		"\0\x02" // answers - PTR & TXT
		"\0\0" // authority
		"\0\0" // additional
		// PTR answer
		"\x05" "_http" "\x04" "_Tcp" "\x05" "local" "\0" // _http._tcp.local.
		"\0\x0C" // 12 - PTR record
		"\0\x01" // internet class - flush not set
		"\0\0\0\x78" // TTL - 0x78 = 120 seconds
		"\0\x11" // 17 bytes
		"\x0E" "Second.Service" "\xC0\x0C" // Mr. Service.<redir to ptr answer>
		// TXT additional
		"\xC0\x28" // redir to ptr target
		"\0\x10" // 16 - TXT record
		"\x80\x01" // internet class with flush
		"\0\0\0\x78" // TTL - 120 seconds
		"\0\x18" // data length
		"\x0B" "key3=value3" "\x0B" "key4=value4"; // txt data

	expected_name = "Second.Service";
	expected_ip = "\xFE\x80\0\0\0\0\0\0\x01\x02\x03\x04\x05\x06\x07\x08";
	expected_txt = "\x0bkey3=value3\x0bkey4=value4";
	expected_port = 9085;

	check(&err, callback_called, 0, "callback not yet called");
	check(&err, emdns_process(m, now, response_part2, sizeof(response_part2) - 1), 0, "process part2");
	check(&err, callback_called, 1, "callback 2 called");

	static const char response_part3[] =
		"\0\0" // transaction ID
		"\x84\0" // flags - authoritative response
		"\0\0" // questions
		"\0\x01" // answers - 1 answer - the PTR record
		"\0\0" // authority
		"\0\x05" // additional - TXT, IN, SRV, NSEC, NSEC
		// PTR answer
		"\x05" "_http" "\x04" "_Tcp" "\x05" "local" "\0" // _http._tcp.local.
		"\0\x0C" // 12 - PTR record
		"\0\x01" // internet class - flush not set
		"\0\0\x11\x94" // TTL - 4500 seconds
		"\0\x09" // 9 data bytes
		"\x06" "router" "\xC0" "\x0C" // router.<redir to ptr name>
		// TXT additional
		"\xC0\x28" // redir to ptr target
		"\0\x10" // 16 - TXT record
		"\x80\x01" // internet class with flush
		"\0\0\x11\x94" // TTL - 4500 seconds
		"\0\x01" // data length
		"\0" // empty text string
		// AAAA additional
		"\x06" "router" "\xC0\x17" // router.<redir to .local>
		"\0\x1C" // 28 - AAAA record
		"\x80\x01" // internet class with flush
		"\0\0\0\x78" // TTL - 120 seconds
		"\0\x10" // data length
		"\xFE\x80\0\0\0\0\0\0\x08\x07\x06\x05\x04\x03\x02\x01" // IP address
		// SRV additional
		"\xC0\x28" // redir to ptr target
		"\0\x21" // 33 - SRV record
		"\x80\x01" // internet class with flush
		"\0\0\0\x78" // TTL - 120 seconds
		"\0\x08" // data length
		"\0\0" // priority - 0
		"\0\0" // weight - 0
		"\0\x50" // port - 80
		"\xC0\x3E" // redir to aaaa name
		// NSEC
		"\xC0\x28" // redir to ptr target router._http._tcp.local
		"\0\x2f" // 48 - NSEC record
		"\x80\x01" // internet class with flush
		"\0\0\x11\x94" // TTL - 4500 seconds
		"\0\x09" // data length
		"\xC0\x28" // next domain - ptr target
		"\0\x05" // bit map length
		"\0\0\x80\0\x40" // bit map with TXT & SRV set
		// NSEC
		"\xC0\x3e" // redir to AAAA name router.local
		"\0\x2f" // 48 - NSEC record
		"\x80\x01" // internet class with flush
		"\0\0\x11\x94" // TTL - 4500 seconds
		"\0\x08" // data length
		"\xC0\x3e" // next domain - AAAA name
		"\0\x04" // bit map length
		"\0\0\0\x08"; // bit map with AAAA set

	// try an actual response from my mac
	expected_name = "router";
	expected_ip = "\xFE\x80\0\0\0\0\0\0\x08\x07\x06\x05\x04\x03\x02\x01";
	expected_txt = "";
	expected_port = 80;

	callback_called = 0;
	check(&err, emdns_process(m, now, response_part3, sizeof(response_part3) - 1), 0, "process part3");
	check(&err, callback_called, 1, "callback 3 called");

	static const char goaway_response[] =
		"\0\0" // transaction ID
		"\x84\0" // flags - authoritative response
		"\0\0" // questions
		"\0\x01" // answers - 1 answer - the PTR record
		"\0\0" // authority
		"\0\0" // additional
		// PTR answer
		"\x05" "_http" "\x04" "_Tcp" "\x05" "local" "\0" // _http._tcp.local.
		"\0\x0C" // 12 - PTR record
		"\0\x01" // internet class - flush not set
		"\0\0\0\0" // TTL - 0 seconds
		"\0\x09" // 9 data bytes
		"\x06" "router" "\xC0" "\x0C"; // router.<redir to ptr name>

	// make sure we handle goaway responses correctly

	expected_name = "router";
	expected_ip = NULL;
	expected_txt = NULL;
	expected_port = 0;

	callback_called = 0;
	now = 9000;
	check(&err, emdns_process(m, now, goaway_response, sizeof(goaway_response) - 1), 0, "process goaway");
	check(&err, callback_called, 0, "callback not called yet");
	check(&err, emdns_next(m, &now, buf, sizeof(buf)), EMDNS_PENDING, "wait for goaway expiry");
	check(&err, now, 10000, "wakeup in a second for expiry");

	now = 9500;
	check(&err, emdns_next(m, &now, buf, sizeof(buf)), EMDNS_PENDING, "wait 2 for goaway expiry");
	check(&err, now, 10000, "wakeup in a second for expiry");

	now = 10000;
	check(&err, emdns_next(m, &now, buf, sizeof(buf)), EMDNS_PENDING, "wait for next thing");
	check(&err, callback_called, 1, "goaway callback called");

	emdns_free(m);
	return err;
}
