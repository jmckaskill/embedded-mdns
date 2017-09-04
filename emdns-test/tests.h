#pragma once

#include "../emdns.h"
#include "../libmdns/emdns-impl.h"
#include <inttypes.h>
#include <string.h>
#include <stdio.h>

int test_publish_ip6();
int test_publish_service();
int test_query();
int test_scan();

static inline void check(int *err, int64_t have, int64_t want, const char *test) {
	fprintf(stderr, "  %s: ", test);
	if (have == want) {
		fprintf(stderr, "OK\n");
	} else {
		fprintf(stderr, "FAIL\n    Want: %" PRId64 "\n    Have: %" PRId64 "\n", want, have);
		(*err)++;
	}
}

static inline void check_not_null(int *err, const void *have, const char *test) {
	fprintf(stderr, "  %s: ", test);
	if (have) {
		fprintf(stderr, "OK\n");
	} else {
		fprintf(stderr, "FAIL\n    Want: Not NULL\n    Have: NULL\n");
		(*err)++;
	}
}

static inline void check_null(int *err, const void *have, const char *test) {
	fprintf(stderr, "  %s: ", test);
	if (!have) {
		fprintf(stderr, "OK\n");
	} else {
		fprintf(stderr, "FAIL\n    Want: NULL\n    Have: %p\n", have);
		(*err)++;
	}
}

static inline void check_range(int *err, int64_t have, int64_t min, int64_t max, const char *test) {
	fprintf(stderr, "  %s: ", test);
	if (min <= have && have <= max) {
		fprintf(stderr, "OK\n");
	} else {
		fprintf(stderr, "FAIL\n    Want: %" PRId64 " to %" PRId64 "\n    Have: %" PRId64 "\n", min, max, have);
		(*err)++;
	}
}

static inline void print_data(const char *data, size_t len) {
	for (size_t i = 0; i < len; i++) {
		if ((i & 2) == 0) {
			fputc(' ', stderr);
		}
		fprintf(stderr, "%02X", ((uint8_t*) data)[i]);
	}
}

static inline void check_data(int *err, const char *have, const char *want, size_t len, const char *test) {
	fprintf(stderr, "  %s: ", test);
	for (size_t i = 0; i < len; i++) {
		if (have[i] != want[i]) {
			fprintf(stderr, "FAIL\n    Want:");
			print_data(want, len);
			fprintf(stderr, "\n    Have:");
			print_data(have, len);
			fprintf(stderr, "\n");
			(*err)++;
			return;
		}
	}

	fprintf(stderr, "OK\n");
}

