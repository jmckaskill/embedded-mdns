#pragma once

#include <string.h>

static void swap_byte(void* a, void* b, size_t count) {
	char* x = (char*) a;
	char* y = (char*) b;

	while (count--) {
		char t = *x; *x = *y; *y = t;
		x += 1;
		y += 1;
	}
}

static void swap_word(void* a, void* b, size_t count) {
	char* x = (char*) a;
	char* y = (char*) b;
	long t[1];

	while (count--) {
		memcpy(t, x, sizeof(long));
		memcpy(x, y, sizeof(long));
		memcpy(y, t, sizeof(long));
		x += sizeof(long);
		y += sizeof(long);
	}
}

void memswap(void* a, void* b, size_t size) {
	size_t words = size / sizeof(long);
	size_t bytes = size % sizeof(long);
	swap_word(a, b, words);
	a = (char*) a + words * sizeof(long);
	b = (char*) b + words * sizeof(long);
	swap_byte(a, b, bytes);
}
