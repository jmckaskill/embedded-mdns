#include <stdlib.h>

void *emdns_mem_realloc(void *data, size_t newsz) {
	return realloc(data, newsz);
}

void *emdns_mem_calloc(size_t newsz) {
	return calloc(1, newsz);
}

void emdns_mem_free(void *data) {
	free(data);
}
