#include <stdio.h>
#include "tests.h"


int main() {
	int errors = 0;
	errors += test_publish_ip6();
	errors += test_query();
	errors += test_scan();
	return errors;
}

