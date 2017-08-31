#include <stdio.h>
#include "tests.h"


int main() {
	int errors = 0;
	errors += test_publish_ip6();
	return errors;
}

