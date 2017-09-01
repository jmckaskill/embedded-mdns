#!/bin/sh

CFLAGS="-Wall -Werror -I libmdns -std=c99 -pedantic -Wno-missing-braces"

cc $CFLAGS -o mdns-scan.exe libmdns/*.c mdns-scan/*.c || exit 1
cc $CFLAGS -o emdns-test.exe libmdns/*.c emdns-test/*.c || exit 1
