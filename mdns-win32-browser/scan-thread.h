#pragma once

#include <winsock2.h>
#include <WS2tcpip.h>
#include <windows.h>

struct answer {
	union {
		struct sockaddr h;
		struct sockaddr_in6 ip6;
		struct sockaddr_in ip4;
	} addr;
	char *text;
	wchar_t name[1];
};

#define MSG_ADD WM_USER
#define MSG_REMOVE (WM_USER + 1)

// svcname must point to a string that persists until the scan thread is stopped
void start_scan_thread(HWND window, int interface_id, struct in_addr interface_ip, const char *svcname);
void stop_scan_thread();
