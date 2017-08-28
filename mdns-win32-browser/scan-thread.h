#pragma once

#include <winsock2.h>
#include <WS2tcpip.h>
#include <windows.h>

struct answer {
	struct sockaddr_in6 addr;
	wchar_t name[1];
};

#define MSG_ADD WM_USER
#define MSG_REMOVE (WM_USER + 1)

// svcname must point to a string that persists until the scan thread is stopped
void start_scan_thread(HWND window, int interface_id, const char *svcname);
void stop_scan_thread();
