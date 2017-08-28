#include "scan-thread.h"
#include <mdns.h>
#include <assert.h>

#pragma comment(lib, "ws2_32.lib")

static HANDLE g_thread = INVALID_HANDLE_VALUE;
static HWND g_window;
static int g_interface_id;
static HANDLE g_stop_event;

static DWORD WINAPI scan_thread(LPVOID param) {
	const char *svc = (char*) param;
	int fd = emdns_bind6(g_interface_id);
	if (fd < 0) {
		return 1;
	}

	HANDLE ev = WSACreateEvent();
	WSAEventSelect(fd, ev, FD_READ);

	struct emdns m = {0};
	emdns_query_aaaa(&m, svc, NULL, NULL);

	for (;;) {
		int timeout;
		for (;;) {
			emdns_time now = (emdns_time) GetTickCount64();
			emdns_time next = now;
			char buf[1024];
			int w = emdns_next(&m, &next, buf, sizeof(buf));
			if (w == EMDNS_PENDING) {
				timeout = next - now;
				break;
			}
			send(fd, buf, w, 0);
		}

		HANDLE events[2] = {ev, g_stop_event};
		if (WaitForMultipleObjects(2, events, FALSE, timeout) == WAIT_OBJECT_0) {
			break;
		}
	}

	CloseHandle(ev);
	closesocket(fd);

	return 0;
}

void start_scan_thread(HWND window, int interface_id, const char *svcname) {
	assert(g_thread == INVALID_HANDLE_VALUE);
	g_window = window;
	g_interface_id = interface_id;
	g_stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
	g_thread = CreateThread(NULL, 0, &scan_thread, (LPVOID) svcname, 0, NULL);
}

void stop_scan_thread() {
	assert(g_thread != INVALID_HANDLE_VALUE);
	SetEvent(g_stop_event);
	WaitForSingleObject(g_thread, INFINITE);
	CloseHandle(g_thread);
	CloseHandle(g_stop_event);
	g_thread = INVALID_HANDLE_VALUE;
}
