#include "scan-thread.h"
#include "../emdns.h"
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>

#ifdef _MSC_VER
#define strdup(a) _strdup(a)
#endif

#pragma comment(lib, "ws2_32.lib")

static HANDLE g_thread = INVALID_HANDLE_VALUE;
static HWND g_window;
static int g_interface_id;
static HANDLE g_stop_event;

static struct answer *create_answer(const char *name, int namesz) {
	int u16len = MultiByteToWideChar(CP_UTF8, 0, name, namesz, NULL, 0);
	struct answer *ret = (struct answer*) malloc(sizeof(struct answer) * (u16len+1) * 2);
	MultiByteToWideChar(CP_UTF8, 0, name, namesz, ret->name, u16len);
	ret->name[u16len] = L'\0';
	ret->text = NULL;
	return ret;
}

static void service_update(void *udata, const char *name, int namesz, const struct sockaddr_in6 *sa, const char *txt, int txtsz) {
	struct answer *a = create_answer(name, namesz);
	if (sa) {
		a->text = (char*) malloc(txtsz+1);
		memcpy(a->text, txt, txtsz);
		a->text[txtsz] = '\0';
		memcpy(&a->addr, sa, sizeof(a->addr));
		PostMessage(g_window, MSG_ADD, (WPARAM) a, 0);
	} else {
		PostMessage(g_window, MSG_REMOVE, (WPARAM) a, 0);
	}
}

static void log(const char *fmt, ...) {
	char buf[512];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	OutputDebugStringA(buf);
}

static DWORD WINAPI scan_thread(LPVOID param) {
	const char *svc = (char*) param;
	struct sockaddr_in6 send_addr;
	int fd = emdns_bind6(g_interface_id, &send_addr);
	if (fd < 0) {
		return 1;
	}

	HANDLE ev = WSACreateEvent();
	WSAEventSelect(fd, ev, FD_READ);

	struct emdns *m = emdns_new("");
	emdns_scan_ip6(m, (emdns_time) GetTickCount64(), svc, NULL, &service_update);

	for (;;) {
		char buf[1024];
		int timeout;
		for (;;) {
			emdns_time now = (emdns_time) GetTickCount64();
			emdns_time next = now;
			int w = emdns_next(m, &next, buf, sizeof(buf));
			if (w == EMDNS_PENDING) {
				timeout = (int) (next - now);
				break;
			}
			sendto(fd, buf, w, 0, (struct sockaddr*) &send_addr, sizeof(send_addr));
		}

		HANDLE events[2] = {ev, g_stop_event};
		DWORD ret = WSAWaitForMultipleEvents(2, events, FALSE, timeout, FALSE);
		switch (ret) {
		case WAIT_OBJECT_0: {
				WSANETWORKEVENTS netevents;
				if (!WSAEnumNetworkEvents(fd, ev, &netevents) && (netevents.lNetworkEvents & FD_READ)) {
					for (;;) {
						int w = recv(fd, buf, sizeof(buf), 0);
						log("recv %d\n", w);
						if (w < 0) {
							break;
						}
						emdns_process(m, (emdns_time) GetTickCount64(), buf, w);
					}
				}
			}
			break;
		case WAIT_TIMEOUT:
			break;
		default:
			goto end;
		}
	}

end:
	CloseHandle(ev);
	closesocket(fd);
	emdns_free(m);

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
