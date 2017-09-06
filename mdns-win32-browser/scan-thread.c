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
static struct in_addr g_interface_ip;
static HANDLE g_stop_event;

static struct answer *create_answer(const char *name, int namesz) {
	int u16len = MultiByteToWideChar(CP_UTF8, 0, name, namesz, NULL, 0);
	struct answer *ret = (struct answer*) malloc(sizeof(struct answer) * (u16len+1) * 2);
	MultiByteToWideChar(CP_UTF8, 0, name, namesz, ret->name, u16len);
	ret->name[u16len] = L'\0';
	ret->text = NULL;
	return ret;
}

static void service_update(void *udata, const char *name, int namesz, const struct sockaddr *sa, int sasz, const char *txt, int txtsz) {
	struct answer *a = create_answer(name, namesz);
	if (sa && sasz <= sizeof(a->addr)) {
		a->text = (char*) malloc(txtsz+1);
		memcpy(a->text, txt, txtsz);
		a->text[txtsz] = '\0';
		memcpy(&a->addr, sa, sasz);
		PostMessage(g_window, MSG_ADD, (WPARAM) a, 0);
	} else {
		PostMessage(g_window, MSG_REMOVE, (WPARAM) a, 0);
	}
}

static DWORD WINAPI scan_thread(LPVOID param) {
	const char *svc = (char*) param;
	struct sockaddr_in send4;
	struct sockaddr_in6 send6;
	int fd6 = emdns_bind6(g_interface_id, &send6);
	if (fd6 < 0) {
		return 1;
	}
	int fd4 = emdns_bind4(g_interface_ip, &send4);
	if (fd4 < 0) {
		closesocket(fd6);
		return 1;
	}

	HANDLE ev4 = WSACreateEvent();
	HANDLE ev6 = WSACreateEvent();
	WSAEventSelect(fd4, ev4, FD_READ);
	WSAEventSelect(fd6, ev6, FD_READ);

	struct emdns *m = emdns_new("");
	emdns_scan(m, (emdns_time) GetTickCount64(), svc, NULL, &service_update);

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
			sendto(fd4, buf, w, 0, (struct sockaddr*) &send4, sizeof(send4));
			sendto(fd6, buf, w, 0, (struct sockaddr*) &send6, sizeof(send6));
		}

		HANDLE events[3] = {g_stop_event, ev4, ev6};
		DWORD ret = WSAWaitForMultipleEvents(3, events, FALSE, timeout, FALSE);
		switch (ret) {
		case WAIT_OBJECT_0+1: {
				WSANETWORKEVENTS netevents;
				if (!WSAEnumNetworkEvents(fd4, ev4, &netevents) && (netevents.lNetworkEvents & FD_READ)) {
					for (;;) {
						int w = recv(fd4, buf, sizeof(buf), 0);
						if (w < 0) {
							break;
						}
						emdns_process(m, (emdns_time) GetTickCount64(), buf, w);
					}
				}
			}
			break;
		case WAIT_OBJECT_0 + 2: {
				WSANETWORKEVENTS netevents;
				if (!WSAEnumNetworkEvents(fd6, ev6, &netevents) && (netevents.lNetworkEvents & FD_READ)) {
					for (;;) {
						int w = recv(fd6, buf, sizeof(buf), 0);
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
	CloseHandle(ev4);
	CloseHandle(ev6);
	closesocket(fd4);
	closesocket(fd6);
	emdns_free(m);

	return 0;
}

void start_scan_thread(HWND window, int interface_id, struct in_addr interface_ip, const char *svcname) {
	assert(g_thread == INVALID_HANDLE_VALUE);
	g_window = window;
	g_interface_id = interface_id;
	g_interface_ip = interface_ip;
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
