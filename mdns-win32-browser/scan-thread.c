#include "scan-thread.h"
#include <mdns.h>
#include <assert.h>

#ifdef _MSC_VER
#define strdup(a) _strdup(a)
#endif

#pragma comment(lib, "ws2_32.lib")

static HANDLE g_thread = INVALID_HANDLE_VALUE;
static HWND g_window;
static int g_interface_id;
static HANDLE g_stop_event;

static struct answer *create_answer(const char *name) {
	size_t u16len = MultiByteToWideChar(CP_UTF8, 0, name, -1, NULL, 0);
	struct answer *ret = (struct answer*) malloc(sizeof(struct answer) * u16len * 2);
	MultiByteToWideChar(CP_UTF8, 0, name, -1, ret->name, u16len);
	return ret;
}

static void service_update(void *udata, const char *name, const struct sockaddr_in6 *sa, const char *txt) {
	struct answer *a = create_answer(name);
	if (sa) {
		// txt is a string vector, find the end so we can copy it
		const char *txtend = txt;
		while (*txtend) {
			txtend += strlen(txtend) + 1;
		}
		a->text = (char*) malloc(txtend - txt + 1);
		memcpy(a->text, txt, txtend - txt + 1);
		memcpy(&a->addr, sa, sizeof(a->addr));
		PostMessage(g_window, MSG_ADD, (WPARAM) a, 0);
	} else {
		PostMessage(g_window, MSG_REMOVE, (WPARAM) a, 0);
	}
}

static DWORD WINAPI scan_thread(LPVOID param) {
	const char *svc = (char*) param;
	int fd = emdns_bind6(g_interface_id);
	if (fd < 0) {
		return 1;
	}

	HANDLE ev = WSACreateEvent();
	WSAEventSelect(fd, ev, FD_READ);

	struct emdns m = {0};
	emdns_scan_ip6(&m, (emdns_time) GetTickCount64(), svc, NULL, &service_update);

	for (;;) {
		char buf[1024];
		int timeout;
		for (;;) {
			emdns_time now = (emdns_time) GetTickCount64();
			emdns_time next = now;
			int w = emdns_next(&m, &next, buf, sizeof(buf));
			if (w == EMDNS_PENDING) {
				timeout = (int) (next - now);
				break;
			}
			send(fd, buf, w, 0);
		}

		HANDLE events[2] = {ev, g_stop_event};
		switch (WaitForMultipleObjects(2, events, FALSE, timeout)) {
		case WAIT_OBJECT_0:
			for (;;) {
				int w = recv(fd, buf, sizeof(buf), 0);
				if (w < 0) {
					break;
				}
				emdns_process(&m, (emdns_time) GetTickCount64(), buf, w);
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
