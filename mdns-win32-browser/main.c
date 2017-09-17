#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <io.h>
#include <Iphlpapi.h>
#include "../emdns.h"
#include "scan-thread.h"


struct text {
	const wchar_t *ENGLISH;
	const wchar_t *GERMAN;
};

static struct text STR_TITLE = {L"mDNS Browser", L"mDNS Browser"};
static struct text STR_SERVICE = {L"Service", L"Service"};
static struct text STR_INTERFACE = {L"Interface", L"Schnittstelle"};
static struct text STR_OPEN = {L"Open", L"Öffnen"};
static struct text STR_IP = {L"IP", L"IP"};
static struct text STR_PORT = {L"Port", L"Port"};
static struct text STR_WEB_UI = {L"Web UI (_http._tcp)", L"Web UI (_http._tcp)"};
static struct text STR_SSH = {L"SSH (_ssh._tcp)", L"SSH (_ssh._tcp)"};
static struct text STR_ERROR = {L"Error", L"Error"};
static struct text STR_NO_INTERFACES = {L"No valid interfaces found", L"No valid interfaces found"};
static struct text STR_PUTTY_ERROR = {L"Failed to launch PuTTY. Please check that it is installed and available in C:\\Program Files\\PuTTY"};

static int wfrom_hex(wchar_t ch) {
	if (L'0' <= ch && ch <= L'9') {
		return ch - L'0';
	} else if (L'a' <= ch && ch <= L'f') {
		return ch - L'a' + 10;
	} else if (L'A' <= ch && ch <= L'F') {
		return ch - L'A' + 10;
	} else {
		return -1;
	}
}

static const wchar_t *get_text(const struct text *text) {
	static int chosen_lang = -1;

	if (chosen_lang < 0) {
		wchar_t buf[256];
		unsigned long numlang, bufsz;
		GetUserPreferredUILanguages(MUI_LANGUAGE_ID, &numlang, buf, &bufsz);
		assert(bufsz == numlang * 5 + 1);

		for (unsigned long i = 0; i < numlang && chosen_lang < 0; i++) {
			int high = wfrom_hex(buf[i*5 + 2]);
			int low = wfrom_hex(buf[i*5 + 3]);
			if (high < 0 || low < 0) {
				continue;
			}

			int langid = (high << 4) | low;
			switch (langid) {
			case LANG_ENGLISH:
			case LANG_GERMAN:
				chosen_lang = langid;
				break;
			}
		}

		if (chosen_lang < 0) {
			chosen_lang = LANG_ENGLISH;
		}
	}

	switch (chosen_lang) {
	case LANG_GERMAN:
		return text->GERMAN ? text->GERMAN : text->ENGLISH;
	default:
		return text->ENGLISH;
	}
}

struct control {
	HWND h;
	int x, y, cx, cy;
};

#define MAX_INTERFACES 16

enum service_type {
	HTTP,
	SSH,
	NUM_SERVICES,
};

struct service {
	struct text *text;
	const char *svcname;
};

static const struct service g_services[] = {
	{&STR_WEB_UI, "_http._tcp.local"},
	{&STR_SSH, "_ssh._tcp.local"},
};


struct mdns_browser {
	HWND window;
	HINSTANCE instance;
	struct control label_ip;
	struct control label_port;
	struct control static_ip;
	struct control static_port;
	struct control button_open;
	struct control label_service;
	struct control label_interface;
	struct control list_nodes;
	struct control combo_service;
	struct control combo_interface;
	
	enum service_type cur_service;
	int cur_interface_id;
	struct in_addr cur_interface_ip;
	int interface_num;
	int interface_ids[MAX_INTERFACES];
};

#define IDC_LABEL 0
#define IDC_SERVICE 1
#define IDC_INTERFACE 2
#define IDC_LIST 3
#define IDC_IP 4
#define IDC_PORT 5
#define IDC_OPEN 6

static SIZE size_max(SIZE a, SIZE b) {
	SIZE ret;
	ret.cx = a.cx > b.cx ? a.cx : b.cx;
	ret.cy = a.cy > b.cy ? a.cy : b.cy;
	return ret;
}

static void set_position(struct control *c, SIZE topleft, SIZE size) {
	c->x = topleft.cx;
	c->y = topleft.cy;
	c->cx = size.cx;
	c->cy = size.cy;
}

static void update_position(struct control *c) {
	SetWindowPos(c->h, HWND_TOP, c->x, c->y, c->cx, c->cy, 0);
}

static SIZE get_text_size(HDC dc, const wchar_t *str, int xpad, int ypad) {
	SIZE sz;
	GetTextExtentPoint32(dc, str, (int) wcslen(str), &sz);
	sz.cx += xpad * 2;
	sz.cy += ypad * 2;
	return sz;
}

static void apply_padding(struct control *c, int xpad, int ypad) {
	c->x += xpad;
	c->cx -= 2*xpad;
	c->y += ypad;
	c->cy -= 2*ypad;
}

static void compute_positions(struct mdns_browser *b, int wincx, int wincy) {
	HDC dc = GetDC(b->window);

	// work from the top down for the rows of combo boxes
	SIZE service_size = get_text_size(dc, get_text(&STR_SERVICE), 5, 5);
	SIZE interface_size = get_text_size(dc, get_text(&STR_INTERFACE), 5, 5);
	SIZE key_size = size_max(service_size, interface_size);

	// note the combo box size needs to include the room for the dropdown
	SIZE combo_size = {wincx - key_size.cx, 5*key_size.cy};

	SIZE key_pos = {0,0};
	SIZE combo_pos = {key_size.cx, 0};

	set_position(&b->label_service, key_pos, key_size);
	set_position(&b->combo_service, combo_pos, combo_size);

	key_pos.cy += key_size.cy;
	combo_pos.cy += key_size.cy;
	
	set_position(&b->label_interface, key_pos, key_size);
	set_position(&b->combo_interface, combo_pos, combo_size);

	key_pos.cy += key_size.cy;

	SIZE list_pos = key_pos;

	// now work from the bottom up to figure out the results panel

	// first the open button
	SIZE open_size = get_text_size(dc, get_text(&STR_OPEN), 10, 10);
	SIZE open_pos = {wincx - open_size.cx, wincy - open_size.cy};
	set_position(&b->button_open, open_pos, open_size);

	SIZE ip_size = get_text_size(dc, L"IP", 5, 5);
	SIZE port_size = get_text_size(dc, L"Port", 5, 5);
	SIZE label_size = size_max(ip_size, port_size);

	SIZE field_size = {wincx - open_size.cx - label_size.cx, label_size.cy};
	SIZE label_pos = {0, wincy - label_size.cy};
	SIZE field_pos = {label_size.cx, label_pos.cy};

	set_position(&b->label_port, label_pos, label_size);
	set_position(&b->static_port, field_pos, field_size);

	label_pos.cy -= label_size.cy;
	field_pos.cy -= field_size.cy;

	set_position(&b->label_ip, label_pos, label_size);
	set_position(&b->static_ip, field_pos, field_size);

	// now we can take the difference of the bottom panel and the top to get the services list
	SIZE list_size = {wincx, label_pos.cy - list_pos.cy};
	set_position(&b->list_nodes, list_pos, list_size);

	apply_padding(&b->label_service, 5, 5);
	apply_padding(&b->combo_service, 5, 5);
	apply_padding(&b->label_interface, 5, 5);
	apply_padding(&b->combo_interface, 5, 5);
	apply_padding(&b->list_nodes, 5, 5);
	apply_padding(&b->label_ip, 5, 5);
	apply_padding(&b->static_ip, 5, 5);
	apply_padding(&b->label_port, 5, 5);
	apply_padding(&b->static_port, 5, 5);
	apply_padding(&b->button_open, 5, 5);
}

static void update_positions(struct mdns_browser *b) {
	update_position(&b->label_service);
	update_position(&b->combo_service);
	update_position(&b->label_interface);
	update_position(&b->combo_interface);
	update_position(&b->list_nodes);
	update_position(&b->label_ip);
	update_position(&b->static_ip);
	update_position(&b->label_port);
	update_position(&b->static_port);
	update_position(&b->button_open);
}

static int on_interface(void *udata, const struct emdns_interface *iface) {
	struct mdns_browser *b = (struct mdns_browser*) udata;
	if (b->interface_num == MAX_INTERFACES || !iface->ip6_num) {
		return 0;
	}

	wchar_t buf[256];
	_snwprintf(buf, sizeof(buf), L"%s (%s)", iface->name, iface->description);
	buf[sizeof(buf) / sizeof(buf[0]) - 1] = L'\0';
	b->interface_ids[b->interface_num] = iface->id;
	SendMessageW(b->combo_interface.h, CB_ADDSTRING, 0, (LPARAM) buf);

	b->interface_num++;
	return 0;
}

static int lookup_interface_ip(void *udata, const struct emdns_interface *iface) {
	struct mdns_browser *b = (struct mdns_browser*) udata;
	if (iface->id != b->cur_interface_id) {
		return 0;
	}
	if (!iface->ip4) {
		return -1;
	}
	b->cur_interface_ip = *iface->ip4;
	return 0;
}

static void add_services(struct mdns_browser *b) {
	for (int i = 0; i < NUM_SERVICES; i++) {
		ComboBox_AddString(b->combo_service.h, get_text(g_services[i].text));
	}
}

static void create_control(struct mdns_browser *b, struct control *c, LPCWSTR ClassName, LPCWSTR Text, DWORD style, int idc) {
	c->h = CreateWindowW(ClassName, Text, style | WS_CHILD, c->x, c->y, c->cx, c->cy, b->window, (HMENU) (uintptr_t) idc, b->instance, NULL);
}

static int append_ip(wchar_t *buf, int bufsz, struct sockaddr *sa, int interface_id) {
	switch (sa->sa_family) {
	case AF_INET: {
			struct sockaddr_in *sa4 = (struct sockaddr_in*) sa;
			InetNtopW(AF_INET, &sa4->sin_addr, buf, bufsz);
			return (int) wcslen(buf);
		}
	case AF_INET6: {
			struct sockaddr_in6 *sa6 = (struct sockaddr_in6*) sa;
			InetNtopW(AF_INET6, &sa6->sin6_addr, buf, bufsz);
			// now convert to UNC version, replace : with -
			wchar_t *p;
			for (p = buf; *p; p++) {
				if (*p == ':') { 
					*p = '-';
				}
			}
			p += swprintf(p, buf + bufsz - p, L"s%d.ipv6-literal.net", interface_id);
			return (int) (p - buf);
		}
	default:
		assert(0);
		return 0;
	}
}

static void start_scan(struct mdns_browser *b) {
	int ifidx = ComboBox_GetCurSel(b->combo_interface.h);
	assert(ifidx < b->interface_num);
	int svcidx = ComboBox_GetCurSel(b->combo_service.h);
	b->cur_interface_id = b->interface_ids[ifidx];
	b->cur_service = (enum service_type) svcidx;
	if (!emdns_lookup_interfaces(b, &lookup_interface_ip)) {
		start_scan_thread(b->window, b->cur_interface_id, b->cur_interface_ip, g_services[b->cur_service].svcname);
	}
}

static void stop_scan(struct mdns_browser *b) {
	stop_scan_thread();
	int num = ListBox_GetCount(b->list_nodes.h);
	for (int i = 0; i < num; i++) {
		struct answer *a = (struct answer*) ListBox_GetItemData(b->list_nodes.h, i);
		free(a->text);
		free(a);
	}
	ListBox_ResetContent(b->list_nodes.h);
}

static void check_ip(struct mdns_browser *b) {
	struct in_addr ip = b->cur_interface_ip;
	if (!emdns_lookup_interfaces(b, &lookup_interface_ip) && ip.s_addr != b->cur_interface_ip.s_addr) {
		stop_scan(b);
		start_scan_thread(b->window, b->cur_interface_id, b->cur_interface_ip, g_services[b->cur_service].svcname);
	}
}

static DWORD WINAPI interface_watcher(void* param) {
	HWND window = (HWND) param;
	HANDLE h = NULL;
	OVERLAPPED ol;
	ol.hEvent = WSACreateEvent();
	if (NotifyAddrChange(&h, &ol) != NO_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
		CloseHandle(ol.hEvent);
		return 1;
	}

	while (WaitForSingleObject(ol.hEvent, INFINITE) == WAIT_OBJECT_0) {
		PostMessage(window, MSG_IFACE_CHANGE, 0, 0);
	}

	CloseHandle(ol.hEvent);
	return 0;
}

LRESULT CALLBACK browser_wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
	static struct mdns_browser b = {0};

	switch (msg) {
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	case WM_CREATE: {
			CREATESTRUCT *cs = (CREATESTRUCT*) lparam;
			b.window = hwnd;
			b.instance = cs->hInstance;
			compute_positions(&b, cs->cx, cs->cy);

			create_control(&b, &b.label_interface, WC_STATICW, get_text(&STR_INTERFACE), WS_VISIBLE, IDC_LABEL);
			create_control(&b, &b.combo_interface, WC_COMBOBOXW, NULL, WS_VISIBLE | CBS_DROPDOWNLIST | CBS_HASSTRINGS, IDC_INTERFACE);

			create_control(&b, &b.label_service, WC_STATICW, get_text(&STR_SERVICE), WS_VISIBLE, IDC_LABEL);
			create_control(&b, &b.combo_service, WC_COMBOBOXW, NULL, WS_VISIBLE | CBS_DROPDOWNLIST | CBS_HASSTRINGS, IDC_SERVICE);

			create_control(&b, &b.list_nodes, WC_LISTBOXW, NULL, WS_VISIBLE | LBS_NOTIFY, IDC_LIST);

			create_control(&b, &b.label_ip, WC_STATICW, get_text(&STR_IP), WS_VISIBLE, IDC_LABEL);
			create_control(&b, &b.static_ip, WC_STATICW, NULL, WS_VISIBLE, IDC_IP);

			create_control(&b, &b.label_port, WC_STATICW, get_text(&STR_PORT), WS_VISIBLE, IDC_LABEL);
			create_control(&b, &b.static_port, WC_STATICW, NULL, WS_VISIBLE, IDC_PORT);

			create_control(&b, &b.button_open, WC_BUTTONW, get_text(&STR_OPEN), WS_VISIBLE, IDC_OPEN);

			add_services(&b);

			if (emdns_lookup_interfaces(&b, &on_interface) || !b.interface_num) {
				MessageBoxW(hwnd, get_text(&STR_NO_INTERFACES), get_text(&STR_ERROR), MB_OK);
				PostQuitMessage(1);
				break;
			}

			ComboBox_SetCurSel(b.combo_interface.h, 0);
			ComboBox_SetCurSel(b.combo_service.h, 0);
			start_scan(&b);
			HANDLE h =CreateThread(NULL, 0, &interface_watcher, hwnd, 0, NULL);
			CloseHandle(h);
			break;
		}
	case WM_COMMAND:
		if (HIWORD(wparam) == LBN_SELCHANGE && LOWORD(wparam) == IDC_LIST) {
			int idx = ListBox_GetCurSel(b.list_nodes.h);
			struct answer *a = (struct answer*) ListBox_GetItemData(b.list_nodes.h, idx);

			wchar_t ip[128], port[32];

			switch (a->addr.h.sa_family) {
			case AF_INET:
				InetNtopW(AF_INET, &a->addr.ip4.sin_addr, ip, sizeof(ip));
				swprintf(port, sizeof(port), L"%d", ntohs(a->addr.ip4.sin_port));
				break;
			case AF_INET6:
				InetNtopW(AF_INET6, &a->addr.ip6.sin6_addr, ip, sizeof(ip));
				swprintf(ip + wcslen(ip), sizeof(ip) - wcslen(ip), L"%%%d", b.cur_interface_id);
				swprintf(port, sizeof(port), L"%d", ntohs(a->addr.ip6.sin6_port));
				break;
			default:
				assert(0);
				ip[0] = 0;
				port[0] = 0;
				break;
			}

			SetWindowTextW(b.static_ip.h, ip);
			SetWindowTextW(b.static_port.h, port);

		} else if ((HIWORD(wparam) == LBN_DBLCLK && LOWORD(wparam) == IDC_LIST) || (HIWORD(wparam) == BN_CLICKED && LOWORD(wparam) == IDC_OPEN)) {
			int idx = ListBox_GetCurSel(b.list_nodes.h);
			struct answer *a = (struct answer*) ListBox_GetItemData(b.list_nodes.h, idx);
			assert(a != NULL);
			wchar_t buf[512];
			int sz = 0;
			uint16_t port = ntohs(a->addr.h.sa_family == AF_INET6 ? a->addr.ip6.sin6_port : a->addr.ip4.sin_port);

			switch (b.cur_service) {
			case HTTP:
				sz += swprintf(buf+sz, sizeof(buf)-sz, L"http://");
				sz += append_ip(buf+sz, sizeof(buf)-sz, &a->addr.h, b.cur_interface_id);
				if (port != 80) {
					sz += swprintf(buf+sz, sizeof(buf)-sz, L":%d", port);
				}
				ShellExecuteW(b.window, NULL, buf, NULL, NULL, SW_SHOW);
				break;
			case SSH:
				sz += swprintf(buf+sz, sizeof(buf)-sz, L"-ssh ");
				if (port != 22) {
					sz += swprintf(buf+sz, sizeof(buf)-sz, L"-P %d ", port);
				}
				sz += append_ip(buf+sz, sizeof(buf)-sz, &a->addr.h, b.cur_interface_id);
				if ((int) (uintptr_t) ShellExecuteW(b.window, NULL, L"C:\\Program Files\\PuTTY\\putty.exe", buf, NULL, SW_SHOW) < 32) {
					MessageBoxW(hwnd, get_text(&STR_PUTTY_ERROR), get_text(&STR_ERROR), MB_OK);
				}
				break;
			default:
				break;
			}
			
		} else if (HIWORD(wparam) == CBN_SELCHANGE && (LOWORD(wparam) == IDC_INTERFACE || LOWORD(wparam) == IDC_SERVICE)) {
			stop_scan(&b);
			start_scan(&b);
		}
		break;
	case WM_SIZE:
		if (wparam != SIZE_MINIMIZED) {
			compute_positions(&b, LOWORD(lparam), HIWORD(lparam));
			update_positions(&b);
		}
		break;
	case MSG_ADD: {
			struct answer *a = (struct answer*) wparam;
			int idx = ListBox_FindString(b.list_nodes.h, 0, a->name);
			if (idx == LB_ERR) {
				idx = ListBox_AddString(b.list_nodes.h, a->name);
			}
			ListBox_SetItemData(b.list_nodes.h, idx, a);
			break;
		}
	case MSG_REMOVE: {
			struct answer *a = (struct answer*) wparam;
			int idx = ListBox_FindString(b.list_nodes.h, 0, a->name);
			if (idx != LB_ERR) {
				struct answer *a = (struct answer*) ListBox_GetItemData(b.list_nodes.h, idx);
				free(a->text);
				free(a);
				ListBox_DeleteString(b.list_nodes.h, idx);
			}
			free(a);
			break;
		}
	case MSG_IFACE_CHANGE:
		check_ip(&b);
		break;
	}

	return DefWindowProcW(hwnd, msg, wparam, lparam);
}

int WINAPI wWinMain(HINSTANCE hinst, HINSTANCE previnst, PWSTR cmdline, int nCmdShow) {

	WNDCLASSW wc = {0};
	wc.lpszClassName = L"MDNSBrowser";
	wc.hInstance = hinst;
	wc.hbrBackground = GetSysColorBrush(COLOR_3DFACE);
	wc.lpfnWndProc = &browser_wndproc;
	wc.hCursor = LoadCursor(0, IDC_ARROW);
	RegisterClassW(&wc);

	CreateWindowW(wc.lpszClassName, get_text(&STR_TITLE), WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 400, 300, NULL, 0, hinst, NULL);

	MSG msg;
	while (GetMessageW(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	return (int) msg.wParam;
}
