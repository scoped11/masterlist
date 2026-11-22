#include "pz_menu.h"
#include "pz_config.h"
#include "pz_game.h"
#include "pz_webserver.h"
#include "pz_overlay.h"
#include "pz_log.h"
#include <cstdio>
#include <cstring>

enum Ctrl : int
{
	IDC_WEB = 101,
	IDC_OVERLAY,
	IDC_NAMES,
	IDC_DIST,
	IDC_POLL,
	IDC_SRC_FIXTURE,
	IDC_SRC_TELEMETRY,
	IDC_SRC_EXTERNAL,
	IDC_APPLY_POLL
};

static HWND g_pollEdit = nullptr;
static bool g_webOn = false;
static bool g_overlayOn = false;

static void EnsureWeb(bool on)
{
	if (on && !g_webOn) { if (PzWeb::Start()) g_webOn = true; }
	else if (!on && g_webOn) { PzWeb::Stop(); g_webOn = false; }
}

static void EnsureOverlay(bool on)
{
	if (on && !g_overlayOn) { if (PzOverlay::Start()) g_overlayOn = true; }
	else if (!on && g_overlayOn) { PzOverlay::Stop(); g_overlayOn = false; }
}

static void OnSourceChanged(DataSource src)
{
	PzConfig::dataSource = src;
	PzConfig::useMock = (src == DataSource::FixtureMock);
}

static LRESULT CALLBACK MenuWndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
	switch (msg)
	{
	case WM_CREATE:
	{
		int y = 10;
		CreateWindowA("BUTTON", "Web radar (port 8880)", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
			10, y, 260, 22, h, (HMENU)IDC_WEB, nullptr, nullptr);
		y += 28;
		CreateWindowA("BUTTON", "Overlay player list", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
			10, y, 260, 22, h, (HMENU)IDC_OVERLAY, nullptr, nullptr);
		y += 28;
		CreateWindowA("BUTTON", "Show names", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
			10, y, 120, 22, h, (HMENU)IDC_NAMES, nullptr, nullptr);
		CreateWindowA("BUTTON", "Show distances", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
			140, y, 130, 22, h, (HMENU)IDC_DIST, nullptr, nullptr);
		y += 32;
		CreateWindowA("STATIC", "Poll interval (ms):", WS_VISIBLE | WS_CHILD,
			10, y, 120, 18, h, nullptr, nullptr, nullptr);
		g_pollEdit = CreateWindowA("EDIT", "250", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER,
			130, y - 2, 60, 22, h, (HMENU)IDC_POLL, nullptr, nullptr);
		CreateWindowA("BUTTON", "Apply", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
			200, y - 2, 60, 22, h, (HMENU)IDC_APPLY_POLL, nullptr, nullptr);
		y += 34;
		CreateWindowA("STATIC", "Data source:", WS_VISIBLE | WS_CHILD, 10, y, 240, 18, h, nullptr, nullptr, nullptr);
		y += 20;
		CreateWindowA("BUTTON", "Fixture / mock", WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON | WS_GROUP,
			10, y, 240, 20, h, (HMENU)IDC_SRC_FIXTURE, nullptr, nullptr);
		y += 22;
		CreateWindowA("BUTTON", "Server mod telemetry file", WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON,
			10, y, 240, 20, h, (HMENU)IDC_SRC_TELEMETRY, nullptr, nullptr);
		y += 22;
		CreateWindowA("BUTTON", "External read-only (needs offsets)", WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON,
			10, y, 260, 20, h, (HMENU)IDC_SRC_EXTERNAL, nullptr, nullptr);
		PzMenu::SyncControlsFromConfig();
		return 0;
	}
	case WM_COMMAND:
	{
		const int id = LOWORD(wp);
		const int code = HIWORD(wp);
		if (code == BN_CLICKED)
		{
			if (id == IDC_APPLY_POLL)
			{
				char buf[32] = {};
				GetWindowTextA(g_pollEdit, buf, sizeof(buf) - 1);
				int v = atoi(buf);
				if (v < 50) v = 50;
				if (v > 5000) v = 5000;
				PzConfig::pollMs = v;
				PZ_LOG("poll interval → %d ms", v);
				return 0;
			}
			if (id == IDC_SRC_FIXTURE || id == IDC_SRC_TELEMETRY || id == IDC_SRC_EXTERNAL)
			{
				if (id == IDC_SRC_FIXTURE) OnSourceChanged(DataSource::FixtureMock);
				else if (id == IDC_SRC_TELEMETRY) OnSourceChanged(DataSource::ServerTelemetryFile);
				else OnSourceChanged(DataSource::ExternalReadOnly);
				PZ_LOG("data source → %d", (int)PzConfig::dataSource);
				return 0;
			}
		}
		if (code == BN_CLICKED || (code == 0 && (wp == IDC_WEB || wp == IDC_OVERLAY || wp == IDC_NAMES || wp == IDC_DIST)))
		{
			// BN_CLICKED for checkboxes on click
		}
		if (id == IDC_WEB && (code == BN_CLICKED))
		{
			PzConfig::webRadarEnabled = (SendMessage(GetDlgItem(h, IDC_WEB), BM_GETCHECK, 0, 0) == BST_CHECKED);
			EnsureWeb(PzConfig::webRadarEnabled);
		}
		else if (id == IDC_OVERLAY && code == BN_CLICKED)
		{
			PzConfig::overlayEnabled = (SendMessage(GetDlgItem(h, IDC_OVERLAY), BM_GETCHECK, 0, 0) == BST_CHECKED);
			EnsureOverlay(PzConfig::overlayEnabled);
		}
		else if (id == IDC_NAMES && code == BN_CLICKED)
			PzConfig::showNames = (SendMessage(GetDlgItem(h, IDC_NAMES), BM_GETCHECK, 0, 0) == BST_CHECKED);
		else if (id == IDC_DIST && code == BN_CLICKED)
			PzConfig::showDistances = (SendMessage(GetDlgItem(h, IDC_DIST), BM_GETCHECK, 0, 0) == BST_CHECKED);
		PzOverlay::Invalidate();
		return 0;
	}
	case WM_CLOSE:
		ShowWindow(h, SW_HIDE);
		return 0;
	case WM_DESTROY:
		EnsureWeb(false);
		EnsureOverlay(false);
		return 0;
	default:
		break;
	}
	return DefWindowProc(h, msg, wp, lp);
}

bool PzMenu::Start(HINSTANCE inst)
{
	if (hwnd) return true;
	WNDCLASSA wc{};
	wc.lpfnWndProc = MenuWndProc;
	wc.hInstance = inst;
	wc.lpszClassName = "PzViewerMenu";
	wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
	RegisterClassA(&wc);
	hwnd = CreateWindowExA(0, "PzViewerMenu", "pz_viewer — display menu (viewer only)",
		WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
		80, 80, 320, 320, nullptr, nullptr, inst, nullptr);
	if (!hwnd) return false;
	ShowWindow(hwnd, SW_SHOW);
	running = true;
	PZ_LOG("menu window open — toggles affect viewer display only");
	return true;
}

void PzMenu::Stop()
{
	if (hwnd) DestroyWindow(hwnd);
	hwnd = nullptr;
	running = false;
}

void PzMenu::SyncControlsFromConfig()
{
	if (!hwnd) return;
	SendDlgItemMessageA(hwnd, IDC_WEB, BM_SETCHECK, PzConfig::webRadarEnabled ? BST_CHECKED : BST_UNCHECKED, 0);
	SendDlgItemMessageA(hwnd, IDC_OVERLAY, BM_SETCHECK, PzConfig::overlayEnabled ? BST_CHECKED : BST_UNCHECKED, 0);
	SendDlgItemMessageA(hwnd, IDC_NAMES, BM_SETCHECK, PzConfig::showNames ? BST_CHECKED : BST_UNCHECKED, 0);
	SendDlgItemMessageA(hwnd, IDC_DIST, BM_SETCHECK, PzConfig::showDistances ? BST_CHECKED : BST_UNCHECKED, 0);
	char ms[16]; sprintf_s(ms, "%d", PzConfig::pollMs);
	SetWindowTextA(g_pollEdit, ms);
	int src = IDC_SRC_FIXTURE;
	if (PzConfig::dataSource == DataSource::ServerTelemetryFile) src = IDC_SRC_TELEMETRY;
	else if (PzConfig::dataSource == DataSource::ExternalReadOnly) src = IDC_SRC_EXTERNAL;
	CheckRadioButton(hwnd, IDC_SRC_FIXTURE, IDC_SRC_EXTERNAL, src);
	EnsureWeb(PzConfig::webRadarEnabled);
	EnsureOverlay(PzConfig::overlayEnabled);
}

void PzMenu::PollMessages()
{
	MSG msg{};
	while (PeekMessageA(&msg, nullptr, 0, 0, PM_REMOVE))
	{
		if (msg.message == WM_QUIT) break;
		TranslateMessage(&msg);
		DispatchMessageA(&msg);
	}
}