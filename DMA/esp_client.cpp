// esp_client.exe — External ESP overlay for PC1
// Connects to CoopyyDMA web API on PC2 and renders ESP over Unturned's window
// Usage: esp_client.exe [server_ip] [port]
//   Default: esp_client.exe 192.168.1.211 9222
// Build: cl /EHsc /O2 /std:c++17 esp_client.cpp /link ws2_32.lib user32.lib gdi32.lib /OUT:esp_client.exe

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <thread>
#include <atomic>
#include <mutex>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

#ifndef M_PI
#define M_PI 3.14159265358979323846f
#endif
#define DEG2RAD(x) ((x) * M_PI / 180.0f)

// ============ DATA STRUCTURES ============

struct vec3 { float x, y, z; };

struct PlayerInfo {
	char name[64];
	vec3 feet, head;
	float distance, health;
	bool isTarget;
};

struct EntityInfo {
	char name[32];
	vec3 pos;
	float distance;
};

struct GameData {
	float yaw, pitch, fov;
	vec3 cam;
	PlayerInfo players[48];
	int playerCount;
	EntityInfo vehicles[64];
	int vehicleCount;
	EntityInfo zombies[128];
	int zombieCount;
	EntityInfo items[128];
	int itemCount;
};

struct ESPConfig {
	bool esp, espBoxes, espNames, espDistance, espHealth, espSnaplines;
	bool radar, vehicleESP, zombieESP, itemESP;
	bool aimbot, silentAim;
	float aimbotFOV;
};

// ============ GLOBALS ============

static std::mutex g_mtx;
static GameData g_gd = {};
static ESPConfig g_cfg = { true, true, true, true, true, false, false, false, false, false, false, false, 15.0f };
static std::atomic<bool> g_running{ true };
static std::atomic<bool> g_connected{ false };
static char g_serverIP[128] = "192.168.1.211";
static int g_serverPort = 9222;
static HWND g_overlay = NULL;
static HWND g_gameWnd = NULL;
static HFONT g_font = NULL;
static HFONT g_fontSmall = NULL;

// ============ JSON HELPERS ============

static float jf(const char* s, const char* k)
{
	char pat[64];
	sprintf_s(pat, "\"%s\":", k);
	const char* p = strstr(s, pat);
	if (!p) return 0;
	return (float)atof(p + strlen(pat));
}

static int ji(const char* s, const char* k)
{
	char pat[64];
	sprintf_s(pat, "\"%s\":", k);
	const char* p = strstr(s, pat);
	if (!p) return 0;
	return atoi(p + strlen(pat));
}

static bool jb(const char* s, const char* k)
{
	char pat[64];
	sprintf_s(pat, "\"%s\":", k);
	const char* p = strstr(s, pat);
	if (!p) return false;
	p += strlen(pat);
	while (*p == ' ') p++;
	return *p == 't';
}

static void js(const char* s, const char* k, char* out, int mx)
{
	char pat[64];
	sprintf_s(pat, "\"%s\":\"", k);
	const char* p = strstr(s, pat);
	if (!p) { out[0] = 0; return; }
	p += strlen(pat);
	int i = 0;
	while (*p && *p != '"' && i < mx - 1) {
		if (*p == '\\' && *(p + 1)) p++;
		out[i++] = *p++;
	}
	out[i] = 0;
}

// ============ HTTP CLIENT ============

static std::string httpGet(const char* path)
{
	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) return "";

	sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_port = htons((u_short)g_serverPort);
	inet_pton(AF_INET, g_serverIP, &addr.sin_addr);

	DWORD timeout = 2000;
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
	setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

	if (connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) {
		closesocket(s);
		return "";
	}

	char req[256];
	sprintf_s(req, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, g_serverIP);
	send(s, req, (int)strlen(req), 0);

	std::string resp;
	char buf[4096];
	int n;
	while ((n = recv(s, buf, sizeof(buf) - 1, 0)) > 0) {
		buf[n] = 0;
		resp += buf;
	}
	closesocket(s);

	auto bodyPos = resp.find("\r\n\r\n");
	if (bodyPos == std::string::npos) return "";
	return resp.substr(bodyPos + 4);
}

// ============ DATA PARSING ============

template<typename F>
static void parseArrayObjects(const char* json, const char* key, F callback)
{
	char pat[32];
	sprintf_s(pat, "\"%s\":[", key);
	const char* arr = strstr(json, pat);
	if (!arr) return;
	arr += strlen(pat);

	while (*arr) {
		while (*arr && *arr != '{' && *arr != ']') arr++;
		if (*arr != '{') break;
		const char* end = strchr(arr, '}');
		if (!end) break;
		int len = (int)(end - arr + 1);
		if (len < 512) {
			char obj[512];
			memcpy(obj, arr, len);
			obj[len] = 0;
			callback(obj);
		}
		arr = end + 1;
	}
}

static void parseGameData(const std::string& body)
{
	const char* j = body.c_str();
	GameData gd = {};
	gd.yaw = jf(j, "yaw");
	gd.pitch = jf(j, "pitch");
	gd.fov = jf(j, "fov");
	if (gd.fov < 10.0f) gd.fov = 90.0f;
	gd.cam = { jf(j, "lx"), jf(j, "ly"), jf(j, "lz") };

	parseArrayObjects(j, "p", [&](const char* obj) {
		if (gd.playerCount >= 48) return;
		auto& p = gd.players[gd.playerCount];
		js(obj, "n", p.name, sizeof(p.name));
		p.feet = { jf(obj, "x"), jf(obj, "y"), jf(obj, "z") };
		p.head = { jf(obj, "hx"), jf(obj, "hy"), jf(obj, "hz") };
		p.distance = jf(obj, "d");
		p.health = jf(obj, "hp");
		p.isTarget = ji(obj, "t") != 0;
		gd.playerCount++;
	});

	parseArrayObjects(j, "v", [&](const char* obj) {
		if (gd.vehicleCount >= 64) return;
		auto& v = gd.vehicles[gd.vehicleCount];
		v.pos = { jf(obj, "x"), jf(obj, "y"), jf(obj, "z") };
		v.distance = jf(obj, "d");
		gd.vehicleCount++;
	});

	parseArrayObjects(j, "z", [&](const char* obj) {
		if (gd.zombieCount >= 128) return;
		auto& z = gd.zombies[gd.zombieCount];
		z.pos = { jf(obj, "x"), jf(obj, "y"), jf(obj, "z") };
		z.distance = jf(obj, "d");
		gd.zombieCount++;
	});

	parseArrayObjects(j, "i", [&](const char* obj) {
		if (gd.itemCount >= 128) return;
		auto& it = gd.items[gd.itemCount];
		js(obj, "n", it.name, sizeof(it.name));
		it.pos = { jf(obj, "x"), jf(obj, "y"), jf(obj, "z") };
		it.distance = jf(obj, "d");
		gd.itemCount++;
	});

	std::lock_guard<std::mutex> lk(g_mtx);
	g_gd = gd;
}

static void parseConfig(const std::string& body)
{
	const char* j = body.c_str();
	ESPConfig c = {};
	c.esp = jb(j, "esp");
	c.espBoxes = jb(j, "espBoxes");
	c.espNames = jb(j, "espNames");
	c.espDistance = jb(j, "espDistance");
	c.espHealth = jb(j, "espHealth");
	c.espSnaplines = jb(j, "espSnaplines");
	c.radar = jb(j, "radar");
	c.vehicleESP = jb(j, "vehicleESP");
	c.zombieESP = jb(j, "zombieESP");
	c.itemESP = jb(j, "itemESP");
	c.aimbot = jb(j, "aimbot");
	c.silentAim = jb(j, "silentAim");
	c.aimbotFOV = jf(j, "aimbotFOV");
	if (c.aimbotFOV < 1.0f) c.aimbotFOV = 15.0f;

	std::lock_guard<std::mutex> lk(g_mtx);
	g_cfg = c;
}

// ============ NETWORK THREADS ============

static void dataThread()
{
	while (g_running) {
		auto body = httpGet("/api/gamedata");
		if (!body.empty()) {
			parseGameData(body);
			g_connected = true;
		} else {
			g_connected = false;
		}
		Sleep(16);
	}
}

static void configThread()
{
	while (g_running) {
		auto body = httpGet("/api/config");
		if (!body.empty()) parseConfig(body);
		Sleep(500);
	}
}

// ============ WORLD TO SCREEN ============

static bool W2S(vec3 world, vec3 cam, float yaw, float pitch, float fov, int sw, int sh, vec3& out)
{
	vec3 delta = { world.x - cam.x, world.y - cam.y, world.z - cam.z };
	float stdPitch = 90.0f - pitch;
	float sy = sinf(DEG2RAD(yaw)), cy = cosf(DEG2RAD(yaw));
	float sp = sinf(DEG2RAD(stdPitch)), cp = cosf(DEG2RAD(stdPitch));

	vec3 fwd = { cp * sy, sp, cp * cy };
	vec3 right = { cy, 0.0f, -sy };
	vec3 up = { -sp * sy, cp, -sp * cy };

	float z = delta.x * fwd.x + delta.y * fwd.y + delta.z * fwd.z;
	if (z < 0.1f) return false;

	float x = delta.x * right.x + delta.y * right.y + delta.z * right.z;
	float y = delta.x * up.x + delta.y * up.y + delta.z * up.z;

	float aspect = (float)sw / (float)sh;
	float tanHF = tanf(DEG2RAD(fov * 0.5f));

	out.x = (sw * 0.5f) * (1.0f + x / (z * tanHF * aspect));
	out.y = (sh * 0.5f) * (1.0f - y / (z * tanHF));
	out.z = z;
	return true;
}

// ============ GDI DRAWING ============

static void DrawRect(HDC hdc, int x, int y, int w, int h, COLORREF c, int thick = 1)
{
	HPEN pen = CreatePen(PS_SOLID, thick, c);
	HPEN op = (HPEN)SelectObject(hdc, pen);
	HBRUSH ob = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
	Rectangle(hdc, x, y, x + w, y + h);
	SelectObject(hdc, ob);
	SelectObject(hdc, op);
	DeleteObject(pen);
}

static void DrawBoxOutline(HDC hdc, int x, int y, int w, int h, COLORREF c)
{
	DrawRect(hdc, x - 1, y - 1, w + 2, h + 2, RGB(1, 1, 1));
	DrawRect(hdc, x, y, w, h, c);
	DrawRect(hdc, x + 1, y + 1, w - 2, h - 2, RGB(1, 1, 1));
}

static void DrawLine(HDC hdc, int x1, int y1, int x2, int y2, COLORREF c, int thick = 1)
{
	HPEN pen = CreatePen(PS_SOLID, thick, c);
	HPEN op = (HPEN)SelectObject(hdc, pen);
	MoveToEx(hdc, x1, y1, NULL);
	LineTo(hdc, x2, y2);
	SelectObject(hdc, op);
	DeleteObject(pen);
}

static void FillRect2(HDC hdc, int x, int y, int w, int h, COLORREF c)
{
	HBRUSH br = CreateSolidBrush(c);
	RECT rc = { x, y, x + w, y + h };
	FillRect(hdc, &rc, br);
	DeleteObject(br);
}

static void DrawText2(HDC hdc, int x, int y, const char* text, COLORREF c, HFONT font = NULL)
{
	if (font) SelectObject(hdc, font);
	SetTextColor(hdc, c);
	SetBkMode(hdc, TRANSPARENT);
	TextOutA(hdc, x, y, text, (int)strlen(text));
}

static void DrawHealthBar(HDC hdc, int x, int y, int w, int h, float hp01)
{
	FillRect2(hdc, x, y, w, h, RGB(1, 1, 1));
	FillRect2(hdc, x + 1, y + 1, w - 2, h - 2, RGB(20, 20, 20));
	int fillH = (int)((h - 2) * hp01);
	int r = (int)(255 * (1.0f - hp01));
	int g = (int)(255 * hp01);
	FillRect2(hdc, x + 1, y + 1 + (h - 2 - fillH), w - 2, fillH, RGB(r, g, 0));
}

static void DrawCircle(HDC hdc, int cx, int cy, int radius, COLORREF c)
{
	HPEN pen = CreatePen(PS_SOLID, 1, c);
	HPEN op = (HPEN)SelectObject(hdc, pen);
	HBRUSH ob = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
	Ellipse(hdc, cx - radius, cy - radius, cx + radius, cy + radius);
	SelectObject(hdc, ob);
	SelectObject(hdc, op);
	DeleteObject(pen);
}

static void DrawFilledCircle(HDC hdc, int cx, int cy, int radius, COLORREF c)
{
	HBRUSH br = CreateSolidBrush(c);
	HPEN pen = CreatePen(PS_SOLID, 1, c);
	HPEN op = (HPEN)SelectObject(hdc, pen);
	HBRUSH ob = (HBRUSH)SelectObject(hdc, br);
	Ellipse(hdc, cx - radius, cy - radius, cx + radius, cy + radius);
	SelectObject(hdc, ob);
	SelectObject(hdc, op);
	DeleteObject(pen);
	DeleteObject(br);
}

// ============ ESP RENDERING ============

static void RenderESP(HDC hdc, int sw, int sh, const GameData& gd, const ESPConfig& cfg)
{
	if (!cfg.esp) return;

	if (cfg.aimbot || cfg.silentAim) {
		float fovR = (cfg.aimbotFOV / gd.fov) * sw * 0.5f;
		DrawCircle(hdc, sw / 2, sh / 2, (int)fovR, RGB(255, 255, 255));
	}

	for (int i = 0; i < gd.playerCount; i++) {
		auto& p = gd.players[i];
		vec3 sf, sh2;
		if (!W2S(p.feet, gd.cam, gd.yaw, gd.pitch, gd.fov, sw, sh, sf)) continue;
		if (!W2S(p.head, gd.cam, gd.yaw, gd.pitch, gd.fov, sw, sh, sh2)) continue;

		float boxH = fabsf(sf.y - sh2.y);
		float boxW = boxH * 0.45f;
		int bx = (int)(sh2.x - boxW * 0.5f);
		int by = (int)sh2.y;
		int bw = (int)boxW;
		int bh = (int)boxH;

		COLORREF boxC = p.isTarget ? RGB(255, 255, 0) : RGB(255, 50, 50);

		if (cfg.espBoxes)
			DrawBoxOutline(hdc, bx, by, bw, bh, boxC);

		if (cfg.espHealth) {
			float hp = p.health / 100.0f;
			if (hp > 1.0f) hp = 1.0f;
			if (hp < 0.0f) hp = 0.0f;
			DrawHealthBar(hdc, bx - 6, by, 4, bh, hp);
			char ht[16];
			sprintf_s(ht, "%.0f HP", p.health);
			int r = (int)(255 * (1.0f - hp));
			int g = (int)(255 * hp);
			DrawText2(hdc, bx + bw + 4, by, ht, RGB(r, g, 0), g_fontSmall);
		}

		int ty = by - 14;
		if (cfg.espNames && p.name[0]) {
			DrawText2(hdc, bx, ty, p.name, RGB(255, 255, 255), g_fontSmall);
			ty -= 14;
		}

		if (cfg.espDistance) {
			char dt[32];
			sprintf_s(dt, "%.0fm", p.distance);
			DrawText2(hdc, bx, (int)(sf.y + 2), dt, RGB(200, 200, 200), g_fontSmall);
		}

		if (cfg.espSnaplines)
			DrawLine(hdc, sw / 2, sh, (int)sf.x, (int)sf.y, RGB(255, 255, 0));
	}

	if (cfg.vehicleESP) {
		for (int i = 0; i < gd.vehicleCount; i++) {
			auto& v = gd.vehicles[i];
			vec3 sp;
			if (!W2S(v.pos, gd.cam, gd.yaw, gd.pitch, gd.fov, sw, sh, sp)) continue;
			char txt[32];
			sprintf_s(txt, "Vehicle [%.0fm]", v.distance);
			DrawText2(hdc, (int)sp.x - 30, (int)sp.y, txt, RGB(0, 200, 255), g_fontSmall);
		}
	}

	if (cfg.itemESP) {
		for (int i = 0; i < gd.itemCount; i++) {
			auto& it = gd.items[i];
			vec3 sp;
			if (!W2S(it.pos, gd.cam, gd.yaw, gd.pitch, gd.fov, sw, sh, sp)) continue;
			char txt[64];
			sprintf_s(txt, "%s [%.0fm]", it.name, it.distance);
			DrawText2(hdc, (int)sp.x - 20, (int)sp.y, txt, RGB(255, 200, 0), g_fontSmall);
		}
	}

	if (cfg.zombieESP) {
		for (int i = 0; i < gd.zombieCount; i++) {
			auto& z = gd.zombies[i];
			vec3 sp;
			if (!W2S(z.pos, gd.cam, gd.yaw, gd.pitch, gd.fov, sw, sh, sp)) continue;
			char txt[32];
			sprintf_s(txt, "Zombie [%.0fm]", z.distance);
			DrawText2(hdc, (int)sp.x - 25, (int)sp.y, txt, RGB(180, 0, 180), g_fontSmall);
		}
	}
}

static void RenderRadar(HDC hdc, int sw, int sh, const GameData& gd, const ESPConfig& cfg)
{
	if (!cfg.radar) return;

	int rsz = 180;
	int rx = sw - rsz - 15, ry = 15;
	int cx = rx + rsz / 2, cy = ry + rsz / 2;
	float range = 150.0f;
	float yr = -DEG2RAD(gd.yaw);

	FillRect2(hdc, rx, ry, rsz, rsz, RGB(10, 10, 10));
	DrawRect(hdc, rx, ry, rsz, rsz, RGB(80, 80, 80));
	DrawLine(hdc, cx, ry, cx, ry + rsz, RGB(40, 40, 40));
	DrawLine(hdc, rx, cy, rx + rsz, cy, RGB(40, 40, 40));
	DrawFilledCircle(hdc, cx, cy, 3, RGB(0, 255, 0));

	for (int i = 0; i < gd.playerCount; i++) {
		auto& p = gd.players[i];
		float dx = p.feet.x - gd.cam.x, dz = p.feet.z - gd.cam.z;
		float rotX = dx * cosf(yr) - dz * sinf(yr);
		float rotZ = dx * sinf(yr) + dz * cosf(yr);
		int dotX = cx + (int)(rotX / range * (rsz / 2));
		int dotY = cy - (int)(rotZ / range * (rsz / 2));
		if (dotX < rx + 3 || dotX > rx + rsz - 3 || dotY < ry + 3 || dotY > ry + rsz - 3) continue;
		DrawFilledCircle(hdc, dotX, dotY, 3, p.isTarget ? RGB(255, 255, 0) : RGB(255, 50, 50));
	}

	if (cfg.zombieESP) {
		for (int i = 0; i < gd.zombieCount; i++) {
			auto& z = gd.zombies[i];
			float dx = z.pos.x - gd.cam.x, dz = z.pos.z - gd.cam.z;
			float rotX = dx * cosf(yr) - dz * sinf(yr);
			float rotZ = dx * sinf(yr) + dz * cosf(yr);
			int dotX = cx + (int)(rotX / range * (rsz / 2));
			int dotY = cy - (int)(rotZ / range * (rsz / 2));
			if (dotX < rx + 2 || dotX > rx + rsz - 2 || dotY < ry + 2 || dotY > ry + rsz - 2) continue;
			DrawFilledCircle(hdc, dotX, dotY, 2, RGB(180, 0, 180));
		}
	}
}

// ============ OVERLAY WINDOW ============

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
	if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
	return DefWindowProcA(hwnd, msg, wp, lp);
}

static HWND FindGameWindow()
{
	HWND hw = FindWindowA(NULL, "Unturned");
	if (!hw) hw = FindWindowA("UnityWndClass", NULL);
	return hw;
}

// ============ MAIN ============

int main(int argc, char* argv[])
{
	SetProcessDPIAware();

	if (argc >= 2) strncpy_s(g_serverIP, argv[1], sizeof(g_serverIP) - 1);
	if (argc >= 3) g_serverPort = atoi(argv[2]);

	printf("=== CoopyyDMA ESP Client ===\n");
	printf("Server: %s:%d\n", g_serverIP, g_serverPort);
	printf("Looking for Unturned window...\n");

	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		printf("WSAStartup failed\n");
		return 1;
	}

	g_gameWnd = FindGameWindow();
	while (!g_gameWnd && g_running) {
		Sleep(1000);
		g_gameWnd = FindGameWindow();
	}
	if (!g_running) return 0;

	RECT gameRect;
	GetClientRect(g_gameWnd, &gameRect);
	POINT topLeft = { 0, 0 };
	ClientToScreen(g_gameWnd, &topLeft);
	int sw = gameRect.right - gameRect.left;
	int sh = gameRect.bottom - gameRect.top;
	printf("Found Unturned: %dx%d at (%d,%d)\n", sw, sh, topLeft.x, topLeft.y);

	WNDCLASSEXA wc = {};
	wc.cbSize = sizeof(wc);
	wc.style = CS_HREDRAW | CS_VREDRAW;
	wc.lpfnWndProc = WndProc;
	wc.hInstance = GetModuleHandle(NULL);
	wc.lpszClassName = "CoopyyESP";
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);
	RegisterClassExA(&wc);

	g_overlay = CreateWindowExA(
		WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
		"CoopyyESP", "",
		WS_POPUP,
		topLeft.x, topLeft.y, sw, sh,
		NULL, NULL, GetModuleHandle(NULL), NULL);

	if (!g_overlay) {
		printf("Failed to create overlay window\n");
		return 1;
	}

	SetLayeredWindowAttributes(g_overlay, RGB(0, 0, 0), 0, LWA_COLORKEY);
	SetWindowDisplayAffinity(g_overlay, WDA_EXCLUDEFROMCAPTURE);
	ShowWindow(g_overlay, SW_SHOWNOACTIVATE);

	g_font = CreateFontA(16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
		DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
		ANTIALIASED_QUALITY, DEFAULT_PITCH, "Consolas");
	g_fontSmall = CreateFontA(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
		DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
		ANTIALIASED_QUALITY, DEFAULT_PITCH, "Consolas");

	printf("Overlay created (stream-proof). Starting data threads...\n");

	std::thread t1(dataThread);
	std::thread t2(configThread);
	t1.detach();
	t2.detach();

	printf("ESP active. Press Ctrl+C to exit.\n\n");

	bool wasConnected = false;

	while (g_running) {
		MSG msg;
		while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
			if (msg.message == WM_QUIT) { g_running = false; break; }
			TranslateMessage(&msg);
			DispatchMessageA(&msg);
		}
		if (!g_running) break;

		if (g_connected && !wasConnected) { printf("[+] Connected to DMA server\n"); wasConnected = true; }
		if (!g_connected && wasConnected) { printf("[-] Lost connection\n"); wasConnected = false; }

		HWND gw = FindGameWindow();
		if (gw && gw != g_gameWnd) g_gameWnd = gw;

		if (g_gameWnd && IsWindow(g_gameWnd)) {
			GetClientRect(g_gameWnd, &gameRect);
			POINT tl = { 0, 0 };
			ClientToScreen(g_gameWnd, &tl);
			int nw = gameRect.right - gameRect.left;
			int nh = gameRect.bottom - gameRect.top;
			if (nw != sw || nh != sh || tl.x != topLeft.x || tl.y != topLeft.y) {
				sw = nw; sh = nh; topLeft = tl;
				MoveWindow(g_overlay, topLeft.x, topLeft.y, sw, sh, FALSE);
			}
		}

		GameData localGD;
		ESPConfig localCfg;
		{
			std::lock_guard<std::mutex> lk(g_mtx);
			localGD = g_gd;
			localCfg = g_cfg;
		}

		HDC hdc = GetDC(g_overlay);
		HDC memDC = CreateCompatibleDC(hdc);
		HBITMAP memBmp = CreateCompatibleBitmap(hdc, sw, sh);
		HBITMAP oldBmp = (HBITMAP)SelectObject(memDC, memBmp);

		RECT clr = { 0, 0, sw, sh };
		HBRUSH clrBr = CreateSolidBrush(RGB(0, 0, 0));
		FillRect(memDC, &clr, clrBr);
		DeleteObject(clrBr);

		SelectObject(memDC, g_font);
		RenderESP(memDC, sw, sh, localGD, localCfg);
		RenderRadar(memDC, sw, sh, localGD, localCfg);

		if (g_connected)
			DrawText2(memDC, 5, sh - 20, "DMA ESP | Streamproof", RGB(0, 255, 100), g_fontSmall);
		else
			DrawText2(memDC, 5, sh - 20, "DMA ESP | Connecting...", RGB(255, 100, 0), g_fontSmall);

		BitBlt(hdc, 0, 0, sw, sh, memDC, 0, 0, SRCCOPY);

		SelectObject(memDC, oldBmp);
		DeleteObject(memBmp);
		DeleteDC(memDC);
		ReleaseDC(g_overlay, hdc);

		Sleep(16);
	}

	if (g_font) DeleteObject(g_font);
	if (g_fontSmall) DeleteObject(g_fontSmall);
	if (g_overlay) DestroyWindow(g_overlay);
	UnregisterClassA("CoopyyESP", GetModuleHandle(NULL));
	WSACleanup();
	return 0;
}
