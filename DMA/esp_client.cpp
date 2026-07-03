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

struct FullConfig {
	bool vals[32] = {};
	float floats[12] = {};
};

struct MenuItem {
	const char* label;
	const char* apiKey;
	bool isSlider;
	int boolIdx;
	int floatIdx;
	float sMin, sMax;
};

static const char* g_boolKeys[] = {
	"aimbot","silentAim","noRecoil","noSpread","rapidFire","infiniteRange",
	"extendedMelee","triggerbot","spinBot","instantReload",
	"esp","espBoxes","espNames","espDistance","espHealth","espSnaplines",
	"radar","vehicleESP","itemESP","zombieESP","fullbright","fovChanger","chams","streamProof",
	"speedHack","flyHack","superJump","vehicleFly","noFallDamage","noclip",
	"godMode","adminMode"
};
static const int NUM_BOOLS = sizeof(g_boolKeys) / sizeof(g_boolKeys[0]);

static const char* g_floatKeys[] = {
	"speedMultiplier","jumpMultiplier","flySpeed","aimbotFOV","aimbotSmooth",
	"customFOV","meleeRange","lootRadius","noclipSpeed"
};
static const int NUM_FLOATS = sizeof(g_floatKeys) / sizeof(g_floatKeys[0]);

enum Tab { TAB_COMBAT, TAB_VISUALS, TAB_MOVEMENT, TAB_PLAYER, TAB_COUNT };
static const char* g_tabNames[] = { "Combat", "Visuals", "Movement", "Player" };

static const MenuItem g_menuItems[][12] = {
	{ // Combat
		{"Aimbot",        "aimbot",        false, 0, -1, 0,0},
		{"Silent Aim",    "silentAim",     false, 1, -1, 0,0},
		{"No Recoil",     "noRecoil",      false, 2, -1, 0,0},
		{"No Spread",     "noSpread",      false, 3, -1, 0,0},
		{"Rapid Fire",    "rapidFire",     false, 4, -1, 0,0},
		{"Inf. Range",    "infiniteRange", false, 5, -1, 0,0},
		{"Ext. Melee",    "extendedMelee", false, 6, -1, 0,0},
		{"Triggerbot",    "triggerbot",     false, 7, -1, 0,0},
		{"Spinbot",       "spinBot",       false, 8, -1, 0,0},
		{"Instant Reload","instantReload", false, 9, -1, 0,0},
		{"Aim FOV",       "aimbotFOV",     true, -1, 3, 2.0f, 90.0f},
		{"Aim Smooth",    "aimbotSmooth",  true, -1, 4, 1.0f, 20.0f},
	},
	{ // Visuals
		{"ESP",           "esp",           false,10, -1, 0,0},
		{"Boxes",         "espBoxes",      false,11, -1, 0,0},
		{"Names",         "espNames",      false,12, -1, 0,0},
		{"Distance",      "espDistance",    false,13, -1, 0,0},
		{"Health",        "espHealth",     false,14, -1, 0,0},
		{"Snaplines",     "espSnaplines",  false,15, -1, 0,0},
		{"Radar",         "radar",         false,16, -1, 0,0},
		{"Vehicle ESP",   "vehicleESP",    false,17, -1, 0,0},
		{"Item ESP",      "itemESP",       false,18, -1, 0,0},
		{"Zombie ESP",    "zombieESP",     false,19, -1, 0,0},
		{"Fullbright",    "fullbright",    false,20, -1, 0,0},
		{"Custom FOV",    "customFOV",     true, -1, 5, 60.0f, 160.0f},
	},
	{ // Movement
		{"Speed Hack",    "speedHack",     false,24, -1, 0,0},
		{"Fly Hack",      "flyHack",       false,25, -1, 0,0},
		{"Super Jump",    "superJump",     false,26, -1, 0,0},
		{"Vehicle Fly",   "vehicleFly",    false,27, -1, 0,0},
		{"No Fall Dmg",   "noFallDamage",  false,28, -1, 0,0},
		{"Noclip",        "noclip",        false,29, -1, 0,0},
		{"Speed",         "speedMultiplier",true,-1, 0, 1.0f, 1.5f},
		{"Jump",          "jumpMultiplier",true, -1, 1, 1.0f, 2.0f},
		{"Fly Speed",     "flySpeed",      true, -1, 2, 2.0f, 15.0f},
		{"Noclip Speed",  "noclipSpeed",   true, -1, 8, 1.0f, 15.0f},
		{0},
		{0},
	},
	{ // Player
		{"God Mode",      "godMode",       false,30, -1, 0,0},
		{"Admin Mode",    "adminMode",     false,31, -1, 0,0},
		{"Loot Teleport", "lootTeleport",  false,-1, -1, 0,0},
		{"Loot Radius",   "lootRadius",    true, -1, 7, 5.0f, 200.0f},
		{"Melee Range",   "meleeRange",    true, -1, 6, 1.0f, 50.0f},
		{0},{0},{0},{0},{0},{0},{0},
	},
};
static const int g_menuCounts[] = { 12, 12, 10, 5 };

// ============ GLOBALS ============

static std::mutex g_mtx;
static GameData g_gd = {};
static ESPConfig g_cfg = { true, true, true, true, true, false, false, false, false, false, false, false, 15.0f };
static FullConfig g_fcfg = {};
static std::atomic<bool> g_running{ true };
static std::atomic<bool> g_connected{ false };
static char g_serverIP[128] = "192.168.1.211";
static int g_serverPort = 9222;
static HWND g_overlay = NULL;
static HWND g_gameWnd = NULL;
static HFONT g_font = NULL;
static HFONT g_fontSmall = NULL;
static bool g_menuOpen = false;
static int g_activeTab = 0;
static HFONT g_menuFont = NULL;
static HFONT g_menuFontBold = NULL;

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

static void httpPost(const char* path)
{
	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) return;
	DWORD timeout = 1000;
	setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
	sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_port = htons((u_short)g_serverPort);
	inet_pton(AF_INET, g_serverIP, &addr.sin_addr);
	if (connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) { closesocket(s); return; }
	char req[256];
	sprintf_s(req, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", path, g_serverIP);
	send(s, req, (int)strlen(req), 0);
	char buf[256]; recv(s, buf, sizeof(buf), 0);
	closesocket(s);
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

	FullConfig fc = {};
	for (int i = 0; i < NUM_BOOLS; i++)
		fc.vals[i] = jb(j, g_boolKeys[i]);
	for (int i = 0; i < NUM_FLOATS; i++)
		fc.floats[i] = jf(j, g_floatKeys[i]);

	std::lock_guard<std::mutex> lk(g_mtx);
	g_cfg = c;
	g_fcfg = fc;
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

// ============ MENU RENDERING ============

static void RenderMenu(HDC hdc, int sw, int sh, const FullConfig& fc)
{
	if (!g_menuOpen) return;

	const int MENU_W = 300, MENU_X = 10, MENU_Y = 10;
	const int TITLE_H = 28, TAB_H = 24, ITEM_H = 22, SLIDER_H = 20, PAD = 4;

	int tabCount = g_menuCounts[g_activeTab];
	int contentH = 0;
	for (int i = 0; i < tabCount; i++) {
		auto& mi = g_menuItems[g_activeTab][i];
		if (!mi.label) continue;
		contentH += mi.isSlider ? SLIDER_H : ITEM_H;
	}
	int menuH = TITLE_H + TAB_H + contentH + PAD * 2;

	FillRect2(hdc, MENU_X, MENU_Y, MENU_W, menuH, RGB(14, 14, 20));
	DrawRect(hdc, MENU_X, MENU_Y, MENU_W, menuH, RGB(55, 55, 95));

	HFONT oldFont = (HFONT)SelectObject(hdc, g_menuFontBold);
	DrawText2(hdc, MENU_X + 10, MENU_Y + 6, "penisfinger DMA  |  F1 close", RGB(100, 170, 255), g_menuFontBold);
	DrawLine(hdc, MENU_X, MENU_Y + TITLE_H, MENU_X + MENU_W, MENU_Y + TITLE_H, RGB(55, 55, 95));

	int tabW = MENU_W / TAB_COUNT;
	int tabY = MENU_Y + TITLE_H;
	for (int t = 0; t < TAB_COUNT; t++) {
		int tx = MENU_X + t * tabW;
		COLORREF bg = (t == g_activeTab) ? RGB(30, 30, 60) : RGB(18, 18, 28);
		FillRect2(hdc, tx, tabY, tabW, TAB_H, bg);
		DrawText2(hdc, tx + 8, tabY + 5, g_tabNames[t],
			t == g_activeTab ? RGB(120, 180, 255) : RGB(100, 100, 130), g_menuFont);
	}
	DrawLine(hdc, MENU_X, tabY + TAB_H, MENU_X + MENU_W, tabY + TAB_H, RGB(55, 55, 95));

	int cy = tabY + TAB_H + PAD;
	for (int i = 0; i < tabCount; i++) {
		auto& mi = g_menuItems[g_activeTab][i];
		if (!mi.label) continue;

		if (mi.isSlider) {
			float val = (mi.floatIdx >= 0 && mi.floatIdx < NUM_FLOATS) ? fc.floats[mi.floatIdx] : 0;
			char txt[64];
			sprintf_s(txt, "%s: %.1f", mi.label, val);
			DrawText2(hdc, MENU_X + 12, cy + 2, txt, RGB(180, 180, 200), g_menuFont);
			int barX = MENU_X + 12, barW = MENU_W - 24, barY = cy + 14;
			FillRect2(hdc, barX, barY, barW, 4, RGB(40, 40, 60));
			float pct = (mi.sMax > mi.sMin) ? (val - mi.sMin) / (mi.sMax - mi.sMin) : 0;
			if (pct < 0) pct = 0; if (pct > 1) pct = 1;
			FillRect2(hdc, barX, barY, (int)(barW * pct), 4, RGB(100, 170, 255));
			cy += SLIDER_H;
		} else {
			bool on = (mi.boolIdx >= 0 && mi.boolIdx < 32) ? fc.vals[mi.boolIdx] : false;
			COLORREF tc = on ? RGB(100, 255, 100) : RGB(150, 60, 60);
			DrawText2(hdc, MENU_X + 12, cy + 3, mi.label, RGB(200, 200, 210), g_menuFont);
			const char* state = on ? "ON" : "OFF";
			DrawText2(hdc, MENU_X + MENU_W - 50, cy + 3, state, tc, g_menuFontBold);
			cy += ITEM_H;
		}
	}
	SelectObject(hdc, oldFont);
}

static void HandleMenuClick(int mx, int my, bool isDown, const FullConfig& fc)
{
	if (!g_menuOpen || !isDown) return;

	const int MENU_X = 10, MENU_Y = 10, MENU_W = 300;
	const int TITLE_H = 28, TAB_H = 24, ITEM_H = 22, SLIDER_H = 20, PAD = 4;

	int tabW = MENU_W / TAB_COUNT;
	int tabY = MENU_Y + TITLE_H;
	if (my >= tabY && my < tabY + TAB_H && mx >= MENU_X && mx < MENU_X + MENU_W) {
		g_activeTab = (mx - MENU_X) / tabW;
		if (g_activeTab >= TAB_COUNT) g_activeTab = TAB_COUNT - 1;
		return;
	}

	int cy = tabY + TAB_H + PAD;
	int tabCount = g_menuCounts[g_activeTab];
	for (int i = 0; i < tabCount; i++) {
		auto& mi = g_menuItems[g_activeTab][i];
		if (!mi.label) continue;
		int h = mi.isSlider ? SLIDER_H : ITEM_H;

		if (my >= cy && my < cy + h && mx >= MENU_X && mx < MENU_X + MENU_W) {
			if (mi.isSlider) {
				int barX = MENU_X + 12, barW = MENU_W - 24;
				float pct = (float)(mx - barX) / (float)barW;
				if (pct < 0) pct = 0; if (pct > 1) pct = 1;
				float val = mi.sMin + pct * (mi.sMax - mi.sMin);
				char path[128];
				sprintf_s(path, "/api/set/%s/%.2f", mi.apiKey, val);
				std::thread([=]() { httpPost(path); }).detach();
			} else {
				char path[128];
				sprintf_s(path, "/api/toggle/%s", mi.apiKey);
				std::thread([=]() { httpPost(path); }).detach();
			}
			return;
		}
		cy += h;
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
		WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
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

	g_menuFont = CreateFontA(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
		DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
		CLEARTYPE_QUALITY, DEFAULT_PITCH, "Segoe UI");
	g_menuFontBold = CreateFontA(13, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
		DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
		CLEARTYPE_QUALITY, DEFAULT_PITCH, "Segoe UI");

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

		static bool f1WasDown = false;
		bool f1Down = (GetAsyncKeyState(VK_F1) & 0x8000) != 0;
		if (f1Down && !f1WasDown) {
			g_menuOpen = !g_menuOpen;
			LONG exStyle = GetWindowLongA(g_overlay, GWL_EXSTYLE);
			if (g_menuOpen)
				SetWindowLongA(g_overlay, GWL_EXSTYLE, exStyle & ~WS_EX_TRANSPARENT);
			else
				SetWindowLongA(g_overlay, GWL_EXSTYLE, exStyle | WS_EX_TRANSPARENT);
		}
		f1WasDown = f1Down;

		static bool lmbWasDown = false;
		bool lmbDown = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
		if (lmbDown && !lmbWasDown && g_menuOpen) {
			POINT mp; GetCursorPos(&mp);
			POINT origin = { 0, 0 }; ClientToScreen(g_overlay, &origin);
			FullConfig fc;
			{ std::lock_guard<std::mutex> lk(g_mtx); fc = g_fcfg; }
			HandleMenuClick(mp.x - origin.x, mp.y - origin.y, true, fc);
		}
		lmbWasDown = lmbDown;

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
				SetWindowPos(g_overlay, HWND_TOP, topLeft.x, topLeft.y, sw, sh, SWP_NOACTIVATE);
			} else {
				SetWindowPos(g_overlay, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
			}
		}

		GameData localGD;
		ESPConfig localCfg;
		FullConfig localFcfg;
		{
			std::lock_guard<std::mutex> lk(g_mtx);
			localGD = g_gd;
			localCfg = g_cfg;
			localFcfg = g_fcfg;
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
		RenderMenu(memDC, sw, sh, localFcfg);

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
	if (g_menuFont) DeleteObject(g_menuFont);
	if (g_menuFontBold) DeleteObject(g_menuFontBold);
	if (g_overlay) DestroyWindow(g_overlay);
	UnregisterClassA("CoopyyESP", GetModuleHandle(NULL));
	WSACleanup();
	return 0;
}
