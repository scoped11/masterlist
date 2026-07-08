// Stealth Menu Client - runs on PC1 (main/target PC)
// Opens the DMA web menu and hides it from anti-cheat screen capture
// using SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)
//
// Build: cl /EHsc /O2 stealth_menu.cpp /link user32.lib shell32.lib wininet.lib
// Usage: stealth_menu.exe 192.168.1.X       (IP of your RADAR PC)
//        stealth_menu.exe 192.168.1.X 7337  (custom port)
//
// Hotkeys:
//   HOME   - toggle menu visibility
//   END    - exit

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <cstdlib>
#include <wininet.h>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "wininet.lib")

#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

static char g_menuUrl[256] = {};
static HWND g_menuHwnd = NULL;
static bool g_visible = true;
static bool g_protected = false;

struct FindWindowData {
	const char* titleFragment;
	HWND result;
};

static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
	auto* data = reinterpret_cast<FindWindowData*>(lParam);
	char title[256] = {};
	GetWindowTextA(hwnd, title, sizeof(title));
	if (strstr(title, data->titleFragment))
	{
		if (IsWindowVisible(hwnd))
		{
			data->result = hwnd;
			return FALSE;
		}
	}
	return TRUE;
}

static HWND FindMenuWindow()
{
	FindWindowData data = { "UnturnedDMA", NULL };
	EnumWindows(EnumWindowsProc, (LPARAM)&data);
	return data.result;
}

static bool IsServerUp(const char* host, int port)
{
	char url[256];
	sprintf_s(url, "http://%s:%d/api/config", host, port);

	HINTERNET hInet = InternetOpenA("StealthMenu", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (!hInet) return false;

	DWORD timeout = 2000;
	InternetSetOptionA(hInet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
	InternetSetOptionA(hInet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

	HINTERNET hUrl = InternetOpenUrlA(hInet, url, NULL, 0,
		INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD, 0);

	bool up = false;
	if (hUrl)
	{
		char buf[64] = {};
		DWORD read = 0;
		if (InternetReadFile(hUrl, buf, sizeof(buf) - 1, &read) && read > 0)
			up = (buf[0] == '{');
		InternetCloseHandle(hUrl);
	}
	InternetCloseHandle(hInet);
	return up;
}

static bool ApplyProtection(HWND hwnd)
{
	typedef BOOL(WINAPI* pSetWindowDisplayAffinity)(HWND, DWORD);
	static pSetWindowDisplayAffinity fn = NULL;

	if (!fn)
	{
		HMODULE hUser32 = GetModuleHandleA("user32.dll");
		if (hUser32)
			fn = (pSetWindowDisplayAffinity)GetProcAddress(hUser32, "SetWindowDisplayAffinity");
	}

	if (!fn) return false;
	return fn(hwnd, WDA_EXCLUDEFROMCAPTURE) != 0;
}

static void ApplyToAllChildren(HWND parent)
{
	ApplyProtection(parent);
	HWND child = GetWindow(parent, GW_CHILD);
	while (child)
	{
		ApplyProtection(child);
		child = GetWindow(child, GW_HWNDNEXT);
	}
}

int main(int argc, char* argv[])
{
	SetConsoleTitleA("UnturnedDMA Stealth Client");

	if (argc < 2)
	{
		printf("=== UnturnedDMA Stealth Menu Client ===\n\n");
		printf("Usage: %s <RADAR_PC_IP> [port]\n\n", argv[0]);
		printf("Example:\n");
		printf("  %s 192.168.1.100\n", argv[0]);
		printf("  %s 192.168.1.100 7337\n\n", argv[0]);
		printf("This runs on your MAIN PC (PC1).\n");
		printf("It opens the cheat menu and hides it from anti-cheat screenshots.\n\n");
		printf("Hotkeys:\n");
		printf("  HOME  - toggle menu visibility\n");
		printf("  END   - exit\n");
		return 1;
	}

	const char* host = argv[1];
	int port = (argc > 2) ? atoi(argv[2]) : 7337;
	sprintf_s(g_menuUrl, "http://%s:%d", host, port);

	printf("=== UnturnedDMA Stealth Menu ===\n");
	printf("Target: %s\n\n", g_menuUrl);

	// Wait for DMA server to come online
	printf("[*] Waiting for DMA server...\n");
	while (!IsServerUp(host, port))
	{
		if (GetAsyncKeyState(VK_END) & 1)
		{
			printf("[!] Cancelled.\n");
			return 0;
		}
		printf(".");
		Sleep(2000);
	}
	printf("\n[+] DMA server is online!\n");

	// Open browser to menu URL
	printf("[*] Opening menu in browser...\n");
	ShellExecuteA(NULL, "open", g_menuUrl, NULL, NULL, SW_SHOW);
	Sleep(3000);

	// Find the browser window with our title
	printf("[*] Looking for menu window...\n");
	int attempts = 0;
	while (!g_menuHwnd && attempts < 15)
	{
		g_menuHwnd = FindMenuWindow();
		if (!g_menuHwnd)
		{
			Sleep(1000);
			attempts++;
		}
	}

	if (!g_menuHwnd)
	{
		printf("[!] Could not find browser window with title 'UnturnedDMA'\n");
		printf("[!] Make sure the page loaded. Retrying in background...\n");
	}
	else
	{
		printf("[+] Found menu window: 0x%p\n", g_menuHwnd);
	}

	// Apply screen capture protection
	if (g_menuHwnd)
	{
		if (ApplyProtection(g_menuHwnd))
		{
			g_protected = true;
			printf("[+] Anti-capture protection ACTIVE\n");
			printf("[+] Window is now INVISIBLE to:\n");
			printf("    - Anti-cheat screenshots\n");
			printf("    - OBS / streaming software\n");
			printf("    - Discord screen share\n");
			printf("    - PrintScreen / Win+Shift+S\n");
		}
		else
		{
			printf("[!] Failed to apply protection (requires Win10 2004+)\n");
		}
	}

	printf("\n[HOME] Toggle visibility | [END] Exit\n\n");

	// Main loop - maintain protection and handle hotkeys
	while (true)
	{
		if (GetAsyncKeyState(VK_END) & 1)
			break;

		// HOME - toggle visibility
		if (GetAsyncKeyState(VK_HOME) & 1)
		{
			if (g_menuHwnd && IsWindow(g_menuHwnd))
			{
				g_visible = !g_visible;
				ShowWindow(g_menuHwnd, g_visible ? SW_SHOW : SW_HIDE);
				printf("[*] Menu %s\n", g_visible ? "SHOWN" : "HIDDEN");
			}
		}

		// Re-find window if lost
		if (!g_menuHwnd || !IsWindow(g_menuHwnd))
		{
			HWND newHwnd = FindMenuWindow();
			if (newHwnd && newHwnd != g_menuHwnd)
			{
				g_menuHwnd = newHwnd;
				if (ApplyProtection(g_menuHwnd))
				{
					g_protected = true;
					printf("[+] Re-applied protection to new window\n");
				}
			}
		}

		// Re-apply protection periodically (some browsers reset it on tab switch)
		if (g_menuHwnd && IsWindow(g_menuHwnd) && g_protected)
		{
			static DWORD lastReapply = 0;
			DWORD now = GetTickCount();
			if (now - lastReapply > 5000)
			{
				ApplyToAllChildren(g_menuHwnd);
				lastReapply = now;
			}
		}

		Sleep(100);
	}

	// Cleanup
	if (g_menuHwnd && IsWindow(g_menuHwnd))
	{
		SetWindowDisplayAffinity(g_menuHwnd, 0);
		printf("[*] Protection removed.\n");
	}

	printf("[*] Exiting.\n");
	return 0;
}
