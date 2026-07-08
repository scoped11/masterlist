#pragma once
#include <Windows.h>
#include <thread>
#include <atomic>
#include <cstdio>
#include "dma_config.h"
#include "../external/game_math.h"

namespace Overlay
{
	inline HWND overlayWnd = NULL;
	inline std::atomic<bool> running{ true };
	inline HFONT espFont = NULL;
	inline HFONT espFontSmall = NULL;

	struct PlayerData
	{
		vector3 feetPos;
		vector3 headPos;
		float distance;
		float health;
		bool valid;
		bool isTarget;
		char name[64];
	};

	struct WorldObjectData
	{
		vector3 pos;
		float distance;
		bool valid;
		char name[32];
	};

	inline PlayerData players[48];
	inline int playerCount = 0;
	inline vector3 localCamPos = {};
	inline float localYaw = 0;
	inline float localPitch = 0;

	inline WorldObjectData vehicles[64];
	inline int vehicleCount = 0;
	inline WorldObjectData items[128];
	inline int itemCount = 0;
	inline WorldObjectData zombies[128];
	inline int zombieCount = 0;

	inline int screenW = 1920;
	inline int screenH = 1080;

	inline void DrawOutlinedRect(HDC hdc, int x, int y, int w, int h, COLORREF color, int thickness = 1)
	{
		HPEN pen = CreatePen(PS_SOLID, thickness, color);
		HPEN oldPen = (HPEN)SelectObject(hdc, pen);
		HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
		Rectangle(hdc, x, y, x + w, y + h);
		SelectObject(hdc, oldBrush);
		SelectObject(hdc, oldPen);
		DeleteObject(pen);
	}

	inline void DrawOutlinedRectOutline(HDC hdc, int x, int y, int w, int h, COLORREF color)
	{
		DrawOutlinedRect(hdc, x - 1, y - 1, w + 2, h + 2, RGB(1, 1, 1), 1);
		DrawOutlinedRect(hdc, x, y, w, h, color, 1);
		DrawOutlinedRect(hdc, x + 1, y + 1, w - 2, h - 2, RGB(1, 1, 1), 1);
	}

	inline void DrawLine(HDC hdc, int x1, int y1, int x2, int y2, COLORREF color, int thickness = 1)
	{
		HPEN pen = CreatePen(PS_SOLID, thickness, color);
		HPEN oldPen = (HPEN)SelectObject(hdc, pen);
		MoveToEx(hdc, x1, y1, NULL);
		LineTo(hdc, x2, y2);
		SelectObject(hdc, oldPen);
		DeleteObject(pen);
	}

	inline void DrawFilledRect(HDC hdc, int x, int y, int w, int h, COLORREF color)
	{
		HBRUSH brush = CreateSolidBrush(color);
		RECT rc = { x, y, x + w, y + h };
		FillRect(hdc, &rc, brush);
		DeleteObject(brush);
	}

	inline void DrawString(HDC hdc, int x, int y, const char* text, COLORREF color, HFONT font = NULL)
	{
		if (font) SelectObject(hdc, font);
		SetTextColor(hdc, color);
		SetBkMode(hdc, TRANSPARENT);
		TextOutA(hdc, x, y, text, (int)strlen(text));
	}

	inline void DrawHealthBar(HDC hdc, int x, int y, int w, int h, float healthPercent)
	{
		DrawFilledRect(hdc, x, y, w, h, RGB(1, 1, 1));
		DrawFilledRect(hdc, x + 1, y + 1, w - 2, h - 2, RGB(20, 20, 20));
		int fillH = (int)((h - 2) * healthPercent);
		int r = (int)(255 * (1.0f - healthPercent));
		int g = (int)(255 * healthPercent);
		DrawFilledRect(hdc, x + 1, y + 1 + (h - 2 - fillH), w - 2, fillH, RGB(r, g, 0));
	}

	inline void DrawCircle(HDC hdc, int cx, int cy, int radius, COLORREF color)
	{
		HPEN pen = CreatePen(PS_SOLID, 1, color);
		HPEN oldPen = (HPEN)SelectObject(hdc, pen);
		HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
		Ellipse(hdc, cx - radius, cy - radius, cx + radius, cy + radius);
		SelectObject(hdc, oldBrush);
		SelectObject(hdc, oldPen);
		DeleteObject(pen);
	}

	inline void DrawFilledCircle(HDC hdc, int cx, int cy, int radius, COLORREF color)
	{
		HBRUSH brush = CreateSolidBrush(color);
		HPEN pen = CreatePen(PS_SOLID, 1, color);
		HPEN oldPen = (HPEN)SelectObject(hdc, pen);
		HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, brush);
		Ellipse(hdc, cx - radius, cy - radius, cx + radius, cy + radius);
		SelectObject(hdc, oldBrush);
		SelectObject(hdc, oldPen);
		DeleteObject(pen);
		DeleteObject(brush);
	}

	inline void RenderRadar(HDC hdc)
	{
		if (!Config::radar) return;

		int radarSize = 180;
		int radarX = screenW - radarSize - 15;
		int radarY = 15;
		int radarCX = radarX + radarSize / 2;
		int radarCY = radarY + radarSize / 2;
		float radarRange = 150.0f;

		DrawFilledRect(hdc, radarX, radarY, radarSize, radarSize, RGB(10, 10, 10));
		DrawOutlinedRect(hdc, radarX, radarY, radarSize, radarSize, RGB(80, 80, 80), 1);
		DrawLine(hdc, radarCX, radarY, radarCX, radarY + radarSize, RGB(40, 40, 40));
		DrawLine(hdc, radarX, radarCY, radarX + radarSize, radarCY, RGB(40, 40, 40));
		DrawFilledCircle(hdc, radarCX, radarCY, 3, RGB(0, 255, 0));

		float yawRad = DEG2RAD(localYaw);

		for (int i = 0; i < playerCount; i++)
		{
			auto& p = players[i];
			if (!p.valid) continue;

			float dx = p.feetPos.x - localCamPos.x;
			float dz = p.feetPos.z - localCamPos.z;
			float rotX = dx * cosf(-yawRad) - dz * sinf(-yawRad);
			float rotZ = dx * sinf(-yawRad) + dz * cosf(-yawRad);

			int dotX = radarCX + (int)(rotX / radarRange * (radarSize / 2));
			int dotY = radarCY - (int)(rotZ / radarRange * (radarSize / 2));

			if (dotX < radarX + 3 || dotX > radarX + radarSize - 3) continue;
			if (dotY < radarY + 3 || dotY > radarY + radarSize - 3) continue;

			COLORREF dotColor = p.isTarget ? RGB(255, 255, 0) : RGB(255, 50, 50);
			DrawFilledCircle(hdc, dotX, dotY, 3, dotColor);
		}

		for (int i = 0; i < zombieCount && Config::zombieESP; i++)
		{
			auto& z = zombies[i];
			if (!z.valid) continue;

			float dx = z.pos.x - localCamPos.x;
			float dz = z.pos.z - localCamPos.z;
			float rotX = dx * cosf(-yawRad) - dz * sinf(-yawRad);
			float rotZ = dx * sinf(-yawRad) + dz * cosf(-yawRad);

			int dotX = radarCX + (int)(rotX / radarRange * (radarSize / 2));
			int dotY = radarCY - (int)(rotZ / radarRange * (radarSize / 2));

			if (dotX < radarX + 2 || dotX > radarX + radarSize - 2) continue;
			if (dotY < radarY + 2 || dotY > radarY + radarSize - 2) continue;

			DrawFilledCircle(hdc, dotX, dotY, 2, RGB(180, 0, 180));
		}
	}

	inline void RenderESP(HDC hdc)
	{
		if (!Config::esp) return;

		if (Config::aimbot || Config::silentAim)
		{
			float fovRadius = (Config::aimbotFOV / Config::gameFOV) * screenW * 0.5f;
			DrawCircle(hdc, screenW / 2, screenH / 2, (int)fovRadius, RGB(255, 255, 255));
		}

		for (int i = 0; i < playerCount; i++)
		{
			auto& p = players[i];
			if (!p.valid) continue;

			vector3 screenFeet, screenHead;
			if (!Math::WorldToScreen(p.feetPos, localCamPos, localYaw, localPitch,
				Config::gameFOV, screenW, screenH, screenFeet))
				continue;
			if (!Math::WorldToScreen(p.headPos, localCamPos, localYaw, localPitch,
				Config::gameFOV, screenW, screenH, screenHead))
				continue;

			float boxH = fabsf(screenFeet.y - screenHead.y);
			float boxW = boxH * 0.45f;
			int bx = (int)(screenHead.x - boxW * 0.5f);
			int by = (int)screenHead.y;
			int bw = (int)boxW;
			int bh = (int)boxH;

			COLORREF boxColor = p.isTarget ? RGB(255, 255, 0) : RGB(255, 50, 50);

			if (Config::espBoxes)
				DrawOutlinedRectOutline(hdc, bx, by, bw, bh, boxColor);

			if (Config::espHealth)
			{
				float hp = p.health / 100.0f;
				if (hp > 1.0f) hp = 1.0f;
				DrawHealthBar(hdc, bx - 6, by, 4, bh, hp);

				char hpText[16];
				sprintf_s(hpText, "%.0f HP", p.health);
				int r = (int)(255 * (1.0f - hp));
				int g = (int)(255 * hp);
				DrawString(hdc, bx + bw + 4, by, hpText, RGB(r, g, 0), espFontSmall);
			}

			int textY = by - 14;
			if (Config::espNames && p.name[0])
			{
				DrawString(hdc, bx, textY, p.name, RGB(255, 255, 255), espFontSmall);
				textY -= 14;
			}

			if (Config::espDistance)
			{
				char distText[32];
				sprintf_s(distText, "%.0fm", p.distance);
				DrawString(hdc, bx, (int)(screenFeet.y + 2), distText, RGB(200, 200, 200), espFontSmall);
			}

			if (Config::espSnaplines)
				DrawLine(hdc, screenW / 2, screenH, (int)screenFeet.x, (int)screenFeet.y, RGB(255, 255, 0), 1);
		}

		// Vehicle ESP
		if (Config::vehicleESP)
		{
			for (int i = 0; i < vehicleCount; i++)
			{
				auto& v = vehicles[i];
				if (!v.valid) continue;
				vector3 sp;
				if (!Math::WorldToScreen(v.pos, localCamPos, localYaw, localPitch,
					Config::gameFOV, screenW, screenH, sp)) continue;
				char txt[32];
				sprintf_s(txt, "Vehicle [%.0fm]", v.distance);
				DrawString(hdc, (int)sp.x - 30, (int)sp.y, txt, RGB(0, 200, 255), espFontSmall);
			}
		}

		// Item ESP
		if (Config::itemESP)
		{
			for (int i = 0; i < itemCount; i++)
			{
				auto& item = items[i];
				if (!item.valid) continue;
				vector3 sp;
				if (!Math::WorldToScreen(item.pos, localCamPos, localYaw, localPitch,
					Config::gameFOV, screenW, screenH, sp)) continue;
				char txt[64];
				sprintf_s(txt, "%s [%.0fm]", item.name, item.distance);
				DrawString(hdc, (int)sp.x - 20, (int)sp.y, txt, RGB(255, 200, 0), espFontSmall);
			}
		}

		// Zombie ESP
		if (Config::zombieESP)
		{
			for (int i = 0; i < zombieCount; i++)
			{
				auto& z = zombies[i];
				if (!z.valid) continue;
				vector3 sp;
				if (!Math::WorldToScreen(z.pos, localCamPos, localYaw, localPitch,
					Config::gameFOV, screenW, screenH, sp)) continue;
				char txt[32];
				sprintf_s(txt, "Zombie [%.0fm]", z.distance);
				DrawString(hdc, (int)sp.x - 25, (int)sp.y, txt, RGB(180, 0, 180), espFontSmall);
			}
		}
	}

	inline LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
	{
		switch (msg)
		{
		case WM_DESTROY:
			PostQuitMessage(0);
			return 0;
		case WM_PAINT:
		{
			PAINTSTRUCT ps;
			BeginPaint(hwnd, &ps);
			EndPaint(hwnd, &ps);
			return 0;
		}
		}
		return DefWindowProcA(hwnd, msg, wParam, lParam);
	}

	inline void Run()
	{
		screenW = GetSystemMetrics(SM_CXSCREEN);
		screenH = GetSystemMetrics(SM_CYSCREEN);

		WNDCLASSEXA wc = {};
		wc.cbSize = sizeof(wc);
		wc.style = CS_HREDRAW | CS_VREDRAW;
		wc.lpfnWndProc = WndProc;
		wc.hInstance = GetModuleHandle(NULL);
		wc.lpszClassName = "UnturnedDMAOverlay";
		wc.hCursor = LoadCursor(NULL, IDC_ARROW);
		RegisterClassExA(&wc);

		DWORD exStyle = WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE;
		if (!Config::streamProof)
			exStyle |= WS_EX_TOPMOST;

		overlayWnd = CreateWindowExA(
			exStyle,
			"UnturnedDMAOverlay", "",
			WS_POPUP,
			0, 0, screenW, screenH,
			NULL, NULL, GetModuleHandle(NULL), NULL);

		if (!overlayWnd) return;

		if (Config::streamProof)
			SetWindowDisplayAffinity(overlayWnd, WDA_EXCLUDEFROMCAPTURE);

		SetLayeredWindowAttributes(overlayWnd, RGB(0, 0, 0), 0, LWA_COLORKEY);
		ShowWindow(overlayWnd, SW_SHOWNOACTIVATE);

		espFont = CreateFontA(16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
			DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
			ANTIALIASED_QUALITY, DEFAULT_PITCH, "Consolas");

		espFontSmall = CreateFontA(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
			DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
			ANTIALIASED_QUALITY, DEFAULT_PITCH, "Consolas");

		MSG msg;
		while (running)
		{
			while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE))
			{
				if (msg.message == WM_QUIT)
				{
					running = false;
					break;
				}
				TranslateMessage(&msg);
				DispatchMessageA(&msg);
			}

			if (Config::streamProof)
				SetWindowPos(overlayWnd, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);

			HDC hdc = GetDC(overlayWnd);
			HDC memDC = CreateCompatibleDC(hdc);
			HBITMAP memBmp = CreateCompatibleBitmap(hdc, screenW, screenH);
			HBITMAP oldBmp = (HBITMAP)SelectObject(memDC, memBmp);

			RECT clearRect = { 0, 0, screenW, screenH };
			HBRUSH clearBrush = CreateSolidBrush(RGB(0, 0, 0));
			FillRect(memDC, &clearRect, clearBrush);
			DeleteObject(clearBrush);

			SelectObject(memDC, espFont);
			RenderESP(memDC);
			RenderRadar(memDC);

			// DMA status watermark
			DrawString(memDC, 5, screenH - 20, "DMA RADAR | Streamproof", RGB(0, 255, 100), espFontSmall);

			BitBlt(hdc, 0, 0, screenW, screenH, memDC, 0, 0, SRCCOPY);

			SelectObject(memDC, oldBmp);
			DeleteObject(memBmp);
			DeleteDC(memDC);
			ReleaseDC(overlayWnd, hdc);

			Sleep(16);
		}

		if (espFont) DeleteObject(espFont);
		if (espFontSmall) DeleteObject(espFontSmall);
		if (overlayWnd) DestroyWindow(overlayWnd);
		UnregisterClassA("UnturnedDMAOverlay", GetModuleHandle(NULL));
	}

	inline void Shutdown()
	{
		running = false;
	}
}
