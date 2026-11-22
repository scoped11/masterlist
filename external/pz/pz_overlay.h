#pragma once
#include "pz_game.h"
#include "pz_config.h"
#include "pz_log.h"
#include <cmath>
#include <Windows.h>
#include <atomic>
#include <thread>
#include <cstdio>

namespace PzOverlay
{
	inline HWND hwnd = nullptr;
	inline std::atomic<bool> running{ false };
	inline std::thread thread;

	inline LRESULT CALLBACK WndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
	{
		if (msg == WM_PAINT)
		{
			PAINTSTRUCT ps{};
			HDC dc = BeginPaint(h, &ps);
			RECT rc; GetClientRect(h, &rc);
			FillRect(dc, &rc, (HBRUSH)(COLOR_WINDOW + 1));
			SetBkMode(dc, TRANSPARENT);

			char header[128];
			sprintf_s(header, "PZ viewer — overlay mode (read-only)");
			TextOutA(dc, 8, 8, header, (int)strlen(header));

			std::lock_guard<std::mutex> lock(PzGame::stateMu);
			int y = 32;
			for (int i = 0; i < PzGame::playerCount; i++)
			{
				if (!PzGame::players[i].valid) continue;
				char line[160];
				float dx = PzGame::players[i].pos.x - PzGame::localPos.x;
				float dy = PzGame::players[i].pos.y - PzGame::localPos.y;
				float dist = sqrtf(dx * dx + dy * dy);
				if (PzConfig::showNames && PzConfig::showDistances)
					sprintf_s(line, "%s  (%.0f, %.0f)  %.0fm", PzGame::players[i].name,
						PzGame::players[i].pos.x, PzGame::players[i].pos.y, dist);
				else if (PzConfig::showNames)
					sprintf_s(line, "%s", PzGame::players[i].name);
				else if (PzConfig::showDistances)
					sprintf_s(line, "(%.0f, %.0f)  %.0fm", PzGame::players[i].pos.x, PzGame::players[i].pos.y, dist);
				else
					sprintf_s(line, "(%.0f, %.0f)", PzGame::players[i].pos.x, PzGame::players[i].pos.y);
				TextOutA(dc, 8, y, line, (int)strlen(line));
				y += 18;
				if (y > rc.bottom - 20) break;
			}
			EndPaint(h, &ps);
			return 0;
		}
		if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
		return DefWindowProc(h, msg, wp, lp);
	}

	inline void MessageLoop()
	{
		MSG msg{};
		while (running.load() && GetMessage(&msg, nullptr, 0, 0))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	inline bool Start()
	{
		if (running.load()) return true;
		WNDCLASSA wc{};
		wc.lpfnWndProc = WndProc;
		wc.hInstance = GetModuleHandle(nullptr);
		wc.lpszClassName = "PzViewerOverlay";
		wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
		RegisterClassA(&wc);
		hwnd = CreateWindowExA(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, "PzViewerOverlay",
			"pz_viewer overlay", WS_OVERLAPPEDWINDOW, 120, 120, 420, 320, nullptr, nullptr, wc.hInstance, nullptr);
		if (!hwnd) return false;
		ShowWindow(hwnd, SW_SHOW);
		running = true;
		thread = std::thread(MessageLoop);
		PZ_LOG("overlay window started");
		return true;
	}

	inline void Stop()
	{
		running = false;
		if (hwnd) { DestroyWindow(hwnd); hwnd = nullptr; }
		if (thread.joinable()) thread.join();
	}

	inline void Invalidate()
	{
		if (hwnd) InvalidateRect(hwnd, nullptr, TRUE);
	}
}