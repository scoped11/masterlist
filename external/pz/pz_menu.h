#pragma once
#include <Windows.h>
#include <atomic>

namespace PzMenu
{
	inline std::atomic<bool> running{ false };
	inline HWND hwnd = nullptr;

	bool Start(HINSTANCE inst);
	void Stop();
	void SyncControlsFromConfig();
	void PollMessages(); // call each frame from main loop
}