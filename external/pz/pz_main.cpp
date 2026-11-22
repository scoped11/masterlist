// pz_viewer — external live player viewer (read-only positions).
// Modes + GDI menu toggles (viewer display only).

#undef UNICODE
#undef _UNICODE
#include <Windows.h>
#include <cstdio>
#include <cstring>
#include "pz_config.h"
#include "pz_game.h"
#include "pz_webserver.h"
#include "pz_overlay.h"
#include "pz_mem.h"
#include "pz_menu.h"
#include "pz_log.h"

static void PrintConsolePlayers()
{
	std::lock_guard<std::mutex> lock(PzGame::stateMu);
	printf("--- %d players (mock=%d) ---\n", PzGame::playerCount, PzGame::usingMock.load() ? 1 : 0);
	for (int i = 0; i < PzGame::playerCount; i++)
	{
		if (!PzGame::players[i].valid) continue;
		printf("  %s  xy=(%.0f, %.0f) z=%.1f\n",
			PzGame::players[i].name, PzGame::players[i].pos.x, PzGame::players[i].pos.y, PzGame::players[i].pos.z);
	}
}

static void Usage()
{
	printf("pz_viewer.exe [--config path] [--no-menu]\n");
	printf("Hotkeys: F6 cycle legacy mode, END exit\n");
	printf("Menu toggles: web radar, overlay, names, distances, poll, data source\n");
}

int main(int argc, char** argv)
{
	const char* cfgPath = "external/pz/pz_config.ini";
	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "--help") == 0) { Usage(); return 0; }
		if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) { cfgPath = argv[++i]; continue; }
		if (strcmp(argv[i], "--no-menu") == 0) { PzConfig::showMenu = false; continue; }
		if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) { PzConfig::mode = PzConfig::ParseMode(argv[++i]); continue; }
	}

	PzConfig::LoadIni(cfgPath);
	PzConfig::LoadIni(PzConfig::offsetsPath.c_str());

	// Legacy mode field still hints default toggles if user has not used menu yet
	if (PzConfig::mode == ViewMode::WebRadar) PzConfig::webRadarEnabled = true;
	if (PzConfig::mode == ViewMode::Overlay) PzConfig::overlayEnabled = true;

	PZ_LOG("pz_viewer — display-only menu, no cheat / bypass wiring");
	PZ_LOG("offsets: OnlinePlayersStatic=0x%llX (0=unset)", (unsigned long long)PzConfig::onlinePlayersStatic);

	if (PzConfig::showMenu)
		PzMenu::Start(GetModuleHandle(nullptr));
	else
	{
		if (PzConfig::webRadarEnabled) PzWeb::Start();
		if (PzConfig::overlayEnabled) PzOverlay::Start();
	}

	for (;;)
	{
		if (GetAsyncKeyState(VK_F6) & 1)
			PzConfig::mode = PzConfig::NextMode(PzConfig::mode);
		if (GetAsyncKeyState(VK_END) & 1)
			break;

		PzMenu::PollMessages();
		PzGame::Update();

		if (PzConfig::mode == ViewMode::Console)
			PrintConsolePlayers();
		if (PzConfig::overlayEnabled)
			PzOverlay::Invalidate();

		Sleep(PzConfig::pollMs);
	}

	PzMenu::Stop();
	PzWeb::Stop();
	PzOverlay::Stop();
	PzMem::Detach();
	return 0;
}