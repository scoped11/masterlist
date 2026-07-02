#include "external/features.h"
#include <thread>
#include <wbemidl.h>
#include <filesystem>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(linker, "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\"")

extern DWORD64 baseAddress;
extern uintptr_t GET_ROOT_DOMAIN_OFFSET;

using namespace std;

static bool g_internalMode = false;

static bool IsDeviceOpen(const char* path)
{
	HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return true; }
	return false;
}

// Detects Speeder's kernel driver by looking for a short random-named
// driver running directly from system32\drivers\ (not DriverStore).
static bool IsSpeederDriverLoaded()
{
	SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
	if (!scm) return false;

	DWORD needed = 0, count = 0, resume = 0;
	EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO,
		SERVICE_DRIVER, SERVICE_ACTIVE, nullptr, 0, &needed, &count, &resume, nullptr);

	std::vector<BYTE> buf(needed);
	resume = 0;
	if (!EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO,
		SERVICE_DRIVER, SERVICE_ACTIVE,
		buf.data(), needed, &needed, &count, &resume, nullptr))
	{
		CloseServiceHandle(scm); return false;
	}

	auto* entries = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSA*>(buf.data());
	bool found = false;
	for (DWORD i = 0; i < count && !found; i++)
	{
		std::string name = entries[i].lpServiceName;
		if (name.size() < 3 || name.size() > 8) continue;

		// Open to get binary path
		SC_HANDLE svc = OpenServiceA(scm, name.c_str(), SERVICE_QUERY_CONFIG);
		if (!svc) continue;

		DWORD cbNeeded = 0;
		QueryServiceConfigA(svc, nullptr, 0, &cbNeeded);
		std::vector<BYTE> cfgBuf(cbNeeded);
		auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGA*>(cfgBuf.data());
		if (QueryServiceConfigA(svc, cfg, cbNeeded, &cbNeeded))
		{
			std::string path = cfg->lpBinaryPathName ? cfg->lpBinaryPathName : "";
			// Speeder driver is directly in system32\drivers\, not DriverStore
			bool inDrivers = (path.find("system32\\drivers\\") != std::string::npos ||
			                  path.find("System32\\drivers\\") != std::string::npos ||
			                  path.find("SystemRoot\\System32\\drivers\\") != std::string::npos);
			bool notDriverStore = (path.find("DriverStore") == std::string::npos);
			// Mixed-case short name is characteristic of Speeder's random naming
			bool hasMixedCase = false;
			bool hasUpper = false, hasLower = false;
			for (char c : name) { if (isupper(c)) hasUpper = true; if (islower(c)) hasLower = true; }
			hasMixedCase = hasUpper && hasLower;

			if (inDrivers && notDriverStore && hasMixedCase)
				found = true;
		}
		CloseServiceHandle(svc);
	}

	CloseServiceHandle(scm);
	return found;
}

static bool IsHypervisorActive()
{
	int cpuInfo[4] = {};
	__cpuid(cpuInfo, 1);
	return (cpuInfo[2] & (1 << 31)) != 0;
}

static bool LaunchMapper()
{
	char exePath[MAX_PATH];
	GetModuleFileNameA(nullptr, exePath, MAX_PATH);
	std::string exeDir(exePath);
	exeDir = exeDir.substr(0, exeDir.find_last_of("\\/") + 1);

	std::string mapperPath = exeDir + "mapper_nal.exe";
	std::string driverPath = exeDir + "Betest.sys";
	if (!std::filesystem::exists(driverPath))
		driverPath = exeDir + "BetestD.sys";

	if (!std::filesystem::exists(mapperPath)) {
		Log("[!] mapper_nal.exe not found in: %s", exeDir.c_str());
		Log("    Place mapper_nal.exe and Betest.sys next to externaltest.exe");
		return false;
	}
	if (!std::filesystem::exists(driverPath)) {
		Log("[!] Betest.sys not found in: %s", exeDir.c_str());
		return false;
	}

	if (IsHypervisorActive()) {
		Log("[!] Hypervisor detected - using NalDrv (--driver nal) to avoid PML4 scan freeze");
	}

	std::string cmd = "\"" + mapperPath + "\" \"" + driverPath +
		"\" --driver nal --stealth 3f --eac 7f --hwid 1f --no-auth";
	Log("[*] Running: %s", cmd.c_str());

	STARTUPINFOA si{}; si.cb = sizeof(si);
	PROCESS_INFORMATION pi{};
	if (!CreateProcessA(nullptr, (LPSTR)cmd.c_str(), nullptr, nullptr, FALSE,
		0, nullptr, exeDir.c_str(), &si, &pi)) {
		Log("[!] Failed to launch mapper: %lu", GetLastError());
		return false;
	}

	Log("[*] Mapper running (PID %lu), waiting...", pi.dwProcessId);
	WaitForSingleObject(pi.hProcess, 120000);

	DWORD exitCode = 0;
	GetExitCodeProcess(pi.hProcess, &exitCode);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	if (exitCode != 0) {
		Log("[!] Mapper exited with code %lu", exitCode);
		return false;
	}

	Log("[+] Mapper completed successfully");

	SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
	if (scm) {
		const char* svcNames[] = { "TrixxSvc", "SivSvc", "WdBroker", "NalDrv", "NalDrvIntel", "iqvw64e", "TsSvc" };
		for (auto sn : svcNames) {
			SC_HANDLE svc = OpenServiceA(scm, sn, SERVICE_ALL_ACCESS);
			if (svc) {
				SERVICE_STATUS ss;
				ControlService(svc, SERVICE_CONTROL_STOP, &ss);
				DeleteService(svc);
				CloseServiceHandle(svc);
			}
		}
		CloseServiceHandle(scm);
		Log("[+] BYOVD service entries cleaned");
	}

	Sleep(1000);
	return true;
}

static bool RunStartupChecks()
{
	Log("========================================");
	Log("        STARTUP DRIVER CHECKS");
	Log("========================================");

	Log("[1/1] Checking Betest driver...");
	const char* names[] = {
		"\\\\.\\MsFlt0", "\\\\.\\WdFilter1", "\\\\.\\FltMgr2",
		"\\\\.\\NdProxy0", "\\\\.\\TdiFilter", "\\\\.\\MsSecFlt",
		"\\\\.\\WfpDrv0", "\\\\.\\NtFilter1",
	};
	for (int i = 0; i < 8; i++)
	{
		if (IsDeviceOpen(names[i]))
		{
			Log("    [+] Betest driver ready (%s).", names[i]);
			Log("========================================");
			return true;
		}
	}

	Log("[!] Driver not found - launching mapper with EAC hardening...");
	if (!LaunchMapper()) {
		Log("[!] Auto-launch failed - run mapper_nal.exe manually.");
		Log("========================================");
		return false;
	}

	for (int i = 0; i < 8; i++)
	{
		if (IsDeviceOpen(names[i]))
		{
			Log("    [+] Betest driver ready (%s).", names[i]);
			Log("========================================");
			return true;
		}
	}

	Log("[!] Driver still not available after mapper ran.");
	Log("========================================");
	return false;
}

int main(int argc, char* argv[])
{
	//ShowWindow(GetConsoleWindow(), SW_HIDE);
	//FreeConsole();

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--internal") == 0) g_internalMode = true;
		if (strcmp(argv[i], "--external") == 0) g_internalMode = false;
	}

	Log("=== Unturned Cheat — %s mode ===", g_internalMode ? "INTERNAL" : "EXTERNAL");

	if (g_internalMode) {
		Log("[*] Internal mode: launching injector for DLL injection into Unturned.exe");
		char exePath[MAX_PATH];
		GetModuleFileNameA(nullptr, exePath, MAX_PATH);
		std::string exeDir(exePath);
		exeDir = exeDir.substr(0, exeDir.find_last_of("\\/") + 1);

		std::string injPath = exeDir + "injector.exe";
		if (!std::filesystem::exists(injPath)) {
			Log("[!] injector.exe not found in: %s", exeDir.c_str());
			Log("    Place injector.exe next to externaltest.exe for internal mode.");
			system("pause");
			return 1;
		}

		std::string dllPath = exeDir + "unturned_internal.dll";
		if (!std::filesystem::exists(dllPath)) {
			Log("[!] unturned_internal.dll not found in: %s", exeDir.c_str());
			Log("    Build the internal DLL and place it next to externaltest.exe.");
			system("pause");
			return 1;
		}

		std::string cmd = "\"" + injPath + "\" --proc Unturned.exe --dll \"" + dllPath + "\" --eac 7f";
		Log("[*] Running: %s", cmd.c_str());
		STARTUPINFOA si{}; si.cb = sizeof(si);
		PROCESS_INFORMATION pi{};
		if (!CreateProcessA(nullptr, (LPSTR)cmd.c_str(), nullptr, nullptr, FALSE,
			0, nullptr, exeDir.c_str(), &si, &pi)) {
			Log("[!] Failed to launch injector: %lu", GetLastError());
			system("pause");
			return 1;
		}
		WaitForSingleObject(pi.hProcess, 60000);
		DWORD exitCode = 0;
		GetExitCodeProcess(pi.hProcess, &exitCode);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		Log("[+] Injector exited with code %lu", exitCode);
		if (exitCode == 0)
			Log("[+] Internal injection complete — cheat running inside Unturned.exe");
		system("pause");
		return (int)exitCode;
	}

	Log("Initializing external mode...");
	if (!RunStartupChecks())
	{
		system("pause");
		return 1;
	}

	Memory::init();

	if (!hProc)
	{
		Log("Failed to attach to Unturned.exe - make sure the game is running");
		system("pause");
		return 1;
	}

	Log("Attached to Unturned.exe");
	Log("Resolving classes...");
	// Retry until mono assemblies are loaded (game may still be booting).
	// Also re-resolve the mono base/root-domain offset each attempt in case
	// the DLL wasn't in the PEB yet when Memory::init() ran.
	while (true)
	{
		if (!baseAddress || !GET_ROOT_DOMAIN_OFFSET)
			Memory::resolve_mono();
		Classes::init();
		if (Classes::Player && Classes::Provider)
			break;
		if (GetAsyncKeyState(VK_END) & 1) return 0;
		Log("Mono not ready yet, retrying in 2s...");
		Sleep(2000);
	}

	Log("Resolving offsets...");
	Offsets::init();
	// Log missing critical offsets so features can be diagnosed
	if (!Offsets::_look || !Offsets::_yaw || !Offsets::_pitch)
		Log("WARNING: Look/yaw/pitch offsets missing — aimbot will not work");
	if (!Offsets::recoilMin_x)
		Log("WARNING: Recoil offsets missing — no-recoil will not work");
	if (!Offsets::_life || !Offsets::_health)
		Log("WARNING: Life/health offsets missing — god mode / health ESP may not work");
	if (!Offsets::_clients)
		Log("WARNING: Clients offset missing — player ESP will not work");

	if (Offsets::_isConnected)
	{
		Log("Waiting for server connection...");
		while (!SDG::Provider::isConnected())
		{
			if (GetAsyncKeyState(VK_END) & 1) return 0;
			Sleep(1000);
			printf(".");
		}
		printf("\n");
	}
	else
	{
		Log("_isConnected offset missing - skipping connection check, waiting 3s for game to load...");
		Sleep(3000);
	}

	Log("Waiting for local player to spawn...");
	SDG::Player* localPlayer = nullptr;
	while (!(localPlayer = Features::GetLocalPlayer()))
	{
		if (GetAsyncKeyState(VK_END) & 1) return 0;
		Sleep(500);
	}

	Log("Local player: %p", localPlayer);
	{
		auto _go = localPlayer->gameObject();
		if (_go) {
			auto pos = _go->transform().position();
			Log("Position: %s", pos.toString().c_str());
		}
	}

	// Start overlay thread
	std::thread overlayThread(Overlay::Run);
	overlayThread.detach();

	Log("Press END to exit.");
	Sleep(300);

	Config::PrintMenu();

	while (true)
	{
		if (GetAsyncKeyState(VK_END) & 1)
			break;

		// Track previous state for menu refresh
		bool prev[] = {
			Config::aimbot, Config::silentAim, Config::esp,
			Config::noRecoil, Config::noSpread, Config::rapidFire,
			Config::infiniteRange, Config::godMode, Config::speedHack,
			Config::flyHack, Config::superJump, Config::adminMode,
			Config::vehicleFly, Config::noFallDamage,
			Config::extendedMelee, Config::noScopeSway,
			Config::spinBot, Config::triggerbot, Config::radar,
			Config::itemESP, Config::zombieESP, Config::vehicleESP,
			Config::fullbright, Config::fovChanger, Config::instantReload
		};
		float prevSpeed = Config::speedMultiplier;
		float prevFov = Config::aimbotFOV;
		float prevCustomFov = Config::customFOV;

		bool cur[] = {
			Config::aimbot, Config::silentAim, Config::esp,
			Config::noRecoil, Config::noSpread, Config::rapidFire,
			Config::infiniteRange, Config::godMode, Config::speedHack,
			Config::flyHack, Config::superJump, Config::adminMode,
			Config::vehicleFly, Config::noFallDamage,
			Config::extendedMelee, Config::noScopeSway,
			Config::spinBot, Config::triggerbot, Config::radar,
			Config::itemESP, Config::zombieESP, Config::vehicleESP,
			Config::fullbright, Config::fovChanger, Config::instantReload
		};

		bool changed = (prevSpeed != Config::speedMultiplier) || (prevFov != Config::aimbotFOV) || (prevCustomFov != Config::customFOV);
		for (int i = 0; i < 25 && !changed; i++)
			if (prev[i] != cur[i]) changed = true;
		if (changed) Config::PrintMenu();

		if (Offsets::_isConnected && !SDG::Provider::isConnected())
		{
			Sleep(1000);
			continue;
		}

		localPlayer = Features::GetLocalPlayer();
		if (!localPlayer)
		{
			Sleep(500);
			continue;
		}

		Config::ProcessHotkeys();
		Features::Update(localPlayer);

		Sleep(3 + (GetTickCount() % 7));
	}

	Log("Shutting down...");
	Overlay::Shutdown();
	Sleep(200);

	// Reset multipliers on exit
	auto lp = Features::GetLocalPlayer();
	if (lp && Offsets::_movement)
	{
		auto mv = lp->movement();
		if (mv && (uintptr_t)mv > 0x10000)
		{
			if (Offsets::pluginSpeedMultiplier) mv->pluginSpeedMultiplier_set(1.0f);
			if (Offsets::pluginJumpMultiplier) mv->pluginJumpMultiplier_set(1.0f);
			if (Offsets::pluginGravityMultiplier) mv->pluginGravityMultiplier_set(1.0f);
		}

		// Reset falling damage multiplier
		if (Offsets::_clothing && Offsets::fallingDamageMultiplier)
		{
			uintptr_t clothingPtr = read<uintptr_t>((uintptr_t)lp + Offsets::_clothing);
			if (clothingPtr && clothingPtr > 0x10000)
				write<float>(1.0f, clothingPtr + Offsets::fallingDamageMultiplier);
		}
	}

	// Reset fullbright
	Config::fullbright = false;
	Features::UpdateFullbright();

	// Reset FOV
	Config::fovChanger = false;
	Features::UpdateFOVChanger();

	return 0;
}
