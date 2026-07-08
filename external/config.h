#pragma once
#include <Windows.h>
#include <cstdio>

namespace Config
{
	inline bool aimbot = false;
	inline bool silentAim = false;
	inline bool esp = false;
	inline bool noRecoil = false;
	inline bool noSpread = false;
	inline bool rapidFire = false;
	inline bool infiniteRange = false;
	inline bool godMode = false;
	inline bool speedHack = false;
	inline bool flyHack = false;
	inline bool superJump = false;
	inline bool adminMode = true;
	inline bool vehicleFly = false;
	inline bool noFallDamage = false;
	inline bool extendedMelee = false;
	inline bool noScopeSway = false;
	inline bool spinBot = false;
	inline bool triggerbot = false;
	inline bool radar = false;
	inline bool itemESP = false;
	inline bool zombieESP = false;
	inline bool vehicleESP = false;
	inline bool fullbright = false;
	inline bool fovChanger = false;
	inline bool instantReload = false;
	inline bool streamProof = true;
	inline bool chams = false;
	inline bool noFlinch = false;

	inline float speedMultiplier = 2.0f;
	inline float jumpMultiplier = 3.0f;
	inline float aimbotFOV = 20.0f;
	inline float aimbotSmooth = 3.0f;
	inline float gameFOV = 90.0f;
	inline float customFOV = 120.0f;

	inline bool espBoxes = true;
	inline bool espHealth = true;
	inline bool espDistance = true;
	inline bool espSnaplines = true;
	inline bool espNames = true;

	inline void HandleHotkeys()
	{
		if (GetAsyncKeyState(VK_F1) & 1) aimbot = !aimbot;
		if (GetAsyncKeyState(VK_F2) & 1) silentAim = !silentAim;
		if (GetAsyncKeyState(VK_F3) & 1) esp = !esp;
		if (GetAsyncKeyState(VK_F4) & 1) noRecoil = !noRecoil;
		if (GetAsyncKeyState(VK_F5) & 1) noSpread = !noSpread;
		if (GetAsyncKeyState(VK_F6) & 1) rapidFire = !rapidFire;
		if (GetAsyncKeyState(VK_F7) & 1) infiniteRange = !infiniteRange;
		if (GetAsyncKeyState(VK_F8) & 1) godMode = !godMode;
		if (GetAsyncKeyState(VK_F9) & 1) speedHack = !speedHack;
		if (GetAsyncKeyState(VK_F10) & 1) flyHack = !flyHack;
		if (GetAsyncKeyState(VK_F11) & 1) superJump = !superJump;
		if (GetAsyncKeyState(VK_INSERT) & 1) adminMode = !adminMode;
		if (GetAsyncKeyState(VK_HOME) & 1) vehicleFly = !vehicleFly;
		if (GetAsyncKeyState(0x4F) & 1) noFallDamage = !noFallDamage;
		if (GetAsyncKeyState(0x50) & 1) extendedMelee = !extendedMelee;
		if (GetAsyncKeyState(0x4C) & 1) noScopeSway = !noScopeSway;
		if (GetAsyncKeyState(0x4B) & 1) spinBot = !spinBot;
		if (GetAsyncKeyState(0x4A) & 1) triggerbot = !triggerbot;
		if (GetAsyncKeyState(0x4D) & 1) radar = !radar;
		if (GetAsyncKeyState(0x49) & 1) itemESP = !itemESP;
		if (GetAsyncKeyState(0x55) & 1) zombieESP = !zombieESP;
		if (GetAsyncKeyState(0x4E) & 1) vehicleESP = !vehicleESP;
		if (GetAsyncKeyState(0x42) & 1) fullbright = !fullbright;
		if (GetAsyncKeyState(0x47) & 1) fovChanger = !fovChanger;
		if (GetAsyncKeyState(0x54) & 1) instantReload = !instantReload;
		if (GetAsyncKeyState(0x59) & 1) streamProof = !streamProof;
		if (GetAsyncKeyState(0x58) & 1) chams = !chams;
		if (GetAsyncKeyState(0x48) & 1) noFlinch = !noFlinch;

		if (GetAsyncKeyState(VK_ADD) & 1)
		{
			speedMultiplier += 0.5f;
			aimbotFOV += 2.0f;
			customFOV += 5.0f;
		}
		if (GetAsyncKeyState(VK_SUBTRACT) & 1)
		{
			speedMultiplier = max(1.0f, speedMultiplier - 0.5f);
			aimbotFOV = max(2.0f, aimbotFOV - 2.0f);
			customFOV = max(60.0f, customFOV - 5.0f);
		}
	}

	inline void PrintMenu()
	{
		printf("========================================\n");
		printf("     UNTURNED DLL - INTERNAL\n");
		printf("========================================\n");
		printf(" [F1]   Aimbot:        %s  (hold RMB)\n", aimbot ? "ON " : "OFF");
		printf(" [F2]   Silent Aim:    %s  (auto on LMB)\n", silentAim ? "ON " : "OFF");
		printf(" [F3]   ESP:           %s  (overlay)\n", esp ? "ON " : "OFF");
		printf(" [F4]   No Recoil:     %s\n", noRecoil ? "ON " : "OFF");
		printf(" [F5]   No Spread:     %s\n", noSpread ? "ON " : "OFF");
		printf(" [F6]   Rapid Fire:    %s  (auto weapons)\n", rapidFire ? "ON " : "OFF");
		printf(" [F7]   Inf Range:     %s  (bullet range)\n", infiniteRange ? "ON " : "OFF");
		printf(" [F8]   God Mode:      %s  (hp/food/water)\n", godMode ? "ON " : "OFF");
		printf(" [F9]   Speed Hack:    %s (x%.1f)\n", speedHack ? "ON " : "OFF", speedMultiplier);
		printf(" [F10]  Fly Hack:      %s  (Space/Ctrl)\n", flyHack ? "ON " : "OFF");
		printf(" [F11]  Super Jump:    %s (x%.1f)\n", superJump ? "ON " : "OFF", jumpMultiplier);
		printf(" [INS]  Admin Mode:    %s  (Shift+F1/F7)\n", adminMode ? "ON " : "OFF");
		printf(" [HOME] Vehicle Fly:   %s  (Space/Ctrl)\n", vehicleFly ? "ON " : "OFF");
		printf(" [O]    No Fall Dmg:   %s\n", noFallDamage ? "ON " : "OFF");
		printf(" [P]    Ext. Melee:    %s  (20m reach)\n", extendedMelee ? "ON " : "OFF");
		printf(" [L]    No Scope Sway: %s\n", noScopeSway ? "ON " : "OFF");
		printf(" [K]    Spin Bot:      %s\n", spinBot ? "ON " : "OFF");
		printf(" [J]    Triggerbot:    %s\n", triggerbot ? "ON " : "OFF");
		printf(" [M]    Radar:         %s\n", radar ? "ON " : "OFF");
		printf(" [I]    Item ESP:      %s\n", itemESP ? "ON " : "OFF");
		printf(" [U]    Zombie ESP:    %s\n", zombieESP ? "ON " : "OFF");
		printf(" [N]    Vehicle ESP:   %s\n", vehicleESP ? "ON " : "OFF");
		printf(" [B]    Fullbright:    %s\n", fullbright ? "ON " : "OFF");
		printf(" [G]    FOV Changer:   %s (%.0f)\n", fovChanger ? "ON " : "OFF", customFOV);
		printf(" [T]    Inst. Reload:  %s\n", instantReload ? "ON " : "OFF");
		printf(" [Y]    Stream Proof:  %s\n", streamProof ? "ON " : "OFF");
		printf(" [X]    Chams:         %s\n", chams ? "ON " : "OFF");
		printf(" [H]    No Flinch:     %s\n", noFlinch ? "ON " : "OFF");
		printf("----------------------------------------\n");
		printf(" [Num+/-] Adjust Speed/FOV/Aimbot FOV\n");
		printf(" [END]    Eject DLL\n");
		printf(" Speed: x%.1f | Aim FOV: %.0f | FOV: %.0f\n", speedMultiplier, aimbotFOV, customFOV);
		printf("========================================\n");
	}
}
