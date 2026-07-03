#pragma once
#include <Windows.h>
#include <cstdio>
#include <string>

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
	inline bool adminMode = false;
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

	// BoCheat features
	inline bool noFog        = false;
	inline bool forceGPS     = false;
	inline bool forceCompass = false;
	inline bool noFlash      = false;
	inline bool nightVision  = false;

	inline bool noclip       = false;
	inline float noclipSpeed = 5.0f;
	inline bool infiniteStats = false;
	inline bool noDebuffs    = false;

	// Extra ESP modes
	inline bool espSkeleton  = false;
	inline bool espChams     = false;
	inline bool espVischeck  = false;  // approximate (FOV cone only, not true raycast)

	// ── Hotkey bindings ──────────────────────────────────────────────────────
	// Each entry is a VK_ code. 0 = unbound (feature only togglable via menu).
	// The overlay menu lets you click a binding slot and press a key to bind,
	// or press Delete/Backspace on the slot to clear it.
	struct HotkeyBinding {
		int vk = 0;      // 0 = unbound
		bool held = false; // tracks last state for edge detection
	};

	inline HotkeyBinding hkAimbot;
	inline HotkeyBinding hkSilentAim;
	inline HotkeyBinding hkESP;
	inline HotkeyBinding hkNoRecoil;
	inline HotkeyBinding hkNoSpread;
	inline HotkeyBinding hkRapidFire;
	inline HotkeyBinding hkGodMode;
	inline HotkeyBinding hkSpeedHack;
	inline HotkeyBinding hkFlyHack;
	inline HotkeyBinding hkSuperJump;
	inline HotkeyBinding hkVehicleFly;
	inline HotkeyBinding hkSpinBot;
	inline HotkeyBinding hkTriggerbot;
	inline HotkeyBinding hkRadar;
	inline HotkeyBinding hkInstantReload;
	inline HotkeyBinding hkNightVision;

	// While non-null, the next key press is captured into this binding (set by clicking [KEY] badge)
	inline HotkeyBinding* bindingTarget = nullptr;

	// Returns a printable name for a VK code
	inline std::string VkName(int vk)
	{
		if (vk == 0) return "---";
		// Common keys
		if (vk >= 'A' && vk <= 'Z') return std::string(1, (char)vk);
		if (vk >= '0' && vk <= '9') return std::string(1, (char)vk);
		if (vk >= VK_F1 && vk <= VK_F12) { return "F" + std::to_string(vk - VK_F1 + 1); }
		switch (vk) {
		case VK_INSERT: return "INS";
		case VK_HOME:   return "HOME";
		case VK_PRIOR:  return "PGUP";
		case VK_NEXT:   return "PGDN";
		case VK_END:    return "END";
		case VK_DELETE: return "DEL";
		case VK_NUMPAD0: case VK_NUMPAD1: case VK_NUMPAD2: case VK_NUMPAD3:
		case VK_NUMPAD4: case VK_NUMPAD5: case VK_NUMPAD6: case VK_NUMPAD7:
		case VK_NUMPAD8: case VK_NUMPAD9:
			return "NUM" + std::to_string(vk - VK_NUMPAD0);
		case VK_XBUTTON1: return "MB4";
		case VK_XBUTTON2: return "MB5";
		case VK_CAPITAL:  return "CAPS";
		default: {
			char buf[8] = {};
			UINT sc = MapVirtualKeyA(vk, MAPVK_VK_TO_VSC);
			GetKeyNameTextA((sc << 16), buf, sizeof(buf));
			if (buf[0]) return buf;
			return "0x" + std::to_string(vk);
		}
		}
	}

	// Pairs of (binding, feature bool) for hotkey processing
	struct HotkeyPair { HotkeyBinding* binding; bool* feature; };
	inline HotkeyPair allHotkeys[] = {
		{ &hkAimbot,       &aimbot       },
		{ &hkSilentAim,    &silentAim    },
		{ &hkESP,          &esp          },
		{ &hkNoRecoil,     &noRecoil     },
		{ &hkNoSpread,     &noSpread     },
		{ &hkRapidFire,    &rapidFire    },
		{ &hkGodMode,      &godMode      },
		{ &hkSpeedHack,    &speedHack    },
		{ &hkFlyHack,      &flyHack      },
		{ &hkSuperJump,    &superJump    },
		{ &hkVehicleFly,   &vehicleFly   },
		{ &hkSpinBot,      &spinBot      },
		{ &hkTriggerbot,   &triggerbot   },
		{ &hkRadar,        &radar        },
		{ &hkInstantReload,&instantReload},
		{ &hkNightVision,  &nightVision  },
	};
	static constexpr int NUM_HOTKEYS = 16;

	// Call once per tick in the main loop to fire hotkey toggles.
	// While bindingTarget is non-null, next non-modifier key press is captured.
	inline void ProcessHotkeys()
	{
		if (bindingTarget != nullptr)
		{
			for (int vk = 8; vk <= 0xFE; vk++)
			{
				if (vk == VK_SHIFT || vk == VK_CONTROL || vk == VK_MENU ||
					vk == VK_LBUTTON || vk == VK_RBUTTON || vk == VK_MBUTTON) continue;
				if (GetAsyncKeyState(vk) & 0x8000)
				{
					bindingTarget->vk = (vk == VK_DELETE || vk == VK_ESCAPE) ? 0 : vk;
					bindingTarget = nullptr;
					break;
				}
			}
			return;
		}

		for (int i = 0; i < NUM_HOTKEYS; i++)
		{
			if (allHotkeys[i].binding->vk == 0) continue;
			bool down = (GetAsyncKeyState(allHotkeys[i].binding->vk) & 0x8000) != 0;
			if (down && !allHotkeys[i].binding->held)
				*allHotkeys[i].feature = !*allHotkeys[i].feature;
			allHotkeys[i].binding->held = down;
		}
	}

	// ── Color presets ────────────────────────────────────────────────────────
	// Color presets (COLORREF = 0x00BBGGRR)
	static const COLORREF colorPresets[] = {
		RGB(255, 50,  50),   // 0 red
		RGB(50,  255, 50),   // 1 green
		RGB(50,  150, 255),  // 2 blue
		RGB(255, 255, 0),    // 3 yellow
		RGB(255, 140, 0),    // 4 orange
		RGB(255, 0,   255),  // 5 magenta
		RGB(0,   255, 255),  // 6 cyan
		RGB(255, 255, 255),  // 7 white
	};
	static const int NUM_PRESETS = 8;

	inline int colorESPBoxIdx      = 0;   // red
	inline int colorSkeletonIdx    = 4;   // orange
	inline int colorChamsIdx       = 5;   // magenta
	inline int colorSnaplineIdx    = 3;   // yellow
	inline int colorAimbotFOVIdx   = 7;   // white
	inline int colorHealthBarIdx   = 1;   // green

	inline COLORREF colorESPBox()    { return colorPresets[colorESPBoxIdx]; }
	inline COLORREF colorSkeleton()  { return colorPresets[colorSkeletonIdx]; }
	inline COLORREF colorChams()     { return colorPresets[colorChamsIdx]; }
	inline COLORREF colorSnapline()  { return colorPresets[colorSnaplineIdx]; }
	inline COLORREF colorAimbotFOV() { return colorPresets[colorAimbotFOVIdx]; }
	inline COLORREF colorHealthBar() { return colorPresets[colorHealthBarIdx]; }

	inline bool  menuOpen  = false;
	inline bool  bgImage   = false;
	inline float menuScale = 1.0f;

	// ── Menu tab state ───────────────────────────────────────────────────────
	// 0=Aimbot  1=Visuals  2=Weapons  3=Movement  4=Misc  5=Colors
	inline int activeTab = 0;
	static const int NUM_TABS = 6;
	static const char* TAB_NAMES[] = { "Aimbot", "Visuals", "Weapons", "Movement", "Misc", "Colors" };

	inline void PrintMenu()
	{
		printf("========================================\n");
		printf("     UNTURNED EXTERNAL — MENU ONLY      \n");
		printf("========================================\n");
		printf(" Aimbot:        %s  (hold RMB to aim)\n", aimbot ? "ON " : "OFF");
		printf(" Silent Aim:    %s  (fires on LMB)\n",    silentAim ? "ON " : "OFF");
		printf(" ESP:           %s\n",                    esp ? "ON " : "OFF");
		printf(" No Recoil:     %s\n",                   noRecoil ? "ON " : "OFF");
		printf(" No Spread:     %s\n",                   noSpread ? "ON " : "OFF");
		printf(" Rapid Fire:    %s\n",                   rapidFire ? "ON " : "OFF");
		printf(" Inf Range:     %s\n",                   infiniteRange ? "ON " : "OFF");
		printf(" God Mode:      %s\n",                   godMode ? "ON " : "OFF");
		printf(" Speed Hack:    %s (x%.1f)\n",           speedHack ? "ON " : "OFF", speedMultiplier);
		printf(" Fly Hack:      %s  (WASD+Space/Ctrl)\n",flyHack ? "ON " : "OFF");
		printf(" Super Jump:    %s (x%.1f)\n",           superJump ? "ON " : "OFF", jumpMultiplier);
		printf(" Vehicle Fly:   %s\n",                   vehicleFly ? "ON " : "OFF");
		printf(" No Fall Dmg:   %s\n",                   noFallDamage ? "ON " : "OFF");
		printf(" Ext. Melee:    %s\n",                   extendedMelee ? "ON " : "OFF");
		printf(" No Scope Sway: %s\n",                   noScopeSway ? "ON " : "OFF");
		printf(" Spin Bot:      %s\n",                   spinBot ? "ON " : "OFF");
		printf(" Triggerbot:    %s\n",                   triggerbot ? "ON " : "OFF");
		printf(" Radar:         %s\n",                   radar ? "ON " : "OFF");
		printf(" Item ESP:      %s\n",                   itemESP ? "ON " : "OFF");
		printf(" Zombie ESP:    %s\n",                   zombieESP ? "ON " : "OFF");
		printf(" Vehicle ESP:   %s\n",                   vehicleESP ? "ON " : "OFF");
		printf(" Fullbright:    %s\n",                   fullbright ? "ON " : "OFF");
		printf(" FOV Changer:   %s (%.0f)\n",            fovChanger ? "ON " : "OFF", customFOV);
		printf(" Inst. Reload:  %s\n",                   instantReload ? "ON " : "OFF");
		printf("----------------------------------------\n");
		printf(" F1  — Toggle overlay menu\n");
		printf(" END — Exit cheat\n");
		printf(" Speed: x%.1f | Aim FOV: %.0f | FOV: %.0f\n", speedMultiplier, aimbotFOV, customFOV);
		printf("========================================\n");
	}
}
