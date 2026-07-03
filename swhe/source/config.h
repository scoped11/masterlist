// config.h — Configuration state and hotkey system for the Unturned SWHE cheat.
//
// All cheat feature toggles, slider values, color selections, and hotkey
// bindings live here as inline globals.  The overlay menu (overlay.h) reads
// and writes these directly; the feature engine (features.h) checks them
// each tick to decide what to activate.
//
// Hotkey system:
//   Each feature can optionally have a HotkeyBinding (a VK_ code).
//   ProcessHotkeys() is called once per tick from the main loop.  It scans
//   all bound keys with GetAsyncKeyState and toggles the corresponding
//   feature bool on the rising edge (key-down transition).
//
//   Binding mode: when bindingTarget is non-null, ProcessHotkeys() instead
//   captures the next non-modifier key press and assigns it to that slot.
//   Pressing Delete or Escape clears the binding (sets vk to 0 = unbound).
//   The overlay menu enters binding mode when the user clicks a hotkey badge.
//
// Color system:
//   8 preset colors are available.  Each ESP element has an index into the
//   preset array.  Clicking a color row in the menu cycles to the next preset.

#pragma once
#include <Windows.h>
#include <cstdio>
#include <string>

namespace Config
{
	// ── Feature toggles ─────────────────────────────────────────────────────
	// Each bool controls whether its corresponding feature is active.
	// Toggled by the in-game menu (click) or by hotkeys (ProcessHotkeys).

	inline bool aimbot = false;         // Smooth aim toward nearest target (hold RMB)
	inline bool silentAim = false;      // Snap-and-restore aim on LMB fire
	inline bool esp = false;            // Master ESP toggle (enables all ESP sub-features)
	inline bool noRecoil = false;       // Zero all weapon recoil values
	inline bool noSpread = false;       // Zero all weapon spread values
	inline bool rapidFire = false;      // Set weapon firerate delay to 0
	inline bool infiniteRange = false;  // Extend weapon range + falloff to 9999m
	inline bool godMode = false;        // Pin health/food/water/stamina/virus to max
	inline bool speedHack = false;      // Multiply movement speed
	inline bool flyHack = false;        // Zero gravity + vertical velocity control
	inline bool superJump = false;      // Multiply jump height
	inline bool adminMode = false;      // Set local player's admin flag to true
	inline bool vehicleFly = false;     // Free-fly vehicles with WASD/Space/Ctrl
	inline bool noFallDamage = false;   // Zero the falling damage multiplier
	inline bool extendedMelee = false;  // Extend melee range to 20m
	inline bool noScopeSway = false;    // Zero the scope sway animation vector
	inline bool spinBot = false;        // Rapidly rotate yaw (+30 deg/tick)
	inline bool triggerbot = false;     // Auto-fire when crosshair is near target
	inline bool radar = false;          // Show 2D radar minimap in top-right corner
	inline bool itemESP = false;        // Show ground item positions with names
	inline bool zombieESP = false;      // Show zombie positions
	inline bool vehicleESP = false;     // Show vehicle positions
	inline bool fullbright = false;     // Force LevelLighting vision = 1 (fullbright)
	inline bool fovChanger = false;     // Override the game's vertical FOV
	inline bool instantReload = false;  // Zero reload time + clear rechamber flag

	// ── Slider values ───────────────────────────────────────────────────────
	inline float speedMultiplier = 2.0f;   // Speed hack multiplier (1x-10x)
	inline float jumpMultiplier = 3.0f;    // Super jump multiplier (1x-10x)
	inline float aimbotFOV = 20.0f;        // Aimbot FOV cone in degrees (5-90)
	inline float aimbotSmooth = 3.0f;      // Aimbot smoothing factor (1=instant, 15=slow)
	inline float gameFOV = 90.0f;          // Game's actual FOV for world-to-screen math
	inline float customFOV = 120.0f;       // Custom FOV value when fovChanger is on

	// ── ESP sub-toggles ─────────────────────────────────────────────────────
	// Only effective when the master 'esp' toggle is on.
	inline bool espBoxes = true;       // Bounding box around players
	inline bool espHealth = true;      // Vertical health bar + HP text
	inline bool espDistance = true;    // Distance label below feet
	inline bool espSnaplines = true;   // Line from screen bottom to player feet
	inline bool espNames = true;       // Player name above the box

	// ── Additional features ─────────────────────────────────────────────────
	inline bool noFog        = false;  // Disable distance fog
	inline bool forceGPS     = false;  // Enable GPS HUD without GPS item
	inline bool forceCompass = false;  // Enable compass HUD without compass item
	inline bool noFlash      = false;  // Zero flashbang stun duration
	inline bool nightVision  = false;  // Force LevelLighting vision = 2 (NV green tint)

	// ── Extra ESP modes ─────────────────────────────────────────────────────
	inline bool espSkeleton  = false;  // Stick-figure skeleton overlay on players
	inline bool espChams     = false;  // Filled silhouette visible through walls
	inline bool espVischeck  = false;  // Skip players behind the camera (FOV cone, not raycast)

	// ── Hotkey bindings ─────────────────────────────────────────────────────
	// Each HotkeyBinding stores a VK_ code (0 = unbound) and a 'held' flag
	// for rising-edge detection.  The menu shows a clickable badge for each
	// binding; clicking enters binding mode where the next key press is captured.
	struct HotkeyBinding {
		int vk = 0;      // Virtual key code (0 = unbound, feature only togglable via menu)
		bool held = false; // Tracks last key state for edge detection
	};

	// Per-feature hotkey bindings
	inline HotkeyBinding hkAimbot;        // Aimbot toggle key
	inline HotkeyBinding hkSilentAim;     // Silent aim toggle key
	inline HotkeyBinding hkESP;           // ESP toggle key
	inline HotkeyBinding hkNoRecoil;      // No recoil toggle key
	inline HotkeyBinding hkNoSpread;      // No spread toggle key
	inline HotkeyBinding hkRapidFire;     // Rapid fire toggle key
	inline HotkeyBinding hkGodMode;       // God mode toggle key
	inline HotkeyBinding hkSpeedHack;     // Speed hack toggle key
	inline HotkeyBinding hkFlyHack;       // Fly hack toggle key
	inline HotkeyBinding hkSuperJump;     // Super jump toggle key
	inline HotkeyBinding hkVehicleFly;    // Vehicle fly toggle key
	inline HotkeyBinding hkSpinBot;       // Spinbot toggle key
	inline HotkeyBinding hkTriggerbot;    // Triggerbot toggle key
	inline HotkeyBinding hkRadar;         // Radar toggle key
	inline HotkeyBinding hkInstantReload; // Instant reload toggle key
	inline HotkeyBinding hkNightVision;   // Night vision toggle key

	// When non-null, the next key press is captured into this binding
	// instead of being processed as a hotkey toggle.  Set by clicking a
	// hotkey badge in the menu; cleared after the key is captured.
	inline HotkeyBinding* bindingTarget = nullptr;

	// Returns a human-readable name for a virtual key code (for the menu badge)
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

	// ── Hotkey processing table ─────────────────────────────────────────────
	// Maps each HotkeyBinding to the feature bool it toggles.
	// ProcessHotkeys() iterates this array each tick.
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

	// Called once per tick from the main loop.
	//
	// In binding mode (bindingTarget != nullptr):
	//   Scans VK 8..0xFE (skipping modifiers and mouse buttons).  When a key
	//   is detected as held, assigns it to the binding slot.  Delete and Escape
	//   clear the binding (set vk = 0) instead of binding themselves.
	//
	// In normal mode:
	//   For each bound hotkey, checks GetAsyncKeyState.  On the rising edge
	//   (key was up last tick, down this tick), toggles the feature bool.
	//   The 'held' field provides edge detection so holding a key doesn't
	//   rapid-toggle.
	inline void ProcessHotkeys()
	{
		if (bindingTarget != nullptr)
		{
			for (int vk = 8; vk <= 0xFE; vk++)
			{
				// Skip modifier and mouse keys — they shouldn't be bindable
				if (vk == VK_SHIFT || vk == VK_CONTROL || vk == VK_MENU ||
					vk == VK_LBUTTON || vk == VK_RBUTTON || vk == VK_MBUTTON) continue;
				if (GetAsyncKeyState(vk) & 0x8000)
				{
					// Delete/Escape = unbind (set to 0); any other key = bind
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
			// Rising edge: toggle the feature when the key transitions from up to down
			if (down && !allHotkeys[i].binding->held)
				*allHotkeys[i].feature = !*allHotkeys[i].feature;
			allHotkeys[i].binding->held = down;
		}
	}

	// ── Color presets ───────────────────────────────────────────────────────
	// 8 preset colors available for ESP elements.  Each ESP component stores
	// an index into this array; clicking a color row in the menu cycles it.
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

	// Per-element color indices (default assignments noted)
	inline int colorESPBoxIdx      = 0;   // red — player bounding boxes
	inline int colorSkeletonIdx    = 4;   // orange — skeleton lines
	inline int colorChamsIdx       = 5;   // magenta — wall-hack chams fill
	inline int colorSnaplineIdx    = 3;   // yellow — snaplines to player feet
	inline int colorAimbotFOVIdx   = 7;   // white — aimbot FOV circle
	inline int colorHealthBarIdx   = 1;   // green — health bar accent

	// Accessor functions that resolve index -> COLORREF
	inline COLORREF colorESPBox()    { return colorPresets[colorESPBoxIdx]; }
	inline COLORREF colorSkeleton()  { return colorPresets[colorSkeletonIdx]; }
	inline COLORREF colorChams()     { return colorPresets[colorChamsIdx]; }
	inline COLORREF colorSnapline()  { return colorPresets[colorSnaplineIdx]; }
	inline COLORREF colorAimbotFOV() { return colorPresets[colorAimbotFOVIdx]; }
	inline COLORREF colorHealthBar() { return colorPresets[colorHealthBarIdx]; }

	// ── Menu state ──────────────────────────────────────────────────────────
	inline bool  menuOpen  = false;   // F1 toggles the overlay menu
	inline bool  bgImage   = false;   // Background image toggle (unused currently)
	inline float menuScale = 1.0f;    // Menu zoom level (scroll wheel: 0.5x-3.0x)

	// ── Menu tab state ──────────────────────────────────────────────────────
	// 6 tabs: Aimbot, Visuals, Weapons, Movement, Misc, Colors
	inline int activeTab = 0;
	static const int NUM_TABS = 6;
	static const char* TAB_NAMES[] = { "Aimbot", "Visuals", "Weapons", "Movement", "Misc", "Colors" };

	// Console-based status printout (used at startup / when console is visible)
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
