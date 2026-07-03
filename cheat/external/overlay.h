#pragma once
#include <Windows.h>
#pragma comment(lib, "winmm.lib")
#include <timeapi.h>
#include <gdiplus.h>
#pragma comment(lib, "gdiplus.lib")
#include <dwmapi.h>
#pragma comment(lib, "dwmapi.lib")
#include <thread>
#include <atomic>
#include <mutex>
#include <cstdio>
#include "config.h"
#include "math.h"
#include "xstr.h"

namespace Overlay
{
	inline HWND overlayWnd = NULL;
	inline HWND gameWnd    = NULL;
	inline std::atomic<bool> running{ true };
	inline HFONT espFont     = NULL;
	inline HFONT espFontSmall = NULL;
	inline HFONT menuFont    = NULL;
	inline HFONT menuFontBold = NULL;

	inline bool  insertWasDown = false;
	inline bool& menuOpen = Config::menuOpen;

	inline ULONG_PTR      g_gdiplusToken = 0;
	inline Gdiplus::Bitmap* g_bgBitmap  = nullptr;

	// -------------------------------------------------------------------------
	// World-object data shared between game thread and overlay thread
	// -------------------------------------------------------------------------
	struct PlayerData {
		vector3 feetPos, headPos;
		float   distance, health;
		bool    valid, isTarget;
		char    name[64];
	};
	struct WorldObjectData {
		vector3 pos;
		float   distance;
		bool    valid;
		char    name[32];
	};

	inline std::mutex dataMutex;
	inline PlayerData     players[48];  inline int playerCount  = 0;
	inline WorldObjectData vehicles[64]; inline int vehicleCount = 0;
	inline WorldObjectData items[128];   inline int itemCount    = 0;
	inline WorldObjectData zombies[128]; inline int zombieCount  = 0;
	inline vector3 localCamPos = {}; inline float localYaw = 0, localPitch = 0;

	// -------------------------------------------------------------------------
	// Menu entry types
	// -------------------------------------------------------------------------
	enum EntryType { EHDR, ETOG, ESLD };

	struct MenuEntry {
		EntryType   type;
		const char* label;
		bool*       toggle;               // ETOG
		float*      value;                // ESLD
		float       minVal, maxVal;       // ESLD
		const char* suffix;               // ESLD
		Config::HotkeyBinding* hotkey;    // optional inline hotkey badge (ETOG only)
	};

#define ME_HDR(lbl)                           { EHDR, lbl,  nullptr, nullptr, 0,    0,     nullptr, nullptr }
#define ME_TOG(lbl, tog)                      { ETOG, lbl,  tog,     nullptr, 0,    0,     nullptr, nullptr }
#define ME_TOG_HK(lbl, tog, hk)               { ETOG, lbl,  tog,     nullptr, 0,    0,     nullptr, hk      }
#define ME_SLD(lbl, val, mn, mx, sfx)         { ESLD, lbl,  nullptr, val,     mn,   mx,    sfx,     nullptr }

	// ── Per-tab entry lists ────────────────────────────────────────────────
	// Tab 0: Aimbot
	static const MenuEntry tabAimbot[] = {
		ME_TOG_HK("Aimbot (hold RMB)",   &Config::aimbot,     &Config::hkAimbot),
		ME_TOG_HK("Silent Aim",          &Config::silentAim,  &Config::hkSilentAim),
		ME_TOG_HK("Triggerbot",          &Config::triggerbot, &Config::hkTriggerbot),
		ME_TOG_HK("Spinbot",             &Config::spinBot,    &Config::hkSpinBot),
		ME_SLD("Aimbot FOV",             &Config::aimbotFOV,  5.0f,  90.0f, "\xB0"),
		ME_SLD("Smooth",                 &Config::aimbotSmooth, 1.0f, 15.0f, ""),
	};
	// Tab 1: Visuals
	static const MenuEntry tabVisuals[] = {
		ME_TOG_HK("ESP",                 &Config::esp,          &Config::hkESP),
		ME_TOG("  Boxes",                &Config::espBoxes),
		ME_TOG("  Health Bars",          &Config::espHealth),
		ME_TOG("  Names",                &Config::espNames),
		ME_TOG("  Distance",             &Config::espDistance),
		ME_TOG("  Snaplines",            &Config::espSnaplines),
		ME_TOG("  Skeleton",             &Config::espSkeleton),
		ME_TOG("  Chams (wall)",         &Config::espChams),
		ME_TOG("  Vischeck",             &Config::espVischeck),
		ME_TOG_HK("Radar",               &Config::radar,        &Config::hkRadar),
		ME_TOG("Item ESP",               &Config::itemESP),
		ME_TOG("Vehicle ESP",            &Config::vehicleESP),
		ME_TOG("Zombie ESP",             &Config::zombieESP),
		ME_TOG_HK("Fullbright",          &Config::fullbright,   nullptr),
		ME_TOG_HK("Night Vision",        &Config::nightVision,  &Config::hkNightVision),
	};
	// Tab 2: Weapons
	static const MenuEntry tabWeapons[] = {
		ME_TOG_HK("No Recoil",           &Config::noRecoil,     &Config::hkNoRecoil),
		ME_TOG_HK("No Spread",           &Config::noSpread,     &Config::hkNoSpread),
		ME_TOG_HK("Rapid Fire",          &Config::rapidFire,    &Config::hkRapidFire),
		ME_TOG("Inf. Range",             &Config::infiniteRange),
		ME_TOG("Extended Melee",         &Config::extendedMelee),
		ME_TOG_HK("Instant Reload",      &Config::instantReload,&Config::hkInstantReload),
		ME_TOG("No Scope Sway",          &Config::noScopeSway),
	};
	// Tab 3: Movement
	static const MenuEntry tabMovement[] = {
		ME_TOG_HK("Speed Hack",          &Config::speedHack,    &Config::hkSpeedHack),
		ME_SLD("Speed Multiplier",       &Config::speedMultiplier, 1.0f, 10.0f, "x"),
		ME_TOG_HK("Fly Hack",            &Config::flyHack,      &Config::hkFlyHack),
		ME_TOG_HK("Super Jump",          &Config::superJump,    &Config::hkSuperJump),
		ME_SLD("Jump Multiplier",        &Config::jumpMultiplier, 1.0f, 10.0f, "x"),
		ME_TOG("No Fall Damage",         &Config::noFallDamage),
		ME_TOG_HK("Vehicle Fly",         &Config::vehicleFly,   &Config::hkVehicleFly),
		ME_TOG("Noclip",                 &Config::noclip),
		ME_SLD("Noclip Speed",           &Config::noclipSpeed,  1.0f, 15.0f, ""),
	};
	// Tab 4: Misc
	static const MenuEntry tabMisc[] = {
		ME_TOG("God Mode",               &Config::godMode),
		ME_TOG("Admin Mode",             &Config::adminMode),
		ME_TOG("FOV Changer",            &Config::fovChanger),
		ME_SLD("Custom FOV",             &Config::customFOV,    60.0f, 180.0f, "\xB0"),
		ME_TOG("No Fog",                 &Config::noFog),
		ME_TOG("Force GPS",              &Config::forceGPS),
		ME_TOG("Force Compass",          &Config::forceCompass),
		ME_TOG("No Flash",               &Config::noFlash),
		ME_TOG("Infinite Stats",         &Config::infiniteStats),
		ME_TOG("No Debuffs",             &Config::noDebuffs),
	};
	// Tab 5: Colors — rendered separately by RenderColorSection

	struct TabDef { const MenuEntry* entries; int count; };
	static const TabDef tabs[] = {
		{ tabAimbot,   (int)(sizeof(tabAimbot)   / sizeof(MenuEntry)) },
		{ tabVisuals,  (int)(sizeof(tabVisuals)  / sizeof(MenuEntry)) },
		{ tabWeapons,  (int)(sizeof(tabWeapons)  / sizeof(MenuEntry)) },
		{ tabMovement, (int)(sizeof(tabMovement) / sizeof(MenuEntry)) },
		{ tabMisc,     (int)(sizeof(tabMisc)     / sizeof(MenuEntry)) },
		{ nullptr, 0 }, // tab 5 = Colors, handled specially
	};

	// -------------------------------------------------------------------------
	// Click / slider hit rects (rebuilt every frame during RenderMenu)
	// -------------------------------------------------------------------------
	struct ClickRect   { RECT rc; bool*  toggle; };
	struct SliderRect  { RECT trackRc; float* value; float minVal; float maxVal; };
	struct HotkeyRect  { RECT rc; Config::HotkeyBinding* binding; };
	struct TabRect     { RECT rc; int tabIdx; };

	inline ClickRect   clickRects[64];   inline int clickRectCount  = 0;
	inline SliderRect  sliderRects[16];  inline int sliderRectCount = 0;
	inline HotkeyRect  hotkeyRects[32];  inline int hotkeyRectCount = 0;
	inline TabRect     tabRects[8];      inline int tabRectCount    = 0;

	// Drag state for sliders
	inline float* activeDragSlider = nullptr;
	inline float  activeDragMin = 0, activeDragMax = 1;
	inline RECT   activeDragTrack = {};

	// Color picker rows
	struct ColorRow { const char* label; int* idx; };
	static const ColorRow colorRows[] = {
		{ "ESP Boxes",    &Config::colorESPBoxIdx    },
		{ "Skeleton",     &Config::colorSkeletonIdx  },
		{ "Chams",        &Config::colorChamsIdx     },
		{ "Snaplines",    &Config::colorSnaplineIdx  },
		{ "Aimbot FOV",   &Config::colorAimbotFOVIdx },
		{ "Health Bar",   &Config::colorHealthBarIdx },
	};
	static const int COLOR_ROW_COUNT = sizeof(colorRows) / sizeof(ColorRow);

	struct ColorClickRect { RECT rc; int* idx; };
	inline ColorClickRect colorClickRects[16];
	inline int            colorClickCount = 0;

	// -------------------------------------------------------------------------
	// Drawing helpers
	// -------------------------------------------------------------------------
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
		HPEN   pen   = CreatePen(PS_SOLID, 1, color);
		HPEN   oldPen   = (HPEN)SelectObject(hdc, pen);
		HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, brush);
		Ellipse(hdc, cx - radius, cy - radius, cx + radius, cy + radius);
		SelectObject(hdc, oldBrush);
		SelectObject(hdc, oldPen);
		DeleteObject(pen);
		DeleteObject(brush);
	}

	// -------------------------------------------------------------------------
	// Menu column renderer (handles headers, toggles, sliders, and hotkey badges)
	// -------------------------------------------------------------------------
	inline void RenderMenuColumn(HDC hdc, const MenuEntry* entries, int count,
		int colX, int startY, int colW, int itemH, int sliderH, POINT mousePos)
	{
		const int HK_W = 38; // width of hotkey badge
		int y = startY;
		for (int i = 0; i < count; i++)
		{
			const auto& e  = entries[i];
			int          rH = (e.type == ESLD) ? sliderH : itemH;

			if (e.type == EHDR)
			{
				DrawFilledRect(hdc, colX, y, colW, rH, RGB(28, 28, 40));
				DrawString(hdc, colX + 8, y + 4, e.label, RGB(100, 170, 255), menuFontBold);
				y += rH;
				continue;
			}

			if (e.type == ETOG)
			{
				// Hot zone is the row minus the hotkey badge area
				int toggleW = e.hotkey ? (colW - HK_W - 4) : colW;
				RECT rc = { colX, y, colX + toggleW, y + rH };
				bool hovered = (mousePos.x >= rc.left && mousePos.x < rc.right &&
					            mousePos.y >= rc.top  && mousePos.y < rc.bottom);

				if (clickRectCount < 64) {
					clickRects[clickRectCount].rc     = rc;
					clickRects[clickRectCount].toggle = e.toggle;
					clickRectCount++;
				}

				bool on = *e.toggle;
				DrawFilledRect(hdc, colX, y, toggleW, rH, hovered ? RGB(42, 42, 54) : RGB(20, 20, 27));

				COLORREF dotColor = on ? RGB(0, 210, 80) : RGB(200, 50, 50);
				DrawFilledRect(hdc, colX + 8, y + 7, 8, 8, dotColor);

				COLORREF textColor = on ? RGB(220, 220, 220) : RGB(130, 130, 130);
				DrawString(hdc, colX + 24, y + 4, e.label, textColor, menuFont);

				// Hotkey badge
				if (e.hotkey)
				{
					int bx = colX + toggleW + 4;
					int by = y + 3;
					int bw = HK_W - 4;
					int bh = rH - 6;
					bool isBinding = (Config::bindingTarget == e.hotkey);
					bool hkHov = (mousePos.x >= bx && mousePos.x < bx + bw &&
					              mousePos.y >= by && mousePos.y < by + bh);

					COLORREF bgCol  = isBinding ? RGB(60, 20,  20)  :
					                  hkHov     ? RGB(50, 50,  70)  : RGB(28, 28, 40);
					COLORREF brdCol = isBinding ? RGB(220, 80, 80)  :
					                  hkHov     ? RGB(100,100,160)  : RGB(55, 55, 90);
					COLORREF txtCol = isBinding ? RGB(255,100,100)  : RGB(160, 160, 210);

					DrawFilledRect(hdc, bx, by, bw, bh, bgCol);
					DrawOutlinedRect(hdc, bx, by, bw, bh, brdCol);

					std::string keyName = isBinding ? "..." : Config::VkName(e.hotkey->vk);
					// Center text in badge
					SIZE ts = {};
					SelectObject(hdc, menuFont);
					GetTextExtentPoint32A(hdc, keyName.c_str(), (int)keyName.size(), &ts);
					int tx = bx + (bw - ts.cx) / 2;
					int ty = by + (bh - ts.cy) / 2;
					DrawString(hdc, tx, ty, keyName.c_str(), txtCol, menuFont);

					if (hotkeyRectCount < 32) {
						RECT hrc = { bx, by, bx + bw, by + bh };
						hotkeyRects[hotkeyRectCount].rc      = hrc;
						hotkeyRects[hotkeyRectCount].binding = e.hotkey;
						hotkeyRectCount++;
					}
				}

				DrawLine(hdc, colX, y + rH - 1, colX + colW, y + rH - 1, RGB(32, 32, 42));
				y += rH;
				continue;
			}

			if (e.type == ESLD)
			{
				DrawFilledRect(hdc, colX, y, colW, rH, RGB(18, 18, 25));
				DrawString(hdc, colX + 8, y + 3, e.label, RGB(180, 180, 210), menuFont);

				char valBuf[24];
				sprintf_s(valBuf, "%.1f%s", *e.value, e.suffix ? e.suffix : "");
				int valW = (int)strlen(valBuf) * 7;
				DrawString(hdc, colX + colW - valW - 6, y + 3, valBuf, RGB(120, 180, 255), menuFont);

				const int TRACK_PAD = 8;
				const int TRACK_H   = 5;
				int trackLeft  = colX + TRACK_PAD;
				int trackRight = colX + colW - TRACK_PAD;
				int trackW     = trackRight - trackLeft;
				int trackY     = y + rH - TRACK_H - 6;

				DrawFilledRect(hdc, trackLeft, trackY, trackW, TRACK_H, RGB(40, 40, 55));

				float t = (*e.value - e.minVal) / (e.maxVal - e.minVal);
				if (t < 0) t = 0; if (t > 1) t = 1;
				int fillW = (int)(trackW * t);
				if (fillW > 0) DrawFilledRect(hdc, trackLeft, trackY, fillW, TRACK_H, RGB(60, 120, 220));

				int knobX = trackLeft + fillW;
				int knobH = 12;
				int knobY = trackY - (knobH - TRACK_H) / 2;
				DrawFilledRect(hdc, knobX - 3, knobY, 6, knobH, RGB(120, 170, 255));
				DrawOutlinedRect(hdc, knobX - 3, knobY, 6, knobH, RGB(60, 80, 160));

				if (sliderRectCount < 16) {
					RECT trackRc = { trackLeft, y + rH/2, trackRight, y + rH };
					sliderRects[sliderRectCount].trackRc = trackRc;
					sliderRects[sliderRectCount].value   = e.value;
					sliderRects[sliderRectCount].minVal  = e.minVal;
					sliderRects[sliderRectCount].maxVal  = e.maxVal;
					sliderRectCount++;
				}

				DrawLine(hdc, colX, y + rH - 1, colX + colW, y + rH - 1, RGB(32, 32, 42));
				y += rH;
				continue;
			}
		}
	}

	// Draw the tab bar; registers TabRects for click detection
	inline int RenderTabBar(HDC hdc, int menuX, int menuW, int y, int tabH, POINT mousePos)
	{
		tabRectCount = 0;
		int tabW = menuW / Config::NUM_TABS;
		for (int i = 0; i < Config::NUM_TABS; i++)
		{
			int tx = menuX + i * tabW;
			bool active  = (Config::activeTab == i);
			bool hovered = (mousePos.x >= tx && mousePos.x < tx + tabW &&
			                mousePos.y >= y  && mousePos.y < y + tabH);
			COLORREF bg  = active  ? RGB(40, 40, 70)  :
			               hovered ? RGB(28, 28, 50)  : RGB(18, 18, 28);
			COLORREF tc  = active  ? RGB(130, 180, 255) : RGB(120, 120, 160);

			DrawFilledRect(hdc, tx, y, tabW, tabH, bg);
			if (active) DrawFilledRect(hdc, tx, y + tabH - 2, tabW, 2, RGB(80, 120, 220));

			SIZE ts = {};
			SelectObject(hdc, menuFont);
			GetTextExtentPoint32A(hdc, Config::TAB_NAMES[i], (int)strlen(Config::TAB_NAMES[i]), &ts);
			int tx2 = tx + (tabW - ts.cx) / 2;
			int ty2 = y  + (tabH - ts.cy) / 2;
			DrawString(hdc, tx2, ty2, Config::TAB_NAMES[i], tc, menuFont);

			DrawLine(hdc, tx + tabW - 1, y, tx + tabW - 1, y + tabH, RGB(32, 32, 50));

			if (tabRectCount < 8) {
				tabRects[tabRectCount].rc     = { tx, y, tx + tabW, y + tabH };
				tabRects[tabRectCount].tabIdx = i;
				tabRectCount++;
			}
		}
		DrawLine(hdc, menuX, y + tabH, menuX + menuW, y + tabH, RGB(55, 55, 95));
		return y + tabH;
	}

	// Color section rendered at the bottom spanning both columns
	inline void RenderColorSection(HDC hdc, int menuX, int menuW, int startY, int itemH, POINT mousePos)
	{
		const int S    = (int)Config::menuScale;
		const int SWATCH = itemH - 6;

		// Section header
		DrawFilledRect(hdc, menuX, startY, menuW, itemH, RGB(28, 28, 40));
		DrawString(hdc, menuX + 8, startY + 4, "-- COLORS  (click to cycle) --", RGB(100, 170, 255), menuFontBold);
		startY += itemH;

		// Two-column layout for color rows
		int halfW = menuW / 2 - 2;
		for (int i = 0; i < COLOR_ROW_COUNT; i++)
		{
			int col   = i % 2;
			int row   = i / 2;
			int cx    = menuX + col * (halfW + 4);
			int cy    = startY + row * itemH;

			RECT rc = { cx, cy, cx + halfW, cy + itemH };
			bool hovered = (mousePos.x >= rc.left && mousePos.x < rc.right &&
			                mousePos.y >= rc.top  && mousePos.y < rc.bottom);

			DrawFilledRect(hdc, cx, cy, halfW, itemH, hovered ? RGB(42,42,54) : RGB(20,20,27));

			COLORREF col_c = Config::colorPresets[*colorRows[i].idx];
			DrawFilledRect(hdc, cx + 8, cy + (itemH-SWATCH)/2, SWATCH, SWATCH, col_c);
			DrawOutlinedRect(hdc, cx + 8, cy + (itemH-SWATCH)/2, SWATCH, SWATCH, RGB(80,80,80));

			DrawString(hdc, cx + 8 + SWATCH + 6, cy + 4, colorRows[i].label, RGB(200,200,200), menuFont);
			DrawLine(hdc, cx, cy + itemH - 1, cx + halfW, cy + itemH - 1, RGB(32,32,42));

			if (colorClickCount < 16) {
				colorClickRects[colorClickCount].rc  = rc;
				colorClickRects[colorClickCount].idx = colorRows[i].idx;
				colorClickCount++;
			}
		}
	}

	// Compute total pixel height of a column
	inline int ColHeight(const MenuEntry* entries, int count, int itemH, int sliderH)
	{
		int h = 0;
		for (int i = 0; i < count; i++)
			h += (entries[i].type == ESLD) ? sliderH : itemH;
		return h;
	}

	// -------------------------------------------------------------------------
	// Menu render (tabbed)
	// -------------------------------------------------------------------------
	inline void RenderMenu(HDC hdc, int screenW, int screenH)
	{
		if (!menuOpen) return;

		POINT mousePos = {};
		GetCursorPos(&mousePos);
		POINT overlayOrigin = { 0, 0 };
		ClientToScreen(overlayWnd, &overlayOrigin);
		mousePos.x -= overlayOrigin.x;
		mousePos.y -= overlayOrigin.y;

		const float S      = Config::menuScale;
		const int ITEM_H   = (int)(22 * S);
		const int SLIDER_H = (int)(36 * S);
		const int TAB_H    = (int)(24 * S);
		const int TITLE_H  = (int)(28 * S);
		const int PAD      = (int)(10 * S);
		const int MENU_W   = (int)(340 * S);
		const int MENU_X   = PAD;
		const int MENU_Y   = PAD;

		// Compute content height for current tab
		int contentH = 0;
		int tab = Config::activeTab;
		if (tab < 5 && tabs[tab].entries)
			contentH = ColHeight(tabs[tab].entries, tabs[tab].count, ITEM_H, SLIDER_H);
		else if (tab == 5)
			contentH = ITEM_H + ((COLOR_ROW_COUNT + 1) / 2) * ITEM_H;

		int menuH = TITLE_H + TAB_H + contentH + 8;

		DrawFilledRect(hdc, MENU_X, MENU_Y, MENU_W, menuH, RGB(14, 14, 20));
		DrawOutlinedRect(hdc, MENU_X, MENU_Y, MENU_W, menuH, RGB(55, 55, 95), 1);

		// Title bar
		DrawFilledRect(hdc, MENU_X, MENU_Y, MENU_W, TITLE_H, RGB(22, 22, 42));
		DrawString(hdc, MENU_X + 10, MENU_Y + 6, "penisfinger  |  F1 to close", RGB(100, 170, 255), menuFontBold);
		DrawLine(hdc, MENU_X, MENU_Y + TITLE_H, MENU_X + MENU_W, MENU_Y + TITLE_H, RGB(55, 55, 95));

		// Tab bar
		clickRectCount  = 0;
		sliderRectCount = 0;
		colorClickCount = 0;
		hotkeyRectCount = 0;
		int contentY = RenderTabBar(hdc, MENU_X, MENU_W, MENU_Y + TITLE_H, TAB_H, mousePos) + 4;

		// Content
		if (tab < 5 && tabs[tab].entries)
		{
			RenderMenuColumn(hdc, tabs[tab].entries, tabs[tab].count,
				MENU_X, contentY, MENU_W, ITEM_H, SLIDER_H, mousePos);
		}
		else if (tab == 5)
		{
			RenderColorSection(hdc, MENU_X, MENU_W, contentY, ITEM_H, mousePos);
		}

		// Binding mode hint at bottom
		if (Config::bindingTarget != nullptr)
		{
			int hy = MENU_Y + menuH - ITEM_H - 2;
			DrawFilledRect(hdc, MENU_X, hy, MENU_W, ITEM_H, RGB(40, 10, 10));
			DrawString(hdc, MENU_X + 8, hy + 4, "Press a key to bind  |  DEL / ESC to unbind", RGB(255, 120, 120), menuFont);
		}
	}

	// -------------------------------------------------------------------------
	// ESP rendering
	// -------------------------------------------------------------------------
	inline void RenderRadar(HDC hdc, int screenW, int screenH)
	{
		if (!Config::radar) return;
		std::lock_guard<std::mutex> lock(dataMutex);

		int radarSize = 180;
		int radarX    = screenW - radarSize - 15;
		int radarY    = 15;
		int radarCX   = radarX + radarSize / 2;
		int radarCY   = radarY + radarSize / 2;
		float radarRange = 150.0f;

		DrawFilledRect(hdc, radarX, radarY, radarSize, radarSize, RGB(10, 10, 10));
		DrawOutlinedRect(hdc, radarX, radarY, radarSize, radarSize, RGB(80, 80, 80), 1);
		DrawLine(hdc, radarCX, radarY, radarCX, radarY + radarSize, RGB(40, 40, 40));
		DrawLine(hdc, radarX, radarCY, radarX + radarSize, radarCY, RGB(40, 40, 40));
		DrawFilledCircle(hdc, radarCX, radarCY, 3, RGB(0, 255, 0));

		float yawRad = DEG2RAD(localYaw);

		for (int i = 0; i < playerCount; i++) {
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

		for (int i = 0; i < zombieCount && Config::zombieESP; i++) {
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

	inline void RenderWorldESP(HDC hdc, int screenW, int screenH)
	{
		if (Config::vehicleESP) {
			for (int i = 0; i < vehicleCount; i++) {
				auto& v = vehicles[i];
				if (!v.valid) continue;
				vector3 screenPos;
				if (!Math::WorldToScreen(v.pos, localCamPos, localYaw, localPitch,
					Config::gameFOV, screenW, screenH, screenPos)) continue;
				char txt[32];
				sprintf_s(txt, "Vehicle [%.0fm]", v.distance);
				DrawString(hdc, (int)screenPos.x - 30, (int)screenPos.y, txt, RGB(0, 200, 255), espFontSmall);
			}
		}
		if (Config::itemESP) {
			for (int i = 0; i < itemCount; i++) {
				auto& item = items[i];
				if (!item.valid) continue;
				vector3 screenPos;
				if (!Math::WorldToScreen(item.pos, localCamPos, localYaw, localPitch,
					Config::gameFOV, screenW, screenH, screenPos)) continue;
				char txt[64];
				sprintf_s(txt, "%s [%.0fm]", item.name, item.distance);
				DrawString(hdc, (int)screenPos.x - 20, (int)screenPos.y, txt, RGB(255, 200, 0), espFontSmall);
			}
		}
		if (Config::zombieESP) {
			for (int i = 0; i < zombieCount; i++) {
				auto& z = zombies[i];
				if (!z.valid) continue;
				vector3 screenPos;
				if (!Math::WorldToScreen(z.pos, localCamPos, localYaw, localPitch,
					Config::gameFOV, screenW, screenH, screenPos)) continue;
				char txt[32];
				sprintf_s(txt, "Zombie [%.0fm]", z.distance);
				DrawString(hdc, (int)screenPos.x - 25, (int)screenPos.y, txt, RGB(180, 0, 180), espFontSmall);
			}
		}
	}

	// Draw a simplified skeleton given head and feet world positions
	inline void DrawSkeleton(HDC hdc, int screenW, int screenH,
		vector3 headPos, vector3 feetPos, COLORREF col)
	{
		float dy = headPos.y - feetPos.y;
		// Approximate bone world positions
		auto bone = [&](float dx, float dy_off, float dz) -> vector3 {
			return { headPos.x + dx, headPos.y - dy_off * dy, headPos.z + dz };
		};
		vector3 head     = headPos;
		vector3 neck     = bone(0,    0.10f, 0);
		vector3 lShoulder= bone(-0.3f,0.25f, 0);
		vector3 rShoulder= bone( 0.3f,0.25f, 0);
		vector3 spine    = bone(0,    0.50f, 0);
		vector3 lHip     = bone(-0.2f,0.60f, 0);
		vector3 rHip     = bone( 0.2f,0.60f, 0);
		vector3 lKnee    = bone(-0.15f,0.78f,0);
		vector3 rKnee    = bone( 0.15f,0.78f,0);
		vector3 lFoot    = { feetPos.x - 0.1f, feetPos.y, feetPos.z };
		vector3 rFoot    = { feetPos.x + 0.1f, feetPos.y, feetPos.z };

		// Project all bones
		auto proj = [&](vector3 wp, vector3& out) -> bool {
			return Math::WorldToScreen(wp, Overlay::localCamPos, Overlay::localYaw, Overlay::localPitch,
				Config::gameFOV, screenW, screenH, out);
		};

		vector3 s_head, s_neck, s_lSh, s_rSh, s_spine, s_lHip, s_rHip, s_lKnee, s_rKnee, s_lFoot, s_rFoot;
		bool ok = proj(head,s_head) & proj(neck,s_neck) & proj(lShoulder,s_lSh) & proj(rShoulder,s_rSh) &
		          proj(spine,s_spine) & proj(lHip,s_lHip) & proj(rHip,s_rHip) &
		          proj(lKnee,s_lKnee) & proj(rKnee,s_rKnee) &
		          proj(lFoot,s_lFoot) & proj(rFoot,s_rFoot);
		if (!ok) return;

		auto L = [&](vector3 a, vector3 b) {
			DrawLine(hdc, (int)a.x,(int)a.y,(int)b.x,(int)b.y, col);
		};
		L(s_head, s_neck);
		L(s_neck, s_lSh);   L(s_neck, s_rSh);
		L(s_neck, s_spine);
		L(s_spine, s_lHip); L(s_spine, s_rHip);
		L(s_lHip, s_lKnee); L(s_lKnee, s_lFoot);
		L(s_rHip, s_rKnee); L(s_rKnee, s_rFoot);
	}

	inline void RenderESP(HDC hdc, int screenW, int screenH)
	{
		if (!Config::esp) return;
		std::lock_guard<std::mutex> lock(dataMutex);

		if (Config::aimbot || Config::silentAim) {
			float fovRadius = (Config::aimbotFOV / Config::gameFOV) * screenW * 0.5f;
			DrawCircle(hdc, screenW / 2, screenH / 2, (int)fovRadius, Config::colorAimbotFOV());
		}

		// Wall-chams pass: draw filled silhouette for every player regardless of occlusion.
		// This happens before the main ESP loop so the box/text draws on top.
		if (Config::espChams) {
			for (int i = 0; i < playerCount; i++) {
				auto& p = players[i];
				if (!p.valid) continue;
				vector3 screenFeet, screenHead;
				if (!Math::WorldToScreen(p.feetPos, localCamPos, localYaw, localPitch,
					Config::gameFOV, screenW, screenH, screenFeet)) continue;
				if (!Math::WorldToScreen(p.headPos, localCamPos, localYaw, localPitch,
					Config::gameFOV, screenW, screenH, screenHead)) continue;
				float boxH = fabsf(screenFeet.y - screenHead.y);
				if (boxH < 4.0f) continue;
				float boxW = boxH * 0.45f;
				int bx = (int)(screenHead.x - boxW * 0.5f);
				int by = (int)screenHead.y;
				int bw = (int)boxW;
				int bh = (int)boxH;
				COLORREF cCol = p.isTarget ? RGB(255, 220, 0) : Config::colorChams();
				DrawFilledRect(hdc, bx + 1, by + 1, bw - 2, bh - 2, cCol);
			}
		}

		for (int i = 0; i < playerCount; i++) {
			auto& p = players[i];
			if (!p.valid) continue;

			// Vischeck: skip players more than 90deg off-axis (behind camera)
			if (Config::espVischeck) {
				vector3 diff = { p.feetPos.x - localCamPos.x, 0, p.feetPos.z - localCamPos.z };
				float yawRad = DEG2RAD(localYaw);
				float fwdX = sinf(yawRad), fwdZ = cosf(yawRad);
				float dot = diff.x * fwdX + diff.z * fwdZ;
				if (dot < 0) continue; // behind camera
			}

			vector3 screenFeet, screenHead;
			if (!Math::WorldToScreen(p.feetPos, localCamPos, localYaw, localPitch,
				Config::gameFOV, screenW, screenH, screenFeet)) continue;
			if (!Math::WorldToScreen(p.headPos, localCamPos, localYaw, localPitch,
				Config::gameFOV, screenW, screenH, screenHead)) continue;

			float boxH = fabsf(screenFeet.y - screenHead.y);
			float boxW = boxH * 0.45f;
			int bx = (int)(screenHead.x - boxW * 0.5f);
			int by = (int)screenHead.y;
			int bw = (int)boxW;
			int bh = (int)boxH;
			COLORREF boxColor = p.isTarget ? RGB(255, 255, 0) : Config::colorESPBox();

			if (Config::espBoxes)
				DrawOutlinedRectOutline(hdc, bx, by, bw, bh, boxColor);

			if (Config::espSkeleton)
				DrawSkeleton(hdc, screenW, screenH, p.headPos, p.feetPos, Config::colorSkeleton());

			if (Config::espHealth) {
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
			if (Config::espNames && p.name[0]) {
				DrawString(hdc, bx, textY, p.name, RGB(255, 255, 255), espFontSmall);
				textY -= 14;
			}
			if (Config::espDistance) {
				char distText[32];
				sprintf_s(distText, "%.0fm", p.distance);
				DrawString(hdc, bx, (int)(screenFeet.y + 2), distText, RGB(200, 200, 200), espFontSmall);
			}
			if (Config::espSnaplines)
				DrawLine(hdc, screenW / 2, screenH, (int)screenFeet.x, (int)screenFeet.y,
					Config::colorSnapline());
		}

		RenderWorldESP(hdc, screenW, screenH);
	}

	// -------------------------------------------------------------------------
	// Window procedure
	// -------------------------------------------------------------------------
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

		case WM_LBUTTONDOWN:
		{
			if (!menuOpen) break;
			int mx = LOWORD(lParam), my = HIWORD(lParam);

			// Check sliders first
			for (int i = 0; i < sliderRectCount; i++) {
				auto& sr = sliderRects[i];
				if (mx >= sr.trackRc.left && mx <= sr.trackRc.right &&
					my >= sr.trackRc.top  && my <= sr.trackRc.bottom)
				{
					activeDragSlider = sr.value;
					activeDragMin    = sr.minVal;
					activeDragMax    = sr.maxVal;
					activeDragTrack  = sr.trackRc;
					float t = (float)(mx - sr.trackRc.left) / max(1, sr.trackRc.right - sr.trackRc.left);
					if (t < 0) t = 0; if (t > 1) t = 1;
					*sr.value = sr.minVal + t * (sr.maxVal - sr.minVal);
					SetCapture(hwnd);
					return 0;
				}
			}

			// Hotkey badges (check before toggles — badge is inside the row area)
			{
				bool handled = false;
				for (int i = 0; i < hotkeyRectCount; i++) {
					auto& hr = hotkeyRects[i];
					if (mx >= hr.rc.left && mx < hr.rc.right &&
						my >= hr.rc.top  && my < hr.rc.bottom)
					{
						// Toggle binding mode for this slot
						Config::bindingTarget = (Config::bindingTarget == hr.binding) ? nullptr : hr.binding;
						handled = true;
						break;
					}
				}
				if (handled) return 0;
			}
			// Tab bar
			for (int i = 0; i < tabRectCount; i++) {
				auto& tr = tabRects[i];
				if (mx >= tr.rc.left && mx < tr.rc.right &&
					my >= tr.rc.top  && my < tr.rc.bottom)
				{
					Config::activeTab = tr.tabIdx;
					Config::bindingTarget = nullptr; // cancel any pending bind on tab change
					return 0;
				}
			}
			// Toggles
			for (int i = 0; i < clickRectCount; i++) {
				auto& cr = clickRects[i];
				if (mx >= cr.rc.left && mx < cr.rc.right &&
					my >= cr.rc.top  && my < cr.rc.bottom)
				{
					if (cr.toggle) *cr.toggle = !*cr.toggle;
					break;
				}
			}
			// Color rows
			for (int i = 0; i < colorClickCount; i++) {
				auto& cc = colorClickRects[i];
				if (mx >= cc.rc.left && mx < cc.rc.right &&
					my >= cc.rc.top  && my < cc.rc.bottom)
				{
					*cc.idx = (*cc.idx + 1) % Config::NUM_PRESETS;
					break;
				}
			}
			return 0;
		}

		case WM_MOUSEMOVE:
		{
			if (activeDragSlider && (wParam & MK_LBUTTON)) {
				int mx = LOWORD(lParam);
				float t = (float)(mx - activeDragTrack.left) / max(1, activeDragTrack.right - activeDragTrack.left);
				if (t < 0) t = 0; if (t > 1) t = 1;
				*activeDragSlider = activeDragMin + t * (activeDragMax - activeDragMin);
			}
			return 0;
		}

		case WM_LBUTTONUP:
		{
			activeDragSlider = nullptr;
			ReleaseCapture();
			return 0;
		}

		case WM_MOUSEWHEEL:
		{
			if (!menuOpen) break;
			int delta = GET_WHEEL_DELTA_WPARAM(wParam);
			Config::menuScale += (delta > 0 ? 0.05f : -0.05f);
			if (Config::menuScale < 0.5f) Config::menuScale = 0.5f;
			if (Config::menuScale > 3.0f) Config::menuScale = 3.0f;
			return 0;
		}
		}
		return DefWindowProcA(hwnd, msg, wParam, lParam);
	}

	// Cached backbuffer — only recreated on window resize (avoids per-frame allocation)
	inline HDC     g_memDC      = NULL;
	inline HBITMAP g_memBmp     = NULL;
	inline HBITMAP g_memOldBmp  = NULL;
	inline int     g_cachedW    = 0;
	inline int     g_cachedH    = 0;
	inline int     g_cachedGX   = -9999;
	inline int     g_cachedGY   = -9999;

	// Per-frame timing for smooth aimbot
	inline double g_frameDeltaMs = 5.0;

	// -------------------------------------------------------------------------
	// Overlay thread
	// -------------------------------------------------------------------------
	inline void Run()
	{
		timeBeginPeriod(1);
		int refreshRate = 60;
		{
			HDC screenDC = GetDC(NULL);
			int rr = GetDeviceCaps(screenDC, VREFRESH);
			ReleaseDC(NULL, screenDC);
			if (rr > 10 && rr <= 360) refreshRate = rr;
		}
		LARGE_INTEGER qpfFreq;
		QueryPerformanceFrequency(&qpfFreq);
		double targetUs = 1000000.0 / refreshRate;

		auto wndClass = XS(0x15,0x2C,0x3F,0x28,0x36,0x3B,0x23,0x19,0x36,0x3B,0x29,0x29);

		WNDCLASSEXA wc = {};
		wc.cbSize        = sizeof(wc);
		wc.style         = CS_HREDRAW | CS_VREDRAW;
		wc.lpfnWndProc   = WndProc;
		wc.hInstance     = GetModuleHandle(NULL);
		wc.lpszClassName = wndClass.c_str();
		wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
		RegisterClassExA(&wc);

		overlayWnd = CreateWindowExA(
			WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE,
			wndClass.c_str(), "",
			WS_POPUP,
			0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN),
			NULL, NULL, GetModuleHandle(NULL), NULL);

		if (!overlayWnd) return;

		// No SetLayeredWindowAttributes — using UpdateLayeredWindow directly (incompatible to mix both)
		ShowWindow(overlayWnd, SW_SHOWNOACTIVATE);
		if (!SetWindowDisplayAffinity(overlayWnd, 0x11)) // WDA_EXCLUDEFROMCAPTURE
			SetWindowDisplayAffinity(overlayWnd, 0x01);   // WDA_MONITOR fallback

		{
			Gdiplus::GdiplusStartupInput gsi;
			Gdiplus::GdiplusStartup(&g_gdiplusToken, &gsi, NULL);
			g_bgBitmap = new Gdiplus::Bitmap(L"C:\\Users\\K\\Pictures\\penis-finger-external.png");
			if (g_bgBitmap->GetLastStatus() != Gdiplus::Ok) {
				delete g_bgBitmap;
				g_bgBitmap = nullptr;
			}
		}

		espFont = CreateFontA(16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
			DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
			ANTIALIASED_QUALITY, DEFAULT_PITCH, "Consolas");
		espFontSmall = CreateFontA(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
			DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
			ANTIALIASED_QUALITY, DEFAULT_PITCH, "Consolas");
		menuFont = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
			DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
			CLEARTYPE_QUALITY, DEFAULT_PITCH, "Segoe UI");
		menuFontBold = CreateFontA(14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
			DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
			CLEARTYPE_QUALITY, DEFAULT_PITCH, "Segoe UI");

		float lastMenuScale = Config::menuScale;

		MSG msg;
		LARGE_INTEGER frameStart;
		while (running)
		{
			QueryPerformanceCounter(&frameStart);
			while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
				if (msg.message == WM_QUIT) { running = false; break; }
				TranslateMessage(&msg);
				DispatchMessageA(&msg);
			}

			if (Config::menuScale != lastMenuScale) {
				lastMenuScale = Config::menuScale;
				int fs = max(8, (int)(14 * Config::menuScale));
				if (menuFont)     { DeleteObject(menuFont);     menuFont = NULL; }
				if (menuFontBold) { DeleteObject(menuFontBold); menuFontBold = NULL; }
				menuFont = CreateFontA(fs, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
					DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
					CLEARTYPE_QUALITY, DEFAULT_PITCH, "Segoe UI");
				menuFontBold = CreateFontA(fs, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
					DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
					CLEARTYPE_QUALITY, DEFAULT_PITCH, "Segoe UI");
			}

			// Toggle menu with F1
			bool insertDown = (GetAsyncKeyState(VK_F1) & 0x8000) != 0;
			if (insertDown && !insertWasDown) {
				menuOpen = !menuOpen;
				LONG exStyle = GetWindowLongA(overlayWnd, GWL_EXSTYLE);
				if (menuOpen)
					SetWindowLongA(overlayWnd, GWL_EXSTYLE, exStyle & ~WS_EX_TRANSPARENT);
				else
					SetWindowLongA(overlayWnd, GWL_EXSTYLE, exStyle | WS_EX_TRANSPARENT);
			}
			insertWasDown = insertDown;

			if (!gameWnd || !IsWindow(gameWnd))
				gameWnd = FindWindowA(NULL, XS(0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E).c_str());
			if (!gameWnd) { Sleep(100); continue; }

			RECT clientRect;
			GetClientRect(gameWnd, &clientRect);
			POINT topLeft = { 0, 0 };
			ClientToScreen(gameWnd, &topLeft);
			int gw = clientRect.right;
			int gh = clientRect.bottom;

			if (topLeft.x != g_cachedGX || topLeft.y != g_cachedGY ||
				gw != g_cachedW || gh != g_cachedH)
			{
				SetWindowPos(overlayWnd, HWND_TOP,
					topLeft.x, topLeft.y, gw, gh, SWP_NOACTIVATE);
				g_cachedGX = topLeft.x; g_cachedGY = topLeft.y;
			}
			else
			{
				SetWindowPos(overlayWnd, HWND_TOP, 0, 0, 0, 0,
					SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
			}

			HDC screenDC = GetDC(NULL);

			// Create or resize the backbuffer only when needed
			if (!g_memDC) g_memDC = CreateCompatibleDC(screenDC);
			if (gw != g_cachedW || gh != g_cachedH) {
				if (g_memBmp) { SelectObject(g_memDC, g_memOldBmp); DeleteObject(g_memBmp); }
				g_memBmp    = CreateCompatibleBitmap(screenDC, gw, gh);
				g_memOldBmp = (HBITMAP)SelectObject(g_memDC, g_memBmp);
				g_cachedW = gw; g_cachedH = gh;
			}

			// Clear to fully transparent black (alpha=0)
			RECT clearRect = { 0, 0, gw, gh };
			HBRUSH clearBrush = CreateSolidBrush(RGB(0, 0, 0));
			FillRect(g_memDC, &clearRect, clearBrush);
			DeleteObject(clearBrush);

			if (Config::esp) {
				SelectObject(g_memDC, espFont);
				RenderESP(g_memDC, gw, gh);
			}
			RenderRadar(g_memDC, gw, gh);
			RenderMenu(g_memDC, gw, gh);

			// UpdateLayeredWindow — GPU-composited, no flicker, no CPU busy-loop needed
			POINT ptSrc = { 0, 0 };
			POINT ptDst = { topLeft.x, topLeft.y };
			SIZE  szWnd = { gw, gh };
			BLENDFUNCTION blend = { AC_SRC_OVER, 0, 255, 0 };
			UpdateLayeredWindow(overlayWnd, screenDC, &ptDst, &szWnd,
				g_memDC, &ptSrc, RGB(0, 0, 0), &blend, ULW_COLORKEY);

			ReleaseDC(NULL, screenDC);

			// Simple sleep-based frame pacing — no busy-spin
			LARGE_INTEGER frameEnd;
			QueryPerformanceCounter(&frameEnd);
			double elapsedMs = (double)(frameEnd.QuadPart - frameStart.QuadPart) / qpfFreq.QuadPart * 1000.0;
			g_frameDeltaMs = max(0.1, elapsedMs);
			double remainMs = (1000.0 / refreshRate) - elapsedMs;
			if (remainMs > 1.0) Sleep((DWORD)remainMs);
		}

		if (g_memBmp) { SelectObject(g_memDC, g_memOldBmp); DeleteObject(g_memBmp); g_memBmp = NULL; }
		if (g_memDC)  { DeleteDC(g_memDC); g_memDC = NULL; }
		timeEndPeriod(1);
		if (espFont)      DeleteObject(espFont);
		if (espFontSmall) DeleteObject(espFontSmall);
		if (menuFont)     DeleteObject(menuFont);
		if (menuFontBold) DeleteObject(menuFontBold);
		if (overlayWnd)   DestroyWindow(overlayWnd);
		UnregisterClassA(wndClass.c_str(), GetModuleHandle(NULL));
		if (g_bgBitmap)     { delete g_bgBitmap; g_bgBitmap = nullptr; }
		if (g_gdiplusToken) { Gdiplus::GdiplusShutdown(g_gdiplusToken); g_gdiplusToken = 0; }
	}

	inline void Shutdown() { running = false; }
}
