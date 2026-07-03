#pragma once
#include <Windows.h>

namespace Config
{
	inline bool aimbot = false;
	inline bool silentAim = false;
	inline bool esp = true;
	inline bool noRecoil = false;
	inline bool noSpread = false;
	inline bool rapidFire = false;
	inline bool infiniteRange = false;
	inline bool godMode = false;
	inline bool speedHack = false;
	inline bool flyHack = false;
	inline bool superJump = false;
	inline bool adminMode = false;
	inline bool noFallDamage = false;
	inline bool noScopeSway = false;
	inline bool noFlinch = false;
	inline bool fullbright = false;
	inline bool radar = true;
	inline bool vehicleESP = false;
	inline bool itemESP = false;
	inline bool zombieESP = false;
	inline bool fovChanger = false;
	inline bool instantReload = false;
	inline bool spinBot = false;
	inline bool extendedMelee = false;
	inline bool triggerbot = false;
	inline bool vehicleFly = false;
	inline bool chams = false;
	inline bool streamProof = true;

	inline bool espBoxes = true;
	inline bool espNames = true;
	inline bool espDistance = true;
	inline bool espHealth = true;
	inline bool espSnaplines = false;

	inline float speedMultiplier = 1.3f;
	inline float jumpMultiplier = 1.5f;
	inline float flySpeed = 8.0f;
	inline float aimbotFOV = 15.0f;
	inline float aimbotSmooth = 5.0f;
	inline float customFOV = 120.0f;
	inline float gameFOV = 90.0f;
	inline float meleeRange = 20.0f;

	inline bool lootTeleport = false;
	inline float lootRadius = 50.0f;

	inline bool noclip = false;
	inline float noclipSpeed = 5.0f;
	inline bool infiniteStats = false;
	inline bool noDebuffs = false;
	inline bool alwaysGPS = false;
	inline bool alwaysCompass = false;
	inline bool teleport = false;
}
