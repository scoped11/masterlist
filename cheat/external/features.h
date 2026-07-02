#pragma once
#include <mutex>
#include "config.h"
#include "math.h"
#include "overlay.h"
#include "types/game.h"

namespace Features
{
	struct AimbotTarget
	{
		int index;
		float fov;
		vector3 position;
	};

	inline AimbotTarget currentTarget = { -1, 9999.0f, {} };

	// Silent aim state
	inline int silentAimTicks = 0;
	inline float savedYaw = 0;
	inline float savedPitch = 0;

	// Spinbot state
	inline float spinAngle = 0;

	struct WeaponOriginals
	{
		uintptr_t assetPtr = 0;
		float recoilMin_x = 0, recoilMax_x = 0, recoilMin_y = 0, recoilMax_y = 0;
		float baseSpread = 0, spreadHip = 0, spreadAim = 0;
		uint8_t firerate = 0;
		float range = 0, damageFalloff = 0;
		bool saved = false;
	};
	inline WeaponOriginals weaponOrig;

	inline SDG::Player* GetLocalPlayer()
	{
		SDG::Player* lp = nullptr;

		if (Offsets::_localPlayer)
		{
			lp = SDG::Player::localPlayer();
			if (lp && (uintptr_t)lp > 0x10000)
				return lp;
		}

		lp = SDG::Player::player();
		if (lp && (uintptr_t)lp > 0x10000)
			return lp;

		return nullptr;
	}

	inline void UpdateWeapon(SDG::Player* localPlayer)
	{
		if (!Offsets::_equipment || !Offsets::_asset) return;

		auto equip = localPlayer->equipment();
		if (!equip) return;

		auto asset = (SDG::ItemGunAsset*)(equip->asset());
		if (!asset || (uintptr_t)asset < 0x10000) return;

		uintptr_t assetAddr = reinterpret_cast<uintptr_t>(asset);

		// If weapon changed, save new originals.
		// Guard: only save if values look real (non-zero) so GC pointer churn
		// doesn't overwrite our saved originals with the already-zeroed values
		// we wrote for no-recoil, making them permanent.
		if (weaponOrig.assetPtr != assetAddr)
		{
			weaponOrig.assetPtr = assetAddr;
			weaponOrig.saved = false; // will be set true once we get real values

			float rx = Offsets::recoilMin_x ? asset->recoilMin_x() : 0.0f;
			float ry = Offsets::recoilMin_y ? asset->recoilMin_y() : 0.0f;
			float spread = Offsets::baseSpreadAngleRadians ? asset->baseSpreadAngleRadians() : 0.0f;
			float rng = Offsets::range ? asset->range() : 0.0f;

			// Only accept if at least one value is non-zero (real weapon data)
			if (rx != 0.0f || ry != 0.0f || spread != 0.0f || rng != 0.0f)
			{
				if (Offsets::recoilMin_x)
				{
					weaponOrig.recoilMin_x = rx;
					weaponOrig.recoilMax_x = asset->recoilMax_x();
					weaponOrig.recoilMin_y = ry;
					weaponOrig.recoilMax_y = asset->recoilMax_y();
				}
				if (Offsets::baseSpreadAngleRadians) weaponOrig.baseSpread = spread;
				if (Offsets::spreadHip) weaponOrig.spreadHip = asset->spreadHip();
				if (Offsets::spreadAim) weaponOrig.spreadAim = asset->spreadAim();
				if (Offsets::firerate) weaponOrig.firerate = asset->firerate();
				if (Offsets::range) weaponOrig.range = rng;
				if (Offsets::damageFalloffRange) weaponOrig.damageFalloff = asset->damageFalloffRange();
				weaponOrig.saved = true;
			}
		}

		if (!weaponOrig.saved) return;

		// No recoil
		if (Offsets::recoilMin_x)
		{
			if (Config::noRecoil)
			{
				asset->recoilMin_x_set(0);
				asset->recoilMax_x_set(0);
				asset->recoilMin_y_set(0);
				asset->recoilMax_y_set(0);
			}
			else
			{
				asset->recoilMin_x_set(weaponOrig.recoilMin_x);
				asset->recoilMax_x_set(weaponOrig.recoilMax_x);
				asset->recoilMin_y_set(weaponOrig.recoilMin_y);
				asset->recoilMax_y_set(weaponOrig.recoilMax_y);
			}
		}

		// No spread
		if (Config::noSpread)
		{
			if (Offsets::baseSpreadAngleRadians) asset->baseSpreadAngleRadians_set(0);
			if (Offsets::spreadHip) asset->spreadHip_set(0);
			if (Offsets::spreadAim) asset->spreadAim_set(0);
		}
		else
		{
			if (Offsets::baseSpreadAngleRadians) asset->baseSpreadAngleRadians_set(weaponOrig.baseSpread);
			if (Offsets::spreadHip) asset->spreadHip_set(weaponOrig.spreadHip);
			if (Offsets::spreadAim) asset->spreadAim_set(weaponOrig.spreadAim);
		}

		// Rapid fire
		if (Offsets::firerate)
			asset->firerate_set(Config::rapidFire ? 0 : weaponOrig.firerate);

		// Range: infinite range > extended melee > original
		if (Offsets::range)
		{
			if (Config::infiniteRange)
			{
				asset->range_set(9999.0f);
				if (Offsets::damageFalloffRange) asset->damageFalloffRange_set(9999.0f);
			}
			else if (Config::extendedMelee)
			{
				asset->range_set(20.0f);
				if (Offsets::damageFalloffRange) asset->damageFalloffRange_set(20.0f);
			}
			else
			{
				asset->range_set(weaponOrig.range);
				if (Offsets::damageFalloffRange) asset->damageFalloffRange_set(weaponOrig.damageFalloff);
			}
		}

		if (Offsets::aimingMovementSpeedMultiplier)
			asset->aimingMovementSpeedMultiplier_set(1.0f);
	}

	inline void UpdateGodMode(SDG::Player* localPlayer)
	{
		if (!Config::godMode) return;
		if (!Offsets::_life) return;

		auto life = localPlayer->life();
		if (!life || (uintptr_t)life < 0x10000) return;

		if (Offsets::_health) life->health_set(100);
		if (Offsets::_food) life->food_set(100);
		if (Offsets::_water) life->water_set(100);
		if (Offsets::_stamina) life->stamina_set(100);
		if (Offsets::_virus) life->virus_set(100);
		if (Offsets::_isBleeding) life->isBleeding_set(false);
		if (Offsets::_isBroken) life->isBroken_set(false);
	}

	inline void UpdateMovement(SDG::Player* localPlayer)
	{
		if (!Offsets::_movement) return;

		auto movement = localPlayer->movement();
		if (!movement || (uintptr_t)movement < 0x10000) return;

		// Speed hack - always write correct value so it resets when toggled off
		if (Offsets::pluginSpeedMultiplier)
			movement->pluginSpeedMultiplier_set(Config::speedHack ? Config::speedMultiplier : 1.0f);

		// Super jump - always write
		if (Offsets::pluginJumpMultiplier)
			movement->pluginJumpMultiplier_set(Config::superJump ? Config::jumpMultiplier : 1.0f);

		// Check if in vehicle
		uintptr_t vehiclePtr = 0;
		if (Offsets::_vehicle)
			vehiclePtr = movement->vehicle();
		bool inVehicle = vehiclePtr && vehiclePtr > 0x10000;

		// Gravity: 0 if foot-fly active; vehicle fly handles its own velocity
		bool shouldZeroGravity = Config::flyHack;

		if (Offsets::pluginGravityMultiplier)
			movement->pluginGravityMultiplier_set(shouldZeroGravity ? 0.0f : 1.0f);

		// Fly velocity control (Space=up, Ctrl=down)
		if (Config::flyHack && Offsets::velocity)
		{
			vector3 vel = movement->velocity();

			if (GetAsyncKeyState(VK_SPACE) & 0x8000)
			{
				vel.y = 18.0f;
			}
			else if (GetAsyncKeyState(VK_CONTROL) & 0x8000)
			{
				vel.y = -18.0f;
				if (Offsets::pendingLaunchVelocity)
					movement->pendingLaunchVelocity_set({ 0, -20.0f, 0 });
			}
			else
			{
				vel.y = 0.0f;
			}

			movement->velocity_set(vel);
		}

		// Vehicle fly — WASD moves relative to where you're looking (full 3D, pitch-based).
		// Looking up + W flies you upward-forward. Space/Ctrl still work for pure vertical.
		if (Config::vehicleFly && inVehicle)
		{
			// Kill all velocity so physics can't fight our position writes
			if (Offsets::velocity)
				movement->velocity_set({ 0.0f, 0.0f, 0.0f });
			if (Offsets::pendingLaunchVelocity)
				movement->pendingLaunchVelocity_set({ 0.0f, 0.0f, 0.0f });

			auto vehicle = reinterpret_cast<SDG::InteractableVehicle*>(vehiclePtr);
			auto vgo = vehicle->gameObject();
			if (vgo && (uintptr_t)vgo > 0x10000)
			{
				auto vTransform = vgo->transform();
				vector3 pos = vTransform.localPosition();

				float yawDeg = 0.0f, pitchDeg = 90.0f; // 90 = horizontal in Unturned convention
				if (Offsets::_look)
				{
					auto look = localPlayer->look();
					if (look && (uintptr_t)look > 0x10000)
					{
						if (Offsets::_yaw)   yawDeg   = look->yaw();
						if (Offsets::_pitch) pitchDeg = look->pitch();
					}
				}

				float yawRad = yawDeg * 3.14159265f / 180.0f;
				// Unturned pitch: 90=horizontal, 0=straight up, 180=straight down
				float stdPitch = (pitchDeg - 90.0f) * 3.14159265f / 180.0f; // 0=horiz, +up, -down

				// Full 3D forward vector (pitch + yaw combined)
				vector3 fwd3D = {
					cosf(stdPitch) * sinf(yawRad),
					sinf(stdPitch),
					cosf(stdPitch) * cosf(yawRad)
				};
				// Flat right vector (yaw only, no pitch roll on strafing)
				vector3 right = { cosf(yawRad), 0.0f, -sinf(yawRad) };

				const float SPEED = 0.35f;

				if (GetAsyncKeyState(0x57) & 0x8000) pos = pos + fwd3D *  SPEED; // W — forward along look dir
				if (GetAsyncKeyState(0x53) & 0x8000) pos = pos + fwd3D * -SPEED; // S — backward
				if (GetAsyncKeyState(0x44) & 0x8000) pos = pos + right *  SPEED; // D — strafe right
				if (GetAsyncKeyState(0x41) & 0x8000) pos = pos + right * -SPEED; // A — strafe left
				if (GetAsyncKeyState(VK_SPACE)   & 0x8000) pos.y += SPEED;       // Space — pure up
				if (GetAsyncKeyState(VK_CONTROL) & 0x8000) pos.y -= SPEED;       // Ctrl — pure down

				vTransform.setLocalPosition(pos);
			}
		}

	}

	inline void UpdateScopeSway(SDG::Player* localPlayer)
	{
		if (!Config::noScopeSway) return;
		if (!Offsets::_animator || !Offsets::scopeSway) return;

		uintptr_t animatorPtr = read<uintptr_t>((uintptr_t)localPlayer + Offsets::_animator);
		if (!animatorPtr || animatorPtr < 0x10000) return;

		vector3 zero = { 0, 0, 0 };
		write<vector3>(zero, animatorPtr + Offsets::scopeSway);
	}

	inline void UpdateSpinBot(SDG::Player* localPlayer)
	{
		if (!Config::spinBot) return;
		if (!Offsets::_look || !Offsets::_yaw) return;

		// Don't spin while aimbot or silent aim is actively firing
		bool aiming = (Config::aimbot && (GetAsyncKeyState(VK_RBUTTON) & 0x8000));
		bool silentFiring = (Config::silentAim && (GetAsyncKeyState(VK_LBUTTON) & 0x8000));
		if (aiming || silentFiring) return;

		auto look = localPlayer->look();
		if (!look || (uintptr_t)look < 0x10000) return;

		// Delta-based spin: read current yaw (which already includes the player's mouse
		// input processed by the game since our last tick), then add our spin increment.
		// This lets the player look freely — their mouse input shifts the base, we just
		// keep adding rotation on top of wherever they're looking.
		float currentYaw = look->yaw();
		currentYaw += 30.0f;
		if (currentYaw >= 360.0f) currentYaw -= 360.0f;
		look->yaw_set(currentYaw);
	}

	inline void UpdateNoFallDamage(SDG::Player* localPlayer)
	{
		if (!Config::noFallDamage) return;
		if (!Offsets::_clothing || !Offsets::fallingDamageMultiplier) return;

		uintptr_t clothingPtr = read<uintptr_t>((uintptr_t)localPlayer + Offsets::_clothing);
		if (!clothingPtr || clothingPtr < 0x10000) return;

		write<float>(0.0f, clothingPtr + Offsets::fallingDamageMultiplier);
	}

	inline void UpdateFullbright()
	{
		if (!Offsets::ll_vision) return;

		try {
			if (Config::fullbright)
				SDG::LevelLighting::vision_set(1);
			else
			{
				int cur = SDG::LevelLighting::vision();
				if (cur == 1)
					SDG::LevelLighting::vision_set(0);
			}
		}
		catch (...) {}
	}

	// ── BoCheat features ─────────────────────────────────────────────────────

	inline void UpdateNoFog()
	{
		if (!Offsets::ll_fog) return;
		try {
			SDG::LevelLighting::fog_set(!Config::noFog);
		} catch (...) {}
	}

	inline void UpdateForceGPS(SDG::Player* localPlayer)
	{
		if (!Config::forceGPS) return;
		if (!Offsets::_movement || !Offsets::pm_gps) return;
		auto mv = localPlayer->movement();
		if (!mv || (uintptr_t)mv < 0x10000) return;
		mv->gps_set(true);
	}

	inline void UpdateForceCompass(SDG::Player* localPlayer)
	{
		if (!Config::forceCompass) return;
		if (!Offsets::_movement || !Offsets::pm_compass) return;
		auto mv = localPlayer->movement();
		if (!mv || (uintptr_t)mv < 0x10000) return;
		mv->compass_set(true);
	}

	inline void UpdateNoFlash(SDG::Player* localPlayer)
	{
		if (!Config::noFlash) return;
		if (!Offsets::_life || !Offsets::pl_stunDuration) return;
		auto life = localPlayer->life();
		if (!life || (uintptr_t)life < 0x10000) return;
		life->stunDuration_set(0.0f);
	}

	inline void UpdateNightVision()
	{
		if (!Offsets::ll_vision) return;
		try {
			if (Config::nightVision)
				SDG::LevelLighting::vision_set(2); // military nightvision
			else if (!Config::fullbright)
			{
				int cur = SDG::LevelLighting::vision();
				if (cur == 2)
					SDG::LevelLighting::vision_set(0);
			}
		} catch (...) {}
	}

	inline float originalFOV = 0;
	inline void UpdateFOVChanger()
	{
		if (!Offsets::os_cachedVerticalFOV) return;
		if (!Classes::OptionsSettings) return;

		if (Config::fovChanger)
		{
			float currentFOV = SDG::OptionsSettings::cachedVerticalFOV();
			if (originalFOV == 0 && currentFOV > 1.0f)
				originalFOV = currentFOV;
			if (fabsf(currentFOV - Config::customFOV) > 0.5f)
				SDG::OptionsSettings::cachedVerticalFOV_set(Config::customFOV);
		}
		else if (originalFOV > 0)
		{
			SDG::OptionsSettings::cachedVerticalFOV_set(originalFOV);
			originalFOV = 0;
		}
	}

	inline void UpdateInstantReload(SDG::Player* localPlayer)
	{
		if (!Config::instantReload) return;
		if (!Offsets::_equipment || !Offsets::_useable) return;

		auto equip = localPlayer->equipment();
		if (!equip) return;

		uintptr_t useablePtr = equip->useable();
		if (!useablePtr || useablePtr < 0x10000) return;

		if (Offsets::ug_reloadTime)
			write<float>(0.0f, useablePtr + Offsets::ug_reloadTime);

		if (Offsets::ug_needsRechamber)
			write<bool>(false, useablePtr + Offsets::ug_needsRechamber);
	}

	inline void UpdateTriggerbot(SDG::Player* localPlayer)
	{
		if (!Config::triggerbot) return;
		if (currentTarget.index < 0) return;
		if (!Offsets::_look || !Offsets::_yaw || !Offsets::_pitch) return;

		auto look = localPlayer->look();
		if (!look || (uintptr_t)look < 0x10000) return;

		float angleDiff = Math::AngleDiffFOV(
			Overlay::localCamPos, currentTarget.position,
			look->yaw(), look->pitch());

		if (angleDiff < 3.0f)
		{
			INPUT input = {};
			input.type = INPUT_MOUSE;
			input.mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
			SendInput(1, &input, sizeof(INPUT));
			Sleep(1);
			input.mi.dwFlags = MOUSEEVENTF_LEFTUP;
			SendInput(1, &input, sizeof(INPUT));
		}
	}

	inline void GatherVehicleData(vector3 localPos)
	{
		if (!Config::vehicleESP) return;
		if (!Offsets::vm_vehicles) return;

		auto vehicles = SDG::VehicleManager::vehicles();
		if (!vehicles) { Overlay::vehicleCount = 0; return; }

		uint32_t count = vehicles->Count();
		if (count > 64) count = 64;

		int valid = 0;
		for (uint32_t i = 0; i < count && valid < 64; i++)
		{
			auto veh = vehicles->Get(i);
			if (!veh || (uintptr_t)veh < 0x10000) continue;

			if (Offsets::_isExploded)
			{
				bool exploded = veh->isExploded();
				if (exploded) continue;
			}

			auto go = veh->gameObject();
			if (!go) continue;

			auto t = go->transform();
			vector3 pos = t.position();

			float dist = Math::Distance(localPos, pos);
			if (dist < 3.0f || dist > 800.0f) continue;

			auto& vd = Overlay::vehicles[valid];
			vd.pos = pos;
			vd.distance = dist;
			vd.valid = true;
			valid++;
		}
		Overlay::vehicleCount = valid;
	}

	inline void GatherItemData(vector3 localPos)
	{
		if (!Config::itemESP) return;
		if (!Offsets::im_clampedItems) return;

		auto items = SDG::ItemManager::clampedItems();
		if (!items) { Overlay::itemCount = 0; return; }

		uint32_t count = items->Count();
		if (count > 128) count = 128;

		int valid = 0;
		for (uint32_t i = 0; i < count && valid < 128; i++)
		{
			auto item = items->Get(i);
			if (!item || (uintptr_t)item < 0x10000) continue;

			auto go = ((SDG::InteractableItem*)item)->gameObject();
			if (!go) continue;

			auto t = go->transform();
			vector3 pos = t.position();

			float dist = Math::Distance(localPos, pos);
			if (dist < 1.0f || dist > 200.0f) continue;

			auto& id = Overlay::items[valid];
			id.pos = pos;
			id.distance = dist;
			id.valid = true;

			id.name[0] = 0;
			if (Offsets::ii_asset && Offsets::ia_itemName)
			{
				uintptr_t assetPtr = ((SDG::InteractableItem*)item)->asset();
				if (assetPtr && assetPtr > 0x10000)
				{
					uintptr_t nameStr = read<uintptr_t>(assetPtr + Offsets::ia_itemName);
					if (nameStr && nameStr > 0x10000)
					{
						auto n = ReadManagedStringA(nameStr);
						if (!n.empty())
							strncpy_s(id.name, n.c_str(), 31);
					}
				}
			}
			if (!id.name[0])
				sprintf_s(id.name, "Item");

			valid++;
		}
		Overlay::itemCount = valid;
	}

	inline void GatherZombieData(vector3 localPos)
	{
		if (!Config::zombieESP) return;
		if (!Offsets::zm_tickingZombies) return;

		auto zombies = SDG::ZombieManager::tickingZombies();
		if (!zombies) { Overlay::zombieCount = 0; return; }

		uint32_t count = zombies->Count();
		if (count > 128) count = 128;

		int valid = 0;
		for (uint32_t i = 0; i < count && valid < 128; i++)
		{
			auto zombie = zombies->Get(i);
			if (!zombie || (uintptr_t)zombie < 0x10000) continue;

			if (Offsets::z_isDead)
			{
				if (zombie->isDead()) continue;
			}

			auto go = zombie->gameObject();
			if (!go) continue;

			auto t = go->transform();
			vector3 pos = t.position();

			float dist = Math::Distance(localPos, pos);
			if (dist < 1.0f || dist > 300.0f) continue;

			auto& zd = Overlay::zombies[valid];
			zd.pos = pos;
			zd.distance = dist;
			zd.valid = true;
			valid++;
		}
		Overlay::zombieCount = valid;
	}

	inline void UpdateAdmin(SDG::Player* localPlayer)
	{
		if (!Config::adminMode) return;
		if (!Offsets::channel || !Offsets::owner) return;

		auto ch = localPlayer->channel();
		if (!ch || (uintptr_t)ch < 0x10000) return;
		auto ow = ch->owner();
		if (!ow || (uintptr_t)ow < 0x10000) return;

		ow->admin_set(1);
	}

	inline void GatherPlayerData(SDG::Player* localPlayer)
	{
		std::lock_guard<std::mutex> lock(Overlay::dataMutex);
		vector3 localPos = {};

		auto go = localPlayer->gameObject();
		if (go)
		{
			auto t = go->transform();
			localPos = t.position();
		}

		float localYawVal = 0;
		float localPitchVal = 0;
		if (Offsets::_look)
		{
			auto look = localPlayer->look();
			if (look && (uintptr_t)look > 0x10000)
			{
				if (Offsets::_yaw) localYawVal = look->yaw();
				if (Offsets::_pitch) localPitchVal = look->pitch();
			}
		}

		Overlay::localCamPos = { localPos.x, localPos.y + 1.65f, localPos.z };
		Overlay::localYaw = localYawVal;
		Overlay::localPitch = localPitchVal;

		if (!Offsets::_clients)
		{
			Overlay::playerCount = 0;
			return;
		}

		auto clients = SDG::Provider::clients();
		if (!clients) { Overlay::playerCount = 0; return; }

		uint32_t count = clients->Count();
		if (count > 48) count = 48;

		currentTarget = { -1, Config::spinBot ? 9999.0f : Config::aimbotFOV, {} };
		int validCount = 0;

		for (uint32_t i = 0; i < count; i++)
		{
			auto steamPlayer = clients->Get(i);
			if (!steamPlayer) continue;

			auto player = steamPlayer->player();
			if (!player) continue;
			if (reinterpret_cast<uintptr_t>(player) == reinterpret_cast<uintptr_t>(localPlayer))
				continue;

			auto pgo = player->gameObject();
			if (!pgo) continue;

			auto transform = pgo->transform();
			vector3 playerPos = transform.position();

			float dist = Math::Distance(localPos, playerPos);
			if (dist < 1.0f || dist > 1500.0f) continue;

			auto& pd = Overlay::players[validCount];
			pd.feetPos = playerPos;
			pd.headPos = { playerPos.x, playerPos.y + 1.9f, playerPos.z };
			pd.distance = dist;
			pd.valid = true;
			pd.isTarget = false;

			if (Offsets::_life)
			{
				auto pLife = player->life();
				if (pLife && (uintptr_t)pLife > 0x10000 && Offsets::_health)
					pd.health = (float)pLife->health();
				else
					pd.health = 100;
			}
			else
				pd.health = 100;

			pd.name[0] = 0;
			if (Offsets::_playerID && Offsets::_characterName)
			{
				uintptr_t pidPtr = read<uintptr_t>((uintptr_t)steamPlayer + Offsets::_playerID);
				if (pidPtr && pidPtr > 0x10000)
				{
					uintptr_t nameStrPtr = read<uintptr_t>(pidPtr + Offsets::_characterName);
					if (nameStrPtr && nameStrPtr > 0x10000)
					{
						auto charName = ReadManagedStringA(nameStrPtr);
						if (!charName.empty())
							strncpy_s(pd.name, charName.c_str(), 63);
					}
				}
			}
			if (!pd.name[0])
				sprintf_s(pd.name, "Player %d", i);

			if (Config::spinBot)
			{
				// When spinning, select closest player by distance
				if (dist < currentTarget.fov)
				{
					currentTarget.index = validCount;
					currentTarget.fov = dist;
					currentTarget.position = pd.headPos;
				}
			}
			else
			{
				float angleFov = Math::AngleDiffFOV(
					Overlay::localCamPos, pd.headPos, localYawVal, localPitchVal);

				if (angleFov < currentTarget.fov)
				{
					currentTarget.index = validCount;
					currentTarget.fov = angleFov;
					currentTarget.position = pd.headPos;
				}
			}

			validCount++;
		}

		if (currentTarget.index >= 0 && currentTarget.index < validCount)
			Overlay::players[currentTarget.index].isTarget = true;

		Overlay::playerCount = validCount;
	}

	inline void UpdateAimbot(SDG::Player* localPlayer)
	{
		if (!Offsets::_look || !Offsets::_yaw || !Offsets::_pitch) return;

		auto look = localPlayer->look();
		if (!look || (uintptr_t)look < 0x10000) return;

		// Silent aim: snap to target for a few ticks, then restore original angles
		if (Config::silentAim)
		{
			// If we're counting down from a snap, restore when done
			if (silentAimTicks > 0)
			{
				silentAimTicks--;
				if (silentAimTicks == 0)
				{
					look->yaw_set(savedYaw);
					look->pitch_set(savedPitch);
				}
				return;
			}

			bool lmbDown = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
			if (lmbDown && currentTarget.index >= 0)
			{
				savedYaw = look->yaw();
				savedPitch = look->pitch();

				vector3 angles = Math::CalcAngle(Overlay::localCamPos, currentTarget.position);
				look->yaw_set(angles.y);
				look->pitch_set(angles.x);

				// Hold aim on target for 8 ticks (~40ms) — covers one 20Hz server tick
				silentAimTicks = 8;
				return;
			}
		}

		// Regular aimbot (smooth aim while holding RMB)
		if (Config::aimbot && (GetAsyncKeyState(VK_RBUTTON) & 0x8000))
		{
			if (currentTarget.index < 0) return;

			vector3 angles = Math::CalcAngle(Overlay::localCamPos, currentTarget.position);
			float currentYaw = look->yaw();
			float currentPitch = look->pitch();
			// Normalize smooth by frame time so speed is consistent regardless of FPS
			float frameScale = (float)(Overlay::g_frameDeltaMs / 5.0); // baseline 5ms tick
			float smooth = max(1.1f, Config::aimbotSmooth / frameScale);
			float newYaw = Math::SmoothAngle(currentYaw, angles.y, smooth);
			float newPitch = Math::SmoothAngle(currentPitch, angles.x, smooth);
			look->yaw_set(newYaw);
			look->pitch_set(newPitch);
		}
	}

	inline int _worldEspTick = 0;

	inline void Update(SDG::Player* localPlayer)
	{
		UpdateAdmin(localPlayer);
		UpdateWeapon(localPlayer);
		UpdateGodMode(localPlayer);
		UpdateMovement(localPlayer);
		UpdateScopeSway(localPlayer);
		UpdateSpinBot(localPlayer);
		UpdateNoFallDamage(localPlayer);
		UpdateFullbright();
		UpdateNightVision();
		UpdateNoFog();
		UpdateFOVChanger();
		UpdateInstantReload(localPlayer);
		UpdateForceGPS(localPlayer);
		UpdateForceCompass(localPlayer);
		UpdateNoFlash(localPlayer);
		GatherPlayerData(localPlayer);
		UpdateAimbot(localPlayer);
		UpdateTriggerbot(localPlayer);

		// World ESP (items/vehicles/zombies) is expensive - only update every 30 frames (~150ms)
		if (++_worldEspTick >= 30)
		{
			_worldEspTick = 0;
			auto go = localPlayer->gameObject();
			vector3 localPos = go ? go->transform().position() : vector3{};
			{
				std::lock_guard<std::mutex> lock(Overlay::dataMutex);
				GatherVehicleData(localPos);
				GatherItemData(localPos);
				GatherZombieData(localPos);
			}
		}
	}
}
