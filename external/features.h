#pragma once
#include "config.h"
#include "game_math.h"
#include "overlay.h"
#include "types/game.h"
#include "chams.h"

namespace Features
{
	struct AimbotTarget
	{
		int index;
		float fov;
		vector3 position;
	};

	inline AimbotTarget currentTarget = { -1, 9999.0f, {} };

	inline int chamsTimer = 0;
	inline bool lastChamsState = false;

	inline int silentAimTicks = 0;
	inline float savedYaw = 0;
	inline float savedPitch = 0;

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

		if (weaponOrig.assetPtr != assetAddr)
		{
			weaponOrig.assetPtr = assetAddr;
			weaponOrig.saved = true;
			if (Offsets::recoilMin_x)
			{
				weaponOrig.recoilMin_x = asset->recoilMin_x();
				weaponOrig.recoilMax_x = asset->recoilMax_x();
				weaponOrig.recoilMin_y = asset->recoilMin_y();
				weaponOrig.recoilMax_y = asset->recoilMax_y();
			}
			if (Offsets::baseSpreadAngleRadians) weaponOrig.baseSpread = asset->baseSpreadAngleRadians();
			if (Offsets::spreadHip) weaponOrig.spreadHip = asset->spreadHip();
			if (Offsets::spreadAim) weaponOrig.spreadAim = asset->spreadAim();
			if (Offsets::firerate) weaponOrig.firerate = asset->firerate();
			if (Offsets::range) weaponOrig.range = asset->range();
			if (Offsets::damageFalloffRange) weaponOrig.damageFalloff = asset->damageFalloffRange();
		}

		if (!weaponOrig.saved) return;

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

		if (Offsets::firerate)
			asset->firerate_set(Config::rapidFire ? 0 : weaponOrig.firerate);

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

	inline float vehicleFlyYaw = 0;
	inline bool vehicleFlyInit = false;

	inline void UpdateMovement(SDG::Player* localPlayer)
	{
		if (!Offsets::_movement) return;

		auto movement = localPlayer->movement();
		if (!movement || (uintptr_t)movement < 0x10000) return;

		if (Offsets::pluginSpeedMultiplier)
			movement->pluginSpeedMultiplier_set(Config::speedHack ? Config::speedMultiplier : 1.0f);

		if (Offsets::pluginJumpMultiplier)
			movement->pluginJumpMultiplier_set(Config::superJump ? Config::jumpMultiplier : 1.0f);

		uintptr_t vehiclePtr = 0;
		if (Offsets::_vehicle)
			vehiclePtr = movement->vehicle();
		bool inVehicle = vehiclePtr && vehiclePtr > 0x10000;

		bool shouldZeroGravity = Config::flyHack || (Config::vehicleFly && inVehicle);

		if (Offsets::pluginGravityMultiplier)
			movement->pluginGravityMultiplier_set(shouldZeroGravity ? 0.0f : 1.0f);

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

		if (Config::vehicleFly && inVehicle)
		{
			if (Offsets::velocity)
				movement->velocity_set({ 0, 0, 0 });
			if (Offsets::pendingLaunchVelocity)
				movement->pendingLaunchVelocity_set({ 0, 0, 0 });

			auto vehicle = reinterpret_cast<SDG::InteractableVehicle*>(vehiclePtr);

			Chams::UpdateVehicleFly(vehicle);

			auto vgo = vehicle->gameObject();
			if (vgo && (uintptr_t)vgo > 0x10000)
			{
				auto vTransform = vgo->transform();
				vector3 pos = vTransform.localPosition();

				if (!vehicleFlyInit)
				{
					vector4 rot = vTransform.localRotation();
					vehicleFlyYaw = atan2f(2.0f * (rot.w * rot.y + rot.x * rot.z),
						1.0f - 2.0f * (rot.y * rot.y + rot.x * rot.x));
					vehicleFlyInit = true;
					printf("[VFLY] Init yaw=%.1f deg\n", vehicleFlyYaw * 180.0f / 3.14159f);
				}

				float speed = Config::speedMultiplier * 0.3f;
				float turnSpeed = 0.03f;

				if (GetAsyncKeyState(0x41) & 0x8000)
					vehicleFlyYaw -= turnSpeed;
				if (GetAsyncKeyState(0x44) & 0x8000)
					vehicleFlyYaw += turnSpeed;

				float fwd_x = sinf(vehicleFlyYaw);
				float fwd_z = cosf(vehicleFlyYaw);

				if (GetAsyncKeyState(0x57) & 0x8000)
				{
					pos.x += fwd_x * speed;
					pos.z += fwd_z * speed;
				}
				if (GetAsyncKeyState(0x53) & 0x8000)
				{
					pos.x -= fwd_x * speed;
					pos.z -= fwd_z * speed;
				}
				if (GetAsyncKeyState(VK_SPACE) & 0x8000)
					pos.y += speed;
				if (GetAsyncKeyState(VK_CONTROL) & 0x8000)
					pos.y -= speed;

				float halfYaw = vehicleFlyYaw * 0.5f;
				vector4 newRot = { 0, sinf(halfYaw), 0, cosf(halfYaw) };
				vTransform.setLocalRotation(newRot);
				vTransform.setLocalPosition(pos);
			}
		}
		else
		{
			if (vehicleFlyInit)
			{
				Chams::RestoreVehiclePhysics();
				vehicleFlyInit = false;
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

		bool aiming = (Config::aimbot && (GetAsyncKeyState(VK_RBUTTON) & 0x8000));
		bool silentFiring = (Config::silentAim && (GetAsyncKeyState(VK_LBUTTON) & 0x8000));
		if (aiming || silentFiring) return;

		auto look = localPlayer->look();
		if (!look || (uintptr_t)look < 0x10000) return;

		spinAngle += 30.0f;
		if (spinAngle >= 360.0f) spinAngle -= 360.0f;
		look->yaw_set(spinAngle);
	}

	inline void UpdateNoFallDamage(SDG::Player* localPlayer)
	{
		if (!Config::noFallDamage) return;
		if (!Offsets::_clothing || !Offsets::fallingDamageMultiplier) return;

		uintptr_t clothingPtr = read<uintptr_t>((uintptr_t)localPlayer + Offsets::_clothing);
		if (!clothingPtr || clothingPtr < 0x10000) return;

		write<float>(0.0f, clothingPtr + Offsets::fallingDamageMultiplier);
	}

	inline void UpdateNoFlinch(SDG::Player* localPlayer)
	{
		if (!Config::noFlinch) return;
		if (!Offsets::_look) return;

		auto look = localPlayer->look();
		if (!look || (uintptr_t)look < 0x10000) return;

		vector4 identity = { 0, 0, 0, 1 };

		if (Offsets::flinchLocalRotation)
			write<vector4>(identity, (uintptr_t)look + Offsets::flinchLocalRotation);

		if (Offsets::smoothedExplosionLocalRotation)
			write<vector4>(identity, (uintptr_t)look + Offsets::smoothedExplosionLocalRotation);
	}

	inline void UpdateFullbright()
	{
		if (!Config::fullbright) return;

		if (Offsets::ll_vision)
			SDG::LevelLighting::vision_set(0);

		Chams::SetFullbright(true);
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

	inline bool ReadListInfo(uintptr_t list, uint32_t& outCount, uintptr_t& outItems)
	{
		outCount = 0;
		outItems = 0;
		if (!list || list < 0x10000) return false;
		__try {
			outCount = *(uint32_t*)(list + 0x18);
			outItems = *(uintptr_t*)(list + 0x10);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) { return false; }
		return outItems > 0x10000 && outCount > 0 && outCount <= 1024;
	}

	inline SDG::Zombie* ReadZombieAt(uintptr_t items, uint32_t index)
	{
		SDG::Zombie* z = nullptr;
		__try { z = *(SDG::Zombie**)(items + 0x20 + index * 8); }
		__except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
		return z;
	}

	inline int ReadArrayLength(uintptr_t arr)
	{
		int len = 0;
		__try { len = *(int*)(arr + 0x18); }
		__except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
		return len;
	}

	inline uintptr_t ReadArrayElement(uintptr_t arr, int index)
	{
		uintptr_t val = 0;
		__try { val = *(uintptr_t*)(arr + 0x20 + index * 8); }
		__except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
		return val;
	}

	inline uintptr_t ReadPtr(uintptr_t addr)
	{
		uintptr_t val = 0;
		__try { val = *(uintptr_t*)addr; }
		__except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
		return val;
	}

	template<typename Func>
	inline void ForEachZombie(Func callback, int maxCount = 512)
	{
		int processed = 0;

		// Method 1: ZombieManager.zombies (List<Zombie>[])
		if (Offsets::zm_zombies)
		{
			uintptr_t zombiesArr = SDG::ZombieManager::zombies();
			if (zombiesArr && zombiesArr > 0x10000)
			{
				int regionCount = ReadArrayLength(zombiesArr);
				if (regionCount > 0 && regionCount < 256)
				{
					for (int r = 0; r < regionCount && processed < maxCount; r++)
					{
						uintptr_t list = ReadArrayElement(zombiesArr, r);
						if (!list || list < 0x10000) continue;

						uint32_t count = 0;
						uintptr_t items = 0;
						if (!ReadListInfo(list, count, items)) continue;

						for (uint32_t i = 0; i < count && processed < maxCount; i++)
						{
							auto z = ReadZombieAt(items, i);
							if (!z || (uintptr_t)z < 0x10000) continue;
							if (Offsets::z_isDead && z->isDead()) continue;
							callback(z);
							processed++;
						}
					}
					if (processed > 0) return;
				}
			}
		}

		// Method 2: ZombieManager.regions (ZombieRegion[]) -> each has .zombies list
		if (Offsets::zm_regions && Offsets::zr_zombies)
		{
			uintptr_t regionsArr = SDG::ZombieManager::regions();
			if (regionsArr && regionsArr > 0x10000)
			{
				int regionCount = ReadArrayLength(regionsArr);
				if (regionCount > 0 && regionCount < 256)
				{
					for (int r = 0; r < regionCount && processed < maxCount; r++)
					{
						uintptr_t region = ReadArrayElement(regionsArr, r);
						if (!region || region < 0x10000) continue;

						uintptr_t list = ReadPtr(region + Offsets::zr_zombies);
						if (!list || list < 0x10000) continue;

						uint32_t count = 0;
						uintptr_t items = 0;
						if (!ReadListInfo(list, count, items)) continue;

						for (uint32_t i = 0; i < count && processed < maxCount; i++)
						{
							auto z = ReadZombieAt(items, i);
							if (!z || (uintptr_t)z < 0x10000) continue;
							if (Offsets::z_isDead && z->isDead()) continue;
							callback(z);
							processed++;
						}
					}
					if (processed > 0) return;
				}
			}
		}

		// Method 3: Fallback to tickingZombies (only active/chasing)
		if (Offsets::zm_tickingZombies)
		{
			auto zombies = SDG::ZombieManager::tickingZombies();
			if (!zombies) return;

			uint32_t count = zombies->Count();
			if (count > 128) count = 128;

			for (uint32_t i = 0; i < count && processed < maxCount; i++)
			{
				auto z = zombies->Get(i);
				if (!z || (uintptr_t)z < 0x10000) continue;
				if (Offsets::z_isDead && z->isDead()) continue;

				callback(z);
				processed++;
			}
		}
	}

	inline void GatherZombieData(vector3 localPos)
	{
		if (!Config::zombieESP) return;

		int valid = 0;
		ForEachZombie([&](SDG::Zombie* zombie)
		{
			if (valid >= 128) return;

			auto go = zombie->gameObject();
			if (!go) return;

			auto t = go->transform();
			vector3 pos = t.position();

			float dist = Math::Distance(localPos, pos);
			if (dist < 1.0f || dist > 300.0f) return;

			auto& zd = Overlay::zombies[valid];
			zd.pos = pos;
			zd.distance = dist;
			zd.valid = true;
			valid++;
		});
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

		GatherVehicleData(localPos);
		GatherItemData(localPos);
		GatherZombieData(localPos);
	}

	inline void UpdateAimbot(SDG::Player* localPlayer)
	{
		if (!Offsets::_look || !Offsets::_yaw || !Offsets::_pitch) return;

		auto look = localPlayer->look();
		if (!look || (uintptr_t)look < 0x10000) return;

		if (Config::silentAim)
		{
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

				silentAimTicks = 4;
				return;
			}
		}

		if (Config::aimbot && (GetAsyncKeyState(VK_RBUTTON) & 0x8000))
		{
			if (currentTarget.index < 0) return;

			vector3 angles = Math::CalcAngle(Overlay::localCamPos, currentTarget.position);
			float currentYaw = look->yaw();
			float currentPitch = look->pitch();
			float newYaw = Math::SmoothAngle(currentYaw, angles.y, Config::aimbotSmooth);
			float newPitch = Math::SmoothAngle(currentPitch, angles.x, Config::aimbotSmooth);
			look->yaw_set(newYaw);
			look->pitch_set(newPitch);
		}
	}

	inline void UpdateChams(SDG::Player* localPlayer)
	{
		if (!Chams::initialized) return;

		if (Config::chams && !lastChamsState)
			chamsTimer = 0;

		if (!Config::chams && lastChamsState)
		{
			if (Offsets::_clients)
			{
				auto clients = SDG::Provider::clients();
				if (clients)
				{
					uint32_t count = clients->Count();
					if (count > 48) count = 48;
					for (uint32_t i = 0; i < count; i++)
					{
						auto sp = clients->Get(i);
						if (!sp) continue;
						auto p = sp->player();
						if (!p || (uintptr_t)p == (uintptr_t)localPlayer) continue;
						Chams::Reset(p);
					}
				}
			}

			ForEachZombie([](SDG::Zombie* z) { Chams::Reset(z); });

			lastChamsState = false;
			return;
		}

		lastChamsState = Config::chams;
		if (!Config::chams) return;

		if (++chamsTimer < 60) return;
		chamsTimer = 0;

		// Player chams
		if (Offsets::_clients)
		{
			auto clients = SDG::Provider::clients();
			if (clients)
			{
				uint32_t count = clients->Count();
				if (count > 48) count = 48;

				for (uint32_t i = 0; i < count; i++)
				{
					auto sp = clients->Get(i);
					if (!sp) continue;
					auto p = sp->player();
					if (!p || (uintptr_t)p == (uintptr_t)localPlayer) continue;
					if ((uintptr_t)p < 0x10000) continue;

					bool isTarget = (currentTarget.index >= 0);
					Chams::Apply(p, isTarget);
				}
			}
		}

		// Zombie chams
		ForEachZombie([](SDG::Zombie* z) { Chams::ApplyZombie(z); });
	}

	inline void Update(SDG::Player* localPlayer)
	{
		UpdateAdmin(localPlayer);
		UpdateWeapon(localPlayer);
		UpdateGodMode(localPlayer);
		UpdateMovement(localPlayer);
		UpdateScopeSway(localPlayer);
		UpdateSpinBot(localPlayer);
		UpdateNoFallDamage(localPlayer);
		UpdateNoFlinch(localPlayer);
		UpdateFullbright();
		UpdateFOVChanger();
		UpdateInstantReload(localPlayer);
		GatherPlayerData(localPlayer);
		UpdateAimbot(localPlayer);
		UpdateTriggerbot(localPlayer);
		UpdateChams(localPlayer);
	}
}
