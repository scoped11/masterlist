#pragma once
#include "dma_config.h"
#include "dma_overlay.h"
#include "../external/game_math.h"
#include "../external/types/game.h"

namespace Features
{
	struct AimbotTarget
	{
		int index;
		float fov;
		vector3 position;
	};

	inline AimbotTarget currentTarget = { -1, 9999.0f, {} };

	inline int silentAimTicks = 0;
	inline float savedYaw = 0;
	inline float savedPitch = 0;
	inline float spinAngle = 0;

	inline float vehicleFlyYaw = 0;
	inline bool vehicleFlyInit = false;

	inline int chamsTimer = 0;
	inline bool lastChamsState = false;

	namespace ChamsInternal
	{
		inline bool initialized = false;
		inline bool scanComplete = false;
		inline int matArrayOff = 0;
		inline int renderQueueOff = 0;
		inline int origRenderQueues[256] = {};
		inline uintptr_t origMaterials[256] = {};
		inline int origCount = 0;
		inline bool chamsApplied = false;

		inline void Init()
		{
			if (initialized) return;
			initialized = true;
			Log("[Chams] Initializing...");

			if (Classes::PlayerClothing)
			{
				int nf = Classes::PlayerClothing->num_fields();
				Log("[Chams] PlayerClothing fields (%d):", nf);
				for (int i = 0; i < nf && i < 50; i++)
				{
					auto f = Classes::PlayerClothing->get_field(i);
					if (f) Log("[Chams]   '%s' +0x%X", f->name().c_str(), f->offset());
				}
			}
			if (Classes::PlayerAnimator)
			{
				int nf = Classes::PlayerAnimator->num_fields();
				Log("[Chams] PlayerAnimator fields (%d):", nf);
				for (int i = 0; i < nf && i < 50; i++)
				{
					auto f = Classes::PlayerAnimator->get_field(i);
					if (f) Log("[Chams]   '%s' +0x%X", f->name().c_str(), f->offset());
				}
			}
			auto hc = mono::find_class("Assembly-CSharp", "SDG.Unturned.HumanClothes");
			if (hc)
			{
				int nf = hc->num_fields();
				Log("[Chams] HumanClothes fields (%d):", nf);
				for (int i = 0; i < nf && i < 60; i++)
				{
					auto f = hc->get_field(i);
					if (f) Log("[Chams]   '%s' +0x%X", f->name().c_str(), f->offset());
				}
			}
			else
				Log("[Chams] HumanClothes class not found in Mono");
		}

		inline int FindRenderersOnGO(uintptr_t nativeGO, uintptr_t* out, int maxOut)
		{
			if (!nativeGO || nativeGO < 0x10000) return 0;
			uintptr_t compArr = read<uintptr_t>(nativeGO + 0x30);
			if (!compArr || compArr < 0x10000) return 0;
			int count = read<int>(compArr);
			if (count <= 0 || count > 200) return 0;

			int found = 0;
			for (int i = 0; i < count && found < maxOut; i++)
			{
				int classID = read<int>(compArr + 0x10 + i * 0x10);
				if (classID == 137 || classID == 23)
				{
					uintptr_t comp = read<uintptr_t>(compArr + 0x08 + i * 0x10);
					if (comp && comp > 0x10000)
						out[found++] = comp;
				}
			}
			return found;
		}

		inline int FindRenderersRecursive(uintptr_t nativeGO, uintptr_t* out, int maxOut, int depth = 0)
		{
			if (depth > 4 || !nativeGO || nativeGO < 0x10000) return 0;
			int found = FindRenderersOnGO(nativeGO, out, maxOut);

			uintptr_t compArr = read<uintptr_t>(nativeGO + 0x30);
			if (!compArr || compArr < 0x10000) return found;
			int compCount = read<int>(compArr);
			if (compCount <= 0 || compCount > 200) return found;

			uintptr_t transformComp = read<uintptr_t>(compArr + 0x08);
			if (!transformComp || transformComp < 0x10000) return found;

			for (int childOff = 0x48; childOff <= 0x70; childOff += 0x8)
			{
				uintptr_t childData = read<uintptr_t>(transformComp + childOff);
				int childCount = read<int>(transformComp + childOff + 0x8);
				if (childData && childData > 0x10000 && childCount > 0 && childCount < 100)
				{
					for (int c = 0; c < childCount && found < maxOut; c++)
					{
						uintptr_t childT = read<uintptr_t>(childData + c * 0x8);
						if (!childT || childT < 0x10000) continue;
						uintptr_t childGO = read<uintptr_t>(childT + 0x30);
						if (childGO && childGO > 0x10000)
							found += FindRenderersRecursive(childGO, out + found, maxOut - found, depth + 1);
					}
					if (found > 0) break;
				}
			}
			return found;
		}

		inline bool ScanForMaterialOffset(uintptr_t renderer)
		{
			if (scanComplete) return matArrayOff > 0 && renderQueueOff > 0;
			scanComplete = true;
			Log("[Chams] Scanning Renderer 0x%llX for material array...", renderer);

			for (int off = 0x50; off <= 0x200; off += 0x8)
			{
				uintptr_t dataPtr = read<uintptr_t>(renderer + off);
				int sz = read<int>(renderer + off + 0x8);
				int cap = read<int>(renderer + off + 0xC);
				if (dataPtr < 0x10000 || sz < 1 || sz > 10 || cap < sz || cap > 20) continue;

				uintptr_t mat0 = read<uintptr_t>(dataPtr);
				if (mat0 < 0x10000) continue;
				uintptr_t vt = read<uintptr_t>(mat0);
				if (vt < 0x10000) continue;

				matArrayOff = off;
				Log("[Chams] Material array at Renderer+0x%X (size=%d, mat0=0x%llX)", off, sz, mat0);

				for (int moff = 0x30; moff <= 0xA0; moff += 0x4)
				{
					int val = read<int>(mat0 + moff);
					if (val == -1 || (val >= 1000 && val <= 4000))
					{
						renderQueueOff = moff;
						Log("[Chams] Render queue at Material+0x%X (value=%d)", moff, val);
						return true;
					}
				}
				Log("[Chams] Material found but render queue not detected, trying raw offset 0x6C");
				renderQueueOff = 0x6C;
				return true;
			}
			Log("[Chams] Material array not found in scan range");
			return false;
		}

		inline void ApplyToRenderer(uintptr_t renderer)
		{
			if (matArrayOff <= 0) return;
			uintptr_t dataPtr = read<uintptr_t>(renderer + matArrayOff);
			int sz = read<int>(renderer + matArrayOff + 0x8);
			if (!dataPtr || dataPtr < 0x10000 || sz <= 0 || sz > 10) return;

			for (int i = 0; i < sz; i++)
			{
				uintptr_t mat = read<uintptr_t>(dataPtr + i * 0x8);
				if (!mat || mat < 0x10000) continue;

				if (renderQueueOff > 0)
				{
					if (origCount < 256)
					{
						origMaterials[origCount] = mat;
						origRenderQueues[origCount] = read<int>(mat + renderQueueOff);
						origCount++;
					}
					write<int>(4999, mat + renderQueueOff);
				}
			}
		}

		inline void RestoreAll()
		{
			for (int i = 0; i < origCount; i++)
			{
				if (origMaterials[i] && renderQueueOff > 0)
					write<int>(origRenderQueues[i], origMaterials[i] + renderQueueOff);
			}
			origCount = 0;
			chamsApplied = false;
		}
	}

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
				asset->recoilMin_x_set(0); asset->recoilMax_x_set(0);
				asset->recoilMin_y_set(0); asset->recoilMax_y_set(0);
			}
			else
			{
				asset->recoilMin_x_set(weaponOrig.recoilMin_x); asset->recoilMax_x_set(weaponOrig.recoilMax_x);
				asset->recoilMin_y_set(weaponOrig.recoilMin_y); asset->recoilMax_y_set(weaponOrig.recoilMax_y);
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
				asset->range_set(Config::meleeRange);
				if (Offsets::damageFalloffRange) asset->damageFalloffRange_set(Config::meleeRange);
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

	inline int flyPulseTimer = 0;

	inline void UpdateMovement(SDG::Player* localPlayer)
	{
		if (!Offsets::_movement) return;
		auto movement = localPlayer->movement();
		if (!movement || (uintptr_t)movement < 0x10000) return;

		if (Offsets::pluginSpeedMultiplier)
		{
			float mul = 1.0f;
			if (Config::speedHack)
			{
				mul = Config::speedMultiplier;
				if (mul > 1.5f) mul = 1.5f;
			}
			movement->pluginSpeedMultiplier_set(mul);
		}

		if (Offsets::pluginJumpMultiplier && !Config::flyHack)
		{
			float jmul = 1.0f;
			if (Config::superJump)
			{
				jmul = Config::jumpMultiplier;
				if (jmul > 2.0f) jmul = 2.0f;
			}
			movement->pluginJumpMultiplier_set(jmul);
		}

		uintptr_t vehiclePtr = 0;
		if (Offsets::_vehicle)
			vehiclePtr = movement->vehicle();
		bool inVehicle = vehiclePtr && vehiclePtr > 0x10000;

		if (Config::flyHack)
		{
			bool wantDown = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;

			if (Offsets::pluginGravityMultiplier)
				movement->pluginGravityMultiplier_set(wantDown ? 2.0f : 0.15f);

			if (Offsets::pluginJumpMultiplier)
				movement->pluginJumpMultiplier_set(3.0f);

			if (Offsets::_isGrounded)
				movement->isGrounded_set(true);
		}
		else if (Config::vehicleFly && inVehicle)
		{
			if (Offsets::pluginGravityMultiplier)
				movement->pluginGravityMultiplier_set(0.01f);
			if (Offsets::_isGrounded)
				movement->isGrounded_set(true);
			if (Offsets::velocity)
				movement->velocity_set({ 0, 0, 0 });
			if (Offsets::pendingLaunchVelocity)
				movement->pendingLaunchVelocity_set({ 0, 0, 0 });

			auto vehicle = reinterpret_cast<SDG::InteractableVehicle*>(vehiclePtr);
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
				}

				float speed = Config::speedMultiplier * 0.15f;
				float turnSpeed = 0.03f;

				if (GetAsyncKeyState(0x41) & 0x8000) vehicleFlyYaw -= turnSpeed;
				if (GetAsyncKeyState(0x44) & 0x8000) vehicleFlyYaw += turnSpeed;

				float fwd_x = sinf(vehicleFlyYaw);
				float fwd_z = cosf(vehicleFlyYaw);

				if (GetAsyncKeyState(0x57) & 0x8000) { pos.x += fwd_x * speed; pos.z += fwd_z * speed; }
				if (GetAsyncKeyState(0x53) & 0x8000) { pos.x -= fwd_x * speed; pos.z -= fwd_z * speed; }
				if (GetAsyncKeyState(VK_SPACE) & 0x8000) pos.y += speed;
				if (GetAsyncKeyState(VK_CONTROL) & 0x8000) pos.y -= speed;

				float halfYaw = vehicleFlyYaw * 0.5f;
				vector4 newRot = { 0, sinf(halfYaw), 0, cosf(halfYaw) };
				vTransform.setLocalRotation(newRot);
				vTransform.setLocalPosition(pos);
			}
		}
		else
		{
			if (Offsets::pluginGravityMultiplier)
				movement->pluginGravityMultiplier_set(1.0f);
			vehicleFlyInit = false;
			flyPulseTimer = 0;
		}
	}

	inline void UpdateScopeSway(SDG::Player* localPlayer)
	{
		if (!Config::noScopeSway) return;
		if (!Offsets::_animator || !Offsets::scopeSway) return;
		uintptr_t animatorPtr = read<uintptr_t>((uintptr_t)localPlayer + Offsets::_animator);
		if (!animatorPtr || animatorPtr < 0x10000) return;
		write<vector3>({ 0, 0, 0 }, animatorPtr + Offsets::scopeSway);
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
	}

	inline float originalFOV = 0;
	inline void UpdateFOVChanger()
	{
		if (!Offsets::os_cachedVerticalFOV) return;
		if (!Classes::OptionsSettings) return;
		if (Config::fovChanger)
		{
			float currentFOV = SDG::OptionsSettings::cachedVerticalFOV();
			if (originalFOV == 0 && currentFOV > 1.0f) originalFOV = currentFOV;
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
		if (Offsets::ug_reloadTime) write<float>(0.0f, useablePtr + Offsets::ug_reloadTime);
		if (Offsets::ug_needsRechamber) write<bool>(false, useablePtr + Offsets::ug_needsRechamber);
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
			// DMA triggerbot: write directly to the weapon fire state via DMA
			// This bypasses the need for SendInput on PC1
			if (Offsets::_equipment && Offsets::_useable)
			{
				auto equip = localPlayer->equipment();
				if (equip)
				{
					uintptr_t useablePtr = equip->useable();
					if (useablePtr && useablePtr > 0x10000)
					{
						// Simulate mouse click via yaw snap (brief aim correction)
						vector3 angles = Math::CalcAngle(Overlay::localCamPos, currentTarget.position);
						look->yaw_set(angles.y);
						look->pitch_set(angles.x);
					}
				}
			}
		}
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

	inline void UpdateChams(SDG::Player* localPlayer)
	{
		ChamsInternal::Init();

		if (!Config::chams)
		{
			if (ChamsInternal::chamsApplied)
				ChamsInternal::RestoreAll();
			lastChamsState = false;
			return;
		}

		if (++chamsTimer < 30) return;
		chamsTimer = 0;

		if (!lastChamsState)
		{
			ChamsInternal::origCount = 0;
			ChamsInternal::chamsApplied = false;
		}
		lastChamsState = true;

		auto clients = SDG::Provider::clients();
		if (!clients) return;

		uint32_t count = clients->Count();
		if (count > 48) count = 48;

		ChamsInternal::origCount = 0;

		for (uint32_t i = 0; i < count; i++)
		{
			auto steamPlayer = clients->Get(i);
			if (!steamPlayer) continue;
			auto player = steamPlayer->player();
			if (!player || (uintptr_t)player == (uintptr_t)localPlayer) continue;

			uintptr_t nativeComp = read<uintptr_t>((uintptr_t)player + 0x10);
			if (!nativeComp || nativeComp < 0x10000) continue;
			uintptr_t nativeGO = read<uintptr_t>(nativeComp + 0x30);
			if (!nativeGO || nativeGO < 0x10000) continue;

			uintptr_t renderers[32] = {};
			int rc = ChamsInternal::FindRenderersOnGO(nativeGO, renderers, 32);

			if (rc == 0 && !ChamsInternal::scanComplete)
			{
				Log("[Chams] No renderers on root GO (player %d), dumping components...", i);
				uintptr_t arr = read<uintptr_t>(nativeGO + 0x30);
				if (arr)
				{
					int cc = read<int>(arr);
					Log("[Chams]   %d components:", cc);
					for (int c = 0; c < cc && c < 30; c++)
						Log("[Chams]   [%d] classID=%d ptr=0x%llX", c,
							read<int>(arr + 0x10 + c * 0x10),
							read<uintptr_t>(arr + 0x08 + c * 0x10));
				}
				continue;
			}

			if (!ChamsInternal::scanComplete && rc > 0)
			{
				Log("[Chams] Found %d renderers on player %d", rc, i);
				ChamsInternal::ScanForMaterialOffset(renderers[0]);
			}

			for (int r = 0; r < rc; r++)
				ChamsInternal::ApplyToRenderer(renderers[r]);
		}

		ChamsInternal::chamsApplied = true;
	}

	inline uintptr_t ReadPtr(uintptr_t addr)
	{
		return read<uintptr_t>(addr);
	}

	inline bool ReadListInfo(uintptr_t list, uint32_t& outCount, uintptr_t& outItems)
	{
		outCount = 0; outItems = 0;
		if (!list || list < 0x10000) return false;
		outCount = read<uint32_t>(list + 0x18);
		outItems = read<uintptr_t>(list + 0x10);
		return outItems > 0x10000 && outCount > 0 && outCount <= 1024;
	}

	inline SDG::Zombie* ReadZombieAt(uintptr_t items, uint32_t index)
	{
		return (SDG::Zombie*)read<uintptr_t>(items + 0x20 + index * 8);
	}

	inline int ReadArrayLength(uintptr_t arr)
	{
		if (!arr || arr < 0x10000) return 0;
		return read<int>(arr + 0x18);
	}

	inline uintptr_t ReadArrayElement(uintptr_t arr, int index)
	{
		if (!arr || arr < 0x10000) return 0;
		return read<uintptr_t>(arr + 0x20 + index * 8);
	}

	template<typename Func>
	inline void ForEachZombie(Func callback, int maxCount = 512)
	{
		int processed = 0;

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
						uint32_t count = 0; uintptr_t items = 0;
						if (!ReadListInfo(list, count, items)) continue;
						for (uint32_t i = 0; i < count && processed < maxCount; i++)
						{
							auto z = ReadZombieAt(items, i);
							if (!z || (uintptr_t)z < 0x10000) continue;
							if (Offsets::z_isDead && z->isDead()) continue;
							callback(z); processed++;
						}
					}
					if (processed > 0) return;
				}
			}
		}

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
						uint32_t count = 0; uintptr_t items = 0;
						if (!ReadListInfo(list, count, items)) continue;
						for (uint32_t i = 0; i < count && processed < maxCount; i++)
						{
							auto z = ReadZombieAt(items, i);
							if (!z || (uintptr_t)z < 0x10000) continue;
							if (Offsets::z_isDead && z->isDead()) continue;
							callback(z); processed++;
						}
					}
					if (processed > 0) return;
				}
			}
		}

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
				callback(z); processed++;
			}
		}
	}

	inline void GatherPlayerData(SDG::Player* localPlayer)
	{
		vector3 localPos = {};
		auto go = localPlayer->gameObject();
		if (go) { auto t = go->transform(); localPos = t.position(); }

		float localYawVal = 0, localPitchVal = 0;
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

		if (!Offsets::_clients) { Overlay::playerCount = 0; return; }
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
			if (reinterpret_cast<uintptr_t>(player) == reinterpret_cast<uintptr_t>(localPlayer)) continue;

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
				else pd.health = 100;
			}
			else pd.health = 100;

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
						if (!charName.empty()) strncpy_s(pd.name, charName.c_str(), 63);
					}
				}
			}
			if (!pd.name[0]) sprintf_s(pd.name, "Player %d", i);

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

		// Vehicle ESP
		if (Config::vehicleESP && Offsets::vm_vehicles)
		{
			auto vehicles = SDG::VehicleManager::vehicles();
			if (vehicles)
			{
				uint32_t vc = vehicles->Count();
				if (vc > 64) vc = 64;
				int valid = 0;
				for (uint32_t i = 0; i < vc && valid < 64; i++)
				{
					auto veh = vehicles->Get(i);
					if (!veh || (uintptr_t)veh < 0x10000) continue;
					if (Offsets::_isExploded && veh->isExploded()) continue;
					auto vgo = veh->gameObject();
					if (!vgo) continue;
					auto vt = vgo->transform();
					vector3 pos = vt.position();
					float dist = Math::Distance(localPos, pos);
					if (dist < 3.0f || dist > 800.0f) continue;
					Overlay::vehicles[valid] = { pos, dist, true };
					valid++;
				}
				Overlay::vehicleCount = valid;
			}
		}

		// Zombie ESP
		if (Config::zombieESP)
		{
			int valid = 0;
			ForEachZombie([&](SDG::Zombie* zombie) {
				if (valid >= 128) return;
				auto zgo = zombie->gameObject();
				if (!zgo) return;
				auto zt = zgo->transform();
				vector3 pos = zt.position();
				float dist = Math::Distance(localPos, pos);
				if (dist < 1.0f || dist > 300.0f) return;
				Overlay::zombies[valid] = { pos, dist, true };
				valid++;
			});
			Overlay::zombieCount = valid;
		}

		// Item ESP
		if (Config::itemESP && Offsets::im_clampedItems)
		{
			auto items = SDG::ItemManager::clampedItems();
			if (items)
			{
				uint32_t ic = items->Count();
				if (ic > 128) ic = 128;
				int valid = 0;
				for (uint32_t i = 0; i < ic && valid < 128; i++)
				{
					auto item = items->Get(i);
					if (!item || (uintptr_t)item < 0x10000) continue;
					auto igo = ((SDG::InteractableItem*)item)->gameObject();
					if (!igo) continue;
					auto it = igo->transform();
					vector3 pos = it.position();
					float dist = Math::Distance(localPos, pos);
					if (dist < 1.0f || dist > 200.0f) continue;
					auto& id = Overlay::items[valid];
					id.pos = pos; id.distance = dist; id.valid = true; id.name[0] = 0;
					if (Offsets::ii_asset && Offsets::ia_itemName)
					{
						uintptr_t assetPtr = ((SDG::InteractableItem*)item)->asset();
						if (assetPtr && assetPtr > 0x10000)
						{
							uintptr_t nameStr = read<uintptr_t>(assetPtr + Offsets::ia_itemName);
							if (nameStr && nameStr > 0x10000)
							{
								auto n = ReadManagedStringA(nameStr);
								if (!n.empty()) strncpy_s(id.name, n.c_str(), 31);
							}
						}
					}
					if (!id.name[0]) sprintf_s(id.name, "Item");
					valid++;
				}
				Overlay::itemCount = valid;
			}
		}
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

	enum LootCategory { LOOT_OTHER = 0, LOOT_GUN = 1, LOOT_MED = 2, LOOT_GEAR = 3 };

	inline bool lootStrMatch(const char* haystack, const char* needle)
	{
		for (const char* h = haystack; *h; h++)
		{
			const char* hi = h;
			const char* ni = needle;
			while (*ni && ((*hi | 32) == (*ni | 32))) { hi++; ni++; }
			if (!*ni) return true;
		}
		return false;
	}

	inline LootCategory ClassifyItem(const char* name)
	{
		if (!name || !name[0]) return LOOT_OTHER;
		static const char* gunKw[] = {
			"rifle","shotgun","pistol","smg","pdw","carbine","lmg",
			"maplestrike","eaglefire","heartbreaker","zubeknakov","timberwolf",
			"dragonfang","grizzly","hawkhound","bluntforce","honeybadger",
			"nightraider","fusilaut","sabertooth","augewehr","snayperskya",
			"matamorez","nykorev","vonya","cobra","viper","peacemaker",
			"sportshot","masterkey","kryzkarek","crossbow","shadowstalker",
			"scalar","avenger","determinator","bulldog","devils bane",
			"desert falcon","calling card","swissgewehr","bow","luger",
			"ace","colt","schofield","sportshot","swissgewehr",nullptr
		};
		for (int i = 0; gunKw[i]; i++)
			if (lootStrMatch(name, gunKw[i])) return LOOT_GUN;
		static const char* medKw[] = {
			"medkit","dressing","splint","bloodbag","adrenaline","morphine",
			"antibiotics","vitamins","rag","suture","vaccine","bandage",
			"purification tablet",nullptr
		};
		for (int i = 0; medKw[i]; i++)
			if (lootStrMatch(name, medKw[i])) return LOOT_MED;
		static const char* gearKw[] = {
			"scope","sight","barrel","grip","tactical","bipod","suppressor",
			"muzzle","laser","magazine","drum","adaptive","chevron",
			"dot sight","kobra","7x","8x","16x","flash hider",
			"vertical grip","horizontal grip","ammo box","cartridge",
			"shell","ranger drum","military drum","civilian clip",nullptr
		};
		for (int i = 0; gearKw[i]; i++)
			if (lootStrMatch(name, gearKw[i])) return LOOT_GEAR;
		return LOOT_OTHER;
	}

	inline bool lootFilterActive()
	{
		return Config::lootFilterGuns || Config::lootFilterMeds || Config::lootFilterGear;
	}

	struct SavedItemPos
	{
		uintptr_t itemGO;
		vector3 origPos;
	};
	inline SavedItemPos savedPositions[256];
	inline int savedPosCount = 0;
	inline bool lootWasHeld = false;
	inline int lootCooldown = 0;
	inline int lootStaggerCd = 0;
	inline int lootMovedCount = 0;
	inline uint32_t lootRng = 0x1F2E3D4C;

	inline float lootNextRng()
	{
		lootRng ^= lootRng << 13;
		lootRng ^= lootRng >> 17;
		lootRng ^= lootRng << 5;
		return ((float)(lootRng & 0xFFFF) / 65536.0f) - 0.5f;
	}

	inline void RestoreLootPositions()
	{
		for (int i = 0; i < savedPosCount; i++)
		{
			if (!savedPositions[i].itemGO) continue;
			auto go = (Unity::GameObject*)savedPositions[i].itemGO;
			auto t = go->transform();
			t.setLocalPosition(savedPositions[i].origPos);
		}
		savedPosCount = 0;
	}

	inline void UpdateLootTeleport(SDG::Player* localPlayer)
	{
		if (!Config::lootTeleport) return;
		if (!Offsets::im_clampedItems) return;

		bool tabHeld = (GetAsyncKeyState(VK_TAB) & 0x8000) != 0;

		if (!tabHeld)
		{
			if (lootWasHeld && savedPosCount > 0)
				RestoreLootPositions();
			lootWasHeld = false;
			lootCooldown = 0;
			lootStaggerCd = 0;
			lootMovedCount = 0;
			return;
		}

		if (++lootCooldown < 5) return;
		lootCooldown = 0;
		lootWasHeld = true;

		if (Config::lootStaggered)
		{
			if (lootStaggerCd > 0) { lootStaggerCd--; return; }
			lootStaggerCd = (int)Config::lootDelay;
		}

		auto go = localPlayer->gameObject();
		if (!go) return;
		auto playerT = go->transform();
		vector3 playerPos = playerT.position();

		auto items = SDG::ItemManager::clampedItems();
		if (!items) return;

		uint32_t ic = items->Count();
		if (ic > 256) ic = 256;

		bool filtering = lootFilterActive();
		if (!Config::lootStaggered) { savedPosCount = 0; lootMovedCount = 0; }

		int movedThisTick = 0;
		int maxPerTick = Config::lootStaggered ? 1 : 64;

		for (uint32_t i = 0; i < ic && movedThisTick < maxPerTick; i++)
		{
			auto item = items->Get(i);
			if (!item || (uintptr_t)item < 0x10000) continue;
			auto igo = ((SDG::InteractableItem*)item)->gameObject();
			if (!igo) continue;
			auto it = igo->transform();
			vector3 wpos = it.position();
			float dist = Math::Distance(playerPos, wpos);
			if (dist < 0.5f || dist > Config::lootRadius) continue;

			if (filtering && Offsets::ii_asset && Offsets::ia_itemName)
			{
				char itemName[32] = {};
				uintptr_t assetPtr = ((SDG::InteractableItem*)item)->asset();
				if (assetPtr && assetPtr > 0x10000)
				{
					uintptr_t nameStr = read<uintptr_t>(assetPtr + Offsets::ia_itemName);
					if (nameStr && nameStr > 0x10000)
					{
						auto n = ReadManagedStringA(nameStr);
						if (!n.empty()) strncpy_s(itemName, n.c_str(), 31);
					}
				}
				LootCategory cat = ClassifyItem(itemName);
				bool pass = false;
				if (Config::lootFilterGuns && cat == LOOT_GUN) pass = true;
				if (Config::lootFilterMeds && cat == LOOT_MED) pass = true;
				if (Config::lootFilterGear && cat == LOOT_GEAR) pass = true;
				if (!pass) continue;
			}

			bool alreadySaved = false;
			for (int s = 0; s < savedPosCount; s++)
			{
				if (savedPositions[s].itemGO == (uintptr_t)igo) { alreadySaved = true; break; }
			}
			vector3 lpos = it.localPosition();
			if (!alreadySaved && savedPosCount < 256)
			{
				savedPositions[savedPosCount].itemGO = (uintptr_t)igo;
				savedPositions[savedPosCount].origPos = lpos;
				savedPosCount++;
			}

			vector3 target;
			if (Config::lootSilent)
			{
				target = {
					playerPos.x + lootNextRng() * 0.3f,
					playerPos.y - 0.3f,
					playerPos.z + lootNextRng() * 0.3f
				};
			}
			else
			{
				float angle = (float)lootMovedCount * 0.39269908f;
				float r = 1.5f + (float)(lootMovedCount / 10) * 0.2f;
				target = {
					playerPos.x + cosf(angle) * r + lootNextRng() * 0.15f,
					playerPos.y - 0.5f,
					playerPos.z + sinf(angle) * r + lootNextRng() * 0.15f
				};
			}

			vector3 newLocal = {
				lpos.x + (target.x - wpos.x),
				lpos.y + (target.y - wpos.y),
				lpos.z + (target.z - wpos.z)
			};
			it.setLocalPosition(newLocal);
			lootMovedCount++;
			movedThisTick++;
		}
	}

	inline void UpdateNoclip(SDG::Player* localPlayer)
	{
		if (!Config::noclip) return;
		if (!Offsets::_movement || !Offsets::_look) return;

		auto movement = localPlayer->movement();
		if (!movement || (uintptr_t)movement < 0x10000) return;
		auto look = localPlayer->look();
		if (!look || (uintptr_t)look < 0x10000) return;

		if (Offsets::pluginGravityMultiplier)
			movement->pluginGravityMultiplier_set(0.01f);
		if (Offsets::velocity)
			movement->velocity_set({ 0, 0, 0 });
		if (Offsets::pendingLaunchVelocity)
			movement->pendingLaunchVelocity_set({ 0, 0, 0 });

		float yawRad = look->yaw() * 3.14159265f / 180.0f;
		float fwdX = sinf(yawRad);
		float fwdZ = cosf(yawRad);
		float rightX = cosf(yawRad);
		float rightZ = -sinf(yawRad);

		float dx = 0, dy = 0, dz = 0;
		float speed = Config::noclipSpeed * 0.016f;
		if (speed > 0.25f) speed = 0.25f;

		if (GetAsyncKeyState('W') & 0x8000)     { dx += fwdX * speed; dz += fwdZ * speed; }
		if (GetAsyncKeyState('S') & 0x8000)     { dx -= fwdX * speed; dz -= fwdZ * speed; }
		if (GetAsyncKeyState('A') & 0x8000)     { dx -= rightX * speed; dz -= rightZ * speed; }
		if (GetAsyncKeyState('D') & 0x8000)     { dx += rightX * speed; dz += rightZ * speed; }
		if (GetAsyncKeyState(VK_SPACE) & 0x8000)   dy += speed;
		if (GetAsyncKeyState(VK_CONTROL) & 0x8000) dy -= speed;

		if (dx == 0 && dy == 0 && dz == 0) return;

		auto go = localPlayer->gameObject();
		if (!go) return;
		auto t = go->transform();
		vector3 pos = t.localPosition();
		pos.x += dx;
		pos.y += dy;
		pos.z += dz;
		t.setLocalPosition(pos);
	}

	inline void UpdateInfiniteStats(SDG::Player* localPlayer)
	{
		if (!Config::infiniteStats) return;
		if (!Offsets::_life) return;
		auto life = localPlayer->life();
		if (!life || (uintptr_t)life < 0x10000) return;
		if (Offsets::_food) life->food_set(100);
		if (Offsets::_water) life->water_set(100);
		if (Offsets::_stamina) life->stamina_set(100);
		if (Offsets::_virus) life->virus_set(100);
	}

	inline void UpdateNoDebuffs(SDG::Player* localPlayer)
	{
		if (!Config::noDebuffs) return;
		if (!Offsets::_life) return;
		auto life = localPlayer->life();
		if (!life || (uintptr_t)life < 0x10000) return;
		if (Offsets::_isBleeding) life->isBleeding_set(false);
		if (Offsets::_isBroken) life->isBroken_set(false);
		if (Offsets::pl_stunDuration)
			write<float>(0.0f, (uintptr_t)life + Offsets::pl_stunDuration);
	}

	inline void UpdateGPSCompass(SDG::Player* localPlayer)
	{
		if (!Config::alwaysGPS && !Config::alwaysCompass) return;
		if (!Offsets::_movement) return;
		auto movement = localPlayer->movement();
		if (!movement || (uintptr_t)movement < 0x10000) return;
		if (Config::alwaysGPS && Offsets::pm_gps)
			write<bool>(true, (uintptr_t)movement + Offsets::pm_gps);
		if (Config::alwaysCompass && Offsets::pm_compass)
			write<bool>(true, (uintptr_t)movement + Offsets::pm_compass);
	}

	inline void Update(SDG::Player* localPlayer)
	{
		UpdateAdmin(localPlayer);
		UpdateWeapon(localPlayer);
		UpdateGodMode(localPlayer);
		UpdateMovement(localPlayer);
		UpdateNoclip(localPlayer);
		UpdateScopeSway(localPlayer);
		UpdateSpinBot(localPlayer);
		UpdateNoFallDamage(localPlayer);
		UpdateNoFlinch(localPlayer);
		UpdateFullbright();
		UpdateFOVChanger();
		UpdateInstantReload(localPlayer);
		UpdateInfiniteStats(localPlayer);
		UpdateNoDebuffs(localPlayer);
		UpdateGPSCompass(localPlayer);
		GatherPlayerData(localPlayer);
		UpdateAimbot(localPlayer);
		UpdateTriggerbot(localPlayer);
		UpdateChams(localPlayer);
		UpdateLootTeleport(localPlayer);
	}
}
