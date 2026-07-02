#include "external/features.h"
#include <thread>

HMODULE g_hModule = NULL;

DWORD WINAPI MainThread(LPVOID lpParam)
{
	AllocConsole();
	FILE* f;
	freopen_s(&f, "CONOUT$", "w", stdout);
	freopen_s(&f, "CONIN$", "r", stdin);
	SetConsoleTitleA("Coopyy DLL");

	Log("Initializing...");
	Memory::init();

	if (!baseAddress)
	{
		Log("Failed to find mono-2.0-bdwgc.dll");
		Log("Press END to eject.");
		while (!(GetAsyncKeyState(VK_END) & 1)) Sleep(100);
		goto cleanup;
	}

	Log("mono base: 0x%p", (void*)baseAddress);
	Log("Resolving classes...");
	Classes::init();

	printf("\n=== Class Debug ===\n");
	printf("Provider       : %p\n", Classes::Provider);
	printf("Player         : %p\n", Classes::Player);
	printf("SteamChannel   : %p\n", Classes::SteamChannel);
	printf("SteamPlayer    : %p\n", Classes::SteamPlayer);
	printf("PlayerEquipment: %p\n", Classes::PlayerEquipment);
	printf("ItemWeaponAsset: %p\n", Classes::ItemWeaponAsset);
	printf("ItemGunAsset   : %p\n", Classes::ItemGunAsset);
	printf("PlayerLife     : %p\n", Classes::PlayerLife);
	printf("PlayerMovement : %p\n", Classes::PlayerMovement);
	printf("PlayerLook     : %p\n", Classes::PlayerLook);
	printf("PlayerAnimator : %p\n", Classes::PlayerAnimator);
	printf("PlayerClothing : %p\n", Classes::PlayerClothing);
	printf("InteractVehicle: %p\n", Classes::InteractableVehicle);
	printf("SteamPlayerID  : %p\n", Classes::SteamPlayerID);
	printf("VehicleManager : %p\n", Classes::VehicleManager);
	printf("ItemManager    : %p\n", Classes::ItemManager);
	printf("InteractItem   : %p\n", Classes::InteractableItem);
	printf("ZombieManager  : %p\n", Classes::ZombieManager);
	printf("ZombieRegion   : %p\n", Classes::ZombieRegion);
	printf("Zombie         : %p\n", Classes::Zombie);
	printf("LevelLighting  : %p\n", Classes::LevelLighting);
	printf("UseableGun     : %p\n", Classes::UseableGun);
	printf("OptionsSettings: %p\n", Classes::OptionsSettings);
	printf("===================\n\n");

	Log("Resolving offsets...");
	Offsets::init();

	printf("\n=== Offset Status ===\n");
	printf("_localPlayer  : %s (0x%X)\n", Offsets::_localPlayer ? "OK" : "--", (uint32_t)Offsets::_localPlayer);
	printf("_player       : %s (0x%X)\n", Offsets::_player ? "OK" : "--", (uint32_t)Offsets::_player);
	printf("--- Life ---\n");
	printf("_life         : %s (0x%X)\n", Offsets::_life ? "OK" : "--", (uint32_t)Offsets::_life);
	printf("_health       : %s (0x%X)\n", Offsets::_health ? "OK" : "--", (uint32_t)Offsets::_health);
	printf("_food         : %s (0x%X)\n", Offsets::_food ? "OK" : "--", (uint32_t)Offsets::_food);
	printf("_water        : %s (0x%X)\n", Offsets::_water ? "OK" : "--", (uint32_t)Offsets::_water);
	printf("_stamina      : %s (0x%X)\n", Offsets::_stamina ? "OK" : "--", (uint32_t)Offsets::_stamina);
	printf("_virus        : %s (0x%X)\n", Offsets::_virus ? "OK" : "--", (uint32_t)Offsets::_virus);
	printf("--- Movement ---\n");
	printf("_movement     : %s (0x%X)\n", Offsets::_movement ? "OK" : "--", (uint32_t)Offsets::_movement);
	printf("velocity      : %s (0x%X)\n", Offsets::velocity ? "OK" : "--", (uint32_t)Offsets::velocity);
	printf("gravityMult   : %s (0x%X)\n", Offsets::pluginGravityMultiplier ? "OK" : "--", (uint32_t)Offsets::pluginGravityMultiplier);
	printf("speedMult     : %s (0x%X)\n", Offsets::pluginSpeedMultiplier ? "OK" : "--", (uint32_t)Offsets::pluginSpeedMultiplier);
	printf("jumpMult      : %s (0x%X)\n", Offsets::pluginJumpMultiplier ? "OK" : "--", (uint32_t)Offsets::pluginJumpMultiplier);
	printf("vehicle       : %s (0x%X)\n", Offsets::_vehicle ? "OK" : "--", (uint32_t)Offsets::_vehicle);
	printf("fallDmgMult   : %s (0x%X)\n", Offsets::pluginFallDamageMultiplier ? "OK" : "--", (uint32_t)Offsets::pluginFallDamageMultiplier);
	printf("--- Look ---\n");
	printf("_look         : %s (0x%X)\n", Offsets::_look ? "OK" : "--", (uint32_t)Offsets::_look);
	printf("_yaw          : %s (0x%X)\n", Offsets::_yaw ? "OK" : "--", (uint32_t)Offsets::_yaw);
	printf("_pitch        : %s (0x%X)\n", Offsets::_pitch ? "OK" : "--", (uint32_t)Offsets::_pitch);
	printf("flinchRot     : %s (0x%X)\n", Offsets::flinchLocalRotation ? "OK" : "--", (uint32_t)Offsets::flinchLocalRotation);
	printf("explosionRot  : %s (0x%X)\n", Offsets::smoothedExplosionLocalRotation ? "OK" : "--", (uint32_t)Offsets::smoothedExplosionLocalRotation);
	printf("--- Weapon ---\n");
	printf("firerate      : %s (0x%X)\n", Offsets::firerate ? "OK" : "--", (uint32_t)Offsets::firerate);
	printf("range         : %s (0x%X)\n", Offsets::range ? "OK" : "--", (uint32_t)Offsets::range);
	printf("spreadHip     : %s (0x%X)\n", Offsets::spreadHip ? "OK" : "--", (uint32_t)Offsets::spreadHip);
	printf("spreadAim     : %s (0x%X)\n", Offsets::spreadAim ? "OK" : "--", (uint32_t)Offsets::spreadAim);
	printf("dmgFalloff    : %s (0x%X)\n", Offsets::damageFalloffRange ? "OK" : "--", (uint32_t)Offsets::damageFalloffRange);
	printf("aimMoveSpeed  : %s (0x%X)\n", Offsets::aimingMovementSpeedMultiplier ? "OK" : "--", (uint32_t)Offsets::aimingMovementSpeedMultiplier);
	printf("--- Animator/Clothing ---\n");
	printf("_animator     : %s (0x%X)\n", Offsets::_animator ? "OK" : "--", (uint32_t)Offsets::_animator);
	printf("scopeSway     : %s (0x%X)\n", Offsets::scopeSway ? "OK" : "--", (uint32_t)Offsets::scopeSway);
	printf("_clothing     : %s (0x%X)\n", Offsets::_clothing ? "OK" : "--", (uint32_t)Offsets::_clothing);
	printf("fallDmgMult   : %s (0x%X)\n", Offsets::fallingDamageMultiplier ? "OK" : "--", (uint32_t)Offsets::fallingDamageMultiplier);
	printf("--- Names ---\n");
	printf("_playerID     : %s (0x%X)\n", Offsets::_playerID ? "OK" : "--", (uint32_t)Offsets::_playerID);
	printf("_characterName: %s (0x%X)\n", Offsets::_characterName ? "OK" : "--", (uint32_t)Offsets::_characterName);
	printf("--- New Features ---\n");
	printf("vm_vehicles   : %s (0x%X)\n", Offsets::vm_vehicles ? "OK" : "--", (uint32_t)Offsets::vm_vehicles);
	printf("im_clampItems : %s (0x%X)\n", Offsets::im_clampedItems ? "OK" : "--", (uint32_t)Offsets::im_clampedItems);
	printf("ii_asset      : %s (0x%X)\n", Offsets::ii_asset ? "OK" : "--", (uint32_t)Offsets::ii_asset);
	printf("ia_itemName   : %s (0x%X)\n", Offsets::ia_itemName ? "OK" : "--", (uint32_t)Offsets::ia_itemName);
	printf("zm_tickZombie : %s (0x%X)\n", Offsets::zm_tickingZombies ? "OK" : "--", (uint32_t)Offsets::zm_tickingZombies);
	printf("zm_zombies    : %s (0x%X)\n", Offsets::zm_zombies ? "OK" : "--", (uint32_t)Offsets::zm_zombies);
	printf("zm_regions    : %s (0x%X)\n", Offsets::zm_regions ? "OK" : "--", (uint32_t)Offsets::zm_regions);
	printf("zr_zombies    : %s (0x%X)\n", Offsets::zr_zombies ? "OK" : "--", (uint32_t)Offsets::zr_zombies);
	printf("z_isDead      : %s (0x%X)\n", Offsets::z_isDead ? "OK" : "--", (uint32_t)Offsets::z_isDead);
	printf("_useable      : %s (0x%X)\n", Offsets::_useable ? "OK" : "--", (uint32_t)Offsets::_useable);
	printf("ug_isReload   : %s (0x%X)\n", Offsets::ug_isReloading ? "OK" : "--", (uint32_t)Offsets::ug_isReloading);
	printf("ug_reloadTime : %s (0x%X)\n", Offsets::ug_reloadTime ? "OK" : "--", (uint32_t)Offsets::ug_reloadTime);
	printf("ug_rechamber  : %s (0x%X)\n", Offsets::ug_needsRechamber ? "OK" : "--", (uint32_t)Offsets::ug_needsRechamber);
	printf("ll_vision     : %s (0x%X)\n", Offsets::ll_vision ? "OK" : "--", (uint32_t)Offsets::ll_vision);
	printf("os_fov        : %s (0x%X)\n", Offsets::os_cachedVerticalFOV ? "OK" : "--", (uint32_t)Offsets::os_cachedVerticalFOV);
	printf("=====================\n\n");

	Log("Initializing chams...");
	Chams::Init();

	Log("Waiting for server connection...");
	while (!SDG::Provider::isConnected())
	{
		if (GetAsyncKeyState(VK_END) & 1) goto cleanup;
		Sleep(1000);
		printf(".");
	}
	printf("\n");

	{
		auto localPlayer = Features::GetLocalPlayer();
		if (!localPlayer)
		{
			Log("Couldn't find local player");
			Log("Press END to eject.");
			while (!(GetAsyncKeyState(VK_END) & 1)) Sleep(100);
			goto cleanup;
		}

		Log("Local player: %p", localPlayer);
		auto pos = localPlayer->gameObject()->transform().position();
		Log("Position: %s", pos.toString().c_str());

		std::thread overlayThread(Overlay::Run);
		overlayThread.detach();

		Log("Press END to eject DLL.");
		Sleep(300);

		Config::PrintMenu();

		while (true)
		{
			if (GetAsyncKeyState(VK_END) & 1)
				break;

			bool prev[] = {
				Config::aimbot, Config::silentAim, Config::esp,
				Config::noRecoil, Config::noSpread, Config::rapidFire,
				Config::infiniteRange, Config::godMode, Config::speedHack,
				Config::flyHack, Config::superJump, Config::adminMode,
				Config::vehicleFly, Config::noFallDamage,
				Config::extendedMelee, Config::noScopeSway,
				Config::spinBot, Config::triggerbot, Config::radar,
				Config::itemESP, Config::zombieESP, Config::vehicleESP,
				Config::fullbright, Config::fovChanger, Config::instantReload,
				Config::streamProof, Config::chams, Config::noFlinch
			};
			float prevSpeed = Config::speedMultiplier;
			float prevFov = Config::aimbotFOV;
			float prevCustomFov = Config::customFOV;

			Config::HandleHotkeys();

			bool cur[] = {
				Config::aimbot, Config::silentAim, Config::esp,
				Config::noRecoil, Config::noSpread, Config::rapidFire,
				Config::infiniteRange, Config::godMode, Config::speedHack,
				Config::flyHack, Config::superJump, Config::adminMode,
				Config::vehicleFly, Config::noFallDamage,
				Config::extendedMelee, Config::noScopeSway,
				Config::spinBot, Config::triggerbot, Config::radar,
				Config::itemESP, Config::zombieESP, Config::vehicleESP,
				Config::fullbright, Config::fovChanger, Config::instantReload,
				Config::streamProof, Config::chams, Config::noFlinch
			};

			bool changed = (prevSpeed != Config::speedMultiplier) || (prevFov != Config::aimbotFOV) || (prevCustomFov != Config::customFOV);
			for (int i = 0; i < 28 && !changed; i++)
				if (prev[i] != cur[i]) changed = true;
			if (changed) Config::PrintMenu();

			if (!SDG::Provider::isConnected())
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

			Features::Update(localPlayer);

			Sleep(5);
		}

		Log("Ejecting...");
		Overlay::Shutdown();
		Sleep(200);

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

			if (Offsets::_clothing && Offsets::fallingDamageMultiplier)
			{
				uintptr_t clothingPtr = read<uintptr_t>((uintptr_t)lp + Offsets::_clothing);
				if (clothingPtr && clothingPtr > 0x10000)
					write<float>(1.0f, clothingPtr + Offsets::fallingDamageMultiplier);
			}
		}

		Chams::RestoreVehiclePhysics();

		Config::fovChanger = false;
		Features::UpdateFOVChanger();
	}

cleanup:
	Log("Bye!");
	Sleep(500);
	FreeConsole();
	FreeLibraryAndExitThread(g_hModule, 0);
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		g_hModule = hModule;
		DisableThreadLibraryCalls(hModule);
		HANDLE hThread = CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
		if (hThread) CloseHandle(hThread);
	}
	return TRUE;
}
