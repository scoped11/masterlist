#include "unturned.h"

namespace Classes
{
	mono_class_t* Provider;
	mono_class_t* Player;
	mono_class_t* SteamChannel;
	mono_class_t* SteamPlayer;

	mono_class_t* PlayerEquipment;
	mono_class_t* ItemAsset;
	mono_class_t* ItemWeaponAsset;
	mono_class_t* ItemGunAsset;

	mono_class_t* PlayerLife;
	mono_class_t* PlayerMovement;
	mono_class_t* PlayerLook;
	mono_class_t* PlayerAnimator;
	mono_class_t* PlayerClothing;
	mono_class_t* InteractableVehicle;
	mono_class_t* SteamPlayerID;
	mono_class_t* VehicleManager;
	mono_class_t* ItemManager;
	mono_class_t* InteractableItem;
	mono_class_t* ZombieManager;
	mono_class_t* ZombieRegion;
	mono_class_t* Zombie;
	mono_class_t* LevelLighting;
	mono_class_t* UseableGun;
	mono_class_t* ItemAsset_Class;
	mono_class_t* OptionsSettings;

	void init()
	{
		Log("  Batch-resolving all classes (single pass)...");

		const char* names[] = {
			"SDG.Unturned.Provider",
			"SDG.Unturned.Player",
			"SDG.Unturned.SteamChannel",
			"SDG.Unturned.SteamPlayer",
			"SDG.Unturned.PlayerEquipment",
			"SDG.Unturned.ItemAsset",
			"SDG.Unturned.ItemWeaponAsset",
			"SDG.Unturned.ItemGunAsset",
			"SDG.Unturned.PlayerLife",
			"SDG.Unturned.PlayerMovement",
			"SDG.Unturned.PlayerLook",
			"SDG.Unturned.PlayerAnimator",
			"SDG.Unturned.PlayerClothing",
			"SDG.Unturned.InteractableVehicle",
			"SDG.Unturned.SteamPlayerID",
			"SDG.Unturned.VehicleManager",
			"SDG.Unturned.ItemManager",
			"SDG.Unturned.InteractableItem",
			"SDG.Unturned.ZombieManager",
			"SDG.Unturned.ZombieRegion",
			"SDG.Unturned.Zombie",
			"SDG.Unturned.LevelLighting",
			"SDG.Unturned.UseableGun",
			"SDG.Unturned.OptionsSettings",
		};
		mono_class_t* results[24] = {};
		mono::find_classes_batch("Assembly-CSharp", names, results, 24);

		Provider           = results[0];
		Player             = results[1];
		SteamChannel       = results[2];
		SteamPlayer        = results[3];
		PlayerEquipment    = results[4];
		ItemAsset          = results[5];
		ItemWeaponAsset    = results[6];
		ItemGunAsset       = results[7];
		PlayerLife         = results[8];
		PlayerMovement     = results[9];
		PlayerLook         = results[10];
		PlayerAnimator     = results[11];
		PlayerClothing     = results[12];
		InteractableVehicle = results[13];
		SteamPlayerID      = results[14];
		VehicleManager     = results[15];
		ItemManager        = results[16];
		InteractableItem   = results[17];
		ZombieManager      = results[18];
		ZombieRegion       = results[19];
		Zombie             = results[20];
		LevelLighting      = results[21];
		UseableGun         = results[22];
		OptionsSettings    = results[23];
		ItemAsset_Class    = results[5];

		int found = 0;
		for (int i = 0; i < 24; i++) if (results[i]) found++;
		Log("  Resolved %d/24 classes.", found);
	}
}

namespace Offsets
{
	uintptr_t _player;
	uintptr_t _localPlayer;

	uintptr_t _isConnected;
	uintptr_t isLoadingUGC;
	uintptr_t _clients;

	uintptr_t channel;
	uintptr_t owner;

	uintptr_t _isAdmin;
	uintptr_t _splayer;
	uintptr_t _joined;

	uintptr_t _equipment;
	uintptr_t _asset;

	uintptr_t recoilMin_x;
	uintptr_t recoilMax_x;
	uintptr_t recoilMin_y;
	uintptr_t recoilMax_y;
	uintptr_t baseSpreadAngleRadians;

	uintptr_t _life;
	uintptr_t _health;
	uintptr_t _food;
	uintptr_t _water;
	uintptr_t _stamina;
	uintptr_t _virus;
	uintptr_t _isBleeding;
	uintptr_t _isBroken;

	uintptr_t _movement;
	uintptr_t pluginGravityMultiplier;
	uintptr_t pluginSpeedMultiplier;
	uintptr_t pluginJumpMultiplier;
	uintptr_t velocity;
	uintptr_t pendingLaunchVelocity;
	uintptr_t _vehicle;
	uintptr_t pluginFallDamageMultiplier;
	uintptr_t _isGrounded;
	uintptr_t totalSpeedMultiplier;
	uintptr_t totalGravityMultiplier;

	uintptr_t _look;
	uintptr_t _yaw;
	uintptr_t _pitch;
	uintptr_t flinchLocalRotation;
	uintptr_t smoothedExplosionLocalRotation;

	uintptr_t _animator;
	uintptr_t scopeSway;

	uintptr_t _clothing;
	uintptr_t fallingDamageMultiplier;

	uintptr_t _playerID;
	uintptr_t _characterName;

	uintptr_t firerate;
	uintptr_t range;
	uintptr_t spreadHip;
	uintptr_t spreadAim;
	uintptr_t aimingMovementSpeedMultiplier;
	uintptr_t damageFalloffRange;

	uintptr_t _speed;
	uintptr_t _fuel;
	uintptr_t _isExploded;
	uintptr_t _health_vehicle;

	uintptr_t vm_vehicles;
	uintptr_t im_clampedItems;
	uintptr_t ii_asset;
	uintptr_t ia_itemName;
	uintptr_t zm_tickingZombies;
	uintptr_t zm_zombies;
	uintptr_t zm_regions;
	uintptr_t zr_zombies;
	uintptr_t z_isDead;
	uintptr_t _useable;
	uintptr_t ug_isReloading;
	uintptr_t ug_reloadTime;
	uintptr_t ug_needsRechamber;
	uintptr_t ll_vision;
	uintptr_t os_cachedVerticalFOV;

	uintptr_t pm_controller;
	uintptr_t pm_gps;
	uintptr_t pm_compass;
	uintptr_t pl_stunDuration;

	void init()
	{
		Log("  Caching fields for all classes (one DMA pass per class)...");

		auto cPlayer         = Classes::Player ? Classes::Player->cache_all_fields() : std::unordered_map<std::string,int>{};
		auto cProvider       = Classes::Provider ? Classes::Provider->cache_all_fields() : std::unordered_map<std::string,int>{};
		auto cSteamPlayer    = Classes::SteamPlayer ? Classes::SteamPlayer->cache_all_fields() : std::unordered_map<std::string,int>{};
		auto cSteamChannel   = Classes::SteamChannel ? Classes::SteamChannel->cache_all_fields() : std::unordered_map<std::string,int>{};
		auto cPlayerEquip    = Classes::PlayerEquipment ? Classes::PlayerEquipment->cache_all_fields() : std::unordered_map<std::string,int>{};
		auto cGunAsset       = Classes::ItemGunAsset ? Classes::ItemGunAsset->cache_all_fields_recursive() : std::unordered_map<std::string,int>{};
		auto cWeaponAsset    = Classes::ItemWeaponAsset ? Classes::ItemWeaponAsset->cache_all_fields() : std::unordered_map<std::string,int>{};
		auto cPlayerLife     = Classes::PlayerLife ? Classes::PlayerLife->cache_all_fields() : std::unordered_map<std::string,int>{};
		auto cPlayerMove     = Classes::PlayerMovement ? Classes::PlayerMovement->cache_all_fields() : std::unordered_map<std::string,int>{};
		auto cPlayerLook     = Classes::PlayerLook ? Classes::PlayerLook->cache_all_fields() : std::unordered_map<std::string,int>{};
		auto cPlayerAnim     = Classes::PlayerAnimator ? Classes::PlayerAnimator->cache_all_fields() : std::unordered_map<std::string,int>{};
		auto cPlayerCloth    = Classes::PlayerClothing ? Classes::PlayerClothing->cache_all_fields() : std::unordered_map<std::string,int>{};
		auto cSteamPlayerID  = Classes::SteamPlayerID ? Classes::SteamPlayerID->cache_all_fields() : std::unordered_map<std::string,int>{};
		auto cVehicle        = Classes::InteractableVehicle ? Classes::InteractableVehicle->cache_all_fields() : std::unordered_map<std::string,int>{};
		auto cVehicleMgr     = Classes::VehicleManager ? Classes::VehicleManager->cache_all_fields() : std::unordered_map<std::string,int>{};
		auto cItemMgr        = Classes::ItemManager ? Classes::ItemManager->cache_all_fields() : std::unordered_map<std::string,int>{};
		auto cInterItem      = Classes::InteractableItem ? Classes::InteractableItem->cache_all_fields() : std::unordered_map<std::string,int>{};
		auto cItemAsset      = Classes::ItemAsset_Class ? Classes::ItemAsset_Class->cache_all_fields() : std::unordered_map<std::string,int>{};
		auto cZombieMgr      = Classes::ZombieManager ? Classes::ZombieManager->cache_all_fields() : std::unordered_map<std::string,int>{};
		auto cZombieRegion   = Classes::ZombieRegion ? Classes::ZombieRegion->cache_all_fields() : std::unordered_map<std::string,int>{};
		auto cZombie         = Classes::Zombie ? Classes::Zombie->cache_all_fields() : std::unordered_map<std::string,int>{};
		auto cUseableGun     = Classes::UseableGun ? Classes::UseableGun->cache_all_fields() : std::unordered_map<std::string,int>{};
		auto cLighting       = Classes::LevelLighting ? Classes::LevelLighting->cache_all_fields() : std::unordered_map<std::string,int>{};
		auto cOptions        = Classes::OptionsSettings ? Classes::OptionsSettings->cache_all_fields() : std::unordered_map<std::string,int>{};

		Log("  All fields cached. Resolving offsets...");

		_localPlayer = cached_offset(cPlayer, "_localPlayer");
		_player = cached_offset(cPlayer, "_player");
		channel = cached_offset_fb(cPlayer, "_channel", "channel");
		_equipment = cached_offset_fb(cPlayer, "_equipment", "equipment");
		_life = cached_offset_fb(cPlayer, "_life", "life");
		_movement = cached_offset_fb(cPlayer, "_movement", "movement");
		_look = cached_offset_fb(cPlayer, "_look", "look");
		_animator = cached_offset_fb(cPlayer, "_animator", "<animator>k__BackingField", "animator");
		_clothing = cached_offset_fb(cPlayer, "_clothing", "<clothing>k__BackingField", "clothing");

		_isConnected = cached_offset_fb(cProvider, "_isConnected", "isConnected");
		isLoadingUGC = cached_offset(cProvider, "isLoadingUGC");
		_clients = cached_offset_fb(cProvider, "_clients", "clients");

		_isAdmin = cached_offset_fb(cSteamPlayer, "_isAdmin", "isAdmin");
		_joined = cached_offset(cSteamPlayer, "_joined");
		_splayer = cached_offset_fb(cSteamPlayer, "_player", "player");
		_playerID = cached_offset_fb(cSteamPlayer, "_playerID", "playerID");

		owner = cached_offset_fb(cSteamChannel, "owner", "_owner");

		_asset = cached_offset_fb(cPlayerEquip, "_asset", "asset");
		_useable = cached_offset_fb(cPlayerEquip, "_useable", "useable");

		recoilMin_x = cached_offset(cGunAsset, "recoilMin_x");
		recoilMax_x = cached_offset(cGunAsset, "recoilMax_x");
		recoilMin_y = cached_offset(cGunAsset, "recoilMin_y");
		recoilMax_y = cached_offset(cGunAsset, "recoilMax_y");
		baseSpreadAngleRadians = cached_offset(cGunAsset, "<baseSpreadAngleRadians>k__BackingField");
		firerate = cached_offset_fb(cGunAsset, "firerate", "_firerate");
		range = cached_offset_fb(cGunAsset, "range", "_range");
		if (!range) range = cached_offset(cWeaponAsset, "range");
		spreadHip = cached_offset_fb(cGunAsset, "spreadHip", "_spreadHip");
		spreadAim = cached_offset_fb(cGunAsset, "spreadAim", "_spreadAim");
		aimingMovementSpeedMultiplier = cached_offset_fb(cGunAsset, "aimingMovementSpeedMultiplier", "_aimingMovementSpeedMultiplier");
		damageFalloffRange = cached_offset_fb(cGunAsset, "damageFalloffRange", "_damageFalloffRange");

		_health = cached_offset_fb(cPlayerLife, "_health", "health");
		_food = cached_offset_fb(cPlayerLife, "_food", "food");
		_water = cached_offset_fb(cPlayerLife, "_water", "water");
		_stamina = cached_offset_fb(cPlayerLife, "_stamina", "stamina");
		_virus = cached_offset_fb(cPlayerLife, "_virus", "virus");
		_isBleeding = cached_offset_fb(cPlayerLife, "_isBleeding", "isBleeding");
		_isBroken = cached_offset_fb(cPlayerLife, "_isBroken", "isBroken");
		pl_stunDuration = cached_offset_fb(cPlayerLife, "_stunDuration", "stunDuration");

		pluginGravityMultiplier = cached_offset_fb(cPlayerMove, "pluginGravityMultiplier", "_pluginGravityMultiplier");
		pluginSpeedMultiplier = cached_offset_fb(cPlayerMove, "pluginSpeedMultiplier", "_pluginSpeedMultiplier");
		pluginJumpMultiplier = cached_offset_fb(cPlayerMove, "pluginJumpMultiplier", "_pluginJumpMultiplier");
		velocity = cached_offset_fb(cPlayerMove, "velocity", "_velocity");
		pendingLaunchVelocity = cached_offset_fb(cPlayerMove, "pendingLaunchVelocity", "_pendingLaunchVelocity");
		_vehicle = cached_offset_fb(cPlayerMove, "_vehicle", "vehicle");
		pluginFallDamageMultiplier = cached_offset_fb(cPlayerMove, "pluginFallDamageMultiplier", "_pluginFallDamageMultiplier");
		_isGrounded = cached_offset_fb(cPlayerMove, "_isGrounded", "isGrounded");
		totalSpeedMultiplier = cached_offset_fb(cPlayerMove, "totalSpeedMultiplier", "_totalSpeedMultiplier");
		if (!totalSpeedMultiplier) totalSpeedMultiplier = cached_offset(cPlayerMove, "<totalSpeedMultiplier>k__BackingField");
		totalGravityMultiplier = cached_offset_fb(cPlayerMove, "totalGravityMultiplier", "_totalGravityMultiplier");
		if (!totalGravityMultiplier) totalGravityMultiplier = cached_offset(cPlayerMove, "<totalGravityMultiplier>k__BackingField");
		pm_controller = cached_offset_fb(cPlayerMove, "controller", "_controller");
		pm_gps = cached_offset_fb(cPlayerMove, "gps", "_gps");
		pm_compass = cached_offset_fb(cPlayerMove, "compass", "_compass");

		_yaw = cached_offset_fb(cPlayerLook, "_yaw", "yaw");
		_pitch = cached_offset_fb(cPlayerLook, "_pitch", "pitch");
		flinchLocalRotation = cached_offset_fb(cPlayerLook, "flinchLocalRotation", "_flinchLocalRotation");
		smoothedExplosionLocalRotation = cached_offset_fb(cPlayerLook, "smoothedExplosionLocalRotation", "_smoothedExplosionLocalRotation");

		scopeSway = cached_offset_fb(cPlayerAnim, "scopeSway", "_scopeSway");
		fallingDamageMultiplier = cached_offset_fb(cPlayerCloth, "fallingDamageMultiplier", "_fallingDamageMultiplier");
		_characterName = cached_offset_fb(cSteamPlayerID, "_characterName", "characterName");

		_speed = cached_offset_fb(cVehicle, "_speed", "speed");
		_fuel = cached_offset_fb(cVehicle, "_fuel", "fuel");
		_isExploded = cached_offset(cVehicle, "_isExploded");
		_health_vehicle = cached_offset_fb(cVehicle, "_health", "health");

		vm_vehicles = cached_offset_fb(cVehicleMgr, "_vehicles", "vehicles");
		im_clampedItems = cached_offset_fb(cItemMgr, "clampedItems", "_clampedItems");
		ii_asset = cached_offset_fb(cInterItem, "asset", "_asset");
		ia_itemName = cached_offset_fb(cItemAsset, "_itemName", "itemName");

		zm_tickingZombies = cached_offset_fb(cZombieMgr, "_tickingZombies", "tickingZombies");
		zm_zombies = cached_offset_fb(cZombieMgr, "zombies", "_zombies");
		if (!zm_zombies) zm_zombies = cached_offset(cZombieMgr, "<zombies>k__BackingField");
		zm_regions = cached_offset_fb(cZombieMgr, "regions", "_regions");
		if (!zm_regions) zm_regions = cached_offset(cZombieMgr, "<regions>k__BackingField");
		zr_zombies = cached_offset_fb(cZombieRegion, "zombies", "_zombies");
		if (!zr_zombies) zr_zombies = cached_offset(cZombieRegion, "<zombies>k__BackingField");

		z_isDead = cached_offset_fb(cZombie, "isDead", "_isDead");

		ug_isReloading = cached_offset_fb(cUseableGun, "isReloading", "_isReloading");
		ug_reloadTime = cached_offset_fb(cUseableGun, "reloadTime", "_reloadTime");
		ug_needsRechamber = cached_offset_fb(cUseableGun, "needsRechamber", "_needsRechamber");

		ll_vision = cached_offset_fb(cLighting, "_vision", "vision");
		os_cachedVerticalFOV = cached_offset_fb(cOptions, "_cachedVerticalFOV", "cachedVerticalFOV");

		Log("  _localPlayer: %s  _player: %s  range: 0x%X",
			_localPlayer ? "OK" : "MISSING", _player ? "OK" : "MISSING", (uint32_t)range);
	}
}
