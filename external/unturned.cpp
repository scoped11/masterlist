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
		_localPlayer = safe_offset(Classes::Player, "_localPlayer");
		_player = safe_offset(Classes::Player, "_player");
		Log("  _localPlayer offset: %s", _localPlayer ? "OK" : "MISSING");
		Log("  _player offset: %s", _player ? "OK" : "MISSING");

		channel = safe_offset(Classes::Player, "_channel");
		if (!channel) channel = safe_offset(Classes::Player, "channel");
		_equipment = safe_offset(Classes::Player, "_equipment");
		if (!_equipment) _equipment = safe_offset(Classes::Player, "equipment");

		_isConnected = safe_offset(Classes::Provider, "_isConnected");
		if (!_isConnected) _isConnected = safe_offset(Classes::Provider, "isConnected");
		isLoadingUGC = safe_offset(Classes::Provider, "isLoadingUGC");
		_clients = safe_offset(Classes::Provider, "_clients");
		if (!_clients) _clients = safe_offset(Classes::Provider, "clients");

		_isAdmin = safe_offset(Classes::SteamPlayer, "_isAdmin");
		if (!_isAdmin) _isAdmin = safe_offset(Classes::SteamPlayer, "isAdmin");
		_joined = safe_offset(Classes::SteamPlayer, "_joined");
		_splayer = safe_offset(Classes::SteamPlayer, "_player");
		if (!_splayer) _splayer = safe_offset(Classes::SteamPlayer, "player");

		owner = safe_offset(Classes::SteamChannel, "owner");
		if (!owner) owner = safe_offset(Classes::SteamChannel, "_owner");

		_asset = safe_offset(Classes::PlayerEquipment, "_asset");
		if (!_asset) _asset = safe_offset(Classes::PlayerEquipment, "asset");

		recoilMin_x = safe_offset(Classes::ItemGunAsset, "recoilMin_x");
		recoilMax_x = safe_offset(Classes::ItemGunAsset, "recoilMax_x");
		recoilMin_y = safe_offset(Classes::ItemGunAsset, "recoilMin_y");
		recoilMax_y = safe_offset(Classes::ItemGunAsset, "recoilMax_y");
		baseSpreadAngleRadians = safe_offset(Classes::ItemGunAsset, "<baseSpreadAngleRadians>k__BackingField");

		_life = safe_offset(Classes::Player, "_life");
		if (!_life) _life = safe_offset(Classes::Player, "life");
		_movement = safe_offset(Classes::Player, "_movement");
		if (!_movement) _movement = safe_offset(Classes::Player, "movement");
		_look = safe_offset(Classes::Player, "_look");
		if (!_look) _look = safe_offset(Classes::Player, "look");

		_health = safe_offset(Classes::PlayerLife, "_health");
		if (!_health) _health = safe_offset(Classes::PlayerLife, "health");
		_food = safe_offset(Classes::PlayerLife, "_food");
		if (!_food) _food = safe_offset(Classes::PlayerLife, "food");
		_water = safe_offset(Classes::PlayerLife, "_water");
		if (!_water) _water = safe_offset(Classes::PlayerLife, "water");
		_stamina = safe_offset(Classes::PlayerLife, "_stamina");
		if (!_stamina) _stamina = safe_offset(Classes::PlayerLife, "stamina");
		_virus = safe_offset(Classes::PlayerLife, "_virus");
		if (!_virus) _virus = safe_offset(Classes::PlayerLife, "virus");
		_isBleeding = safe_offset(Classes::PlayerLife, "_isBleeding");
		if (!_isBleeding) _isBleeding = safe_offset(Classes::PlayerLife, "isBleeding");
		_isBroken = safe_offset(Classes::PlayerLife, "_isBroken");
		if (!_isBroken) _isBroken = safe_offset(Classes::PlayerLife, "isBroken");

		pluginGravityMultiplier = safe_offset(Classes::PlayerMovement, "pluginGravityMultiplier");
		if (!pluginGravityMultiplier) pluginGravityMultiplier = safe_offset(Classes::PlayerMovement, "_pluginGravityMultiplier");
		pluginSpeedMultiplier = safe_offset(Classes::PlayerMovement, "pluginSpeedMultiplier");
		if (!pluginSpeedMultiplier) pluginSpeedMultiplier = safe_offset(Classes::PlayerMovement, "_pluginSpeedMultiplier");
		pluginJumpMultiplier = safe_offset(Classes::PlayerMovement, "pluginJumpMultiplier");
		if (!pluginJumpMultiplier) pluginJumpMultiplier = safe_offset(Classes::PlayerMovement, "_pluginJumpMultiplier");
		velocity = safe_offset(Classes::PlayerMovement, "velocity");
		if (!velocity) velocity = safe_offset(Classes::PlayerMovement, "_velocity");
		pendingLaunchVelocity = safe_offset(Classes::PlayerMovement, "pendingLaunchVelocity");
		if (!pendingLaunchVelocity) pendingLaunchVelocity = safe_offset(Classes::PlayerMovement, "_pendingLaunchVelocity");
		_vehicle = safe_offset(Classes::PlayerMovement, "_vehicle");
		if (!_vehicle) _vehicle = safe_offset(Classes::PlayerMovement, "vehicle");
		pluginFallDamageMultiplier = safe_offset(Classes::PlayerMovement, "pluginFallDamageMultiplier");
		if (!pluginFallDamageMultiplier) pluginFallDamageMultiplier = safe_offset(Classes::PlayerMovement, "_pluginFallDamageMultiplier");

		_isGrounded = safe_offset(Classes::PlayerMovement, "_isGrounded");
		if (!_isGrounded) _isGrounded = safe_offset(Classes::PlayerMovement, "isGrounded");
		totalSpeedMultiplier = safe_offset(Classes::PlayerMovement, "totalSpeedMultiplier");
		if (!totalSpeedMultiplier) totalSpeedMultiplier = safe_offset(Classes::PlayerMovement, "_totalSpeedMultiplier");
		if (!totalSpeedMultiplier) totalSpeedMultiplier = safe_offset(Classes::PlayerMovement, "<totalSpeedMultiplier>k__BackingField");
		totalGravityMultiplier = safe_offset(Classes::PlayerMovement, "totalGravityMultiplier");
		if (!totalGravityMultiplier) totalGravityMultiplier = safe_offset(Classes::PlayerMovement, "_totalGravityMultiplier");
		if (!totalGravityMultiplier) totalGravityMultiplier = safe_offset(Classes::PlayerMovement, "<totalGravityMultiplier>k__BackingField");
		Log("  _isGrounded: %s  totalSpeedMul: %s  totalGravMul: %s",
			_isGrounded ? "OK" : "--", totalSpeedMultiplier ? "OK" : "--", totalGravityMultiplier ? "OK" : "--");

		pm_controller = safe_offset(Classes::PlayerMovement, "controller");
		if (!pm_controller) pm_controller = safe_offset(Classes::PlayerMovement, "_controller");
		pm_gps = safe_offset(Classes::PlayerMovement, "gps");
		if (!pm_gps) pm_gps = safe_offset(Classes::PlayerMovement, "_gps");
		pm_compass = safe_offset(Classes::PlayerMovement, "compass");
		if (!pm_compass) pm_compass = safe_offset(Classes::PlayerMovement, "_compass");
		pl_stunDuration = safe_offset(Classes::PlayerLife, "_stunDuration");
		if (!pl_stunDuration) pl_stunDuration = safe_offset(Classes::PlayerLife, "stunDuration");

		_yaw = safe_offset(Classes::PlayerLook, "_yaw");
		if (!_yaw) _yaw = safe_offset(Classes::PlayerLook, "yaw");
		_pitch = safe_offset(Classes::PlayerLook, "_pitch");
		if (!_pitch) _pitch = safe_offset(Classes::PlayerLook, "pitch");

		flinchLocalRotation = safe_offset(Classes::PlayerLook, "flinchLocalRotation");
		if (!flinchLocalRotation) flinchLocalRotation = safe_offset(Classes::PlayerLook, "_flinchLocalRotation");
		smoothedExplosionLocalRotation = safe_offset(Classes::PlayerLook, "smoothedExplosionLocalRotation");
		if (!smoothedExplosionLocalRotation) smoothedExplosionLocalRotation = safe_offset(Classes::PlayerLook, "_smoothedExplosionLocalRotation");

		_animator = safe_offset(Classes::Player, "_animator");
		if (!_animator) _animator = safe_offset(Classes::Player, "<animator>k__BackingField");
		if (!_animator) _animator = safe_offset(Classes::Player, "animator");
		scopeSway = safe_offset(Classes::PlayerAnimator, "scopeSway");
		if (!scopeSway) scopeSway = safe_offset(Classes::PlayerAnimator, "_scopeSway");

		_clothing = safe_offset(Classes::Player, "_clothing");
		if (!_clothing) _clothing = safe_offset(Classes::Player, "<clothing>k__BackingField");
		if (!_clothing) _clothing = safe_offset(Classes::Player, "clothing");
		fallingDamageMultiplier = safe_offset(Classes::PlayerClothing, "fallingDamageMultiplier");
		if (!fallingDamageMultiplier) fallingDamageMultiplier = safe_offset(Classes::PlayerClothing, "_fallingDamageMultiplier");

		_playerID = safe_offset(Classes::SteamPlayer, "_playerID");
		if (!_playerID) _playerID = safe_offset(Classes::SteamPlayer, "playerID");
		_characterName = safe_offset(Classes::SteamPlayerID, "_characterName");
		if (!_characterName) _characterName = safe_offset(Classes::SteamPlayerID, "characterName");

		firerate = safe_offset(Classes::ItemGunAsset, "firerate");
		if (!firerate) firerate = safe_offset(Classes::ItemGunAsset, "_firerate");

		range = safe_offset_recursive(Classes::ItemGunAsset, "range");
		if (!range) range = safe_offset_recursive(Classes::ItemGunAsset, "_range");
		if (!range) range = safe_offset(Classes::ItemWeaponAsset, "range");
		Log("  range offset: 0x%X (recursive from ItemGunAsset)", (uint32_t)range);

		spreadHip = safe_offset(Classes::ItemGunAsset, "spreadHip");
		if (!spreadHip) spreadHip = safe_offset(Classes::ItemGunAsset, "_spreadHip");
		spreadAim = safe_offset(Classes::ItemGunAsset, "spreadAim");
		if (!spreadAim) spreadAim = safe_offset(Classes::ItemGunAsset, "_spreadAim");
		aimingMovementSpeedMultiplier = safe_offset(Classes::ItemGunAsset, "aimingMovementSpeedMultiplier");
		if (!aimingMovementSpeedMultiplier) aimingMovementSpeedMultiplier = safe_offset(Classes::ItemGunAsset, "_aimingMovementSpeedMultiplier");
		damageFalloffRange = safe_offset(Classes::ItemGunAsset, "damageFalloffRange");
		if (!damageFalloffRange) damageFalloffRange = safe_offset(Classes::ItemGunAsset, "_damageFalloffRange");

		_speed = safe_offset(Classes::InteractableVehicle, "_speed");
		if (!_speed) _speed = safe_offset(Classes::InteractableVehicle, "speed");
		_fuel = safe_offset(Classes::InteractableVehicle, "_fuel");
		if (!_fuel) _fuel = safe_offset(Classes::InteractableVehicle, "fuel");
		_isExploded = safe_offset(Classes::InteractableVehicle, "_isExploded");
		_health_vehicle = safe_offset(Classes::InteractableVehicle, "_health");
		if (!_health_vehicle) _health_vehicle = safe_offset(Classes::InteractableVehicle, "health");

		vm_vehicles = safe_offset(Classes::VehicleManager, "_vehicles");
		if (!vm_vehicles) vm_vehicles = safe_offset(Classes::VehicleManager, "vehicles");

		im_clampedItems = safe_offset(Classes::ItemManager, "clampedItems");
		if (!im_clampedItems) im_clampedItems = safe_offset(Classes::ItemManager, "_clampedItems");

		ii_asset = safe_offset(Classes::InteractableItem, "asset");
		if (!ii_asset) ii_asset = safe_offset(Classes::InteractableItem, "_asset");

		ia_itemName = safe_offset(Classes::ItemAsset_Class, "_itemName");
		if (!ia_itemName) ia_itemName = safe_offset(Classes::ItemAsset_Class, "itemName");

		zm_tickingZombies = safe_offset(Classes::ZombieManager, "_tickingZombies");
		if (!zm_tickingZombies) zm_tickingZombies = safe_offset(Classes::ZombieManager, "tickingZombies");

		zm_zombies = safe_offset(Classes::ZombieManager, "zombies");
		if (!zm_zombies) zm_zombies = safe_offset(Classes::ZombieManager, "_zombies");
		if (!zm_zombies) zm_zombies = safe_offset(Classes::ZombieManager, "<zombies>k__BackingField");

		zm_regions = safe_offset(Classes::ZombieManager, "regions");
		if (!zm_regions) zm_regions = safe_offset(Classes::ZombieManager, "_regions");
		if (!zm_regions) zm_regions = safe_offset(Classes::ZombieManager, "<regions>k__BackingField");

		if (Classes::ZombieRegion)
		{
			zr_zombies = safe_offset(Classes::ZombieRegion, "zombies");
			if (!zr_zombies) zr_zombies = safe_offset(Classes::ZombieRegion, "_zombies");
			if (!zr_zombies) zr_zombies = safe_offset(Classes::ZombieRegion, "<zombies>k__BackingField");
		}

		Log("  zm_zombies: %s (0x%X)  zm_regions: %s (0x%X)  zr_zombies: %s (0x%X)",
			zm_zombies ? "OK" : "--", (uint32_t)zm_zombies,
			zm_regions ? "OK" : "--", (uint32_t)zm_regions,
			zr_zombies ? "OK" : "--", (uint32_t)zr_zombies);

		// Dump all ZombieManager fields for debugging
		if (Classes::ZombieManager)
		{
			int nf = Classes::ZombieManager->num_fields();
			Log("  ZombieManager has %d fields:", nf);
			for (int i = 0; i < nf && i < 30; i++)
			{
				auto f = Classes::ZombieManager->get_field(i);
				if (f) Log("    [%d] '%s' offset=0x%X", i, f->name().c_str(), f->offset());
			}
		}
		if (Classes::ZombieRegion)
		{
			int nf = Classes::ZombieRegion->num_fields();
			Log("  ZombieRegion has %d fields:", nf);
			for (int i = 0; i < nf && i < 30; i++)
			{
				auto f = Classes::ZombieRegion->get_field(i);
				if (f) Log("    [%d] '%s' offset=0x%X", i, f->name().c_str(), f->offset());
			}
		}

		if (Classes::LevelLighting)
		{
			int nf = Classes::LevelLighting->num_fields();
			Log("  LevelLighting has %d fields:", nf);
			for (int i = 0; i < nf && i < 40; i++)
			{
				auto f = Classes::LevelLighting->get_field(i);
				if (f) Log("    [%d] '%s' offset=0x%X", i, f->name().c_str(), f->offset());
			}
		}

		z_isDead = safe_offset(Classes::Zombie, "isDead");
		if (!z_isDead) z_isDead = safe_offset(Classes::Zombie, "_isDead");

		_useable = safe_offset(Classes::PlayerEquipment, "_useable");
		if (!_useable) _useable = safe_offset(Classes::PlayerEquipment, "useable");

		ug_isReloading = safe_offset(Classes::UseableGun, "isReloading");
		if (!ug_isReloading) ug_isReloading = safe_offset(Classes::UseableGun, "_isReloading");
		ug_reloadTime = safe_offset(Classes::UseableGun, "reloadTime");
		if (!ug_reloadTime) ug_reloadTime = safe_offset(Classes::UseableGun, "_reloadTime");
		ug_needsRechamber = safe_offset(Classes::UseableGun, "needsRechamber");
		if (!ug_needsRechamber) ug_needsRechamber = safe_offset(Classes::UseableGun, "_needsRechamber");

		ll_vision = safe_offset(Classes::LevelLighting, "_vision");
		if (!ll_vision) ll_vision = safe_offset(Classes::LevelLighting, "vision");

		os_cachedVerticalFOV = safe_offset(Classes::OptionsSettings, "_cachedVerticalFOV");
		if (!os_cachedVerticalFOV) os_cachedVerticalFOV = safe_offset(Classes::OptionsSettings, "cachedVerticalFOV");
	}
}
