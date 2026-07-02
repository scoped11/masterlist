#include "unturned.h"
#include "xstr.h"

// Encrypted "Assembly-CSharp"
#define _ASM XS(0x1B,0x29,0x29,0x3F,0x37,0x38,0x36,0x23,0x77,0x19,0x09,0x32,0x3B,0x28,0x2A)

namespace Classes
{
	mono_class_t* Provider      = nullptr;
	mono_class_t* Player        = nullptr;
	mono_class_t* SteamChannel  = nullptr;
	mono_class_t* SteamPlayer   = nullptr;
	mono_class_t* PlayerEquipment   = nullptr;
	mono_class_t* ItemAsset         = nullptr;
	mono_class_t* ItemWeaponAsset   = nullptr;
	mono_class_t* ItemGunAsset      = nullptr;
	mono_class_t* PlayerLife        = nullptr;
	mono_class_t* PlayerMovement    = nullptr;
	mono_class_t* PlayerLook        = nullptr;
	mono_class_t* PlayerAnimator    = nullptr;
	mono_class_t* PlayerClothing    = nullptr;
	mono_class_t* InteractableVehicle = nullptr;
	mono_class_t* SteamPlayerID     = nullptr;
	mono_class_t* VehicleManager    = nullptr;
	mono_class_t* ItemManager       = nullptr;
	mono_class_t* InteractableItem  = nullptr;
	mono_class_t* ZombieManager     = nullptr;
	mono_class_t* Zombie            = nullptr;
	mono_class_t* LevelLighting     = nullptr;
	mono_class_t* UseableGun        = nullptr;
	mono_class_t* ItemAsset_Class   = nullptr;
	mono_class_t* OptionsSettings   = nullptr;

	void init()
	{
		auto asm_ = _ASM;
		Log("  Finding Provider...");
		Provider = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x0A,0x28,0x35,0x2C,0x33,0x3E,0x3F,0x28).c_str());
		Log("  Finding Player...");
		Player = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x0A,0x36,0x3B,0x23,0x3F,0x28).c_str());
		Log("  Finding SteamChannel...");
		SteamChannel = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x09,0x2E,0x3F,0x3B,0x37,0x19,0x32,0x3B,0x34,0x34,0x3F,0x36).c_str());
		Log("  Finding SteamPlayer...");
		SteamPlayer = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x09,0x2E,0x3F,0x3B,0x37,0x0A,0x36,0x3B,0x23,0x3F,0x28).c_str());
		Log("  Finding PlayerEquipment...");
		PlayerEquipment = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x0A,0x36,0x3B,0x23,0x3F,0x28,0x1F,0x2B,0x2F,0x33,0x2A,0x37,0x3F,0x34,0x2E).c_str());
		Log("  Finding ItemAsset...");
		ItemAsset = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x13,0x2E,0x3F,0x37,0x1B,0x29,0x29,0x3F,0x2E).c_str());
		Log("  Finding ItemWeaponAsset...");
		ItemWeaponAsset = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x13,0x2E,0x3F,0x37,0x0D,0x3F,0x3B,0x2A,0x35,0x34,0x1B,0x29,0x29,0x3F,0x2E).c_str());
		Log("  Finding ItemGunAsset...");
		ItemGunAsset = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x13,0x2E,0x3F,0x37,0x1D,0x2F,0x34,0x1B,0x29,0x29,0x3F,0x2E).c_str());
		Log("  Finding PlayerLife...");
		PlayerLife = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x0A,0x36,0x3B,0x23,0x3F,0x28,0x16,0x33,0x3C,0x3F).c_str());
		Log("  Finding PlayerMovement...");
		PlayerMovement = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x0A,0x36,0x3B,0x23,0x3F,0x28,0x17,0x35,0x2C,0x3F,0x37,0x3F,0x34,0x2E).c_str());
		Log("  Finding PlayerLook...");
		PlayerLook = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x0A,0x36,0x3B,0x23,0x3F,0x28,0x16,0x35,0x35,0x31).c_str());
		Log("  Finding PlayerAnimator...");
		PlayerAnimator = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x0A,0x36,0x3B,0x23,0x3F,0x28,0x1B,0x34,0x33,0x37,0x3B,0x2E,0x35,0x28).c_str());
		Log("  Finding PlayerClothing...");
		PlayerClothing = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x0A,0x36,0x3B,0x23,0x3F,0x28,0x19,0x36,0x35,0x2E,0x32,0x33,0x34,0x3D).c_str());
		Log("  Finding InteractableVehicle...");
		InteractableVehicle = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x13,0x34,0x2E,0x3F,0x28,0x3B,0x39,0x2E,0x3B,0x38,0x36,0x3F,0x0C,0x3F,0x32,0x33,0x39,0x36,0x3F).c_str());
		Log("  Finding SteamPlayerID...");
		SteamPlayerID = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x09,0x2E,0x3F,0x3B,0x37,0x0A,0x36,0x3B,0x23,0x3F,0x28,0x13,0x1E).c_str());
		Log("  Finding VehicleManager...");
		VehicleManager = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x0C,0x3F,0x32,0x33,0x39,0x36,0x3F,0x17,0x3B,0x34,0x3B,0x3D,0x3F,0x28).c_str());
		Log("  Finding ItemManager...");
		ItemManager = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x13,0x2E,0x3F,0x37,0x17,0x3B,0x34,0x3B,0x3D,0x3F,0x28).c_str());
		Log("  Finding InteractableItem...");
		InteractableItem = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x13,0x34,0x2E,0x3F,0x28,0x3B,0x39,0x2E,0x3B,0x38,0x36,0x3F,0x13,0x2E,0x3F,0x37).c_str());
		Log("  Finding ZombieManager...");
		ZombieManager = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x00,0x35,0x37,0x38,0x33,0x3F,0x17,0x3B,0x34,0x3B,0x3D,0x3F,0x28).c_str());
		Log("  Finding Zombie...");
		Zombie = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x00,0x35,0x37,0x38,0x33,0x3F).c_str());
		Log("  Finding LevelLighting...");
		LevelLighting = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x16,0x3F,0x2C,0x3F,0x36,0x16,0x33,0x3D,0x32,0x2E,0x33,0x34,0x3D).c_str());
		Log("  Finding UseableGun...");
		UseableGun = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x0F,0x29,0x3F,0x3B,0x38,0x36,0x3F,0x1D,0x2F,0x34).c_str());
		Log("  Finding ItemAsset (class)...");
		ItemAsset_Class = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x13,0x2E,0x3F,0x37,0x1B,0x29,0x29,0x3F,0x2E).c_str());
		Log("  Finding OptionsSettings...");
		OptionsSettings = mono::find_class(asm_.c_str(), XS(0x09,0x1E,0x1D,0x74,0x0F,0x34,0x2E,0x2F,0x28,0x34,0x3F,0x3E,0x74,0x15,0x2A,0x2E,0x33,0x35,0x34,0x29,0x09,0x3F,0x2E,0x2E,0x33,0x34,0x3D,0x29).c_str());
		Log("  All classes resolved.");
	}
}

namespace Offsets
{
	uintptr_t _player     = 0;
	uintptr_t _localPlayer = 0;
	uintptr_t _isConnected = 0;
	uintptr_t isLoadingUGC = 0;
	uintptr_t _clients    = 0;
	uintptr_t channel     = 0;
	uintptr_t owner       = 0;
	uintptr_t _isAdmin    = 0;
	uintptr_t _splayer    = 0;
	uintptr_t _equipment  = 0;
	uintptr_t _asset      = 0;
	uintptr_t _joined     = 0;
	uintptr_t recoilMin_x = 0;
	uintptr_t recoilMax_x = 0;
	uintptr_t recoilMin_y = 0;
	uintptr_t recoilMax_y = 0;
	uintptr_t baseSpreadAngleRadians = 0;
	uintptr_t _life       = 0;
	uintptr_t _health     = 0;
	uintptr_t _food       = 0;
	uintptr_t _water      = 0;
	uintptr_t _stamina    = 0;
	uintptr_t _virus      = 0;
	uintptr_t _isBleeding = 0;
	uintptr_t _isBroken   = 0;
	uintptr_t _movement   = 0;
	uintptr_t pluginGravityMultiplier  = 0;
	uintptr_t pluginSpeedMultiplier    = 0;
	uintptr_t pluginJumpMultiplier     = 0;
	uintptr_t velocity    = 0;
	uintptr_t pendingLaunchVelocity = 0;
	uintptr_t _vehicle    = 0;
	uintptr_t pluginFallDamageMultiplier = 0;
	uintptr_t _look       = 0;
	uintptr_t _yaw        = 0;
	uintptr_t _pitch      = 0;
	uintptr_t _animator   = 0;
	uintptr_t scopeSway   = 0;
	uintptr_t _clothing   = 0;
	uintptr_t fallingDamageMultiplier = 0;
	uintptr_t _playerID   = 0;
	uintptr_t _characterName = 0;
	uintptr_t firerate    = 0;
	uintptr_t range       = 0;
	uintptr_t spreadHip   = 0;
	uintptr_t spreadAim   = 0;
	uintptr_t aimingMovementSpeedMultiplier = 0;
	uintptr_t damageFalloffRange = 0;
	uintptr_t _speed      = 0;
	uintptr_t _fuel       = 0;
	uintptr_t _isExploded = 0;
	uintptr_t _health_vehicle = 0;
	uintptr_t vm_vehicles = 0;
	uintptr_t im_clampedItems = 0;
	uintptr_t ii_asset    = 0;
	uintptr_t ia_itemName = 0;
	uintptr_t zm_tickingZombies = 0;
	uintptr_t z_isDead    = 0;
	uintptr_t _useable    = 0;
	uintptr_t ug_isReloading  = 0;
	uintptr_t ug_reloadTime   = 0;
	uintptr_t ug_needsRechamber = 0;
	uintptr_t ll_vision   = 0;
	uintptr_t ll_fog      = 0;
	uintptr_t os_cachedVerticalFOV = 0;
	uintptr_t pm_gps      = 0;
	uintptr_t pm_compass  = 0;
	uintptr_t pl_stunDuration = 0;

	void init()
	{
		Log("Resolving offsets from classes...");
		// NOTE: field names updated for current game version (underscore prefix added to private fields)
		// _localPlayer moved from Provider to Player class; _player moved to SteamPlayer
		_player       = safe_offset(Classes::SteamPlayer, "_player");
		_localPlayer  = safe_offset(Classes::Player, "_localPlayer");
		_isConnected  = safe_offset(Classes::Provider, "_isConnected");
		isLoadingUGC  = safe_offset(Classes::Provider, "isLoadingUGC");
		_clients      = safe_offset(Classes::Provider, "_clients");
		channel       = safe_offset(Classes::Player, "_channel");      // Player._channel → SteamChannel*
		owner         = safe_offset(Classes::SteamChannel, "owner");
		_isAdmin      = safe_offset(Classes::SteamPlayer, "_isAdmin");
		_splayer      = safe_offset(Classes::SteamChannel, "owner");
		_equipment    = safe_offset(Classes::Player, "_equipment");
		_asset        = safe_offset(Classes::PlayerEquipment, "asset");
		_joined       = safe_offset(Classes::SteamPlayer, "_joined");
		recoilMin_x   = safe_offset(Classes::ItemGunAsset, "recoilMin_x");
		recoilMax_x   = safe_offset(Classes::ItemGunAsset, "recoilMax_x");
		recoilMin_y   = safe_offset(Classes::ItemGunAsset, "recoilMin_y");
		recoilMax_y   = safe_offset(Classes::ItemGunAsset, "recoilMax_y");
		baseSpreadAngleRadians = safe_offset(Classes::ItemGunAsset, "baseSpreadAngleRadians");
		_life         = safe_offset(Classes::Player, "_life");
		_health       = safe_offset(Classes::PlayerLife, "_health");
		_food         = safe_offset(Classes::PlayerLife, "_food");
		_water        = safe_offset(Classes::PlayerLife, "_water");
		_stamina      = safe_offset(Classes::PlayerLife, "_stamina");
		_virus        = safe_offset(Classes::PlayerLife, "_virus");
		_isBleeding   = safe_offset(Classes::PlayerLife, "_isBleeding");
		_isBroken     = safe_offset(Classes::PlayerLife, "_isBroken");
		_movement     = safe_offset(Classes::Player, "_movement");
		pluginGravityMultiplier  = safe_offset(Classes::PlayerMovement, "pluginGravityMultiplier");
		pluginSpeedMultiplier    = safe_offset(Classes::PlayerMovement, "pluginSpeedMultiplier");
		pluginJumpMultiplier     = safe_offset(Classes::PlayerMovement, "pluginJumpMultiplier");
		velocity      = safe_offset(Classes::PlayerMovement, "velocity");
		pendingLaunchVelocity = safe_offset(Classes::PlayerMovement, "pendingLaunchVelocity");
		_vehicle      = safe_offset(Classes::PlayerMovement, "vehicle");
		pluginFallDamageMultiplier = safe_offset(Classes::PlayerMovement, "pluginFallDamageMultiplier");
		_look         = safe_offset(Classes::Player, "_look");
		_yaw          = safe_offset(Classes::PlayerLook, "_yaw");
		_pitch        = safe_offset(Classes::PlayerLook, "_pitch");
		_animator     = safe_offset(Classes::Player, "_animator");
		scopeSway     = safe_offset(Classes::PlayerAnimator, "scopeSway");
		_clothing     = safe_offset(Classes::Player, "_clothing");
		fallingDamageMultiplier = safe_offset(Classes::PlayerClothing, "fallingDamageMultiplier");
		_playerID     = safe_offset(Classes::SteamPlayer, "_playerID");
		_characterName = safe_offset(Classes::SteamPlayerID, "_characterName");
		firerate      = safe_offset(Classes::ItemGunAsset, "firerate");
		range         = safe_offset(Classes::ItemWeaponAsset, "range");
		spreadHip     = safe_offset(Classes::ItemGunAsset, "spreadHip");
		spreadAim     = safe_offset(Classes::ItemGunAsset, "spreadAim");
		aimingMovementSpeedMultiplier = safe_offset(Classes::ItemGunAsset, "aimingMovementSpeedMultiplier");
		damageFalloffRange = safe_offset(Classes::ItemWeaponAsset, "_damageFalloffRange");
		_speed        = safe_offset(Classes::InteractableVehicle, "speed");
		_fuel         = safe_offset(Classes::InteractableVehicle, "fuel");
		_isExploded   = safe_offset(Classes::InteractableVehicle, "isExploded");
		_health_vehicle = safe_offset(Classes::InteractableVehicle, "health");
		vm_vehicles   = safe_offset(Classes::VehicleManager, "_vehicles");
		im_clampedItems = safe_offset(Classes::ItemManager, "clampedItems");
		ii_asset      = safe_offset(Classes::InteractableItem, "asset");
		ia_itemName   = safe_offset(Classes::ItemAsset_Class, "_itemName");
		zm_tickingZombies = safe_offset(Classes::ZombieManager, "_tickingZombies");
		z_isDead      = safe_offset(Classes::Zombie, "isDead");
		_useable      = safe_offset(Classes::PlayerEquipment, "_useable");
		ug_isReloading  = safe_offset(Classes::UseableGun, "isReloading");
		ug_reloadTime   = safe_offset(Classes::UseableGun, "reloadTime");
		ug_needsRechamber = safe_offset(Classes::UseableGun, "needsRechamber");
		ll_vision     = safe_offset(Classes::LevelLighting, "_vision");
		ll_fog        = safe_offset(Classes::LevelLighting, "fog");
		os_cachedVerticalFOV = safe_offset(Classes::OptionsSettings, "_cachedVerticalFOV");
		// BoCheat features
		pm_gps        = safe_offset(Classes::PlayerMovement, "gps");
		pm_compass    = safe_offset(Classes::PlayerMovement, "compass");
		pl_stunDuration = safe_offset(Classes::PlayerLife, "_stunDuration");
		Log("Offsets resolved.");
	}
}
