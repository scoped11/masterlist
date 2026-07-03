#ifndef UNTURNED_H
#define UNTURNED_H

#include "mono.h"

#define THISPTR reinterpret_cast<uintptr_t>(this)

#define FIELD_DEF(return_type, klass, name, offset, ...) \
    return_type klass::name() { \
        return read<return_type>(THISPTR + offset); \
    } \
	void klass::name##_set(return_type val) { \
		return write<return_type>(val, THISPTR + offset); \
	}

#define FIELD_DEC(return_type, name) \
    return_type name(); \
	void name##_set(return_type val);

#define STATIC_FIELD_DEF(return_type, klass, name, offset, ...) \
    return_type klass::name() { \
        return read<return_type>(instance() + offset); \
    } \
	void klass::name##_set(return_type val) { \
		return write<return_type>(val, instance() + offset); \
	}

#define STATIC_FIELD_DEC(return_type, name) \
    static return_type name(); \
	static void name##_set(return_type val);

#define INSTANCE_DEF(class_name) \
    static inline uintptr_t instance() { \
        static uintptr_t inst = 0; \
		if (!inst) { \
			inst = class_name->get_vtable(mono::get_root_domain())->get_static_field_data(); \
		} \
        return inst; \
    }

#define GAMEOBJECT_DEF(klass) \
    Unity::GameObject* klass::gameObject() { \
        return (Unity::GameObject*)read<uintptr_t>( \
            read<uintptr_t>(THISPTR + 0x10) + 0x30); \
    }


namespace Classes
{
	extern mono_class_t* Provider;
	extern mono_class_t* Player;
	extern mono_class_t* SteamChannel;
	extern mono_class_t* SteamPlayer;

	extern mono_class_t* PlayerEquipment;
	extern mono_class_t* ItemAsset;
	extern mono_class_t* ItemWeaponAsset;
	extern mono_class_t* ItemGunAsset;

	extern mono_class_t* PlayerLife;
	extern mono_class_t* PlayerMovement;
	extern mono_class_t* PlayerLook;
	extern mono_class_t* PlayerAnimator;
	extern mono_class_t* PlayerClothing;
	extern mono_class_t* InteractableVehicle;
	extern mono_class_t* SteamPlayerID;
	extern mono_class_t* VehicleManager;
	extern mono_class_t* ItemManager;
	extern mono_class_t* InteractableItem;
	extern mono_class_t* ZombieManager;
	extern mono_class_t* ZombieRegion;
	extern mono_class_t* Zombie;
	extern mono_class_t* LevelLighting;
	extern mono_class_t* UseableGun;
	extern mono_class_t* ItemAsset_Class;
	extern mono_class_t* OptionsSettings;

	void init();
}

namespace Offsets
{
	extern uintptr_t _player;
	extern uintptr_t _localPlayer;

	extern uintptr_t _isConnected;
	extern uintptr_t isLoadingUGC;
	extern uintptr_t _clients;

	extern uintptr_t channel;
	extern uintptr_t owner;

	extern uintptr_t _isAdmin;
	extern uintptr_t _splayer;

	extern uintptr_t _equipment;
	extern uintptr_t _asset;
	extern uintptr_t _joined;

	extern uintptr_t recoilMin_x;
	extern uintptr_t recoilMax_x;
	extern uintptr_t recoilMin_y;
	extern uintptr_t recoilMax_y;
	extern uintptr_t baseSpreadAngleRadians;

	extern uintptr_t _life;
	extern uintptr_t _health;
	extern uintptr_t _food;
	extern uintptr_t _water;
	extern uintptr_t _stamina;
	extern uintptr_t _virus;
	extern uintptr_t _isBleeding;
	extern uintptr_t _isBroken;

	extern uintptr_t _movement;
	extern uintptr_t pluginGravityMultiplier;
	extern uintptr_t pluginSpeedMultiplier;
	extern uintptr_t pluginJumpMultiplier;
	extern uintptr_t velocity;
	extern uintptr_t pendingLaunchVelocity;
	extern uintptr_t _vehicle;
	extern uintptr_t pluginFallDamageMultiplier;
	extern uintptr_t _isGrounded;
	extern uintptr_t totalSpeedMultiplier;
	extern uintptr_t totalGravityMultiplier;

	extern uintptr_t _look;
	extern uintptr_t _yaw;
	extern uintptr_t _pitch;
	extern uintptr_t flinchLocalRotation;
	extern uintptr_t smoothedExplosionLocalRotation;

	extern uintptr_t _animator;
	extern uintptr_t scopeSway;

	extern uintptr_t _clothing;
	extern uintptr_t fallingDamageMultiplier;

	extern uintptr_t _playerID;
	extern uintptr_t _characterName;

	extern uintptr_t firerate;
	extern uintptr_t range;
	extern uintptr_t spreadHip;
	extern uintptr_t spreadAim;
	extern uintptr_t aimingMovementSpeedMultiplier;
	extern uintptr_t damageFalloffRange;

	extern uintptr_t _speed;
	extern uintptr_t _fuel;
	extern uintptr_t _isExploded;
	extern uintptr_t _health_vehicle;

	extern uintptr_t vm_vehicles;
	extern uintptr_t im_clampedItems;
	extern uintptr_t ii_asset;
	extern uintptr_t ia_itemName;
	extern uintptr_t zm_tickingZombies;
	extern uintptr_t zm_zombies;
	extern uintptr_t zm_regions;
	extern uintptr_t zr_zombies;
	extern uintptr_t z_isDead;
	extern uintptr_t _useable;
	extern uintptr_t ug_isReloading;
	extern uintptr_t ug_reloadTime;
	extern uintptr_t ug_needsRechamber;
	extern uintptr_t ll_vision;
	extern uintptr_t os_cachedVerticalFOV;

	extern uintptr_t pm_controller;
	extern uintptr_t pm_gps;
	extern uintptr_t pm_compass;
	extern uintptr_t pl_stunDuration;

	void init();
}

inline uintptr_t safe_offset(mono_class_t* klass, const char* name)
{
	if (!klass) return 0;
	auto field = klass->find_field(name);
	return field ? field->offset() : 0;
}

inline uintptr_t safe_offset_recursive(mono_class_t* klass, const char* name)
{
	if (!klass) return 0;
	auto field = klass->find_field_recursive(name);
	return field ? field->offset() : 0;
}

#ifndef DMA_BUILD
inline std::wstring ReadManagedString(uintptr_t addr)
{
	if (!addr) return L"";
	int len = read<int>(addr + 0x10);
	if (len <= 0 || len > 256) return L"";
	auto buf = std::make_unique<wchar_t[]>(len + 1);
	read_buffer(addr + 0x14, buf.get(), len * sizeof(wchar_t));
	buf[len] = 0;
	return std::wstring(buf.get(), len);
}

inline std::string ReadManagedStringA(uintptr_t addr)
{
	auto ws = ReadManagedString(addr);
	if (ws.empty()) return "";
	std::string result;
	result.reserve(ws.size());
	for (auto c : ws)
		result += (char)c;
	return result;
}
#endif

#endif
