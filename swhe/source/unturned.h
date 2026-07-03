// ============================================================================
// unturned.h -- Unturned Game Class Definitions and Offset Resolution
// ============================================================================
//
// This header defines the interface between the cheat and Unturned's game
// objects. Unturned is a Unity game built with C# (Mono runtime), and all
// game classes live under the SDG namespace (Smartly Dressed Games, the
// developer).
//
// The file is organized into three sections:
//
//   1. MACROS -- field accessor generation and static instance helpers
//   2. Classes namespace -- mono_class_t* pointers resolved at runtime via
//      Mono reflection. These point to the in-memory class metadata for each
//      game class (Player, PlayerLife, InteractableVehicle, etc.)
//   3. Offsets namespace -- field offsets within each class, also resolved at
//      runtime. These are the byte offsets used to read/write specific fields
//      (health, position, speed, etc.) from game object instances.
//
// At startup:
//   Classes::init() uses mono::find_class() to locate each class in the
//   "Assembly-CSharp" assembly by its fully-qualified SDG.Unturned.* name.
//   Offsets::init() then uses safe_offset() to look up each field by name
//   within the resolved class, extracting its byte offset from the Mono
//   metadata. This makes the cheat resilient to game updates -- offsets are
//   discovered dynamically rather than hardcoded.
//
// ============================================================================

#ifndef UNTURNED_H
#define UNTURNED_H

#include "mono.h"

// Shorthand for casting `this` to a raw address for field reads.
#define THISPTR reinterpret_cast<uintptr_t>(this)

// ── Field accessor macros ─────────────────────────────────────────────────
// FIELD_DEF / FIELD_DEC: generates a getter and setter for an instance field.
// The getter reads<T> at (this + offset), the setter writes<T> at the same.
// FIELD_DEC goes in the struct declaration, FIELD_DEF goes in the .cpp file.
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

// STATIC_FIELD_DEF / STATIC_FIELD_DEC: same as above but for static fields.
// Instead of (this + offset), reads from (instance() + offset) where
// instance() returns the class's static field data block from the vtable.
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

// INSTANCE_DEF: generates a static instance() method that retrieves the
// static field data pointer for a class. This is how we access C# static
// fields like Provider._clients -- the vtable's static field data block
// contains all static field values for the class.
#define INSTANCE_DEF(class_name) \
    static inline uintptr_t instance() { \
        static uintptr_t inst = 0; \
		if (!inst) { \
			inst = class_name->get_vtable(mono::get_root_domain())->get_static_field_data(); \
		} \
        return inst; \
    }

// GAMEOBJECT_DEF: generates a gameObject() accessor that follows the
// Unity Component -> Transform -> GameObject chain at known offsets.
#define GAMEOBJECT_DEF(klass) \
    Unity::GameObject* klass::gameObject() { \
        return (Unity::GameObject*)read<uintptr_t>( \
            read<uintptr_t>(THISPTR + 0x10) + 0x30); \
    }


// ============================================================================
// Classes namespace
// ============================================================================
// Each pointer here is resolved at runtime by Classes::init() via
// mono::find_class("Assembly-CSharp", "SDG.Unturned.<ClassName>").
// They represent the Mono metadata for each game class and are used
// for field offset lookups and vtable access.
namespace Classes
{
	extern mono_class_t* Provider;           // Server/client connection state, player list
	extern mono_class_t* Player;             // The main player component (owns Life, Movement, etc.)
	extern mono_class_t* SteamChannel;       // Network channel per player
	extern mono_class_t* SteamPlayer;        // Player identity + network state

	extern mono_class_t* PlayerEquipment;    // Currently held item/weapon
	extern mono_class_t* ItemAsset;          // Base class for all item data
	extern mono_class_t* ItemWeaponAsset;    // Weapon-specific item data (range, damage falloff)
	extern mono_class_t* ItemGunAsset;       // Gun-specific item data (recoil, spread, firerate)

	extern mono_class_t* PlayerLife;         // Health, food, water, stamina, bleeding, etc.
	extern mono_class_t* PlayerMovement;     // Position, velocity, speed/gravity multipliers
	extern mono_class_t* PlayerLook;         // Camera yaw/pitch
	extern mono_class_t* PlayerAnimator;     // Animation state, scope sway
	extern mono_class_t* PlayerClothing;     // Equipped clothing items
	extern mono_class_t* InteractableVehicle;// Vehicle instances (speed, fuel, health)
	extern mono_class_t* SteamPlayerID;      // Steam identity (character name, Steam64 ID)
	extern mono_class_t* VehicleManager;     // Global vehicle list
	extern mono_class_t* ItemManager;        // Ground item tracking
	extern mono_class_t* InteractableItem;   // Dropped item instances
	extern mono_class_t* ZombieManager;      // Global zombie list
	extern mono_class_t* Zombie;             // Individual zombie state
	extern mono_class_t* LevelLighting;      // Time of day, fog, night vision
	extern mono_class_t* UseableGun;         // Active gun state (reloading, rechambering)
	extern mono_class_t* ItemAsset_Class;    // ItemAsset for item name lookups
	extern mono_class_t* OptionsSettings;    // Game settings (FOV, etc.)

	void init();
}

// ============================================================================
// Offsets namespace
// ============================================================================
// Each value here is a byte offset within the corresponding class's
// instances, resolved dynamically by Offsets::init() using Mono reflection.
// Example: Offsets::_health is the offset of PlayerLife._health, so
// read<byte>(playerLife + Offsets::_health) gives the player's HP.
namespace Offsets
{
	// Player / SteamPlayer core
	extern uintptr_t _player;        // SteamPlayer._player -> Player*
	extern uintptr_t _localPlayer;   // Player._localPlayer (static) -> local Player*

	// Provider (connection state)
	extern uintptr_t _isConnected;   // Provider._isConnected (static bool)
	extern uintptr_t isLoadingUGC;   // Provider.isLoadingUGC (workshop loading flag)
	extern uintptr_t _clients;       // Provider._clients (static List<SteamPlayer>)

	// Player -> SteamChannel -> SteamPlayer chain
	extern uintptr_t channel;        // Player._channel -> SteamChannel*
	extern uintptr_t owner;          // SteamChannel.owner -> SteamPlayer*

	extern uintptr_t _isAdmin;       // SteamPlayer._isAdmin
	extern uintptr_t _splayer;       // alias for SteamChannel.owner

	// PlayerEquipment
	extern uintptr_t _equipment;     // Player._equipment -> PlayerEquipment*
	extern uintptr_t _asset;         // PlayerEquipment.asset -> ItemAsset*
	extern uintptr_t _joined;        // SteamPlayer._joined (join timestamp)

	// ItemGunAsset -- recoil and spread parameters
	extern uintptr_t recoilMin_x;
	extern uintptr_t recoilMax_x;
	extern uintptr_t recoilMin_y;
	extern uintptr_t recoilMax_y;
	extern uintptr_t baseSpreadAngleRadians;

	// PlayerLife -- vitals
	extern uintptr_t _life;          // Player._life -> PlayerLife*
	extern uintptr_t _health;        // PlayerLife._health (byte, 0-100)
	extern uintptr_t _food;          // PlayerLife._food (byte)
	extern uintptr_t _water;         // PlayerLife._water (byte)
	extern uintptr_t _stamina;       // PlayerLife._stamina (byte)
	extern uintptr_t _virus;         // PlayerLife._virus (byte, infection)
	extern uintptr_t _isBleeding;    // PlayerLife._isBleeding (bool)
	extern uintptr_t _isBroken;      // PlayerLife._isBroken (bool)

	// PlayerMovement -- physics multipliers and state
	extern uintptr_t _movement;      // Player._movement -> PlayerMovement*
	extern uintptr_t pluginGravityMultiplier;  // server-side gravity scale
	extern uintptr_t pluginSpeedMultiplier;    // server-side speed scale
	extern uintptr_t pluginJumpMultiplier;     // server-side jump scale
	extern uintptr_t velocity;                 // current velocity vector
	extern uintptr_t pendingLaunchVelocity;    // queued launch impulse
	extern uintptr_t _vehicle;                 // currently occupied vehicle
	extern uintptr_t pluginFallDamageMultiplier;

	// PlayerLook -- camera angles
	extern uintptr_t _look;          // Player._look -> PlayerLook*
	extern uintptr_t _yaw;           // PlayerLook._yaw (float, degrees)
	extern uintptr_t _pitch;         // PlayerLook._pitch (float, degrees)

	// PlayerAnimator
	extern uintptr_t _animator;      // Player._animator -> PlayerAnimator*
	extern uintptr_t scopeSway;      // PlayerAnimator.scopeSway (float)

	// PlayerClothing
	extern uintptr_t _clothing;      // Player._clothing -> PlayerClothing*
	extern uintptr_t fallingDamageMultiplier;

	// SteamPlayer / SteamPlayerID -- identity
	extern uintptr_t _playerID;      // SteamPlayer._playerID -> SteamPlayerID
	extern uintptr_t _characterName; // SteamPlayerID._characterName (System.String*)

	// ItemGunAsset -- weapon stats
	extern uintptr_t firerate;
	extern uintptr_t range;
	extern uintptr_t spreadHip;
	extern uintptr_t spreadAim;
	extern uintptr_t aimingMovementSpeedMultiplier;
	extern uintptr_t damageFalloffRange;

	// InteractableVehicle
	extern uintptr_t _speed;         // current speed (float)
	extern uintptr_t _fuel;          // fuel level (ushort)
	extern uintptr_t _isExploded;    // destroyed flag (bool)
	extern uintptr_t _health_vehicle;// vehicle HP (ushort)

	// VehicleManager (static)
	extern uintptr_t vm_vehicles;    // VehicleManager._vehicles (List<InteractableVehicle>)

	// ItemManager (static)
	extern uintptr_t im_clampedItems;// ItemManager.clampedItems (ground items)

	// InteractableItem
	extern uintptr_t ii_asset;       // InteractableItem.asset -> ItemAsset*

	// ItemAsset
	extern uintptr_t ia_itemName;    // ItemAsset._itemName (System.String*)

	// ZombieManager (static)
	extern uintptr_t zm_tickingZombies; // ZombieManager._tickingZombies (List<Zombie>)

	// Zombie
	extern uintptr_t z_isDead;       // Zombie.isDead (bool)

	// PlayerEquipment useable
	extern uintptr_t _useable;       // PlayerEquipment._useable -> Useable*

	// UseableGun -- reload state
	extern uintptr_t ug_isReloading;   // UseableGun.isReloading (bool)
	extern uintptr_t ug_reloadTime;    // UseableGun.reloadTime (float)
	extern uintptr_t ug_needsRechamber;// UseableGun.needsRechamber (bool)

	// LevelLighting (static)
	extern uintptr_t ll_vision;      // LevelLighting._vision (night vision color)
	extern uintptr_t ll_fog;         // LevelLighting.fog (fog intensity)

	// OptionsSettings (static)
	extern uintptr_t os_cachedVerticalFOV; // OptionsSettings._cachedVerticalFOV (float)

	// BoCheat features (additional exploits)
	extern uintptr_t pm_gps;         // PlayerMovement.gps (always-on GPS)
	extern uintptr_t pm_compass;     // PlayerMovement.compass (always-on compass)
	extern uintptr_t pl_stunDuration;// PlayerLife._stunDuration (stun effect timer)

	void init();
}

// ── safe_offset / safe_offset_recursive ───────────────────────────────────
// Wrappers around mono_class_t::find_field() that return 0 on failure
// instead of crashing. Used by Offsets::init() for every field lookup.

inline uintptr_t safe_offset(mono_class_t* klass, const char* name)
{
	if (!klass) return 0;
	auto field = klass->find_field(name);
	return field ? field->offset() : 0;
}

// Same as safe_offset but walks the class hierarchy (base classes).
inline uintptr_t safe_offset_recursive(mono_class_t* klass, const char* name)
{
	if (!klass) return 0;
	auto field = klass->find_field_recursive(name);
	return field ? field->offset() : 0;
}

// ── ReadManagedString / ReadManagedStringA ─────────────────────────────────
// Reads a .NET System.String object from the target process.
// System.String memory layout (64-bit Mono):
//   +0x00  object header (vtable ptr, sync block)
//   +0x10  int m_stringLength   -- number of UTF-16 code units
//   +0x14  char[] m_firstChar   -- inline UTF-16 character data
// ReadManagedString returns the wide string (wchar_t).
// ReadManagedStringA converts to narrow ASCII (lossy for non-ASCII chars).

inline std::wstring ReadManagedString(uintptr_t addr)
{
	if (!addr) return L"";
	int len = read<int>(addr + 0x10);          // m_stringLength
	if (len <= 0 || len > 256) return L"";
	auto buf = std::make_unique<wchar_t[]>(len + 1);
	read_buffer(addr + 0x14, buf.get(), len * sizeof(wchar_t)); // m_firstChar[]
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
