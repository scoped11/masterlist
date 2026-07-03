#ifndef GAME_H
#define GAME_H

#include "../unturned.h"
#include "unity.h"

// ---------------------------------------------------------------------------
// SDG namespace — mirrors the C# classes from Unturned's managed assemblies.
//
// Each class here is a C++ shadow of a Mono/.NET class inside SDG.Unturned.
// Fields are declared with FIELD_DEC / STATIC_FIELD_DEC macros (defined in
// unturned.h) which expand into getter + setter function declarations.
// The actual implementations live in game.cpp via FIELD_DEF / STATIC_FIELD_DEF.
//
// Memory layout:
//   - FIELD_DEC(T, name)        => T name();  void name_set(T val);
//     At runtime: read<T>(this + offset)  /  write<T>(val, this + offset)
//
//   - STATIC_FIELD_DEC(T, name) => static T name();  static void name_set(T);
//     At runtime: read<T>(instance() + offset)   (instance() caches the
//     MonoClass vtable's static-field-data pointer via INSTANCE_DEF)
//
//   - INSTANCE_DEF(class_name)  => provides the static instance() helper that
//     resolves the Mono class vtable once and returns the address of its
//     static field block — used by STATIC_FIELD_DEF to reach static fields.
//
//   - GAMEOBJECT_DEF(klass) (in game.cpp) wires gameObject() to walk the
//     Unity internal Component -> ObjectStore -> GameObject chain:
//       this+0x10 -> component list -> +0x30 -> GameObject*
// ---------------------------------------------------------------------------

namespace SDG
{
	// Forward declarations — every game class used across the codebase.
	class SteamPlayer;
	class SteamChannel;
	class Player;
	class Provider;
	class Equipment;
	class Asset;
	class ItemGunAsset;
	class PlayerLife;
	class PlayerMovement;
	class PlayerLook;
	class InteractableVehicle;
	class Zombie;
	class InteractableItem;

	// -----------------------------------------------------------------------
	// SteamPlayer — lobby-level wrapper around a connected player.
	// Contains the Player MonoBehaviour ref and admin flag.
	// -----------------------------------------------------------------------
	class SteamPlayer
	{
	public:
		FIELD_DEC(Player*, player);   // -> SDG.Player MonoBehaviour
		FIELD_DEC(bool, admin);       // server-side admin privilege flag
	};

	// -----------------------------------------------------------------------
	// SteamChannel — per-player networking channel.
	// owner() yields the SteamPlayer who owns this channel.
	// -----------------------------------------------------------------------
	class SteamChannel
	{
	public:
		FIELD_DEC(SteamPlayer*, owner);
	};

	// -----------------------------------------------------------------------
	// PlayerLife — health, hunger, thirst, stamina, virus, bleed/broken status.
	// All integer stats are 0-100 bytes; stunDuration is a float timer.
	// -----------------------------------------------------------------------
	class PlayerLife
	{
	public:
		FIELD_DEC(uint8_t, health);
		FIELD_DEC(uint8_t, food);
		FIELD_DEC(uint8_t, water);
		FIELD_DEC(uint8_t, stamina);
		FIELD_DEC(uint8_t, virus);
		FIELD_DEC(bool, isBleeding);
		FIELD_DEC(bool, isBroken);
		FIELD_DEC(float, stunDuration);
	};

	// -----------------------------------------------------------------------
	// PlayerMovement — physics multipliers, velocity, vehicle reference.
	// pluginGravity/Speed/Jump/FallDamageMultiplier are server-trusted floats;
	// writing to them client-side takes effect because BattlEye does not
	// validate field-level memory writes on the managed heap.
	// -----------------------------------------------------------------------
	class PlayerMovement
	{
	public:
		FIELD_DEC(float, pluginGravityMultiplier);
		FIELD_DEC(float, pluginSpeedMultiplier);
		FIELD_DEC(float, pluginJumpMultiplier);
		FIELD_DEC(vector3, velocity);
		FIELD_DEC(vector3, pendingLaunchVelocity);
		FIELD_DEC(uintptr_t, vehicle);               // InteractableVehicle* if in vehicle, else 0
		FIELD_DEC(float, pluginFallDamageMultiplier);
		FIELD_DEC(bool, gps);                         // minimap GPS unlocked
		FIELD_DEC(bool, compass);                     // compass HUD unlocked
		Unity::GameObject* gameObject();
	};

	// -----------------------------------------------------------------------
	// PlayerLook — camera yaw/pitch in Unturned convention.
	// Pitch: 90 = horizontal, 0 = straight up, 180 = straight down.
	// Yaw:   0 = north (+Z), 90 = east (+X).
	// -----------------------------------------------------------------------
	class PlayerLook
	{
	public:
		FIELD_DEC(float, yaw);
		FIELD_DEC(float, pitch);
	};

	// -----------------------------------------------------------------------
	// Player — the central MonoBehaviour; owns channel, equipment, life,
	// movement, look sub-components.  INSTANCE_DEF caches the Mono vtable
	// so static fields (player / localPlayer) can be read from the class's
	// static field data block rather than from an object instance.
	// -----------------------------------------------------------------------
	class Player
	{
		INSTANCE_DEF(Classes::Player);
	public:
		FIELD_DEC(SteamChannel*, channel);
		FIELD_DEC(Equipment*, equipment);
		FIELD_DEC(PlayerLife*, life);
		FIELD_DEC(PlayerMovement*, movement);
		FIELD_DEC(PlayerLook*, look);
		STATIC_FIELD_DEC(Player*, player);       // SDG.Player._player   (server context)
		STATIC_FIELD_DEC(Player*, localPlayer);   // SDG.Player._localPlayer (client-side)
		Unity::GameObject* gameObject();
	};

	// -----------------------------------------------------------------------
	// Provider — network session manager.
	// isConnected = currently in a server; clients = List<SteamPlayer>.
	// -----------------------------------------------------------------------
	class Provider
	{
		INSTANCE_DEF(Classes::Provider);
	public:
		STATIC_FIELD_DEC(bool, isConnected);
		STATIC_FIELD_DEC(Unity::Array<SteamPlayer*>*, clients);  // all connected players
	};

	// -----------------------------------------------------------------------
	// Equipment — currently held item.
	// asset points to the ItemAsset base; useable points to the active
	// UseableGun / UseableMelee / etc. MonoBehaviour.
	// -----------------------------------------------------------------------
	class Equipment
	{
	public:
		FIELD_DEC(Asset*, asset);
		FIELD_DEC(uintptr_t, useable);
	};

	// -----------------------------------------------------------------------
	// Asset — base class for all item definitions (empty here, acts as a
	// type-safe pointer target; cast to ItemGunAsset when the held item
	// is a firearm).
	// -----------------------------------------------------------------------
	class Asset
	{
	public:
	};

	// -----------------------------------------------------------------------
	// ItemGunAsset — firearm definition fields.
	// recoil, spread, firerate, range, damage falloff — all writable for
	// no-recoil / no-spread / rapid-fire / extended-range manipulation.
	// -----------------------------------------------------------------------
	class ItemGunAsset
	{
	public:
		FIELD_DEC(float, recoilMin_x);
		FIELD_DEC(float, recoilMax_x);
		FIELD_DEC(float, recoilMin_y);
		FIELD_DEC(float, recoilMax_y);
		FIELD_DEC(float, baseSpreadAngleRadians);
		FIELD_DEC(uint8_t, firerate);                  // ticks between shots
		FIELD_DEC(float, range);                       // max hit-scan distance
		FIELD_DEC(float, spreadHip);
		FIELD_DEC(float, spreadAim);
		FIELD_DEC(float, aimingMovementSpeedMultiplier);
		FIELD_DEC(float, damageFalloffRange);
	};

	// -----------------------------------------------------------------------
	// InteractableVehicle — in-world vehicle state.
	// -----------------------------------------------------------------------
	class InteractableVehicle
	{
	public:
		FIELD_DEC(float, speed);
		FIELD_DEC(uint16_t, fuel);
		FIELD_DEC(bool, isExploded);
		FIELD_DEC(uint16_t, health_vehicle);
		Unity::GameObject* gameObject();
	};

	// -----------------------------------------------------------------------
	// VehicleManager — singleton; static vehicles array holds every spawned
	// vehicle in the current map.
	// -----------------------------------------------------------------------
	class VehicleManager
	{
		INSTANCE_DEF(Classes::VehicleManager);
	public:
		STATIC_FIELD_DEC(Unity::Array<InteractableVehicle*>*, vehicles);
	};

	// -----------------------------------------------------------------------
	// ItemManager — singleton; clampedItems holds nearby ground items.
	// -----------------------------------------------------------------------
	class ItemManager
	{
		INSTANCE_DEF(Classes::ItemManager);
	public:
		STATIC_FIELD_DEC(Unity::Array<InteractableItem*>*, clampedItems);
	};

	// -----------------------------------------------------------------------
	// InteractableItem — a pickupable item lying on the ground.
	// -----------------------------------------------------------------------
	class InteractableItem
	{
	public:
		FIELD_DEC(uintptr_t, asset);       // -> ItemAsset for name/icon lookup
		Unity::GameObject* gameObject();
	};

	// -----------------------------------------------------------------------
	// ZombieManager — singleton; tickingZombies = all active zombies.
	// -----------------------------------------------------------------------
	class ZombieManager
	{
		INSTANCE_DEF(Classes::ZombieManager);
	public:
		STATIC_FIELD_DEC(Unity::Array<Zombie*>*, tickingZombies);
	};

	// -----------------------------------------------------------------------
	// Zombie — individual zombie; isDead filters corpses from the ESP list.
	// -----------------------------------------------------------------------
	class Zombie
	{
	public:
		FIELD_DEC(bool, isDead);
		Unity::GameObject* gameObject();
	};

	// -----------------------------------------------------------------------
	// LevelLighting — global lighting state.
	// vision: nightvision mode (writable for fullbright).
	// fog: fog enable flag (writable to remove fog).
	// -----------------------------------------------------------------------
	class LevelLighting
	{
		INSTANCE_DEF(Classes::LevelLighting);
	public:
		STATIC_FIELD_DEC(int, vision);
		STATIC_FIELD_DEC(bool, fog);
	};

	// -----------------------------------------------------------------------
	// OptionsSettings — client settings singleton.
	// cachedVerticalFOV: vertical FOV in degrees; writable for FOV changer.
	// -----------------------------------------------------------------------
	class OptionsSettings
	{
		INSTANCE_DEF(Classes::OptionsSettings);
	public:
		STATIC_FIELD_DEC(float, cachedVerticalFOV);
	};
}

#endif
