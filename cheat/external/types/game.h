#ifndef GAME_H
#define GAME_H

#include "../unturned.h"
#include "unity.h"

namespace SDG
{
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

	class SteamPlayer
	{
	public:
		FIELD_DEC(Player*, player);
		FIELD_DEC(bool, admin);
	};

	class SteamChannel
	{
	public:
		FIELD_DEC(SteamPlayer*, owner);
	};

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

	class PlayerMovement
	{
	public:
		FIELD_DEC(float, pluginGravityMultiplier);
		FIELD_DEC(float, pluginSpeedMultiplier);
		FIELD_DEC(float, pluginJumpMultiplier);
		FIELD_DEC(vector3, velocity);
		FIELD_DEC(vector3, pendingLaunchVelocity);
		FIELD_DEC(uintptr_t, vehicle);
		FIELD_DEC(float, pluginFallDamageMultiplier);
		FIELD_DEC(bool, gps);
		FIELD_DEC(bool, compass);
		Unity::GameObject* gameObject();
	};

	class PlayerLook
	{
	public:
		FIELD_DEC(float, yaw);
		FIELD_DEC(float, pitch);
	};

	class Player
	{
		INSTANCE_DEF(Classes::Player);
	public:
		FIELD_DEC(SteamChannel*, channel);
		FIELD_DEC(Equipment*, equipment);
		FIELD_DEC(PlayerLife*, life);
		FIELD_DEC(PlayerMovement*, movement);
		FIELD_DEC(PlayerLook*, look);
		STATIC_FIELD_DEC(Player*, player);
		STATIC_FIELD_DEC(Player*, localPlayer);
		Unity::GameObject* gameObject();
	};

	class Provider
	{
		INSTANCE_DEF(Classes::Provider);
	public:
		STATIC_FIELD_DEC(bool, isConnected);
		STATIC_FIELD_DEC(Unity::Array<SteamPlayer*>*, clients);
	};

	class Equipment
	{
	public:
		FIELD_DEC(Asset*, asset);
		FIELD_DEC(uintptr_t, useable);
	};

	class Asset
	{
	public:
	};

	class ItemGunAsset
	{
	public:
		FIELD_DEC(float, recoilMin_x);
		FIELD_DEC(float, recoilMax_x);
		FIELD_DEC(float, recoilMin_y);
		FIELD_DEC(float, recoilMax_y);
		FIELD_DEC(float, baseSpreadAngleRadians);
		FIELD_DEC(uint8_t, firerate);
		FIELD_DEC(float, range);
		FIELD_DEC(float, spreadHip);
		FIELD_DEC(float, spreadAim);
		FIELD_DEC(float, aimingMovementSpeedMultiplier);
		FIELD_DEC(float, damageFalloffRange);
	};

	class InteractableVehicle
	{
	public:
		FIELD_DEC(float, speed);
		FIELD_DEC(uint16_t, fuel);
		FIELD_DEC(bool, isExploded);
		FIELD_DEC(uint16_t, health_vehicle);
		Unity::GameObject* gameObject();
	};

	class VehicleManager
	{
		INSTANCE_DEF(Classes::VehicleManager);
	public:
		STATIC_FIELD_DEC(Unity::Array<InteractableVehicle*>*, vehicles);
	};

	class ItemManager
	{
		INSTANCE_DEF(Classes::ItemManager);
	public:
		STATIC_FIELD_DEC(Unity::Array<InteractableItem*>*, clampedItems);
	};

	class InteractableItem
	{
	public:
		FIELD_DEC(uintptr_t, asset);
		Unity::GameObject* gameObject();
	};

	class ZombieManager
	{
		INSTANCE_DEF(Classes::ZombieManager);
	public:
		STATIC_FIELD_DEC(Unity::Array<Zombie*>*, tickingZombies);
	};

	class Zombie
	{
	public:
		FIELD_DEC(bool, isDead);
		Unity::GameObject* gameObject();
	};

	class LevelLighting
	{
		INSTANCE_DEF(Classes::LevelLighting);
	public:
		STATIC_FIELD_DEC(int, vision);
		STATIC_FIELD_DEC(bool, fog);
	};

	class OptionsSettings
	{
		INSTANCE_DEF(Classes::OptionsSettings);
	public:
		STATIC_FIELD_DEC(float, cachedVerticalFOV);
	};
}

#endif
