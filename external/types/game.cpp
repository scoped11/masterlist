#include "game.h"

namespace SDG
{
	STATIC_FIELD_DEF(Player*, Player, player, Offsets::_player);

	Player* Player::localPlayer()
	{
		if (Offsets::_localPlayer)
			return read<Player*>(instance() + Offsets::_localPlayer);
		return read<Player*>(instance() + Offsets::_player);
	}
	void Player::localPlayer_set(Player* val)
	{
		if (Offsets::_localPlayer)
			write<Player*>(val, instance() + Offsets::_localPlayer);
		else
			write<Player*>(val, instance() + Offsets::_player);
	}

	FIELD_DEF(Equipment*, Player, equipment, Offsets::_equipment);
	FIELD_DEF(SteamChannel*, Player, channel, Offsets::channel);
	FIELD_DEF(PlayerLife*, Player, life, Offsets::_life);
	FIELD_DEF(PlayerMovement*, Player, movement, Offsets::_movement);
	FIELD_DEF(PlayerLook*, Player, look, Offsets::_look);
	GAMEOBJECT_DEF(Player);

	FIELD_DEF(SteamPlayer*, SteamChannel, owner, Offsets::owner);

	FIELD_DEF(Player*, SteamPlayer, player, Offsets::_splayer);
	FIELD_DEF(bool, SteamPlayer, admin, Offsets::_isAdmin);

	STATIC_FIELD_DEF(bool, Provider, isConnected, Offsets::_isConnected);
	STATIC_FIELD_DEF(Unity::Array<SteamPlayer*>*, Provider, clients, Offsets::_clients);

	FIELD_DEF(Asset*, Equipment, asset, Offsets::_asset);
	FIELD_DEF(uintptr_t, Equipment, useable, Offsets::_useable);

	FIELD_DEF(float, ItemGunAsset, recoilMin_x, Offsets::recoilMin_x);
	FIELD_DEF(float, ItemGunAsset, recoilMax_x, Offsets::recoilMax_x);
	FIELD_DEF(float, ItemGunAsset, recoilMin_y, Offsets::recoilMin_y);
	FIELD_DEF(float, ItemGunAsset, recoilMax_y, Offsets::recoilMax_y);
	FIELD_DEF(float, ItemGunAsset, baseSpreadAngleRadians, Offsets::baseSpreadAngleRadians);
	FIELD_DEF(uint8_t, ItemGunAsset, firerate, Offsets::firerate);
	FIELD_DEF(float, ItemGunAsset, range, Offsets::range);
	FIELD_DEF(float, ItemGunAsset, spreadHip, Offsets::spreadHip);
	FIELD_DEF(float, ItemGunAsset, spreadAim, Offsets::spreadAim);
	FIELD_DEF(float, ItemGunAsset, aimingMovementSpeedMultiplier, Offsets::aimingMovementSpeedMultiplier);
	FIELD_DEF(float, ItemGunAsset, damageFalloffRange, Offsets::damageFalloffRange);

	FIELD_DEF(uint8_t, PlayerLife, health, Offsets::_health);
	FIELD_DEF(uint8_t, PlayerLife, food, Offsets::_food);
	FIELD_DEF(uint8_t, PlayerLife, water, Offsets::_water);
	FIELD_DEF(uint8_t, PlayerLife, stamina, Offsets::_stamina);
	FIELD_DEF(uint8_t, PlayerLife, virus, Offsets::_virus);
	FIELD_DEF(bool, PlayerLife, isBleeding, Offsets::_isBleeding);
	FIELD_DEF(bool, PlayerLife, isBroken, Offsets::_isBroken);

	FIELD_DEF(float, PlayerMovement, pluginGravityMultiplier, Offsets::pluginGravityMultiplier);
	FIELD_DEF(float, PlayerMovement, pluginSpeedMultiplier, Offsets::pluginSpeedMultiplier);
	FIELD_DEF(float, PlayerMovement, pluginJumpMultiplier, Offsets::pluginJumpMultiplier);
	FIELD_DEF(vector3, PlayerMovement, velocity, Offsets::velocity);
	FIELD_DEF(vector3, PlayerMovement, pendingLaunchVelocity, Offsets::pendingLaunchVelocity);
	FIELD_DEF(uintptr_t, PlayerMovement, vehicle, Offsets::_vehicle);
	FIELD_DEF(float, PlayerMovement, pluginFallDamageMultiplier, Offsets::pluginFallDamageMultiplier);
	FIELD_DEF(bool, PlayerMovement, isGrounded, Offsets::_isGrounded);
	FIELD_DEF(float, PlayerMovement, totalSpeedMultiplier, Offsets::totalSpeedMultiplier);
	FIELD_DEF(float, PlayerMovement, totalGravityMultiplier, Offsets::totalGravityMultiplier);
	GAMEOBJECT_DEF(PlayerMovement);

	FIELD_DEF(float, PlayerLook, yaw, Offsets::_yaw);
	FIELD_DEF(float, PlayerLook, pitch, Offsets::_pitch);

	FIELD_DEF(float, InteractableVehicle, speed, Offsets::_speed);
	FIELD_DEF(uint16_t, InteractableVehicle, fuel, Offsets::_fuel);
	FIELD_DEF(bool, InteractableVehicle, isExploded, Offsets::_isExploded);
	FIELD_DEF(uint16_t, InteractableVehicle, health_vehicle, Offsets::_health_vehicle);
	GAMEOBJECT_DEF(InteractableVehicle);

	STATIC_FIELD_DEF(Unity::Array<InteractableVehicle*>*, VehicleManager, vehicles, Offsets::vm_vehicles);

	STATIC_FIELD_DEF(Unity::Array<InteractableItem*>*, ItemManager, clampedItems, Offsets::im_clampedItems);

	FIELD_DEF(uintptr_t, InteractableItem, asset, Offsets::ii_asset);
	GAMEOBJECT_DEF(InteractableItem);

	STATIC_FIELD_DEF(Unity::Array<Zombie*>*, ZombieManager, tickingZombies, Offsets::zm_tickingZombies);
	STATIC_FIELD_DEF(uintptr_t, ZombieManager, zombies, Offsets::zm_zombies);
	STATIC_FIELD_DEF(uintptr_t, ZombieManager, regions, Offsets::zm_regions);

	FIELD_DEF(bool, Zombie, isDead, Offsets::z_isDead);
	GAMEOBJECT_DEF(Zombie);

	STATIC_FIELD_DEF(int, LevelLighting, vision, Offsets::ll_vision);

	STATIC_FIELD_DEF(float, OptionsSettings, cachedVerticalFOV, Offsets::os_cachedVerticalFOV);
}
