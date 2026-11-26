#pragma once
#include "dma_config.h"
#include "../external/unturned.h"
#include <atomic>

namespace SpawnItems
{
	inline std::atomic<bool> pending{ false };
	inline std::atomic<uint16_t> queuedId{ 0 };
	inline std::atomic<uint8_t> queuedQty{ 1 };
	inline std::atomic<int> lastResult{ 0 };

	inline bool initDone = false;
	inline uintptr_t pi_items = 0;
	inline uintptr_t jar_id = 0;
	inline uintptr_t jar_amount = 0;

	inline void Enqueue(uint16_t id, uint8_t qty)
	{
		if (qty < 1) qty = 1;
		if (qty > 100) qty = 100;
		queuedId.store(id);
		queuedQty.store(qty);
		lastResult.store(0);
		pending.store(true);
	}

	inline void EnsureInit()
	{
		if (initDone) return;
		initDone = true;

		if (!Classes::PlayerInventory)
			Classes::PlayerInventory = mono::find_class("Assembly-CSharp", "SDG.Unturned.PlayerInventory");

		if (!Offsets::_inventory && Classes::Player)
		{
			Offsets::_inventory = safe_offset(Classes::Player, "_inventory");
			if (!Offsets::_inventory)
				Offsets::_inventory = safe_offset(Classes::Player, "inventory");
		}

		if (Classes::PlayerInventory)
		{
			pi_items = safe_offset(Classes::PlayerInventory, "items");
			if (!pi_items) pi_items = safe_offset(Classes::PlayerInventory, "_items");
			if (!pi_items) pi_items = safe_offset(Classes::PlayerInventory, "jarItems");
		}

		mono_class_t* jarClass = mono::find_class("Assembly-CSharp", "SDG.Unturned.ItemJar");
		if (jarClass)
		{
			jar_id = safe_offset(jarClass, "_id");
			if (!jar_id) jar_id = safe_offset(jarClass, "id");
			jar_amount = safe_offset(jarClass, "_amount");
			if (!jar_amount) jar_amount = safe_offset(jarClass, "amount");
			if (!jar_amount) jar_amount = safe_offset(jarClass, "quantity");
		}

		Log("[Spawn] inventory off=0x%X items off=0x%X jar id=0x%X amt=0x%X",
			(uint32_t)Offsets::_inventory, (uint32_t)pi_items,
			(uint32_t)jar_id, (uint32_t)jar_amount);
	}

	inline bool WriteJar(uintptr_t jar, uint16_t id, uint8_t qty)
	{
		if (!jar || jar < 0x10000 || !jar_id || !jar_amount) return false;
		write<uint16_t>(id, jar + jar_id);
		write<uint8_t>(qty, jar + jar_amount);
		return true;
	}

	inline bool TrySpawnInInventory(uintptr_t inv, uint16_t id, uint8_t qty)
	{
		if (!inv || inv < 0x10000 || !pi_items) return false;

		uintptr_t list = read<uintptr_t>(inv + pi_items);
		if (!list || list < 0x10000) return false;

		uintptr_t array = read<uintptr_t>(list + 0x10);
		int count = read<int>(list + 0x18);
		if (!array || array < 0x10000 || count <= 0 || count > 512) return false;

		for (int i = 0; i < count; i++)
		{
			uintptr_t jar = read<uintptr_t>(array + 0x20 + (size_t)i * 8);
			if (!jar || jar < 0x10000) continue;
			uint8_t amt = jar_amount ? read<uint8_t>(jar + jar_amount) : 0;
			uint16_t curId = jar_id ? read<uint16_t>(jar + jar_id) : 0;
			if (amt == 0 || curId == 0)
				return WriteJar(jar, id, qty);
		}

		uintptr_t jar0 = read<uintptr_t>(array + 0x20);
		return WriteJar(jar0, id, qty);
	}

	inline void Update(SDG::Player* localPlayer)
	{
		if (!pending.load(std::memory_order_acquire)) return;
		pending.store(false, std::memory_order_release);

		EnsureInit();

		if (!Config::adminMode)
			Log("[Spawn] Enable Admin Mode on multiplayer — servers may reject client inventory edits");

		if (!localPlayer || !Offsets::_inventory || !pi_items || !jar_id || !jar_amount)
		{
			lastResult.store(-1);
			return;
		}

		uintptr_t invPtr = read<uintptr_t>(reinterpret_cast<uintptr_t>(localPlayer) + Offsets::_inventory);
		uint16_t id = queuedId.load();
		uint8_t qty = queuedQty.load();

		bool ok = TrySpawnInInventory(invPtr, id, qty);
		lastResult.store(ok ? 1 : -1);
		Log("[Spawn] %s item %u x%u (DMA inventory write)",
			ok ? "OK" : "FAIL", id, qty);
	}
}