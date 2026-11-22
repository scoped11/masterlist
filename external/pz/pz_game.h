#pragma once
#include "pz_types.h"
#include <mutex>
#include <atomic>
#include <cstdint>

namespace PzGame
{
	inline PlayerRecord players[kMaxPlayers];
	inline int playerCount = 0;
	inline Vec3 localPos{};
	inline std::mutex stateMu;
	inline std::atomic<bool> usingMock{ true };
	inline std::atomic<bool> offsetsReady{ false };

	void ResetPlayers();
	bool Update(); // returns true if snapshot changed materially
	const char* BuildPlayersJson(char* buf, size_t cap);
}