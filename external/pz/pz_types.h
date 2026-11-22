#pragma once
#include <cstdint>
#include <cstring>
#include <cmath>

struct Vec3
{
	float x = 0, y = 0, z = 0;
};

struct PlayerRecord
{
	char name[64];
	Vec3 pos;
	float health = 100.f;
	bool valid = false;
	bool isLocal = false;
};

inline constexpr int kMaxPlayers = 64;