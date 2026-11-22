#pragma once
#include "pz_types.h"
#include <string>

enum class DataSource
{
	FixtureMock = 0,
	ServerTelemetryFile = 1,
	ExternalReadOnly = 2
};

namespace PzTelemetryFile
{
	bool LoadPlayersFromJsonFile(const char* path, PlayerRecord* out, int& count, int maxCount, bool& fromFixture);
	std::string DefaultServerTelemetryPath();
}