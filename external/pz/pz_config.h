#pragma once
#include <string>
#include "pz_telemetry_file.h"

enum class ViewMode
{
	Overlay = 0,
	WebRadar = 1,
	Console = 2,
	Minimal = 3,
	_COUNT
};

namespace PzConfig
{
	inline ViewMode mode = ViewMode::WebRadar;
	inline int httpPort = 8880;
	inline bool httpLan = false;
	inline bool useMock = true;
	inline std::string exeName = "ProjectZomboid64.exe";
	inline std::string moduleName = "ProjectZomboid64.exe";
	inline std::string offsetsPath = "external/pz/offsets/pz_offsets.ini";
	inline int pollMs = 250;
	inline bool showMenu = true;
	inline bool webRadarEnabled = true;
	inline bool overlayEnabled = false;
	inline bool showNames = true;
	inline bool showDistances = true;
	inline DataSource dataSource = DataSource::FixtureMock;
	inline std::string fixturePath = "zomboid/fixtures/sample_players.json";
	inline std::string telemetryPath = ""; // empty = default server mod path

	// Runtime offsets (populated from ini; 0 = unset)
	inline uint64_t onlinePlayersStatic = 0;
	inline uint64_t isoPlayer_x = 0;
	inline uint64_t isoPlayer_y = 0;
	inline uint64_t isoPlayer_z = 0;
	inline uint64_t isoPlayer_username = 0;

	bool LoadIni(const char* path);
	const char* ModeName(ViewMode m);
	ViewMode ParseMode(const char* s);
	ViewMode NextMode(ViewMode cur);
}