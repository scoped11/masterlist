#include "pz_config.h"
#include "pz_log.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <cstdlib>

namespace
{
	static void Trim(std::string& s)
	{
		while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ')) s.pop_back();
		size_t i = 0;
		while (i < s.size() && s[i] == ' ') i++;
		s = s.substr(i);
	}

	static uint64_t ParseHex(const std::string& v)
	{
		if (v.empty()) return 0;
		return strtoull(v.c_str(), nullptr, 0);
	}
}

const char* PzConfig::ModeName(ViewMode m)
{
	switch (m)
	{
	case ViewMode::Overlay: return "overlay";
	case ViewMode::WebRadar: return "web_radar";
	case ViewMode::Console: return "console";
	case ViewMode::Minimal: return "minimal";
	default: return "?";
	}
}

ViewMode PzConfig::ParseMode(const char* s)
{
	if (!s) return ViewMode::WebRadar;
	if (_stricmp(s, "overlay") == 0) return ViewMode::Overlay;
	if (_stricmp(s, "web_radar") == 0) return ViewMode::WebRadar;
	if (_stricmp(s, "console") == 0) return ViewMode::Console;
	if (_stricmp(s, "minimal") == 0) return ViewMode::Minimal;
	return ViewMode::WebRadar;
}

ViewMode PzConfig::NextMode(ViewMode cur)
{
	int n = (static_cast<int>(cur) + 1) % static_cast<int>(ViewMode::_COUNT);
	return static_cast<ViewMode>(n);
}

bool PzConfig::LoadIni(const char* path)
{
	std::ifstream f(path);
	if (!f)
	{
		PZ_LOG("config not found (%s), using defaults", path);
		return false;
	}
	std::string line, section;
	while (std::getline(f, line))
	{
		Trim(line);
		if (line.empty() || line[0] == '#' || line[0] == ';') continue;
		if (line[0] == '[' && line.back() == ']')
		{
			section = line.substr(1, line.size() - 2);
			continue;
		}
		size_t eq = line.find('=');
		if (eq == std::string::npos) continue;
		std::string key = line.substr(0, eq);
		std::string val = line.substr(eq + 1);
		Trim(key); Trim(val);

		if (section == "viewer" || section.empty())
		{
			if (_stricmp(key.c_str(), "mode") == 0) mode = ParseMode(val.c_str());
			else if (_stricmp(key.c_str(), "http_port") == 0) httpPort = atoi(val.c_str());
			else if (_stricmp(key.c_str(), "http_lan") == 0) httpLan = (val == "1" || _stricmp(val.c_str(), "true") == 0);
			else if (_stricmp(key.c_str(), "mock") == 0) useMock = (val == "1" || _stricmp(val.c_str(), "true") == 0);
			else if (_stricmp(key.c_str(), "poll_ms") == 0) pollMs = atoi(val.c_str());
			else if (_stricmp(key.c_str(), "exe") == 0) exeName = val;
			else if (_stricmp(key.c_str(), "module") == 0) moduleName = val;
			else if (_stricmp(key.c_str(), "offsets") == 0) offsetsPath = val;
			else if (_stricmp(key.c_str(), "show_menu") == 0) showMenu = (val == "1" || _stricmp(val.c_str(), "true") == 0);
			else if (_stricmp(key.c_str(), "web_radar") == 0) webRadarEnabled = (val == "1" || _stricmp(val.c_str(), "true") == 0);
			else if (_stricmp(key.c_str(), "overlay") == 0) overlayEnabled = (val == "1" || _stricmp(val.c_str(), "true") == 0);
			else if (_stricmp(key.c_str(), "show_names") == 0) showNames = (val == "1" || _stricmp(val.c_str(), "true") == 0);
			else if (_stricmp(key.c_str(), "show_distances") == 0) showDistances = (val == "1" || _stricmp(val.c_str(), "true") == 0);
			else if (_stricmp(key.c_str(), "fixture_path") == 0) fixturePath = val;
			else if (_stricmp(key.c_str(), "telemetry_path") == 0) telemetryPath = val;
			else if (_stricmp(key.c_str(), "data_source") == 0)
			{
				if (_stricmp(val.c_str(), "fixture") == 0) dataSource = DataSource::FixtureMock;
				else if (_stricmp(val.c_str(), "telemetry") == 0) dataSource = DataSource::ServerTelemetryFile;
				else if (_stricmp(val.c_str(), "external") == 0) dataSource = DataSource::ExternalReadOnly;
			}
		}
		else if (section == "offsets")
		{
			if (_stricmp(key.c_str(), "OnlinePlayersStatic") == 0) onlinePlayersStatic = ParseHex(val);
			else if (_stricmp(key.c_str(), "IsoPlayer_x") == 0) isoPlayer_x = ParseHex(val);
			else if (_stricmp(key.c_str(), "IsoPlayer_y") == 0) isoPlayer_y = ParseHex(val);
			else if (_stricmp(key.c_str(), "IsoPlayer_z") == 0) isoPlayer_z = ParseHex(val);
			else if (_stricmp(key.c_str(), "IsoPlayer_username") == 0) isoPlayer_username = ParseHex(val);
		}
	}
	PZ_LOG("config loaded: mode=%s port=%d mock=%d", ModeName(mode), httpPort, useMock ? 1 : 0);
	return true;
}