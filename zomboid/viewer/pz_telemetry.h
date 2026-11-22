#pragma once
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <mutex>
#include <fstream>
#include <sstream>

namespace Telemetry
{
	inline std::mutex g_mu;
	inline std::string g_path;
	inline std::string g_json = "{\"schema\":1,\"players\":[]}";

	inline void SetPath(const std::string& path) { g_path = path; }

	inline std::string DefaultPath()
	{
		char home[MAX_PATH] = {};
	 DWORD n = ExpandEnvironmentStringsA("%USERPROFILE%", home, MAX_PATH);
		if (n == 0 || n >= MAX_PATH) return "players.json";
		return std::string(home) + "\\Zomboid\\MasterlistLiveViewer\\telemetry\\players.json";
	}

	inline bool ReadFileToString(const std::string& path, std::string& out)
	{
		std::ifstream f(path, std::ios::binary);
		if (!f) return false;
		std::ostringstream ss;
		ss << f.rdbuf();
		out = ss.str();
		return !out.empty();
	}

	inline void ReloadFromDisk()
	{
		if (g_path.empty()) return;
		std::string fresh;
		if (!ReadFileToString(g_path, fresh)) return;
		if (fresh.find("\"players\"") == std::string::npos) return;
		std::lock_guard<std::mutex> lock(g_mu);
		g_json = std::move(fresh);
	}

	inline void LoadFixtureOnce(const std::string& fixturePath)
	{
		std::string fresh;
		if (ReadFileToString(fixturePath, fresh))
		{
			std::lock_guard<std::mutex> lock(g_mu);
			g_json = std::move(fresh);
		}
	}

	inline std::string Snapshot()
	{
		std::lock_guard<std::mutex> lock(g_mu);
		return g_json;
	}
}