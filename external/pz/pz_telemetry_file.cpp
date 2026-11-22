#include "pz_telemetry_file.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

std::string PzTelemetryFile::DefaultServerTelemetryPath()
{
	char home[MAX_PATH] = {};
	if (ExpandEnvironmentStringsA("%USERPROFILE%", home, MAX_PATH) == 0)
		return "";
	return std::string(home) + "\\Zomboid\\MasterlistLiveViewer\\telemetry\\players.json";
}

static void ResetOut(PlayerRecord* out, int maxCount, int& count)
{
	count = 0;
	for (int i = 0; i < maxCount; i++) out[i].valid = false;
}

bool PzTelemetryFile::LoadPlayersFromJsonFile(const char* path, PlayerRecord* out, int& count, int maxCount, bool& fromFixture)
{
	fromFixture = false;
	ResetOut(out, maxCount, count);
	if (!path || !path[0]) return false;

	std::ifstream f(path, std::ios::binary);
	if (!f) return false;
	std::ostringstream ss;
	ss << f.rdbuf();
	std::string json = ss.str();
	if (json.find("\"players\"") == std::string::npos) return false;

	if (json.find("\"fixture\"") != std::string::npos || json.find("\"source\":\"fixture\"") != std::string::npos)
		fromFixture = true;

	const char* p = json.c_str();
	int idx = 0;
	while (idx < maxCount)
	{
		const char* u = strstr(p, "\"username\"");
		if (!u) break;
		const char* q1 = strchr(u, '"');
		if (!q1) break;
		q1 = strchr(q1 + 1, '"');
		if (!q1) break;
		q1++;
		const char* q2 = strchr(q1, '"');
		if (!q2) break;

		double x = 0, y = 0, z = 0;
		const char* xp = strstr(u, "\"x\"");
		const char* yp = strstr(u, "\"y\"");
		const char* zp = strstr(u, "\"z\"");
		if (xp) sscanf_s(xp, "\"x\":%lf", &x);
		if (yp) sscanf_s(yp, "\"y\":%lf", &y);
		if (zp) sscanf_s(zp, "\"z\":%lf", &z);

		PlayerRecord& rec = out[idx];
		memset(&rec, 0, sizeof(rec));
		size_t len = (size_t)(q2 - q1);
		if (len >= sizeof(rec.name)) len = sizeof(rec.name) - 1;
		memcpy(rec.name, q1, len);
		rec.name[len] = 0;
		rec.pos = { (float)x, (float)y, (float)z };
		rec.valid = true;
		rec.health = 100.f;
		idx++;
		p = q2 + 1;
	}
	count = idx;
	return count > 0;
}