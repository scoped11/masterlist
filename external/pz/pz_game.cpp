#include "pz_game.h"
#include "pz_config.h"
#include "pz_mem.h"
#include "pz_log.h"
#include "pz_telemetry_file.h"
#include <cmath>
#include <cstdio>
#include <cstring>

namespace
{
	inline void SetPlayer(int idx, const char* name, float x, float y, float z, bool local = false)
	{
		if (idx < 0 || idx >= kMaxPlayers) return;
		PlayerRecord& p = PzGame::players[idx];
		memset(&p, 0, sizeof(p));
		strncpy_s(p.name, name, _TRUNCATE);
		p.pos = { x, y, z };
		p.valid = true;
		p.isLocal = local;
		p.health = 100.f;
	}

	void MockSnapshot()
	{
		static float t = 0.f;
		t += 0.05f;
		PzGame::ResetPlayers();
		SetPlayer(0, "You (mock)", 10800.f + sinf(t) * 40.f, 9400.f, 0.f, true);
		SetPlayer(1, "Ally (mock)", 10880.f, 9450.f + cosf(t) * 30.f, 0.f);
		SetPlayer(2, "Ally2 (mock)", 10740.f + cosf(t) * 20.f, 9320.f, 1.f);
		PzGame::playerCount = 3;
		PzGame::localPos = PzGame::players[0].pos;
		PzGame::usingMock = true;
	}

	bool ReadFromConfiguredOffsets()
	{
		if (!PzMem::process || !PzConfig::onlinePlayersStatic)
			return false;

		uint64_t listAddr = 0;
		if (!PzMem::Read(PzConfig::onlinePlayersStatic, listAddr) || !listAddr)
			return false;

		// MVP hook: user must fill JVM/Java ArrayList walk after tools/dumper2 scrape.
		// Until then, this path intentionally returns false (no fabricated reads).
		(void)listAddr;
		return false;
	}
}

void PzGame::ResetPlayers()
{
	std::lock_guard<std::mutex> lock(stateMu);
	playerCount = 0;
	for (int i = 0; i < kMaxPlayers; i++) players[i].valid = false;
}

bool PzGame::Update()
{
	bool ok = false;
	PzGame::usingMock = false;

	if (PzConfig::dataSource == DataSource::FixtureMock)
	{
		PlayerRecord tmp[kMaxPlayers];
		int n = 0;
		bool fromFix = false;
		const char* path = PzConfig::fixturePath.c_str();
		if (PzTelemetryFile::LoadPlayersFromJsonFile(path, tmp, n, kMaxPlayers, fromFix))
		{
			std::lock_guard<std::mutex> lock(stateMu);
			playerCount = n;
			for (int i = 0; i < n; i++) players[i] = tmp[i];
			if (n > 0) localPos = players[0].pos;
			usingMock = true;
			return true;
		}
		MockSnapshot();
		return true;
	}

	if (PzConfig::dataSource == DataSource::ServerTelemetryFile)
	{
		std::string path = PzConfig::telemetryPath.empty()
			? PzTelemetryFile::DefaultServerTelemetryPath()
			: PzConfig::telemetryPath;
		PlayerRecord tmp[kMaxPlayers];
		int n = 0;
		bool fromFix = false;
		if (PzTelemetryFile::LoadPlayersFromJsonFile(path.c_str(), tmp, n, kMaxPlayers, fromFix))
		{
			std::lock_guard<std::mutex> lock(stateMu);
			playerCount = n;
			for (int i = 0; i < n; i++) players[i] = tmp[i];
			if (n > 0) localPos = players[0].pos;
			usingMock = false;
			return true;
		}
		PzGame::usingMock = true;
		return false;
	}

	// ExternalReadOnly: attach + offsets only when user supplied lawful read-only config
	if (!PzMem::process)
	{
		if (PzMem::Attach(PzConfig::exeName.c_str(), PzConfig::moduleName.c_str()))
			offsetsReady = PzConfig::onlinePlayersStatic != 0;
	}
	if (PzMem::process && offsetsReady)
		ok = ReadFromConfiguredOffsets();

	if (!ok)
	{
		PzGame::usingMock = true;
		if (PzConfig::dataSource == DataSource::ExternalReadOnly)
			PZ_LOG("external path idle — set offsets in pz_offsets.ini or use telemetry/fixture in menu");
	}
	return ok;
}

const char* PzGame::BuildPlayersJson(char* buf, size_t cap)
{
	std::lock_guard<std::mutex> lock(stateMu);
	size_t pos = 0;
	pos += snprintf(buf + pos, cap - pos,
		"{\"schema\":1,\"mode\":\"%s\",\"mock\":%s,\"players\":[",
		PzConfig::ModeName(PzConfig::mode), usingMock.load() ? "true" : "false");
	bool first = true;
	for (int i = 0; i < playerCount && i < kMaxPlayers; i++)
	{
		if (!players[i].valid) continue;
		if (!first) pos += snprintf(buf + pos, cap - pos, ",");
		first = false;
		pos += snprintf(buf + pos, cap - pos,
			"{\"username\":\"%s\",\"x\":%.2f,\"y\":%.2f,\"z\":%.2f,\"local\":%s}",
			players[i].name, players[i].pos.x, players[i].pos.y, players[i].pos.z,
			players[i].isLocal ? "true" : "false");
		if (pos >= cap - 4) break;
	}
	snprintf(buf + pos, cap - pos, "]}");
	return buf;
}