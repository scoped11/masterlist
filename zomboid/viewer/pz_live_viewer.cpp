// Project Zomboid live player viewer — localhost web radar (port 8880).
// Legitimate server-admin path: reads JSON written by MasterlistLiveViewer server mod.
//
// Build: see build.cmd or pz_live_viewer.vcxproj (VS2022 x64)

#undef UNICODE
#undef _UNICODE
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <chrono>
#include "pz_telemetry.h"
#include "pz_webserver.h"

static void PrintUsage()
{
	printf(
		"pz_live_viewer — server telemetry → http://127.0.0.1:8880\n\n"
		"  --telemetry <path>   JSON file from MasterlistLiveViewer mod\n"
		"  --port <n>           default 8880\n"
		"  --fixture <path>     demo JSON (no game)\n"
		"  --lan                bind 0.0.0.0 (private networks only)\n"
		"  --console-only       print players to stdout, no HTTP\n"
	);
}

static void ConsolePollLoop()
{
	for (;;)
	{
		Telemetry::ReloadFromDisk();
		std::string json = Telemetry::Snapshot();
		printf("%s\n", json.c_str());
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
}

int main(int argc, char** argv)
{
	int port = 8880;
	bool consoleOnly = false;
	bool useLan = false;
	std::string telemetryPath;
	std::string fixturePath;

	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) { PrintUsage(); return 0; }
		if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) { port = atoi(argv[++i]); continue; }
		if (strcmp(argv[i], "--telemetry") == 0 && i + 1 < argc) { telemetryPath = argv[++i]; continue; }
		if (strcmp(argv[i], "--fixture") == 0 && i + 1 < argc) { fixturePath = argv[++i]; continue; }
		if (strcmp(argv[i], "--lan") == 0) { useLan = true; continue; }
		if (strcmp(argv[i], "--console-only") == 0) { consoleOnly = true; continue; }
	}

	if (telemetryPath.empty()) telemetryPath = Telemetry::DefaultPath();
	Telemetry::SetPath(telemetryPath);
	if (!fixturePath.empty()) Telemetry::LoadFixtureOnce(fixturePath);

	if (consoleOnly)
	{
		printf("[pz_live_viewer] console mode, file: %s\n", telemetryPath.c_str());
		ConsolePollLoop();
		return 0;
	}

	const char* bind = useLan ? "0.0.0.0" : "127.0.0.1";
	if (!WebServer::Start(port, bind))
	{
		fprintf(stderr, "Failed to start HTTP on %s:%d\n", bind, port);
		return 1;
	}

	printf("Press Enter to stop.\n");
	getchar();
	WebServer::Stop();
	return 0;
}