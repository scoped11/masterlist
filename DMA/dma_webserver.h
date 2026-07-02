#pragma once
#include "dma_config.h"
#include "dma_webui.h"
#include "log.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <string>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")

namespace WebServer
{
	inline SOCKET listenSock = INVALID_SOCKET;
	inline std::thread serverThread;
	inline volatile bool running = false;
	inline int serverPort = 7337;

	struct BoolBinding { const char* name; bool* ptr; };
	struct FloatBinding { const char* name; float* ptr; float lo; float hi; };

	inline BoolBinding boolMap[] = {
		{"aimbot",        &Config::aimbot},
		{"silentAim",     &Config::silentAim},
		{"esp",           &Config::esp},
		{"noRecoil",      &Config::noRecoil},
		{"noSpread",      &Config::noSpread},
		{"rapidFire",     &Config::rapidFire},
		{"infiniteRange", &Config::infiniteRange},
		{"godMode",       &Config::godMode},
		{"speedHack",     &Config::speedHack},
		{"flyHack",       &Config::flyHack},
		{"superJump",     &Config::superJump},
		{"adminMode",     &Config::adminMode},
		{"noFallDamage",  &Config::noFallDamage},
		{"noScopeSway",   &Config::noScopeSway},
		{"noFlinch",      &Config::noFlinch},
		{"fullbright",    &Config::fullbright},
		{"radar",         &Config::radar},
		{"vehicleESP",    &Config::vehicleESP},
		{"itemESP",       &Config::itemESP},
		{"zombieESP",     &Config::zombieESP},
		{"fovChanger",    &Config::fovChanger},
		{"instantReload", &Config::instantReload},
		{"spinBot",       &Config::spinBot},
		{"extendedMelee", &Config::extendedMelee},
		{"triggerbot",    &Config::triggerbot},
		{"vehicleFly",    &Config::vehicleFly},
		{"chams",         &Config::chams},
		{"streamProof",   &Config::streamProof},
		{"lootTeleport",  &Config::lootTeleport},
		{"espBoxes",      &Config::espBoxes},
		{"espNames",      &Config::espNames},
		{"espDistance",    &Config::espDistance},
		{"espHealth",     &Config::espHealth},
		{"espSnaplines",  &Config::espSnaplines},
	};

	inline FloatBinding floatMap[] = {
		{"speedMultiplier", &Config::speedMultiplier, 1.0f, 1.5f},
		{"jumpMultiplier",  &Config::jumpMultiplier,  1.0f, 2.0f},
		{"flySpeed",        &Config::flySpeed,         2.0f, 15.0f},
		{"aimbotFOV",       &Config::aimbotFOV,       2.0f, 90.0f},
		{"aimbotSmooth",    &Config::aimbotSmooth,     1.0f, 20.0f},
		{"customFOV",       &Config::customFOV,        60.0f, 160.0f},
		{"meleeRange",      &Config::meleeRange,       1.0f, 50.0f},
		{"lootRadius",      &Config::lootRadius,       5.0f, 200.0f},
	};

	inline void SendResponse(SOCKET s, int code, const char* contentType, const char* body, int bodyLen)
	{
		const char* statusText = (code == 200) ? "OK" : (code == 404) ? "Not Found" : "Bad Request";
		char header[512];
		int hlen = sprintf_s(header,
			"HTTP/1.1 %d %s\r\n"
			"Content-Type: %s\r\n"
			"Content-Length: %d\r\n"
			"Access-Control-Allow-Origin: *\r\n"
			"Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
			"Access-Control-Allow-Headers: Content-Type\r\n"
			"Connection: close\r\n"
			"\r\n",
			code, statusText, contentType, bodyLen);
		send(s, header, hlen, 0);
		if (bodyLen > 0) send(s, body, bodyLen, 0);
	}

	inline void SendJSON(SOCKET s, const char* json)
	{
		SendResponse(s, 200, "application/json", json, (int)strlen(json));
	}

	inline void HandleConfigGet(SOCKET s)
	{
		char buf[4096];
		int pos = 0;
		pos += sprintf_s(buf + pos, sizeof(buf) - pos, "{");
		for (int i = 0; i < _countof(boolMap); i++)
		{
			pos += sprintf_s(buf + pos, sizeof(buf) - pos, "\"%s\":%s",
				boolMap[i].name, *boolMap[i].ptr ? "true" : "false");
			pos += sprintf_s(buf + pos, sizeof(buf) - pos, ",");
		}
		for (int i = 0; i < _countof(floatMap); i++)
		{
			pos += sprintf_s(buf + pos, sizeof(buf) - pos, "\"%s\":%.2f",
				floatMap[i].name, *floatMap[i].ptr);
			if (i < _countof(floatMap) - 1)
				pos += sprintf_s(buf + pos, sizeof(buf) - pos, ",");
		}
		pos += sprintf_s(buf + pos, sizeof(buf) - pos, "}");
		SendJSON(s, buf);
	}

	inline void HandleToggle(SOCKET s, const char* feature)
	{
		for (int i = 0; i < _countof(boolMap); i++)
		{
			if (_stricmp(boolMap[i].name, feature) == 0)
			{
				*boolMap[i].ptr = !*boolMap[i].ptr;
				char resp[128];
				sprintf_s(resp, "{\"feature\":\"%s\",\"value\":%s}",
					boolMap[i].name, *boolMap[i].ptr ? "true" : "false");
				SendJSON(s, resp);
				return;
			}
		}
		SendResponse(s, 404, "application/json", "{\"error\":\"unknown feature\"}", 27);
	}

	inline void HandleSet(SOCKET s, const char* feature, const char* value)
	{
		float fval = (float)atof(value);
		for (int i = 0; i < _countof(floatMap); i++)
		{
			if (_stricmp(floatMap[i].name, feature) == 0)
			{
				if (fval < floatMap[i].lo) fval = floatMap[i].lo;
				if (fval > floatMap[i].hi) fval = floatMap[i].hi;
				*floatMap[i].ptr = fval;
				char resp[128];
				sprintf_s(resp, "{\"feature\":\"%s\",\"value\":%.2f}",
					floatMap[i].name, fval);
				SendJSON(s, resp);
				return;
			}
		}
		SendResponse(s, 404, "application/json", "{\"error\":\"unknown feature\"}", 27);
	}

	inline std::string JsonSafeName(const char* name)
	{
		std::string out;
		for (int i = 0; name[i] && i < 63; i++)
		{
			char c = name[i];
			if (c == '"' || c == '\\') out += '\\';
			if (c >= 32 && c < 127) out += c;
		}
		return out;
	}

	inline void HandleGameData(SOCKET s)
	{
		char buf[256];
		std::string json = "{";
		sprintf_s(buf, "\"yaw\":%.2f,\"pitch\":%.2f,\"fov\":%.1f,\"lx\":%.1f,\"ly\":%.1f,\"lz\":%.1f,",
			Overlay::localYaw, Overlay::localPitch, Config::fovChanger ? Config::customFOV : Config::gameFOV,
			Overlay::localCamPos.x, Overlay::localCamPos.y, Overlay::localCamPos.z);
		json += buf;

		json += "\"p\":[";
		bool first = true;
		for (int i = 0; i < Overlay::playerCount && i < 48; i++)
		{
			auto& p = Overlay::players[i];
			if (!p.valid) continue;
			if (!first) json += ",";
			first = false;
			auto n = JsonSafeName(p.name);
			sprintf_s(buf, "{\"n\":\"%s\",\"x\":%.1f,\"y\":%.1f,\"z\":%.1f,\"hx\":%.1f,\"hy\":%.1f,\"hz\":%.1f,\"d\":%.1f,\"hp\":%.0f,\"t\":%d}",
				n.c_str(), p.feetPos.x, p.feetPos.y, p.feetPos.z,
				p.headPos.x, p.headPos.y, p.headPos.z,
				p.distance, p.health, p.isTarget ? 1 : 0);
			json += buf;
		}
		json += "],\"v\":[";
		first = true;
		for (int i = 0; i < Overlay::vehicleCount && i < 64; i++)
		{
			auto& v = Overlay::vehicles[i];
			if (!v.valid) continue;
			if (!first) json += ",";
			first = false;
			sprintf_s(buf, "{\"x\":%.1f,\"y\":%.1f,\"z\":%.1f,\"d\":%.1f}", v.pos.x, v.pos.y, v.pos.z, v.distance);
			json += buf;
		}
		json += "],\"z\":[";
		first = true;
		for (int i = 0; i < Overlay::zombieCount && i < 128; i++)
		{
			auto& z = Overlay::zombies[i];
			if (!z.valid) continue;
			if (!first) json += ",";
			first = false;
			sprintf_s(buf, "{\"x\":%.1f,\"y\":%.1f,\"z\":%.1f,\"d\":%.1f}", z.pos.x, z.pos.y, z.pos.z, z.distance);
			json += buf;
		}
		json += "],\"i\":[";
		first = true;
		for (int i = 0; i < Overlay::itemCount && i < 128; i++)
		{
			auto& it = Overlay::items[i];
			if (!it.valid) continue;
			if (!first) json += ",";
			first = false;
			auto n = JsonSafeName(it.name);
			sprintf_s(buf, "{\"n\":\"%s\",\"x\":%.1f,\"y\":%.1f,\"z\":%.1f,\"d\":%.1f}", n.c_str(), it.pos.x, it.pos.y, it.pos.z, it.distance);
			json += buf;
		}
		json += "]}";
		SendJSON(s, json.c_str());
	}

	inline void HandleClient(SOCKET client)
	{
		char buf[4096] = {};
		int received = recv(client, buf, sizeof(buf) - 1, 0);
		if (received <= 0) { closesocket(client); return; }
		buf[received] = 0;

		char method[16] = {}, path[512] = {};
		sscanf_s(buf, "%15s %511s", method, (unsigned)sizeof(method), path, (unsigned)sizeof(path));

		if (_stricmp(method, "OPTIONS") == 0)
		{
			SendResponse(client, 200, "text/plain", "", 0);
		}
		else if (_stricmp(method, "GET") == 0 && strcmp(path, "/") == 0)
		{
			int htmlLen = (int)strlen(WEB_UI_HTML);
			SendResponse(client, 200, "text/html; charset=utf-8", WEB_UI_HTML, htmlLen);
		}
		else if (_stricmp(method, "GET") == 0 && strcmp(path, "/api/config") == 0)
		{
			HandleConfigGet(client);
		}
		else if (_stricmp(method, "GET") == 0 && strcmp(path, "/api/gamedata") == 0)
		{
			HandleGameData(client);
		}
		else if (_stricmp(method, "POST") == 0 && strncmp(path, "/api/toggle/", 12) == 0)
		{
			HandleToggle(client, path + 12);
		}
		else if (_stricmp(method, "POST") == 0 && strncmp(path, "/api/set/", 9) == 0)
		{
			char feature[64] = {}, value[32] = {};
			const char* p = path + 9;
			const char* slash = strchr(p, '/');
			if (slash)
			{
				int flen = (int)(slash - p);
				if (flen > 63) flen = 63;
				memcpy(feature, p, flen); feature[flen] = 0;
				strncpy_s(value, slash + 1, 31);
				HandleSet(client, feature, value);
			}
			else
			{
				SendResponse(client, 400, "application/json", "{\"error\":\"missing value\"}", 24);
			}
		}
		else
		{
			SendResponse(client, 404, "text/plain", "Not Found", 9);
		}

		closesocket(client);
	}

	inline void ServerLoop()
	{
		while (running)
		{
			fd_set readfds;
			FD_ZERO(&readfds);
			FD_SET(listenSock, &readfds);
			timeval tv = { 1, 0 };

			int sel = select(0, &readfds, NULL, NULL, &tv);
			if (sel > 0 && FD_ISSET(listenSock, &readfds))
			{
				sockaddr_in clientAddr = {};
				int addrLen = sizeof(clientAddr);
				SOCKET client = accept(listenSock, (sockaddr*)&clientAddr, &addrLen);
				if (client != INVALID_SOCKET)
				{
					std::thread(HandleClient, client).detach();
				}
			}
		}
	}

	inline std::string GetLocalIP()
	{
		char hostname[256] = {};
		gethostname(hostname, sizeof(hostname));
		addrinfo hints = {}, *result = nullptr;
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		if (getaddrinfo(hostname, NULL, &hints, &result) == 0 && result)
		{
			char ip[64] = {};
			sockaddr_in* addr = (sockaddr_in*)result->ai_addr;
			inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
			freeaddrinfo(result);
			return std::string(ip);
		}
		if (result) freeaddrinfo(result);
		return "0.0.0.0";
	}

	inline bool Start(int port = 7337)
	{
		serverPort = port;
		WSADATA wsa;
		if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;

		listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (listenSock == INVALID_SOCKET) return false;

		int opt = 1;
		setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

		sockaddr_in addr = {};
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_port = htons((u_short)port);

		if (bind(listenSock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
		{
			closesocket(listenSock);
			listenSock = INVALID_SOCKET;
			return false;
		}

		if (listen(listenSock, SOMAXCONN) == SOCKET_ERROR)
		{
			closesocket(listenSock);
			listenSock = INVALID_SOCKET;
			return false;
		}

		running = true;
		serverThread = std::thread(ServerLoop);
		serverThread.detach();

		std::string ip = GetLocalIP();
		Log("[+] Web menu running on http://%s:%d", ip.c_str(), port);
		Log("[+] Open this URL on your MAIN PC (PC1) to control the cheat");
		return true;
	}

	inline void Stop()
	{
		running = false;
		if (listenSock != INVALID_SOCKET)
		{
			closesocket(listenSock);
			listenSock = INVALID_SOCKET;
		}
	}
}
