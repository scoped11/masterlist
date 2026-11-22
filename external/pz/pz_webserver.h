#pragma once
#include "pz_config.h"
#include "pz_game.h"
#include "pz_webui.h"
#include "pz_log.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <atomic>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")

namespace PzWeb
{
	inline std::atomic<bool> running{ false };
	inline SOCKET listenSock = INVALID_SOCKET;
	inline std::thread serverThread;

	inline void Send(SOCKET c, int code, const char* type, const char* body, int len)
	{
		char hdr[384];
		int hlen = sprintf_s(hdr, "HTTP/1.1 %d OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n"
			"Access-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n", code, type, len);
		send(c, hdr, hlen, 0);
		if (len > 0) send(c, body, len, 0);
	}

	inline void Client(SOCKET c)
	{
		char req[2048] = {};
		int n = recv(c, req, sizeof(req) - 1, 0);
		if (n <= 0) { closesocket(c); return; }
		char method[16] = {}, path[128] = {};
		sscanf_s(req, "%15s %127s", method, (unsigned)sizeof(method), path, (unsigned)sizeof(path));
		if (_stricmp(method, "GET") == 0 && (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0))
		{
			int l = (int)strlen(PZ_RADAR_HTML);
			Send(c, 200, "text/html; charset=utf-8", PZ_RADAR_HTML, l);
		}
		else if (_stricmp(method, "GET") == 0 && strcmp(path, "/api/players") == 0)
		{
			char json[8192];
			PzGame::BuildPlayersJson(json, sizeof(json));
			Send(c, 200, "application/json", json, (int)strlen(json));
		}
		else Send(c, 404, "text/plain", "not found", 9);
		closesocket(c);
	}

	inline void Loop()
	{
		while (running.load())
		{
			fd_set fds; FD_ZERO(&fds); FD_SET(listenSock, &fds);
			timeval tv{ 1, 0 };
			if (select(0, &fds, nullptr, nullptr, &tv) > 0 && FD_ISSET(listenSock, &fds))
			{
				SOCKET c = accept(listenSock, nullptr, nullptr);
				if (c != INVALID_SOCKET) Client(c);
			}
		}
	}

	inline bool Start()
	{
		if (running.load()) return true;
		WSADATA wsa{};
		if (WSAStartup(MAKEWORD(2, 2), &wsa)) return false;
		listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (listenSock == INVALID_SOCKET) return false;
		int yes = 1;
		setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));
		sockaddr_in addr{}; addr.sin_family = AF_INET;
		addr.sin_port = htons((u_short)PzConfig::httpPort);
		const char* bindIp = PzConfig::httpLan ? "0.0.0.0" : "127.0.0.1";
		inet_pton(AF_INET, bindIp, &addr.sin_addr);
		if (bind(listenSock, (sockaddr*)&addr, sizeof(addr)) || listen(listenSock, 8))
		{
			closesocket(listenSock);
			return false;
		}
		running = true;
		serverThread = std::thread(Loop);
		PZ_LOG("web radar http://%s:%d/", bindIp, PzConfig::httpPort);
		return true;
	}

	inline void Stop()
	{
		running = false;
		if (listenSock != INVALID_SOCKET) { closesocket(listenSock); listenSock = INVALID_SOCKET; }
		if (serverThread.joinable()) serverThread.join();
		WSACleanup();
	}
}