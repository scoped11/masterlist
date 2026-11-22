#pragma once
#include "pz_telemetry.h"
#include "pz_webui.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <atomic>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")

namespace WebServer
{
	inline SOCKET listenSock = INVALID_SOCKET;
	inline std::thread serverThread;
	inline std::atomic<bool> running{ false };
	inline int serverPort = 8880;
	inline const char* bindAddr = "127.0.0.1";

	inline void SendResponse(SOCKET s, int code, const char* contentType, const char* body, int bodyLen, bool keepAlive = true)
	{
		const char* statusText = (code == 200) ? "OK" : (code == 404) ? "Not Found" : "Bad Request";
		char header[512];
		int hlen = sprintf_s(header,
			"HTTP/1.1 %d %s\r\n"
			"Content-Type: %s\r\n"
			"Content-Length: %d\r\n"
			"Access-Control-Allow-Origin: *\r\n"
			"Cache-Control: no-store\r\n"
			"Connection: %s\r\n"
			"\r\n",
			code, statusText, contentType, bodyLen, keepAlive ? "keep-alive" : "close");
		send(s, header, hlen, 0);
		if (bodyLen > 0) send(s, body, bodyLen, 0);
	}

	inline void SendJSON(SOCKET s, const std::string& json)
	{
		SendResponse(s, 200, "application/json", json.c_str(), (int)json.size());
	}

	inline void HandleClient(SOCKET client)
	{
		char buf[2048] = {};
		int received = recv(client, buf, sizeof(buf) - 1, 0);
		if (received <= 0) { closesocket(client); return; }
		buf[received] = 0;

		char method[16] = {}, path[256] = {};
		sscanf_s(buf, "%15s %255s", method, (unsigned)sizeof(method), path, (unsigned)sizeof(path));

		if (_stricmp(method, "GET") == 0 && (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0))
		{
			int htmlLen = (int)strlen(PZ_WEB_UI_HTML);
			SendResponse(client, 200, "text/html; charset=utf-8", PZ_WEB_UI_HTML, htmlLen, false);
		}
		else if (_stricmp(method, "GET") == 0 && strcmp(path, "/api/players") == 0)
		{
			Telemetry::ReloadFromDisk();
			SendJSON(client, Telemetry::Snapshot());
		}
		else if (_stricmp(method, "OPTIONS") == 0)
		{
			SendResponse(client, 200, "text/plain", "", 0, false);
		}
		else
		{
			SendResponse(client, 404, "application/json", "{\"error\":\"not found\"}", 22, false);
		}
		closesocket(client);
	}

	inline void ServerLoop()
	{
		while (running.load())
		{
			fd_set readSet;
			FD_ZERO(&readSet);
			FD_SET(listenSock, &readSet);
			timeval tv = { 1, 0 };
			int sel = select(0, &readSet, nullptr, nullptr, &tv);
			if (sel <= 0 || !FD_ISSET(listenSock, &readSet)) continue;
			SOCKET client = accept(listenSock, nullptr, nullptr);
			if (client != INVALID_SOCKET) HandleClient(client);
		}
	}

	inline bool Start(int port, const char* addr)
	{
		serverPort = port;
		bindAddr = addr;
		WSADATA wsa = {};
		if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;

		listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (listenSock == INVALID_SOCKET) return false;

		int yes = 1;
		setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));

		sockaddr_in sa = {};
		sa.sin_family = AF_INET;
		sa.sin_port = htons((u_short)port);
		inet_pton(AF_INET, bindAddr, &sa.sin_addr);
		if (bind(listenSock, (sockaddr*)&sa, sizeof(sa)) != 0) return false;
		if (listen(listenSock, 8) != 0) return false;

		running.store(true);
		serverThread = std::thread(ServerLoop);
		printf("[pz_live_viewer] http://%s:%d/ (telemetry: %s)\n", bindAddr, port, Telemetry::g_path.c_str());
		return true;
	}

	inline void Stop()
	{
		running.store(false);
		if (listenSock != INVALID_SOCKET)
		{
			closesocket(listenSock);
			listenSock = INVALID_SOCKET;
		}
		if (serverThread.joinable()) serverThread.join();
		WSACleanup();
	}
}