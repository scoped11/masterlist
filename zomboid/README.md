# Project Zomboid — Live Player Viewer (legitimate / server-admin)

A **small stack for servers you control** (dedicated host, listen server, or co-op): a **server-side Lua mod** publishes connected player positions to disk, and a **Windows viewer** serves a browser radar on **`http://localhost:8880`** (same port convention as [`research/LINKS.md`](../research/LINKS.md) shared radar endpoint).

This is **not** an external-memory reader, injector, or anti-cheat bypass. It only works when:

1. You run (or administrate) the multiplayer **server**, and  
2. You install the **MasterlistLiveViewer** workshop-style mod on that server, and  
3. You run the viewer on a machine that can read the JSON file the mod writes (typically the same PC as the dedicated server).

## Architecture

```
┌─────────────────────────── PZ dedicated / listen server ───────────────────────────┐
│  MasterlistLiveViewer (Lua, server-only)                                             │
│    getOnlinePlayers() → username, x, y, z every ~1s                                  │
│    writes: <Zomboid>/MasterlistLiveViewer/telemetry/players.json                     │
└──────────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼ (file read)
┌─────────────────────────── pz_live_viewer.exe (Windows) ─────────────────────────────┐
│  GET /              → minimal HTML radar (polls /api/players)                        │
│  GET /api/players   → JSON snapshot (passthrough from file)                          │
│  default bind: 127.0.0.1:8880  (use --lan only on private networks you trust)      │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

### Why this path (vs DMA / external)

| Approach | Legit on your server | Live positions | MVP effort |
|----------|---------------------|----------------|------------|
| **Server Lua + file + local HTTP** (this repo) | Yes | Yes | Low |
| RCON / admin UI | Yes | Limited / not built for radar | Medium |
| Client memory / DMA | No on third-party servers; fragile | Yes | High; out of scope |

Vanilla already gates **remote player visibility** on the in-game map via `MapRemotePlayerVisibility` and related sandbox settings. This viewer shows whatever the **server** exposes to the mod via `getOnlinePlayers()` on the authority side — it does not override client fog-of-war on public servers you do not control.

## Install the server mod

1. Copy [`mods/MasterlistLiveViewer`](mods/MasterlistLiveViewer) into your server’s mods folder, or subscribe/pack as a Workshop item.
2. Enable **MasterlistLiveViewer** in the server’s `ini` / admin UI and restart the server.
3. After players connect, confirm the file exists:
   - `%UserProfile%\Zomboid\MasterlistLiveViewer\telemetry\players.json`  
   - (Path is under the server user’s Zomboid folder; exact layout may vary slightly by B41/B42.)

Optional: set `MasterlistLiveViewer.WriteIntervalMs` in sandbox vars if you add the sandbox option (default 1000 ms in code).

## Build the viewer (Visual Studio 2022)

**Requirements:** VS 2022 with “Desktop development with C++”, Windows 10/11 SDK.

### Option A — Visual Studio

1. Open [`viewer/pz_live_viewer.sln`](viewer/pz_live_viewer.sln).
2. Configuration: **Release | x64**.
3. Build. Output: `viewer/x64/Release/pz_live_viewer.exe`.

### Option B — Developer Command Prompt

```bat
cd zomboid\viewer
build.cmd
```

## Run the viewer

```bat
pz_live_viewer.exe
```

| Flag | Meaning |
|------|---------|
| `--telemetry path\to\players.json` | Override telemetry file (default: `%USERPROFILE%\Zomboid\MasterlistLiveViewer\telemetry\players.json`) |
| `--port 8880` | HTTP port (default 8880) |
| `--fixture zomboid\fixtures\sample_players.json` | Dev/demo mode without the game |
| `--lan` | Bind `0.0.0.0` instead of `127.0.0.1` (private LAN only) |

Open **http://localhost:8880/** — the page polls `/api/players` and draws named dots on a simple world map.

Console mode: run with `--console-only` to print player list to stdout every second (no HTTP).

## Limits / honesty

- **No game attached:** use `--fixture` to verify build and UI only.
- **Listen server:** the mod runs on the host; viewer must read the host’s telemetry path.
- **Remote dedicated server:** copy/sync `players.json` to the viewer machine (e.g. SMB share) or run the viewer on the server box — there is no covert client hook.
- **Visibility rules:** server sandbox and vanilla map rules still apply to what clients see in-game; this tool only reflects server-side online player list data you already own as admin.
- **Linux dedicated server:** the Lua mod is expected to work; the C++ viewer is **Windows-only** today (VS2022). Use the JSON file from any stack that can serve HTTP, or run the viewer on a Windows admin machine with access to the file.

## Repository layout

```
zomboid/
  README.md
  fixtures/sample_players.json
  mods/MasterlistLiveViewer/     # install on server
  viewer/                        # pz_live_viewer.exe sources
```

## Related masterlist patterns

- HTTP radar shape inspired by [`DMA/dma_webserver.h`](../DMA/dma_webserver.h) (`/api/gamedata`, static HTML) — stripped of cheat/toggle surfaces.
- Port **8880** aligned with [`research/LINKS.md`](../research/LINKS.md) shared radar endpoint.