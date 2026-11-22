# `pz_viewer` — external live player viewer

Read-only **external** process viewer for Project Zomboid, patterned on:

- `external/unturned.cpp`, `external/overlay.h`, `external/mem.*` (game state → overlay)
- `DMA/dma_webserver.h` + [`research/LINKS.md`](../../research/LINKS.md) shared radar **`http://localhost:8880`**

**Hard limits:** no grief/troll actions, no anti-cheat or server-block bypass, no writes to game memory in this MVP.

## Display menu (clickable toggles — viewer only)

On startup, `pz_viewer` opens a small **GDI control panel** (patterned on `external/overlay.h` topmost windows). Every control changes **how the viewer renders or polls** — not game state.

| Toggle | What it does |
|--------|----------------|
| **Web radar** | Starts/stops HTTP server on port **8880** (`/` map + `/api/players`). |
| **Overlay player list** | Opens/closes the always-on-top text overlay with live positions. |
| **Show names** | Includes usernames in overlay lines (and web map labels). |
| **Show distances** | Shows distance-from-local in overlay (2D tile distance). |
| **Poll interval (ms) + Apply** | How often viewer refreshes JSON/overlay (50–5000 ms). |
| **Fixture / mock** | Reads `fixture_path` JSON (default `zomboid/fixtures/sample_players.json`) for offline UI tests. |
| **Server mod telemetry file** | Reads `MasterlistLiveViewer` `players.json` from `%USERPROFILE%\\Zomboid\\...` (or `telemetry_path` in ini). |
| **External read-only** | Attempts `ReadProcessMemory` **only** if you filled lawful offsets in `offsets/pz_offsets.ini`; no bypass wiring is included. |

- `--no-menu` — skip the panel; use `pz_config.ini` only.
- **END** — exit app.

## Runtime modes (config + hotkeys)

| Mode | Behavior |
|------|----------|
| `overlay` | Small always-on-top list window (`pz_overlay.h`) |
| `web_radar` | HTTP server on port **8880** — `/` + `/api/players` |
| `console` | Prints player table to stdout |
| `minimal` | Background poll only (low noise) |

- Default config: [`pz_config.ini`](pz_config.ini) (`mode=web_radar`, `mock=true`)
- **F6** — cycle modes at runtime  
- **END** — exit

## Build (VS2022)

From repo root:

```bat
build_scripts\bld_pz_viewer.cmd
```

Or open [`pz_viewer.sln`](pz_viewer.sln) → **Release | x64**.

Output: `build\pz_viewer.exe`

## Run without game (mock)

```bat
build\pz_viewer.exe
```

Enable **Web radar** in the menu (on by default), then open http://127.0.0.1:8880/

**Server mod path:** install [`../../zomboid/mods/MasterlistLiveViewer`](../../zomboid/mods/MasterlistLiveViewer), run server, select **Server mod telemetry file** in the menu.

## Run with game (your offsets required)

1. Set `mock=false` in `pz_config.ini`
2. Fill [`offsets/pz_offsets.ini`](offsets/pz_offsets.ini) from a **local** JVM scrape (`tools/dumper2.cpp` on `ProjectZomboid64.exe` + `jvm.dll`)
3. Launch PZ, then `build\pz_viewer.exe`

Until offsets are set, the tool **falls back to mock data** and logs that fact (no silent cheating claims).

## Offset / research gaps

| Source in repo | What it is |
|----------------|------------|
| `research/LINKS.md` ZDMA / CaptainDMA links | **FPGA DMA firmware** downloads — unrelated to PZ structs |
| `tools/dumper2.cpp` | JVM class enumerator for live `ReadProcessMemory` — use this to find `IsoPlayer` / list roots |
| `zomboid/mods/MasterlistLiveViewer` | Optional **server-mod** telemetry path (admin server); not required for external client |

**Detection / blocking (honest):**

- External RPM requires OS permission; protected processes will block `OpenProcess` (PZ client is usually readable on Windows).
- Multiplayer may **not replicate** all remote player coordinates to your client — you only see what the server sends, regardless of memory reads.
- Public servers you do not control: policy risk + incomplete data; intended for **your** co-op / owned environments.
- No BattlEye on stock PZ client today; that can change — do not treat this as permission to evade future protections.

## Related

- Server-mod alternative: [`../../zomboid/README.md`](../../zomboid/README.md)