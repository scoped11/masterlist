# MASTERLIST

Source code index for all tools, mappers, and research artifacts.

## Tools

| Tool | Description | Anti-Cheat |
|------|-------------|------------|
| `ac_killer` | Background watchdog — auto-terminates AC processes/services/drivers | BE, EAC, ACE, EXENS |
| `ac_launch` | Bypass launcher — starts games without AC initialization | BE, EAC, ACE |
| `be_freeze` | Suspends BattlEye heartbeat threads so game stays alive after BE killed | BE |
| `dumper2` | Process memory dumper using ReadProcessMemory + Toolhelp32 | Usermode |
| `dumper_dma` | DMA memory dumper via FPGA card (MemProcFS/VMM API) | Hardware-level, invisible |
| `static_dumper` | Disk-based PE analysis without running process | N/A |
| `apex_dumper` | Apex Legends specific dumper | EAC |
| `offset_mgr` | Offset manager for game structures | N/A |

## Mapper

Kernel driver mapper with multiple BYOVD backends:
- `primitive_nal.hpp` — Intel NalDrv (default)
- `primitive_trixx.hpp` — Sapphire TRIXX (EV signed, phys R/W)
- `primitive_corsair.hpp` — CorsairLLAccess64 (WHQL signed)
- `primitive_rtcore.hpp` — MSI RTCore
- `primitive_siv.hpp` — SIV utility
- `primitive_ts.hpp` — ThrottleStop

## Cheat

External overlay cheats (research artifacts):
- `apex_external.cpp` — Apex Legends
- `deltaforce_external.cpp` — Delta Force
- `externaltest.cpp` — Unturned test harness

## Build

All tools build with MSVC:
```
cl /O2 /EHsc tool.cpp advapi32.lib [psapi.lib] [shlwapi.lib] /link /SUBSYSTEM:CONSOLE
```
