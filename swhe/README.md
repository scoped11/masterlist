# Unturned SWHE External Cheat

Usermode-only external cheat for Unturned using the **WaryasSWHE** (Shatter Window Hook Exploit) for memory access. No kernel driver, no mapper, no admin privileges required.

---

## Table of Contents

1. [How It Works](#how-it-works)
2. [Setup Guide](#setup-guide)
3. [Building From Source](#building-from-source)
4. [Running](#running)
5. [Features List](#features-list)
6. [Hotkeys](#hotkeys)
7. [Architecture Overview](#architecture-overview)
8. [How to Add a New Feature](#how-to-add-a-new-feature)
9. [How to Remove a Feature](#how-to-remove-a-feature)
10. [How to Hook Into the Memory System](#how-to-hook-into-the-memory-system)
11. [How to Port to Another Game](#how-to-port-to-another-game)
12. [Security / Bypass Layer](#security--bypass-layer)
13. [File Reference](#file-reference)
14. [Troubleshooting](#troubleshooting)
15. [Limitations](#limitations)

---

## How It Works

Traditional external cheats use `ReadProcessMemory` / `WriteProcessMemory` or a kernel driver to access game memory. Both are easily detected by anti-cheat.

SWHE (Shatter Window Hook Exploit) takes a completely different approach:

1. **Shared Memory**: Windows maps certain DLLs (like `SHCore.dll`) into a shared memory section visible to both your process and the target. Both processes see the same physical pages.

2. **Gadget Chain**: The exploit pattern-scans `ntdll.dll` for a write gadget, `shell32.dll` for a trampoline, and uses `RtlCopyString` as the copy primitive.

3. **Trigger**: `SetWindowsHookExA(WH_SHELL)` installs a hook into the target's thread. `SendMessageA(WM_APPCOMMAND)` triggers it. The hook executes the gadget chain inside the target process, which calls `RtlCopyString` to copy memory between the target's address space and the shared memory section.

4. **Read Result**: After the gadget executes, the copied data appears in the shared memory section, which our process can read directly.

**No RPM. No kernel driver. No handle to the process. Pure usermode.**

The read limit is **0x700 bytes per call** (imposed by the shared memory struct layout). Our wrapper automatically chunks larger reads.

---

## Setup Guide

### Prerequisites

- **Windows 10 or 11** (any recent build)
- **Unturned** installed and running (Steam version)
- **Visual Studio 2022+** with "Desktop development with C++" workload (only if building from source)

### Quick Start (Pre-built Binary)

1. Launch **Unturned** from Steam
2. Get to the main menu (or join a server)
3. Run `unturned_swhe.exe` (no admin needed)
4. Wait for "SWHE exploit initialized OK" and "Resolving classes..."
5. Once offsets resolve, join a server (or if already in one, ESP will start)
6. Press **F1** to open the menu
7. Press **END** to exit cleanly

### If It Fails to Attach

- Make sure Unturned is running and visible (not minimized)
- Make sure you're not running another instance of the cheat
- If "SWHE exploit init failed" appears, restart Unturned and try again
- The exploit needs the game window to be findable via `FindWindowA`

---

## Building From Source

### Option 1: Use build.cmd

1. Open a **Developer Command Prompt for VS** (or a regular terminal)
2. Navigate to the `swhe/` directory
3. Run `build.cmd`
4. Output: `unturned_swhe.exe`

### Option 2: Manual cl.exe

```
cl /O2 /EHsc /std:c++20 /D_CRT_SECURE_NO_WARNINGS /DWIN32_LEAN_AND_MEAN /I. ^
   source\main.cpp source\mem.cpp source\unturned.cpp ^
   WaryasSWHE\exploit.cpp WaryasSWHE\utils.cpp WaryasSWHE\pe_mapper.cpp ^
   source\types\game.cpp source\types\unity.cpp ^
   gdi32.lib user32.lib psapi.lib ntdll.lib shell32.lib shlwapi.lib ^
   /Fe:unturned_swhe.exe /link /SUBSYSTEM:CONSOLE
```

### Option 3: Visual Studio Project

Create a new Console Application project, add all `.cpp` files from `source/` and `WaryasSWHE/`, set include path to the root directory, link the libs listed above, and build as x64 Release.

---

## Running

```
unturned_swhe.exe
```

That's it. No arguments, no driver, no mapper, no admin. Just run it with Unturned open.

### What Happens on Launch

1. **Security init** - anti-debug checks, PE header wipe, integrity baseline, heartbeat thread starts
2. **Process search** - scans for `Unturned.exe` via toolhelp snapshot
3. **SWHE init** - finds shared memory in SHCore.dll, pattern scans ntdll/shell32 for gadgets
4. **Mono resolution** - walks PEB to find `mono-2.0-bdwgc.dll`, locates `mono_get_root_domain`
5. **Class resolution** - uses Mono reflection to find all game classes (Player, Life, Equipment, etc.)
6. **Offset resolution** - resolves field offsets within each class
7. **Overlay** - spawns GDI overlay thread (transparent, streamproof, hidden from taskbar)
8. **Feature loop** - runs all features every tick (~3-10ms)

---

## Features List

### Combat
| Feature | Description |
|---------|-------------|
| Aimbot | Smooth aim toward nearest player head (hold RMB) |
| Silent Aim | Snap to target for a few ticks on left-click, then restore angles |
| Triggerbot | Auto-fire when crosshair is on a player |
| Spinbot | Continuously rotate yaw (anti-aim) |
| No Recoil | Zero all recoil values on current weapon |
| No Spread | Zero bullet spread |
| Rapid Fire | Set fire rate to 0 |
| Infinite Range | Set weapon range to 9999 |
| Extended Melee | Set melee range to 20 |
| No Scope Sway | Zero scope sway vector |
| Instant Reload | Set reload time to 0 |

### Movement
| Feature | Description |
|---------|-------------|
| Speed Hack | Multiply movement speed |
| Super Jump | Multiply jump height |
| Fly Hack | Zero gravity + Space/Ctrl for vertical movement |
| Vehicle Fly | Full 3D flight in vehicles (pitch-aware) |
| No Fall Damage | Zero falling damage multiplier |

### Survival
| Feature | Description |
|---------|-------------|
| God Mode | Max health, food, water, stamina, virus; clear bleed/broken |

### Visuals
| Feature | Description |
|---------|-------------|
| Player ESP | Boxes, names, health bars, distance, snaplines |
| Vehicle ESP | Vehicle positions with distance |
| Item ESP | Item positions with names and distance |
| Zombie ESP | Zombie positions with distance |
| Fullbright | Force vision mode to bright |
| Night Vision | Force military night vision |
| No Fog | Disable fog rendering |
| FOV Changer | Override vertical FOV |

### Utility
| Feature | Description |
|---------|-------------|
| Admin Mode | Set admin flag on local player |
| Force GPS | Always show GPS minimap |
| Force Compass | Always show compass |
| No Flash | Zero stun/flash duration |

---

## Hotkeys

| Key | Action |
|-----|--------|
| **F1** | Toggle menu |
| **F2** | Toggle player ESP |
| **F3** | Toggle god mode |
| **F4** | Toggle speed hack |
| **F5** | Toggle fly hack |
| **F6** | Toggle no recoil |
| **F7** | Toggle aimbot |
| **F8** | Toggle vehicle ESP |
| **F9** | Toggle vehicle fly |
| **F10** | Toggle fullbright |
| **F11** | Toggle spinbot |
| **F12** | Toggle item ESP |
| **RMB** | Aimbot (hold) |
| **LMB** | Silent aim (hold, if enabled) |
| **Space** | Fly up (when flying) |
| **Ctrl** | Fly down (when flying) |
| **END** | Exit cheat |

Hotkeys are defined in `config.h` and can be changed by modifying the `ProcessHotkeys()` function.

---

## Architecture Overview

```
main.cpp                    Entry point + main loop
    |
    +-- security.h          Anti-debug, anti-dump, integrity, heartbeat
    |
    +-- mem.h / mem.cpp      Memory interface (read<T>, write<T>, read_buffer)
    |       |
    |       +-- mem_swhe.h   SWHE wrapper (chunked reads/writes)
    |               |
    |               +-- WaryasSWHE/exploit.hpp/.cpp   The actual exploit
    |
    +-- mono.h               Mono runtime reflection (class/field discovery)
    |
    +-- unturned.h/.cpp      Game class definitions + offset resolution
    |       |
    |       +-- types/game.h     SDG:: game structs (Player, Life, Equipment...)
    |       +-- types/unity.h    Unity engine types (GameObject, Transform...)
    |       +-- types/transform.h Transform math
    |
    +-- features.h           All cheat features (ESP data gathering, aimbot, mods)
    |
    +-- overlay.h            GDI overlay rendering (ESP drawing, menu)
    |
    +-- config.h             Settings + hotkey processing
    +-- math.h               Angle calc, world-to-screen
    +-- xstr.h               XOR string encryption
    +-- log.h                Printf wrapper
    +-- decrypt.h            Stub (no encryption on Unturned)
```

### Memory Read Flow

```
Game Feature (features.h)
    calls read<float>(playerAddr + offset)
        -> mem.h: read<T>() template
            -> SwheRead::ReadBuffer()       [mem_swhe.h]
                -> chunks into 0x700 byte reads
                    -> g_exploit.ReadData()  [exploit.cpp]
                        -> SetWindowsHookExA + SendMessageA
                        -> gadget chain executes RtlCopyString in target
                        -> data appears in shared memory
                        -> memcpy to caller's buffer
```

---

## How to Add a New Feature

### Step 1: Add Config Toggle

In `config.h`, add a new `inline bool`:

```cpp
inline bool myFeature = false;
```

### Step 2: Add Hotkey (Optional)

In `config.h` inside `ProcessHotkeys()`, add:

```cpp
if (GetAsyncKeyState(VK_SOME_KEY) & 1) {
    myFeature = !myFeature;
    Log(myFeature ? "My Feature ON" : "My Feature OFF");
}
```

### Step 3: Add Menu Entry (Optional)

In `overlay.h` inside the menu rendering section, add your feature to the `menuItems` array:

```cpp
{"My Feature", &Config::myFeature, nullptr, nullptr},
```

### Step 4: Implement the Feature

In `features.h`, add a new function:

```cpp
inline void UpdateMyFeature(SDG::Player* localPlayer)
{
    if (!Config::myFeature) return;

    // Read some value from the game
    float someValue = read<float>((uintptr_t)localPlayer + someOffset);

    // Write a modified value back
    write<float>(newValue, (uintptr_t)localPlayer + someOffset);
}
```

### Step 5: Call It From Update()

In `features.h` at the bottom of `Update()`:

```cpp
inline void Update(SDG::Player* localPlayer)
{
    // ... existing features ...
    UpdateMyFeature(localPlayer);
}
```

### Step 6: Add Offset (If Needed)

If your feature needs a new game offset, add it in `unturned.h`:

1. In the `Offsets` namespace, add: `inline uintptr_t myOffset = 0;`
2. In `Offsets::init()`, add: `myOffset = findOffset(Classes::SomeClass, "fieldName");`

The Mono reflection system will automatically find the correct offset at runtime.

---

## How to Remove a Feature

1. Delete the `UpdateXxx()` function from `features.h`
2. Remove the call from `Update()`
3. Remove the config toggle from `config.h`
4. Remove the hotkey from `ProcessHotkeys()`
5. Remove the menu entry from `overlay.h`
6. Remove any offsets only used by that feature from `unturned.h`

The code will compile fine with the feature removed since everything is loosely coupled.

---

## How to Hook Into the Memory System

The memory system exposes three functions you can use anywhere:

### Reading Memory

```cpp
#include "mem.h"

// Read a single value (any type)
float health = read<float>(address);
uintptr_t ptr = read<uintptr_t>(address);
int count = read<int>(address);
bool flag = read<bool>(address);

// Read a block of memory
char buffer[256];
read_buffer(address, buffer, sizeof(buffer));

// Read a struct
MyStruct s;
read_buffer(address, &s, sizeof(s));
```

### Writing Memory

```cpp
// Write a single value
write<float>(100.0f, address);
write<bool>(true, address);
write<int>(0, address);
```

### Pointer Chains

```cpp
// Follow a pointer chain: base -> ptr1 -> ptr2 -> value
uintptr_t ptr1 = read<uintptr_t>(base + 0x10);
uintptr_t ptr2 = read<uintptr_t>(ptr1 + 0x28);
float value = read<float>(ptr2 + 0x4C);
```

### Finding Game Objects via Mono

```cpp
// Find a class
auto myClass = mono::find_class("Assembly-CSharp", "SDG.Unturned.SomeClass");

// Find a field offset
auto field = myClass->find_field("someField");
int offset = field->offset();

// Use it
float val = read<float>(objectAddress + offset);
```

### Process Info

```cpp
extern DWORD pID;           // Target process ID
extern HANDLE hProc;        // Limited query handle
extern DWORD64 baseAddress; // Mono DLL base address
```

---

## How to Port to Another Game

To use this SWHE memory system with a different game:

### 1. Change the Target Process

In `mem.cpp`, change the process name:

```cpp
const char* procName = "YourGame.exe";
```

And the SWHE init:

```cpp
g_proc.Initialize(L"YourGameWindow", nullptr, (char*)"YourGame.exe");
```

### 2. Replace Mono Reflection

If the game isn't Unity/Mono:
- Remove `mono.h` includes
- Remove `Memory::resolve_mono()` calls
- Find offsets manually (hardcode or pattern scan)

If it is Unity but uses IL2CPP instead of Mono:
- Replace `mono.h` with an IL2CPP metadata parser
- The memory R/W layer (`mem.h`) stays exactly the same

### 3. Replace Game Classes

- Replace `unturned.h` / `unturned.cpp` with your game's class definitions
- Replace `types/game.h` with your game's struct layouts
- Keep `types/unity.h` if it's still Unity, otherwise replace

### 4. Replace Features

- Rewrite `features.h` with your game's features
- Rewrite `overlay.h` rendering to draw what you need

### 5. Keep These Files Unchanged

- `mem.h`, `mem.cpp`, `mem_swhe.h` - memory interface (game-agnostic)
- `WaryasSWHE/*` - the exploit itself (game-agnostic)
- `security.h` - bypass layer (game-agnostic)
- `config.h` - just needs new hotkeys
- `math.h` - generic math (may need game-specific W2S)
- `xstr.h`, `log.h` - utilities

---

## Security / Bypass Layer

The cheat includes multiple anti-analysis protections in `security.h`:

| Protection | What It Does |
|-----------|--------------|
| **Thread Hiding** | `NtSetInformationThread(ThreadHideFromDebugger)` on main, overlay, and heartbeat threads |
| **Anti-Debug (8 vectors)** | IsDebuggerPresent, debug port, debug object handle, PEB NtGlobalFlag, kernel debugger, heap flags, invalid handle trap, RDTSC timing, ntdll hook detection |
| **Anti-Dump** | Zeroes PE headers in memory (SizeOfImage, ImageBase, EntryPoint, data directories) |
| **Anti-Attach** | ProcessBreakOnTermination - attaching a debugger crashes the process |
| **Self-Integrity** | CRC32 of .text section + IAT hash verification |
| **Heartbeat** | Background thread re-checks integrity + anti-debug every 2-3 seconds; self-destructs if tampered |
| **Streamproof Overlay** | `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` - invisible to OBS, screenshots, screen capture |
| **Window Stealth** | `WS_EX_TOOLWINDOW` (no taskbar/Alt+Tab), random class name, click-through, no focus steal |
| **String Encryption** | XOR encryption on all sensitive strings (decrypted at runtime) |

### What It Does NOT Have

These protections required a kernel driver (which SWHE eliminates):
- DKOM process hiding
- CR3 page table shuffle
- PEB sanitization ("svchost.exe" disguise)
- Handle scrubbing
- Anti-cheat IOCTL neutralization

---

## File Reference

| File | Description |
|------|-------------|
| `source/main.cpp` | Entry point - security init, SWHE attach, Mono resolve, feature loop |
| `source/mem.h` | Memory interface - `read<T>()`, `write<T>()`, `read_buffer()` |
| `source/mem.cpp` | Process attach, PEB module walk, Mono DLL finder |
| `source/mem_swhe.h` | SWHE wrapper - chunked R/W over exploit, global CProcess/CExploit |
| `source/mono.h` | Mono runtime reflection - class/field/method discovery from memory |
| `source/features.h` | All cheat features - ESP data, aimbot, weapon mods, movement, god mode |
| `source/overlay.h` | GDI overlay - streamproof rendering, ESP drawing, in-game menu |
| `source/security.h` | Anti-debug, anti-dump, anti-attach, integrity heartbeat |
| `source/config.h` | Feature toggles, hotkey processing |
| `source/math.h` | Angle calculations, world-to-screen projection |
| `source/unturned.h` | Game class definitions (SDG namespace), Mono class/offset resolution |
| `source/unturned.cpp` | Static field resolution helpers |
| `source/types/game.h` | SDG game structs (Player, Life, Equipment, Movement, etc.) |
| `source/types/game.cpp` | Game type implementations |
| `source/types/unity.h` | Unity engine types (GameObject, Transform, Component) |
| `source/types/unity.cpp` | Unity type implementations (SSE-optimized transform reads) |
| `source/types/transform.h` | Transform data structures (TransformData, TransformAccessReadOnly) |
| `source/decrypt.h` | Stub - no encryption needed for Unturned |
| `source/xstr.h` | XOR string encryption/decryption (key 0x5A) |
| `source/log.h` | Printf logging wrapper |
| `WaryasSWHE/exploit.hpp` | CExploit/CProcess class definitions |
| `WaryasSWHE/exploit.cpp` | SWHE exploit implementation (shared mem, gadget scan, R/W via hooks) |
| `WaryasSWHE/utils.hpp/.cpp` | Path conversion utilities |
| `WaryasSWHE/pe_mapper.hpp/.cpp` | PE file parser for offline gadget scanning |
| `build.cmd` | Build script (auto-finds MSVC) |
| `unturned_swhe.exe` | Pre-built binary |

---

## Troubleshooting

### "SWHE exploit init failed"
- Unturned must be running and the window must be visible (not minimized)
- Try restarting Unturned
- Make sure no other instance of the cheat is running
- Check that SHCore.dll is loaded (it should be on any modern Windows)

### "Mono not ready yet, retrying..."
- The Mono runtime hasn't loaded yet. Wait for the game to fully start.
- If it loops forever, the mono DLL name may have changed in an Unturned update

### "CRITICAL: Could not find root domain offset!"
- The `mono_get_root_domain` export pattern has changed
- Check `mono.h` `find_root_domain_offset()` - may need new pattern

### Offsets are wrong / features don't work
- Unturned updated and changed its class layout
- Re-run or add new patterns to `unturned.h` `Offsets::init()`
- Most offsets auto-resolve via Mono reflection, but struct layouts in `types/game.h` may need updating

### Overlay not visible
- Make sure the game is in windowed or borderless windowed mode
- The overlay uses `WS_EX_TOPMOST` so it should be on top

### Game flickers
- This is normal. The exploit briefly hides and shows the game window for each R/W operation.
- More reads = more flicker. The code minimizes this by caching and batching.

### Security check failed on launch
- A debugger is attached, or the process has been tampered with
- Close any debuggers (x64dbg, IDA, etc.) and try again

---

## Limitations

1. **Window flicker**: Each SWHE read/write hides the game window briefly. Heavy read loops cause visible flicker.
2. **Read size**: Maximum 0x700 bytes per read call (auto-chunked, but adds overhead for large reads).
3. **Speed**: Slower than kernel R/W or RPM. Each read involves a hook install, message send, gadget execution, and unhook.
4. **Window requirement**: The target must have a visible window. Headless/background processes won't work.
5. **No kernel stealth**: Unlike the driver-based version, there's no DKOM hiding, CR3 shuffle, or PEB sanitization.
6. **Pattern dependency**: The ntdll/shell32 gadget patterns may break on major Windows updates.
7. **Single-threaded reads**: The exploit is not thread-safe. All reads happen on the main thread and the overlay thread must not read simultaneously (use locks if needed).
