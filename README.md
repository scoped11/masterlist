# Coopyy DLL - Unturned Internal Cheat

An internal DLL cheat for Unturned built on Mono runtime reflection. Injected via `CreateRemoteThread` + `LoadLibraryA`.

## Features

| Feature | Hotkey | Description |
|---------|--------|-------------|
| Aimbot | F1 | Locks aim to nearest player in FOV |
| Silent Aim | F2 | Server-side aim correction |
| ESP | F3 | Player boxes, names, distance, health bars |
| No Recoil | F4 | Zeroes weapon recoil values |
| No Spread | F5 | Zeroes weapon spread angles |
| Rapid Fire | F6 | Maxes weapon fire rate |
| Infinite Range | F7 | Sets weapon range to 9999 |
| God Mode | F8 | Full health/food/water/stamina/immunity |
| Speed Hack | F9 | Adjustable movement speed multiplier |
| Fly Hack | F10 | Free-fly movement (on foot) |
| Super Jump | F11 | Increased jump multiplier |
| Admin Mode | F12 | Enables admin flag on SteamPlayer |
| Vehicle Fly | V | Fly while in a vehicle (WASD + Space/Ctrl) |
| No Fall Damage | N | Zeroes fall damage multiplier |
| Extended Melee | M | Extends melee weapon range |
| No Scope Sway | B | Removes scope sway |
| Spin Bot | J | Spins player yaw |
| Triggerbot | T | Auto-fires when crosshair is on target |
| Radar | G | Mini-map showing nearby players |
| Item ESP | I | Shows nearby item pickups |
| Zombie ESP | Z | Shows nearby zombies |
| Vehicle ESP | K | Shows nearby vehicles with health/fuel |
| Fullbright | L | Forces daytime lighting + max ambient |
| FOV Changer | O | Custom field of view |
| Instant Reload | P | Skips reload animation |
| Stream Proof | Y | Hides overlay from screen capture |
| Chams | X | Wallhack - see players/zombies through walls |
| **Speed +/-** | +/- | Adjust speed multiplier |
| **Eject** | END | Unloads the DLL cleanly |

## Architecture

```
coopyy_dll/
  dllmain.cpp           - Entry point, main loop, cleanup
  external/
    mem.h / mem.cpp      - Memory read/write with SEH protection
    mono.h               - Mono runtime reflection (classes, fields, vtables)
    unturned.h / .cpp    - Game class and offset resolution
    features.h           - All cheat feature logic
    config.h             - Hotkeys, settings, menu display
    overlay.h            - GDI overlay window (ESP rendering)
    chams.h              - Mono runtime invoke (chams, vehicle fly, fullbright)
    log.h                - Console logging
    math.h               - Angle calculations, distance, world-to-screen
    types/
      transform.h        - vector3, vector4, matrix4x4
      unity.h / .cpp     - Unity GameObject, Transform, Array<T>
      game.h / .cpp       - Unturned game classes (Player, Zombie, Vehicle, etc.)
```

## How It Works

1. **DllMain** creates a worker thread via `CreateThread`
2. Worker thread resolves `mono-2.0-bdwgc.dll` base address
3. Mono reflection finds all game classes and field offsets dynamically
4. `mono_thread_attach` registers the worker thread with the Mono runtime
5. `Chams::Init` resolves Unity engine methods via `mono_runtime_invoke`
6. Main loop runs at ~200Hz: reads game state, applies cheats, updates overlay
7. GDI overlay renders ESP on a transparent always-on-top window
8. Press END to eject - restores original values and unloads cleanly

## Building

1. Open `coopyy_dll.sln` in Visual Studio 2022
2. Set configuration to **x64** (Debug or Release)
3. Build - output is `coopyy_dll.dll`
4. Place next to `injector.exe` and run the injector

## Requirements

- Visual Studio 2022 with C++ desktop workload
- Windows SDK 10.0+
- C++17 standard
- x64 target (Unturned is 64-bit)
