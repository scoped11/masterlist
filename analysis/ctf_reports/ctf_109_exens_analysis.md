# CTF Task 109: EXENS Anti-Cheat Analysis Report

**Target**: EXENS Anti-Cheat (STALCRAFT: X / Stalzone)
**Date**: 2026-06-30

## 1. Overview

EXENS is a **proprietary usermode anti-cheat** built by EXBO studio exclusively for STALCRAFT: X. It has **no kernel driver** -- it starts and stops with the game process.

**No EXENS files, code, or references exist in this project.** No game-specific cheat module exists for Stalzone (project targets Unturned, Apex, and Delta Force only).

## 2. Detection Methods

### Server-Side (Primary)
- All shots, physics, and player actions validated server-side
- Client is fundamentally untrusted
- Speed hacks, teleports, and damage mods are impossible without server cooperation
- Statistical analysis of aim patterns
- Wave bans (delayed, not instant)

### Client-Side
- Memory signature scanning at runtime
- File integrity checks (game assets, models, textures)
- Macro/behavioral detection (active since March 2025)

## 3. Difficulty Assessment

| Anti-Cheat | Kernel Driver | Bypass Difficulty |
|------------|---------------|-------------------|
| BattlEye | Yes | High |
| EAC | Yes | High |
| ACE | Yes | Very High |
| **EXENS** | **No** | **Low-Medium** |

EXENS is the easiest of the four because:
- No kernel-mode protections
- No BYOVD/mapper needed
- No OB callback blocking handle access
- Standard ReadProcessMemory from elevated process would work

## 4. Bypass Strategies

1. **External RPM-based ESP** -- standard ReadProcessMemory/NtReadVirtualMemory from an elevated process. No driver needed.
2. **Read-only cheats only** -- server rejects invalid game state. Stick to ESP/radar.
3. **Avoid write-based cheats** -- server validates all mutations.
4. **Randomize read timing** -- defeat pattern-based detection of memory access frequency.
5. **Existing project infrastructure (NAL mapper, DKOM) is overkill** for EXENS.

## 5. What Would Be Needed for Full Analysis

1. EXENS usermode module from STALCRAFT install directory
2. IPC protocol analysis between EXENS and game client
3. Black-box testing of server-side validation (cannot dump server logic)

## 6. Recommendations

- **Lowest priority target** for the rewrite -- no kernel bypass needed
- If targeting Stalzone, build a simple usermode RPM tool rather than using the full driver stack
- Focus resources on EAC/BE/ACE which are the harder targets
