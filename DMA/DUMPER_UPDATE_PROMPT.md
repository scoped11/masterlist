# Dumper Update Task — Add Encryption Support for UE5 + IL2CPP Games

## Goal
Update `dma_offsetdump.h` in the masterlist repo (`scoped11/masterlist`, path: `DMA/dma_offsetdump.h`) so the DMA dumper can handle encrypted pointers for **UE5 games** (Delta Force, Arena Breakout) and **IL2CPP games** (Rust).

Currently only the R6 Siege / AnvilNext `DumpNativeOffsets()` path has encryption handling (XOR + ROL/ROR brute-force + xref-based key extraction). The `DumpUEOffsets()` and `DumpIL2CPPOffsets()` paths do zero encryption work — they sig-scan for GWorld/GNames/GObjects and if the pointer value looks invalid they just output `0x0`.

## What Each Engine Encrypts

### UE5 Games (Delta Force, Arena Breakout)
These games use custom anti-cheat (ACE for Delta Force, Nexon for Arena Breakout) that may encrypt:
1. **GWorld pointer** — the sig scan finds the RIP-relative LEA that references GWorld, but the value stored there may be XOR'd or rotated
2. **Actor pointers in the entity list** — individual entity pointers in `ULevel::Actors[]` may be encrypted
3. **GNames pool** — name entries may be XOR'd to prevent string scanning

Common UE5 encryption patterns:
- XOR with a compile-time constant (changes per patch)
- XOR + bit rotation (ROL/ROR) — same pattern R6 uses
- Per-pointer encryption using the pointer's own address as part of the key (`ptr ^ (addr * constant)`)
- ADD/SUB-based obfuscation (less common)

### IL2CPP Games (Rust)
Rust uses EAC which may:
1. **Encrypt or strip `global-metadata.dat`** — the magic `0xFAB11BAF` may be XOR'd or the entire blob encrypted with a session key
2. **Obfuscate IL2CPP method pointers** — GameAssembly.dll exports may point to trampolines instead of real methods
3. **Use custom metadata loading** — metadata may be decrypted into a private heap, not memory-mapped in the normal location

## Existing Code Structure

The file is `dma_offsetdump.h`, a single header in the `OffsetDump` namespace. Key functions:

```
DumpUEOffsets(game, outDir, isUE5)     — lines 831-1080, handles UE4/UE5
DumpIL2CPPOffsets(game, outDir)        — lines 449-830, handles Unity IL2CPP
DumpNativeOffsets(game, outDir)        — lines ~2300-3500, handles R6/AnvilNext (HAS encryption)
```

Helper functions already available:
- `ScanPattern(base, size, pattern, skip)` — byte pattern scanner with `??` wildcards
- `ResolveRIP(instrAddr, opcodeLen)` — resolves RIP-relative displacement
- `GetPESections(modBase)` — returns vector of SectionInfo
- `read<T>(addr)` / `read_buffer(addr, buf, size)` — DMA memory reads
- `ReadUEFName(gnamesBase, nameIndex)` — reads UE FName from GNames pool

The R6 encryption code (in `DumpNativeOffsets`) does:
1. Read the raw pointer value from the sig-scanned address
2. If the value looks invalid (not a valid pointer range), try ROL 1-63 and ROR 1-63
3. Validate each candidate by chasing the chain: `candidate -> +0x1C8 (EntityList) -> read count -> check range`
4. If ROL/ROR alone fails, scan .text for xrefs to the encrypted pointer address
5. At each xref, disassemble forward looking for XOR (48 33, 48 35, 48 31) and ROL/ROR (48 C1 C0-CF) instructions
6. Extract the key and rotation, try all orderings (XOR then ROL, ROL then XOR, inverses)
7. Validate by chasing the decrypted chain

## What To Implement

### 1. Add encryption detection to `DumpUEOffsets()`

After the GWorld sig scan finds a candidate `gworldPtr` and reads the raw value, add validation + decryption:

```cpp
DWORD64 gworldRaw = read<DWORD64>(gworldPtr);
bool gworldValid = false;
DWORD64 gworldDecrypted = gworldRaw;
DWORD64 gworldXorKey = 0;
int gworldRotation = 0;

// Validate: chase UWorld -> PersistentLevel -> Actors
int persistOff = isUE5 ? 0x30 : 0x30;
int actorsOff = 0x98;
int actorCountOff = 0xA0;

auto validateGWorld = [&](DWORD64 val) -> bool {
    if (val < 0x10000 || val > 0x7FFFFFFFFFFF) return false;
    DWORD64 level = read<DWORD64>(val + persistOff);
    if (level < 0x10000 || level > 0x7FFFFFFFFFFF) return false;
    DWORD64 actors = read<DWORD64>(level + actorsOff);
    int32_t count = read<int32_t>(level + actorCountOff);
    return (actors > 0x10000 && actors < 0x7FFFFFFFFFFF && count > 0 && count < 100000);
};
```

Then try the same progression as R6:
1. Plain pointer — if `validateGWorld(gworldRaw)` passes, it's unencrypted
2. ROL 1-63, ROR 1-63 brute force
3. If that fails, xref scan in .text for code that loads `[gworldPtr]`, extract XOR key + rotation from surrounding instructions
4. Try all XOR+ROL orderings

Output the decryption parameters in the dump:
```cpp
fprintf(f, "// GWorld encryption: XOR=0x%llX ROT=%d\n", gworldXorKey, gworldRotation);
fprintf(f, "    constexpr uintptr_t GWorld_XorKey  = 0x%llX;\n", gworldXorKey);
fprintf(f, "    constexpr int       GWorld_Rotation = %d;\n", gworldRotation);
```

Also add the same pattern for **GNames** — some UE5 games encrypt the GNames pool pointer too.

### 2. Add GWorld pointer encryption output to the .ini file

After the offsets.h dump, also write a game_offsets.ini with a `[Decryption]` section:
```ini
[Decryption]
GWorldXorKey=0xABCD1234
GWorldRotation=13
GNamesXorKey=0x0
GNamesRotation=0
```

### 3. Improve `DumpIL2CPPOffsets()` metadata finding

The current code scans .data/.rdata for pointers to the magic `0xFAB11BAF`. For EAC games:

a) **Try XOR'd magic**: scan for `0xFAB11BAF ^ common_keys` (try small integer keys 1-255, then try the game's process ID as a key, then try the base address XOR'd)

b) **Scan larger regions**: EAC may allocate metadata in a private heap outside any module. Use VMMDLL_Map_GetVad to enumerate all committed memory regions and scan each for the magic.

c) **Look for the metadata decryption routine**: scan GameAssembly.dll .text for patterns like:
```
// il2cpp::vm::MetadataLoader::LoadMetadataFile
48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B ?? ?? ?? ?? ?? 48 33 C4
```
Then trace the return value to find where metadata gets written.

d) **If metadata is found but field offsets are all zero**: the IL2CPP runtime computes field offsets at startup and stores them in `Il2CppClass::fields[i].offset`. Scan for `il2cpp_class_from_name` or `il2cpp_field_get_offset` exports in GameAssembly.dll and read the runtime-computed offsets instead of the metadata-only tokens.

### 4. Add actor pointer encryption detection for UE5

After finding GWorld and walking to the actor list, try reading actors. If actor pointers look invalid (not in valid pointer range), try the same XOR+ROL approach on each one:

```cpp
// After reading actor array
DWORD64 rawActor = read<DWORD64>(actorArray + i * 8);
// If raw actor is invalid, try decryption
if (rawActor < 0x10000 || rawActor > 0x7FFFFFFFFFFF) {
    // Try same key as GWorld
    DWORD64 dec = rawActor ^ gworldXorKey;
    if (gworldRotation > 0) dec = _rotl64(dec, gworldRotation);
    else if (gworldRotation < 0) dec = _rotr64(dec, -gworldRotation);
    // validate...
}
```

Some games use per-element encryption where the key includes the array index:
```cpp
DWORD64 dec = rawActor ^ (gworldXorKey + i * someConstant);
```

Log what works so the cheat code can replicate it.

## Files To Edit
- `DMA/dma_offsetdump.h` — all changes go here

## Build Info
The dumper is built as part of `dma_main.cpp`. It uses the VMMDLL API from MemProcFS for DMA reads. The `read<T>()` and `read_buffer()` functions are in `dma_mem.h`.

## Testing
The dumper should be tested against each game by running it on a machine with the FPGA card connected to a target PC running the game. The output should be checked for:
1. GWorld/GNames/GObjects addresses are non-zero
2. If encrypted, the decryption keys are logged and the chain validation passes
3. The output .h file contains valid-looking offsets
4. For IL2CPP, field offsets are actual integers (not zero tokens)

## Important Notes
- Don't break existing functionality — the R6 AnvilNext path must still work
- The UE5 common offsets (UWorld::PersistentLevel = 0x30, etc.) are hardcoded defaults that may vary per game. Add a comment noting they should be verified against the dump
- Keep the same logging style: `[+]` for success, `[-]` for failure, `[*]` for progress, `[!]` for warnings
- The encryption keys change every game patch — the dumper's job is to extract them automatically each time
