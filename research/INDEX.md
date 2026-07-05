# Research Index

All research conducted across sessions — GitHub repos evaluated, analysis papers produced, techniques studied, and external resources referenced.

## Research Papers Produced

| File | Topic | Date |
|------|-------|------|
| ctf_118_anvilnext_analysis.md | AnvilNext 2.0 engine architecture (R6 Siege binary) — middleware stack, PE sections, singleton patterns | 2026-07-03 |
| ctf_118_anvilnext_verification.md | Verification of AnvilNext findings | 2026-07-03 |
| ctf_120_pointer_encryption.md | Pointer encryption schemes in modern game engines — XOR/rotate/AES patterns | 2026-07-03 |
| ctf_120_pointer_encryption_verification.md | Verification of pointer encryption research | 2026-07-03 |
| ctf_121_aggressive_pointer_re.md | Aggressive pointer reverse engineering — breaking runtime encryption | 2026-07-03 |
| ctf_121_aggressive_pointer_re_verification.md | Verification of aggressive pointer RE | 2026-07-03 |
| ctf_122_eac_defensive_pointer_encryption.md | EAC defensive pointer encryption — how EAC protects game memory from external reads | 2026-07-03 |
| ctf_122_eac_defensive_pointer_encryption_verification.md | Verification of EAC pointer encryption findings | 2026-07-03 |
| ctf_1014_spoofer_bsod_round2.md | HWID spoofer BSOD analysis — root cause of crashes during disk serial spoofing | 2026-07-04 |
| ctf_1014_spoofer_bsod_round2_verification.md | Verification of spoofer BSOD root cause | 2026-07-04 |

## GitHub Repos Evaluated

| Repo | Verdict | Notes |
|------|---------|-------|
| DErDYAST1R/EAC-CR3Bypass | Useless | Fake/incomplete — no actual bypass code, just readme hype |
| DErDYAST1R/EACBypass-CR3ReadyDrv | Useless | Same author, same quality — no working code |
| huzun1/reflective-kernel-loading | Redundant | Reflective driver loading concept; we already have a working mapper |
| huzun1/x64dbg | Useless | Just a fork of x64dbg with no meaningful additions |
| incredd1bl/Stalcraft-WH-Chams-Speedhack-FB | Fake | Claimed EAC bypass for Stalcraft — actually just a scam/empty repo |

## Techniques Studied & Implemented

### Kernel-Mode Bypass
- **ObOpenObjectByPointer(KernelMode)** — bypasses ALL ObRegisterCallbacks (EAC/BE handle stripping)
- **BYOVD (Bring Your Own Vulnerable Driver)** — CorsairLLAccess64.sys (WHQL-signed, not blocklisted)
- **Manual mapping** — load unsigned .sys into kernel memory via vulnerable driver R/W primitive
- **ZwCreateThreadEx** — kernel-initiated remote thread creation, bypasses usermode hooking

### Anti-Cheat Architecture
- **EAC kernel driver** (EasyAntiCheat_EOSSys) — ephemeral Type 1 service, registers ObRegisterCallbacks
- **BattlEye** (BEDaisy.sys) — PsSetCreateProcessNotifyRoutine + ObRegisterCallbacks + ETW
- **ObRegisterCallbacks persistence** — callbacks stay active even after stopping AC service until driver fully unloads
- **WdFilter.sys** (Windows Defender) — also registers ObRegisterCallbacks, blocks cross-process ops

### DMA (Direct Memory Access)
- **PCILeech/MemProcFS** — FPGA-based hardware memory reading via PCIe bus mastering
- **DMA + Hypervisor conflict** — EPT remapping conflicts with raw physical DMA reads → PFN_LIST_CORRUPT
- **Xilinx Artix-7 (VEN_10EE&DEV_0666)** — common DMA card FPGA for game cheating

### Hypervisor
- **TRIXX.sys** — PML4 scanner for CR3 discovery; dangerous on host (freezes/BSODs with VBox/Hyper-V/VMware)
- **AVM-Virtualizer** — hypervisor tool; conflicts with vmx86.sys (VMware holding VT-x)
- **EPT (Extended Page Tables)** — second-level address translation; basis for memory hiding

### HWID Spoofing
- **Registry-only spoofing** — obsolete; modern AC queries hardware via IOCTL_STORAGE_QUERY_PROPERTY
- **IRP-level disk serial spoofing** — intercepts storport.sys/disk.sys dispatch for proper spoofing
- **Type 3 serial offset** — fixed in HwidSpoof.c for correct STORAGE_DEVICE_DESCRIPTOR parsing

### UE5 Offset Extraction
- **Dumper-7** — runtime SDK dumper for Unreal Engine games; injects as DLL, outputs to C:\Dumper-7\SDK
- **String xref + singleton heuristic** — automated offset discovery via dumper2 for static analysis

### Stealth
- **Pool tag randomization** — cycle through MS-lookalike pool tags to avoid BigPoolTable scanning
- **PE header zeroing** — erase MZ/PE signatures from mapped kernel allocations
- **ETW patching** — trampoline EtwRegister/EtwEventWrite to suppress AC telemetry
- **DKOM** — Direct Kernel Object Manipulation for process hiding (ActiveProcessLinks unlink)

## External Resources Referenced

- **Microsoft Vulnerable Driver Blocklist** — NalDrv (iqvw64e.sys) is listed; CorsairLLAccess64 is NOT
- **OWASP / MSDN** — kernel driver security patterns, ObRegisterCallbacks documentation
- **Intel VT-x / EPT documentation** — for hypervisor implementation understanding
- **Ubisoft legal notices** (in-game) — confirmed middleware stack (Wwise, Havok, Vivox, NVIDIA NGX)
- **PCILeech GitHub (ufrisk/pcileech)** — reference for DMA firmware and MemProcFS usage
- **Sysinternals (Microsoft)** — DbgView, Process Explorer for kernel debugging
