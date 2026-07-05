# Requirements

Software and tools required to build, run, and test everything in this project.

## Build Tools

- **Visual Studio 2022** (Community or higher) — C/C++ Desktop Development workload
- **Windows Driver Kit (WDK)** — kernel driver compilation (kinject.sys, BetestDriver.sys, HwidSpoof.sys)
- **Windows SDK** (comes with VS2022) — Windows API headers

## Runtime / System

- **Windows 10/11 Pro** — required for Hyper-V, test signing, kernel driver loading
- **VMware Workstation Pro** — VMTEST sandbox VM for safe driver testing
- **Test Signing Mode** (`bcdedit /set testsigning on`) — load unsigned kernel drivers

## Hardware

- **DMA Card** (PCILeech-compatible, Xilinx Artix-7 FPGA) — hardware memory access for DMA cheats
- **Secondary PC or VM** — DMA target / testing environment

## Drivers (BYOVD)

- **CorsairLLAccess64.sys** — WHQL-signed vulnerable driver for kernel R/W primitive
- **NalDrvIntel.sys** — Intel NAL driver (blocked by MS Vulnerable Driver Blocklist on newer systems)

## Tools / Utilities

- **PCILeech** — DMA card firmware flashing and memory access
- **MemProcFS** — DMA-based virtual filesystem for process memory
- **DbgView (Sysinternals)** — kernel debug output viewer
- **Process Hacker / System Informer** — process inspection, handle viewer, driver listing
- **x64dbg** — usermode debugging
- **IDA Pro** — binary reverse engineering / disassembly
- **Git for Windows** — version control
- **GitHub CLI (`gh`)** — repo management from command line

## Game-Specific

- **Steam** — game launcher (Hunger, R6 Siege)
- **Dumper-7** (UE SDK dumper DLL) — runtime offset extraction for Unreal Engine 5 games

## Anti-Cheat Testing (offline/single-player only)

- **EasyAntiCheat** — ships with Hunger (ProjectRLH)
- **BattlEye** — ships with R6 Siege, Unturned, DayZ
