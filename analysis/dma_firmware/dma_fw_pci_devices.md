# DMA Firmware — PCI Device Inventory

**System:** ASUS PRIME Z790-V AX / i9-12900K / Z790 chipset  
**BIOS:** 1661  
**GPU:** NVIDIA RTX 5070  

---

## Best Clone Candidates

### 1. Realtek PCIe GbE Controller — IDEAL
| Field | Value |
|-------|-------|
| VID | `10EC` |
| DID | `8168` |
| SUBSYS | `86771043` |
| REV | `15` |
| Class | Network Controller |

Most cloned device in DMA firmware. Simple config space, small BARs, every motherboard has one. SUBSYS `86771043` = ASUS OEM — matches your board.

### 2. Realtek 8851BE WiFi 6 NIC — IDEAL
| Field | Value |
|-------|-------|
| VID | `10EC` |
| DID | `B851` |
| SUBSYS | `E100105B` |
| REV | `00` |
| Class | Network Controller |

Simple PCIe device, small BAR. Can disable/remove the physical WiFi card in BIOS to avoid duplicate device conflict.

### 3. Intel HD Audio Controller — GOOD
| Field | Value |
|-------|-------|
| VID | `8086` |
| DID | `7A50` |
| SUBSYS | `87FB1043` |
| REV | `11` |
| Class | Multimedia Controller |

Common and simple, but chipset-integrated (PCH). Some AC checks expect audio on a specific bus/dev/fn — works if your DMA slot position matches.

### 4. Intel Management Engine Interface — GOOD
| Field | Value |
|-------|-------|
| VID | `8086` |
| DID | `7AE8` |
| SUBSYS | `85431043` |
| REV | `03` |
| Class | Communication Controller |

Every Intel board has one. Low traffic, simple BARs. Risk: duplicate MEI on same system could flag in device manager.

---

## DO NOT Clone

### NVIDIA GeForce RTX 5070 — AVOID
| Field | Value |
|-------|-------|
| VID | `10DE` |
| DID | `2F04` |
| SUBSYS | `417E1458` |
| REV | `A1` |

Massive BARs (256MB+), driver expects real GPU, duplicate GPU VID is an instant flag.

### Intel USB 3.20 xHCI Controller — AVOID
| Field | Value |
|-------|-------|
| VID | `8086` |
| DID | `7A60` |
| SUBSYS | `88821043` |
| REV | `11` |

EAC specifically checks for XHCI controllers on unusual PCIe slots (Jan 2025 detection wave).

### Intel RST VMD Controllers — AVOID
| Field | Value |
|-------|-------|
| VID | `8086` |
| DID | `09AB` / `467F` |

Storage controller — complex capabilities, NVMe-specific interactions, cloning breaks storage stack.

---

## Infrastructure Devices (No Clone Value)

| Device | VID:DID | Reason |
|--------|---------|--------|
| Host CPU bridge | `8086:4660` | Core chipset — unique per CPU |
| ISA bridge | `8086:7A04` | PCH internal — one per board |
| RAM controller | `8086:7A27` | Chipset internal |
| Performance monitor | `8086:467D` | CPU internal |
| NVIDIA HD Audio | `10DE:2F80` | GPU companion — only exists if GPU present |
| 7x PCIe root ports | `8086:7A30-7A40, 460D` | Bridges, not endpoints |

---

## PCIe Root Ports

| DEV ID | Full ID |
|--------|---------|
| `7A39` | `VEN_8086&DEV_7A39&SUBSYS_88821043&REV_11` |
| `7A3A` | `VEN_8086&DEV_7A3A&SUBSYS_88821043&REV_11` |
| `460D` | `VEN_8086&DEV_460D&SUBSYS_88821043&REV_02` |
| `7A30` | `VEN_8086&DEV_7A30&SUBSYS_88821043&REV_11` |
| `7A38` | `VEN_8086&DEV_7A38&SUBSYS_88821043&REV_11` |
| `7A3B` | `VEN_8086&DEV_7A3B&SUBSYS_88821043&REV_11` |
| `7A40` | `VEN_8086&DEV_7A40&SUBSYS_88821043&REV_11` |

---

## Firmware Notes

- Copy full 256-byte config header: VID, DID, SUBSYS, REV, Class Code, BARs, capability pointers
- Emulate PCIe capability structures: PM, MSI/MSI-X, PCIe link cap (match negotiated link speed/width)
- Shadow config space must return consistent values across all reads at every offset — EAC reads at boot and again later, comparing for drift
- Match the link speed/width your physical slot negotiates (Gen3 x1 / x4 etc)
