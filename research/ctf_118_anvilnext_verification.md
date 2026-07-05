# Verification Worksheet — CTF 118: AnvilNext 2.0 Analysis

**Companion to:** `ctf_118_anvilnext_analysis.md`
**Purpose:** Per-claim fact-checking checklist. Every `[UNVERIFIED]` and `[VERIFY]` tag in the main document has a row here. A claim is "green" only when the checkbox is ticked, a source is listed, and any numeric value has been re-derived from a freshly run tool.

**Legend:**

- `Type` — VERIFY (needs citation) / UNVERIFIED (needs empirical or original-source support)
- `Priority` — HIGH (load-bearing to a section conclusion) / MEDIUM (supports argument but not load-bearing) / LOW (color/context)
- `Source Required` — what kind of evidence closes the tag
- `Status` — `[ ]` open, `[x]` closed
- `Notes` — where the verifier records the citation URL, tool re-run output, or decision to reframe/remove

---

## Section 2 — AnvilNext 2.0 Architecture

### 2.1 Historical Evolution

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 2.1-1 | Rainbow Six Siege (2015) shipped on AnvilNext 2.0 | VERIFY | HIGH | Ubisoft press release or GDC talk | [ ] | |
| 2.1-2 | For Honor (2017) shipped on AnvilNext 2.0 | VERIFY | MEDIUM | Ubisoft press or postmortem | [ ] | |
| 2.1-3 | Ghost Recon Wildlands (2017) shipped on AnvilNext 2.0 | VERIFY | MEDIUM | Ubisoft press or postmortem | [ ] | |
| 2.1-4 | Ghost Recon Breakpoint (2019) shipped on AnvilNext 2.0 | VERIFY | MEDIUM | Ubisoft press or postmortem | [ ] | |
| 2.1-5 | "Anvil Pipeline" is the specific Ubisoft phrase for 2020 refresh | VERIFY | HIGH | Ubisoft News post or dev blog | [ ] | |
| 2.1-6 | Exact quarter/month of 2020 Anvil rebrand | UNVERIFIED | MEDIUM | Specific Ubisoft blog dated post | [ ] | |

### 2.2 Executable Fingerprint

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 2.2-1 | Full PDB path string `F:\tc\01\wrk\p4\4a820094\rainbowsix\bin\pc\scimitar_engine_win64_2022_flto_dx12.pdb` | VERIFY | HIGH | Hex-dump of PE debug directory | [ ] | Only the exe module name is confirmed in archived text |
| 2.2-2 | 2022 build maps to Y7S1-Y7S4 season range | VERIFY | LOW | Ubisoft patch changelog | [ ] | |
| 2.2-3 | Toolchain is clang-cl + LLD, not MSVC | UNVERIFIED | HIGH | PE `IMAGE_DEBUG_TYPE_CODEVIEW` signature check | [ ] | Rich header dump would also help |
| 2.2-4 | `p4` = Perforce, `tc` = TeamCity | VERIFY | LOW | Confirm via Ubisoft engineering blog or GDC | [ ] | |

### 2.3 Component Diagram

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 2.3-1 | Physics=Havok — not proven from artifacts | VERIFY | HIGH | Runtime module inventory or `.rdata` re-dump | [ ] | Reframe to "engine unknown from static evidence" |
| 2.3-2 | DLSS specifically is inference from NGX presence | VERIFY | MEDIUM | Confirm from Siege release notes | [ ] | |
| 2.3-3 | Wwise 305 exports figure | VERIFY | HIGH | Recount from full 662-entry export listing | [ ] | Rerun exports scan |

### 2.4 Entity Model

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 2.4-1 | Specific GDC/UDC talks on composition-first entity model | VERIFY | HIGH | Talk titles, presenters, years | [ ] | |
| 2.4-2 | SpawnManager RVA `0x11F20F60` reconciles with actual .data boundary | UNVERIFIED | HIGH | Reconcile INI vs static PE analysis | [ ] | Both offsets fall in .text under current layout |
| 2.4-3 | GameManager RVA `0x11CF0A68` reconciles with actual .data boundary | UNVERIFIED | HIGH | Reconcile INI vs static PE analysis | [ ] | |
| 2.4-4 | `48 8B 3D` MOV RDI singleton pattern is not MSVC-specific | VERIFY | MEDIUM | Note that clang-cl + LLD emit same encoding | [ ] | Correct the "MSVC-specific" attribution |
| 2.4-5 | Whether Siege ships with `/GR-` (RTTI disable) | UNVERIFIED | MEDIUM | Check `.rdata` for RTTI structures if available | [ ] | |

### 2.5 Threading

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 2.5-1 | Specific GDC sessions on task/job graph | VERIFY | HIGH | Session titles/years | [ ] | |
| 2.5-2 | Physics engine identity | VERIFY | HIGH | See 2.3-1 | [ ] | |
| 2.5-3 | Thread topology of 2022 build | UNVERIFIED | MEDIUM | Process Explorer snapshot during live match | [ ] | |
| 2.5-4 | `__security_cookie` presence claim | UNVERIFIED | LOW | Remove; not observed in dump | [ ] | Reframed |
| 2.5-5 | `.tls` size argument | UNVERIFIED | LOW | Corrected: 42.8 KB is normal | [ ] | Reframed |

### 2.6 Section Table

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 2.6-1 | Corrected section VAs and sizes match freshly-run dumper | UNVERIFIED | HIGH | Re-run dumper2 against current binary | [ ] | Use §2.6 table values |
| 2.6-2 | UBX prefix exclusivity (not in commercial packer inventory) | VERIFY | MEDIUM | Survey citation or reframe | [ ] | Weaker claim: not in widely-known commercial protector inventory |
| 2.6-3 | "Ubisoft-internal custom protector" attribution | VERIFY | MEDIUM | Primary source | [ ] | RE community writeup |
| 2.6-4 | `.UBX0` functional attribution to VM dispatch | UNVERIFIED | LOW | Runtime analysis of `.UBX0` execution | [ ] | Currently analogy from VMProtect layouts |
| 2.6-5 | 29% share, not "substantial majority" | UNVERIFIED | MEDIUM | Recompute from corrected numbers | [ ] | |
| 2.6-6 | Entropy 8.000 span figures | VERIFY | HIGH | Run entropy tool, archive output | [ ] | Currently no archived output |
| 2.6-7 | On-page-decryption model of streaming loader | UNVERIFIED | HIGH | Runtime observation | [ ] | Reframed to hypothesis; OPERATIONAL BYPASS RISK if not carefully framed |
| 2.6-8 | Recommendation to acquire live dump | VERIFY | MEDIUM | Depends on 2.6-7 | [ ] | Softer phrasing accepted |
| 2.6-9 | Pointer-encryption gadget location inside `.UBX1` | UNVERIFIED | HIGH | Runtime capture | [ ] | Reframed as limit-of-static-analysis; OPERATIONAL BYPASS RISK addressed |

---

## Section 3 — Middleware Integrations

### 3 preamble

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 3-P1 | `flto` in filename as LTO evidence | VERIFY | LOW | PE optional header check | [ ] | |
| 3-P2 | File size 395 MB vs 130.7 MB reconciliation | UNVERIFIED | HIGH | Confirm which file/dump size is intended | [ ] | Archived dump: 130.7 MB file, ~493 MB SizeOfImage |

### 3.1 Wwise

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 3.1-1 | "No FMOD" claim limited to archived export table | VERIFY | MEDIUM | Full binary strings scan | [ ] | |
| 3.1-2 | 305 unique AK symbols figure | UNVERIFIED | HIGH | Recount from full export listing | [ ] | Archive shows 662 total exports; not 662 AK |
| 3.1-3 | Full 662-entry export recount for AK share | VERIFY | HIGH | Rerun exports scan | [ ] | |
| 3.1-4 | Sub-counts (210 SoundEngine, 12 StreamMgr, 16 MemoryMgr, 4 MusicEngine, 17 Monitor) | VERIFY | MEDIUM | Recount against full export table | [ ] | |
| 3.1-5 | GDC talk citations for Wwise destruction audio | VERIFY | MEDIUM | Talk titles/years | [ ] | |

### 3.2 Havok

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 3.2-1 | Realblast voxel vs procedural-mesh characterization | VERIFY | LOW | Ubisoft technical article | [ ] | |
| 3.2-2 | Havok copyright string reconfirmation | VERIFY | MEDIUM | Live legal-notices page | [ ] | |
| 3.2-3 | 2015 copyright vintage vs API family shipped | VERIFY | MEDIUM | Havok/Microsoft docs | [ ] | |
| 3.2-4 | "4 fragmentary hknp hits" figure | UNVERIFIED | LOW | Archive shows 0; drop or resource the count | [ ] | |
| 3.2-5 | `.rdata` RawSize=0 means content not written | VERIFY | HIGH | Confirm from dumper output | [ ] | Archived value is 0 |
| 3.2-6 | "Launch integration partner for Havok FX in 2015" | VERIFY | LOW | Havok/Microsoft blog or GDC | [ ] | |
| 3.2-7 | GDC 2015/2016 Havok talks citation | VERIFY | LOW | Talk titles | [ ] | |
| 3.2-8 | Server-authority split claim | UNVERIFIED | MEDIUM | Ubisoft postmortem or hedge to inference | [ ] | |

### 3.3 Umbra

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 3.3-1 | "No Umbra symbols" scope | VERIFY | LOW | Full strings scan | [ ] | |
| 3.3-2 | Umbra absence from legal notices | VERIFY | MEDIUM | Live legal notices page | [ ] | |
| 3.3-3 | Tiger engine's use of Umbra | VERIFY | LOW | Public documentation citation | [ ] | |

### 3.4 Enlighten

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 3.4-1 | Enlighten ownership chain (drop "Autodesk" step) | VERIFY | MEDIUM | Silicon Studio acquisition history | [ ] | |
| 3.4-2 | Enlighten strings absence scope | VERIFY | LOW | Full strings scan | [ ] | |

### 3.5 SpeedTree

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 3.5-1 | SpeedTree strings absence scope | VERIFY | LOW | Full strings scan | [ ] | |

### 3.6 Bink Video

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 3.6-1 | libvpx / Ogg Vorbis declarations | VERIFY | MEDIUM | Live legal notices page | [ ] | |

### 3.7 Direct3D 12

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 3.7-1 | "15 D3D12 hits" figure | UNVERIFIED | LOW | Recount from strings scan | [ ] | Archive shows single d3d12.dll entry |
| 3.7-2 | NGX helper symbols in dump | VERIFY | LOW | Full export listing | [ ] | |
| 3.7-3 | "HLd3d9.dll = handleable-loader d3d9" expansion | UNVERIFIED | LOW | Cite source or drop parenthetical | [ ] | Not a standard term |

### 3.8 Vivox + libtox

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 3.8-1 | Voicechat hit count | VERIFY | MEDIUM | Recount against full 662-entry export table | [ ] | |
| 3.8-2 | `SetFriendsProviderResult` symbol; friend-list-drives-routing | VERIFY | LOW | Show symbol or hedge | [ ] | |
| 3.8-3 | Whether `libtox.dll` is actually the Tox Project SDK | VERIFY | HIGH | Independent confirmation | [ ] | Uncommon in AAA titles |

### 3.9 Legal-notices middleware

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 3.9-1 | Reconfirm each entry against live legal notices | VERIFY | HIGH | Live page snapshot | [ ] | HumanIK, Simplygon, Dolby/DTS, HarfBuzz, PCRE2, Zstandard, Scaleform, RTXGI |
| 3.9-2 | PCRE2 "chat filtering" use case | VERIFY | LOW | Hedge to inference | [ ] | |
| 3.9-3 | Whether Siege still ships Scaleform | VERIFY | MEDIUM | Current build DLL list | [ ] | |
| 3.9-4 | Whether RTXGI declared in current Siege legal notices | VERIFY | MEDIUM | Live legal notices page | [ ] | RTX support not widely publicized |

### 3.10 Cross-cutting

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 3.10-1 | Earlier draft UBX VAs/sizes correction | UNVERIFIED | HIGH | Use §2.6 values | [ ] | |
| 3.10-2 | "No VMP/Themida/Denuvo markers" scope | VERIFY | MEDIUM | Full strings scan | [ ] | |
| 3.10-3 | 96 MB entropy-8.000 and on-page-touch decryption | UNVERIFIED | HIGH | Entropy scan output + runtime observation | [ ] | Hypothesis-status only |
| 3.10-4 | Corrected `.rdata` VA `0x1410B000` | UNVERIFIED | HIGH | Confirm from dumper output | [ ] | |

---

## Section 4 — Anti-Tampering

### 4 opening

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 4-O1 | Build tag `4a820094` | UNVERIFIED | LOW | PDB path re-verification | [ ] | |

### 4.1 Section-level obfuscation

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 4.1-1 | Section VAs/sizes match archived dump | UNVERIFIED | HIGH | Use §2.6 table | [ ] | |
| 4.1-2 | Entropy scan output | VERIFY | HIGH | Run entropy tool | [ ] | |
| 4.1-3 | Cross-title UBX presence per title | VERIFY | MEDIUM | RE writeup per title | [ ] | |
| 4.1-4 | Rolles VMProtect writeup title/venue | VERIFY | LOW | Bibliographic check | [ ] | |
| 4.1-5 | Loki paper USENIX Security 2022 | VERIFY | LOW | Author list confirmation | [ ] | Schloegel, Blazytko, et al. |
| 4.1-6 | Corrected packer-genealogy citation (Ugarte-Pedrero et al. IEEE S&P 2015) | UNVERIFIED | LOW | Bibliographic check | [ ] | Replace "Yan et al. RAID 2015" |
| 4.1-7 | Ubisoft streaming-decrypt in job postings/GDC | UNVERIFIED | LOW | Specific post or talk | [ ] | |
| 4.1-8 | Obfuscator-LLVM SPRO 2015 | VERIFY | LOW | Year confirmation | [ ] | |
| 4.1-9 | 44/34 EAC/vmp fragmentary hit counts | UNVERIFIED | LOW | Recompute or drop | [ ] | |
| 4.1-10 | 94% EAC figure attribution (kernel driver, not user-mode module) | UNVERIFIED | HIGH | Reference ctf_103 report | [ ] | Correct conflation |
| 4.1-11 | Specific 2020+ AAA titles with two-tier protector | VERIFY | LOW | Citations | [ ] | |
| 4.1-12 | `.pdata` unwind failure inside packed body | VERIFY | LOW | IDA/Ghidra observation | [ ] | |

### 4.2 Pointer encryption

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 4.2-1 | PUBG XOR key writeup | VERIFY | LOW | Community writeup URL | [ ] | |
| 4.2-2 | Overwatch PEB-derived pointer encryption writeup | VERIFY | LOW | Community writeup URL | [ ] | |
| 4.2-3 | Modern Warfare position-dependent XOR | VERIFY | LOW | Community writeup URL | [ ] | |
| 4.2-4 | SpawnManager MOV RDI, GameManager MOV RCX pattern distinction | VERIFY | MEDIUM | INI cross-check | [ ] | |
| 4.2-5 | Offsets INI vs static PE analysis reconciliation | UNVERIFIED | HIGH | Reconcile artifacts | [ ] | Load-bearing |
| 4.2-6 | Opcode-search scan output | UNVERIFIED | MEDIUM | Preserve scan output | [ ] | |
| 4.2-7 | Individual opcode counts | UNVERIFIED | LOW | Recompute | [ ] | |
| 4.2-8 | Six-constant catalogue | UNVERIFIED | LOW | Re-scan and archive | [ ] | |

### 4.3 Import minimalism

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 4.3-1 | Kaspersky/CrowdStrike API-hashing report | VERIFY | LOW | Specific report URL | [ ] | |
| 4.3-2 | Denuvo/BattlEye API-hashing community writeup | VERIFY | LOW | Community writeup URL | [ ] | |

### 4.4 Callbacks/heartbeat

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 4.4-1 | Ubisoft GDC tick manager talk | VERIFY | MEDIUM | Talk title/year | [ ] | |
| 4.4-2 | EA Anti-Cheat blog post for Frostbite | VERIFY | LOW | Post URL | [ ] | |
| 4.4-3 | Community VAC/Source 2 reversing | VERIFY | LOW | Writeup URL | [ ] | |
| 4.4-4 | Riot Vanguard "beacon architecture" framing | VERIFY | LOW | Riot blog verification | [ ] | |
| 4.4-5 | "BattlEye whitepaper" sourcing | UNVERIFIED | HIGH | Confirm public status or remove | [ ] | Implied leaked material |
| 4.4-6 | DexGuard integrity-check documentation | VERIFY | LOW | DexGuard docs URL | [ ] | |

### 4.5 Self-checks

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 4.5-1 | XXH64 PRIME1 terminology | VERIFY | LOW | Correct "seed" to "PRIME1" | [ ] | |
| 4.5-2 | Six-constant CRC comparison | UNVERIFIED | LOW | Depends on 4.2-8 | [ ] | |
| 4.5-3 | DMA freeze attempt removed for OPERATIONAL BYPASS RISK | UNVERIFIED | HIGH | Verify removal is complete | [x] | Reframed defensively; verify pass complete |

### 4.6 Taxonomy summary

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 4.6-1 | Table VA range for `.text` packed body | UNVERIFIED | MEDIUM | Use §2.6 | [ ] | |
| 4.6-2 | Table entries reference §2.6 substitution | UNVERIFIED | MEDIUM | Cross-check | [ ] | |
| 4.6-3 | Pointer-encryption public analogues citations | VERIFY | MEDIUM | See 4.2-1/2/3 | [ ] | |
| 4.6-4 | Tick manager public documentation citation | VERIFY | MEDIUM | See 4.4-1 | [ ] | |

---

## Section 5 — Methodology

### 5.1 Binary Triage

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 5.1-1 | SizeOfImage `0x1ED04000` (~493 MB) | UNVERIFIED | HIGH | Confirm from dumper | [ ] | Earlier draft `0x18B09000` incorrect |
| 5.1-2 | Full PDB path capture | VERIFY | HIGH | Hex-dump | [ ] | |

### 5.2 String extraction

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 5.2-1 | Pattern scan "size 0x0" issue | VERIFY | MEDIUM | Separate strings extraction | [ ] | Scanner may not have reached .text |
| 5.2-2 | ~105 MB dump size and .text boundary | VERIFY | MEDIUM | Header comparison | [ ] | |
| 5.2-3 | RTTI mangling `.?AV*@@` | VERIFY | LOW | Inferred; verify on capture | [ ] | |
| 5.2-4 | `/GR-` conflation and Ubisoft's use of `/GR-` | UNVERIFIED | MEDIUM | Correct RTTI-disable vs stripping | [ ] | |

### 5.3 Singleton heuristic

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 5.3-1 | "Almost universally" generalization | VERIFY | LOW | Soften or document | [ ] | |
| 5.3-2 | dumper2 vote structure | VERIFY | MEDIUM | Cross-check with dumper2.cpp | [ ] | |
| 5.3-3 | Candidate offsets fall in .text | UNVERIFIED | HIGH | Reconcile INI vs static analysis | [ ] | See 4.2-5 |
| 5.3-4 | Zero-hit pattern scan independent confirmation | VERIFY | MEDIUM | String-cross-reference pass | [ ] | |

### 5.4 RIP-relative

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 5.4-1 | Top-20 ranked-candidate table | UNVERIFIED | MEDIUM | Rerun scanner, archive | [ ] | Only 2 in current INI |
| 5.4-2 | Corrected game name: Delta Force, not Deep Rock Galactic | UNVERIFIED | MEDIUM | Verify from df_offsets.ini | [x] | Correction applied |

### 5.5 Hot field

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 5.5-1 | XMM/EAX register-type heuristic | VERIFY | LOW | Empirical demonstration | [ ] | |

### 5.6 Limitations

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 5.6-1 | 96 MB flat-8.000 entropy figure | UNVERIFIED | HIGH | Preserve entropy scan output | [ ] | |

### 5.7 Reproducibility checklist

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 5.7-1 | PDB build identifier `p4\4a820094` | VERIFY | LOW | Depends on 2.2-1 | [ ] | |

---

## Section 6 — Defensive Implications

### 6 opening

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 6-O1 | ~130 MB / ~26% correction (was 104 MB / 65%) | UNVERIFIED | HIGH | Use §2.6 | [ ] | |

### 6.1 What analysis reveals

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 6.1-1 | Unity singleton framing correction | VERIFY | LOW | Reframe UnityPlayer.dll | [ ] | |
| 6.1-2 | Frostbite singleton name | VERIFY | LOW | Check project bf2042 notes | [ ] | |

### 6.2 Detection ideas

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 6.2-1 | "False-positive rate is zero" softening | VERIFY | LOW | Text says "very low" now | [x] | |
| 6.2-2 | "~10^4 known callers" claim | VERIFY | LOW | Softened to "bounded, enumerable" | [x] | |
| 6.2-3 | IOMMU translation-request logging as research primitive | VERIFY | LOW | Keep caveat | [x] | |

### 6.3 Pointer encryption recs

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 6.3-1 | Overwatch/PUBG "XOR + rotate with session-derived key" | UNVERIFIED | MEDIUM | Cite writeups or hedge | [x] | Text hedged |
| 6.3-2 | Attributing decrypt-gadget placement to Ubisoft | UNVERIFIED | LOW | Reframed as conditional | [x] | |

### 6.4 Section obfuscation recs

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 6.4-1 | 65% share correction | UNVERIFIED | HIGH | Use §2.6 numbers | [x] | Corrected inline |
| 6.4-2 | 94% EAC metric specification | VERIFY | MEDIUM | Specify "by section size" | [x] | |

### 6.5 Offset randomization

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 6.5-1 | Layout randomization cost | VERIFY | MEDIUM | Softened from "modest" | [x] | |

### 6.6 Hardware detection

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 6.6-1 | "Praetorian, BlackHat, CCC" attribution | UNVERIFIED | LOW | Cite specific talks | [ ] | |
| 6.6-2 | TLP timing discrimination reliability | VERIFY | LOW | Cite public research | [ ] | |
| 6.6-3 | Internal AC check name "PciBus" | VERIFY | LOW | Not attested; cite or drop | [ ] | |

### 6.7 Economics

| # | Claim | Type | Priority | Source Required | Status | Notes |
|---|-------|------|----------|-----------------|--------|-------|
| 6.7-1 | Iteration cost economic argument | VERIFY | LOW | Cite market commentary or frame as opinion | [ ] | |

---

## Global verification actions

Before publication, the following consolidated actions must be completed:

1. **Re-run dumper2 against the current shipping `RainbowSix.exe`.** Archive the full output (`r6_dump_YYYYMMDD.txt`). This closes 2.6-1, 2.6-6, 3.1-3, 3.10-4, 4.1-1, 4.1-2, 4.1-9, 5.1-1, 5.4-1, 5.6-1, 6-O1, 6.4-1.
2. **Reconcile the offsets INI against the static section table.** Determine whether the INI is stale (regenerate) or whether it was captured against a live process with a different image base (document explicitly). This closes 2.4-2, 2.4-3, 4.2-5, 5.3-3.
3. **Hex-dump the PE debug directory.** Extract the exact PDB path string and CodeView signature type. This closes 2.2-1, 2.2-3, 5.1-2, 5.7-1.
4. **Snapshot the current Ubisoft R6 legal notices page.** Cite each middleware entry with the URL and access date. This closes 3.2-2, 3.3-2, 3.6-1, 3.9-1, 3.9-3, 3.9-4.
5. **Resolve every bibliographic tag.** GDC talks, academic papers (Rolles, Loki, packer-genealogy, Obfuscator-LLVM, Aucsmith), and community writeups (PUBG, Overwatch, Modern Warfare, Vanguard, EA blog, DexGuard, PCIe fingerprinting). This closes 4.1-4/5/6/7/8, 4.2-1/2/3, 4.3-1/2, 4.4-1/2/3/4/6, 6.3-1, 6.6-1/2/3, 6.7-1, and their equivalents in §2/§3/§5.
6. **Full-binary strings scan.** Absence claims (FMOD, Havok, Umbra, Enlighten, SpeedTree, Bink, VMProtect/Themida/Denuvo) all currently rest on the archived summary rather than a raw scan. Rerun and archive. This closes 3.1-1, 3.2-4, 3.3-1, 3.4-2, 3.5-1, 3.10-2.
7. **Take an OPERATIONAL BYPASS RISK pass.** Confirm that no passage in the final text reads as attacker guidance. Section 4.5's shadow-copy-check example, Section 2.6's on-page-decryption discussion, and Section 4.2's decrypt-gadget hypothesis are the specific passages to re-audit. Currently marked closed via reframe (see 4.5-3, 2.6-9); confirm pass completeness before publication.

---

*End of worksheet.*
