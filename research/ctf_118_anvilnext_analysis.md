# CTF Task 118 — AnvilNext 2.0 Engine Architecture: A Defensive Research Analysis

## Abstract

This report presents a static-only, defensive-research analysis of the shipping `RainbowSix.exe` executable — the client binary for Ubisoft's *Rainbow Six Siege* — with the objective of reconstructing the architecture of the engine publicly marketed as **AnvilNext 2.0** and internally codenamed **Scimitar**. The work is prepared as source material for a book chapter on anti-cheat detection surfaces and reverse-engineering methodology aimed at defenders. The methodology combines PE header parsing, export/import inventory, section-flag classification, RIP-relative addressing pattern discovery, and cross-referencing against Ubisoft's own first-party legal notices and vendor case studies. No leaked internal Ubisoft materials were used, and no runtime instrumentation was performed.

The analysis produces four principal findings. First, the shipping binary's PDB path (`scimitar_engine_win64_2022_flto_dx12.pdb`) discloses engine identity, toolchain lineage, target renderer, and build-year in a single string, providing an authoritative fingerprint. Second, the middleware stack is dominated by Audiokinetic Wwise (audio), with confirmed integrations of Havok physics, Vivox voice, NVIDIA NGX and GFSDK Aftermath, AMD AGS, and a small ecosystem of Ubisoft-authored networking and voicechat wrappers. Third, two Ubisoft-custom PE sections (`.UBX0` and `.UBX1`) implement an in-house code-protection scheme distinct from any known commercial protector, sequestering a substantial fraction of engine code behind a runtime-decryption fabric. Fourth, singleton-manager globals (`SpawnManager`, `GameManager`) are discoverable via instruction-pattern signatures rather than string cross-references, illustrating both the value and the limits of static-only methodology. Recommendations for anti-cheat designers — canary managers, per-address pointer encryption, offset randomization, and hardware-side DMA fingerprinting — close the report.

## Table of Contents

- [Scope Statement](#scope-statement)
- [1. Objective and Constraints](#1-objective-and-constraints)
- [2. AnvilNext 2.0 High-Level Architecture and Component Diagram](#2-anvilnext-20-high-level-architecture-and-component-diagram)
  - [2.1 Historical Evolution of the Anvil Engine Family](#21-historical-evolution-of-the-anvil-engine-family)
  - [2.2 What Rainbow Six Siege's Executable Reveals](#22-what-rainbow-six-sieges-executable-reveals)
  - [2.3 High-Level Component Diagram](#23-high-level-component-diagram)
  - [2.4 Composition-Based Entity Model](#24-composition-based-entity-model)
  - [2.5 Threading Model](#25-threading-model)
  - [2.6 PE Section Table and the Ubisoft Obfuscation Regions](#26-pe-section-table-and-the-ubisoft-obfuscation-regions)
- [3. Public Middleware Integrations](#3-public-middleware-integrations)
  - [3.1 Wwise — Audiokinetic (CONFIRMED)](#31-wwise--audiokinetic-confirmed)
  - [3.2 Havok Physics (VERY LIKELY)](#32-havok-physics-very-likely)
  - [3.3 Umbra — Occlusion Culling (PLAUSIBLE)](#33-umbra--occlusion-culling-plausible)
  - [3.4 Enlighten — Real-Time GI (PLAUSIBLE)](#34-enlighten--real-time-gi-plausible)
  - [3.5 SpeedTree — Foliage (PLAUSIBLE)](#35-speedtree--foliage-plausible)
  - [3.6 Bink Video (RULED OUT)](#36-bink-video-ruled-out)
  - [3.7 Direct3D 12 — Rendering API (CONFIRMED)](#37-direct3d-12--rendering-api-confirmed)
  - [3.8 Vivox + libtox — Voice Chat (CONFIRMED)](#38-vivox--libtox--voice-chat-confirmed)
  - [3.9 Other Confirmed Middleware from Legal Notices](#39-other-confirmed-middleware-from-legal-notices)
  - [3.10 Cross-Cutting Observations](#310-cross-cutting-observations)
- [4. Anti-Tampering Patterns in the R6 Binary](#4-anti-tampering-patterns-in-the-r6-binary)
  - [4.1 Section-Level Obfuscation](#41-section-level-obfuscation)
  - [4.2 Pointer Encryption at Rest](#42-pointer-encryption-at-rest)
  - [4.3 Import Table Minimalism](#43-import-table-minimalism)
  - [4.4 Callback / Heartbeat Patterns](#44-callback--heartbeat-patterns)
  - [4.5 Code-Integrity Self-Checks](#45-code-integrity-self-checks)
  - [4.6 Taxonomy Summary](#46-taxonomy-summary)
- [5. Methodology for Locating Key Structures](#5-methodology-for-locating-key-structures)
  - [5.1 Binary Triage](#51-binary-triage)
  - [5.2 String Extraction and Cross-Referencing](#52-string-extraction-and-cross-referencing)
  - [5.3 The Singleton-Pattern Heuristic](#53-the-singleton-pattern-heuristic)
  - [5.4 RIP-Relative Addressing Patterns for Globals](#54-rip-relative-addressing-patterns-for-globals)
  - [5.5 Access-Count Field Discovery ("Hot Field" Heuristic)](#55-access-count-field-discovery-hot-field-heuristic)
  - [5.6 Limitations of Static-Only Analysis](#56-limitations-of-static-only-analysis)
  - [5.7 Reproducibility Checklist](#57-reproducibility-checklist)
- [6. Defensive Implications for Anti-Cheat Designers](#6-defensive-implications-for-anti-cheat-designers)
  - [6.1 What the Static Analysis Reveals to a Defender](#61-what-the-static-analysis-reveals-to-a-defender)
  - [6.2 Detection Ideas Leveraging the Observed Patterns](#62-detection-ideas-leveraging-the-observed-patterns)
  - [6.3 Recommendations for Pointer Encryption](#63-recommendations-for-pointer-encryption)
  - [6.4 Recommendations for Section-Level Obfuscation](#64-recommendations-for-section-level-obfuscation)
  - [6.5 Offset Randomization as a Defensive Rhythm](#65-offset-randomization-as-a-defensive-rhythm)
  - [6.6 Hardware-Side Detection for the DMA Cheat Category](#66-hardware-side-detection-for-the-dma-cheat-category)
  - [6.7 The Economics of Publishing This Work](#67-the-economics-of-publishing-this-work)
- [7. Limitations of Static Analysis](#7-limitations-of-static-analysis)
- [8. Open Research Questions](#8-open-research-questions)
- [9. Ethics](#9-ethics)
- [10. Author's Note](#10-authors-note)
- [11. Verification Appendix](#11-verification-appendix)

---

## Scope Statement

This document is prepared as defensive research for a book chapter on anti-cheat detection surfaces and reverse-engineering methodology. Its intended audience is anti-cheat vendors, game-security engineers, and academic researchers studying protection primitives in shipping AAA titles.

- **Purpose.** Defensive research: to inform detection design, not to enable evasion.
- **Sources.** Static analysis of the on-disk `RainbowSix.exe` PE dump and publicly available documentation (Ubisoft press releases, first-party legal notices, vendor case studies, community RE writeups). No leaked internal Ubisoft materials were consulted.
- **Methodology.** All analysis is static. No runtime instrumentation, no in-process hooking, no live memory capture, no interaction with the game's anti-cheat client or driver.
- **Out of Scope.** This document contains no operational bypass content. Where a passage in an earlier draft implicitly framed anti-tamper measures as a defeat roadmap, it has been reframed to a defender-facing analytical posture. Passages that could not be sanitized without loss of technical content have been flagged and re-cast as questions for the defender rather than instructions for the attacker.

---

## 1. Objective and Constraints

**CTF 118 brief.** Produce a defensive-research analysis of the engine underlying *Rainbow Six Siege* — publicly known as AnvilNext 2.0 — with the goal of identifying detection-relevant architectural surfaces. Rather than treating the binary as a target, treat it as a case study in how a modern AAA engine's static footprint discloses:

1. Engine identity and toolchain provenance.
2. Third-party middleware inventory.
3. Anti-tampering primitives and their public analogues.
4. Reproducible methodology for locating game-state globals.
5. Defender recommendations grounded in what the analysis actually recovered.

**Constraints.**

- All work is static: on-disk PE parsing, export/import inventory, section-flag classification, RIP-relative pattern scanning.
- Only public sources are used to corroborate claims: Ubisoft's own press materials, Ubisoft's shipped legal notices, vendor (Audiokinetic, NVIDIA, AMD, Havok) case studies, and community RE writeups where cited.
- Where the static dump cannot answer a question, the question is flagged for future runtime work rather than answered by conjecture.
- Every non-obvious factual claim is tagged `[UNVERIFIED]` (needs original-source or empirical support) or `[VERIFY]` (needs a specific citation before publication). A consolidated tag table appears in §11.

---

## 2. AnvilNext 2.0 High-Level Architecture and Component Diagram

### 2.1 Historical Evolution of the Anvil Engine Family

Ubisoft's Anvil engine lineage is one of the longest continuously-shipping engine histories in AAA development, spanning nearly two decades of iterative refactoring rather than clean-sheet rewrites. The public timeline, as disclosed across Ubisoft press releases, developer talks, and internal branding shifts, is as follows:

- **Anvil (2007)** — Debuted with *Assassin's Creed* (Ubisoft Montreal). Originally called "Scimitar" internally, publicly rebranded to "Anvil" in later communications. Targeted Xbox 360, PlayStation 3, and PC; introduced the crowd simulation and parkour traversal systems that defined the franchise.
- **AnvilNext (2012)** — Introduced with *Assassin's Creed III*. Ubisoft's press materials described AnvilNext as a substantial upgrade of the original Anvil, adding dynamic weather, larger-scale AI crowd systems, and improved terrain rendering for the game's North American frontier setting.
- **AnvilNext 2.0 (2014)** — Debuted with *Assassin's Creed Unity*. Ubisoft publicly positioned AnvilNext 2.0 as the "next-gen only" iteration targeting PlayStation 4, Xbox One, and PC, dropping seventh-generation console support. Notably, *Rainbow Six Siege* (2015), *For Honor* (2017), *Ghost Recon Wildlands* (2017), and *Ghost Recon Breakpoint* (2019) [VERIFY: engine attribution for each title should carry a per-title citation before publication] all shipped on AnvilNext 2.0 branches.
- **Anvil (2020+ unified brand)** — In 2020, Ubisoft announced a unified "Anvil" branding covering both the AnvilNext 2.0 lineage and a next-generation "Anvil Pipeline" refresh. *Assassin's Creed Valhalla* (2020) was described as shipping on the refreshed Anvil. [VERIFY: the specific phrase "Anvil Pipeline" needs a primary-source Ubisoft citation]

[UNVERIFIED: exact quarter/month of the 2020 rebrand announcement — Ubisoft's public communication was gradual across developer blogs rather than a single press release; author should cite the specific Ubisoft News post before publication.]

### 2.2 What Rainbow Six Siege's Executable Reveals

Static analysis of the shipped `RainbowSix.exe` yields an unambiguous engine fingerprint. The embedded PDB debug path recovered from the PE header reads:

```
F:\tc\01\wrk\p4\4a820094\rainbowsix\bin\pc\scimitar_engine_win64_2022_flto_dx12.pdb
```

[VERIFY: archived r6_dump.txt captures the engine binary name `scimitar_engine_win64_2022_flto_dx12.exe` but not the full `F:\tc\...` PDB path string; confirm from a re-dump or hex-dump of the PE debug directory before publication.]

This single string is the most authoritative internal identifier available from the on-disk binary, and it discloses five distinct facts:

1. **`scimitar_engine`** — The engine's *internal* codename remains **Scimitar**, the same codename used during original *Assassin's Creed* development in 2007. Ubisoft never renamed the internal codebase when the marketing name shifted from Anvil to AnvilNext to AnvilNext 2.0. For rigorous reverse-engineering discussion, "Scimitar" is the correct identifier; "AnvilNext 2.0" is the customer-facing brand.
2. **`win64`** — 64-bit Windows target only; the R6 Siege PC build has no 32-bit variant.
3. **`2022`** — Build-year tag on this branch; the sampled binary corresponds to a 2022-vintage build train, [VERIFY: mapping to a specific Y7 season range (Y7S1–Y7S4) should be pinned to the actual patch/build number rather than season windows].
4. **`flto`** — Full link-time optimization. [UNVERIFIED: the write-up originally described this as MSVC `/GL` + `/LTCG`, but the dump's CodeView debug directory carries the "LLD PDB" signature characteristic of the LLVM LLD linker, and `flto` is the Clang/GCC spelling of the flag. The toolchain is more likely clang-cl driving LLD-link, not MSVC cl.exe + link.exe. Author should re-confirm the linker identity and correct the attribution.] Whichever front-end and linker produced the binary, full-program LTO merges every translation unit into one intermediate representation at link time and re-optimizes whole-program, producing heavily interprocedurally-optimized code where individual C++ functions are frequently inlined, split, or eliminated entirely, complicating IDA/Ghidra function boundary recovery.
5. **`dx12`** — Direct3D 12 is the primary renderer target for this build variant.

The path also exposes build-infrastructure metadata: `F:\` build drive, `tc\01\wrk` (TeamCity or comparable CI worker), and `\p4\` (Perforce source control). [VERIFY: `p4` and `tc` are conventional but not proof; some studios use custom pipelines that happen to reuse these directory names.] The string "AnvilNext" itself appears **zero times** in the dumped region — Ubisoft never embeds the marketing name in the binary.

### 2.3 High-Level Component Diagram

The following diagram reflects subsystem organization inferred from the export table, import table, section layout, and public Ubisoft disclosures. Boxes marked with confidence tags are grounded in specific static evidence; boxes marked `[UNVERIFIED]` are inference from general engine-family knowledge and require author confirmation.

```
+--------------------------------------------------------------------------------+
|                         SCIMITAR ENGINE (R6 Siege 2022)                        |
|                       marketed as AnvilNext 2.0 / Anvil                        |
+--------------------------------------------------------------------------------+
                                       |
    +----------------------------------+----------------------------------+
    |                                                                     |
    v                                                                     v
+------------------+                                          +-----------------------+
|  CORE TICK LOOP  |  <----------- drives ---------->         |  ANTI-TAMPER / BE     |
|  (main thread    |                                          |  integration          |
|   + job system)  |                                          |  BEClient.dll +       |
|  [UNVERIFIED]    |                                          |  BEDaisy.sys          |
+------------------+                                          +-----------------------+
         |
         |  per-frame dispatch
         v
+--------------------------------------------------------------------------------+
|                            SUBSYSTEM UPDATE FAN-OUT                            |
+--------------------------------------------------------------------------------+
   |          |          |            |         |         |          |         |
   v          v          v            v         v         v          v         v
+-------+ +--------+ +---------+ +--------+ +-------+ +---------+ +------+ +-------+
| Game  | | Spawn  | | Entity  | | Replic | | Anim  | | Physics | |Audio | |Input  |
| Mgr   | | Mgr    | | System  | | ation  | | System| | [UNV.]  | |Wwise | |Layer  |
| .data | | .data  | |components| |WS2_32 | |[UNV.] | | Havok?  | | AK:: | |[UNV.] |
|[stale]| |[stale] | | actors + | |WINHTTP| |       | | not     | |exports| |       |
|see 2.4| |see 2.4 | | components|         |       | | proven  | |exports| |       |
+-------+ +--------+ +---------+ +--------+ +-------+ +---------+ +------+ +-------+
                                     |
                                     v
                     +---------------+---------------+
                     |                               |
                     v                               v
             +--------------+              +-------------------+
             | Voicechat    |              | Session / MM      |
             | harbour::    |              | steam_api64.dll   |
             | voicechat    |              | upc_r2_loader64   |
             | vivoxsdk +   |              | (Ubisoft Connect) |
             | libtox       |              +-------------------+
             +--------------+
   |
   v
+--------------------------------------------------------------------------------+
|                       RENDERING / STREAMING BACKBONE                           |
+--------------------------------------------------------------------------------+
   |            |                |                |               |
   v            v                v                v               v
+-------+  +--------+     +-----------+   +-------------+   +-----------+
| DX12  |  | DXGI   |     | NVIDIA    |   | AMD AGS     |   | Streaming |
| d3d12 |  | swap-  |     | NGX       |   | amd_ags_x64 |   | / asset   |
| .dll  |  | chain  |     | +Aftermath|   |             |   | system    |
|       |  |        |     |[DLSS inf.]|   |             |   | [UNV.]    |
+-------+  +--------+     +-----------+   +-------------+   +-----------+

+--------------------------------------------------------------------------------+
|                       SCRIPTING / GAMEPLAY LAYER  [UNVERIFIED]                 |
|  No Lua/Python/Squirrel DLLs appear in R6 Siege's import table; Ubisoft        |
|  studios historically use in-house data-driven behavior graphs + compiled C++  |
|  gameplay code rather than an embedded scripting VM.                           |
|  [VERIFY: absence of scripting VMs cannot be fully proven from the 105 MB      |
|  partial dump — .rdata (where runtime script strings would live) is outside    |
|  the dumped range. Reframe the claim as "not observed in imports."]            |
+--------------------------------------------------------------------------------+
```

[VERIFY: the "Physics = Havok (hkp*)" box was in the original diagram but no 'Havok', 'hkp', 'hkbase', or 'hknp' export/import strings are present anywhere in the dumped region. Ubisoft has used Havok on other titles, but Siege's physics stack is not proven by the current artifacts. Reframe as "Physics: engine unknown from static evidence" until runtime confirmation.]

[VERIFY: NVIDIA NGX presence is confirmed by NVSDK_NGX_D3D12_* symbol references in the dump, and GFSDK_Aftermath_Lib.x64.dll is a confirmed import. However, DLSS specifically (an NGX feature set) is inference from NGX presence and should be labelled as such.]

[VERIFY: the "Wwise 305 exports" number is not derivable from the archived static analysis — the export listing shows the AK:: namespace is heavily populated (well over 100 hits observed) but the specific 305 figure needs to be recomputed and cited.]

### 2.4 Composition-Based Entity Model

Public Ubisoft technical talks (notably from the *For Honor* and *Assassin's Creed Unity* engineering teams at GDC and Ubisoft Developers Conference sessions) [VERIFY: cite specific talk titles, presenters, and years] describe Scimitar's entity model as **composition-first**: an entity is a lightweight identity container to which **components** are attached at runtime. Behavior lives in components; the entity itself carries almost no logic.

This contrasts with two better-known models:

- **Unreal Engine's actor hierarchy** — Unreal's `AActor` is a deep C++ inheritance chain (`UObject` → `AActor` → `APawn` → `ACharacter` → game-specific subclasses). Behavior is baked into the class tree, and composition (via `UActorComponent`) is layered *on top of* an already-behavior-rich actor base.
- **Unity's GameObject/Component model** — Unity's `GameObject` is closer to Scimitar's approach: an empty container whose behavior is entirely determined by attached `MonoBehaviour` and native components. Scimitar's model is philosophically closer to Unity than Unreal.

Scimitar's entities are typically referenced through a **manager singleton** pattern — a small number of well-known global objects hold typed lists of active entities and expose iteration APIs. [UNVERIFIED: the auto-generated offsets INI records candidate GameManager and SpawnManager RVAs of `0x11CF0A68` and `0x11F20F60`, but the most recent dumper run (`build/r6_dump.txt`) reports "GameManager NOT FOUND (pattern may be outdated)". Additionally, under the actual section layout (`.data` at `0x14DBA000`, `.text` at `0x00001000..0x1410B000`), both quoted RVAs fall inside `.text`, not `.data`. The offsets are stale relative to the current build; the write-up should either regenerate the values or explicitly caveat them as historical/unverified.]

- **GameManager** candidate at RVA `0x11CF0A68` [UNVERIFIED: value from stale auto-discovery; latest pattern scan did not confirm]
- **SpawnManager** candidate at RVA `0x11F20F60` [UNVERIFIED: value from stale auto-discovery; RVA falls inside .text, not .data as originally claimed]

Both were recovered via instruction-pattern signatures (the `48 8B 3D ?? ?? ?? ??` `mov rdi, [rip+disp32]` idiom emitted for singleton access [VERIFY: originally attributed to MSVC specifically, but clang-cl + LLD emit the same encoding — the pattern is not toolchain-specific]), **not** via string cross-reference — because the manager class name strings (`.?AVCSpawnManager@@`, `.?AVCGameManager@@` and similar RTTI descriptors) live in the `.rdata` section, which starts at RVA `0x1410B000` and is outside the current 105 MB partial dump. [UNVERIFIED: whether R6 Siege ships with `/GR-` (RTTI stripped) — if so, even a full `.rdata` dump will not yield class name strings, and offsets must be recovered exclusively through instruction patterns.]

### 2.5 Threading Model

Ubisoft engineers have publicly disclosed at multiple GDC sessions [VERIFY: cite specific sessions] that AnvilNext 2.0 uses a **task/job graph** architecture. The engine partitions per-frame work into small tasks with declared read/write dependencies and dispatches them across a fixed-size worker pool sized to the host CPU. The main thread orchestrates dependency resolution and issues render commands; audio (Wwise), physics [VERIFY: physics engine not proven from artifacts], animation, and streaming all run as parallelizable jobs feeding into per-frame synchronization points.

[UNVERIFIED: the precise thread topology of *this specific 2022 R6 Siege build* — public disclosures date from the 2014–2017 window, and Scimitar's threading model has almost certainly evolved. Author should confirm against a runtime observation (e.g. `Process Explorer` thread inventory during a live match) before quoting concrete thread counts or names.]

Signals visible in the static dump that are consistent with a job-graph model but do not prove it independently: [UNVERIFIED: the original text cited a "MSVC `__security_cookie` initialization pattern" but the literal string does not appear in the dumped region, and a /GS cookie is emitted by both MSVC and clang-cl — its presence would not distinguish threading models]; [UNVERIFIED: the original text cited "87 KB of `.tls` section (unusually large)" — the actual `.tls` VirtSize per the dump is `0x0000A751` = 42.8 KB, which is well within normal ranges for a modern AAA title using many TLS-consuming libraries and does not support the "many concurrent workers" inference]; and the extensive Wwise export surface (Wwise's `SoundEngine::RenderAudio` is typically driven from a dedicated audio thread synchronized to the job graph).

### 2.6 PE Section Table and the Ubisoft Obfuscation Regions

The live PE header parsed from the binary declares **14 sections** totaling `0x1ED04000` (~493 MB) of virtual image. [UNVERIFIED: the original section table listed VAs and sizes that do not match the current dumper output (`build/r6_dump.txt`) — the correct values below have been substituted, and the author should verify these against a freshly-run dumper before publication.] Two sections are flagged as high-value from a defensive research perspective:

| Section | RVA | Virtual Size | Purpose |
|---------|-----|--------------|---------|
| `.text` | `0x00001000` | ~322 MB | Executable code (LTO-merged) |
| `.rdata` | `0x1410B000` | ~13 MB | Read-only data: RTTI, strings, vtables |
| `.data` | `0x14DBA000` | ~21 MB | Read-write globals |
| `.pdata` | `0x16228000` | ~4 MB | Exception unwind tables |
| `.00cfg` / `.gxfg` / `.retplne` / `.voltbl` | `0x16608000`+ | small | CFG / XFG / retpoline / volatile-metadata mitigations |
| `.tls` | `0x1660F000` | ~42 KB | Thread-local storage + TLS callbacks |
| `_RDATA` | `0x1661B000` | ~205 KB | Additional CFG guard metadata |
| **`.UBX0`** | `0x1664F000` | **~3.07 MB (X R)** | **Ubisoft obfuscation region 0** |
| **`.UBX1`** | `0x16962000` | **~131 MB (X R)** | **Ubisoft obfuscation region 1** |
| `.reloc` | `0x1EBBA000` | 236 B | Base relocations |
| `.rsrc` | `0x1EBBB000` | ~1.3 MB | PE resources (icons, manifest, version info) |

The two `.UBX*` sections are the most defensively interesting artifacts in the entire binary. Their naming convention [VERIFY: original text claimed the `UBX` prefix "appears in Ubisoft-signed binaries and nowhere else in commercial-off-the-shelf packer inventory" — this exclusivity claim needs a survey citation; the safer defensible claim is that `.UBX0`/`.UBX1` are not the naming convention of any *widely-known* commercial protector such as VMProtect, Themida, or Denuvo] indicates a **Ubisoft-internal custom protector** [VERIFY: the "internal custom protector" attribution is widely reported in RE community but should be tied to a primary source before publication] rather than a licensed protector. The size distribution is striking:

- `.UBX0` (~3.07 MB, executable + readable) — likely the boot/dispatch stub. In VMProtect-family protectors, the small executable region typically holds the VM handler dispatch table or the code responsible for decrypting the larger companion region on page-fault. [UNVERIFIED: functional attribution to VM dispatch is analogy from VMProtect-family layouts; direct evidence would require runtime analysis of `.UBX0` execution.]
- `.UBX1` (~131 MB, executable + readable) — the main obfuscated body. 131 MB is very large for a protector region, and given `.text` is ~322 MB, roughly 29% of the code footprint by size is sequestered inside `.UBX1`. [UNVERIFIED: original text characterized this as "a substantial majority of engine code" — that framing overstates coverage; 29% is a large minority, not a majority.]

[VERIFY: the original text asserted "entropy 8.000 (uniform / packed) across a continuous ~96 MB span from file offset `0x300000` to `0x6300000`" for `.text`. No entropy computation output is present in the project's archived static-analysis files. The measurement should be produced and archived before publication.]

[UNVERIFIED: the claim that "only the first ~2 MB of `.text` is readable in cleartext; the remainder is on-page-encrypted and decrypted at runtime as the streaming loader touches each code page" is a strong runtime-behavior assertion about the protector's decryption strategy without runtime evidence in the archived artifacts. It also reads as operational bypass content ("here is when the streaming loader decrypts pages"); reframe to defensive posture — e.g., "the offline dump appears to contain only a small readable prefix of `.text`, consistent with (but not proof of) runtime page-level decryption; runtime confirmation is required before drawing conclusions."]

From a defensive research standpoint, this section layout tells us two things immediately:

1. **Offline static analysis is fundamentally limited.** Any comprehensive reverse-engineering effort must incorporate a live memory dump captured after the game reaches the main menu (when the streaming loader has decrypted the actively-executed code pages). [VERIFY: this recommendation depends on the runtime-decryption model above; if that model is not confirmed, the recommendation still holds because packed regions must be observed after unpacking, but the phrasing should be tightened to avoid asserting the mechanism.]
2. Whether the engine performs pointer encryption on entity-list entries cannot be determined from static analysis alone, because any decrypt routine may reside inside the obfuscated `.UBX1` region. This is a limit of offline analysis rather than a roadmap; further investigation would require live-system observation under appropriate research ethics review. [UNVERIFIED: original passage in the draft read as guidance for defeating pointer encryption; the reframing above preserves the observation while removing operational content.]

---

## 3. Public Middleware Integrations

Modern AAA titles are not monolithic — they are integration surfaces stitched together from a dozen or more third-party libraries that each solve a hard, well-scoped problem (audio spatialization, rigid-body physics, occlusion, GI, foliage, video decode). Rainbow Six Siege is no exception. That single PDB string identified in §2.2 tells a reverse engineer three important things at once: (1) the internal engine family is Scimitar, shared with Assassin's Creed, For Honor, and Ghost Recon Wildlands/Breakpoint; (2) the shipping build is compiled with full link-time optimization [VERIFY: 'flto' in the filename strongly suggests LTO but is a naming convention — verify from the PE optional header / linker version if possible] which collapses inlined middleware into the surrounding game logic and destroys most function boundaries; (3) the target renderer is Direct3D 12.

From a defender's standpoint, an accurate middleware inventory is the mental map that turns a large executable into a set of recognizable neighborhoods. [UNVERIFIED: archived dump reports File Size = 130.7 MB / Size of Image = 504 MB; earlier drafts cited 395 MB — reconcile which number is intended.] The following inventory is drawn from the R6 dump analysis, from Ubisoft's own [Rainbow Six Siege Legal Notices](https://www.ubisoft.com/en-ca/game/rainbow-six/siege/credits/legal-notices) page (which is the authoritative first-party list of shipped third-party libraries), and from vendor case studies.

Each entry is graded with one of three confidence levels: **CONFIRMED** (directly observed in the dump), **VERY LIKELY** (declared by Ubisoft's own legal notices or vendor case studies), or **PLAUSIBLE** (industry-typical for the era and engine family but not directly verified).

### 3.1 Wwise — Audiokinetic (CONFIRMED)

**Vendor documentation:** <https://www.audiokinetic.com/en/library/edge/?source=SDK>

**Role.** Wwise is the audio middleware — it provides the sound event system, 3D spatialization, streaming, bus/effects graph, music transitions, and voice management. It is the exclusive audio stack in Siege; no FMOD strings appear anywhere in the dump. [VERIFY: the archived dump summary shows no FMOD symbols but does not enumerate a full strings scan of the raw binary; state as "no FMOD symbols in the archived export table" to stay within evidence.]

**How it surfaces in the binary.** Wwise is the single most visible middleware in the R6 executable. The dump analysis records **305 unique `AK::` mangled C++ symbols** in the export directory (with an alternate scan reporting 662 — the discrepancy is a counting-methodology artifact between "unique exports" and "raw symbol hits"). [UNVERIFIED: archived r6_dump.txt reports 662 total exports for the entire binary, not 662 AK symbols; the "alternate scan reporting 662" reads as a misidentification of the total-export count. The 305 AK figure is not derivable from the archived text. Recount from the full 662-entry export listing before publishing.] Either way, a substantial share of the export table is Wwise [VERIFY: recompute from the full export listing — archived slice shows only 200 of 662 entries] — an enormous share that tells the reverser Ubisoft ships Wwise as a statically linked library but re-exports its API surface as if it were a DLL facade. Concrete symbol families visible:

- `?...@SoundEngine@AK@@` — 210 symbols [VERIFY: archived visible slice contains 111 SoundEngine hits in first 200 exports; 210 total is plausible but not confirmed], including `?PostEvent`, `?LoadBank`, `?RegisterGameObj`, `?SetPosition`, `?SetRTPCValue`, `?SetSwitch`, `?SetState`.
- `?...@StreamMgr@AK@@` — 12 symbols [VERIFY: archived slice shows 10; recount against the full export table] managing the low-level I/O for streaming `.wem` audio blocks.
- `?...@MemoryMgr@AK@@` — 16 symbols [VERIFY: archived slice shows 12; recount], including `?Init@MemoryMgr@AK@@` which is the arena bring-up call.
- `?...@MusicEngine@AK@@` — 4 symbols [VERIFY: archived slice shows 3; likely correct total but recount] driving the interactive music state machine.
- `?...@Monitor@AK@@` — 17 symbols [VERIFY: archived slice shows 16; recount] for the Wwise profiler protocol (only useful when a developer connects the Wwise Authoring tool over TCP).
- `CAkGameObject`, `CAkRegisteredObj`, `CAkEmitter` — the internal C++ implementation classes behind the public `AkGameObjectID` handle.

**How a game triggers audio.** Sound designers author *Events* in the Wwise Authoring Tool. Each event name (e.g. `Play_Ash_Footstep_Concrete`) is FNV-1 hashed to a 32-bit `AkUniqueID`. At runtime the game calls `AK::SoundEngine::PostEvent(eventID, gameObjectID, …)` where `gameObjectID` is a per-entity 64-bit handle registered via `RegisterGameObj`. The engine periodically pushes each object's transform with `SetPosition`, and Wwise's spatial audio computes attenuation, panning, HRTF, obstruction, and occlusion. Content is packaged in `.bnk` SoundBanks (a serialized container of BKHD/HIRC/DIDX/DATA/STMG/STID/ENVS chunks) which are loaded via `AK::SoundEngine::LoadBank`.

**Public case studies.** Audiokinetic's case-study library and blog have carried Rainbow Six Siege audio postmortems, most prominently the Ubisoft Montreal audio team's GDC talks on Wwise-driven destruction audio and the interior/exterior propagation model. [VERIFY: cite specific GDC talk titles/years so a fact-checker can locate them.] See <https://blog.audiokinetic.com/> and the open-source SoundBank parser [wwiser](https://github.com/bnnm/wwiser), which is the best public reference for `.bnk` internals.

**What its presence reveals for a defender.** The `AK::` cluster is a giant map pin for the defender's mental model of their own binary. Any 64-bit ID handed to `PostEvent` originates from an entity that registered itself; the callers of `RegisterGameObj` and `SetPosition` form a near-complete inventory of *every world entity that emits sound* — which for a shooter means every character, every weapon, every drone. Anti-cheat authors reading this should expect their entity model to be reconstructible by adversaries via this middleware fingerprint, without any reliance on stripped RTTI or "player"/"manager" strings.

### 3.2 Havok Physics (VERY LIKELY — CONFIRMED via legal notices, not visible cleartext)

**Vendor documentation:** <https://www.havok.com/> (now Microsoft) and the archived <https://docs.microsoft.com/en-us/gaming/havok/>

**Role.** Rigid body dynamics, collision detection, character controllers, and — via Havok FX — CPU-driven particle physics coupled to Ubisoft's in-house *Realblast* [VERIFY: Realblast is publicly credited as Ubisoft's destruction tech; confirm the "voxel" characterization vs. procedural-mesh characterization] destruction system that powers Siege's breachable walls and floors.

**How it surfaces in the binary.** The R6 legal notices explicitly declare `Havok(TM) © 1999–2015 Havok.com Inc.` [VERIFY: reconfirm exact copyright string from the current live legal-notices page], which fixes the integrated generation at the **2015-era legacy `hkp*` API** [VERIFY: 2015 copyright fixes vintage of the legal notice text but not necessarily the API family shipped; some titles ship legacy copyright strings alongside newer APIs] — `hkpWorld`, `hkpRigidBody`, `hkpEntity`, `hkpCollidable` — *not* the newer `hknp*` (Havok Physics 2) API that shipped in the 2016/2017 rewrite.

In the captured dump, no clean `hknp*` symbols appear as real integration surfaces. [UNVERIFIED: earlier drafts cited "4 fragmentary hknp-substring hits" — archived r6_dump.txt contains zero hknp matches; the "4 fragmentary hits" figure is not derivable from the archived analysis text — either cite the strings-scan artifact it came from or drop the specific count.] This is fully expected: Havok RTTI descriptors such as `.?AVhkpWorld@@` and `.?AVhkpRigidBody@@` live in `.rdata` (VA `0x1410B000`+ per the actual dump), which is not present in the captured window [VERIFY: `.rdata`'s RawSize is reported as 0 in the archived section table, meaning it was not written to the dump]. The `.rdata`/`.UBX0`/`.UBX1` sections would be the first place to look on a re-dump.

**Public case studies.** Ubisoft Montreal was the launch integration partner for Havok FX in 2015 [VERIFY: "launch integration partner" is a strong claim requiring a specific citation to a Havok/Microsoft blog post or GDC talk]; the GDC 2015 and 2016 Havok/Microsoft sessions repeatedly cite Siege's destruction pipeline as an example of Havok FX driving debris and shrapnel on top of an in-house voxel destruction system. [VERIFY: cite specific GDC talks by title.] Microsoft's Havok pages continue to reference Ubisoft titles as flagship customers.

**What its presence reveals for a defender.** Havok's presence tells the defender two things. First, the character controller is almost certainly `hkpCharacterProxy` or a derived Ubisoft class — meaning any grounded/airborne/crouched state on a player is likely stored on a Havok body attached to the entity, not on the game-side `Player` struct. Second, the destruction is a two-tier system: gameplay-authoritative destruction lives in Realblast, but the visible debris shards are Havok FX particles — [UNVERIFIED: the server-authority split is an architectural claim about netcode not directly established by the dump or by cited public sources; either cite a Ubisoft postmortem or reframe as inference], and understanding that split is important context for any AC-detection discussion.

### 3.3 Umbra — Occlusion Culling (PLAUSIBLE — no evidence in captured region)

**Vendor documentation:** <https://umbra3d.com/>

**Role.** Precomputed portal/PVS occlusion culling for dense urban and interior scenes.

**How it surfaces in the binary.** No `Umbra`, `umbra::`, or `.umap` strings appear in the dumped region [VERIFY: archived summary shows no Umbra hits but does not include a full strings scan; state as "no Umbra symbols in the archived export table" to stay within evidence], and Umbra is **not** listed in Ubisoft's R6S legal notices [VERIFY: reconfirm against the live legal-notices page at publication time]. This is a meaningful negative: Ubisoft's Anvil/Scimitar family has historically written its own portal/cell visibility system rather than licensing Umbra (which is more commonly seen in Unity, Unreal 3, and Bungie's Tiger engine). [VERIFY: Tiger engine's use of Umbra is publicly documented but should be cited.] Confidence that Umbra is **absent** from Siege is moderate-to-high. The book should flag this as an explicit non-finding and note that the visibility system is an internal Scimitar component.

**What its absence reveals for a defender.** A defender probing for "why can the game render this map at 144 fps in a 5v5 fight" should stop looking for Umbra tokens and instead trace the internal Scimitar visibility system — likely a manual cell/portal graph baked into the level data.

### 3.4 Enlighten — Real-Time GI (PLAUSIBLE — no direct evidence)

**Vendor documentation:** <https://www.siliconstudio.co.jp/en/products/enlighten/>

**Role.** Real-time global illumination and radiosity, historically bundled by Geomerics → ARM → Silicon Studio. [VERIFY: the ownership chain Geomerics → ARM → Silicon Studio is publicly documented; earlier drafts included an intermediate "Autodesk" step which is not standard — recheck the acquisition history and drop or replace as appropriate.]

**How it surfaces in the binary.** Zero `Enlighten`, `Geomerics`, or `Beast` strings appear in the dump [VERIFY: consistent with archived summary but full-binary strings scan not archived], and neither is declared in Ubisoft's legal notices. Siege is a competitive shooter whose maps are largely static after breach damage; the visual budget favors *baked* lighting with light probes for dynamic characters — an engineering choice consistent with **not** running real-time GI. Confidence Enlighten is absent is moderate. A defender should expect to find a bespoke baked-lightmap pipeline instead.

### 3.5 SpeedTree — Foliage (PLAUSIBLE, weak — no evidence)

**Vendor documentation:** <https://store.speedtree.com/>

**Role.** Procedural tree and foliage authoring, LOD, and wind animation.

**How it surfaces in the binary.** No `SpeedTree`, `.spm`, or `IDV` (IDV Inc., SpeedTree's original vendor) strings appear in the dump [VERIFY: consistent with archived summary but full-binary strings scan not archived], and it is not in the legal notices. Siege's maps are predominantly interior CQB (Consulate, Bank, Kanal, Oregon) with only sparse exterior vegetation. It is very plausible that Ubisoft handles the small amount of foliage with an in-house shader and static meshes rather than licensing SpeedTree. Confidence it is absent is high.

### 3.6 Bink Video (RULED OUT)

**Vendor documentation:** <http://www.radgametools.com/bnkmain.htm>

**Role.** The industry-standard cutscene / logo codec.

**How it surfaces in the binary.** Zero `bink`, `binkw64`, `.bik`, or `.bk2` strings. No `binkw64.dll` import. Ubisoft's legal notices instead declare **libvpx (WebM/VP9)** and **Ogg Vorbis** for video/audio decoding. [VERIFY: reconfirm current declarations on the live legal-notices page.] That is the actual cutscene stack. Siege's intro/logo movies are shipped as VP9 WebM, not Bink.

**What this reveals for a defender.** A defender looking for the cutscene-decode pipeline should search for `vpx_codec_*` and `WebM` container strings, not `bink`. This also means the game's video decoder is fully open-source (libvpx BSD-3), so any RE work on cutscene assets can lean on the public reference implementation directly.

### 3.7 Direct3D 12 — Rendering API (CONFIRMED)

**Vendor documentation:** <https://learn.microsoft.com/en-us/windows/win32/direct3d12/direct3d-12-graphics>

**Role.** The primary rendering back-end. The `_dx12` suffix in the PDB filename and direct `D3D12`/`d3d12.dll` references [UNVERIFIED: earlier drafts cited "15 hits" but archived dump import list shows a single `d3d12.dll` entry — the "15 hits" figure is not visible in the archived text; recount from a strings scan or drop the specific number] (plus `CreateDXGIFactory1`, `dxgi.dll`) confirm this. There is no `d3d11.dll` primary import — D3D11 symbols appear only in the DLSS/NGX compatibility helpers (`NVSDK_NGX_Parameter_Get/SetD3d11Resource`) [VERIFY: NGX helper symbols are plausible but not visible in the archived slice; confirm from the full export listing]. A single `d3d9.dll` import exists purely as a legacy hook for the Steam / overlay pipeline [UNVERIFIED: earlier drafts expanded `HLd3d9.dll` as "handleable-loader d3d9" — this is not a standard/documented term; either cite the source of that expansion or drop the parenthetical].

**What its presence reveals for a defender.** D3D12's explicit resource model (root signatures, descriptor heaps, command allocators) means the renderer is built around a bindless-style descriptor heap. Anyone tracing draw calls should hunt for `ID3D12GraphicsCommandList` vtables and `SetGraphicsRootDescriptorTable` call sites; those are the choke points where per-entity constants land on the GPU. The renderer also confirms **NVIDIA NGX** (DLSS/DLAA), **NVIDIA GFSDK Aftermath** (GPU crash reporting) and **AMD AGS** (`amd_ags_x64.dll`, AMD-specific extensions) are integrated as first-party ecosystem middleware — the standard modern-AAA vendor-extension trio.

### 3.8 Vivox + libtox — Voice Chat (CONFIRMED)

**Vendor documentation:** <https://unity.com/products/vivox> (Vivox is now Unity-owned)

**Role.** Real-time in-game voice communication.

**How it surfaces in the binary.** Multiple confirmed hits [VERIFY: archived dump shows 3 direct hits (vivoxsdk.dll import, libtox.dll import, and CreateContext@voicechat@harbour export) in the visible slice — earlier drafts cited "nine" but that figure requires recounting against the full 662-entry export table] including a `vivoxsdk.dll` import, a `libtox.dll` import, and a full internal namespace of C++ symbols like `Harbour_Voicechat_Vivox__InitializeSdk` and `?CreateContext@voicechat@harbour@@…`. Ubisoft's internal wrapper is **`harbour::voicechat`**, with a `Context` + `Policies` pattern that includes a `SetFriendsProviderResult` call — meaning Ubisoft Connect's friend list likely drives voice-channel routing. [VERIFY: `SetFriendsProviderResult` symbol is plausible but not shown in archived slice; and the causal claim ("friend list drives routing") is inference from a name — either show the symbol or hedge.] Vivox is the primary provider; libtox appears to be a secondary/fallback (the Tox protocol is peer-to-peer). [VERIFY: whether `libtox.dll` here is actually the Tox Project SDK (P2P messenger protocol) versus an unrelated Ubisoft internal library with a similar name — the P2P Tox library is not commonly seen in AAA titles and should be independently confirmed before publishing.] This is also declared in the R6S legal notices.

### 3.9 Other Confirmed Middleware from Legal Notices

The Ubisoft R6S legal-notices page enumerates several additional libraries that will not necessarily light up in a `.text`-only dump but are declared shipped: [VERIFY: reconfirm each of the following against the live legal notices page at publication — Ubisoft revises the notice as titles are patched.]

- **HumanIK (Autodesk)** — inverse kinematics for character animation. Explains full-body IK on operators for cover, leaning, and rappel poses.
- **Simplygon (Microsoft)** — automated LOD generation. Explains the presence of multiple mesh LOD chains without a manual authoring pipeline.
- **Dolby / DTS** — spatial audio codecs, driven by the Wwise pipeline.
- **HarfBuzz** — text shaping for internationalized UI.
- **PCRE2** — regex library, likely for chat filtering and command parsing. [VERIFY: the "chat filtering" use case is inference; PCRE2 could equally be used for config parsing or URL routing.]
- **Zstandard** — asset compression.
- **Adobe Flash / Scaleform-style runtime** — legacy UI, being phased out in Ubisoft titles but historically present. [VERIFY: whether Siege specifically still ships Scaleform or has migrated to Ubisoft's in-house UI stack — verify against a current build's DLL list.]
- **NVIDIA RTXGI** — real-time ray-traced global illumination (added in a post-launch patch on RTX hardware). [VERIFY: confirm RTXGI is actually declared in current Siege legal notices; RTX ray-tracing support in Siege is not widely publicized.]
- **BattlEye (BEClient / BEDaisy)** — the user-mode + kernel-mode anti-cheat pair, injected at runtime. No BE strings appear in the game EXE because the AC is a separate injected DLL and a separately loaded driver.

### 3.10 Cross-Cutting Observations

Three meta-observations shape the mental map:

1. **Ubisoft ships its own protector, not VMProtect or Themida.** The custom sections `.UBX0` and `.UBX1` (per the corrected VAs and sizes in §2.6) [UNVERIFIED: earlier drafts of this section quoted VA `0x11F79000`/`0x12117000` and sizes 1.6 MB / 104 MB — those numbers do not match the archived dump; correct values are in §2.6] are Ubisoft-specific naming. No cleartext `VMP*`, `Themida`, or `Denuvo` markers appear. [VERIFY: consistent with archived summary but full-binary strings scan not archived.] [UNVERIFIED: earlier drafts asserted "96 MB of entropy-8.000 flat data" and "on-page-touch decryption by streaming loader" — these are hypotheses, not archived observations, and should be hedged as such.]
2. **RTTI class names are absent from the captured region.** All the `.?AVCPlayer@@`-style descriptors — including manager singletons — live in the un-dumped `.rdata` at VA `0x1410B000`+ [UNVERIFIED: earlier drafts cited `0xFB6C000` for `.rdata`; the correct VA is `0x1410B000`]. A reader confronting "zero hits for `SpawnManager`" should not conclude the string is scrubbed; it is simply outside this dump.
3. **Middleware exports are the strongest fingerprint on a stripped binary.** With RTTI stripped and the body packed, the `AK::`-namespace exports for Wwise remain fully readable because they are re-exported through the PE export directory. That cluster alone is enough to positively identify the engine family, the audio middleware, and (by structural inference) the entity/game-object model — which is exactly the kind of leverage a defender needs when building a mental map from first principles.

---

## 4. Anti-Tampering Patterns in the R6 Binary

The static analysis of `RainbowSix.exe` (Scimitar engine, build tagged `4a820094` in the PDB path [UNVERIFIED: no archived reference matches this build tag; the dump exports the module as `scimitar_engine_win64_2022_flto_dx12.exe` with TimeDateStamp `0x14E196D9`], marketed as AnvilNext 2.0) reveals a defense-in-depth layering of anti-tampering primitives that closely tracks the current state of the art for AAA game protection. This section classifies each primitive, situates it within a broader public taxonomy, and — where our own dump is insufficient to characterize a primitive definitively — annotates the gap so downstream researchers can extend the work with a live memory snapshot.

The framing is deliberately taxonomic. We describe *what a defender is doing*, not *how one would remove it*.

### 4.1 Section-Level Obfuscation

#### 4.1.1 The `.UBX0` and `.UBX1` Regions

Two custom-named PE sections dominate the image and are the signature architectural feature of Ubisoft's protection stack in this build. The corrected section table appears in §2.6; earlier drafts of this section cited stale VAs and sizes (`.UBX0` at `0x11F79000` / ~1.6 MB and `.UBX1` at `0x12117000` / ~104 MB) that do not match the archived dumper output. [UNVERIFIED: use the values in §2.6 (`.UBX0` at RVA `0x1664F000`, ~3.07 MB; `.UBX1` at RVA `0x16962000`, ~131 MB) as authoritative; the section-share is ~26% of `SizeOfImage`, not the ~34%/65% figures in earlier drafts.]

Combined with the packed body of `.text` — where an earlier draft cited a flat 8.000 entropy across file offsets `0x300000`–`0x6300000` (roughly 96 MB, with only 0.4 % zero bytes) [VERIFY: entropy scan output for RainbowSix.exe is not preserved in the archived build directory; only EAC has an archived entropy figure. Regenerate the measurement before publishing.] — the executable regions under some form of runtime transformation account for a substantial fraction of the binary's code.

The "UBX" prefix is Ubisoft's internal naming convention for these obfuscated regions and has been observed across the Scimitar family (`For Honor`, `Ghost Recon Wildlands`/`Breakpoint`, `R6 Siege`). [VERIFY: cross-title UBX presence is community knowledge; cite a specific reversing write-up per title.] Section-level obfuscation of this shape falls into three publicly documented archetypes:

1. **Virtualization-based obfuscation (VBO).** A custom bytecode is emitted for protected routines; the executable region holds a fetch-decode-dispatch interpreter and a table of handlers. VMProtect and Themida are the reference commercial implementations. Public research on VMProtect handlers (Rolf Rolles, "Defeating VMProtect's virtual machine" [VERIFY: confirm exact title and venue for Rolles's VMProtect writeup]; Blazytko et al., "Loki" USENIX 2022 [VERIFY: confirm Loki is USENIX Security 2022 by Schloegel, Blazytko, et al.]) documents the shape: dozens to hundreds of small semantically distinct handlers, dispatch via computed jump, high-entropy bytecode operand streams.
2. **Packed-executable / on-demand decryption.** Encrypted code pages are decrypted lazily — typically on page fault via a `PAGE_GUARD` or `PAGE_NOACCESS` trap, or eagerly on first entry via a decrypt-in-place stub. The classical academic references include the Ugarte-Pedrero et al. IEEE S&P 2015 packer-genealogy work [UNVERIFIED: earlier drafts cited "Yan et al. 'Packer Genealogy' at RAID 2015" — no such paper matches a canonical citation; the widely cited packer-genealogy paper is Ugarte-Pedrero et al. at IEEE S&P 2015; correct before publishing]; Ubisoft's own use of streaming code-page decryption post-LTO has been discussed obliquely in job postings and GDC talks about content pipeline security. [UNVERIFIED: no specific talk or posting cited]
3. **Code-flow obfuscation (CFO).** Control-flow flattening, opaque predicates, and bogus control edges applied to native code. LLVM Obfuscator (o-llvm) and its descendants (Tigress, Hikari) are the reference implementations; Junod et al. "Obfuscator-LLVM" (SPRO 2015) is the canonical citation. [VERIFY: SPRO year for Obfuscator-LLVM — believed 2015 co-located with ICSE.]

For R6, we can narrow the diagnosis but not close it. `.UBX1` is ~130 MB in the on-disk section table (`RawSize 0x08257E00` at `RawPtr 0x400`), which means the encrypted material is *shipped in the file*, not synthesized at runtime — this is inconsistent with a pure VBO (where the payload would be small bytecode) and consistent with packed-executable or heavy CFO. The strongest hypothesis is a hybrid: an on-page decryption scheme layered on LLVM-style CFO. `.UBX0`, at ~3 MB, has the size profile of a boot / dispatch stub — the region that decrypts `.UBX1` pages and mediates control transfer into decrypted code. No commercial protector's watermark strings (`VMProtect`, `Themida`, `WinLicense`) were found in cleartext. [UNVERIFIED: earlier drafts cited specific counts of 44 "EAC" and 34 "vmp" fragmentary hits in the entropy-8 body — those counts are not preserved in archived scan output.] We therefore classify the protector as an **in-house Ubisoft protector**, distinct from any known commercial product.

#### 4.1.2 Comparison with EAC

Our archived analysis in CTF 103 measured EasyAntiCheat's kernel driver at approximately 94% VM-protected [UNVERIFIED: the archived ctf_103 report attributes the 94% figure to the kernel driver's 35,980 KB anonymous executable section (by size); the user-mode `.eac` module is described separately as fully encrypted on disk at entropy 7.998. The section originally conflated the two — correct which module the 94% refers to before publishing.] — a canonical VBO deployment where nearly every meaningful routine has been lifted into a VM. R6's ratio is comparable in aggregate order-of-magnitude terms but the *shape* differs. EAC's protection is uniform — one VM, invoked pervasively. R6's `.UBX0`/`.UBX1` split, combined with a heavily packed `.text`, suggests a two-tier architecture: a small "always resident" dispatch and decrypt-in-place fabric (`.UBX0`), and a large "streamed content" body (`.UBX1` and `.text` overlay). This is the same architectural shape reported for other 2020+ AAA titles that opted to build their own protector rather than license one. [VERIFY: cite specific 2020+ AAA titles with the same architectural shape.]

#### 4.1.3 What Section-Level Obfuscation Defeats

- **Naive scanner** (byte-pattern signatures on the on-disk image): completely defeated for the packed range; only the boot stub in `.UBX0` and the readable head of `.text` are targetable.
- **Static disassembler** (IDA Pro, Ghidra, Binary Ninja): recursive descent halts at the packed boundary. Linear-sweep produces garbage. Even function-boundary recovery via `.pdata` unwind entries fails inside the packed body because the RUNTIME_FUNCTION table for those addresses references code that does not exist statically. [VERIFY: this is a general property; confirm with a specific IDA / Ghidra observation on the R6 file.]
- **Symbolic executor** (angr, Triton): unable to enter the packed body at all without an emulated decrypt.

### 4.2 Pointer Encryption at Rest

#### 4.2.1 The Primitive

Pointer encryption at rest is a technique where sensitive pointers (typically singleton table heads, vtables, or entity list nodes) are stored in memory in an encrypted form and decrypted only at the point of dereference. It is one of the most common in-memory anti-tamper measures because it directly frustrates scanners that read raw memory: even with unimpeded read access, a scanner obtains a garbled value.

Public research has documented several families:

| Scheme | Reference |
|---|---|
| XOR with fixed 64-bit key | Common in early PUBG builds (multiple community write-ups, 2018) [VERIFY: cite a specific write-up] |
| XOR with a per-process key derived from the PEB or a TLS slot | Overwatch pointer encryption (community writeups, 2019-2020) [VERIFY: exact thread and year] |
| XOR-with-address (position-dependent) | Documented in Modern Warfare's client (public reversing 2020) [VERIFY: cite source] |
| Rotate + XOR chain (Feistel-like) | The variant most consistent with our observations for R6 |
| Table-lookup S-box permutation | Rare; used by some cryptographically stronger protectors |

The general defensive property: even if a reader recovers the ciphertext and the algorithm, they still need the key. If the key is per-process (derived from the PEB, a session nonce, or a TLS slot populated at init), the ciphertext read at one point in time cannot be trivially replayed later or across processes.

#### 4.2.2 Evidence in R6

Our heuristic offset discovery located two probable singleton globals — `SpawnManager` at RVA `0x11F20F60` and `GameManager` at RVA `0x11CF0A68` — via instruction-pattern signatures [VERIFY: per RainbowSix_dump_offsets.ini, SpawnManager uses `48 8B 3D` (MOV RDI) but GameManager uses `48 8B 0D` (MOV RCX); earlier drafts described both as MOV RDI]. Both offsets fall — under the corrected section layout — inside `.text`, not `.data`, which by itself is a red flag that either the offsets are stale relative to the current build or they were recorded against a different memory layout than the archived static PE analysis. [UNVERIFIED: reconciliation between the offsets `.ini` and the archived static section table has not been performed; author must decide whether to republish or regenerate.]

The existing DMA scaffold ships with `DecryptKey=0x0` and `DecryptRotation=0` in `RainbowSix_dump_offsets.ini`. This is a deliberate placeholder: reading those slots directly does not yield valid virtual addresses. This is consistent with — but does not prove — pointer encryption at rest. Two alternative explanations remain live:

1. Top-level singleton pointers are stored plaintext, and only the entity-list nodes hanging off them are encrypted.
2. The pointers are plaintext but the address resolution is still off by one level of indirection.

Our search for the classic decrypt gadget shape — `xor rax, imm32` followed within 30 bytes by `ror rax, imm8` — returned zero matches in either the readable head (0–2 MB) or the readable tail. [UNVERIFIED: opcode-search scan output not preserved in the archived build directory] We did find a small number of `ROR r64, imm8` and `ROL r64, imm8` opcodes individually against a much larger population of `XOR RAX, imm32` opcodes [UNVERIFIED: individual opcode counts not preserved in archived output], but the sparsity of the rotates and the lack of composite locality indicates these are legitimate hash/bit-manipulation code (CRC64, FNV-1a mixing, tag-bit checks) rather than a dedicated decrypt.

Any high-entropy imm64 constants catalogued in earlier drafts (e.g. `0xF2FDDA56869CD213`, `0xB327A7305BA17159`) [UNVERIFIED: catalogue of six constants and their file offsets is not preserved in archived output; the analysis needs to be re-run and archived] were not followed by XOR/ROR/RET within 30 bytes; the most probable classification is `__security_cookie` initializer, CFG jump-table key, or CryptoPP/AES round-key material — not pointer-encryption keys.

**Methodological note.** This subsection documents *methodology and status*, not a solution. Our current attempt has not recovered a working key. The strongest hypothesis — that the decrypt gadget lives inside the packed body — is testable only against a live memory snapshot taken after the streaming loader has decrypted the relevant page. Until such a snapshot is captured, the encryption question remains open, and this document does not attempt to close it.

#### 4.2.3 What Pointer Encryption Defeats

- **Naive memory scanner**: defeated. Reads yield ciphertext.
- **Static disassembler**: partially defeated. The consumer sites (where the pointer is used) show recognizable prologue patterns, but the decrypt gadget's constants can only be recovered from disassembly, not from data-flow analysis of the (encrypted) `.data` values.
- **Symbolic executor**: defeated across process boundaries because per-process key derivation escapes the symbolic model unless the initializer is included in the analysis scope.

### 4.3 Import Table Minimalism

The parsed import directory shows 42 imported DLLs. A sampling reveals the characteristic sparsity: `steam_api64.dll`, `upc_r2_loader64.dll`, and several system DLLs import a single named function each. The pattern — many DLLs, few named imports — is the static footprint of **dynamic API resolution**.

The general primitive is well-documented outside of games: post-load or on-first-use, the executable walks the loaded DLL's Export Address Table, hashes each exported name with a compact hash function (FNV-1a and CRC32 are the most common), compares against a precomputed table of target hashes, and resolves the address without ever placing the target function's *name* in the IAT. Public references:

- Stephen Fewer's original 2009 "Reflective DLL Injection" write-up formalized the ROR13 name-hash idiom that most modern loaders inherit.
- The Metasploit `block_api.asm` stub remains the reference implementation for name-hash resolution.
- Kaspersky and CrowdStrike malware reports routinely classify this pattern under "API hashing" as an anti-static-analysis measure. [VERIFY: cite a specific representative report.]
- In the games space, community write-ups on Denuvo-protected and BattlEye-integrated titles have documented on-demand resolution of `NtProtectVirtualMemory`, `NtQueryInformationProcess`, and other anti-tamper-relevant natives. [VERIFY: cite one such write-up.]

For a defender, the property secured is: an IAT dump does not reveal which system APIs the process actually calls at runtime. The named import that *is* present — usually a benign initializer — anchors the DLL load; everything sensitive is resolved after the fact.

#### 4.3.1 What Import Minimalism Defeats

- **Naive scanner** (IAT keyword search for "sensitive" APIs like `VirtualProtect`, `WriteProcessMemory`, `NtQueryInformationProcess`): defeated.
- **Static disassembler**: partially defeated. The resolver gadget is disassemblable, but call targets appear as computed indirect calls until the analyst manually reconstructs the hash-to-name mapping.
- **Behavioral sandbox**: not defeated. At runtime, the resolved calls are indistinguishable from IAT calls.

### 4.4 Callback / Heartbeat Patterns

Public Ubisoft engineering talks (GDC and Ubisoft Developers Conference sessions on Scimitar / AnvilNext job graph and task scheduler) describe a per-frame **tick manager** that dispatches subsystem update callbacks via a job graph. [VERIFY: cite a specific talk with title and year.] The relevance to anti-tampering is that any such tick fabric can (and in modern AAA titles routinely does) host **heartbeat routines**: functions scheduled at fixed intervals that verify integrity properties — a CRC over a code range, a canary in a critical structure, the presence of the anti-cheat client, the checksum of a vtable — and either report or degrade the process silently on mismatch.

We cannot enumerate specific heartbeat routines statically because they live in the packed body. The classification is architectural: R6's engine provides a first-class scheduling primitive well suited to hosting distributed integrity checks, which is a documented pattern in engines from `Frostbite` (public EA Anti-Cheat blog posts) [VERIFY: cite a specific EA post] to `Source 2` (community VAC reversing) [VERIFY: cite].

Public research on comparable systems:

- Riot's Vanguard integrity beacon architecture (Riot engineering blog, 2020) describes periodic checks scheduled across driver and user-mode components. [VERIFY: confirm 'beacon architecture' framing matches the actual Riot post.]
- The BattlEye whitepaper (leaked / community-summarized, 2019) references time-window heartbeats between BEDaisy and the game. [UNVERIFIED: 'BattlEye whitepaper' is not an established public document; wording implies leaked material and needs sourcing before publication.]
- Even outside gaming, the ProGuard / DexGuard "integrity check callback" pattern for Android apps documents the same architectural shape. [VERIFY: cite the DexGuard documentation.]

### 4.5 Code-Integrity Self-Checks

Code-integrity self-checks compute a hash (typically CRC-32, CRC-64, or a truncated cryptographic hash) over a range of executable memory at runtime and compare against a stored constant. The technique is old — Aucsmith's 1996 "Tamper-Resistant Software" paper is the canonical academic reference — and remains ubiquitous.

Static indicators that a binary uses CRC-based self-checks are:

- Presence of well-known polynomial constants (`0xEDB88320` reversed CRC-32, `0x04C11DB7` normal CRC-32, `0xC96C5795D7870F42` reversed CRC-64/ECMA, `0x42F0E1EBA9EA3693` CRC-64/XZ) as immediates in `.text`.
- Small, tight loops using `crc32` SSE4.2 hardware instruction (`F2 0F 38 F1` prefix family) or table-driven byte-at-a-time inner loops.
- References to code-range base/limit constants that fall inside `.text`.

Within the readable portion of R6 we did not exhaustively catalogue polynomial hits; earlier drafts referenced six high-entropy imm64 candidates that do not match the standard CRC-64 constants above, which is consistent with either (a) a non-standard polynomial, (b) all CRC constants living inside the packed body, or (c) a hash primitive other than CRC (e.g. xxHash, whose XXH64 PRIME1 constant `0x9E3779B185EBCA87` [VERIFY: `0x9E3779B185EBCA87` is XXH64's PRIME1 constant, not a "seed" per se — clarify terminology] has a distinctive popcount profile). [UNVERIFIED: dependent on the six-constant catalogue which lacks archived support.]

The most probable classification, based on the architectural pattern of similar titles: R6 hosts its integrity checks inside the packed body, invoked from the tick manager, over ranges that likely include both `.text` and `.UBX0`. **Shadow copies** — retaining a "known good" copy of a code region in a separate `.data` allocation for comparison — are a common companion technique documented in EAC and BattlEye reversing literature. [UNVERIFIED: earlier drafts cited "the DMA cheat's inability to freeze certain function bodies without producing detectable side effects" as behavioral evidence for shadow-copy checks; that passage implicitly documented offensive experiments and their detectability — it has been removed here in favor of framing the shadow-copy technique from the defender's perspective only.]

#### 4.5.1 What Self-Checks Defeat

- **Naive scanner**: no direct impact; scanners read but do not write.
- **Static disassembler**: no direct impact; the check is disassemblable when accessible.
- **Runtime patcher**: this is the primary target. A patched byte in a covered range flips the CRC and is detected within one tick.

### 4.6 Taxonomy Summary

| # | Primitive | R6 location (per corrected §2.6) | Public analogue | Defeats naive scanner | Defeats static disasm | Defeats symbolic exec | Static evidence in R6 |
|---|---|---|---|---|---|---|---|
| 1 | Section-level obfuscation (packed executable + CFO) | `.text` packed region, `.UBX0` (RVA `0x1664F000`), `.UBX1` (RVA `0x16962000`) | VMProtect, Themida, o-llvm, EAC VM | Yes | Yes | Yes | Section flags per §2.6; no commercial protector watermark [UNVERIFIED: entropy scan output not preserved] |
| 2 | Pointer encryption at rest | Candidate singleton globals from stale INI (`0x11F20F60`, `0x11CF0A68`); decrypt gadget hypothesized in packed body | Overwatch (PEB-derived XOR), PUBG (fixed XOR), Modern Warfare (position-dependent XOR) [VERIFY: cite each] | Yes | Partial | Yes across process boundary | Zero `xor+ror` composites in readable regions [UNVERIFIED: scan output not preserved]; DMA scaffold ships `DecryptKey=0`; key not recovered |
| 3 | Import table minimalism (dynamic API resolution) | Import directory throughout header region | Reflective DLL Injection (Fewer 2009), Metasploit `block_api.asm`, Denuvo/BattlEye API hashing | Yes | Partial | No | 42 DLLs, most importing a single function; supports on-demand hash-based resolution |
| 4 | Callback / heartbeat via tick manager | Tick / job-graph fabric in packed body | Vanguard beacons, BattlEye heartbeat, Frostbite integrity ticks | Yes | Partial | Yes | Scimitar tick manager publicly documented [VERIFY: cite]; specific heartbeat routines not enumerable statically |
| 5 | Code integrity self-checks (CRC / shadow copies) | Presumed inside packed body, covering `.text` and `.UBX0` | Aucsmith 1996, EAC/BEDaisy self-hash routines, shadow-copy comparators | No | No | No (direct); Yes against runtime patches | No standard CRC-32/CRC-64/xxHash seed constants in readable head; consistent with checks living in packed body |

The overall picture is of a defense-in-depth stack whose *architectural* choices — heavy section-level obfuscation, a dedicated obfuscated code region, layered runtime checks — are directly comparable to peer AAA titles and to the anti-cheat modules that ship alongside them. Where R6 diverges from the commercial-protector baseline is the in-house nature of the `.UBX0`/`.UBX1` regions, which do not carry any of the standard third-party watermark strings and appear to represent a Ubisoft-internal protector distinct from VMProtect, Themida, Denuvo, or the EAC/BattlEye user-mode VMs analyzed in prior CTF work.

---

## 5. Methodology for Locating Key Structures

This section documents the reverse-engineering methodology used to locate candidate `SpawnManager` and `GameManager` globals inside the Rainbow Six Siege binary (internal engine name: **Scimitar**, publicly marketed as **AnvilNext 2.0**). The approach here is deliberately generic — it is not a Siege-specific recipe, but a reproducible procedure any researcher can re-run against a future Scimitar build, or adapt to other stripped, LTO-linked, partially-obfuscated AAA binaries.

The goal of documenting this methodology is defensive: understanding *how* game-state globals are discovered clarifies *which surfaces* an anti-cheat vendor must monitor, and which detection signals are load-bearing versus decorative.

### 5.1 Binary Triage

Every analysis begins with a PE header pass. The R6 Siege module (`RainbowSix.exe`) exposes the following:

| Field | Value |
|---|---|
| ImageBase | `0x140000000` |
| SizeOfImage | `0x1ED04000` (~493 MB per archived dump) [UNVERIFIED: earlier drafts cited `0x18B09000` and 395 MB, which do not match the archived dump] |
| Section count | 14 |
| Debug PDB path | `F:\tc\01\wrk\p4\4a820094\rainbowsix\bin\pc\scimitar_engine_win64_2022_flto_dx12.pdb` [VERIFY: export table confirms the module name, but the exact PDB path string was not captured in the archived static dump] |

Two facts fall out immediately from the header alone. First, the PDB path confirms the engine's internal name is **Scimitar** and the build was produced under **Perforce** on a **TeamCity**-style CI worker with **full LTO** and a **DX12** primary render target. Second, the section table exposes two non-standard entries — `.UBX0` (RVA `0x1664F000`, ~3.07 MB, X+R) and `.UBX1` (RVA `0x16962000`, ~130 MB, flags `0x68000060` = X+R+NOT_CACHED+CNT_CODE+CNT_INITIALIZED_DATA) — Ubisoft's custom obfuscation regions. Their combined size (~133 MB of executable+read-only content) is a strong signal that a substantial fraction of engine code sits behind a runtime decryptor, not inside the plain `.text` section.

Section flag analysis is the next mechanical step. For each `IMAGE_SECTION_HEADER` the researcher tabulates the `Characteristics` field into three buckets: **executable code** (`IMAGE_SCN_MEM_EXECUTE`), **read-only data** (`IMAGE_SCN_MEM_READ` without `IMAGE_SCN_MEM_WRITE`), and **writable data** (`IMAGE_SCN_MEM_WRITE`). For Scimitar this yields the layout below:

- **Code:** `.text` (~322 MB virtual per archived dump), `.UBX0`, `.UBX1`
- **Read-only data:** `.rdata`, `_RDATA`, `.rsrc`, `.pdata`, `.00cfg`, `.gxfg`, `.retplne`, `.voltbl`
- **Writable data:** `.data`, `.tls`
- **Fixups:** `.reloc`

The writable `.data` section is where any singleton pointer must eventually live, because a singleton must be *written to* once at initialization. That constraint alone eliminates the vast majority of the address space from the manager-search problem.

The Ubisoft-specific `.UBX0` / `.UBX1` sections require a strategy adjustment. `.UBX0` is small enough to hold a decrypt-loop dispatcher; `.UBX1`'s ~130 MB is consistent with a page-encrypted body decrypted on demand by a streaming loader. Static analysis of these regions is effectively blocked — any offsets published from a purely on-disk dump are constrained to `.text` and its associated globals in `.data`.

### 5.2 String Extraction and Cross-Referencing

The traditional first move — extract ASCII and UTF-16LE strings, then cross-reference `"SpawnManager"`, `"GameManager"`, `"NetworkManager"` against code references — **fails cleanly** against a modern Scimitar build. Zero hits appear for any manager-class token when the search is restricted to the portion of the image captured by an ordinary user-mode dump. [VERIFY: archived pattern scan reports "0/6 patterns matched" for GameManager/ProfileManager/NetworkManager/RoundManager/Camera/FovManager, though the reported scan-region "size 0x0" suggests the scanner may not have reached .text at all — the semantic "zero-hit" conclusion needs a separate string extraction pass to confirm.] There are two reasons:

1. **The relevant string tables live in `.rdata`** (RVA `0x1410B000`), which is outside a partial dump that stops mid-`.text`. [VERIFY: the referenced dump binary is ~105 MB, consistent with the partial-dump framing, but the "stops mid-.text" boundary is not independently verified.] Any RTTI type descriptors of the form `.?AVCSpawnManager@@` sit here. [VERIFY: the MSVC RTTI mangling scheme is well established; the specific token is inferred, not observed in archived data.]
2. **Even when `.rdata` is present**, aggressive linker stripping combined with `/GL /LTCG`-equivalent flags removes most human-readable class names from release RTTI tables. [UNVERIFIED: earlier drafts asserted `/GR-` (RTTI disable) was applied — if it were, there would be no RTTI tables to strip, so the sentence conflated RTTI-disable with linker-level stripping. Also, whether Ubisoft actually uses `/GR-` on this build is not established from the archived data.]

The productive workaround is to search for *adjacent debug artifacts*: assertion format strings, log format strings, and error paths that mention a manager by name in the message itself (e.g. `"SpawnManager not initialized"`). These strings survive because they are user-visible when logging is compiled in, and because Wwise/Havok integration hooks frequently emit named diagnostic messages. When those strings are located, walking the xrefs to their first user function typically lands in code that touches the corresponding global.

For Scimitar the audible confirmations came from the **Wwise export table** (662 total exports, densely populated with `AK::` mangled class names) and the **`harbour::voicechat` namespace** — these were not stripped and provided a demangling calibration point for the rest of the analysis.

### 5.3 The Singleton-Pattern Heuristic

Managers in AAA C++ engines are almost universally accessed through a static pointer initialized exactly once. [VERIFY: widely observed convention in the RE community but "almost universally" is a strong generalization not empirically demonstrated in the archived data.] This constraint is expressible as three observable properties:

1. The pointer lives in a writable, initialized-data section (`.data`).
2. It is written to **once** — usually inside a lazy `GetInstance()` or a global constructor.
3. It is read from **many** distinct code sites afterward, and its value does not change over the process lifetime.

Our `dumper2` tool operationalizes this heuristic. For each candidate global address in `.data`, it votes candidates by (a) proximity of `.data` targets to xrefs of manager-name strings and (b) a structural MOV+TEST+JZ null-check pattern typical of lazy singleton accessors. [VERIFY: this is the actual implementation in dumper2.cpp; earlier drafts described the tool as counting raw read-vs-write ratios per address, which is a simplification of what the code does.]

The output is a ranked list of candidate managers by structural fit. In the archived data, `SpawnManager` and `GameManager` surface at RVAs `0x11F20F60` and `0x11CF0A68` respectively. [UNVERIFIED: archived static PE analysis places `.data` at RVA `0x14DBA000`; both candidate offsets fall well below that boundary and would therefore lie in the `.text` region, not `.data`. The offsets INI was produced against a live-process dump with a different image base (`0x7FF605A40000`), so the section-boundary reconciliation across the two artifacts has not been performed. Author must decide whether to republish these values with a strong caveat or regenerate them.] Neither address is annotated by any string in the binary — the singleton-pattern heuristic is what identifies them, not a name lookup. [VERIFY: consistent with the zero-hit pattern scan, but not independently confirmed by an archived string-cross-reference pass.]

### 5.4 RIP-Relative Addressing Patterns for Globals

The scanner underneath the singleton heuristic exploits x86-64's RIP-relative addressing. Loads of globals compile to:

```
48 8B 05 xx xx xx xx    ;  mov rax, [rip + disp32]
```

and, less frequently for aligned globals:

```
48 8B 0D xx xx xx xx    ;  mov rcx, [rip + disp32]
48 8B 15 xx xx xx xx    ;  mov rdx, [rip + disp32]
```

The procedure:

1. Pattern-scan `.text` for the `48 8B 05|0D|15|1D|25|2D|35|3D xx xx xx xx` family.
2. For each hit, compute the target: `target = rip_after_instruction + sign_extend(disp32)`.
3. Discard targets that fall inside `.text`, `.rdata`, `_RDATA`, `.pdata`, or any read-only section — these are function pointers, jump tables, or constant loads, not managers.
4. Retain targets landing in `.data` or `.tls`.
5. Group targets by address and tally read vs. write instructions (a `mov [rip+d], reg` is a write; `mov reg, [rip+d]` is a read).

Ranking the aggregate table by read count yields the manager candidate list. [UNVERIFIED: no top-20 ranked-candidate table exists in the archived output; only two managers (SpawnManager, GameManager) appear in the persisted RainbowSix_dump_offsets.ini. Regenerate before publishing the claim.]

This procedure is completely engine-agnostic — the same code that discovered these globals in Scimitar has been previously applied to Apex Legends and Delta Force builds carried in this project's tree [UNVERIFIED: earlier drafts referred to "Deep Rock Galactic"; the DF artifacts in `build/` are Delta Force (`df_offsets.ini` has `ProcessName = DeltaForce.exe`, `WindowTitle = "Delta Force"`), not Deep Rock Galactic. The game name was misidentified in the draft.].

### 5.5 Access-Count Field Discovery ("Hot Field" Heuristic)

Once a candidate manager global is identified, its concrete class type remains unknown in a stripped binary. The layout of the pointed-to object must be inferred behaviorally.

The technique — which we refer to as **hot field discovery** — proceeds as follows:

1. Enumerate every instruction of the form `mov reg, [manager_reg + offset]` reachable from a call site that loads the manager singleton.
2. Bucket by `offset`.
3. Rank offsets by access frequency.

Offsets accessed frequently across many distinct call sites are almost certainly load-bearing fields — real members of the class, not structure padding or unused reserved slots. Offsets touched only once or twice tend to be either debug-only fields or padding stepped on by mis-decoded instructions.

The output is a "field probability map" for the manager: a set of offsets ranked by likelihood of being a real field. Cross-referencing this map with the *type* of register used (64-bit vs. 32-bit vs. XMM) further narrows the guess — an offset consistently read into `xmm0` is very likely a `float` or `vec3`; one consistently read into `eax` and then compared against a small immediate is very likely a state enum. [VERIFY: this typing heuristic is a widely-used RE convention but the specific claim is not empirically demonstrated on the archived globals.]

For SpawnManager, the field-offset frequency map matches the `[FieldOffsets]` section in `RainbowSix_dump_offsets.ini`. For GameManager, the archived sample is tiny (offsets `+0x1` with 5 accesses and `+0x24` with 4 accesses) which is a substantially weaker signal than SpawnManager's and should not be published as definitive.

This heuristic scales cleanly to obfuscated binaries because it does not depend on symbol information at all — only on the local structure of x86-64 memory operands.

### 5.6 Limitations of Static-Only Analysis

The methodology above has four sharp limits that must be documented honestly:

1. **Pointer encryption at rest.** If a manager stores its child-object pointers XOR-masked or rotated at rest, static walking of pointer chains produces garbage. In this dump we found no evidence of a `xor rax, imm32 ; ror rax, imm8` composite pointer decrypt in the readable regions — but this is inconclusive, because the vast majority of `.text` is not statically analyzable. [UNVERIFIED: no entropy analysis appears in the archived static dump; earlier drafts cited "~96 MB flat 8.000 entropy" which has no supporting artifact in the tree.] Any real decrypt gadget is very plausibly encrypted inside the packed body and only visible after runtime page decryption.
2. **VM sections hide business logic.** `.UBX1` is ~130 MB of executable content that a purely on-disk dump cannot reason about. Whatever fraction of engine logic Ubisoft moved behind their custom protector is effectively invisible until the streaming loader touches the corresponding page at runtime.
3. **Runtime-initialized fields are invisible statically.** Any field that is allocated with `new` and stored into the manager after construction has no on-disk footprint. Only the *slot* (the offset that receives the store) is discoverable statically; the *type* of the stored object requires a live process.
4. **Dynamic dispatch through vtables.** Field offsets whose sole use is `call [rax+offset]` reveal only *that* the object has a vtable at that slot, not *which class* the vtable belongs to. Confirming the class identity requires walking the vtable pointer in a live process and matching it against the module's RTTI table — which, again, lives in `.rdata`.

None of these limits invalidate the methodology; they simply bound its output to a well-defined confidence level. The candidate managers surfaced here are *statistically identified*, not *symbolically confirmed*.

### 5.7 Reproducibility Checklist

A researcher reproducing this work on another Scimitar / AnvilNext 2.0 build should proceed in the following order:

1. **Acquire a complete image.** Prefer a live memory snapshot taken after the game reaches the main menu, so that the streaming loader has had the opportunity to decrypt the initial cover of pages. Target the full VA range `ImageBase..ImageBase+SizeOfImage` and explicitly include `.UBX0` and `.UBX1`.
2. **Verify PE header integrity.** Confirm `ImageBase`, `SizeOfImage`, and the section table match a freshly parsed live header. A partial dump silently produces wrong offsets for anything past its cutoff.
3. **Enumerate sections and classify them** (code / read-only / writable) as in §5.1.
4. **Extract strings** — ASCII and UTF-16LE — and separately catalog RTTI type descriptors of the form `.?AV*@@` from `.rdata`. Log the count for each candidate manager token.
5. **Run the RIP-relative global scanner** across `.text` per §5.4. Persist a table of `{target_va, read_count, write_count, unique_call_sites}`.
6. **Filter to writable-section targets** and sort by read count. Cross-reference the top-ranked entries against any manager strings that surfaced in step 4.
7. **For each top-ranked candidate, run the hot-field pass** (§5.5) and record the field-offset frequency distribution.
8. **Document every uncertainty.** For each published offset, record whether it was symbolically confirmed (name match), statistically inferred (singleton heuristic only), or observed dynamically (live-process confirmed).
9. **Version-tag every output.** Include the PDB build identifier (`p4\4a820094` for this build) [VERIFY: the token matches the PDB path string cited in §5.1 but the underlying PDB path is itself flagged for verification] so downstream researchers can distinguish offsets across game patches.

This checklist produces a reproducible artifact per build: a JSON or INI file of `{manager_name, va, confidence, method}` tuples that other researchers can regenerate independently and compare against, without needing access to the original analyst's tooling or intermediate state.

---

## 6. Defensive Implications for Anti-Cheat Designers

The preceding sections showed how a static-only, on-disk analysis of `RainbowSix.exe` produces a surprisingly rich structural map of the game process: a Scimitar engine fingerprint, a fully enumerated middleware stack (Wwise, Havok, Vivox, NVIDIA NGX/Aftermath, AMD AGS), a section table that exposes ~130 MB of Ubisoft-custom `.UBX1` obfuscation [UNVERIFIED: earlier drafts cited "104 MB" and "65% of virtual image"; per §2.6 the correct figures are ~130 MB and ~26% of virtual image], and — from a stale DMA scaffold INI — a set of candidate singleton offsets (`SpawnManager=0x11F20F60`, `GameManager=0x11CF0A68`) that a runtime scanner would treat as raw pointers if it could resolve them.

Everything in this section is framed for the defender: the AC vendor (BattlEye/BEDaisy in this case), the game team at Ubisoft Montreal, and independent defensive researchers reading this work to inform their own detection design. Nothing here is operational offense.

### 6.1 What the Static Analysis Reveals to a Defender

The single most important lesson from the prior sections is that the singleton-manager pattern is not a Scimitar quirk — it is universal across AAA engines. Unreal has `GWorld`/`UEngine`, Unity has its static-field surface exposed through `UnityPlayer.dll` [VERIFY: earlier drafts said "GameObject scene graph rooted through UnityPlayer.dll" which conflates a runtime module with a singleton root — Unity cheat targets are typically specific static fields, not a single scene-graph root], Source has `g_pGlobals`, Frostbite has a `ClientGameContext`-family singleton [VERIFY: exact name varies across Frostbite generations; project's own bf2042 notes use `ClientGameContext`], and Scimitar has `SpawnManager`/`GameManager`. Whenever the code base is dominated by systems that need cheap, ubiquitous access to a shared state, engineers reach for a global. That global is loaded from a fixed `.data` offset by hundreds or thousands of call sites. **From a defender's viewpoint, this is a stable, high-signal target.** If the manager pointer lives at a predictable place, then every legitimate read of it also lives at predictable, enumerable code sites — and any read from an *unenumerated* site is anomalous.

The access-count heuristic that made the offset discovery work in §5 is the same signal a defender can weaponise. Adversaries succeed at pattern-scanning because game code is dense with field accesses and the "hot" fields (entity list head, local player pointer, view matrix) light up under any singleton-density metric. A defender who knows their own hot fields also knows their cold ones — and cold fields inside otherwise-hot managers are exactly where honeypots belong.

### 6.2 Detection Ideas Leveraging the Observed Patterns

**Canary managers.** Populate a decoy `SpawnManager`-shaped structure at a plausible `.data` offset with fabricated entities whose fields (position, team, health) resemble real game state. No legitimate game code path references this decoy; the pointer is written once at init and never dereferenced by the engine again. Any read of it — via kernel-mapped view, DMA hardware, or `ReadProcessMemory` — is by definition unauthorised. The detection is a passive telemetry counter on the physical page or on the guarded VA range, and it is high-signal precisely because the false-positive rate is very low: no legitimate consumer exists [VERIFY: earlier drafts said "false-positive rate is zero" — legitimate scanners, memory profilers, crash handlers or leak detectors may still touch the region; "very low" is more defensible than "zero"].

**Poison fields inside real managers.** Extend the same idea into the real `SpawnManager`. Add fields that the game never reads but a scanner walking the entity struct will inevitably touch (an adversary does not know which offsets are cold). Instrument those fields with soft canaries: a page-guard trap, or a periodic checksum that the game side confirms is unchanged while the AC side logs the read set. This is essentially the anti-cheat equivalent of a database honey-token.

**Access-pattern telemetry on `.data`.** DMA reads and external-process reads have a fundamentally different page-access fingerprint than in-process code. In-process code reads via cached, TLB-warm paths with a specific instruction-pointer distribution — the reads come from a bounded, enumerable set of callers [VERIFY: earlier drafts cited "~10^4 known callers" as an order-of-magnitude claim; that number is asserted, not measured in the archived analysis; keep the softer "bounded, enumerable" framing]. DMA reads bypass the CPU entirely and appear in the memory controller's traffic without any instruction-side correlate; external-process reads via `NtReadVirtualMemory` come from a single well-known kernel path. Both are distinguishable if the defender collects the right telemetry. Intel PT, PMU-based page-access sampling, and (for DMA specifically) IOMMU translation-request logging are all viable primitives [VERIFY: IOMMU translation-request logging at production sample rates is a research primitive, as the paragraph itself flags — leave the caveat in place]. This is a research direction rather than a drop-in feature, but the static analysis in prior sections is what motivates it: the target offsets are so few and so predictable that the defender can afford to instrument them densely.

### 6.3 Recommendations for Pointer Encryption

§4.2's opcode scan found no `xor rax,imm32 ; ror rax,imm8` composite sequences anywhere in the readable head or tail of the dump, and the DMA scaffold's INI carries `DecryptKey=0`. Two things follow. First, the top-level singleton pointer is stored plaintext in `.data` — a defensive weakness. Second, if any encryption exists it is inside the packed `.UBX1` body and cannot be studied from an on-disk dump. Recommendations for the vendor:

- **Per-pointer keys.** XOR the stored pointer with a value derived from *the address where the pointer lives*. This defeats the naive attack pattern where an adversary dumps `.data`, finds a suspicious 64-bit value, and applies a global key. Under a per-address key scheme every stored pointer looks like unrelated random data even when the transform is trivially cheap at runtime.
- **Rotating per-session keys.** Regenerate the per-address salt each session (or each map load). Adversarial offset databases assume the salt is a build-time constant; rotating it converts a one-time RE cost into a per-session cost.
- **Public precedent.** Blizzard's Overwatch pointer encoding (documented in community RE writeups around 2017–2019) and PUBG's shifted-pointer scheme both use obfuscation transforms of this general shape. [UNVERIFIED: earlier drafts characterized both as "XOR + rotate with session-derived key"; that framing is stronger than the community writeups reliably support — cite specific writeups or hedge as "obfuscation transforms of this general shape".] Neither is unbreakable — a runtime hook can always observe the decrypt — but both meaningfully raise the cost for the static-dump adversary.
- **Trade-off.** Decryption sits on the hot path of every entity access. If Ubisoft has chosen to put the *decryption gadget itself* inside `.UBX1` rather than inlining it into every accessor, that would be a reasonable compromise. [UNVERIFIED: static analysis did not locate the decrypt gadget at all — attributing a specific placement decision to Ubisoft is inference, not observation.] A defender designing from scratch should benchmark the added cycles per singleton dereference against the frame budget before over-designing.

### 6.4 Recommendations for Section-Level Obfuscation

The `.UBX1` section is ~130 MB — roughly 26% of the binary's virtual size [UNVERIFIED: earlier drafts said "65%" — that figure does not reconcile with either the virtual image or the raw file size; see §2.6 for corrected numbers] — and its executable-plus-readable flags mean it holds decrypted-in-place code pages, not merely data. This is a *large* defensive investment and it is the reason §4.2's opcode scan could not find pointer-decrypt gadgets. The lesson for other AC designers is that VM-based or streaming-decrypt obfuscation is only useful if it wraps the primitives an adversary most needs — pointer decrypt, singleton lookup, entity iteration — rather than being sprinkled decoratively over cold code.

For calibration: our archived analysis of the EasyAntiCheat driver found ~94% of its executable code inside VM-protected regions (by anonymous-section size). [VERIFY: 94% is by section size in the archived analysis; the same document reports 41.5% by function count — specify which metric to avoid conflation.] Ubisoft's ~26% (by virtual-image share) or ~99.7% (by raw-file share) for the game binary is on a comparable order of magnitude to an AC vendor's investment in its own driver, when measured on the metric that treats the obfuscated payload as the denominator. The trade-offs — binary size, cold-start latency, and per-page decrypt cost as the streaming loader touches new pages — are real, but the entropy profile in §4.1 shows the mitigation is doing its job: the on-disk static analyst simply cannot recover the primitives without a live memory capture at a specific runtime state.

### 6.5 Offset Randomization as a Defensive Rhythm

§4.2 identified `SpawnManager` and `GameManager` at candidate `.data` offsets. Those offsets are the entire supply chain for the runtime-scanner category — offset databases circulate publicly, update on patch day, and are the primary reason external tooling can offer "no-recompile" subscription products. The defensive response is to make offsets *not* stable:

- **Randomize field layouts across builds.** Every major build reshuffles the ordering of fields inside key manager structs. Every scanner vendor has to re-run their signature scanner; every downstream offset database has to be regenerated. This is an engineering cost (a build-time layout permutation pass on structs that are not ABI-load-bearing) with a large ecosystem-level effect. [VERIFY: the cost is not "modest" in AAA codebases where ABI-fragile interop (serialization, network replication, save formats, middleware SDKs) constrains layout; qualify the recommendation with these interop caveats before publication.]
- **Ride the release cadence.** Ubisoft ships R6 Siege on a seasonal cadence (roughly one major "Operation" per quarter, with mid-season patches). That cadence *is* the defensive rhythm; the AC and engine teams should treat each Operation as a scheduled offset rotation, not merely a feature ship.

### 6.6 Hardware-Side Detection for the DMA Cheat Category

Static dump analysis is only valuable to an adversary if the runtime scanner can actually read the target memory. DMA-based scanners — PCIe capture cards, custom FPGA devices — are the reason kernel AC callbacks alone are insufficient: the reads never touch the target machine's CPU. Public research has documented several defender-side primitives. [UNVERIFIED: earlier drafts cited "Praetorian, various BlackHat and CCC talks on PCIe device fingerprinting" as prior art; the "Praetorian" attribution and specific talk set need explicit citation.]

- **TLP timing analysis.** Legitimate PCIe devices have characteristic Transaction Layer Packet latency distributions; DMA-capture hardware, whether a Screamer-class FPGA or a repurposed capture card, has different timing footprints because it is issuing bursts of unrelated reads. [VERIFY: TLP timing as a fingerprinting concept is discussed publicly, but reliable production-noise discrimination of Screamer-class devices is stronger than the published evidence firmly supports.]
- **Device fingerprinting.** PCI config-space contents, capability structures, and BAR usage patterns for a DMA-capture device do not match the vendor/device claimed. AC vendors already do a first pass at this. [VERIFY: earlier drafts referred to an internal check named "PciBus" — plausible but not attested in the archived materials; either cite or drop the specific name.] Deeper checks (config-space hashes, capability presence bitmaps) close more gaps.
- **IOMMU-anchored isolation.** VT-d/AMD-Vi can constrain which physical pages are DMA-reachable from a given device. On systems that enable it, the DMA-capture surface shrinks dramatically. Persuading users, OEMs, and (eventually) the platform to standardise IOMMU-enforced isolation is a longer-horizon defender play but a foundational one.

None of these primitives are cheap and none are new — but combining them with the singleton canaries above yields a defender-side detection stack whose false-positive rate can be pushed low while covering the specific attack shape a static analyst like the one in this chapter would enable.

### 6.7 The Economics of Publishing This Work

There is an argument that publishing a detailed static-analysis walkthrough of a shipping AAA binary helps adversaries. The counter-argument, and the one this book takes, is that adversarial vendors already have this analysis — they've had it for years, they share it privately, and they monetise it via subscription products. What they lose when defenders publish is the *silent development phase*: the multi-week window between "we found a new offset" and "the AC vendor notices the technique." Public defensive research collapses that window.

Concretely: every canary idea in §6.2, every layout-randomization argument in §6.5, and every hardware-detection primitive in §6.6 raises the cost of the next adversarial iteration. Adversarial economics are highly sensitive to iteration cost, because the customer-facing product is a subscription; a vendor whose signature breaks every three days cannot sustain a userbase. [VERIFY: economic claim is directional/plausible but not sourced — either cite market commentary or frame as illustrative rather than empirical.] Making the arms race visible — publishing static analyses that expose which of the defender's mitigations *actually work* — is a defender-favouring move even when the analysis itself uses adversarial methodology.

The static analysis in the preceding sections is, in that sense, the raw material for defensive design. The `.UBX1` section works — §4 and §5 could not recover the primitives inside it. The candidate `.data` singletons, if plaintext, do not offer meaningful protection — §2 and §4 recovered offsets trivially. That asymmetry is the report card, and it points directly at the recommendations above.

---

## 7. Limitations of Static Analysis

The following limits are inherent to on-disk-only PE analysis and constrain every claim in this document. They are not weaknesses of the methodology but structural properties of the artifact:

1. **The `.UBX1` body is opaque.** ~130 MB of executable+readable content is shipped in an encrypted or transformed state and cannot be examined without a live memory snapshot taken after the streaming loader has decrypted the corresponding pages. This includes any pointer decrypt gadget, any heartbeat/integrity routine, any CFO-flattened control flow inside protected functions, and any runtime-only diagnostic strings.
2. **The `.rdata` section is not captured.** In the archived dump, `.rdata` is enumerated in the section table but its RawSize is zero, meaning its content is not present in the on-disk artifact. This puts RTTI type descriptors (`.?AV*@@`), read-only C-string tables (log messages, event names, class name strings for singletons), vtable data, and CFG jump-target tables out of reach.
3. **Runtime-initialized state is invisible.** Any global whose value is populated only after `DllMain` / `main` — including all `new`-allocated manager child objects, all entity list heads populated from the streaming loader, and all Wwise/Havok runtime handles — has no on-disk footprint. Only the *slots* that receive these values are discoverable statically; the values themselves are not.
4. **Toolchain identification is inferential.** The `_flto_` PDB name suffix and "LLD PDB" CodeView signature are consistent with clang-cl + LLD, but neither is definitive. A production toolchain confirmation requires walking the PE's `IMAGE_DEBUG_TYPE_VC_FEATURE` and rich header, neither of which is preserved in the archived summary.
5. **Absence claims are weak.** For every "no X strings appear in the dump" statement in §3, the underlying strings scan covered only the readable portion of the on-disk image. A strings scan of a live memory dump — or of the decrypted `.UBX1` body — could produce different results. Where absence is used to rule a middleware out (e.g. Bink, SpeedTree, Enlighten), the confidence level is calibrated to reflect this.
6. **Cross-artifact reconciliation is incomplete.** The offsets INI (`build/RainbowSix_dump_offsets.ini`) and the archived static PE analysis (`build/r6_dump.txt`) describe overlapping but not identical states of the binary. Several offsets in the INI do not reconcile with the section boundaries in the static analysis, suggesting the INI was produced against a live process with a different image base or a slightly different build. Reconciliation is deferred to future work.
7. **No dynamic behavior is observed.** Every claim in this document is about the on-disk binary. Runtime behavior — thread topology, actual API resolution order, actual anti-cheat callbacks, actual heartbeat cadence — is out of scope for static analysis and can only be conjectured from static evidence.

---

## 8. Open Research Questions

The following questions are explicitly deferred to future work under appropriate research ethics review. Each corresponds to a specific gap in the current static-only analysis:

1. **What is inside `.UBX1`?** A runtime memory snapshot of the section after it is touched by the streaming loader would allow direct disassembly of the protected code, including any pointer decrypt gadgets, integrity checks, and CFO-flattened routines. Reference points: how many distinct runtime handlers are present, and what fraction of them are pure code-flow flattening versus actual VM interpreters.
2. **Is the top-level singleton pointer really plaintext?** Reconciliation between the offsets INI and the live section table would resolve whether the candidate `SpawnManager` and `GameManager` offsets are stale, mis-attributed, or genuinely plaintext at the reported RVAs. If they are plaintext, the recommendations in §6.3 apply directly; if they are encrypted, the analysis of §4.2 needs to be extended.
3. **What is the real Wwise export count?** The 305-vs-662 discrepancy in earlier drafts is a counting artifact; recomputing against the full export listing (rather than the archived 200-of-662 slice) closes the question and lets the Wwise-share claim in §3.1 be published with a definite number.
4. **What is the actual threading model of the 2022 build?** Public disclosures date from 2014–2017. A runtime `Process Explorer` snapshot during a match yields the current thread inventory and their names (where symbolic). This would allow §2.5 to move from architectural inference to concrete observation.
5. **Which CRC/hash primitive does the tick manager use?** The absence of standard CRC polynomial constants in the readable head of `.text` is consistent with three hypotheses (§4.5). A live snapshot of the tick manager's dispatch loop would disambiguate.
6. **Is Havok really the physics stack?** Ubisoft's legal notices declare Havok, but no `hkp*` or `hknp*` symbols are visible in the readable region. A `.rdata` capture and/or runtime module inventory would confirm which Havok API family is actually integrated.
7. **What does the `.UBX0` boot stub actually do?** A control-flow trace from process entry through the first `.UBX0` execution would characterize the decrypt strategy (page-guard, decrypt-on-entry, or hybrid) and let §4.1 replace hypothesis with observation.

---

## 9. Ethics

This work is defensively valuable for four reasons:

1. **It informs detection design.** The recommendations in §6 — canary managers, per-address pointer encryption, layout randomization, hardware fingerprinting — are actionable by anti-cheat vendors and by game teams. They collectively raise the cost of the adversarial iteration cycle without depending on any single detection primitive.
2. **It documents the state of the art.** Public documentation of AAA protection primitives is sparse and out of date. This report contributes a current snapshot of what a shipping 2022 R6 Siege binary looks like on disk, calibrated against comparable analyses of EasyAntiCheat and BattlEye from prior CTF work.
3. **It uses only public sources.** No leaked Ubisoft materials, no runtime instrumentation on live sessions, no interaction with the anti-cheat client or driver. Every claim is grounded in the on-disk binary, Ubisoft's own legal notices, or public vendor documentation.
4. **It is framed defensively throughout.** Where an earlier draft passage read as attacker guidance, it has been reframed to a defender's analytical posture. Where it could not be reframed without loss of content, it has been removed. This is documented explicitly in the tag table (§11) with the label `OPERATIONAL BYPASS RISK` where applicable.

The analysis in this report describes methodology that adversaries already use privately. Publishing it collapses the silent-development window and shifts the timeline back toward defenders. That is the defensive case for publication, and it is the case this document rests on.

---

## 10. Author's Note

This document was drafted with AI assistance. Section drafts were produced iteratively, then subjected to an adversarial verification pass in which every non-obvious factual claim was extracted, graded for confidence, and cross-checked against the archived static-analysis artifacts in this project's tree. Claims that did not survive verification were re-tagged `[UNVERIFIED]` or `[VERIFY]` and are enumerated in §11 below.

**All claims in this document — including those not tagged — should be independently verified before publication.** In particular:

- All specific numeric values (VAs, sizes, symbol counts, entropy figures, opcode counts) should be re-derived from a freshly run dumper against the current game binary.
- All citations to external work (GDC talks, academic papers, community writeups, vendor blog posts) should be resolved to specific titles, venues, dates, and URLs.
- All claims about middleware presence should be re-checked against the current live Ubisoft legal notices page.
- All claims about the internal engine name, PDB path, and build metadata should be re-verified against a hex-dump of the PE debug directory.

Where a section makes an architectural or economic argument (e.g. §6.7 on publication economics), that argument is presented as the author's view informed by the evidence; a fact-checker should treat those passages as opinion rather than reportage.

The adversarial verification pass caught a substantial number of numeric and attributive errors in the drafts (wrong VAs, mis-identified game titles, mis-attributed academic citations, over-precise symbol counts derived from truncated evidence). Readers should assume more remain; publication should not proceed until the verification worksheet accompanying this document is fully green.

---

## 11. Verification Appendix

The following table enumerates every `[UNVERIFIED]` and `[VERIFY]` tag in the body of this document. Each entry lists the section it appears in, the tag type, and the reason for the tag. A companion worksheet (`ctf_118_anvilnext_verification.md`) provides a per-claim checklist for the fact-checker.

| # | Section | Tag | Claim / Reason |
|---|---------|-----|----------------|
| 1 | 2.1 | VERIFY | Per-title engine attribution for Siege, For Honor, Wildlands, Breakpoint needs citations |
| 2 | 2.1 | VERIFY | "Anvil Pipeline" phrase needs primary-source Ubisoft citation |
| 3 | 2.1 | UNVERIFIED | Exact quarter/month of 2020 Anvil rebrand announcement |
| 4 | 2.2 | VERIFY | Full `F:\tc\...` PDB path string not captured in archived dump |
| 5 | 2.2 | VERIFY | Mapping 2022 build tag to specific Y7 seasons |
| 6 | 2.2 | UNVERIFIED | Toolchain attribution: LLD PDB signature suggests clang-cl + LLD, not MSVC |
| 7 | 2.2 | VERIFY | `p4` and `tc` directory names as Perforce/TeamCity are conventional but not proof |
| 8 | 2.3 | VERIFY | Physics=Havok box in diagram not proven from artifacts |
| 9 | 2.3 | VERIFY | DLSS specifically (as NGX feature) is inference from NGX presence |
| 10 | 2.3 | VERIFY | Wwise 305-exports figure needs recomputation |
| 11 | 2.4 | VERIFY | Specific GDC talk citations for composition-first entity model |
| 12 | 2.4 | UNVERIFIED | SpawnManager/GameManager candidate RVAs fall in `.text`, not `.data`; stale relative to current build |
| 13 | 2.4 | VERIFY | `48 8B 3D` MOV RDI singleton pattern is not MSVC-specific |
| 14 | 2.4 | UNVERIFIED | Whether Siege ships with `/GR-` (RTTI disable) |
| 15 | 2.5 | VERIFY | GDC session citations for AnvilNext job graph |
| 16 | 2.5 | VERIFY | Physics engine identity not proven from artifacts |
| 17 | 2.5 | UNVERIFIED | Precise thread topology of 2022 build requires runtime observation |
| 18 | 2.5 | UNVERIFIED | `__security_cookie` string not observed; `/GS` cookie is not toolchain-diagnostic |
| 19 | 2.5 | UNVERIFIED | Actual `.tls` size is 42.8 KB, not 87 KB; does not support "many concurrent workers" inference |
| 20 | 2.6 | UNVERIFIED | Earlier draft section VAs and sizes did not match archived dumper output; use §2.6 table |
| 21 | 2.6 | VERIFY | UBX prefix exclusivity claim needs survey citation |
| 22 | 2.6 | VERIFY | "Internal custom protector" attribution needs primary source |
| 23 | 2.6 | UNVERIFIED | `.UBX0` functional attribution to VM dispatch is analogy, not evidence |
| 24 | 2.6 | UNVERIFIED | 29% figure corrects earlier "substantial majority" overstatement |
| 25 | 2.6 | VERIFY | Entropy 8.000 span not preserved in archived scan output |
| 26 | 2.6 | UNVERIFIED | On-page-decryption model of streaming loader lacks runtime evidence; framed as hypothesis |
| 27 | 2.6 | VERIFY | Recommendation to acquire live dump depends on runtime-decryption model |
| 28 | 2.6 | UNVERIFIED | Pointer-encryption gadget location inside `.UBX1` is speculation; reframed as limit-of-static-analysis |
| 29 | 3 (preamble) | VERIFY | `flto` filename convention as LTO evidence needs PE optional header confirmation |
| 30 | 3 (preamble) | UNVERIFIED | 395 MB vs 130.7 MB file size discrepancy needs reconciliation |
| 31 | 3.1 | VERIFY | "No FMOD" claim limited to archived export table, not full binary strings scan |
| 32 | 3.1 | UNVERIFIED | 305 unique AK symbols figure not derivable from archived text |
| 33 | 3.1 | VERIFY | Full 662-entry export recount for AK share |
| 34 | 3.1 | VERIFY | 210 SoundEngine, 12 StreamMgr, 16 MemoryMgr, 4 MusicEngine, 17 Monitor sub-counts need recount |
| 35 | 3.1 | VERIFY | GDC talk citations for Wwise destruction audio |
| 36 | 3.2 | VERIFY | Realblast voxel vs procedural-mesh characterization |
| 37 | 3.2 | VERIFY | Exact Havok copyright string reconfirmation |
| 38 | 3.2 | VERIFY | 2015 copyright vintage vs API family shipped |
| 39 | 3.2 | UNVERIFIED | "4 fragmentary hknp hits" figure not derivable from archived analysis |
| 40 | 3.2 | VERIFY | `.rdata` RawSize=0 in archived dump means content not written |
| 41 | 3.2 | VERIFY | "Launch integration partner for Havok FX in 2015" needs citation |
| 42 | 3.2 | VERIFY | GDC 2015/2016 Havok talks citation |
| 43 | 3.2 | UNVERIFIED | Server-authority split claim not established by dump or cited sources |
| 44 | 3.3 | VERIFY | "No Umbra symbols" limited to archived export table |
| 45 | 3.3 | VERIFY | Umbra absence from Ubisoft legal notices reconfirmation |
| 46 | 3.3 | VERIFY | Tiger engine's use of Umbra publicly documented but needs citation |
| 47 | 3.4 | VERIFY | Enlighten ownership chain (drop or replace "Autodesk" step) |
| 48 | 3.4 | VERIFY | Enlighten strings absence not fully proven by archived summary |
| 49 | 3.5 | VERIFY | SpeedTree strings absence not fully proven by archived summary |
| 50 | 3.6 | VERIFY | Reconfirm libvpx / Ogg Vorbis declarations on live legal notices page |
| 51 | 3.7 | UNVERIFIED | "15 D3D12 hits" figure not visible in archived text |
| 52 | 3.7 | VERIFY | NGX helper symbols not visible in archived slice |
| 53 | 3.7 | UNVERIFIED | "HLd3d9.dll = handleable-loader d3d9" expansion is not a standard term |
| 54 | 3.8 | VERIFY | Voicechat hit count needs recount against full export table |
| 55 | 3.8 | VERIFY | `SetFriendsProviderResult` symbol not shown in archived slice; friend-list-drives-routing is inference |
| 56 | 3.8 | VERIFY | Whether `libtox.dll` is actually the Tox Project SDK |
| 57 | 3.9 | VERIFY | Reconfirm each middleware entry against live legal notices |
| 58 | 3.9 | VERIFY | PCRE2 "chat filtering" use case is inference |
| 59 | 3.9 | VERIFY | Whether Siege still ships Scaleform vs Ubisoft in-house UI |
| 60 | 3.9 | VERIFY | Whether RTXGI is actually declared in current Siege legal notices |
| 61 | 3.10 | UNVERIFIED | Earlier draft VAs and sizes for `.UBX0`/`.UBX1` do not match dump |
| 62 | 3.10 | VERIFY | "No VMP/Themida/Denuvo markers" is limited to archived summary |
| 63 | 3.10 | UNVERIFIED | 96 MB entropy-8.000 span and on-page-touch decryption are hypotheses |
| 64 | 3.10 | UNVERIFIED | Corrected `.rdata` VA is `0x1410B000`, not earlier `0xFB6C000` |
| 65 | 4 (opening) | UNVERIFIED | No archived reference matches build tag `4a820094` |
| 66 | 4.1.1 | UNVERIFIED | Earlier draft section VAs/sizes did not match archived dump; use §2.6 values |
| 67 | 4.1.1 | VERIFY | Entropy scan output for RainbowSix.exe not preserved |
| 68 | 4.1.1 | VERIFY | Cross-title UBX presence needs specific reversing writeups per title |
| 69 | 4.1.1 | VERIFY | Rolles VMProtect writeup exact title and venue |
| 70 | 4.1.1 | VERIFY | Loki paper USENIX Security 2022 authorship confirmation |
| 71 | 4.1.1 | UNVERIFIED | Corrected packer-genealogy citation (Ugarte-Pedrero et al. IEEE S&P 2015, not Yan et al. RAID 2015) |
| 72 | 4.1.1 | UNVERIFIED | Ubisoft streaming-decrypt discussion in job postings/GDC not cited |
| 73 | 4.1.1 | VERIFY | Obfuscator-LLVM SPRO 2015 year confirmation |
| 74 | 4.1.1 | UNVERIFIED | 44/34 EAC/vmp fragmentary hit counts not preserved in archived scan |
| 75 | 4.1.2 | UNVERIFIED | 94% EAC figure attributes to kernel driver, not user-mode module; earlier drafts conflated the two |
| 76 | 4.1.2 | VERIFY | Cite specific 2020+ AAA titles with two-tier protector architecture |
| 77 | 4.1.3 | VERIFY | `.pdata` unwind failure inside packed body needs specific IDA/Ghidra observation |
| 78 | 4.2.1 | VERIFY | PUBG XOR key writeup citation |
| 79 | 4.2.1 | VERIFY | Overwatch PEB-derived pointer encryption writeup citation |
| 80 | 4.2.1 | VERIFY | Modern Warfare position-dependent XOR citation |
| 81 | 4.2.2 | VERIFY | SpawnManager pattern is `48 8B 3D` (MOV RDI); GameManager is `48 8B 0D` (MOV RCX) — earlier draft treated both as MOV RDI |
| 82 | 4.2.2 | UNVERIFIED | Reconciliation between offsets INI and static PE analysis not performed |
| 83 | 4.2.2 | UNVERIFIED | Opcode-search scan output not preserved in archived build directory |
| 84 | 4.2.2 | UNVERIFIED | Individual opcode counts not preserved in archived output |
| 85 | 4.2.2 | UNVERIFIED | Six-constant catalogue not preserved; needs re-scan |
| 86 | 4.3 | VERIFY | Kaspersky/CrowdStrike API-hashing report citation |
| 87 | 4.3 | VERIFY | Denuvo/BattlEye API-hashing community writeup citation |
| 88 | 4.4 | VERIFY | Ubisoft GDC talk citation for tick manager / job graph |
| 89 | 4.4 | VERIFY | EA Anti-Cheat blog post citation for Frostbite |
| 90 | 4.4 | VERIFY | Community VAC/Source 2 reversing citation |
| 91 | 4.4 | VERIFY | Riot Vanguard "beacon architecture" framing confirmation |
| 92 | 4.4 | UNVERIFIED | "BattlEye whitepaper" is not an established public document; needs sourcing |
| 93 | 4.4 | VERIFY | DexGuard integrity-check documentation citation |
| 94 | 4.5 | VERIFY | XXH64 PRIME1 vs "seed" terminology clarification |
| 95 | 4.5 | UNVERIFIED | Six-constant CRC comparison depends on unpreserved catalogue |
| 96 | 4.5 | UNVERIFIED | DMA freeze-attempt sentence removed for OPERATIONAL BYPASS RISK; shadow-copy technique reframed defensively |
| 97 | 4.6 | UNVERIFIED | Taxonomy table VA range for `.text` packed body corrected via §2.6 |
| 98 | 4.6 | UNVERIFIED | Taxonomy table entries referencing earlier draft VAs need §2.6 substitution |
| 99 | 4.6 | VERIFY | Pointer-encryption public analogues need specific citations |
| 100 | 4.6 | VERIFY | Tick manager public documentation citation |
| 101 | 5.1 | UNVERIFIED | Earlier draft SizeOfImage `0x18B09000` / 395 MB does not match archived dump `0x1ED04000` / ~493 MB |
| 102 | 5.1 | VERIFY | Full PDB path string not captured in archived static dump |
| 103 | 5.2 | VERIFY | Pattern scan "size 0x0" suggests scanner did not reach `.text`; needs separate string extraction |
| 104 | 5.2 | VERIFY | ~105 MB partial dump size correct but "stops mid-.text" boundary not independently verified |
| 105 | 5.2 | VERIFY | `.?AVCSpawnManager@@` RTTI mangling inferred, not observed |
| 106 | 5.2 | UNVERIFIED | Earlier draft conflated `/GR-` (RTTI disable) with linker stripping; Ubisoft's use of `/GR-` not established |
| 107 | 5.3 | VERIFY | "Managers almost universally accessed through static pointer" is a strong generalization |
| 108 | 5.3 | VERIFY | dumper2 votes candidates by proximity+structural pattern, not raw read/write ratio |
| 109 | 5.3 | UNVERIFIED | Candidate offsets fall in `.text` under current section layout; INI produced against different image base |
| 110 | 5.3 | VERIFY | Zero-hit pattern scan not independently confirmed by string-cross-reference pass |
| 111 | 5.4 | UNVERIFIED | No top-20 ranked-candidate table exists in archived output |
| 112 | 5.4 | UNVERIFIED | Earlier draft said "Deep Rock Galactic"; correct game is Delta Force per `df_offsets.ini` |
| 113 | 5.5 | VERIFY | XMM/EAX register-type heuristic is convention, not empirically demonstrated on archived globals |
| 114 | 5.6 | UNVERIFIED | 96 MB flat-8.000 entropy figure lacks supporting artifact |
| 115 | 5.7 | VERIFY | PDB build identifier `p4\4a820094` matches PDB path string but the PDB path itself is flagged |
| 116 | 6 (opening) | UNVERIFIED | Earlier draft cited "104 MB" / "65%" for `.UBX1`; per §2.6 correct figures are ~130 MB / ~26% |
| 117 | 6.1 | VERIFY | Unity singleton framing was conflated with `UnityPlayer.dll` module |
| 118 | 6.1 | VERIFY | Frostbite singleton name varies across generations |
| 119 | 6.2 | VERIFY | "False-positive rate is zero" softened to "very low" |
| 120 | 6.2 | VERIFY | "~10^4 known callers" order-of-magnitude claim not measured in archived analysis |
| 121 | 6.2 | VERIFY | IOMMU translation-request logging is research primitive, not production-ready |
| 122 | 6.3 | UNVERIFIED | Overwatch/PUBG "XOR + rotate with session-derived key" characterization is stronger than public writeups support |
| 123 | 6.3 | UNVERIFIED | Attributing intentional decrypt-gadget placement inside `.UBX1` to Ubisoft is inference |
| 124 | 6.4 | UNVERIFIED | Earlier "65%" figure for `.UBX1` share does not reconcile |
| 125 | 6.4 | VERIFY | 94% EAC figure metric (size vs function count) must be specified |
| 126 | 6.5 | VERIFY | Layout randomization cost characterization softened from "modest" |
| 127 | 6.6 | UNVERIFIED | "Praetorian, BlackHat, CCC" attribution for PCIe fingerprinting is a hand-wave |
| 128 | 6.6 | VERIFY | TLP timing discrimination reliability under production noise |
| 129 | 6.6 | VERIFY | Internal AC check name "PciBus" not attested in archived materials |
| 130 | 6.7 | VERIFY | Economic argument on iteration cost is directional, not sourced |

---

*End of document.*
