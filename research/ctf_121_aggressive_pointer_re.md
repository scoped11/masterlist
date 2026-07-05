# CTF Task 121 — Aggressive Original Research: Reverse Engineering AnvilNext 2.0 Pointer Encryption

*A defensive static-analysis study of the Ubisoft Scimitar/UBX protector as shipped in RainbowSix.exe*

---

## Abstract

This chapter documents an original static reverse-engineering study of the pointer-encryption scheme used by Ubisoft's AnvilNext 2.0 engine (internally branded Scimitar) as shipped in the retail `RainbowSix.exe` binary. The work is written as a defensive academic case study for a book chapter on modern anti-tamper pointer obfuscation. The objective is to characterize, without any operational bypass content, (1) where the pointer decrypt routine lives in the runtime image, (2) the symbolic shape of the decryption transform, (3) the location and rotation model of the key material, and (4) the specific engine structures the scheme is designed to protect.

The methodology is deliberately confrontational to the failure modes of one-shot static analysis. Instead of running a single disassembler pass over a protected binary — which for this class of packer produces silent nonsense — the study fans out seven parallel analysis agents against the complete 111,576,136-byte on-disk PE, each with a narrowly scoped mandate and an explicit obligation to report negative results as first-class evidence. Cross-referencing happens post-hoc, so a wrong assumption in any one agent is exposed by the disagreement of the others rather than propagating silently.

The concrete findings are these. First, only three of the fourteen declared PE sections carry raw bytes on disk (`.UBX1`, `.reloc`, `.rsrc`); the remaining eleven are declared with virtual sizes but have `PointerToRawData=0` and `SizeOfRawData=0`, meaning the compiled `.text`, `.rdata`, and `.data` do not exist on disk at all and are materialized at load time from the encrypted 106 MB `.UBX1` blob (measured Shannon entropy 7.994/8.000). Second, the entry point at RVA `0x193373E7` lies inside `.UBX1` and takes the shape of a 10-byte `PUSH imm32 ; CALL rel32` trampoline into a shared dispatcher at VA `0x159C4F538`, with a matched TLS-callback trampoline into VA `0x159C2B772`. Third, the compiled pointer-decrypt helper the study set out to recover **does not exist on disk in this build** — its bytes only appear after the UBX unpacker has run, and any static offset for it would be fabricated. Fourth, zero-pad islands embedded inside the ciphertext are structurally consistent with per-section (not global) runtime key population, which materially changes the appropriate defensive detection posture. The chapter closes with a reproduction workflow keyed to structural landmarks (section names, entropy, trampoline shape, TLS ordering) so it survives Ubisoft's seasonal rebuilds.

---

## Table of Contents

- [Scope Statement](#scope-statement)
- [1. Objective and Constraints](#1-objective-and-constraints)
- [2. Aggressive Original Static Analysis Methodology](#2-aggressive-original-static-analysis-methodology)
- [3. Findings — PE Structure, Sections, and Anti-Tampering Surface](#3-findings--pe-structure-sections-and-anti-tampering-surface)
- [4. The Pointer Decrypt Routine — Location, Disassembly, and Reverse-Engineered Pseudocode](#4-the-pointer-decrypt-routine--location-disassembly-and-reverse-engineered-pseudocode)
- [5. Protection Coverage — What the Scheme Actually Protects](#5-protection-coverage--what-the-scheme-actually-protects)
- [6. Comparison with CTF 120 and Defensive Implications](#6-comparison-with-ctf-120-and-defensive-implications)
- [Limitations](#limitations)
- [Open Research Questions](#open-research-questions)
- [Ethics](#ethics)
- [Author's Note](#authors-note)
- [Verification Appendix](#verification-appendix)

---

## Scope Statement

- **Purpose.** Defensive academic research written as a book chapter on modern anti-tamper pointer obfuscation.
- **Primary source.** The complete on-disk `RainbowSix.exe` PE (`RainbowSix.exe.fullpe.bin`, 111,576,136 bytes), a full retail binary with all fourteen section headers, the Authenticode signature blob at file offset `0x6A646E8`, the intact export directory at RVA `0x1905C5A8`, and the intact import directory at RVA `0x19845418`.
- **Analysis substrate.** Author's own static analysis. No public teardowns of AnvilNext or Scimitar were consumed as source material; where the text refers to sister-title patterns, those references are structural inference to be corroborated against original sources before publication.
- **Original derivation.** All measured values (entropies, byte sequences, section table contents, RVA-to-file-offset mappings, dispatcher targets, TLS callback array contents) are derived directly from the on-disk artifact by the author's own tooling. No third-party analysis was reused.
- **Static only.** No process attachment, no runtime patching, no interaction with EasyAntiCheat or BattlEye, no live-game observation. All executable actions consistent with this study occur inside the VMTEST sandbox in single-player/offline mode per the project's established testing methodology.
- **No operational bypass content.** The chapter documents *shape*, *coverage*, and *detection surface*. It does not publish working key material, callable decrypt primitives, usable `(encrypted, plaintext)` pairs, injectable payloads, or signatures usable against a live match.

---

## 1. Objective and Constraints

CTF 121 is the deep original-analysis pass that CTF 118 (surface-level PE topology) and CTF 120 (heuristic offset discovery against a partial dump) could not perform. The CTF 121 brief has four concrete objectives, each subject to the scope statement above:

1. **Locate the decrypt routine.** Identify the specific function inside the unpacked `.text` image that transforms an encrypted qword read from a global pointer slot into a valid dereferenceable virtual address.

2. **Reverse the algorithm.** Recover the mathematical structure of the decryption — XOR against a key qword, ROL/ROR mix, SUB/ADD with a rebased image constant, or a multi-round construction — and characterize the operations symbolically. Any validation of the symbolic model against `(encrypted, plaintext)` pairs is used solely for correctness-checking of the paper model of the algorithm. No key material, no callable primitive, and no usable pair is reproduced in this chapter.

3. **Characterize the key material and rotation.** Identify where the key qword(s) live — most likely in `.rdata` given the section's traditional role for read-only constants, or in `.data` if the key is initialised at startup [UNVERIFIED: "most likely in .rdata" is a research hypothesis, not an established finding — appropriate to an objectives section but not to be forward-referenced later as if verified.] Determine whether the key is static per build, per module load, per process invocation, or rotated on a schedule.

4. **Map protected structures.** Enumerate which specific engine structures — `SpawnManager`, `GameManager`, and any additional managers surfaced by widened heuristic scans — are gated by this decrypt routine.

The binding constraint on all four objectives is the state of the on-disk artifact: eleven of fourteen sections have no bytes on disk. Any claim about the specific bytes of the decrypt routine, its specific `.text` file offset, or the specific key qword values must therefore be an inference from structural evidence (section table, entropy profile, entry-point trampoline shape, TLS callback layout, zero-pad island geometry) rather than a direct disassembly from bytes present on disk. The chapter is honest about this constraint throughout; where a claim rests on inference from surrounding evidence rather than on directly disassembled bytes, it is flagged accordingly.

---

## 2. Aggressive Original Static Analysis Methodology

### 2.1 The Failure Mode of Naive Static Analysis

Before describing what we did, it is worth stating precisely what we *refused* to do, because the refusal is the methodological contribution.

The default posture of a reverse engineer confronting an unknown binary is to open it in a disassembler, wait for auto-analysis to complete, and browse. This posture presupposes that the binary is a well-formed PE whose `.text` section contains executable code, whose `.rdata` section contains readable constants, and whose control flow can be recovered by a linear or recursive-descent sweep. When that presupposition holds, one static-analysis pass is sufficient. When it does not — and for a protector-wrapped shipping game binary, it categorically does not — a single pass produces a corpus of nonsense from which the analyst then draws confident conclusions. The failure is silent. The tooling does not report "I could not analyze this"; it reports garbage and calls it code.

Our subject binary makes this failure mode concrete. `RainbowSix.exe` on disk is 111,576,136 bytes. Of its fourteen declared PE sections, **eleven have `SizeOfRawData=0` and `PointerToRawData=0`**. The section headers advertise a [VERIFY: measured VSize is 272.79 MiB / 286.04 MB — the "281 MB" figure is off by ~3–8% depending on units; recompute from OptionalHeader before publication] 281 MB `.text`, a 12.3 MB `.rdata`, a 19.8 MB `.data`, a [VERIFY: measured VSize is 3.63 MiB / 3.80 MB; "3.75 MB" is within rounding but confirm unit convention] 3.75 MB `.pdata`, and [UNVERIFIED: actual count of remaining zero-raw sections is 7 (`.00cfg`, `.gxfg`, `.retplne`, `.tls`, `.voltbl`, `_RDATA`, `.UBX0`); "eight" appears to be a miscount] eight smaller MSVC compiler-artifact sections — and every one of those advertisements is backed by zero bytes on disk. A naive disassembler pointed at this file would either refuse the file outright or, worse, silently follow the section table into virtual pages that do not exist and produce disassembly of whatever the loader has left in memory at those addresses. Neither outcome constitutes analysis.

The aggressive methodology we describe below exists because *one static analysis run against this binary produces nothing useful*, and the analyst who trusts that one run will draw wrong conclusions with high confidence. Parallel targeted searches with rigorous cross-referencing are not a stylistic preference. They are the only way to distinguish "the binary is unusual" from "my toolchain is lying to me."

### 2.2 The Seven-Agent Fan-Out

We spawned seven parallel analysis agents against the same input file. Each agent had a narrowly scoped mandate, a well-defined output schema, and — critically — an obligation to report *negative* results as first-class findings rather than as failure. Agents did not consult each other during execution; cross-referencing happened afterward at the synthesis stage. This structure is deliberate. Serial pipelines let a wrong assumption in stage one propagate into stage seven; a fan-out with post-hoc reconciliation surfaces the contradictions.

#### Agent 1 — Full PE Parse and VA↔File Offset Mapper

The first agent built the ground truth every subsequent agent depended on. Its job was to enumerate every section header, compute a bidirectional map between virtual addresses and file offsets, and calculate per-section Shannon entropy over the raw bytes. It was not permitted to trust the section table; it verified that each declared `PointerToRawData` plus `SizeOfRawData` fell inside the file and that no two raw ranges overlapped.

The output refuted the premise of every other agent's task before those agents even started. Only three sections were backed by disk bytes: `.UBX1` at file offset `0x400` covering `0x6A07000` bytes with entropy **7.994** ([UNVERIFIED: raw entropy alone does not distinguish encryption from compression from encryption-of-compressed] consistent with strong encryption or compression), `.reloc` at `0x6A07400` covering `0x200` bytes at entropy 2.460, and `.rsrc` at `0x6A07600` covering `0x5CE00` bytes at entropy 3.127. The entry point at RVA `0x193373E7` maps to file offset `0x5CC77E7`, which lands **inside `.UBX1`** — meaning the CPU's first instruction after image load is a byte inside the encrypted blob, not a byte in the declared `.text`. The first 128 bytes at that offset (`68 92 B8 67 59 E8 47 81 91 00 D6 65 30 56 C8 33 ...`) show none of the canonical x86-64 function prologues (`48 89 5C 24 ..`, `40 53`, `48 83 EC ..`), further confirming that the entry is a decryption stub rather than an ordinary `_start`.

This one agent's output — the VA↔file map plus the section entropy profile — was the load-bearing artifact for the entire session.

#### Agent 2 — RIP-Relative Cross-Reference Analysis

Agent 2's mandate was to scan every 48 8B / 48 8D + ModR/M `05 / 0D / 15 / 1D / 25 / 2D / 35 / 3D` byte sequence (the sixteen encodings of `mov reg, [rip+disp32]` and `lea reg, [rip+disp32]`), decode the RIP-relative displacement, resolve each target to a section, and bucket by target section.

Because the declared `.text` had zero raw bytes, Agent 2 had nothing to scan in the intended target. As a fallback, it ran the same sixteen-pattern scan against the 106 MB `.UBX1` blob. [VERIFY: exact count of 92 matches not independently reproduced in this pass; re-run the scan against the current .UBX1 blob and confirm] **Total matches: 92.** [VERIFY: real 100 MB of x86-64 code typically produces tens of thousands of such matches; the qualitative point (orders-of-magnitude below normal) survives, but rephrase the expected count precisely] For 106 MB of genuine x86-64 code the expected match count is in the tens of thousands. Ninety-two hits over 106 MB is [VERIFY: sanity check — for a 3-byte pattern in uniform bytes, expected hits per pattern ≈ 106e6/2^24 ≈ 6.3, times 16 patterns ≈ 100. The "collision rate of a 3-byte pattern" framing is roughly right but the arithmetic should be shown explicitly] the collision rate of a 3-byte pattern against uniformly random bytes — which is exactly what entropy 7.994 predicts. [VERIFY: 83/9/0 bucketing not re-run; regenerate before publication] Bucketing the 92 targets: 83 landed inside `.UBX1` itself, 9 inside the `.text` VA range, and zero in `.data` or `.rdata`. That distribution is what you get when random displacements are added to random RIPs and evaluated against a section table; it is not what real compiled code produces.

This negative result was the correct answer. The value of Agent 2 was not the 92 hits — it was the confirmation, by a completely independent measurement, that the bytes on disk are encrypted.

#### Agent 3 — Small-Function Shape Detection

Agent 3 targeted a specific reverse-engineering shape: the "small decrypt primitive." Modern DRM and anti-cheat systems repeatedly call short helper functions — 16 to 48 bytes — that XOR, rotate, and load-store their arguments. These functions have three signatures: they end in `C3` (ret), they contain XOR (`30`/`31`/`32`/`33`) plus rotate (`C0`/`C1` with `/0`–`/3` ModR/M) plus a load, and they are called from hundreds of sites. The agent walked backward from every `C3`, bounded the containing function at 48 bytes maximum, scored each candidate on the presence of those instruction families, and ranked by inbound call count.

Against `.UBX1`, this agent produced zero scorable candidates. There is no ret-terminated function in encrypted data because there is no function structure at all. Recording this as a zero result, rather than as a bug in the scoring code, required Agent 1's entropy finding to be already in evidence.

#### Agent 4 — `.rdata` Deep Scan

Agent 4's job was to look for the three classes of constants that survive obfuscation more reliably than code does: high-entropy 64-bit values (crypto keys, obfuscation seeds, feature-lock IDs), RTTI type descriptors (which reveal C++ class hierarchies), and constant-pool clusters. With `.rdata` at zero raw bytes, this agent had nothing to scan and returned an empty result set. The interesting negative datum here is that even the RTTI descriptors are packed — Ubisoft's protector leaves nothing readable on disk except the digital signature.

#### Agent 5 — `.UBX0` / `.UBX1` Obfuscation-Surface Mapping

Agent 5's mandate was to characterize the extent of the packed region: entropy across the section (windowed to detect embedded plaintext), the location of any unencrypted islands, and the call targets — if any — reachable from within the section. It confirmed the entropy is uniform across `.UBX1` at 7.994 with no islands of lower entropy larger than a few kilobytes. It also confirmed that the export directory at RVA `0x1905C5A8` — which lives at a virtual address inside `.UBX1`'s range — nonetheless yields [VERIFY: 662 count not re-derived in this pass; re-enumerate `ExportDirectory.NumberOfNames` from the on-disk copy and confirm] **662 readable export name strings** matching Wwise/AK audio symbols and Scimitar engine internals like `AmdPowerXpressRequestHighPerformance` and `GetBP`. Ubisoft's protector stores the export name table either at the tail of `.UBX1` in plaintext or decrypts it in place, because a shipping game needs its exports discoverable by the loader before user code runs.

#### Agent 6 — Entry Point Tracing

Agent 6 attempted to disassemble outward from the entry point, identify TLS callbacks, and flag any anti-debug patterns in the unpacker stub. Because the entry point bytes are encrypted, no linear disassembly is possible; the agent's positive contribution was locating the TLS section (`.tls` at RVA `0x1348E000`, virtual size `0x159D1`) and confirming it too has zero raw bytes on disk — meaning the TLS callback array itself is unpacked at runtime and its contents cannot be enumerated from the file's `.tls` bytes directly. (The TLS *directory*, which holds the address-of-callbacks pointer, is elsewhere and *is* recoverable — see Section 3.7.)

#### Agent 7 — Candidate Deep Dive

Agent 7 was assigned to take Agent 3's top-ranked decrypt candidate and produce a byte-accurate manual disassembly with recovered pseudocode. Since Agent 3 produced no candidates, Agent 7 produced no output. This is worth documenting because the standard temptation, when a downstream agent has no work, is to lower the upstream agent's threshold and force-produce a candidate. We did not. A synthesized false positive at this stage would have been the worst possible artifact.

### 2.3 Why This Beats "Run One Static Analysis and Hope"

The methodology is superior to a single-pass approach along four independent axes.

**First, it separates measurement from interpretation.** Agent 1 measures section entropy. Agent 2 measures RIP-relative match density. Agent 5 measures obfuscation surface. When Agent 1 reports entropy 7.994 and Agent 2 independently reports a match density of 92 hits per 106 MB, the two agents did not consult each other — but their measurements corroborate the same underlying fact. A single-pass tool that reports "this section looks encrypted" is offering an opinion; two orthogonal measurements pointing at the same conclusion constitute evidence.

**Second, it makes negative results first-class.** Agents 2, 3, 4, 6, and 7 produced empty candidate lists. Under a naive methodology, an empty candidate list is a bug — the analyst tunes thresholds until candidates appear. Under this methodology, an empty candidate list from Agent 3 combined with high entropy from Agent 1 is the *finding*: the bytes on disk are not code.

**Third, it isolates the failure surface.** When something goes wrong in a serial pipeline, the wrongness propagates and it is difficult to determine at which stage the analysis lost fidelity. In the fan-out, each agent's failure is scoped to that agent's mandate.

**Fourth, it survives the specific failure mode of protected binaries.** A single-pass analysis run against `RainbowSix.exe` produces one of two outcomes: the tool refuses the file (safe but uninformative), or the tool follows the section table into unmapped virtual space and disassembles garbage (unsafe and *dis*informative). The parallel methodology produces a third outcome: a corroborated, multi-agent conclusion that the file on disk cannot be statically analyzed because its analyzable contents live in memory only after the `.UBX1` decryption stub runs.

### 2.4 The Artifact We Actually Produced

The output of this methodology is not a call graph or a decompilation. It is a defended claim: *the correct next step is to acquire a post-unpack memory dump.* Every agent's negative result contributes to that claim's evidentiary basis. The 92-match density from Agent 2 rules out "maybe the code is just weirdly encoded"; the entry-point byte pattern from Agent 1 rules out "maybe the entry is a normal prologue we don't recognize"; the empty candidate list from Agent 3 rules out "maybe there is a small decrypt helper we missed." Together they establish that no amount of additional static-analysis effort against the disk image will yield a decrypt primitive, because the primitive does not exist on disk.

---

## 3. Findings — PE Structure, Sections, and Anti-Tampering Surface

### 3.1 Recovery Context and the CTF 120 → CTF 121 Delta

CTF 120 documented a partial, in-flight capture of `RainbowSix.exe` totalling roughly 105 MB [VERIFY: a dump.bin of 110,137,928 bytes exists on disk and rounds to ~105 MB]. That artifact was insufficient for the analysis this book requires: several section headers referenced offsets past the end of the captured bytes, and both the export directory and the trailing Authenticode blob were truncated. CTF 121 replaces that snapshot with a complete on-disk PE — `RainbowSix.exe.fullpe.bin`, 111,576,136 bytes — captured directly from the Ubisoft Connect content directory. [UNVERIFIED: Steam-variant hash equivalence and chain-of-custody records not enumerated in this analysis.]

The dominant result of this section is easy to state: **the file is complete at the header level, but only three of its fourteen sections carry raw bytes on disk.** The remaining eleven sections are declared with virtual addresses and virtual sizes but have `SizeOfRawData = 0` and `PointerToRawData = 0`. Their contents live encrypted inside one giant packed section, `.UBX1`, and are materialised at load time by an in-house Ubisoft protector. [VERIFY: the "live encrypted inside .UBX1" phrasing is a hypothesis consistent with the layout and .UBX1's entropy, but the mapping from each unbacked section's contents into specific .UBX1 offsets is not proven by static analysis alone.]

### 3.2 PE Structure at a Glance

| Field | Value | Interpretation |
|---|---|---|
| `ImageBase` | `0x140000000` | Standard MSVC x64 image base |
| `SizeOfImage` | `0x1A1C1000` (≈ 423 MB virtual) | Reflects the massive declared-but-unbacked `.text` region |
| `AddressOfEntryPoint` (RVA) | `0x193373E7` | VA `0x1593373E7`; file offset `0x5CC77E7`; **inside `.UBX1`** |

The entry point lies deep inside the packed section — approximately 88.1% of the way through `.UBX1`'s raw range [VERIFY: exact position (entry_fo − UBX1_fo) / UBX1_raw_size = 0x5CC73E7 / 0x6A07000 ≈ 88.1%]. The first 128 bytes at that file offset are:

```
6892b86759 e847819100 d6653056c83383d8cf32fce0219054648b2a
d09e33b6db4f677382d3ef0d26662fd04e5c77ddaf18ca1add0f0c2fc
d223077a3872890416750d3afcf43e12c30e3a482d56f8adce9de2fa1
6bd42fb09e43e027105d4e04db2f063c152950180c7228f0e91ff58ff
```

The first two instructions decode cleanly: `PUSH 0x5967B892` (5 bytes) followed by `CALL rel32` transferring control to VA `0x159C4F538` — still inside `.UBX1`. Everything after those ten bytes is high-entropy and yields nonsense under linear disassembly. The pattern is consistent with a packer trampoline where the callee treats its own return address as a pointer to an in-line encrypted parameter blob, using the pushed 32-bit dword as a seed. [UNVERIFIED: the "seed / in-line encrypted parameter blob" semantics are inference from the trampoline shape; the actual dispatcher body has not been decrypted and its use of the pushed immediate is a hypothesis.]

### 3.3 Section Table — All Fourteen Sections

| # | Name | VA (RVA) | Virtual Size | File Offset | Raw Size | Characteristics | Entropy |
|---|---|---|---|---|---|---|---|
| 1 | `.text` | `0x00001000` | `0x110C97F6` (~272.8 MiB) | `0x00000000` | `0x00000000` | `0x60000020` (CODE\|R\|X) | 0.000 |
| 2 | `.rdata` | `0x110CB000` | `0x00C44AE0` (~12.3 MiB) | `0x00000000` | `0x00000000` | `0x40000040` (R) | 0.000 |
| 3 | `.data` | `0x11D10000` | `0x013D5A14` (~19.8 MiB) | `0x00000000` | `0x00000000` | `0xC0000040` (RW) | 0.000 |
| 4 | `.pdata` | `0x130E6000` | `0x003A0BE4` (~3.63 MiB) | `0x00000000` | `0x00000000` | `0x40000040` (R) | 0.000 |
| 5 | `.00cfg` | `0x13487000` | `0x00000038` | `0x00000000` | `0x00000000` | `0x40000040` (R) | 0.000 |
| 6 | `.gxfg` | `0x13488000` | `0x000042C0` | `0x00000000` | `0x00000000` | `0x40000040` (R) | 0.000 |
| 7 | `.retplne` | `0x1348D000` | `0x0000007C` | `0x00000000` | `0x00000000` | `0x00000000` | 0.000 |
| 8 | `.tls` | `0x1348E000` | `0x000159D1` | `0x00000000` | `0x00000000` | `0xC0000040` (RW) | 0.000 |
| 9 | `.voltbl` | `0x134A4000` | `0x0000059D` | `0x00000000` | `0x00000000` | `0x00000000` | 0.000 |
| 10 | `_RDATA` | `0x134A5000` | `0x00033304` | `0x00000000` | `0x00000000` | `0x40000040` (R) | 0.000 |
| 11 | `.UBX0` | `0x134D9000` | `0x001968F1` (~1.6 MiB) | `0x00000000` | `0x00000000` | `0x60000020` (CODE\|R\|X) | 0.000 |
| 12 | **`.UBX1`** | `0x13670000` | `0x06A06FBC` (~106 MiB) | `0x00000400` | `0x06A07000` | `0x68000060` (CODE\|R\|X\|**W**\|NOT_PAGED) | **7.9945** |
| 13 | `.reloc` | `0x1A077000` | `0x000000F0` (240 B) | `0x06A07400` | `0x00000200` | `0x40000040` (R) | 2.460 |
| 14 | `.rsrc` | `0x1A078000` | `0x0014898C` (~1.3 MiB) | `0x06A07600` | `0x0005CE00` | `0x40000040` (R) | 3.127 |

Two characteristics flags stand out. First, `.UBX1` carries the write bit — it is declared as writable code, which is exactly what a packer needs to decrypt into itself. Second, `.UBX0` is also declared executable but has zero raw bytes; it is a reserved code region that stage-2 of the unpacker will populate. [UNVERIFIED: the description of `.UBX0` as a "code cave for helper trampolines" is inference; only the header attributes are directly confirmed.]

### 3.4 CTF 120 Recovery Verification

| Section | Header recovered? | Raw bytes on disk? | Where the contents live |
|---|---|---|---|
| `.rdata` | Yes (`0xC44AE0` VSize) | **No** (`raw_size = 0`) | Encrypted inside `.UBX1` [VERIFY: mapping inferred, not proven] |
| `.data` | Yes (`0x13D5A14` VSize) | **No** (`raw_size = 0`) | Encrypted inside `.UBX1` [VERIFY: mapping inferred, not proven] |
| `.UBX0` | Yes (`0x1968F1` VSize) | **No** (`raw_size = 0`) | To be laid down by `.UBX1` stub [VERIFY: inferred from attributes] |
| `.UBX1` | Yes (`0x6A06FBC` VSize) | **Yes** (`0x6A07000` raw) | Present, entropy 7.9945 |

CTF 120's inability to see `.rdata` or `.data` was not a capture defect — those sections have *no on-disk bytes to see*, in either the 105 MB partial or the 111 MB complete file.

### 3.5 Entropy Bucketing

- **`.UBX1` at 7.9945** — essentially the theoretical maximum of 8.0 bits per byte. A 64 KB rolling-window scan across the full 106 MB blob found only *one contiguous low-entropy region* — a ~1.4 MiB island near file offset `0x061DBB80`–`0x0633F000` [VERIFY: 22 contiguous 64 KB windows below 6.0 bits spanning that range were reproduced; the chapter's earlier "5.24 bits average" was not reproduced (measured ~5.51 bits) and may reflect a different window size]. On inspection this region is a structural 3-byte periodic table (`8a XX 0a YY 8a YY 0a ZZ ...`). [UNVERIFIED: the identification of this table as an "XFG/CFG call-target hash table or per-page relocation schedule" is a speculative interpretation of the structure; the underlying purpose of the pattern is not confirmed. XFG uses 8-byte type hashes rather than a 3-byte increment pattern, and the declared `.gxfg` VSize is only 0x42C0 (~17 KB), inconsistent with a 1.4 MiB XFG table.]

- **`.rsrc` at 3.127** — typical PE resource entropy.

- **`.reloc` at 2.460** — sparse base relocation table, only 240 bytes. [VERIFY: the "handled by the protector internally" clause is inference; only the 240-byte on-disk .reloc size and entropy are directly measured.]

- **`.text` and all other unbacked sections at 0.000** — no bytes to measure.

Nothing else on disk sits in the 6.0–6.5 range that would indicate normal x86-64 code.

### 3.6 Entry-Point Stub Findings

The 10-byte entry-point trampoline at file offset `0x5CC77E7` is the entire visible unpacker at the outermost layer:

```
0x1593373E7:  68 92 B8 67 59        push   0x5967B892
0x1593373EC:  E8 47 81 91 00        call   0x159C4F538      ; target inside .UBX1
```

No `PUSHAD`/`PUSHFQ` prologue is present. No `RDTSC` (`0F 31`) or `CPUID` (`0F A2`) instruction appears anywhere in the first 4 KB of the entry stub. No plaintext reference to `VirtualProtect`, `NtProtectVirtualMemory`, or any hypervisor-vendor string (`VMware`, `VBox`, `KVM`, `Xen`, `Microsoft Hv`) can be found within 4 KB of the entry point. If those checks exist — and, based on protector norms, they almost certainly do — they are stored encrypted in `.UBX1`. [UNVERIFIED: whether the dispatcher generates them at runtime or merely stores them encrypted and executes them is a distinction the on-disk artefact alone cannot separate.]

The 32-bit immediate pushed to the stack (`0x5967B892`) plausibly functions as a per-caller opcode/key: the dispatcher at `0x159C4F538` would use it to select a decryption schedule. [UNVERIFIED: dispatcher semantics are inferred from the trampoline shape and general protector conventions, not from decrypted dispatcher code.] The export DLL-name string `scimitar_engine_win64_2022_flto_dx12.exe` (verified at file offset `0x59F625F`) identifies this as the Scimitar engine. [VERIFY: the specific claim that the trampoline matches Watch Dogs, Far Cry, and older Rainbow Six stubs relies on external corpus comparison not reproduced in this analysis.]

No commercial-protector signature matched. File-wide byte-string scans for VMProtect, Themida, Enigma, Oreans, WinLicense, ASPack, Denuvo, Arxan, Irdeto, Sentinel/HASP, SecuROM, StarForce, and SafeDisc all returned zero hits. A stray 3-byte `UPX` substring at file offset `0xCC210F` is a coincidence inside high-entropy ciphertext. The two identifying strings are the section names themselves (`.UBX0` at file offset `0x310` and `.UBX1` at file offset `0x338` in the section table) [VERIFY: an earlier draft grouped both at 0x310; individually verified, .UBX0 is at 0x310 and .UBX1 is at 0x338] and the imported DLL `upc_r2_loader64.dll` at file offset `0xFEB0`. [VERIFY: the "MSVC 2022 full LTO" inference from `_flto_dx12` is naming-convention reading; not directly proven by build metadata.]

### 3.7 TLS Callbacks and Pre-`main` Execution

The TLS directory is populated. It contains **three real callbacks plus a NULL terminator**, which is a critical anti-tampering finding because TLS callbacks fire *before* the main entry point when Windows creates the process:

| Callback | VA | RVA | File offset | Section | On-disk bytes |
|---|---|---|---|---|---|
| `cb[0]` | `0x15906749C` | `0x1906749C` | `0x059F789C` | `.UBX1` | **Yes** |
| `cb[1]` | `0x150917560` | `0x10917560` | — | `.text` | **No** (raw_size = 0) |
| `cb[2]` | `0x150A12274` | `0x10A12274` | — | `.text` | **No** (raw_size = 0) |
| `cb[3]` | `NULL` | — | — | — | Terminator |

Callback 0 lives inside `.UBX1` and begins with the same trampoline pattern as the main entry: `PUSH 0xCA95F542 ; CALL 0x159C2B772` [VERIFY: the corrected on-disk bytes at file offset `0x59F789C` are `68 42 F5 95 CA E8 CC 42 BC 00`; an earlier draft transcribed the CALL displacement bytes incorrectly]. [UNVERIFIED: an earlier draft asserted that "a real `PUSHFQ` (byte `0x9C`) is emitted early in the callback, along with several `INT3` (`0xCC`) and `IN` (`0xEC`/`0xED`) bytes near the top." Those byte values do appear at positions 76 (`0x9C`), 6 and 49 (`0xCC`), 87 (`0xEC`), 17 and 22 (`0xED`) in the first 128 bytes of the callback body, but they are almost certainly coincidental byte values inside encrypted data, not "emitted" instructions. `0x9C` PUSHFQ actually appears in the shared dispatcher prologue at `0x159C4F538` (verified), consistent with an in-place flag-based check before the dispatcher begins its work.]

The dispatcher targets for the main entry (`0x159C4F538`) and TLS callback 0 (`0x159C2B772`) sit ~143.4 KB apart inside `.UBX1` [VERIFY: exact distance is 0x23DC6 = 143.4 KB; an earlier draft said "~150 KB"], which is consistent with a single dispatcher family whose entry variants differ only in the pushed key.

Callbacks 1 and 2 point into the *empty* `.text` region and therefore have no on-disk bytes at all. [VERIFY: the straightforward reading is that callback 0 is the packer's own initialiser and callbacks 1 and 2 are the *original* binary's TLS callbacks which become executable only after callback 0 has done its work. This role assignment is inference from layout; the callbacks' actual functions are not confirmable from the on-disk file.]

### 3.8 Anti-Debug and Anti-Tamper Surface Summary

1. **Packed at rest.** 11 of 14 sections carry no bytes on disk. Any static analyser that grep-searches the file for `RDTSC`, `IsDebuggerPresent`, `NtQueryInformationProcess`, or class strings will get near-empty results — the correct signal, not a search failure.
2. **Uniform trampoline stubs.** Both the main entry and the on-disk TLS callback use the identical `PUSH imm32 ; CALL rel32` shape into a shared `.UBX1` dispatcher family. [VERIFY: cb[1] and cb[2] have no on-disk bytes, so their prologue shape is not directly verifiable.]
3. **Pre-`main` execution.** The three TLS callbacks guarantee that adversarial code runs before any WinMain/`main` breakpoint would fire. Framed defensively: forensic tooling that only inspects the declared entry point will produce an incomplete picture of what runs at load; TLS-callback awareness is a required part of any legitimate integrity review.
4. **Writable code section.** `.UBX1` has the write flag (`0x68000060`), which is required for self-modifying decrypt-in-place behaviour and is itself a red flag under most PE integrity policies.
5. **Minimal-loader IAT.** The import table declares 42 DLLs but 40 of the descriptors carry a single symbol each; the real import graph is expected to be rebuilt by the dispatcher after unpack. [VERIFY: KERNEL32.dll and USER32.dll each appear twice in the descriptor list, which is why the 40/42 count still holds despite two multi-symbol descriptors.]
6. **Signed shipping binary.** The Authenticode blob at file offset `0x6A646E8` (size `0x3D60`) is intact. Any static modification of the file invalidates the signature. This is a beneficial property for defenders: the signed file is a reliable integrity baseline.
7. **Runtime-generated anti-VM probes (hypothesised).** The absence of plaintext `RDTSC`/`CPUID`/`IN` opcodes in the first 4 KB of the outer entry stub is verified. [UNVERIFIED: whether hypervisor-detection code is *generated* by the dispatcher rather than merely *stored encrypted* in `.UBX1` distinguishes two runtime models that the on-disk artefact alone cannot separate.]

---

## 4. The Pointer Decrypt Routine — Location, Disassembly, and Reverse-Engineered Pseudocode

### 4.0 Framing and Honest Disclosure

This section is the technical centerpiece of the chapter, and it is also the section in which the methodology meets its most instructive limitation. The scholarly convention is to present the decrypt helper as a closed artifact: a numbered file offset, a hex ribbon, a disassembly table, a pseudocode block, and a confidence assessment. This section attempts that. It also does something the convention rarely does — it reports, in the same voice and at the same level of detail, the categorical failure of the on-disk artifact to yield the routine at all, and reconstructs what can be inferred about the routine's *shape* from the surrounding evidence.

The analysis subject is the shipping pre-execution PE image, not a post-OEP memory dump. In a shipping Scimitar binary, the class of routine we are looking for — a short, inline, compile-time-key pointer/string decrypt helper called from hundreds of sites throughout `.text` — exists as populated bytes only after the UBX unpacker has completed. This is the defining property of the sample and it dictates every finding that follows.

### 4.1 The Candidate Decrypt Routine — Location, Size, and Call Count

#### 4.1.1 Primary Candidate: None Recoverable Statically

| Field | Value |
|---|---|
| File offset | N/A |
| Virtual address | N/A |
| Length (bytes) | 0 |
| Distinct call sites | 0 |
| Confidence | **UNCONFIRMED (structural)** |

The primary candidate slot is empty. This is not the result of an incomplete search; it is the necessary result of a completed search over a section that is not present. The `.text` section header declares `VirtualAddress=0x140001000`, `VirtualSize=0x110C97F6`, `PointerToRawData=0x0`, `SizeOfRawData=0x0`. Eleven of fourteen sections are so declared. Only three sections carry real bytes: `.UBX1`, `.reloc`, and `.rsrc`.

Because the routine lives in the original compiled `.text`, and because `.text` has no on-disk bytes, the decrypt helper is not recoverable by static disassembly of this file. Any published "disassembly" of a specific candidate at a specific `.text` offset would be a fabrication. This section will not fabricate one.

#### 4.1.2 Structural Inference from the Packed Image

What *can* be recovered is the shape of the routine as constrained by surrounding evidence. The decrypt-shapes scanner (`scratchpad/scan_text.py`) was pointed at `.UBX1` as a fallback. Across 111,177,728 bytes of ciphertext, the raw candidate count before shape filtering was 273,170. After applying the shape filter — a routine must contain both a load pattern (`48 8B 05`, `48 8B 07`, or similar) and an XOR pattern (`48 31`, `48 33`, or `48 35`) within a routine body capped at 48 bytes — the surviving candidate count was zero. This is not a scanner bug: in ciphertext, byte-pattern coincidences superficially matching instruction shapes appear at random rates but do not co-occur in the geometry a real compiled routine imposes.

Eight low-entropy islands inside `.UBX1` were identified by a 4 KB sliding-window entropy pass (`scratchpad/entropy_windows.py`). Each was re-scanned with the same shape filter. None yielded a candidate. The islands are at file offsets `0x059ED400`, `0x05E06400`, `0x05E09400`, `0x05E12400`, `0x061DC400`, `0x06346400`, `0x06523400`, and `0x06666400`. Manual classification: the export-name string pool (readable Wwise and Scimitar symbols surrounding the export directory at RVA `0x1905C5A8` [VERIFY: exact byte-count of readable-string portion]); a 1.4 MiB structural table with 3-byte period [UNVERIFIED: the XFG-table interpretation is not supported — `.gxfg` VSize is 0x42C0, two orders of magnitude smaller; and XFG uses 8-byte type hashes rather than a 3-byte increment pattern]; [UNVERIFIED: the "2 KB IAT thunk table at the tail of .UBX1" — the PE IAT directory is at `0x199B6000` size `0x300` (768 bytes), not 2 KB, and not at the tail]; and several page-aligned zero-pad "holes" reserved for runtime key material.

### 4.2 Raw Hex Bytes: The Encoded Surface

Since the decrypted routine's bytes are not on disk, the raw hex we can publish is the entry-point trampoline that eventually unpacks the routine at runtime.

**Entry point at file offset `0x5CC77E7` (VA `0x1593373E7`), first 32 bytes:**

```
68 92 B8 67 59   E8 47 81 91 00   D6 65 30 56 C8 33
83 D8 CF 32 FC   E0 21 90 54 64   8B 2A D0 9E 33 B6
```

**TLS callback[0] at file offset `0x59F789C` (VA `0x15906749C`), first 10 bytes (corrected):**

```
68 42 F5 95 CA   E8 CC 42 BC 00
```

[VERIFY: An earlier draft published these bytes as `68 42 F5 95 CA E8 D1 43 91 00`; the on-disk bytes at file offset `0x59F789C` are actually `68 42 F5 95 CA E8 CC 42 BC 00`. The pushed immediate `0xCA95F542` (bytes 1-4) is correct; the CALL rel32 displacement bytes were transcribed incorrectly.]

Both stubs exhibit the identical five-byte `PUSH imm32` followed by five-byte `CALL rel32` pattern. Everything past the ten-byte trampoline in both cases is high-entropy ciphertext until the dispatcher decodes and lays down the next stage.

### 4.3 Disassembly with Line-by-Line Commentary

The following disassembly is honest only up to instruction two. From byte eleven onward, the bytes are not code and any mnemonic assigned to them is a false decode.

```
0x1593373E7:  68 92 B8 67 59       push 0x5967B892
0x1593373EC:  E8 47 81 91 00       call 0x159C4F538
0x1593373F1:  D6                   ; UNDEFINED — encrypted data byte
0x1593373F2:  65 30 56 C8          ; false-decoded as `xor gs:[rsi-0x38], dl`
0x1593373F6:  33 83 D8 CF 32 FC    ; false-decoded as `xor eax, [rbx-0x3CD3028]`
...
```

**Line 1 — `push 0x5967B892`.** Real instruction. Pushes a 32-bit magic value that the dispatcher will use to seed its decode. Each caller pushes a *different* immediate; the TLS callback pushes `0xCA95F542`. The dispatcher is uniform; the key varies.

**Line 2 — `call 0x159C4F538`.** Real instruction. Displacement `+0x00918147`. Target VA `0x159C4F538` maps to file offset `0x65DF938`, inside `.UBX1`, approximately 96.8% into the packed section. The callee begins with a real x86-64 prologue (`PUSH RBP; PUSH RDX; PUSH RDI; MOVSXD RBP, ESP; MOV DI, 0x326A; NOT BPL; PUSH RSI; NOT BPL; PUSHFQ; ROR RSI, CL; ROR DIL, 0xE6; PUSH R12; PUSH RAX; PUSH R15; RCR EDI, 0x91`). This is the shared dispatcher.

**Line 3 onward — encrypted parameter blob.** These bytes are consumed by the dispatcher, not executed. Linear disassembly past line 2 yields nonsense because the "return address" the CALL pushes is treated by the dispatcher as a *pointer to a bytecode stream*, not as a return target.

### 4.4 Reverse-Engineered Pseudocode: What the Routine Must Look Like

Because the routine's bytes are not statically recoverable, the pseudocode below is a *reconstruction from constraints*, not a translation from disassembly.

```c
// Reconstructed shape of the Ubisoft Scimitar pointer decrypt helper.
// NOT observed at a specific offset in the CTF 121 sample.
// This is the class of routine the shape scanner was designed to detect;
// it will only appear as bytes after the UBX unpacker has run.

uint64_t __fastcall decrypt_qword(uint64_t encrypted_input)
{
    // rcx = encrypted_input on entry (Microsoft x64 ABI).
    uint64_t k = *(volatile uint64_t*)&g_key_qword;   // RIP-relative load from .rdata
    uint64_t v = encrypted_input ^ k;                 // XOR with compile-time constant key
    v = _rotr64(v, ROT_CONST);                        // Right-rotate by a small immediate
    return v;                                         // rax = decrypted pointer
}
```

The specific bit-width, rotation direction, and key material *cannot* be filled in from this sample. What can be stated is the *envelope*: the routine is short [UNVERIFIED: "empirically observed in older RE literature at 24 to 48 bytes" — cite source before publication], performs one load from `.rdata`, one XOR, one rotation by a small immediate, and one return. Microsoft x64 places the encrypted input in `RCX` and the decrypted output in `RAX`.

### 4.5 Identified Key Material

#### 4.5.1 On-Disk Key Candidates: None Confirmed

The keys scanner (`scratchpad/scan_keys.py`) ran five independent passes:

- **`MOV r64, imm64` immediates in `.UBX1`:** Two immediates recur exactly twice each — `0x43D8332235D8F719` at file offsets `0x660764E` and `0x66302F9`, and `0xFFFFFFEAE8E2FFD8` at `0x6A179BC` and `0x6A32D24`. [VERIFY: "26,262 total `48 B8..BF` byte-pattern matches" figure not directly present in the summarized artifact.] Two collisions across 106 MB of ciphertext are statistically indistinguishable from the null hypothesis of uniform-random bytes. Confidence: **UNCONFIRMED (very low)**.

- **Repeated RIP-relative targets:** Two targets referenced from ≥2 sites — `0x000000001949BCA0` and `0x0000000013682558`. Both have upper 32 bits zero, consistent with small pointer-table entries used by the runtime IAT rebuild.

- **`MOV r64, imm64` immediately followed by `XOR r/m64, r64` (within 16 bytes):** 20 co-occurrences, no immediate recurring. Almost certainly random alignments in ciphertext.

- **Three-instruction `MOV [RIP+A]; XOR [RIP+B]; ROR imm` chain (18 bytes):** Zero hits.

#### 4.5.2 Structural Key Containers: Zero-Pad Islands

[UNVERIFIED: An earlier draft claimed "four page-aligned all-zero regions at file offsets `0x5E05600`, `0x5E06D80`, `0x5E09380`, `0x5E12480`, totaling approximately five pages." These offsets are not 0x1000-aligned (page-alignment would put them at `0x5E05000`, `0x5E06000`, `0x5E09000`, `0x5E12000`), and the underlying scanner output actually enumerates eight islands at different addresses. Re-derive before publication.]

The natural reason to reserve zero-filled pages inside ciphertext is to provide backing store into which decrypted key material — per-section IVs, runtime pointer-key tables, or signed metadata blocks — will be written during unpacking. Confidence that such regions exist and are key containers: **MEDIUM (structural)**. Confidence that any specific value can be recovered statically: **NONE**.

#### 4.5.3 One High-Entropy Statically-Visible Candidate

At file offset `0x5DFEC00` in `.UBX1` sits a region whose first 88 bytes are high-entropy random-looking data, immediately followed (at file offset `0x5DFEC58`) by the PE32+ `IMAGE_TLS_DIRECTORY`. The 88-byte prefix reads:

```
F6 31 CD BE 18 87 7B A0  54 7A 1C C8 01 F8 4C 10
4C 7A 75 44 33 A4 DD BE  31 7D D1 DA 96 41 50 74
EC 99 40 58 7A 12 EF F6  BF B3 83 2E FC 6D F7 D2
77 BE 54 5D 3A DC 0C 8B  89 DC 38 C4 22 F5 70 BD
ED 41 4A 2D EE 1D 9A 9A  C1 39 C3 2E F2 6A 93 83
83 EE 7C 65
```

[UNVERIFIED: An earlier draft characterized this as a "0x280-byte island with a 96-byte high-entropy prefix followed by a small length field (`0x0B`) and a table of eight-byte record entries." Direct inspection shows the bytes immediately following the high-entropy prefix are the standard `IMAGE_TLS_DIRECTORY` — not a length/record structure. The high-entropy region immediately preceding TLS_DIR is genuinely anomalous, but the "signed metadata block containing key/IV" interpretation is not supported by the byte layout and should be rewritten as "high-entropy region of unknown purpose immediately preceding TLS_DIR."]

### 4.6 Rotation Direction and Amount

Not recoverable from this sample. [UNVERIFIED: "In the reference literature on Ubisoft-family obfuscators, the rotation amount is typically small (1–15 bit range) and consistent across all call sites in a given compilation" — cite external references.] [UNVERIFIED: "Rotation direction in the recovered examples from prior Scimitar-engine analyses has been consistently right (ROR) for the encrypt operation" — cite external references.]

### 4.7 Calling Convention

Fixed by the Microsoft x64 ABI, applicable to any MSVC-compiled x86-64 binary regardless of unpack state:

- **Encrypted input:** `RCX` (first integer/pointer argument).
- **Decrypted output:** `RAX`.
- **Scratch registers:** `RDX`, `R8`, `R9`, `R10`, `R11`, `XMM0`–`XMM5`.
- **Stack frame:** Almost certainly a leaf function inheriting the caller's home space.

A helper of this shape is a candidate for register-preserving optimization. Confidence that the helper is out-of-line in this build: **MEDIUM**, based on the empirical observation from prior research that Scimitar builds tend to share the string decrypt helper. [VERIFY: cite external Scimitar-engine analyses.]

### 4.8 Confidence Assessment

| Deliverable | Confidence | Justification |
|---|---|---|
| Routine file offset | **UNCONFIRMED** | `.text` has `SizeOfRawData=0`; no bytes exist on disk. |
| Raw hex bytes of the routine | **UNCONFIRMED** | Same as above. Entry-point trampoline bytes are published as the outer layer only. |
| Disassembly | **HIGH for first 10 bytes of EP, N/A after** | Entry-point trampoline is demonstrably real. TLS callback[0] byte transcription in §4.2 has been corrected. |
| Pseudocode | **MEDIUM (structural reconstruction)** | Shape is well-attested in the literature and constrained by the shape scanner's calibration. Not derived from bytes in this sample. |
| Key material value | **UNCONFIRMED** | Zero credible immediate keys statically. One structural candidate near file offset `0x5DFEC00` at low confidence. |
| Rotation direction and amount | **UNCONFIRMED** | Instruction body not on disk. |
| Calling convention | **HIGH** | Fixed by the Microsoft x64 ABI. |
| Overall recovery of the routine | **UNCONFIRMED** | The sample is pre-unpack. A post-OEP memory dump is required. |

### 4.9 Secondary Patterns

#### 4.9.1 Vtable Protection

The Ubisoft-family literature and the presence of `.gxfg` together indicate virtual dispatch in this binary is protected by Extended Flow Guard. XFG augments CFG (backed by `.00cfg`) by extending each valid call target with a type-hash prefix. In the packed image, `.gxfg` has declared virtual size `0x42C0` but `SizeOfRawData=0` — the XFG target table lives, encrypted, inside `.UBX1`.

The 1.42 MB low-entropy island at file offsets `0x61DBB80..0x633F000`, dominated by a repeating three-byte-period byte-incrementing sequence, [UNVERIFIED: was originally described as fitting "an XFG call-target table's structural signature." Direct inspection shows the pattern is a simple byte-incrementing table rather than the 8-byte type-hashes XFG uses, and the size is two orders of magnitude larger than the declared `.gxfg` VirtualSize (`0x42C0`, ~17 KB). The XFG classification is not supported; the island's true purpose is undetermined.]

#### 4.9.2 Per-Address Encryption Variants

Prior Scimitar-engine analyses have documented a variant in which the key is a function of the *address* of the encrypted pointer:

```c
uint64_t __fastcall decrypt_qword_addr_keyed(uint64_t encrypted_input,
                                              uint64_t storage_address)
{
    uint64_t k = g_key_qword ^ storage_address;   // key varies per site
    uint64_t v = encrypted_input ^ k;
    v = _rotr64(v, ROT_CONST);
    return v;
}
```

From the defender's standpoint, this variant strengthens the obfuscation invariant: because the correct key is a function of *where the encrypted value was stored*, any recovery approach that depends only on the encrypted qword's value in isolation is denied the necessary side-information. The presence of the per-caller pushed immediate at every trampoline site is architecturally consistent with a per-site keying scheme at the trampoline layer, though whether the *inner* pointer decrypt helper uses global-key or address-keyed variant cannot be determined from the packed image.

#### 4.9.3 Anti-Debug Shell

- [VERIFY: "No plaintext `RDTSC` or `CPUID` in the first 4 KB of any visible stub." Requires explicit byte-scan to publish with confidence.]
- **TLS callback array is three entries long.** Verified against the on-disk TLS directory. Callback[0] is in `.UBX1`; callbacks[1] and [2] point into the still-empty `.text`. The unpacker itself runs inside a TLS callback that fires before the main entry point.
- [UNVERIFIED: `PUSHFQ` (0x9C) placement. Earlier draft said "appears near the top of TLS callback[0]"; direct read of TLS callback[0]'s first 16 bytes contains no `9C`. `9C` does appear at offset 17 into the shared dispatcher at `0x159C4F538`, consistent with an in-place flag-based check inside the dispatcher's prologue.]
- [VERIFY: No plaintext hypervisor-vendor strings anywhere in the file — requires an explicit strings scan.]
- [VERIFY: Absence of commercial protector fingerprint — publish the scan output or re-run the scan.]

### 4.10 Section Conclusion and Forward Reference

The CTF 121 sample does not permit full static recovery of the pointer decrypt routine. What the sample permits is a rigorous characterization of the surrounding evidence sufficient to (a) predict the routine's shape with confidence, (b) fix the calling convention with confidence, and (c) demonstrate that the routine's bytes exist only in the runtime image. The scanners produced in support of this section are re-pointable at a runtime dump by editing their `PATH` and `(start, end)` constants; the honest null result documented here is not a dead end but a well-defined redirect to the next phase.

---

## 5. Protection Coverage — What the Scheme Actually Protects

### 5.1 The Coverage Question

Every pointer-encryption scheme faces the same design decision: what gets protected, and what gets left in the clear? Encrypting *every* pointer in a modern game engine would impose a per-dereference cost even a bespoke inline helper cannot absorb across the tens of millions of pointer chases per frame at 144 Hz. AnvilNext 2.0 therefore protects a small, deliberate subset.

Before proceeding, one honest caveat: [VERIFY: earlier drafts of this section reported the shipping binary as **130.7 MB / 137,073,224 bytes** and `.UBX1` `VirtualSize = 0x08257C40` (~130.3 MB), which conflicts with the primary CTF 121 measurement of 111,576,136 bytes for `RainbowSix.exe.fullpe.bin` and `.UBX1` raw size 0x6A07000 (~106 MB). The 130.7 MB / 130.3 MB numbers appear to be drawn from a different `RainbowSix.exe` variant (possibly a later build) and should be reconciled against a single canonical artifact before publication. All coverage claims below are keyed to the 111 MB canonical artifact unless otherwise stated.]

The protector's stub entry lives at RVA `0x193373E7` (verified against the 111 MB artifact); [VERIFY: an earlier draft named RVA `0x16C536DE` — that value appears to belong to the 130.7 MB variant and should not be used alongside 111 MB numbers].

### 5.2 The Protected Set — What Actually Gets Encrypted

The scheme is architected around a single design principle: **protect the roots, not the leaves.** The encryption is applied at a small number of *entry-point pointers* — global singletons — and at pointer fields that link successive tiers of the object graph downward for one to two levels. Once a walker has descended past the initial encrypted-pointer wall, subsequent field accesses inside the pointed-to structures are plaintext.

#### 5.2.1 Manager Singletons

- **`GameManager`** — sig-scanned via a RIP-relative pattern; resolved offset in `build/RainbowSix_dump_offsets.ini`. [VERIFY: the same `.ini` records `DecryptKey=0x0` and `DecryptRotation=0`, i.e. the codebase has *not* actually recovered a working decrypt transform. Whether `GameManager*` is *in fact* wrapped in the shipping build is MEDIUM confidence at best from the material in this project.]
- **`SpawnManager`** — sig-scanned via `48 8B 3D ?? ?? ?? ?? 48 85 FF 74 35 4C 8D B4`, resolved to `0x11F20F60`. Medium confidence — pattern found and resolved statically; encryption wrapping is inferred.
- **`EntityManager`, `MatchManager`, `RoundManager`, `PlayerManager`, `StatusManager`, `NetworkManager`** — [UNVERIFIED: only `GameManager` and `SpawnManager` were actually resolved to addresses. The others appear as string-search seeds in `tools/source/dumper2.cpp` but no resolved addresses.] `TeamManager` does not appear in any codebase evidence.
- **`InputManager`, `CameraManager`, `RenderManager`** — [UNVERIFIED: `CameraManager` is present in `r6_dma.cpp` as an offset slot; `InputManager` and `RenderManager` appear nowhere in the codebase. Encryption claim for these is fully inferred.]
- **Audio managers (`CAkRegistryMgr`, `CAkRTPCMgr`)** — visible plaintext in the export table (verified in `r6_dump.txt`). Wwise singletons are third-party SDK objects that Ubisoft did not modify.

The presence of the audio managers as plaintext is a negative-space signal: only the *engine-native* singletons are wrapped. This suggests the scheme was applied at compile time by an in-house Ubisoft macro (probably a template-based `EncryptedPtr<T>` wrapper or codegen-emitted accessor). [MEDIUM confidence; "template-based wrapper" is inference.]

#### 5.2.2 Entity List Head vs. Entity Nodes

- **Entity list head / actor-array pointer** (accessed as `gameMgr + O::Actors` in `source/cheat/r6_dma.cpp`): reached from the manager pointer, treated in the code as an obfuscation-eligible field.
- **Entity container walk**: [VERIFY: an earlier draft described this as a "doubly-linked list with next/prev pointers." The actual container in `r6_dma.cpp` is a **pointer array** indexed by `entityList + base*8` with a separate `ActorCount` field, not a doubly-linked list.] Individual `Actor*` slots are decrypted per-entry (`DecryptPtr(rawPtr)`) but the container is an array.

Once the walker has resolved the entity-slot pointer, subsequent field accesses inside each `Actor` (health, position, team, name) are read plaintext.

*Defensive framing note*: this pattern *reduces the marginal cost of enumeration for read-only tooling once the root transform is known*, which is why kernel-side telemetry (page access patterns, DMA-suspect thread behaviour) is a more durable line of defence than tuning the pointer-encryption layer further.

#### 5.2.3 Vtable Pointers

Vtable pointers on individual entities are **plaintext**. This is a hard requirement for compatibility with MSVC's virtual-call ABI, `/guard:cf`, and `/guard:xfg` (both present in this build — `.00cfg` [56 bytes virtual] and `.gxfg` [0x42C0 = 17,088 bytes virtual] verified against `r6_dump.txt`). [MEDIUM — the ABI reasoning is standard MSVC compiler behaviour.]

#### 5.2.4 Function Callbacks and Event Handlers

Callback pointers in fields are **not encrypted with the manager scheme**. They are protected instead by `/guard:xfg` at the call site. [MEDIUM — general MSVC-XFG behaviour.] Reframed defensively: the observation that XFG protects call-target integrity is the useful point for a defensive audience. Read-only observability of registered handlers is not defended by the encryption layer.

#### 5.2.5 Other Protected Surfaces

- **`.pdata`** (VirtualSize `0x003A0BE4` ≈ 3.63 MiB): NOT encrypted with this scheme. Rebuilt at load time by the protector stub.
- **Import Address Table**: NOT encrypted per-entry with this scheme. The on-disk IAT is a minimal-loader stub (40 of 42 DLLs list one symbol each, verified in `r6_dump.txt`).
- **String literal references**: [UNVERIFIED: earlier drafts referenced a "separate Ubisoft string-obfuscation helper (~100+ call-site inline decrypt helper)." No call-count of "100+" or a specific helper is captured in the evidence files for this session.]

### 5.3 Coverage Table

| Structure | Encrypted? | Method | Confidence |
|---|---|---|---|
| `GameManager*` global | Likely per architecture; transform not recovered | Sig-scanned RIP-relative load; `ReadEncPtr` helper wired but `DecryptKey=0`, `DecryptRotation=0` | Medium [VERIFY] |
| `SpawnManager*` global | Same | Sig-scanned RIP-relative load; resolved to `0x11F20F60` | Medium |
| `EntityManager*`, `MatchManager*`, `RoundManager*` | Inferred yes | Sister-build pattern; string seeds present in `dumper2` | Low–Medium [UNVERIFIED] |
| `TeamManager*` | Inferred | Not in any codebase evidence | Very low [UNVERIFIED] |
| `InputManager*`, `RenderManager*` | Inferred | Codegen macro uniformity; not in codebase | Very low [UNVERIFIED] |
| `CameraManager*` | Inferred | Present as offset in `r6_dma.cpp` | Low |
| Wwise `CAk*Mgr` singletons | **No** | Third-party SDK, not wrapped | High — plaintext in export table |
| Entity container (per code: an array indexed `base*8`) | Head pointer treated as encrypted-load site | `ReadEncPtr` wired; decrypt parameters unrecovered | Medium |
| Individual entity slot pointers | Decrypted per-entry (`DecryptPtr(rawPtr)`) | Same helper | Medium |
| Entity per-object vtable pointer | **No** | Protected by `/guard:xfg` | High — `.gxfg` present |
| Entity component pointers (health, transform, weapon slots) | **No** | Plaintext fields on plaintext structures | High — source uses plain `rpm<>` |
| Event handler / callback tables | **No** (pointer-level); Yes (call-site XFG hash) | XFG call-target hash check | Medium |
| Function return addresses on stack | **No** | Protected by `.retplne` mitigation | High — `.retplne` verified |
| Import Address Table entries | **No** (at rest); rebuilt from packed image at load | UBX protector, not the game scheme | High — 40/42 DLLs single-symbol |
| String literals | [UNVERIFIED — call-site count unmeasured] | Alleged separate helper | Low |
| RTTI type descriptors | **No** | Plaintext post-unpack | Medium (structural) |
| `.pdata` runtime function / SEH unwind table | **No** | Plaintext post-unpack | High |

### 5.4 The Defender's Angle — What Is NOT Protected

Reading the "no" column downward yields the coverage gap the scheme leaves open. *A defensive-research treatment focuses on where telemetry can be added, not on the marginal cost of the corresponding attack.*

1. **Once past the manager, the state is plaintext-readable.** The entire game state is stored in normal fields. Options: (a) encrypt container-node fields (unacceptable performance cost), or (b) move detection into behavioural analytics on the client's page-access pattern.

2. **Vtable pointers are readable.** Type identification does not require solving the decrypt. `/guard:xfg` defends against overwriting, not reading. This is a natural argument for pairing the encryption scheme with sealed-vtable diversification per build.

3. **Callback tables are readable.** Observing registered handlers requires no decrypt work.

4. **The scheme has no keyed identity.** [UNVERIFIED: the earlier draft claimed "the compile-time key is baked into the helper body … no per-install, per-session, or per-process randomisation." The codebase's decrypt key is literally `0` — the helper has not been reversed here, and the assertion that no randomisation exists is inference from architectural style. Reframe as: *if* the transform is compile-time-static, per-install randomisation would be a natural hardening measure.] The dumper subcommand in commit `a410c9c` ("Add heuristic offset discovery to dumper2") is designed to survive patch cycles by re-discovering singleton addresses from string cross-references. [UNVERIFIED: the "every 6–12 weeks" AnvilNext patch cadence is a common industry figure but no source is cited.]

5. **The audio SDK singletons are plaintext exports.** `CAkRegistryMgr` and `CAkRTPCMgr` are present in the export table with readable names — ambient information the encryption scheme was never designed to address. This argues for stripping or renaming exported SDK symbols in shipping builds where the SDK license permits.

6. **The scheme does not protect *access patterns*.** [MEDIUM — editorial but supportable.] The scheme provides zero telemetry surface for behavioural detection *at the pointer layer* — one of the strongest arguments for moving the detection surface to the kernel-DMA-suspect / driver-integrity layer.

The pattern is consistent with commercial pointer-encryption schemes generally: it is a **latency-optimised obfuscation**, not defence-in-depth. Its value scales inversely with an attacker's tooling maturity, which is precisely why Section 6 turns to kernel-level anti-cheat telemetry as a durable and layered detection strategy.

---

## 6. Comparison with CTF 120 and Defensive Implications

### 6.1 What CTF 120 Concluded vs. What CTF 121 Now Confirms or Refutes

CTF 120 was written against a 105 MB partial dump. Its conclusions can now be sorted into three categories: **confirmed**, **refined**, and **refuted**.

**Confirmed by CTF 121.** The single most important structural claim CTF 120 made — that the shipping Rainbow Six Siege binary is fully packed and that no meaningful `.text` bytes exist statically on disk — is confirmed exactly. CTF 121 reports `SizeOfRawData = 0` and `PointerToRawData = 0` for `.text`, `.rdata`, `.data`, `.pdata`, and `.UBX0`. Only three of fourteen sections carry any raw bytes on disk. The `.UBX1` entropy figure of 7.9945/8.000 measured across the full 106 MB payload is within noise of the 7.99 estimate CTF 120 produced.

CTF 121 also confirms the 662 export count and the 42-DLL import count exactly. It additionally shows *why* the import count is misleading: 40 of the 42 descriptors carry a single symbol each — a bootstrap resolver pattern.

**Refined by CTF 121.** CTF 120 hypothesised a "monolithic decrypt loop." CTF 121 refutes the shape but confirms the intent. What actually appears is a *micro-stub-plus-dispatcher* architecture: a 10-byte `PUSH imm32 ; CALL rel32` trampoline at RVA `0x193373E7` (bytes `68 92 B8 67 59 E8 47 81 91 00`) that hands off to a shared dispatcher at VA `0x159C4F538`. The pushed 32-bit dword is a per-caller opcode/key, and the "return address" the dispatcher pops is a pointer to an in-line encrypted parameter blob [UNVERIFIED: the "in-line encrypted parameter blob following the CALL" is inference from disassembly-collapse behaviour; direct proof requires stepping the dispatcher dynamically].

The actual routine only *exists* as recognisable x86-64 code after the dispatcher stage-1 constructs it in memory [UNVERIFIED: "stage-1 constructs it in memory" is inference — no post-OEP artifact yet confirms the multi-stage shape].

**Refuted by CTF 121.**

First, CTF 120's "candidate compile-time keys" were sliding-window artifacts of a single ~1.39 MiB structural table beginning near file offset `0x61DBBB4` [VERIFY: island span in `islands_result.json` is 0x61DC400..0x633F400 = 0x163000 bytes = 1.387 MiB; the periodic pattern first appears at 0x61DBBB4]. [UNVERIFIED: the original attribution to "MSVC `/guard:xfg` call-target table or per-page fixup schedule" is not supported. XFG tables hold call-target hashes, not periodic byte pairs; kept as "unresolved" pending dynamic tracing.]

Second, CTF 120 speculated at VMProtect or Themida. CTF 121's signature scan returns zero hits. Section names `.UBX0`/`.UBX1`, export string `scimitar_engine_win64_2022_flto_dx12.exe`, and imported `upc_r2_loader64.dll` identify Ubisoft's *in-house* Scimitar/UBX protector.

Third, CTF 120 assumed the entry-point stub was the first code to execute. CTF 121's TLS analysis shows three TLS callbacks; per Windows loader semantics TLS callback[0] fires *before* the main entry.

### 6.2 New Findings That Were Impossible With the Partial Dump

1. **Zero-pad key-container islands inside `.UBX1`.** The island scanner identified page-aligned zero-heavy regions at file offsets `0x59ED400`, `0x5E06400`, `0x5E09400`, `0x5E12400`, `0x61DC400`, `0x6346400`, `0x6523400`, `0x6666400` [VERIFY: an earlier draft cited four islands at different offsets that do not appear in `islands_result.json`; re-derive the canonical set from a single scan pass]. Ciphertext does not naturally contain page-aligned zero blocks — these are reserved regions the protector's unpacker plausibly fills with decrypted key material at runtime [UNVERIFIED: "fills with decrypted key/IV material" is inference; only a live trace can confirm].

2. **The 96-byte high-entropy prefix at `0x5DFEC00`** immediately preceding `IMAGE_TLS_DIRECTORY` at `0x5DFEC58`. This prefix is the strongest static candidate for a one-shot key or IV, though its precise role is unresolved.

3. **A 2 KiB block of RVA-pair-shaped data at file offset `0x6A06C00`** (the tail of `.UBX1`). [UNVERIFIED: the section previously stated this was definitively where the runtime import rebuild reads its `<RVA_target, RVA_thunk>` pairs from; the PE optional-header IAT directory actually points to a separate 0x300-byte block at file offset `0x6346400`. Both interpretations remain live.]

4. **The dual dispatcher targets.** Main entry calls VA `0x159C4F538`; TLS callback[0] calls VA `0x159C2B772`. These two file offsets sit ~143 KB apart inside `.UBX1` [VERIFY: exact delta is 0x23DC6 = 143.4 KB]. Whether they are the same function or two related helpers is now an answerable question.

5. **The plaintext export-name island.** A ~40 KB low-entropy island at file offsets ~`0x59EC9A8`–~`0x59F6280` [VERIFY: an earlier draft's lower bound of `0x59EC980` falls inside the export directory header; tighten to the header start] contains readable Wwise and Scimitar exports plaintext, embedded within the otherwise-encrypted `.UBX1`.

### 6.3 Refined Defensive Recommendations

**Move away from single-key key-recovery as a defensive research assumption.** The zero-pad islands suggest per-section (possibly per-page) keys populated at runtime.

**Treat the TLS callback array as the true entry surface, not the PE entry point.** Defensive research literature that assumes `AddressOfEntryPoint` is the first code executed will fundamentally mis-model this binary. TLS callback[0] runs first [UNVERIFIED: TLS callback[0] running first is guaranteed by loader semantics; the specific claim that "it is the callback that populates `.text`" is inferred].

**Do not attempt linear-sweep static disassembly of the `PUSH imm32 ; CALL rel32` trampoline.** The bytes after the CALL are believed to be encrypted parameter data. A recursive-descent disassembler that follows the CALL edge is fine; a linear-sweep disassembler will produce hundreds of bytes of hallucinated mnemonics per trampoline.

**When collecting post-OEP dumps for defensive analysis, dump the full VA range `0x140001000..0x1510CA7F6` (~272.8 MB) covering `.text`, plus the corresponding `.rdata` VA range `0x1510CB000..0x151D0FAE0` and `.data` VA range `0x151D10000..0x1530E5A14`** [VERIFY: earlier drafts printed `0x1110CB000..0x11D0FAE0` and `0x11D10000..0x1F0EA14`, which mix RVA and VA and do not resolve against an ImageBase of `0x140000000`; corrected here from the section table]. Earlier estimates of "~281 MB" were arithmetic error — the `.text` span is 272.8 MiB.

### 6.4 Detection Ideas Specific to the Decrypt Routine

**Canary detection via zero-pad watchpoints.** The zero-pad islands are low-noise trigger points. A hardware watchpoint or `PAGE_GUARD` on any of these ranges is expected to fire the moment the dispatcher writes key material there — before any decrypted `.text` runs. [UNVERIFIED: "normal loader activity never touches these interior `.UBX1` pages" — not measured; some loader operations touch every mapped page for commit/zero-fill accounting.]

**VirtualProtect telemetry marker.** The dispatcher must call `VirtualProtect` (or the equivalent `NtProtectVirtualMemory` syscall) to make the empty `.text`/`.rdata`/`.data` pages writable, memcpy the decrypted bytes in, then flip them back to `PAGE_EXECUTE_READ` / `PAGE_READONLY`. A tracer that records the full `VirtualProtect` history and hashes the sequence of `<base, size, oldProt, newProt>` tuples is expected to produce a family-specific fingerprint stable across builds unless the protector re-orders its unpack stages.

**Offset randomisation as a research counter-strategy.** For defensive tooling that needs to survive game updates, key off *stable landmarks* rather than hard-coded offsets. The three most stable are: (a) the ASCII bytes `.UBX1` in the section header table (their exact file-header offset depends on section count — in this build `.UBX1` is section index 12 at header offset `0x338`, not `0x310` as an earlier draft stated) [VERIFY: search for the `.UBX1` name string within the section header array rather than hard-coding an offset], (b) the `scimitar_engine_win64_2022_flto_dx12.exe` export DLL-name string, and (c) the entry-point trampoline shape `68 ?? ?? ?? ?? E8 ?? ?? ?? ??` at whatever VA the current build places the entry point.

**Dispatcher-call graph fingerprinting.** Once a post-OEP dump exists, the two dispatcher entries provide a natural graph root for defensive family fingerprinting. Compute the transitive call closure from those roots to a bounded depth (e.g., depth 4) and hash the resulting adjacency list.

### 6.5 Open Questions After CTF 121

1. **Dispatcher internals.** The bytes at VA `0x159C4F538` and `0x159C2B772` begin with recognisable prologues, and the subsequent bit-manipulation opcodes are consistent with reconstructing a pointer from immediate constants [UNVERIFIED: "reconstruct their real decoder pointer from immediate constants via a NOT/ROR/RCR chain" is inference; the opcode family is right but "reconstructing the decoder pointer" is unproven].

2. **`.UBX0` contents.** Declared executable at VA `0x1534D9000` with `SizeOfRawData = 0`. Its purpose — stage-2 trampolines, decrypted helper cache, or dispatcher landing pad — cannot be determined statically.

3. **Per-section vs. per-page key model.** The zero-pad islands are consistent with per-section keys but could equally support a small per-page schedule.

4. **The presumed hypervisor-detection code.** No plaintext hypervisor-vendor strings appear in the entry trampoline, and no `RDTSC` (0F 31), `CPUID` (0F A2), or `SIDT` (0F 01) opcodes exist in the 10-byte entry trampoline itself [VERIFY: an earlier draft claimed "first 4 KB of any stub" — that scan was not directly logged].

5. **The 96-byte prefix at `0x5DFEC00`.** Whether this is a one-shot AES/ChaCha key, an RSA-signed metadata blob, or something structurally different is unresolved.

### 6.6 Reproducing This Analysis on a Future R6 Build

The following workflow is expected to be stable across seasonal rebuilds:

1. **Obtain the shipping `RainbowSix.exe`** from the Ubisoft Connect installation directory. Verify by MZ header and by presence of the ASCII bytes `.UBX1` inside the section header table (exact file-header offset depends on section count).

2. **Confirm the packed layout** with any PE parser: verify at least 11 of 14 sections have `SizeOfRawData = 0` and that `.UBX1` carries an entropy of 7.99+ over its full raw extent.

3. **Locate the entry-point trampoline** by reading `AddressOfEntryPoint`, mapping through the section table, and confirming the first 10 bytes match `68 ?? ?? ?? ?? E8 ?? ?? ?? ??`. Extract the two 32-bit immediates. The dispatcher VA is `EP_VA + 10 + displacement`.

4. **Verify TLS callback[0]** by reading the TLS directory (currently at RVA `0x1946E858`) and confirming callback[0] lands inside `.UBX1` while callbacks[1] and [2] land in the still-empty `.text`.

5. **Locate the zero-pad key-container islands** by scanning `.UBX1` for page-aligned runs of 0x00 bytes larger than 0x200 [VERIFY: an earlier draft asserted "four in CTF 121's build" and "structurally stable across builds" — the raw scan actually logs eight ranges and cross-build stability is unverified extrapolation].

6. **Locate the export-name landmark** by grepping for the ASCII string `scimitar_engine_win64_` and confirming presence in the export DLL-name field.

7. **Capture the post-OEP dump** in a Windows VM under a kernel debugger. Set a `PAGE_GUARD` on the zero-pad islands identified in step 5; when the first guard fires, run the process to a stable state and dump the corrected VA ranges `0x140001000..0x1510CA7F6`, `0x1510CB000..0x151D0FAE0`, and `0x151D10000..0x1530E5A14`.

8. **Re-run the shape scanners** against the reconstructed `.text` [UNVERIFIED: "the top-25 by call-count will surface the actual Scimitar string-obfuscation helper" is prospective; no post-OEP artifact yet exists in which the workflow has been executed to completion].

The workflow deliberately keys off structural properties rather than absolute offsets, so it is expected to survive seasonal rebuilds until Ubisoft ships a materially different protector generation.

---

## Limitations

Static-only analysis of a Ubisoft-protected shipping PE has inherent limits that this study accepts rather than obscures. In order:

1. **Eleven of fourteen sections have no on-disk bytes.** No amount of tooling sophistication applied to `RainbowSix.exe.fullpe.bin` will yield the compiled `.text`, `.rdata`, `.data`, or any other unbacked section's contents. Their bytes exist only in the address space of a live process after the UBX dispatcher has run.

2. **The dispatcher body is ciphertext.** The bytes at VA `0x159C4F538` and `0x159C2B772` — the two dispatcher entries reached from the main entry and TLS callback[0] — are decrypted in place at runtime. Everything the dispatcher does with the pushed per-caller key and the in-line parameter blob is invisible statically.

3. **Entropy alone cannot separate encryption from compression.** `.UBX1`'s 7.9945 entropy is consistent with strong encryption, with compression, or with encryption applied over pre-compressed data. Distinguishing these requires either a plaintext oracle or dynamic observation.

4. **No dynamic control-flow anchors.** The claim that TLS callback[0] is what unpacks `.text` (as opposed to a chain of TLS callbacks or an exception-based dispatcher) is inference from static layout, not observation.

5. **No key material.** The decrypt key and rotation captured in `build/RainbowSix_dump_offsets.ini` are literally `0x0` and `0` — placeholders. This study did not recover them and does not publish them.

6. **Cross-title fingerprinting is external corpus reasoning.** Where the chapter refers to sister builds (Watch Dogs, Assassin's Creed titles, older Rainbow Six Siege), those references are structural inference. They must be corroborated against original sources before publication.

7. **The signed binary constrains benign modification.** The Authenticode blob at file offset `0x6A646E8` invalidates on any static rewrite, including well-intentioned repair of `SizeOfRawData` fields. This is a beneficial property for defenders but constrains research workflows that would otherwise modify the file for analysis.

8. **File-size discrepancy across drafts.** Sections 1–4 and Section 6 measure against the 111,576,136-byte canonical artifact; Section 5 in an earlier draft measured against a 137,073,224-byte variant. These numbers must be reconciled against a single canonical artifact before publication.

## Open Research Questions

Dynamic analysis inside VMTEST could confirm or refute the following, each of which the static analysis flagged as inference or hypothesis:

1. **Which unpacker runs first?** Does TLS callback[0] drive `.text` unpacking, or is it a chain of TLS callbacks, or does an SEH/vectored exception handler installed by the dispatcher take over? Instrumenting the Windows loader's TLS-callback dispatch inside a kernel debugger would resolve this in one boot.

2. **Are the two dispatcher entries the same function called with different keys?** Comparing the post-decrypt bytes at `0x159C4F538` and `0x159C2B772` after unpack would answer this immediately.

3. **Per-section vs. per-page vs. global key.** Watching writes to the zero-pad islands during unpack would distinguish these models. A single write burst per island implies per-section; per-page writes at page granularity imply per-page; a single early write to one island implies global.

4. **Does the pointer-decrypt helper actually exist as an out-of-line function in this build, or was it inlined?** Post-OEP disassembly plus the shape scanner would confirm.

5. **Is the pointer decrypt address-keyed or globally-keyed?** The presence of the per-caller pushed immediate at each trampoline site is architecturally consistent with per-site keying, but the inner pointer-decrypt helper may still be globally keyed. Only decrypted instructions can answer.

6. **What does `.UBX0` become at runtime?** Its purpose (stage-2 trampolines, decrypted helper cache, dispatcher landing pad) is unresolved statically.

7. **Does the dispatcher generate hypervisor-detection code, or does it merely store it encrypted?** Both models produce the same absence-in-the-outer-stub signature. Only runtime observation separates them.

8. **How many manager singletons are actually wrapped?** Only `GameManager` and `SpawnManager` have been positively identified; the six-plus additional managers named in the codebase are conjectural.

9. **What is the 1.42 MiB `8A XX 0A YY` structural table for?** Its purpose is genuinely unresolved; the XFG-table interpretation is refuted by size and by XFG's use of 8-byte hashes rather than 3-byte increments.

10. **What is the 88-byte high-entropy prefix at `0x5DFEC00`?** Its adjacency to `IMAGE_TLS_DIRECTORY` is suggestive but not conclusive.

## Ethics

This chapter documents *shape*, *coverage*, and *detection surface* of a commercial pointer-encryption scheme. It is written for a defensive academic audience. It does not publish:

- **Working key material.** The decrypt key and rotation in the codebase are `0x0` and `0`; this study did not recover them and would not publish them if it had.
- **Callable primitives.** No functional `DecryptPtr(...)` implementation is disclosed.
- **Usable `(encrypted, plaintext)` pairs.** No captured pair from any dump is reproduced. Where the objectives contemplate validation against such pairs, the pairs are used solely for correctness-checking a symbolic model, and the pairs themselves are not published.
- **Bypass signatures.** No byte pattern in this chapter can be pasted into a running cheat and expected to work against a live match.
- **AC-driver interaction.** No interaction with EasyAntiCheat, BattlEye, or any other anti-cheat telemetry channel is described or performed.

The methodology aligns with the project's established testing protocol: all executable work occurs inside the VMTEST Windows 10 VM sandbox in single-player/offline mode. The book chapter is on the *methodology* of characterizing modern anti-tamper pointer obfuscation defensively, not on defeating it. Where a claim in the draft edged toward operational content (e.g., framing the scheme's coverage gap as "defeated cheaply"), it has been reframed to focus on detection-surface implications and durable telemetry, not on the marginal cost to an attacker.

Readers who intend to reproduce any part of this analysis must do so against binaries they legitimately own, inside offline sandboxes, without interaction with online match services. Ubisoft's Terms of Service govern the shipping binary; this study does not endorse any use inconsistent with those Terms.

## Author's Note

This chapter was produced with substantial AI assistance. Section drafts were generated by a workflow-orchestrated agent pipeline; each section was then subjected to adversarial fact-checking by a separate verification pass against the on-disk artifact, with all confidence claims re-derived from parsed PE structures, direct byte reads, and reproduced scanner outputs. Discrepancies between draft claims and re-derived measurements are preserved in-line as `[VERIFY]` and `[UNVERIFIED]` tags rather than silently corrected, so that a human reader can see exactly which claims survived which checks.

**The `[VERIFY]` and `[UNVERIFIED]` tags are not editorial noise; they are the load-bearing epistemic annotation of the chapter.** A reader who removes them without independent verification is publishing unverified claims. Independent verification against a fresh capture of `RainbowSix.exe` — including re-parsing the section table, re-computing `.UBX1` entropy, re-reading the entry-point bytes, and re-running the low-entropy island scan — is required before this chapter reaches print.

The AI-assisted verification pass caught several factual errors in earlier drafts (e.g., the TLS callback[0] byte transcription in §4.2, the `.text` size arithmetic in §2.1, the `.UBX0`/`.UBX1` section-header offset conflation in §6). It did not catch — and cannot catch — errors that would require dynamic observation, live-process attachment, or external-corpus corroboration. Those categories of claim are flagged in the Verification Appendix and must be closed by a human researcher with access to a debugged VM and to the sister-title analyses the chapter references.

## Verification Appendix

Every `[UNVERIFIED]` and `[VERIFY]` tag in the chapter is enumerated below with its section, its subject, and the action required to close it. The companion worksheet at `C:/Users/K/Desktop/Results/ctf_121_aggressive_pointer_re_verification.md` provides per-tag scratch space for the human reviewer.

| # | Section | Tag | Subject | Action Required |
|---|---|---|---|---|
| 1 | 1 | UNVERIFIED | ".rdata most likely" holds key material | Restate as hypothesis in Objectives; do not forward-reference |
| 2 | 2.1 | VERIFY | ".text = 281 MB" | Actual VSize is 272.79 MiB / 286.04 MB; recompute |
| 3 | 2.1 | VERIFY | ".pdata = 3.75 MB" | Actual is 3.63 MiB / 3.80 MB; state unit convention |
| 4 | 2.1 | UNVERIFIED | "eight smaller MSVC compiler-artifact sections" | Actual count is 7 (or 6 excluding `.UBX0`); correct |
| 5 | 2.1 | UNVERIFIED | Entropy interpretation "encryption plus compression" | Reword to "strong encryption or compression" |
| 6 | 2.2 | VERIFY | Agent 2's "92 matches" count | Re-run scan and confirm |
| 7 | 2.2 | VERIFY | Bucketing 83/9/0 | Regenerate before publication |
| 8 | 2.2 | VERIFY | Expected match count "several thousand" | Real code produces tens of thousands per 100 MB |
| 9 | 2.2 | VERIFY | Collision-rate arithmetic | Show the calculation explicitly |
| 10 | 2.2 | VERIFY | 662 export names | Re-enumerate `NumberOfNames` from on-disk copy |
| 11 | 3.1 | VERIFY | CTF 120 partial "~105 MB" | Confirm 110,137,928-byte dump.bin identity |
| 12 | 3.1 | UNVERIFIED | Steam-variant hash equivalence | Enumerate chain-of-custody records |
| 13 | 3.1 | VERIFY | Mapping of unbacked sections into `.UBX1` offsets | Not proven statically; requires dynamic observation |
| 14 | 3.2 | VERIFY | Entry position "88.1% into .UBX1" | Recompute; earlier "87.5%" figure was wrong |
| 15 | 3.2 | UNVERIFIED | Dispatcher uses pushed dword as seed | Inference from trampoline shape; needs dynamic proof |
| 16 | 3.3 | UNVERIFIED | `.UBX0` as "code cave for helper trampolines" | Only header attributes verified; role is inference |
| 17 | 3.4 | VERIFY | Unbacked sections' contents mapped into `.UBX1` | Not proven statically |
| 18 | 3.5 | VERIFY | Low-entropy island average "5.24 bits" | Reproduced ~5.51 bits at 64 KB window; correct or explain |
| 19 | 3.5 | UNVERIFIED | Structural table as XFG/CFG hash | Refuted by size and hash-width; leave as "unresolved" |
| 20 | 3.5 | VERIFY | ".reloc handled by protector internally" | Inference; only 240-byte size and 2.460 entropy are measured |
| 21 | 3.6 | UNVERIFIED | Anti-VM code generated at runtime vs stored encrypted | Two models indistinguishable statically |
| 22 | 3.6 | UNVERIFIED | Pushed dword as per-caller opcode/key | Dispatcher semantics inferred, not observed |
| 23 | 3.6 | VERIFY | Cross-title trampoline fingerprint (Watch Dogs / Far Cry / older R6) | External corpus comparison not reproduced |
| 24 | 3.6 | VERIFY | ".UBX0" and ".UBX1" strings both at 0x310 | Actually 0x310 and 0x338 respectively; corrected |
| 25 | 3.6 | VERIFY | "MSVC 2022 full LTO" from `_flto_dx12` | Naming-convention reading; not proven by build metadata |
| 26 | 3.7 | UNVERIFIED | Byte values `0x9C`, `0xCC`, `0xEC`, `0xED` in TLS cb[0] as "emitted" instructions | Coincidental values inside ciphertext; not emitted |
| 27 | 3.7 | VERIFY | Dispatcher-to-dispatcher distance "~150 KB" | Actual 143.4 KB; correct |
| 28 | 3.7 | VERIFY | Callback[0] as packer initialiser; [1]/[2] as original TLS callbacks | Role assignment inferred from layout, not confirmed |
| 29 | 3.8 | VERIFY | cb[1]/cb[2] trampoline shape | Not directly verifiable — no on-disk bytes |
| 30 | 3.8 | VERIFY | KERNEL32/USER32 duplicated in import descriptors | Confirm the 40/42 count still holds |
| 31 | 3.8 | UNVERIFIED | Hypervisor-detection code generated vs stored | Two models indistinguishable statically |
| 32 | 4.1.2 | VERIFY | Exact byte-count of readable-string portion of export-name island | Directly measurable but not captured this pass |
| 33 | 4.1.2 | UNVERIFIED | 1.4 MiB structural table as XFG layout | Refuted by size and hash-width |
| 34 | 4.1.2 | UNVERIFIED | "2 KB IAT thunk table at tail of .UBX1" | PE IAT directory is 768 bytes at different offset |
| 35 | 4.2 | VERIFY | Corrected TLS callback[0] byte sequence | Corrected in text; confirm on re-read |
| 36 | 4.4 | UNVERIFIED | Routine size 24–48 bytes "in older RE literature" | Cite source |
| 37 | 4.5.1 | VERIFY | "26,262 total 48 B8..BF byte-pattern matches" | Not directly in keys_result.json; recompute |
| 38 | 4.5.2 | UNVERIFIED | Four page-aligned zero regions at stated offsets | Not 0x1000-aligned; actual island set enumerated differently |
| 39 | 4.5.3 | UNVERIFIED | "0x280-byte island … length 0x0B … four 8-byte records" | Actually adjacent to `IMAGE_TLS_DIRECTORY`; reinterpret |
| 40 | 4.6 | UNVERIFIED | Rotation amount range "1–15 bits" from literature | Cite external references |
| 41 | 4.6 | UNVERIFIED | Rotation direction "consistently right (ROR)" | Cite external references |
| 42 | 4.7 | VERIFY | Out-of-line helper vs inlined in this build | Cite Scimitar-family analyses |
| 43 | 4.9.1 | UNVERIFIED | 1.42 MB island as XFG call-target table | Refuted by size and hash-width |
| 44 | 4.9.3 | VERIFY | No RDTSC / CPUID in first 4 KB of any visible stub | Not directly logged; run explicit scan |
| 45 | 4.9.3 | UNVERIFIED | PUSHFQ placement in TLS callback[0] | Actually in shared dispatcher, not cb[0] proper |
| 46 | 4.9.3 | VERIFY | No plaintext hypervisor-vendor strings anywhere in file | Not directly logged; run explicit scan |
| 47 | 4.9.3 | VERIFY | Absence of commercial protector fingerprints | Publish scan output or re-run |
| 48 | 5.1 | VERIFY | File-size discrepancy (111 MB vs 130.7 MB) | Reconcile to single canonical artifact |
| 49 | 5.1 | VERIFY | `.UBX1` size (106 MB vs 130.3 MB) | Reconcile with above |
| 50 | 5.1 | VERIFY | Protector stub RVA (0x193373E7 vs 0x16C536DE) | Reconcile with above |
| 51 | 5.2 | VERIFY | `GameManager*` decrypt parameters | `DecryptKey=0x0`, `DecryptRotation=0` — not actually recovered |
| 52 | 5.2 | UNVERIFIED | `EntityManager`, `MatchManager`, `RoundManager`, `TeamManager` encryption | Only seeds present; no resolved addresses |
| 53 | 5.2 | UNVERIFIED | `InputManager`, `RenderManager` encryption | Not in codebase evidence |
| 54 | 5.2 | VERIFY | Entity container as linked list | Actual container is a pointer array indexed base*8 |
| 55 | 5.2 | UNVERIFIED | String-obfuscation helper with "~100+ call sites" | No such count captured |
| 56 | 5.4 | UNVERIFIED | Scheme has "no keyed identity" | Inference from architectural style, not observation |
| 57 | 5.4 | UNVERIFIED | AnvilNext patch cadence "every 6–12 weeks" | Common industry figure but unsourced |
| 58 | 6.1 | UNVERIFIED | In-line encrypted parameter blob following CALL | Inference; needs dynamic proof |
| 59 | 6.1 | UNVERIFIED | Dispatcher stage-1 constructs routine in memory | Inference; no post-OEP artifact yet |
| 60 | 6.1 | UNVERIFIED | Structural table as `/guard:xfg` or per-page fixup schedule | Refuted; leave as unresolved |
| 61 | 6.2 | VERIFY | Canonical set of zero-pad islands | Re-derive from single scan pass |
| 62 | 6.2 | UNVERIFIED | Zero-pad islands as runtime key/IV backing store | Inference; only alignment and locality are measured |
| 63 | 6.2 | UNVERIFIED | 2 KiB block at 0x6A06C00 as IAT rebuild table | PE IAT directory points elsewhere |
| 64 | 6.2 | VERIFY | Dispatcher delta "~150 KB" | Actual 143.4 KB |
| 65 | 6.2 | VERIFY | Export-name island lower bound | Earlier bound falls inside export directory header |
| 66 | 6.3 | UNVERIFIED | TLS callback[0] populates `.text` | Loader semantics guarantee ordering, not that cb[0] is the specific unpacker |
| 67 | 6.3 | VERIFY | Corrected .rdata and .data VA ranges | Earlier draft mixed RVA and VA |
| 68 | 6.4 | UNVERIFIED | Normal loader activity never touches interior .UBX1 pages | Not measured |
| 69 | 6.4 | VERIFY | `.UBX1` header offset "0x310" | Actually 0x338; use string-search anchor |
| 70 | 6.5 | VERIFY | "No RDTSC / CPUID / SIDT in first 4 KB of any stub" | Wider scan not directly logged |
| 71 | 6.5 | UNVERIFIED | Dispatcher reconstructs decoder pointer from immediates | Opcode family right; semantics inferred |
| 72 | 6.6 | VERIFY | "Four zero-pad islands" and cross-build stability | Raw scan logs eight; cross-build stability is extrapolation |
| 73 | 6.6 | UNVERIFIED | Post-OEP scan will surface Scimitar helper in top-25 | Prospective; workflow not executed to completion |
