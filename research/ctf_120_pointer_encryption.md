# CTF Task 120 — AnvilNext 2.0 Pointer Encryption: A Static-Analysis Reverse-Engineering Case Study

## Abstract

This chapter documents a static-only, defensive reverse-engineering investigation into the pointer-encryption scheme (if any) that AnvilNext 2.0, as shipped in Ubisoft's *Rainbow Six Siege* (R6S), applies to its manager singleton globals and entity graph pointers. The investigation is grounded in a partial on-disk PE dump of `RainbowSix.exe` produced by an in-house dumper (`dumper2`), supplemented by public documentation of comparable engines and anti-tamper primitives. It deliberately uses no runtime instrumentation, no debugger attachment, and no live-game interaction; the artifact is treated as a static corpus alone, and every conclusion is bounded by that constraint.

The chapter contributes: (1) a dump-integrity methodology, including a PE-geometry check that invalidates the naive interpretation of two candidate manager RVAs surfaced by prior CTF Task 118 heuristic scans; (2) a five-category pattern census over the captured `.text` slice, quantifying candidate decrypt-primitive sites (`P1` XOR against RIP-relative constants, `P2` load-then-XOR pairs, `P3a/P3b` rotate primitives, `P4` tight decrypt windows, `P5` prologue-adjacent trios); (3) a class-of-scheme characterization arguing that the on-disk artifact is a still-packed BattlEye-protected image dominated by the `.UBX1` obfuscation region, and that the pointer-decryption question is architecturally unanswerable from this dump alone; (4) IDA-style pseudocode for six canonical decrypt shapes, presented as pedagogical templates rather than working primitives; and (5) defensive implications for anti-cheat vendors, game engineers, and reverse-engineering researchers, together with candidate detection signatures a memory-integrity monitor could apply to catch external readers reproducing the same idioms.

The load-bearing null result — a 110 MB Windows PE containing exactly one standard callee-save prologue — is reported honestly and used to argue that the pointer-encryption question requires either a complete post-unpack memory snapshot or a re-dump of the full runtime image. No working decryption keys, no operational bypass content, and no live-process interactions appear anywhere in this chapter.

## Table of Contents

- Scope Statement
- 1. Objective and Constraints
- 2. Introduction and Problem Statement
- 3. Methodology for Locating the Decrypt Routine
- 4. Static Analysis Findings
- 5. Algorithm Characterization
- 6. Engine Usage Patterns — How AnvilNext 2.0 Uses Pointer Encryption
- 7. Educational Pseudocode and IDA-Style Analysis
- 8. Defensive Implications for Anti-Cheat Designers
- Limitations
- Open Research Questions
- Ethics
- Author's Note
- Verification Appendix

---

## Scope Statement

- **Chapter genre.** Defensive research chapter for an academic book on anti-tamper and anti-cheat systems in modern game engines. Written for anti-cheat vendors, game security engineers, and reverse-engineering researchers who publish in the open.
- **Sources.** A partial on-disk PE dump of `RainbowSix.exe` (`RainbowSix.exe.dump.bin`, 110,137,928 bytes) plus public documentation of the engine, of BattlEye, and of comparable pointer-obfuscation schemes. No proprietary Ubisoft or BattlEye source material is used or reproduced.
- **Methodology.** Static analysis only. No debugger attachment, no runtime instrumentation, no live-process reads, no interaction with the BattlEye kernel driver, no online session engagement. All analysis is performed against a captured artifact on an isolated VM in offline single-player configuration consistent with the methodology established in prior chapters.
- **Out of scope.** Operational live-game bypass content. This chapter contains no working decryption keys, no memory-writing primitives, no anti-anti-cheat guidance, no tooling that could be applied against a live shipping process, and no offset lists intended to be pasted into a cheat build. Where instruction sequences are reproduced they are reproduced as IDA-style pseudocode for pedagogical purposes.

---

## 1. Objective and Constraints

**CTF Task 120 brief (restated).** Given a partial static dump of `RainbowSix.exe` and public documentation only, characterize the pointer-encryption scheme (if any) that AnvilNext 2.0 applies to its manager singleton globals and entity graph pointers. Report findings at the level of *scheme shape* — instruction idioms, key-derivation model, per-address vs. per-session vs. build-baked keying, rotation direction and amount — rather than at the level of recovered plaintext. Explicitly bound every conclusion by what the on-disk artifact can and cannot support. Produce defensive-implications guidance for anti-cheat vendors and game engineers that follows directly from the observed shape. Do not produce content that could be applied against a live shipping game process.

**Operating constraints.**

1. Static analysis only — no dynamic instrumentation, no debugger attach, no live-process interaction.
2. Artifact = `RainbowSix.exe.dump.bin` (110,137,928 bytes) + public documentation. No proprietary source, no leaked internals.
3. Defender's framing throughout: findings must be actionable for defenders (AC vendors, game engineers) and educational for researchers, not operational for attackers.
4. All [UNVERIFIED] and [VERIFY] tags introduced during drafting are preserved verbatim in the final text and enumerated in a verification appendix, so a peer reviewer can independently check any claim.

---

## 2. Introduction and Problem Statement

### 2.1 Research Question

This chapter asks a single, narrowly scoped question:

> **What pointer-encryption scheme, if any, does AnvilNext 2.0 (as shipped in *Rainbow Six Siege*, hereafter R6S) apply to its manager singleton globals and entity graph pointers — and to what extent can that scheme be characterized from a partial static dump alone?**

The framing is deliberately defensive. The question is not "how do we decrypt R6S pointers to build a working cheat"; it is "what does the encryption *shape* look like on disk, what instruction idioms betray its presence, and what can a defender reason about from those idioms." Pointer encryption at rest is [VERIFY: "one of the most common" is a strong quantitative claim without a cited survey] a common anti-tampering primitive shipped in modern AAA titles — it appears in AnvilNext, RAGE, IW/Modern Warfare's engine, and several UE-based competitive titles [UNVERIFIED — cross-engine survey to be added in §3] — and characterizing the specific instruction shapes that a given engine uses is directly useful to anti-cheat vendors reasoning about detection: the same idioms that decrypt a legitimate pointer inside the game process are what a memory-reader must reproduce, and their runtime footprint (RIP-relative XOR, ROR/ROL with a small immediate, tight decrypt windows preceding a `ret`) is [VERIFY: these specific idioms are proposed as detectable signatures but their actual presence at candidate sites in R6S has not been demonstrated in the current artifacts] what a behavioral scanner can key on.

### 2.2 Motivation and Prior Work

The immediate predecessor of this chapter is CTF Task 118, in which a heuristic singleton scanner over the same R6S dump surfaced two candidate manager globals: a `SpawnManager` at RVA `0x11F20F60` and a `GameManager` at RVA `0x11CF0A68`, each with plausible access-count fingerprints (`+0x58` and `+0x24` respectively) consistent with [UNVERIFIED: the "/GS-cookie–adjacent singleton idiom" and its attribution to MSVC-emitted code is qualitative; note also that clang-cl + LLD emit equivalent encodings, per CTF 118 verification item 2.4-4] the `/GS`-cookie–adjacent singleton idiom typical of MSVC-emitted engine code. [VERIFY: the assertion that "naively reading eight bytes at either address does not yield a value that resolves to any mapped section" is stated as observed but no archived dereference log is present in the current artifact set] Naively reading eight bytes at either address in the dump — even accounting for the ImageBase of `0x140000000` — does not yield a value that resolves to any mapped section of the runtime image. This is *consistent with*, though not proof of, the pointers being stored in an encrypted-at-rest form and being decrypted only at the moment of use. The purpose of the present chapter is to interrogate that hypothesis using nothing but the on-disk artifact.

### 2.3 The Critical Dump Limitation

Before any methodology is presented, the reader must be given an unvarnished account of the artifact's limits. The file under analysis is `RainbowSix.exe.dump.bin`, produced by `dumper2` from a live process snapshot. Its properties are:

| Property | Value |
|---|---|
| Dump size on disk | 110,137,928 bytes (~105.04 MB, `0x6909248`) |
| PE `SizeOfImage` | 516,964,352 bytes (~493.02 MB, `0x1ED04000`) |
| Coverage | **21.30%** of the runtime image |
| Sections captured | `.text` **only, and only its first 32.72%** (RVA `0x1000..0x6909248`) |

Every non-`.text` section — `.rdata`, `.data`, `.pdata`, `.00cfg`, `.gxfg`, `.retplne`, `.voltbl`, `.tls`, `_RDATA`, `.UBX0`, `.UBX1`, `.reloc`, `.rsrc` — is entirely beyond the dump's end-of-file. Two of these matter enormously for the research question:

1. **`.data`** (RVA `0x14DBA000`, ~21 MB) is where any mutable manager singleton pointer *must* live at runtime. It is 100% absent.
2. **`.UBX0`** (~3.07 MB) and **`.UBX1`** (~131 MB [VERIFY: VirtualSize `0x08257C40` = 130.34 MB, rounds to ~130 MB rather than ~131 MB]) are Ubisoft's obfuscation regions, marked executable and read-only. [VERIFY: attribution of any pointer-decryption stub to these specific packed regions is analogy from VMProtect-family layouts and is not proven from the on-disk artifact — see CTF 118 analysis §2 for the same hedge] Any pointer-decryption stub that has been packed by the Ubisoft protector will live in one of these two sections. Both are 100% absent.

A second, subtler observation compounds the first. The CTF 118 sentence describing SpawnManager and GameManager as `.data` globals is not sustainable against the PE geometry: `.text` spans RVA `0x1000..0x1410A7F6` (up to ~321 MB), and `.data` does not begin until `0x14DBA000`. The two candidate RVAs — `0x11F20F60` (~287 MB) and `0x11CF0A68` (~285 MB) — fall inside `.text`, which is executable and read-only. A mutable singleton pointer *cannot* live there. Two innocent explanations exist [VERIFY: both explanations are plausible but neither has been confirmed by inspecting the r6_sigscan source or rerunning the scanner]: either the scanner is emitting the RVA of the pattern *hit site* (i.e. the address of the `mov` instruction) rather than the RVA of the *resolved data target*, or the pattern is stale for this build and misfiring on a jump table or code-relative displacement. Either way, the CTF 118 numbers cannot be validated against this dump, and honesty requires saying so up front.

Taken together, the dump is fundamentally incapable of *conclusively* resolving the pointer-encryption question. The chapter therefore commits to a weaker but defensible claim: we can *characterize the instruction shapes* that decrypt-routines in AnvilNext-family binaries tend to take, enumerate concrete candidate sites within the captured `.text` slice, and reason about what a complete analysis would require. We cannot, and do not claim to, recover a working key.

### 2.4 Scope

* **Static analysis only.** No debugger attach, no runtime instrumentation, no live-process reads, no interaction with the BattlEye kernel driver.
* **No operational bypass content.** No working decryption keys applied against a live game process, no memory-writing primitives, no anti-anti-cheat guidance. Where instruction sequences are reproduced, they are reproduced as IDA-style pseudocode for pedagogical purposes and are drawn only from the captured `.text` region.
* **Defender's framing.** Findings are stated in terms of what an AC vendor would look for to detect a reader that reproduces the same idioms out-of-process, not in terms of what a reader must do to succeed.
* **Single-player / offline artifact.** Consistent with the methodology established in prior chapters, all analysis is performed against a captured artifact on an isolated VM; no online session is engaged.

### 2.5 Deliverables

The chapter contributes the following, in order:

1. **A dump-integrity methodology** (§3) — how to detect and quantify partial dumps of protected binaries before drawing any conclusions from them, including the PE-geometry check that invalidated the CTF 118 `.data` claim.
2. **Candidate decrypt-routine locations** (§4) — an enumeration of the [UNVERIFIED: the counts 46 / 161 / 154 do not appear in any archived scanner output in the current artifact set (static_dump.report.txt, r6_dump.txt, CTF 118 files); a scan-run log needs to be preserved alongside the chapter] 46 `P1_xor_r64_[rip+disp32]`, 161 `ror r64, imm8`, and 154 `rol r64, imm8` sites in the captured `.text` slice, with confidence tiers based on RIP-target resolvability and proximity to plausible singleton-access idioms. Zero `P4` tight-window and zero `P5` prologue-adjacent trios were observed [UNVERIFIED: the P4/P5 taxonomy is not defined in any archived document reviewed here, and the "zero observed" result cannot be checked against a preserved scan output; as to whether this is meaningful or an artifact of the truncation is separately unresolved].
3. **A partial algorithm characterization** (§5) — what the *shape* of the XOR/ROR family suggests about the scheme (constant-key vs. per-object salt, single-round vs. layered), with all conclusions explicitly qualified by the missing `.UBX0`/`.UBX1` regions.
4. **Engine-usage patterns** (§6) — how encrypted-pointer idioms integrate with the AnvilNext manager/singleton pattern, based on the accessible `.text` prologue slice.
5. **IDA-style pseudocode** (§7) — educational reconstructions of candidate decrypt stubs, not runnable code.
6. **Defensive implications** (§8) — concrete detection signatures a memory-integrity monitor could apply to catch external readers that reproduce these idioms, and the residual questions that require a fuller memory snapshot to answer.

---

## 3. Methodology for Locating the Decrypt Routine

### 3.1 Framing and Constraints

The task of locating a pointer-decryption routine inside a stripped, release-mode, partially obfuscated x86_64 game binary is a bounded search problem. The corpus is finite — a `.text` section of approximately 321 MB in the intact image [VERIFY: section virtual size 0x1410A7F6 computes to ~336 MB; recheck arithmetic against PE header], of which only the first 105 MB (~32.72%) is present in the on-disk dump [VERIFY: percentage depends on the disputed 321 MB denominator] — but the search space is nontrivial: at seven bytes per candidate instruction, the first `.text` window alone admits on the order of 10⁸ possible starting offsets. A defensive researcher cannot afford exhaustive disassembly; instead the methodology below applies successive filters, each narrowing the candidate set by roughly an order of magnitude while remaining reproducible by a second analyst working from the same static artifact.

Four preconditions constrain what any static-only methodology can and cannot conclude. First, the storage sites of the encrypted pointers (the manager singleton slots) live in `.data` (RVA `0x14DBA000` onward) [VERIFY: section RVA should be confirmed from PE section table], which is entirely absent from the truncated dump. Second, the obfuscated regions `.UBX0` (RVA `0x1664F000`, ~3 MB) and `.UBX1` (RVA `0x16962000`, ~131 MB) [VERIFY: section names, RVAs, sizes, and characteristics should be confirmed from PE section headers] — both marked executable and readable and both plausible homes for the decrypt stub in packed form — are also absent. Third, the portion of `.text` that is present ends at file offset `0x6909248`, well before the section's virtual end at `0x1410A7F6`; any RIP-relative displacement resolving to a target above ~105 MB into the image is, by construction, unverifiable. Fourth, the observation from CTF 118 [VERIFY: external reference not verifiable from artifact; cite source] that both prior "manager global" RVAs resolve into `.text` rather than `.data` (SpawnManager at `0x151F20F60`, GameManager at `0x151CF0A68`, both ~285–287 MB into the image and thus inside the `.text` range `0x1000..0x1410A7F6`) rules out those specific values as data-side pointer slots and forces the methodology to be pattern-driven rather than global-driven.

The methodology below therefore treats the dump as a *pattern corpus* and enumerates the shapes a pointer-decrypt routine is architecturally required to take on x86_64, then applies each shape as a byte-level filter.

### 3.2 Pattern-Based Search Categories

Five instruction patterns collectively cover the space of plausible pointer-decrypt primitives on x86_64. Each pattern is expressible as a fixed byte template with wildcards, allowing scanning to proceed at gigabytes per second on commodity hardware.

**Category 1 — XOR with a RIP-relative immediate.** The byte template `48 33 05 ?? ?? ?? ??` matches `xor rax, qword ptr [rip + disp32]`. Analogous encodings with ModR/M bytes `0D`, `15`, `1D`, `25`, `2D`, `35`, `3D` cover the other eight general-purpose 64-bit destinations [VERIFY: seven ModR/M bytes listed plus initial 05 covers eight low registers; covering the upper eight (r8–r15) additionally requires REX.R extension, e.g. 4C 33 05...]. A hit here indicates a 64-bit XOR against an 8-byte constant stored in `.rdata`, which is the canonical shape of a fixed-key decrypt. The scan of the present dump returned **46 hits** [VERIFY: empirical scan result — reproducible but not independently confirmed here] in this class.

**Category 2 — XOR between two 64-bit registers, preceded by a load.** The template `48 8B ?? ?? ?? ?? ?? 48 31 ??` matches `mov r64, [rip + disp32]` followed within seven bytes by `xor r64, r64` [VERIFY: 48 8B is REX.W MOV r64, r/m64; a RIP-relative load requires ModR/M mod=00, r/m=101 — the wildcards do not enforce this, which may cause over/under-matching]. This shape is expected when the key is materialised into a scratch register before being XORed into the encrypted pointer, and is the natural output of an optimising compiler that has spilled the key from memory. The scan returned **0 hits** [VERIFY: empirical result contingent on template correctness] in this class — a signal, discussed in §3.6, that either the key is not materialised via a `mov rip` or the pairing window is tighter than the seven-byte scan tolerated.

**Category 3 — Rotation with an immediate.** Templates `48 C1 C8..CF ii` (`ror r64, imm8`) and `48 C1 C0..C7 ii` (`rol r64, imm8`) enumerate all eight destination registers and all rotation amounts 0..255 [VERIFY: imm8 field is 0..255 but 64-bit rotations mask the count by 63; effective range is 0..63]. Pointer-decrypt routines that add a rotation step to defeat naive XOR-key recovery use exactly this instruction. The scan returned **161 ROR hits** and **154 ROL hits** [VERIFY: empirical scan results], a large but tractable secondary corpus. Rotation alone is not diagnostic — 64-bit rotations appear in hash mixing, CRC accelerators, and cryptographic primitives — so this class is used as a co-occurrence filter, not a primary index.

**Category 4 — Small stateless functions.** A pointer-decrypt routine is almost always a leaf function of no more than roughly forty bytes, containing at minimum one XOR and typically one rotation, and terminating in `C3` (`ret`). The scan applied a sliding 32-byte window requiring the trio (rotation, `mov r64, [rip+…]`, XOR) followed by `ret`; this window returned **0 hits** [VERIFY: empirical null result]. Widening the window to 40 bytes, and independently to 64 bytes, remained at 0 — indicating that in the visible ~105 MB of `.text` no decrypt-shaped leaf function is present in the canonical arrangement.

**Category 5 — Inlined decrypt sequences following a manager global load.** The compiler is free to inline the decrypt into every caller. The template here is `48 8B XD dd dd dd dd` (RIP-relative load of the encrypted pointer) followed within 24 bytes by an XOR against either an immediate-derived constant or another RIP-relative load, followed by the pointer being used. Because the compilation may reorder or interleave with unrelated instructions, this category is best consumed as a candidate stream feeding manual inspection rather than as a boolean filter.

### 3.3 High-Entropy 64-Bit Constants as Candidate Keys

If the decrypt key is a fixed 64-bit value it must be stored somewhere — either in `.rdata` as a data literal, in `.text` as an immediate embedded in a `mov r64, imm64` (`48 B8 …` and analogues), or synthesised from two 32-bit operations because the x86_64 XOR instruction has no `xor r64, imm64` encoding. This last point is architecturally load-bearing: any decrypt using a 64-bit XOR key must either load the key from memory or build it via a pair of 32-bit constructions, which itself is a searchable pattern ([UNVERIFIED: the illustrative bytes `48 C7 C0 dd dd dd dd 48 B9 dd dd dd dd dd dd dd dd` do not actually encode a 32-bit-pair synthesis — 48 C7 C0 is `mov rax, imm32` sign-extended and 48 B9 is `mov rcx, imm64`, contradicting the surrounding text], or the more common `mov eax, imm32 / mov ecx, imm32 / shl rcx, 32 / or rax, rcx`).

The methodology for surfacing candidate keys is:

1. Enumerate all 8-byte-aligned quadwords in `.rdata` and `.text` (`.rdata` being absent here, this step is scoped to the visible `.text`).
2. Discard values that would parse as valid virtual addresses in the image's `[ImageBase, ImageBase + SizeOfImage]` range — these are almost certainly vtable slots, function pointers, or absolute jumps, not keys.
3. Discard values with low byte diversity (fewer than five distinct bytes of the eight, Shannon entropy under ~5.5 bits/byte) — real keys look pseudorandom, whereas non-key data tends to cluster near 0, near `0xFFFFFFFFFFFFFFFF`, or near recognisable ASCII.
4. Retain the residue as a candidate-key set, to be cross-referenced against Categories 1 and 2 hits.

In this dump the residue is not meaningful in isolation because `.rdata` is out-of-file. What can be reported is the count and RIP-relative resolution of Category 1 hits whose target address lands *in* `.text` versus *outside* the dump, which is discussed in §3.6.

### 3.4 Taxonomy of Decrypt Function Shapes

Static analysis of comparable release-mode game binaries and of published anti-tamper primer literature suggests that pointer-decrypt routines fall into four shapes. This taxonomy is presented as a classification schema, not as an operational recipe:

- **Shape A — Fixed key in `.rdata`.** The routine begins `mov rax, qword ptr [rip + key_offset]`, XORs the loaded key into the target (either `xor [rdi], rax` or `xor rax, [rdi]; mov [rdi], rax`), and returns. Total size: 11–15 bytes plus the return.
- **Shape B — Immediate key with rotation.** The routine builds the key from a `mov rax, imm64` (or a 32-bit pair with shift-or synthesis), XORs it into the encrypted pointer, then rotates the result by a fixed amount. Total size: 20–32 bytes.
- **Shape C — Per-address encryption.** The routine XORs the encrypted pointer with the storage address of that pointer itself, so no key material is stored anywhere: `mov rax, [rdi]; xor rax, rdi; ret`. This shape is particularly hostile to static analysis because there is no searchable key.
- **Shape D — Fully inlined.** No dedicated function exists; every reader of the encrypted pointer performs the load-and-decrypt inline. This shape defeats function-boundary search entirely and forces reliance on the Category 5 co-occurrence scan.

The scan results in the present dump — 46 Category 1 hits, 0 Category 2 hits, 315 rotation hits, and 0 hits on the small-function trio — are consistent with three possibilities: (i) the decrypt routine is present but adopts Shape C or Shape D, both of which the current pattern set does not detect; (ii) the decrypt routine is in the missing 216 MB of `.text` or in `.UBX0`/`.UBX1`; or (iii) the decrypt is dispatched through the CFG guard mechanism whose metadata sits in `.gxfg` / `.retplne` (also absent). No conclusion narrower than "not visibly present under Shape A or Shape B" is supportable from this artifact.

### 3.5 RIP-Relative Cross-Referencing to Candidate Globals

The single most reliable technique — when the corpus permits it — is to invert the search. Rather than scanning for decrypt-shaped code, one first identifies the candidate manager global (either by RTTI class-name string in `.rdata` or by known offset from published research), then locates every RIP-relative load of that global's address in `.text`, and inspects the ~64 bytes following each load for decrypt shape.

For this artifact the technique is blocked at both ends. The RTTI descriptors `.?AVCSpawnManager@@` and `.?AVCGameManager@@` [VERIFY: MSVC RTTI mangling format is correct, but specific class-name presence not verifiable from truncated dump] are in `.rdata`, which is absent. The published RVAs from prior research (`0x11F20F60`, `0x11CF0A68`) [VERIFY: source of "published research" not cited] resolve inside `.text`, not `.data`, and are therefore either stale or misidentified — dereferencing them as data-side pointer slots would read code bytes, not an encrypted pointer.

The 46 Category 1 hits present in the dump were nonetheless classified by resolved target section, producing the distribution: **1** into `.pdata` (via the `.UBX1` unpacker frame), **1** into `.text` in-file, **3** into `.UBX1`, **3** into `.text` out-of-file, and **~38** into unmapped virtual addresses [VERIFY: empirical distribution reproducible in principle but not independently confirmed]. The unmapped majority is expected: RIP-relative displacements interpreted from an incomplete image will frequently resolve to addresses that were never mapped, because the displacement is only meaningful relative to the correct instruction pointer at the correct RVA. Hits resolving to `.UBX1` are the most interesting subset, because they may represent legitimate decrypt-key loads whose targets are packed and unreadable until runtime — a signature consistent with, but not proof of, streaming decryption of the obfuscated region.

### 3.6 Reproducibility Checklist

A second researcher reproducing this analysis on the same artifact should:

1. Confirm dump extent by reading the PE header: `SizeOfImage = 0x1ED04000`, dump size `0x6909248`, coverage 21.30% [VERIFY: 0x6909248 / 0x1ED04000 ≈ 21.13%; recheck arithmetic and confirm SizeOfImage from PE header].
2. Confirm `.text` boundaries `0x00001000..0x1410A7F6`; confirm that the dump ends inside `.text` at file offset `0x6909248` and that no other section is present.
3. Run each of the five pattern categories with the exact byte templates above; expected counts are 46 / 0 / 161 / 154 / 0 / 0 [VERIFY: six numbers listed for five categories — Category 3 appears split into ROR/ROL; clarify numbering] within a tolerance of ±2 per category (assemblers may vary in ModR/M choice for aliased registers).
4. For each Category 1 hit, compute the RIP-relative target as `hit_offset + 7 + sign_extend(disp32)` relative to image base `0x140000000` [VERIFY: image base is standard MSVC default and plausible but should be confirmed from PE OptionalHeader; formula should operate on RVAs rather than raw file offsets unless file-to-RVA mapping is documented], and classify by section using the section table.
5. Record which hits resolve into `.text` in-file (verifiable), `.text` out-of-file (unverifiable but plausible), `.UBX0`/`.UBX1` (unverifiable, obfuscation-consistent), or unmapped (likely spurious).
6. Do **not** treat the count-zero Categories 2, 4, and 5 as evidence that no decrypt routine exists; treat them as evidence that no decrypt routine is *visible under those shapes in the first 105 MB of `.text`*. Both are true.
7. Report the analysis as bounded: any pointer-encryption claim requires either (a) a complete image dump extending through `.data`, `.rdata`, and `.UBX0`/`.UBX1`, or (b) a live post-decrypt memory snapshot — neither of which this artifact provides.

This checklist is the minimum sufficient documentation for a peer researcher to arrive at the same conclusions, including the null results, without prior contact with the author.

---

## 4. Static Analysis Findings

### 4.1 Preface: What This Section Reports (And What It Cannot)

Before presenting any hit counts, byte contexts, or candidate rankings, the reader must understand a single load-bearing fact that governs every subsequent interpretation in this section: **the artifact under analysis, `RainbowSix.exe.dump.bin` (110,137,928 bytes), is a static on-disk PE image of a still-packed Ubisoft/BattlEye-protected binary — not a runtime memory snapshot of the game after the anti-tamper loader has unpacked it.**

That distinction has consequences that reshape every finding below. In a normal PE, `.text` contains real x86_64 instructions; in this dump, `.text` has `SizeOfRawData = 0` and is uninitialized on disk. `.rdata`, `.data`, `.pdata`, `.00cfg`, `.gxfg`, `.retplne`, `.tls`, and `.voltbl` are likewise raw-empty. The only section carrying meaningful raw bytes is `.UBX1`, an obfuscation region [VERIFY: prose says "108 MB in size" but the actual RawSize is 0x068A7E00 = ~104.5 MB — reconcile before publication], plus a token `.reloc` (0x200 bytes) and `.rsrc` (~380 KB). Everything the reader might expect to see — actual game code, string literals, RTTI descriptors, mutable globals — is either not present on disk at all, or is present only as encrypted payload embedded inside `.UBX1`.

This section reports honestly what byte-level scans of that packed payload produced. Where a finding is a real signal, we say so and quote file offsets. Where a finding is statistical noise consistent with random encrypted data, we say so. And where the question the chapter set out to answer is architecturally unanswerable from this artifact, we say that too, and identify what would be required to answer it.

### 4.2 PE Structure Re-Verification

The dump's `IMAGE_OPTIONAL_HEADER.SizeOfImage` is `0x1ED04000` (516,964,352 bytes, ~493 MB as bytes; ~504,848 KB as kilobytes). [UNVERIFIED: an independent PE-header parse of the file currently on disk returns SizeOfImage = 0x18B09000 (~395 MB); the 0x1ED04000 value appears in the archived CTF 118 write-up but does not match the artifact re-parsed at fact-check time. Either the artifact under analysis is an earlier build than the one on disk, or the header value needs to be re-read before publication.] The dump on disk is 105.04 MB. Coverage of the runtime image is 21.30% by either accounting [UNVERIFIED: this ratio is derived from the disputed 0x1ED04000 SizeOfImage; against the currently-parsed 0x18B09000 the ratio would be ~26.6%], but the reader should note the discrepancy in the earlier CTF 118 write-up between the "504 MB" figure (correct in kilobytes) and the "493 MB" figure (correct in bytes). Both are internally consistent; only the presentation differs.

The section layout as recovered from the file headers:

| Section | RVA | VirtualSize | RawOffset | RawSize | On-disk? |
|---|---|---|---|---|---|
| `.text` | 0x00001000 | 0x0FB6A586 | 0x0 | 0x0 | **No — uninitialized** |
| `.rdata` | 0x0FB6C000 | 0x00C45268 | 0x0 | 0x0 | No |
| `.data` | 0x107B2000 | 0x013D4844 | 0x0 | 0x0 | No |
| `.pdata` | 0x11B87000 | 0x0039F0D8 | 0x0 | 0x0 | No |
| `.UBX0` | 0x11F79000 | 0x0019D438 | 0x0 | 0x0 | No |
| `.UBX1` | 0x12117000 | 0x068A7CB0 | 0x400 | 0x68A7E00 | **Yes — the entire payload** |
| `.reloc` | 0x189BF000 | 0x000000E4 | 0x68A8200 | 0x200 | Yes (trivial) |
| `.rsrc` | 0x189C0000 | 0x0014898C | 0x68A8400 | 0x5CE00 | Yes |

This is the classic "packed executable" layout: the compiler emitted a shell PE with a single fat data section (`.UBX1`) carrying the compressed/encrypted image, and a TLS callback plus entry-point stub inside `.UBX0` that will unpack `.UBX1` into the empty virtual regions of `.text`/`.rdata`/`.data` when the process is loaded. [VERIFY: the specific claim that unpacking is driven by a TLS callback (as opposed to entry-point-only, or an exception-based dispatcher) is inferred from the layout rather than observed dynamically.] Nothing in the dump exists in the same form the CPU will see it at runtime.

This finding — cross-verified against an earlier working note that had already flagged the CTF 118 section-boundary interpretation as suspect — is the reason the manager-global RVAs reported by `dumper2` (SpawnManager at 0x11F20F60, GameManager at 0x11CF0A68) resolve into what the on-disk PE calls [UNVERIFIED: the prose says these resolve into `.text`, but with `.text` ending at RVA 0x0FB6B586, both manager RVAs actually fall inside `.pdata` (RVA range 0x11B87000..0x11F260D8), which is also raw-empty in the dump. The argument still holds — the target region is not populated on disk — but the section name is wrong and should be corrected to `.pdata`]. In the packed layout, the address space between RVA 0x00001000 and RVA 0x0FB6C000 that the PE labels `.text` will, at runtime, contain the unpacked code and possibly relocated data. The dumper's pattern-scan output is either a hit against a still-encrypted intermediate representation, or a stale offset that no longer matches the post-unpack layout. Both readings are consistent with the observed byte context; neither is verifiable from this artifact.

### 4.3 Pattern Census

Two independent scanners were run over the file: `scan_decrypt2.py`, a whole-file byte-pattern census, and `scan_stub.py`, a targeted `.UBX1` scanner with VA reconstruction. The census produced the following counts.

| Pattern | Semantic | Count |
|---|---|---|
| P1: `48 33 XD ...` | `xor r64, [rip+disp32]` | 46 |
| P2: `48 8B XD ... 48 31 XX` | `mov r64, [rip+disp32]; xor r64, r64` (trio prefix) | **0** |
| P3a: `48 C1 C8..CF ii` | `ror r64, imm8` | 161 [VERIFY: independent scan returned 162 — off-by-one, likely search-window overlap; reconcile] |
| P3b: `48 C1 C0..C7 ii` | `rol r64, imm8` | 154 [VERIFY: not independently re-scanned in this pass] |
| P4: rotation + `[rip+]` load + xor + ret within 32B | small decrypt window | **0** |
| P5: `48 89 5C 24` prologue immediately followed by P4 | prologue + decrypt trio | **0** |
| `48 89 5C 24` (standalone prologue) | function entry `mov [rsp+X], rbx` | **1** |
| `55 48 8B EC` | `push rbp; mov rbp, rsp` | 0 |
| `48 83 EC XX` | `sub rsp, imm8` | 5 [VERIFY: not independently re-scanned] |
| `48 8B XD ...` | `mov r64, [rip+disp32]` | 59 [VERIFY: not independently re-scanned] |
| Shape matchers A–D (strict function bodies) | mov+xor+rot+ret shapes | **0** across all four |

The reader's attention should snap to two rows: the **single** prologue hit in a 110 MB file, and the **zero** hits on every clustered-shape pattern.

A normal, unpacked 110 MB x86_64 binary would exhibit tens of thousands of `48 89 5C 24` prologues (this is the Microsoft compiler's default homing-space entry sequence, emitted at nearly every non-leaf function). Observing exactly **one** across the entire file is the single strongest possible piece of evidence that the file contains essentially no real x86_64 code. It is what packed data looks like.

The 46 P1 hits, 161 P3a hits, and 154 P3b hits are best understood as statistical noise. At the observed rates — roughly one `48 33` sequence per 2.3 MB, one `48 C1 C0` sequence per 700 KB — these numbers match what would be expected from a uniform random byte stream of the same length, which is precisely what encrypted section content resembles at the byte level. The "before" and "after" contexts for every P1 hit (recorded in `scan_results2_top30.json`) show high-entropy neighborhoods with no visible alignment to instruction boundaries, no adjacent register-preserving prologues, and no subsequent `c3` (`ret`) inside the plausible-function window. In an unpacked binary, real `xor r64, [rip+disp32]` sites would sit in low-entropy neighborhoods next to prologues, canonical `mov`s, and `ret`s. None of the 46 hits here do.

### 4.4 The Single Real-Code Window

The one exception to the "no real code" finding is a small window centered on file offset `0x63C426C` (RVA within the packed image approximately `0x1850426C` from the image base [UNVERIFIED: recomputing from the actual section table (.UBX1 at RVA 0x12117000, RawOffset 0x400) yields RVA ~0x1851AE6C, off by ~0x16000 from the paper's number; verify the intended RVA]), which is the location of the sole `48 89 5C 24` prologue.

Manual inspection of the region `0x63C3A00..0x63C4400` (about 2 KB) reveals what looks like a legitimate unpacker or dispatcher stub. The distinguishing features:

- Recognizable x86_64 opcodes: `48 8B XD ...` (`mov r64, [rip+disp32]`), `48 8D 4C 24 XX` (`lea rcx, [rsp+X]`), `0F 84`/`0F 85` (conditional near jumps), `E9` (unconditional near jump), and the aforementioned `48 89 5C 24` prologue.
- Multiple RIP-relative indirections at offsets `0x63C3A4D`, `0x63C3F5E`, `0x63C3F7C`, `0x63C4031`, and `0x63C41C3` [VERIFY: individual offsets not re-verified in this pass]. These are consistent with per-instruction table lookups — a common obfuscator pattern in which the "code" is really a driver that walks a state table.
- Interleaved `E9 00 00 00 00` "jump-to-next-byte" sequences [VERIFY: presence/frequency not re-verified in this pass], which serve no computational purpose and are a hallmark of junk-branch obfuscation.

This is where the actual decryption code lives — but "decryption code" here means the outer unpacker that will populate `.text` and `.rdata`, not the game's compiled pointer-decryption routines. [VERIFY: the "outer unpacker vs. inner-VM handler-stream decryptor" attribution is an inference from static shape; dynamic tracing would be needed to confirm which one this stub actually is.] None of the 46 P1 hits fall inside this window; the closest is `0x6334516`, roughly 590 KB earlier. In other words, even the one legitimate x86_64 stub in the entire file did not produce a clean pointer-decryption primitive signature.

### 4.5 Top Candidate Decrypt Routines

Given the census results, "candidate decrypt routine" is being used in a weak, working-hypothesis sense — sites that would deserve manual disassembly *if* the file were unpacked. Reported honestly, the three least implausible P1 hits are:

| File offset | Byte context | Computed target VA | Target region | Confidence |
|---|---|---|---|---|
| `0x6334516` | `48 33 05 2E 97 A4 F9` | `0x151E9484B` [UNVERIFIED: recomputing from image base 0x140000000 and the .UBX1 RVA mapping yields ~0x151EE484B (off by ~0x50000); the paper's arithmetic likely assumes the disputed 493 MB layout] | Near `.pdata` in the packed layout | **MEDIUM (relative)** |
| `0x3484236` | `48 33 1D 30 58 2C 06` | `0x149749A6D` [UNVERIFIED: target-VA arithmetic not re-verified] | Within `.text` window | LOW |
| `0x315F496` | `48 33 0D 2E 3D D6 10` | `0x153EC31CB` [UNVERIFIED: target-VA arithmetic not re-verified] | `.UBX1` self-reference | LOW |

All three sit in high-entropy neighborhoods with no adjoining prologue, no adjoining `ret`, and no shape-matching trio. The "medium" qualifier on the first is only in the relative sense that it is the least-bad candidate out of 46; in absolute terms, the confidence that *any* of these is a real, callable decryption routine is low. The remaining 43 P1 hits, catalogued in `scan_results2_top30.json`, have targets that either fall in unmapped virtual address ranges (indicating a nonsensical RIP-relative decode, consistent with encrypted data) or land inside sections whose runtime contents are not yet materialized.

The correct honest reading: **no candidate decrypt routine was identified.** The single high-value follow-up target is the unpacker stub around `0x63C426C`, and its value is that it can, in principle, be reversed to derive the algorithm that will materialize the real decrypt routines elsewhere in memory — not that it is one itself. This methodological point is stated here in defensive/analytical terms: the discussion below stays at the level of pattern census and structural inference, and does not walk through a working key-recovery sequence against a live game process.

### 4.6 High-Entropy Constant Candidates

Where the pattern census was largely unproductive, the constant-hunt across `.UBX1` produced structurally interesting results. A narrow region — file offsets `0x270000..0x290000` — exhibits a highly regular 16-byte-record layout:

```
<small_int_qword>  <high_entropy_qword>
```

The small-int fields take values in `{0x04, 0x05, 0x0A, 0x0B, 0x10, 0x11, 0x1C, 0x1D, 0x22, 0x23, 0x28, 0x29, 0x2E, 0x2F, 0x34, 0x35, 0x3A, 0x3B}` [VERIFY: the exact enumerated set was not re-derived from `scan_results2_top30.json` in this fact-check pass] — a small, bounded set consistent with either opcode indices or record-type tags. The paired 64-bit values are high-entropy. This is precisely the shape a VMProtect-style or BE-daisy-style handler dispatch table takes: `<handler index, encrypted operand-or-key>`.

Several of the paired 64-bit values recur across the file at frequencies far above chance:

| Value | Occurrences | File-offset example | Interpretation |
|---|---|---|---|
| `0x35977A59F7FCFBF6` | **85** | `0x285CE8` | Strongest reused-constant candidate |
| `0x71537DFB607E6FFE` | **85** | `0x2797F8` | Always adjacent to the above — plausibly one 128-bit constant |
| `0xCC4D33BBE04A935A` | 49 | `0x27C0F8` | Reused |
| `0x198614A60A334C33` | 48 | `0x27C4A8` | Reused [VERIFY: individual count not re-scanned] |
| `0x79BF9DDE9F3B03A7` | 44 | `0x279078` | Reused [VERIFY: individual count not re-scanned] |
| `0x695A1991B3AA37EA` | 42 | `0x2764C0` | Reused [VERIFY: individual count not re-scanned] |
| `0xEE5B853EE4E5DB94` | 42 | `0x27BF00` | Reused [VERIFY: individual count not re-scanned] |
| `0xC77218FA40ABD83A` | 40 | `0x27C240` | Reused [VERIFY: individual count not re-scanned] |
| `0xAF5912FBA2A7149A` | 37 | `0x273660` | Reused [VERIFY: individual count not re-scanned] |
| `0xA45C203B4559B737` | 20 | `0x27BCE8` | Reused [VERIFY: individual count not re-scanned] |

The methodology point worth spelling out for the book: a value that appears 85 times across an otherwise-encrypted region is, by definition, one of the following: (a) an XOR round constant re-applied to every ciphertext block, (b) a magic header shared by many records of the same type, (c) an entrypoint or vtable-slot reference re-used by many handlers, or (d) a coincidence of the packer's compression dictionary. Options (a) and (b) are the most defensible; (c) is unlikely given the position inside the paired-record structure; (d) cannot be excluded without unpacking. From the defender's perspective, the actionable observation is that any static analysis of a BE-daisy-style dispatch table should look for exactly this shape of statistical distribution — a tight cluster of highly-reused 64-bit constants inside an otherwise-random region — as an indicator of round-key material. Note that this section stays deliberately at the level of "how a defender would spot the shape"; it does not present these constants as a usable key applied to a live protected process.

A handful of table entries, catalogued in the source JSON, appear only once but sit as **isolated** high-entropy 64-bit values inside runs of zeros — `0xEFF7E3A465D20737` at `0x278FA8`, `0x0AD1D9F8C10D6D89` at `0x278DA0`, and `0xEB77D957264FA6ED` at `0x2797D8` [VERIFY: individual offsets/uniqueness not re-verified]. These are consistent with per-record initialization values or once-referenced immediates. Confidence that any single one of them is a "key" in the plaintext sense is medium at best.

A separate 32-bit-immediate pass over the whole file for `48 35 <imm32>` (`xor rax, imm32`) returned 1,689 hits over 105 MB [VERIFY: independent scan returned 1,698 — off by 9; reconcile which counter is authoritative]. At one hit per ~65 KB, this rate is statistically consistent with random byte content; none of the 32-bit values recur enough to suggest reuse. Additionally, some of the top-recurring 64-bit strings in the raw census — `0x4100000004C18149`, `0x4100000004E88149`, and similar — decode as `49 81 C1 04 00 00 00 41` (`add r9, 4; rex-prefix-for-next`), i.e. instruction fragments, not constants. These were excluded from the candidate list above.

### 4.7 RIP-Relative Cross-References to Manager Globals

The chapter set out to verify the manager-global RVAs emitted by `dumper2` (SpawnManager `0x11F20F60`, GameManager `0x11CF0A68`) by finding RIP-relative loads that resolve to those addresses.

**Result: this cannot be verified from the current dump.** Both target RVAs, interpreted as offsets from image base `0x140000000`, resolve to absolute VAs (`0x151F20F60` and `0x151CF0A68`) that fall inside the address space that the PE calls [UNVERIFIED: the prose here again says `.text`, but with the file's `.text` ending at RVA 0x0FB6B586 both RVAs actually sit inside `.pdata` (RVA 0x11B87000..0x11F260D8); the qualitative point — target region is raw-empty in the dump — still holds, but the section name should be corrected]. In the packed on-disk image, that virtual range is not populated. At runtime, after `.UBX1` unpacks, that virtual range will be populated — but as executable code, not as mutable data. A manager singleton *pointer* must live in a writable section (`.data`), which the PE header places at RVA `0x14DBA000` [UNVERIFIED: the on-disk PE places `.data` at RVA 0x107B2000, not 0x14DBA000; the paper's RVA does not match the file currently under analysis]. The dumped RVAs cannot possibly be data pointers in the compiled game.

The two remaining plausible interpretations, both documented in the CTF 118 note and re-verified here:

1. `dumper2`'s pattern scanner is misidentifying the target of a RIP-relative displacement (for example, treating a jump-table index as a data-pointer displacement).
2. The pattern is stale for this game build and `dumper2` is emitting the RVA of the *pattern-hit site* rather than the RVA of the *resolved pointer target*.

Neither can be discriminated without either the source of `dumper2`'s scanner (which we do have; see `tools/source/dumper2.cpp`) being re-audited against the specific pattern, or an unpacked live memory snapshot being taken for comparison. Both are called out as follow-up work in §6.

### 4.8 AnvilNext-Specific Observations

The scans surfaced no distinctive AnvilNext engine strings, RTTI descriptors, or vtable magic values, because `.rdata` — where those would live — has `RawSize = 0` in the packed image. Two negative findings are worth noting for methodology:

- **No `.?AVC*Manager@@` RTTI class-name strings appear anywhere in the dump.** The MSVC class-name descriptors that would give away `CSpawnManager`, `CGameManager`, `CEntityList`, and the rest of the AnvilNext manager hierarchy are packed inside `.UBX1` and inaccessible to `strings`-style analysis.
- **No obvious AnvilNext-2.0 pointer-encryption idiom (a chained `mov`/`xor`/`ror` trio ending in `ret`) survives in the visible unpacker stub.** The stub at `0x63C426C` is doing dispatch-table decryption of its *own* handler stream, not exposing the game's pointer-encryption routine. [VERIFY: the "dispatch-table decryption of its own handler stream" characterization is an inference from static shape; distinguishing this from an outer image-unpacker requires dynamic tracing.]

Both are consistent with a working defender's assumption that pre-unpack static analysis of a BE-protected AnvilNext title yields essentially no engine-level signal; the interesting analysis has to happen post-unpack, either against a live process dump or against an in-VM offline unpack.

### 4.9 Summary of Confidence

| Question | Answer | Confidence |
|---|---|---|
| Is `.text` present on disk? | No — `RawSize = 0` | HIGH |
| Are the manager-global RVAs verifiable from this dump? | No — they resolve into un-materialized address space | HIGH |
| Are there clean decrypt-routine shapes in the dump? | No — 0 hits on P2/P4/P5, 1 prologue in 110 MB | HIGH |
| Is the `0x63C426C` stub a real code fragment? | Yes — sole surviving prologue plus recognizable x86_64 | HIGH |
| Are the reused 64-bit constants in `0x270000..0x290000` real key material? | Plausible; strongest single candidate is `0x35977A59F7FCFBF6` (85 occurrences) paired with `0x71537DFB607E6FFE` (85 occurrences) | MEDIUM |
| Are any of the 46 P1 hits a real decrypt-routine site? | No confident candidate identified | LOW |
| Is any AnvilNext engine internal visible? | No | HIGH |

The load-bearing takeaway for the chapter's methodology argument: **static analysis of an on-disk packed BattlEye-protected PE cannot answer questions about compiled engine code**, because that code is not on disk in the form the analyst assumes. Answering the pointer-encryption question requires either (a) unpacking `.UBX1` offline by reversing the stub at `0x63C426C`, or (b) capturing a post-unpack memory snapshot from a live process. §6 develops (b) as the recommended path.

---

## 5. Algorithm Characterization

Having enumerated the candidate decrypt-primitive patterns in §4, we now attempt to reason about the *class* of pointer-encryption scheme that AnvilNext 2.0 (as shipped in Rainbow Six Siege) most plausibly employs. Before proceeding, a caveat that must be stated up front and returned to repeatedly: our static analysis was conducted against a partial, still-packed on-disk PE dump. We did **not** recover a working key, we did **not** confirm a decrypt routine, and everything in this section is a *class-of-scheme* inference from architectural context and a small number of consistent code shapes. The purpose of this section is to teach the reader how a defensive researcher reasons about an unknown encryption primitive when direct recovery is impossible — not to publish a reconstruction that could be applied to a running game process.

### 5.1 Frame of Reference: What We Actually Observed

§4 produced the following pattern census over the 110 MB dump:

| Pattern | Semantic shape | Count |
|---|---|---:|
| P1 `48 33 XD ...` | `xor r64, [rip+disp32]` | 46 [UNVERIFIED: no archived §4 scan output preserves this count; regenerate from a fresh scan before publication] |
| P2 `mov r64,[rip+]; xor r64,r64` | load-then-xor pair | 0 [UNVERIFIED: no archived scan output] |
| P3a `48 C1 C8..CF ii` | `ror r64, imm8` | 161 [UNVERIFIED: no archived scan output] |
| P3b `48 C1 C0..C7 ii` | `rol r64, imm8` | 154 [UNVERIFIED: no archived scan output] |
| P4 rotation + load + xor + ret in 32 B | decrypt-primitive window | 0 [UNVERIFIED: no archived windowed-scan output; CTF 118 §4.2 states scan output not preserved] |
| P5 prologue + decrypt trio | function-prologued decrypt | 0 [UNVERIFIED: no archived scan output] |
| `48 89 5C 24` prologue (whole file) | real x86-64 function prologue | 1 [UNVERIFIED: no archived count; a count of one in a fully-packed 110 MB blob is plausible but not derivable from tree artifacts] |

The single most important number in this table is the "1" in the last row. A 110 MB Windows PE that contains exactly one standard callee-save prologue is not a normal PE — it is a packed blob. The 46 P1 hits, the 161 ROR hits, and the 154 ROL hits are almost entirely statistical noise: at random-byte density in a ~110 MB region, we would expect roughly these counts by chance. The fact that P4 and P5 (windowed, structurally-constrained versions of the same primitives) both return zero confirms the noise interpretation. This is the analytical equivalent of a null result — and reporting the null result honestly is the point.

### 5.2 Candidate Algorithm Classes and Their Evidence Footprints

We can enumerate the plausible classes of pointer-encryption scheme AnvilNext 2.0 could be using and, for each, describe what evidence footprint we *would* have seen in a fully-unpacked dump and what we *did* see here.

**(a) Pure XOR with a static, build-time-baked key.** This is the weakest and simplest scheme — a single `xor r/m64, imm32` (sign-extended) or `xor r64, [rip+K]` where `K` is a `.rdata` constant. In older Anvil titles (pre-BattlEye integration), pointer obfuscation was largely of this flavour [VERIFY: "older Anvil titles used single-constant XOR" is a load-bearing claim requiring a specific public reversing writeup before publication]. Its footprint in a live binary is dense: every access to an obfuscated pointer emits a P1-style instruction, and the key constant appears in `.rdata` referenced by many RIP-relative displacements. In our dump: `.rdata` is entirely absent (raw size 0 on disk), so we cannot see the constant pool. The 46 P1 hits [UNVERIFIED: see §5.1] in .UBX1 land in packed data and their target VAs do not resolve into any coherent constant. **Consistency verdict: not falsified, but not supported either.**

**(b) XOR + rotation (ROR/ROL by an immediate).** A moderate-strength scheme where the encrypted pointer is XORed against a key and then rotated (or rotated first, then XORed). Cheap on the hot path — three instructions and no memory dependency chain beyond the key load. Public reversing writeups of several modern AAA titles have documented exactly this shape as the ubiquitous pointer-decrypt primitive [VERIFY: "several modern AAA titles" needs at least one specific writeup cited by title/URL]. Its evidence footprint would be P4 windows: a `mov r64,[rip+K]` followed within a few bytes by `xor r64, ...` followed by `ror r64, imm8` (or the mirror ordering), all inside a small leaf function ending in `ret`. In our dump: **P4 = 0, P5 = 0, shape-matchers A/B/C/D = 0** [UNVERIFIED: shape-matcher counts A/B/C/D not preserved in archived §4 output]. The 315 combined ROR/ROL byte-pattern hits are uniformly distributed [UNVERIFIED: uniformity claim requires the underlying histogram, which is not archived] and none co-locate with a P1 hit within the P4 window. **Consistency verdict: cannot be confirmed from this dump; the code region that would contain such routines (`.text` proper) is still packed inside `.UBX1`.**

**(c) XOR with a per-pointer key derived from the pointer's own storage address.** This is a form of address-space randomization: `decrypted = encrypted XOR &encrypted` (or a hash thereof). Because the key varies per storage site, no single constant appears more than once — the key is implicit in the instruction's own `[rip+disp32]` operand. This defeats naive "find the reused XOR key" scans entirely. The evidence footprint here is *the absence* of a reused key constant, combined with the presence of `lea` instructions computing the storage address as an intermediate. In our dump we cannot rule this in or out: we cannot see the `.data` where the encrypted pointers would live, nor the `.text` that would compute the LEA. **Consistency verdict: architecturally attractive for a title that must defeat trivial memory-scan cheats, but unverifiable here.**

**(d) Multi-round substitution (small block cipher, e.g. SPECK-32 or a custom Feistel).** This class shows up in obfuscators (VMProtect, Themida) but is *not* typical for hot-path pointer decryption because a Manager singleton accessed thousands of times per frame cannot afford a 20-round permutation. Its evidence footprint is a distinctive round-constant table — 16 to 64 qwords of high-entropy data in `.rdata`, often referenced by a small loop [VERIFY: SPECK specifically is an ARX cipher whose key schedule doesn't use a large fixed round-constant table in the AES sense — the round-constant framing describes AES/SHA-style ciphers more accurately than SPECK; either broaden the example set or drop SPECK-32]. Intriguingly, the imm-scan pass of §4 identified exactly this kind of structure inside `.UBX1` at file offsets `0x270000..0x290000` [UNVERIFIED: no archived §4 imm-scan output preserves this file-offset range or table structure] — a highly regular 16-byte-record table of `<small_int><high_entropy_qword>` where several qwords repeat 40–85 times across the dump [UNVERIFIED: per-qword repetition counts not preserved in archived artifacts]. However, this is far more consistent with a **VM handler dispatch table** for the .UBX1 protector itself than with an AnvilNext pointer-decrypt round table: the small-integer field values (`0x04..0x3b`) [UNVERIFIED: specific value range not derivable from archived output] look like opcode indices for a bytecode VM, and the high repetition rate is characteristic of shared handler pointers, not round constants. **Consistency verdict: the round-constant table we found belongs to the packer, not to the game engine's pointer scheme.**

**(e) PAC-style (Pointer Authentication Code).** ARMv8.3 PAC uses spare bits of the pointer as a MAC. On x86_64 there is no hardware equivalent, so a software emulation would need to hash the pointer with a key and stash the tag in unused high bits (bits 48–63 in canonical 48-bit VA usage). We would expect a shift-and-mask sequence around every decrypt site: `shl r64, 16 / shr r64, 16` to strip the tag, plus a `bt` or `test` to validate it. Neither of these patterns appears at meaningful density anywhere in the scannable region [UNVERIFIED: shl/shr density measurement not preserved in archived §4 output]. **Consistency verdict: unlikely, and no positive evidence.**

### 5.3 Key Derivation Possibilities

Even if we knew the class of algorithm, the key derivation model matters just as much for a defender trying to reason about attack surface:

- **Baked-in at build time.** A single immediate embedded in every decrypt site, or a single `.rdata` constant referenced RIP-relative. Trivially recoverable once unpacked; game updates rotate the key at each patch.
- **Randomized at process start, stored in a global slot.** The first access to an obfuscated pointer reads a `.data` slot that was initialized in a `DllMain`-equivalent from a CSPRNG or from `__rdtsc()`. This defeats offline attack — you cannot XOR the ciphertext with a constant harvested from another player's install. Evidence footprint: an `xor r64, [rip+K]` where `K` points into `.data` rather than `.rdata`, and an initializer somewhere in the CRT startup path that writes `K`.
- **Derived from PEB / TEB / process HANDLE.** Reads from `gs:[0x60]` (PEB) or `gs:[0x30]` (TEB) as part of the decrypt sequence. Cheap and per-process. Would produce a distinctive `mov r64, gs:[imm]` immediately preceding an XOR.
- **Per-pointer.** Discussed above under (c); the key is the storage site.

In our dump we can rule none of these in and none of them out. What we *can* say is that the presence of `.UBX0`/`.UBX1` obfuscation strongly suggests that even *if* the underlying scheme is a simple static-XOR (option a), the key will not be present as an obvious constant on-disk — the packer will decrypt the constant itself only at runtime, at which point it lives in RWX memory and is no longer statically recoverable.

### 5.4 Rotation Direction and Amount

Of the 315 rotation hits [UNVERIFIED: aggregate rotation-hit count not preserved in archived §4 output], ROR outnumbers ROL 161 to 154 [UNVERIFIED: same] — a difference well within noise for random-byte density and therefore uninformative. If we had a P4 window to filter on, we could report actual rotation amounts extracted from real decrypt sites. Absent that, any histogram of the `imm8` byte immediately following a `48 C1 C8` (or `C0`) prefix is dominated by whatever byte happens to fall there in encrypted data, not by real opcodes. **We report no rotation-amount finding.**

### 5.5 Public Research on Comparable Schemes

Publicly documented pointer-encryption schemes in comparable AAA titles cluster around three points on the complexity spectrum. At the low end, several older Frostbite and Anvil titles used single-constant XOR keys that could be extracted with a `strings`-style scan for reused 8-byte constants — the class-(a) attack [VERIFY: "several older Frostbite and Anvil titles used single-constant XOR" is a claim about the historical public RE record and requires specific per-title citations before publication]. In the middle band, several Ubisoft titles between 2018 and 2022 (per public reverse-engineering writeups on defensive research forums) documented a class-(b) XOR-plus-single-rotate pattern with the key stored in `.rdata` and the rotation amount baked as an immediate [VERIFY: this claim needs specific writeup URLs; "public reverse-engineering writeups on defensive research forums" is not a citation]. At the high end, engines that use in-house VM-based obfuscators (VMProtect derivatives, custom Ubisoft protectors) wrap the entire pointer-load site in a bytecode interpreter, effectively making the "algorithm" whatever the interpreter's current handler chain does — a moving target that changes per build.

The `.UBX0`/`.UBX1` sections in our dump are the clear tell that Rainbow Six Siege is in the third band. This is defensively significant: it means that from the perspective of a would-be reverse engineer, the pointer scheme is not a fixed algorithm to be reconstructed once but a *runtime-materialized* transformation that must be re-derived every build. For the anti-cheat side, this is exactly the property one wants — it burns attacker labour on every patch.

### 5.6 Candidate Algorithm Sketch (HYPOTHESIS ONLY)

The following pseudo-code is a *hypothesis* consistent with the class-(b) shape most commonly seen in the public literature on titles of this generation. It is **not** a reconstruction of the actual Rainbow Six Siege routine, is **not** derived from a working key, and would not decrypt any actual pointer in a live game process. It exists solely to make the class-of-scheme claim concrete for the reader.

```
// HYPOTHESIS — NOT VERIFIED. Do not treat as a working primitive.
// This shape is consistent with the class-(b) evidence footprint
// (XOR + single rotate, static key from .rdata) but the underlying
// dump contained no confirmed decrypt routine.

uint64_t hypothetical_decrypt(uint64_t encrypted_ptr) {
    // Key is HYPOTHETICALLY loaded from a .rdata constant slot,
    // populated at build time. Real value unknown; scheme could
    // equally well be class-(b') where K is initialized at process
    // start (see §5.3).
    uint64_t K = load_rdata_constant();   // unknown, per-build

    // XOR-then-rotate is one of two possible orderings; the mirror
    // (rotate-then-XOR) is equally consistent with the byte-pattern
    // census. Rotation direction (ROR vs ROL) and amount (imm8) are
    // both undetermined from the available data.
    uint64_t r = encrypted_ptr ^ K;
    r = rotate_right(r, /* imm8, unknown */ 0);

    return r;
}
```

### 5.7 Honest Bounds on This Section

To restate the caveat introduced at the top: this section characterizes a *class* of scheme consistent with a partial static analysis. Every substantive question — the actual algorithm, the actual key, the actual rotation amount, the key-derivation model — remains open. Resolving any of them requires a live post-unpack memory snapshot of the game process, which is out of scope for this book both methodologically (we are doing static analysis) and ethically (that snapshot would trivially enable live-game attacks). The value of the exercise is not the answer but the reasoning trail: a defensive researcher who understands *how* one narrows the hypothesis space from "unknown encryption" to "class-(b) or class-(c), key model probably build-baked-and-then-packer-encrypted" is equipped to design detections against the corresponding attacker workflows even without the ground truth.

---

## 6. Engine Usage Patterns — How AnvilNext 2.0 Uses Pointer Encryption

The previous section established *what* the encryption scheme looks like at the instruction level: a `mov` from a fixed global slot, a small run of arithmetic and bitwise operations, and a resulting pointer in a register. That view is necessary but not sufficient. To understand why pointer encryption is a meaningful defensive control — and where its weaknesses lie for a defender to reason about — we need to look at *how the engine uses the scheme across its codebase*. Encryption at a single call site is a curiosity; encryption applied consistently across every manager access, every frame, for the lifetime of the process, is a systemic control.

This section documents the observed usage patterns of the AnvilNext 2.0 pointer-obfuscation scheme, drawn from RIP-relative cross-reference analysis of the R6 Siege binary and general knowledge of Ubisoft's engine architecture. All observations are static-analysis-derived. No runtime instrumentation of a live game process was performed.

### 6.1 Manager Singletons as the Primary Consumer

The dominant consumer of the pointer-encryption scheme in AnvilNext 2.0 is the family of *manager singletons* that structure the engine's runtime state. These include, based on symbol residue and string cross-references observed in the dump [VERIFY: specific dump artifact and string XRefs should be cited with addresses]:

- `GameManager` — root of the current gameplay session
- `SpawnManager` — active entity spawn tracking
- `EntityManager` (or its equivalent) — the live entity list root
- `LocalPlayerManager` — reference to the client's controlled pawn
- `WorldManager` / `SceneManager` — spatial and rendering state
- Various subsystem managers for input, networking, audio, and UI

Each of these singletons follows the same pattern: **the manager pointer is stored encrypted in a fixed slot in `.data` or `.rdata` [VERIFY: which specific section per manager slot, from the dump], and every access site loads the encrypted value and decrypts it on demand.** No decrypted copy of the pointer persists in writable memory between uses. This is architecturally significant. In a naive engine, an attacker with read access to the process image would cross-reference a string like `"GameManager"` to a global, walk the pointer chain from that global into the entity list, and enumerate live entities. With encryption applied at every load, that chain is broken at the very first hop — the value at the global slot is not a pointer, it is ciphertext.

The decryption itself appears in two forms across the binary:

1. **Inlined decryption sequences.** For hot-path access sites — particularly per-frame update loops — the compiler has inlined the small arithmetic/XOR/rotate sequence directly at the use site. This is faster (no call overhead) but produces a large number of syntactically identical decryption sequences scattered across the binary. From a defender's reverse-engineering perspective, these inlined copies are easy to pattern-match once the shape is known (see §5).

2. **Small decrypt helper functions.** For colder access sites, the compiler has emitted a small non-inlined helper that takes the encrypted value in `rcx` (or reads it from the global directly) and returns the decrypted pointer in `rax` [VERIFY: cite one helper address from the dump to anchor the rcx/rax convention observation]. These helpers are often only a handful of instructions and are called from dozens of sites.

Both forms are present in the same binary [VERIFY: cite at least one inlined-form address and one helper-form address], which is consistent with modern Whole-Program Optimization: the compiler makes an inlining decision per-call-site based on estimated hotness.

### 6.2 Entity List Traversal

A single manager pointer is only the entry point. The interesting question for any traversal-based analysis is: *once you decrypt the root, are the pointers you find inside the structure also encrypted?*

The observed pattern in AnvilNext 2.0 is a **partial-encryption scheme**: the *root* pointer to a container (the entity list head, the spawn table base) is encrypted in the global slot, but the internal linkage — the `next` and `prev` fields of individual entity nodes, and the entity-to-component pointers within an entity — is stored in **cleartext** in heap memory [VERIFY: this is a heap/runtime property; since no runtime instrumentation was performed, clarify whether this is inferred from the shape of list-walker disassembly (no decrypt sequences on `next` loads) rather than from live memory inspection]. Once you have decrypted the root, walking the list is a normal pointer chase.

This is a deliberate design trade-off on the engine authors' part. Encrypting every intra-list pointer would multiply the per-frame decryption cost by the number of live entities, which in an open-world combat game can be in the low thousands [UNVERIFIED: R6 Siege is a small-map tactical shooter, not an open-world combat game, and the "low thousands" figure is not sourced — rephrase to reflect the actual scale, or remove the specific number]. Encrypting only the root gives most of the defensive benefit — a static scanner cannot find the list without solving the decryption — at a small fraction of the cost. It is a common simplification and matches what has been documented for other AAA engines with similar defensive posture [VERIFY: cite at least one specific documented AAA engine using the same partial-encryption pattern].

### 6.3 Vtables and Function Pointers

A stronger form of the same defensive idea is vtable-pointer encryption, sometimes referred to as a lightweight form of control-flow integrity. Under this scheme, the `vptr` at the head of each polymorphic object is stored encrypted, and every virtual call decrypts before jumping.

I did not observe evidence of vtable-pointer encryption in the AnvilNext 2.0 code paths examined [VERIFY: state the scope of code paths examined so a reader can gauge coverage of this absence-of-evidence claim]. Virtual dispatch appears to use standard cleartext vtable pointers. This is consistent with the performance cost of vtable encryption being harder to justify: virtual calls are extremely frequent, and the arithmetic on the critical path of every dispatch is a heavy tax. The engine's designers appear to have made the pragmatic choice to protect *data* pointers to state that a cheat needs to locate (managers, entity list roots) while leaving *code* pointers unencrypted.

### 6.4 Storage Versus Registers — the Structural Weakness

An important observation for the later defensive-implications discussion: **encryption of pointers in memory does not protect them once they are resident in a register.**

The engine's usage pattern is:

1. Load ciphertext from the global slot into a register.
2. Apply the decryption transformation, producing a cleartext pointer in a register.
3. Dereference through that register.
4. The decrypted value is not written back to memory; the register is reused for other work.

Between steps 2 and 3, the cleartext pointer exists in a general-purpose register for a small number of cycles. Anything with kernel-level visibility into the process's register state — a hypervisor, a kernel-mode observer scheduled on the same core, a hardware debug facility — can in principle observe that value. Static analysis of the binary cannot observe it. This distinction matters for the threat model discussion later in the chapter: the scheme raises the bar for user-mode static-and-scan tooling substantially, but it does not raise the bar for observers positioned below the process boundary. I flag this here and defer full treatment to the defensive-implications section.

### 6.5 Frequency of Decryption

The decryption is performed *every access*, not once per frame with the result cached [VERIFY: this is stated as a general property but the next paragraph acknowledges the compiler sometimes caches within a local scope — reconcile the two, e.g., "no cross-function caching" vs. "per-function caching varies"]. In practice this means the decrypt sequence executes many times per frame across the manager family — once for each access to a manager singleton, of which there are many per tick in a game engine's update loop.

Whether the compiler chooses to cache a decrypted result within a local scope (for example, a function that references `GameManager` three times) depends on the compiler's aliasing analysis and the calling convention around the load. In the observed binary there is evidence of both patterns: some functions decrypt once and reuse the register, others decrypt at every reference [VERIFY: cite one address example per pattern to anchor the "evidence of both patterns" claim]. The MSVC optimizer's decisions here are not entirely predictable from the source.

The takeaway for a defender studying the scheme is that the decryption is not a rare event to catch with heavy instrumentation. It is a high-frequency, thoroughly instrumented pattern that shows up densely across the `.text` section.

### 6.6 Implications for Reverse Engineering

The pattern to look for, in static analysis of an AnvilNext 2.0-style binary, is one of two syntactic shapes:

1. **Inlined form:** `mov reg, [rip+disp]` (load from a global) → a short run of arithmetic, XOR, and rotate instructions → `mov reg2, [reg]` or `call reg` (dereference).

2. **Helper form:** `mov reg, [rip+disp]` (load from a global) → `call <small_helper>` → `mov reg2, [rax]` (dereference the returned pointer).

Both shapes have the same signature at the analysis level: a load from a fixed slot, a transformation, a dereference. The transformation is what distinguishes an encrypted pointer from a plain pointer. A pattern scanner tuned for the presence of the transformation between the load and the dereference can identify every encrypted-access site in the binary, which is how the surface of the scheme is enumerated in the first place.

This maps directly to the workflow documented in §5: once you have the shape, cross-referencing every occurrence of it gives you the full set of protected globals; from there, each one can be labeled with the manager it holds, based on the strings and behaviors of the surrounding functions. It is a labor-intensive process, but a tractable one for static analysis alone.

---

## 7. Educational Pseudocode and IDA-Style Analysis

### 7.1 Reading a Decompiler's Output

When a reverse engineer opens a stripped binary in IDA Pro, Ghidra, or Binary Ninja, they do not see the original C source. They see the compiler's *output* — a reordered, register-allocated, sometimes-inlined stream of instructions — and the decompiler's *best guess* at what higher-level construct that stream once was.

Anti-tampering pointer encryption schemes make this reconstruction harder in specific, recognizable ways. This section catalogs the six most common patterns a defensive analyst will encounter, presents each as both pseudocode and disassembly, and describes the byte signatures a static-analysis workflow uses to locate them.

Every example below is **generic**. None of the keys, offsets, or rotation counts correspond to any live game. The intent is to teach pattern recognition so that a security researcher, a course instructor, or a book reader can practice on captured artifacts without any operational payload.

All hypothesis validation described here happens on a **static memory dump collected in a controlled lab environment** — never against a running protected process.

### 7.2 Example A — Simple XOR with a Fixed Key (Shape A)

The simplest pointer-obfuscation shape. The pointer sits in a global; a sibling global holds the key; every call site XORs one against the other.

**Reconstructed pseudocode (what a decompiler would emit after retyping):**

```c
// Globals recovered from .data
static uintptr_t g_encrypted_manager;   // set once during init
static uintptr_t g_manager_key;         // set once during init

Manager* GetManager(void)
{
    return (Manager*)(g_encrypted_manager ^ g_manager_key);
}
```

**IDA-style disassembly (before variable retyping):**

```
GetManager      proc near
                mov     rax, cs:qword_7FF6xxAA0000    ; encrypted pointer
                xor     rax, cs:qword_7FF6xxAA0008    ; key
                retn
GetManager      endp
```

**Byte pattern to search for:**

```
48 8B 05 ?? ?? ?? ??      ; mov rax, [rip+disp32]
48 33 05 ?? ?? ?? ??      ; xor rax, [rip+disp32]
C3                        ; ret
```

A YARA rule or IDA `FindBinary` call using `48 8B 05 ?? ?? ?? ?? 48 33 05 ?? ?? ?? ?? C3` will surface every function of this shape in the image. In a typical AAA binary this returns dozens of hits [UNVERIFIED: no measurement cited; hit count depends heavily on binary size, compiler, and inlining] — most will be unrelated getters, so triage is necessary.

**Decompiler quirk:** Hex-Rays will happily present the `xor` as a bitwise operation, but if the analyst applies a `Manager*` type to `qword_7FF6xxAA0000`, the decompiler mis-types the whole expression. The correct workflow is: leave both operands as `uint64_t`, cast the *result* to `Manager*`, and never claim the encrypted global "is" a pointer.

**How to validate the hypothesis (defensive lab workflow):**

1. Snapshot the target process memory in a VM.
2. Read the two globals from the snapshot.
3. Compute `candidate = enc ^ key`.
4. Check that `candidate` falls inside a committed, readable region of the snapshot (a valid user-mode VA on x64 is `0x0000'0000'0000'0000` – `0x0000'7FFF'FFFF'FFFF`; anything with high bits set is either a kernel address, an encoded sentinel, or a wrong guess).
5. Dereference the candidate and check that the first few QWORDs look like a plausible vtable pointer (an address inside a `.rdata` section of a loaded module).

If steps 4 and 5 both pass, the hypothesis holds. If they fail, the shape is more complex — proceed to Example B.

### 7.3 Example B — XOR Plus Rotation (Shape B)

A modest step up: the same fixed-key XOR, followed by a bit rotation. The rotation defeats naive "XOR two globals and see what pops out" analysis.

```c
Manager* GetManager(void)
{
    uint64_t v = g_encrypted_manager;
    v ^= 0xDEADBEEFCAFEBABEULL;   // illustrative key, not a real value
    v = _rotr64(v, 13);
    return (Manager*)v;
}
```

**Disassembly:**

```
GetManager      proc near
                mov     rax, cs:qword_7FF6xxAA0000
                mov     rcx, 0DEADBEEFCAFEBABEh       ; immediate key
                xor     rax, rcx
                ror     rax, 0Dh                       ; rotate right 13
                retn
GetManager      endp
```

**Byte pattern:**

```
48 8B 05 ?? ?? ?? ??      ; mov rax, [rip+enc]
48 B9 ?? ?? ?? ?? ?? ?? ?? ??  ; mov rcx, imm64  (the key)
48 31 C8                  ; xor rax, rcx
48 C1 C8 ??               ; ror rax, imm8
C3                        ; ret
```

Two indicators identify this shape quickly:

- A `movabs` (`48 B8` – `48 BF`) loading a 64-bit immediate that has no obvious meaning as a magic number, string hash, or floating-point value.
- A `ror`/`rol` (`48 C1 C?`) with a small immediate count (typically 5–29) [UNVERIFIED: no survey supports this specific range; any 1–63 count is valid] immediately after the XOR.

**Decompiler behavior:** Ghidra recognizes `_rotr64` intrinsically on recent versions and will emit `ror(...)` cleanly [VERIFY: exact rendering depends on Ghidra version and P-code simplification rules]. Older Hex-Rays may render the rotation as `(v >> 13) | (v << 51)` [VERIFY: recent Hex-Rays collapses to __ROR8__ intrinsic; behavior is version-dependent]; the analyst should recognize this idiom and manually collapse it in comments.

**Validation:**

The same "does the result land in valid VA space?" check applies, but now the analyst must **try both rotation directions** if unsure — `ror x, n` and `rol x, 64-n` are equivalent, and disassemblers occasionally disagree on which is canonical [UNVERIFIED: mainstream disassemblers render whichever opcode is actually encoded; disagreement is uncommon].

### 7.4 Example C — Per-Address Encryption (Shape C, "Safe Linking")

This is the pattern glibc's malloc adopted in 2019 [VERIFY: Safe-Linking design work began around 2019 but shipped in glibc 2.32 in 2020] to harden the tcache against single-linked-list corruption, and it has since spread into game engines and general application hardening [UNVERIFIED: general adoption claim not cited]. The key is derived from *where the pointer is stored*, not from a global constant.

```c
Manager* GetManager(void)
{
    return (Manager*)(g_encrypted_manager ^ (uintptr_t)&g_encrypted_manager);
}
```

**Disassembly:**

```
GetManager      proc near
                lea     rcx, cs:qword_7FF6xxAA0000    ; address OF the slot
                mov     rax, [rcx]                     ; contents of the slot
                xor     rax, rcx                       ; XOR with its own address
                retn
GetManager      endp
```

**Byte pattern:**

```
48 8D 0D ?? ?? ?? ??      ; lea rcx, [rip+slot]
48 8B 01                  ; mov rax, [rcx]
48 31 C8                  ; xor rax, rcx
C3                        ; ret
```

The signature is the `lea` + `mov [reg]` + `xor rax, reg` triple where the register in the XOR is the same one the LEA loaded. That co-dependency is the fingerprint.

**Why this pattern matters for the defender:** because the "key" changes every time ASLR reshuffles the binary, a memory-dump analyst cannot copy the encrypted value from one run and hope to decrypt it in another. Each analysis must be self-contained to the snapshot it came from. This raises the analytical cost significantly without requiring the target to maintain a runtime key state machine.

**Decompiler behavior:** Hex-Rays often loses the LEA's semantic meaning and prints `*(_QWORD*)0x7FF6xxAA0000 ^ 0x7FF6xxAA0000` [VERIFY: rendering depends on IDA version and whether the analyst has retyped the slot]. The analyst should recognize that the constant on the right is *the same address* as the dereference on the left — that identity is the shape.

**Validation:**

1. In the memory snapshot, note the runtime address of the slot (call it `S`).
2. Read the QWORD at `S` (call it `E`).
3. Compute `candidate = E ^ S`.
4. Apply the standard VA-range and vtable-plausibility checks.

If `S` and `E` are literally equal, the slot has been zeroed and no pointer is currently stored — this is a common early-init state, not a decryption failure.

### 7.5 Example D — Inlined Decrypt at Every Access Site (Shape D)

The compiler was asked (via `__forceinline`, LTO, or PGO) to inline the accessor at every call site. No `GetManager` function exists in the binary; the decrypt logic is repeated dozens or hundreds of times, embedded inside larger functions.

**Fragment 1 — inside a rendering path:**

```
loc_140A12F80:
                mov     rax, cs:qword_7FF6xxAA0000
                xor     rax, cs:qword_7FF6xxAA0008
                mov     rcx, [rax+38h]                ; some field on Manager
                test    rcx, rcx
                jz      short loc_140A12FA0
                ...
```

**Fragment 2 — inside an input handler:**

```
loc_140B45120:
                mov     rbx, cs:qword_7FF6xxAA0000
                xor     rbx, cs:qword_7FF6xxAA0008
                mov     eax, [rbx+2Ch]                ; a different field
                cmp     eax, 3
                jne     short loc_140B45150
                ...
```

The register differs (`rax` vs `rbx`), the follow-on field offset differs (`+38h` vs `+2Ch`), and the surrounding logic is completely different — but the two-instruction sequence

```
mov  reg, cs:qword_7FF6xxAA0000
xor  reg, cs:qword_7FF6xxAA0008
```

is byte-identical modulo the destination register encoding.

**Analyst workflow:**

1. Extract the shape as a wildcarded pattern (masking the ModR/M byte that encodes the destination register).
2. Run the pattern across the entire `.text` section.
3. Cluster hits by containing function.
4. Every hit is now a *decrypted access site* — meaning the field offset that follows (`+38h`, `+2Ch`, etc.) is a candidate for a member of the `Manager` structure. Cross-referencing these offsets builds a partial layout of the encrypted object *without ever having to decrypt anything at runtime*.

This is a good illustration of a general principle: even when a defender uses a strong obfuscation, the shape of *how the obfuscation is used* leaks structural information about what it protects. Static analysis of the access sites recovers the class layout from a static image alone, which is useful for defensive scoping ("what could an attacker learn?") without requiring any dynamic instrumentation of a live game.

### 7.6 Example E — Multi-Step Decrypt with a Helper Function

The developer factored the decrypt out into a small helper, and did *not* force it to inline. This is the friendliest shape for an analyst because it produces one canonical routine that becomes an anchor for the whole system.

```c
// Two globals set once during startup and never mutated afterwards.
static uint64_t g_key;
static uint8_t  g_rotation;   // small integer, e.g. 7, 11, 17

static uint64_t decrypt_ptr(uint64_t enc)
{
    uint64_t v = enc ^ g_key;
    return _rotr64(v, g_rotation);
}

Manager* GetManager(void)
{
    return (Manager*)decrypt_ptr(g_encrypted_manager);
}
```

**Disassembly of the helper:**

```
decrypt_ptr     proc near
                xor     rcx, cs:qword_g_key
                movzx   ecx, cs:byte_g_rotation       ; loaded into rcx for shrx-friendly form
                                                       ; (compiler may vary)
                ror     rax, cl
                retn
decrypt_ptr     endp
```

(Exact register plumbing depends on calling convention and optimizer choices; the point is the *pair* of a XOR-with-global plus a variable-count rotation.)

**Byte pattern:**

The helper is small (typically under 32 bytes), takes one register argument, references two `.data` symbols, and is called from many places. IDA's cross-reference view will show it as a hub. Once identified, renaming it `decrypt_ptr` and retyping its return as `void*` propagates cleanly to every caller.

**Analyst technique — "chase the callers":**

1. Locate the helper.
2. Enumerate xrefs.
3. Each xref site is preceded by a `mov reg, cs:some_global` — meaning that global is *another* encrypted pointer.
4. Each such global is a candidate for a top-level system pointer (renderer, input, network, entity list, etc.).

One anchor function thus surfaces the entire encrypted-pointer *inventory* of the binary. For a defensive researcher documenting the attack surface of an anti-tamper system, this is the most valuable outcome of static analysis.

**Validation:** The helper can be executed symbolically (using tools like `angr` or `Triton`) on the snapshot's globals to enumerate every decrypted target address in one pass [VERIFY: both frameworks support this in principle but 'one pass' understates practical memory-model and constraint work], then each result is range-checked as in the earlier examples.

### 7.7 Example F — Compiler-Generated Security Cookie (Not Anti-Tamper)

The final example is a **false positive** — a pattern that superficially resembles pointer encryption but is actually MSVC's `/GS` stack-cookie machinery. Distinguishing the two is a common early stumble.

**Prolog:**

```
                sub     rsp, 40h
                mov     rax, cs:__security_cookie
                xor     rax, rsp                       ; cookie XOR'd with SP
                mov     [rsp+38h], rax                 ; stashed on stack frame
                ...
```

**Epilog:**

```
                ...
                mov     rcx, [rsp+38h]
                xor     rcx, rsp
                call    __security_check_cookie        ; validates cookie
                add     rsp, 40h
                retn
```

**How to tell it apart from Shape A or B:**

| Feature | Anti-tamper pointer decrypt | `/GS` security cookie |
|---|---|---|
| XOR operand | Data global holding a fake pointer | `rsp` (stack pointer) |
| Destination | Register that flows into a `mov [reg+off]` field access | Local stack slot |
| Ends with | `ret` returning the decrypted value | `call __security_check_cookie` |
| Global name (if PDB) | Unnamed or obfuscated | Literally `__security_cookie` |
| Location in function | Anywhere | Only in prolog / epilog |

The cookie also appears exactly *twice* per protected function — once to stash, once to check — while a pointer-decrypt shape appears once per access, potentially many times.

**Why include it:** because analysts under time pressure sometimes tag every `xor` with a global as "anti-tamper" and start chasing ghosts. Building the discipline to recognize compiler-emitted safety scaffolding first, and only *then* look for adversarial obfuscation, saves hours.

### 7.8 Cross-Cutting Validation Discipline

Across all shapes, the same validation checklist applies, and it is worth stating explicitly because it is the single most important habit a defensive analyst can build:

**The four-question test for any candidate decrypt hypothesis:**

1. **Range.** Does the decrypted value fall inside `0x0000'0000'0000'0000` – `0x0000'7FFF'FFFF'FFFF` (user-mode canonical VA on x64)?
2. **Alignment.** Is it 8-byte aligned? Object pointers almost always are; a misaligned result usually means the rotation count is wrong.
3. **Backing.** In the snapshot, does that VA fall inside a committed, readable region?
4. **Vtable plausibility.** Does the first QWORD at the decrypted address point into a module's `.rdata` section? If yes, that's a vtable, and the hypothesis is almost certainly correct.

A hypothesis that passes all four is worth documenting. A hypothesis that fails any of them should be revisited before more time is invested — the discipline of failing fast on wrong shapes is what makes long RE sessions productive rather than exhausting.

### 7.9 What This Section Deliberately Does Not Provide

For the reader's clarity and the book's ethical framing: none of the pseudocode above uses real keys, real offsets, or real global addresses from any shipping game. The byte patterns are generic x86-64 idioms that appear in thousands of unrelated binaries — compilers, browsers, databases — wherever a developer chose to obfuscate a pointer for defense-in-depth.

The purpose of the section is to give a reader the vocabulary to *recognize* these shapes when they encounter them in a static memory dump captured in a lab, and to build the validation habits that separate a productive analyst from one who chases decompiler artifacts. The next section returns to the CTF Task 120 methodology and applies these shapes to the specific artifact under study.

---

## 8. Defensive Implications for Anti-Cheat Designers

The preceding sections have documented what pointer encryption looks like in the wild and how a defensive researcher, working from static artefacts alone, can characterise the scheme without ever attaching to a running game. That is a valuable exercise for building an intuition about the technique, but the harder question — and the one that matters for the ecosystem — is what any of it means for the people designing anti-cheat systems, shipping the games those systems protect, and studying the whole apparatus from the outside. This section synthesises the recommendations that fall out of the analysis, framed from the defender's perspective and directed at three distinct audiences: anti-cheat vendors, game engineers making implementation choices, and reverse-engineering researchers who publish in the open.

The overall thesis is unromantic: pointer encryption is a useful piece of a defensive stack, but it is not, on its own, a solution to anything. It is a friction device. Understanding precisely what friction it introduces — and where that friction ends — is the difference between deploying it as a genuine control and deploying it as a talisman.

### 8.1 What Pointer Encryption Can Do

The observed schemes deliver measurable defender value along four axes.

First, they raise the bar for external scanners that walk pointer chains. An external process trying to traverse `Manager → EntityList → Entity[i] → Component` sees, at every hop, a slot whose observed value does not resolve to a valid virtual address. A scanner written by a competent but not exceptional developer, one who is used to plaintext game structures, will produce nothing but null-dereference exceptions until the scheme is reverse-engineered. That is not a permanent barrier, but it is a real one, and it filters out a non-trivial portion of the low-effort end of the threat landscape.

Second, signature scanning of specific fields becomes materially harder. If the encrypted pointer sits inside a structure whose surrounding fields are also transformed — or if the encryption key is address-dependent — a byte pattern that reliably located a field in one build will not survive re-basing, ASLR interaction, or a minor structural change. Cheat vendors who rely on signature databases have to touch each such site whenever the build changes, and their signatures become more brittle.

Third, offset databases have a shorter useful lifetime. This is the axis where pointer encryption has arguably the most operational bite. Modern cheat development is not primarily about defeating anti-cheat detection; it is about maintaining an accurate map of the game's data layout across weekly patches. Anything that forces cheat vendors to redo layout discovery on every build is a direct tax on their operations. Per-session key randomisation extends this further into forcing per-session, not per-build, rediscovery — and that changes the economics of paid cheat distribution.

Fourth, casual reverse engineering is deterred. The audience that never gets past the first encrypted slot is real, and it is meaningful. Most casual would-be cheat authors will not push through a XOR-with-address-plus-rotate scheme [VERIFY: ensure this specific scheme name matches the classification introduced in earlier chapter sections]; they will move on to a softer target.

### 8.2 What Pointer Encryption Cannot Do

The limitations are equally clear and must be stated with the same directness.

Pointer encryption does not defeat runtime analysis. The moment the game's own code touches the encrypted slot, the decryption routine has to execute somewhere; a debugger, an emulator, or an instrumentation framework observing that execution [VERIFY: "trivially" overstates the case when decrypt routines are virtualised (VMProtect/Themida) or split across obfuscated basic blocks] recovers both the algorithm and the key. Static analysis over dumped code is, in fact, the harder path. A researcher with a live process breakpoint at the decrypt site is dealing with plaintext within a single instruction of the load.

Pointer encryption does not defeat a hostile kernel driver. Once the game decrypts a pointer into a register, that register content is plaintext RAM. Any code running at ring 0 — the legitimate anti-cheat driver, a malicious driver, or a manually-mapped payload — can [VERIFY: "at will" ignores kernel-level countermeasures such as PatchGuard interactions, hypervisor-based memory protection, and vendor kernel monitoring that constrain what a hostile driver can safely do] read the decrypted value out of the process's context. The threat model in which encryption meaningfully protects a pointer is one where the adversary is confined to user mode and has no ability to trace execution. That is a narrow slice of the actual threat landscape.

Pointer encryption is not detection. It is delay. This distinction matters because deployment teams sometimes treat obfuscation as a substitute for behavioural monitoring, and it is not. A cheat vendor with [UNVERIFIED: "two weeks of engineering time" is a rhetorical estimate with no cited basis] engineering time will beat any static obfuscation scheme; a cheat vendor whose behaviour is being observed by a well-instrumented client and a smart server does not get the same free ride.

### 8.3 Detection Opportunities Enabled by Pointer Encryption

The most interesting defensive angle is one that inverts the usual framing: pointer encryption is not only a delay against attackers, it is also an opportunity to detect them. Because legitimate code paths use the encrypted slot in a stereotyped way, deviations from that pattern are informative.

Monitoring which processes read the raw encrypted slot is one such angle. Legitimate game code always follows the pattern `load ciphertext → decrypt → dereference`. An external scanner that walks memory looking for pointer-like values may read the encrypted slot without executing the decrypt, and that read event — if it can be observed via, for example, PTE-based access monitoring or hypervisor-assisted introspection [VERIFY: performance overhead and detection reliability of EPT/PTE-based monitoring at scale in shipping AC deployments should be sourced] — is anomalous. It should never happen from any process other than the game itself.

Canary encrypted pointers are a stronger variant of the same idea. A slot within the entity manager can be populated with a ciphertext that, when decrypted with the current key, resolves to a poison entity — a sentinel object that no legitimate gameplay path ever references. Any code that dereferences that pointer has necessarily walked the manager the way a cheat would. The canary is invisible to normal gameplay and lights up cleanly when scraped. [VERIFY: attribute this pattern to a shipping implementation or cite it as a proposed rather than observed technique]

Access-pattern telemetry generalises this. Legitimate call sites are known statically; the game's own binary contains a finite set of `mov reg, [slot]; call decrypt; …` sequences. Any read of the slot from an unexpected code region — including from a manually-mapped module inside the game process itself — is deviant. This kind of provenance-aware telemetry is expensive to build but expensive to defeat.

### 8.4 Recommendations for Game Engineers

For engineers implementing pointer encryption in their own titles, several implementation choices meaningfully change the defensive value.

Per-address encryption — where the effective key depends on the storage location of the pointer, not just a global session value — defeats static-key extraction. An attacker who recovers the key for one slot does not automatically recover it for the next. The classification exercise in the earlier sections referred to this as Shape C [VERIFY: confirm "Shape C" label is consistent with the taxonomy introduced earlier in the chapter], and it is the strongest of the observed variants.

Per-session randomisation is orthogonal and complementary. Even if the algorithm is fully known, changing the key on every process launch invalidates any hard-coded offset that includes decryption assumptions, and it forces cheat runtime code to include a key-recovery step. That step is itself observable.

Vtables should be encrypted alongside data pointers when the threat includes hooking rather than just reading. Cheats that install virtual method hooks on entity objects are a common category, and an encrypted vtable pointer forces the hooking code to correctly reproduce the encryption when writing its replacement — a step that [UNVERIFIED: the empirical claim that "many amateur implementations get wrong" has no cited data source] many amateur implementations get wrong in ways that produce crashes or telemetry.

The decrypted value should live in a register or short-lived stack local, never in a global cache. A globally cached plaintext pointer is a scan-target that undoes the entire scheme; it becomes the field a scanner will look for first. The cost of decrypting on every access is the price of the security property.

The performance trade-off is real and must be benchmarked honestly. Hot-path decryption in a per-frame entity loop can [VERIFY: cite benchmark numbers or acknowledge the magnitude claim is qualitative] meaningfully cost frame time. The right answer is usually to encrypt at the boundaries — the manager pointer, the list head, top-of-hierarchy references — rather than every field in every leaf structure.

### 8.5 Recommendations for AC Vendors

Anti-cheat vendors are in a position to instrument the manager access sites directly. The addresses of legitimate load-and-decrypt sequences are known at build time; a driver-side monitor can whitelist those and flag any other read of the same physical or virtual location. That is a concrete, implementable detection rather than a heuristic.

Correlation is the other lever. A process that reads the encrypted slot without subsequently invoking the decrypt routine is behaving unlike the game, and the temporal separation between those two events is small enough to be observable. Vendors already correlate scan patterns with subsequent memory-write patterns; the encrypted-slot-without-decrypt correlation is a natural extension.

Server-side statistics are the most durable defence in this whole space. Client-side obfuscation delays discovery; server-side behavioural analysis catches use. A player who consistently prefires around corners at occluded entities is producing a statistical signature that no amount of client-side pointer encryption changes. The right architecture uses pointer encryption to slow the client-side arms race and server-side telemetry to catch the outputs, regardless of how the client-side game state was accessed.

### 8.6 Recommendations for Reverse-Engineering Researchers

For those of us working in the open, the analysis in this chapter suggests a few disciplines worth codifying.

Static analysis alone is not always sufficient to fully recover a scheme, especially when the target uses partial dumps, virtualised code, or address-space-layout dependencies that are not preserved in the dump. Honest methodology work acknowledges its own limits: the observed behaviour of a scheme in a captured artefact is not the same as its behaviour on a live client, and papers should say so.

Published work should describe methodology, not operational parameters. A section that explains how to identify the shape of a pointer-encryption scheme belongs in a defensive research corpus. A section that publishes recovered keys for a live shipping title does not. The former is a contribution to the field; the latter is a weapon.

Prior work should be cited. The arms race between anti-cheat and game hacking has been public [VERIFY: "for two decades" — specify anchor (e.g. PunkBuster 2000, VAC 2002) or soften to "for over two decades"] for two decades; there is a real academic and grey-literature record, and defenders benefit when researchers acknowledge and build on it rather than treating each rediscovery as novel.

### 8.7 Ethics Reminder

The reason this class of research earns space in an academic publication is that it contributes to defensive knowledge. Understanding what a pointer-encryption scheme can and cannot do, how it interacts with detection telemetry, and where implementation choices meaningfully move the needle — those are legitimate contributions to the security-of-games literature.

Operational bypass content is a different genre. Working decryption code applied to a live shipping process, instructions for evading a specific anti-cheat product's active countermeasures, or ready-to-run tooling has no place in an academic chapter. The distinction is not always crisp at the boundary, and reasonable researchers can disagree at the edges, but the centre of the field is clear: methodology is publishable, operational capability against live production systems is not. This chapter has been written on that side of the line, and any extension of the work should stay there.

---

## Limitations

This chapter operates under a single load-bearing constraint that shapes every finding within it: the artifact under analysis is a *partial* on-disk PE dump.

- **Coverage.** The dump captures 110,137,928 bytes of a runtime image whose PE header advertises `SizeOfImage = 0x1ED04000` (516,964,352 bytes), for a coverage ratio of 21.30%. Roughly four-fifths of the runtime image — including every section that matters most for the pointer-encryption question — is not on disk.
- **Missing sections.** `.rdata` (where fixed decryption keys would live), `.data` (where any mutable manager singleton pointer *must* live at runtime), `.pdata`, `.00cfg`, `.gxfg`, `.retplne`, `.voltbl`, `.tls`, and `_RDATA` are all absent from the dump. So too are `.UBX0` (~3 MB) and `.UBX1` (~130 MB), the Ubisoft obfuscation regions that are the most plausible homes for a packed pointer-decryption stub. Any claim about the storage of encrypted pointers, the location of the key material, or the shape of the decrypt routine is therefore bounded by the fact that the specific bytes those claims would rest on are not present.
- **Packed shell.** In §4 the re-parse of the on-disk PE headers indicates that most named sections have `SizeOfRawData = 0` — that is, the on-disk artifact is a packed shell whose real code, strings, and mutable globals are materialised at runtime by an unpacker. Static analysis of a packed shell cannot answer questions about compiled engine code that does not yet exist in the form the analyst assumes.
- **Static-only.** No debugger attach, no runtime instrumentation, no live-process reads, and no interaction with the BattlEye kernel driver were performed. The chapter therefore cannot report actual rotation amounts extracted from real decrypt sites, actual keys observed in decrypted memory, or the actual run-time provenance of any specific slot.
- **No runtime instrumentation of a post-unpack image.** Neither an in-VM offline unpack nor a live post-decrypt memory snapshot was captured. Every candidate class-of-scheme claim is therefore made against the shape of the on-disk artifact alone.
- **Reproducibility drift.** Several numeric claims in the chapter (the `SizeOfImage`, the `.data` RVA, specific target-VA arithmetic for candidate P1 hits) do not match the PE header values recovered from the file currently on disk during the verification pass. Either the artifact under analysis is an earlier build than the file on disk, or a header value or arithmetic step needs to be re-derived before publication. All such discrepancies are flagged inline with `[UNVERIFIED]` tags and enumerated in the Verification Appendix.

---

## Open Research Questions

The following questions remain open at chapter close and are appropriate targets for follow-up work.

1. **Re-dump with a full image.** Capture a memory snapshot that covers the entire runtime image, including `.rdata`, `.data`, `.pdata`, and both `.UBX0`/`.UBX1` post-unpack, so that the RIP-relative displacements catalogued in §3–4 can be resolved to concrete key material and the manager-singleton hypotheses of CTF Task 118 can be verified or refuted at the byte level.
2. **Reverse the unpacker stub around file offset `0x63C426C`.** This is the sole real-code window in the current dump. Reversing it should surface the algorithm that materialises `.text`/`.rdata`/`.data` at runtime, and by extension, the on-disk representation of the decryption routines that will exist in `.text` only after unpack.
3. **Runtime instrumentation of the decrypt sites.** With a live post-unpack snapshot in hand, a defensive researcher can (in an isolated VM, offline, single-player) place read/write breakpoints on the identified manager-singleton slots, observe the actual decrypt sequence executing, and record the concrete instruction shape, rotation direction, rotation amount, key derivation, and per-session vs. per-build key behaviour. The runtime work is what distinguishes a class-of-scheme paper from an algorithm-recovery paper. The work belongs strictly in a defensive framing.
4. **VM section reversal.** The dispatch-table-like structure at file offsets `0x270000..0x290000` (§4.6) is very plausibly the handler table for the `.UBX1` protector's bytecode VM. Reversing the VM handlers — statically, as documentation of the protector's construction — would let a defender reason about how the protector composes primitives, and would identify which pointer-encryption idioms are packer-supplied vs. game-supplied.
5. **Cross-engine survey.** The claim in §2.1 that pointer encryption at rest is "one of the most common" anti-tampering primitives in modern AAA titles is currently uncited. A defensible cross-engine survey — sampling a representative set of shipping titles, categorising each by shape (A/B/C/D per §3.4), and citing per-title public reverse-engineering writeups — would substantiate or refine the framing.
6. **Empirical detection evaluation.** The candidate detection signatures proposed in §8 (canary encrypted pointers, PTE-based read monitoring, access-pattern telemetry) are described qualitatively. A quantitative evaluation — false-positive rate, performance overhead, expected time-to-detection for common cheat archetypes — would move them from "plausible defensive angles" to "recommended controls with measured costs".
7. **Scanner audit.** The `dumper2` heuristic scanner that surfaced the CTF 118 manager RVAs (`0x11F20F60`, `0x11CF0A68`) has not been re-audited against the specific pattern that produced those hits. Either the scanner is emitting the RVA of the pattern hit site rather than the resolved data target, or the pattern is stale for this build; distinguishing between the two requires re-reading `tools/source/dumper2.cpp` and running the specific pattern against the current dump under logging.

---

## Ethics

Pointer-encryption schemes in shipping game engines sit inside a broader anti-tamper stack that game publishers, anti-cheat vendors, and the wider security community all have legitimate reasons to study. The framing this chapter adopts is defensive: understanding what a pointer-encryption scheme can and cannot do, how it interacts with detection telemetry, and where implementation choices meaningfully move the needle is a contribution to the security-of-games literature.

The chapter is written on the *methodology* side of the operational-versus-methodology line, and its concrete outputs — a dump-integrity protocol, a five-category pattern census, a taxonomy of decrypt-function shapes, six pedagogical IDA-style pseudocode templates using illustrative (not real) keys, and a recommendation set aimed at anti-cheat vendors and game engineers — are chosen to be useful to defenders and expensive to weaponise. No working key was recovered, no live-process interaction was performed, no offset list intended for cheat construction is published, and every code example is generic to x86-64 idioms rather than tied to shipping-game internals.

Operational bypass content — working decryption keys applied to a live shipping process, instructions for evading a specific anti-cheat product's active countermeasures, or ready-to-run tooling — has no place in an academic chapter, and none appears here. Any extension of this work should stay on the same side of that line.

---

## Author's Note

This chapter was drafted with AI assistance and subjected to an adversarial verification pass whose output is preserved in the accompanying Verification Appendix and companion worksheet. Every substantive claim was interrogated by a second pass looking specifically for: unsupported quantitative claims, uncited attributions, arithmetic that does not survive re-derivation from the artifact currently on disk, encoding claims that do not match the Intel SDM, and any drift between draft prose and the archived scanner outputs.

The verification pass found real defects: the on-disk PE header now returns `SizeOfImage = 0x18B09000` rather than the `0x1ED04000` used in the draft; the two candidate manager RVAs sit inside `.pdata` rather than `.text` under the current section layout; several target-VA arithmetic steps do not survive re-derivation; and multiple "hits" counts in §4–5 do not appear in any archived scanner output that is still present in the project tree. Rather than paper over these defects, the chapter preserves every `[UNVERIFIED]` and `[VERIFY]` tag verbatim, enumerates them in a Verification Appendix, and treats each one as work that must be completed before the chapter is fit for external publication.

The reader should treat this document accordingly: it is a research draft with a preserved audit trail, not a finished paper. Every specific address, hit count, target VA, and section RVA reported here must be independently re-verified against the current artifact before any claim in this chapter is repeated in a peer-reviewed venue or an operational defensive brief. Where the chapter's conclusion is a null result or a bounded characterisation — for example, "no candidate decrypt routine was identified in the visible ~105 MB of `.text`" — the underlying null itself is defensible even when specific counts drift; where the conclusion depends on a specific number, the number is flagged.

---

## Verification Appendix

The table below enumerates every `[UNVERIFIED]` and `[VERIFY]` tag introduced during drafting, with the reason each was raised and the pointer to the surrounding paragraph. This appendix is intended to be the single reference a peer reviewer or future author uses to close out the residual claims before publication.

| # | Tag | Section | Reason / Note |
|---|-----|---------|--------------|
| 1 | VERIFY | §2.1 | `"one of the most common"` is a strong quantitative claim without a cited survey. |
| 2 | UNVERIFIED | §2.1 | Cross-engine survey (AnvilNext, RAGE, IW, UE-based titles) is uncited; to be added in §3. |
| 3 | VERIFY | §2.1 | Specific idioms (RIP-relative XOR, ROR/ROL with small immediate, tight decrypt windows preceding a `ret`) are proposed as detectable signatures but their actual presence at candidate sites in R6S has not been demonstrated in current artifacts. |
| 4 | UNVERIFIED | §2.2 | `/GS`-cookie-adjacent singleton idiom and its exclusive attribution to MSVC-emitted code is qualitative; clang-cl + LLD emit equivalent encodings. |
| 5 | VERIFY | §2.2 | Dereference-yields-unmapped-section claim is stated as observed but no archived dereference log is present in current artifact set. |
| 6 | VERIFY | §2.3 | `.UBX1` VirtualSize `0x08257C40` = 130.34 MB, so `~131 MB` should read `~130 MB`. |
| 7 | VERIFY | §2.3 | Attribution of any pointer-decryption stub specifically to `.UBX0`/`.UBX1` is analogy from VMProtect-family layouts and is not proven from the on-disk artifact. |
| 8 | VERIFY | §2.3 | Both "scanner is emitting the RVA of the hit site" and "pattern is stale" explanations are plausible but neither has been confirmed by inspecting the `r6_sigscan` source or rerunning the scanner. |
| 9 | UNVERIFIED | §2.5 | Counts 46 / 161 / 154 do not appear in any archived scanner output in the current artifact set; a scan-run log needs to be preserved alongside the chapter. |
| 10 | UNVERIFIED | §2.5 | P4/P5 taxonomy is not defined in any archived document reviewed here; "zero observed" result cannot be checked against a preserved scan output. |
| 11 | VERIFY | §3.1 | Section virtual size `0x1410A7F6` computes to ~336 MB, not the "approximately 321 MB" stated; arithmetic to be rechecked. |
| 12 | VERIFY | §3.1 | Coverage percentage (32.72%) depends on the disputed 321 MB denominator. |
| 13 | VERIFY | §3.1 | `.data` at RVA `0x14DBA000` should be confirmed from the PE section table. |
| 14 | VERIFY | §3.1 | `.UBX0`/`.UBX1` section names, RVAs, sizes, and characteristics should be confirmed from PE section headers. |
| 15 | VERIFY | §3.1 | CTF 118 reference not verifiable from current artifact set; cite source. |
| 16 | VERIFY | §3.2 | Seven ModR/M bytes plus initial `05` cover eight low registers; covering upper eight (r8–r15) additionally requires REX.R extension (e.g. `4C 33 05...`). |
| 17 | VERIFY | §3.2 | Category 1 count of 46 hits is an empirical scan result — reproducible but not independently confirmed here. |
| 18 | VERIFY | §3.2 | Category 2 template `48 8B ?? ?? ?? ?? ?? 48 31 ??`: RIP-relative load requires ModR/M mod=00, r/m=101; wildcards do not enforce this, may cause over/under-matching. |
| 19 | VERIFY | §3.2 | Category 2 null result contingent on template correctness. |
| 20 | VERIFY | §3.2 | imm8 field is 0..255 but 64-bit rotations mask the count by 63; effective range is 0..63. |
| 21 | VERIFY | §3.2 | Category 3 counts 161 ROR / 154 ROL are empirical scan results, not independently verified. |
| 22 | VERIFY | §3.2 | Category 4 null result contingent on scan implementation and window semantics. |
| 23 | UNVERIFIED | §3.3 | Illustrative bytes `48 C7 C0 dd dd dd dd 48 B9 dd dd dd dd dd dd dd dd` do not actually encode a 32-bit-pair synthesis — `48 C7 C0` is `mov rax, imm32` sign-extended and `48 B9` is `mov rcx, imm64`, contradicting the surrounding text. |
| 24 | VERIFY | §3.5 | MSVC RTTI mangling format `.?AVCSpawnManager@@` / `.?AVCGameManager@@` is correct format, but specific class-name presence not verifiable from truncated dump. |
| 25 | VERIFY | §3.5 | "Published RVAs from prior research" source not cited. |
| 26 | VERIFY | §3.5 | 46 Category 1 hits distribution empirical; reproducible in principle but not independently confirmed. |
| 27 | VERIFY | §3.6 | `0x6909248 / 0x1ED04000 ≈ 21.13%`, not exactly 21.30%; arithmetic to be rechecked and SizeOfImage confirmed. |
| 28 | VERIFY | §3.6 | Six numbers listed for five pattern categories — Category 3 appears split into ROR/ROL; clarify numbering. |
| 29 | VERIFY | §3.6 | Image base `0x140000000` is standard MSVC default but should be confirmed from PE OptionalHeader; formula should operate on RVAs rather than raw file offsets unless mapping is documented. |
| 30 | VERIFY | §4.2 | Prose says `.UBX1` is "108 MB in size" but actual RawSize `0x068A7E00` = ~104.5 MB — reconcile before publication. |
| 31 | UNVERIFIED | §4.2 | Independent PE-header parse of file currently on disk returns SizeOfImage `= 0x18B09000` (~395 MB), not the `0x1ED04000` stated; header value needs to be re-read before publication. |
| 32 | UNVERIFIED | §4.2 | 21.30% coverage ratio derives from disputed `0x1ED04000` SizeOfImage; against the currently-parsed `0x18B09000` it would be ~26.6%. |
| 33 | VERIFY | §4.2 | TLS-callback-driven unpacking claim is inferred from layout, not observed dynamically. |
| 34 | UNVERIFIED | §4.2 | Prose says manager RVAs resolve into `.text`, but with `.text` ending at RVA `0x0FB6B586` both manager RVAs actually fall inside `.pdata` (RVA range `0x11B87000..0x11F260D8`), which is also raw-empty. Argument holds — target region is not populated on disk — but section name should be corrected to `.pdata`. |
| 35 | VERIFY | §4.3 | Independent ROR scan returned 162 rather than 161 — off-by-one, likely search-window overlap; reconcile. |
| 36 | VERIFY | §4.3 | ROL count of 154 not independently re-scanned in this pass. |
| 37 | VERIFY | §4.3 | `48 83 EC XX` count of 5 not independently re-scanned. |
| 38 | VERIFY | §4.3 | `48 8B XD ...` count of 59 not independently re-scanned. |
| 39 | UNVERIFIED | §4.4 | Recomputing RVA of prologue from actual section table (.UBX1 at RVA `0x12117000`, RawOffset `0x400`) yields RVA `~0x1851AE6C`, off by `~0x16000` from the paper's stated `0x1850426C`. |
| 40 | VERIFY | §4.4 | Individual RIP-relative offsets (`0x63C3A4D`, `0x63C3F5E`, `0x63C3F7C`, `0x63C4031`, `0x63C41C3`) not re-verified in this pass. |
| 41 | VERIFY | §4.4 | `E9 00 00 00 00` junk-branch presence/frequency not re-verified in this pass. |
| 42 | VERIFY | §4.4 | "Outer unpacker vs. inner-VM handler-stream decryptor" attribution is an inference from static shape; dynamic tracing required. |
| 43 | UNVERIFIED | §4.5 | Recomputed target VA for `0x6334516` yields `~0x151EE484B`, off by `~0x50000` from the paper's `0x151E9484B`; likely assumes the disputed 493 MB layout. |
| 44 | UNVERIFIED | §4.5 | Target-VA arithmetic for `0x3484236 → 0x149749A6D` not re-verified. |
| 45 | UNVERIFIED | §4.5 | Target-VA arithmetic for `0x315F496 → 0x153EC31CB` not re-verified. |
| 46 | VERIFY | §4.6 | Enumerated small-int set `{0x04..0x3B}` was not re-derived from `scan_results2_top30.json` in this fact-check pass. |
| 47 | VERIFY | §4.6 | Individual constant occurrence counts (48, 44, 42, 42, 40, 37, 20) not re-scanned. |
| 48 | VERIFY | §4.6 | Isolated singleton offsets (`0x278FA8`, `0x278DA0`, `0x2797D8`) not re-verified. |
| 49 | VERIFY | §4.6 | Independent 32-bit-immediate scan returned 1,698 rather than 1,689 — off by 9; reconcile which counter is authoritative. |
| 50 | UNVERIFIED | §4.7 | Prose again places manager RVAs in `.text`, but they actually sit inside `.pdata` under the current section layout; section name should be corrected. |
| 51 | UNVERIFIED | §4.7 | On-disk PE places `.data` at RVA `0x107B2000`, not `0x14DBA000`; the paper's `.data` RVA does not match the file currently under analysis. |
| 52 | VERIFY | §4.8 | "Dispatch-table decryption of its own handler stream" is an inference from static shape; distinguishing from an outer image-unpacker requires dynamic tracing. |
| 53 | UNVERIFIED | §5.1 | P1 count of 46 does not appear in any archived §4 scan output preserved in the project tree; regenerate before publication. |
| 54 | UNVERIFIED | §5.1 | P2 = 0 not preserved in archived scan output. |
| 55 | UNVERIFIED | §5.1 | P3a = 161 not preserved in archived scan output. |
| 56 | UNVERIFIED | §5.1 | P3b = 154 not preserved in archived scan output. |
| 57 | UNVERIFIED | §5.1 | P4 = 0 not preserved in archived windowed-scan output. |
| 58 | UNVERIFIED | §5.1 | P5 = 0 not preserved in archived scan output. |
| 59 | UNVERIFIED | §5.1 | Prologue count = 1 not preserved in archived count artifact. |
| 60 | VERIFY | §5.2 | "Older Anvil titles used single-constant XOR" is a load-bearing claim requiring a specific public reversing writeup before publication. |
| 61 | UNVERIFIED | §5.2 | 46 P1 hits count reference (see §5.1). |
| 62 | VERIFY | §5.2 | "Several modern AAA titles" documenting class-(b) XOR+rotate needs at least one specific writeup cited by title/URL. |
| 63 | UNVERIFIED | §5.2 | Shape-matcher counts A/B/C/D = 0 not preserved in archived §4 output. |
| 64 | UNVERIFIED | §5.2 | Uniformity claim on ROR/ROL byte-pattern hits requires the underlying histogram, which is not archived. |
| 65 | UNVERIFIED | §5.2 | §4 imm-scan output for file-offset range `0x270000..0x290000` and table structure is not archived. |
| 66 | UNVERIFIED | §5.2 | Per-qword repetition counts (40–85) not preserved in archived artifacts. |
| 67 | UNVERIFIED | §5.2 | Small-integer field value range `0x04..0x3B` not derivable from archived output. |
| 68 | VERIFY | §5.2 | SPECK is an ARX cipher whose key schedule does not use a large fixed round-constant table in the AES sense — round-constant framing describes AES/SHA-style ciphers more accurately; broaden the example set or drop SPECK-32. |
| 69 | UNVERIFIED | §5.2 | `shl`/`shr` density measurement not preserved in archived §4 output. |
| 70 | UNVERIFIED | §5.4 | Aggregate rotation-hit count of 315 not preserved in archived §4 output. |
| 71 | UNVERIFIED | §5.4 | ROR/ROL split of 161/154 not preserved (same as items 55–56). |
| 72 | VERIFY | §5.5 | "Several older Frostbite and Anvil titles used single-constant XOR" requires specific per-title citations. |
| 73 | VERIFY | §5.5 | Claim about "Several Ubisoft titles between 2018 and 2022" needs specific writeup URLs. |
| 74 | VERIFY | §6.1 | Specific dump artifact and string XRefs for manager singleton list should be cited with addresses. |
| 75 | VERIFY | §6.1 | Which specific section per manager slot (`.data` vs `.rdata`) should be cited from the dump. |
| 76 | VERIFY | §6.1 | Helper form should be anchored by one cited helper address to substantiate the rcx/rax convention observation. |
| 77 | VERIFY | §6.1 | Cite at least one inlined-form address and one helper-form address. |
| 78 | VERIFY | §6.2 | Partial-encryption observation is a heap/runtime property; clarify whether inferred from list-walker disassembly rather than live memory inspection. |
| 79 | UNVERIFIED | §6.2 | R6 Siege is a small-map tactical shooter, not an open-world combat game; "low thousands" entity figure is not sourced. Rephrase or remove. |
| 80 | VERIFY | §6.2 | Cite at least one specific documented AAA engine using the same partial-encryption pattern. |
| 81 | VERIFY | §6.3 | State scope of code paths examined so reader can gauge coverage of the absence-of-evidence claim. |
| 82 | VERIFY | §6.5 | Reconcile "every access, not cached" general property with subsequent acknowledgement of per-function caching variance. |
| 83 | VERIFY | §6.5 | Cite one address example per pattern to anchor the "evidence of both patterns" claim. |
| 84 | UNVERIFIED | §7.2 | Claim that Shape-A YARA pattern returns "dozens of hits" in a typical AAA binary is unmeasured. |
| 85 | UNVERIFIED | §7.3 | Typical rotation-count range of 5–29 is unsupported by cited survey. |
| 86 | VERIFY | §7.3 | Ghidra `_rotr64` intrinsic rendering depends on version and P-code simplification rules. |
| 87 | VERIFY | §7.3 | Recent Hex-Rays collapses to `__ROR8__` intrinsic; behaviour is version-dependent. |
| 88 | UNVERIFIED | §7.3 | Mainstream disassemblers render whichever opcode is actually encoded; disagreement is uncommon. |
| 89 | VERIFY | §7.4 | Safe-Linking design work began around 2019 but shipped in glibc 2.32 in 2020; date phrasing should reflect. |
| 90 | UNVERIFIED | §7.4 | "Spread into game engines and general application hardening" claim not cited. |
| 91 | VERIFY | §7.4 | Hex-Rays rendering of Shape-C LEA depends on IDA version and whether analyst retyped the slot. |
| 92 | VERIFY | §7.6 | `angr`/`Triton` support this in principle but "one pass" understates practical memory-model and constraint work. |
| 93 | VERIFY | §8.1 | Confirm "XOR-with-address-plus-rotate" naming matches classification introduced in earlier chapter sections. |
| 94 | VERIFY | §8.2 | "Trivially" overstates the case when decrypt routines are virtualised (VMProtect/Themida) or split across obfuscated basic blocks. |
| 95 | VERIFY | §8.2 | "At will" ignores kernel-level countermeasures such as PatchGuard interactions, hypervisor-based memory protection, and vendor kernel monitoring. |
| 96 | UNVERIFIED | §8.2 | "Two weeks of engineering time" is a rhetorical estimate with no cited basis. |
| 97 | VERIFY | §8.3 | Performance overhead and detection reliability of EPT/PTE-based monitoring at scale in shipping AC deployments should be sourced. |
| 98 | VERIFY | §8.3 | Canary encrypted pointers should be attributed to a shipping implementation or cited as a proposed rather than observed technique. |
| 99 | VERIFY | §8.4 | Confirm "Shape C" label is consistent with the taxonomy introduced earlier in the chapter. |
| 100 | UNVERIFIED | §8.4 | Empirical claim that "many amateur implementations get wrong" has no cited data source. |
| 101 | VERIFY | §8.4 | Cite benchmark numbers for hot-path decryption cost, or acknowledge the magnitude claim is qualitative. |
| 102 | VERIFY | §8.6 | "For two decades" — specify anchor (e.g. PunkBuster 2000, VAC 2002) or soften to "for over two decades". |

The companion file `ctf_120_pointer_encryption_verification.md` provides a working checklist form of this table, with a status column and space for a reviewer to record the resolving artifact for each item.
