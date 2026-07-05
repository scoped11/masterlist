# CTF Task 122 — AnvilNext 2.0 Pointer Encryption and the EAC-Class Defensive Detection Surface

## Abstract

Modern client-side anti-cheat rests on an implicit adversary model: an attacker who reads process memory, walks pointer chains from a known root, and dereferences to reach game-state fields. A subset of commercial game engines has quietly invalidated that model by storing pointers as ciphertext — encoded 64-bit values transformed at load time so that plaintext exists only transiently in a register. Ubisoft's AnvilNext 2.0 [VERIFY: confirm the "2.0" generation label against a citable Ubisoft primary source — internal branding is Scimitar, verified via the export DLL string `scimitar_engine_win64_2022_flto_dx12.exe` at file offset `0x59F625F` in `RainbowSix.exe.fullpe.bin`; the "AnvilNext 2.0" label is journalist shorthand and not internally attested], the engine powering *Rainbow Six Siege*, is one such engine.

This chapter presents a static-only defensive analysis of the AnvilNext 2.0 pointer-encryption pattern. From the shipping `RainbowSix.exe` binary, 11 of 14 declared PE sections have `PointerToRawData = 0`; the compiled code is consolidated inside a single 106 MiB custom section, `.UBX1`, measured at 7.9945 bits-per-byte Shannon entropy. The compiled decrypt routine is not present on disk in analyzable form — it is materialized only after runtime TLS-driven unpacking. Section 3 refines the CTF 121 model through sliding-window entropy analysis, aligned-boundary scans, and a marker sweep, showing that `.UBX1` decomposes into 3–5 uniform ciphertext plateaus punctuated by low-entropy structural islands most consistent with reserved runtime-key-material slots.

Section 4 presents a six-class taxonomy of pointer-encryption schemes observed in shipped Windows binaries and infers, from structural evidence alone, that AnvilNext 2.0 is most consistent with Class D at per-section granularity. Section 5 argues that the scheme protects a small set of manager singletons while leaving the plaintext object graph, vtables, string pointers, and stack cookies unwrapped. Section 6 pivots to the defensive question the chapter exists to answer: *Rainbow Six Siege* ships BattlEye, not EasyAntiCheat, but EAC and BattlEye share a family of detection primitives. Cross-referencing each pointer-encryption class against EAC's documented primitives (from CTF Task 103) surfaces the single primitive — access-pattern telemetry on the backing physical pages of protected slots — that meaningfully sees pointer-encryption-aware adversaries, and identifies the systemic blind spot: PCIe DMA-side reads that a software-only anti-cheat cannot observe regardless of encryption strength.

The contribution is defensive: no working key is extracted, no callable primitive is presented, no live-service bypass is demonstrated.

---

## Table of Contents

1. [Objective and Constraints](#1-objective-and-constraints)
2. [Introduction and Scope](#2-introduction-and-scope)
3. [Prior Findings Recap and the Structural Wall](#3-prior-findings-recap-and-the-structural-wall)
4. [Deeper .UBX1 Structural Analysis](#4-deeper-ubx1-structural-analysis)
5. [Pointer-Encryption Class Taxonomy](#5-pointer-encryption-class-taxonomy)
6. [Protection Coverage — What the Scheme Protects](#6-protection-coverage--what-the-scheme-protects)
7. [Defensive Implications for EAC-Class Detection](#7-defensive-implications-for-eac-class-detection)
8. [Limitations](#8-limitations)
9. [Open Research Questions](#9-open-research-questions)
10. [Ethics](#10-ethics)
11. [Author's Note](#11-authors-note)
12. [Verification Appendix](#12-verification-appendix)

---

## Scope Statement

This chapter is **defensive research** conducted through **static analysis only** of a legally obtained on-disk artifact (`RainbowSix.exe.fullpe.bin`) on an isolated analysis workstation. It presents no operational bypass, no working key material, no callable decryption primitive, and no live-process interference.

*Rainbow Six Siege* is protected by **BattlEye**, not EasyAntiCheat. BattlEye's runtime, driver, and detection heuristics are **explicitly out of scope** — this project does not reverse, analyze, or publish anything that could function as a Siege-specific bypass. The AnvilNext 2.0 pointer-encryption pattern is examined here purely as a *class-level artifact* whose defensive lessons are transferable to EAC-protected titles that may exhibit structurally similar patterns.

The chapter's central pivot — mapping AnvilNext 2.0's pattern onto EAC's documented detection primitives — is **counterfactual**: *if* the pattern appeared in an EAC-protected title, which EAC primitives would fire and which would silently pass? The answer illuminates EAC's coverage. It illuminates BattlEye and Siege only by analogy.

All algorithmic content is presented at the **class level**. Illustrative constants (`0xAAAAAAAAAAAAAAAA`, `0xDEADBEEFCAFEBABE`) are used throughout; no keys extracted from live product are shown. No dynamic instrumentation was performed against any shipping Ubisoft build. No BattlEye or EAC runtime data was captured. The static artifact was examined on disk, in a VM, without launching either the game or Ubisoft Connect.

---

## 1. Objective and Constraints

**CTF Task 122 brief.** Building on CTF 121's aggressive reverse engineering of the shipping `RainbowSix.exe` PE artifact, this chapter isolates two questions from the observed pointer-encryption pattern in Ubisoft's AnvilNext 2.0 engine:

1. **What class of pointer-encryption scheme is AnvilNext 2.0 using?** Not the exact key — extracting a live key would cross into operational territory this project explicitly avoids — but the *algorithmic class*. Is it XOR-with-a-static-mask? Rotate-and-XOR? A per-object key derived from the object's own address? A stronger construction? The class determines the reverse-engineering cost, the detection surface, and the defensive lessons transferable to other titles. [VERIFY: the chapter must not later present the "XOR + rotation" pseudocode as observed disassembly — per CTF 121 §4.0, the routine's bytes are not statically recoverable and the pseudocode is a structural reconstruction, not a translation from bytes.]

2. **What EAC-class detection primitives would catch cheats operating against this class of scheme?** This is the pivot that gives the chapter its defensive-research framing.

**Constraints inherited from CTF 118 / 120 / 121:**

- Static analysis only on a legally obtained on-disk artifact.
- No dynamic instrumentation, no live-process attach, no debugger against a running Ubisoft Connect session.
- No bypass of BattlEye's runtime measurements.
- No extraction of the actual encryption key or per-object salt values.
- No code that resolves a real in-game pointer.
- No discussion of BattlEye's runtime, driver, or detection heuristics.
- Pseudocode discipline: constants are shown as symbolic names (`K_ENGINE`, `S_OBJ`), never as extracted values.

**Deliverables.** Class-level pseudocode, a taxonomy, a coverage inference, and a mapping of that class against EAC's documented detection primitives — sufficient for a defensive engineer to understand the adversary space and the scanner design space, deliberately insufficient to constitute a working attack.

---

## 2. Introduction and Scope

### 2.1 The Research Question

Modern anti-cheat architectures assume a specific adversary model: an attacker who reads process memory, walks pointer chains from a known root (usually a module base or a global singleton), and repeatedly dereferences to reach the game-state fields they want to observe or mutate. The overwhelming majority of publicly documented cheats — external DMA, internal hooks, kernel primitives — operate at this level of abstraction. They treat pointers as pointers.

A subset of commercial game engines has quietly moved to invalidate that assumption. In these engines, pointers are not stored in memory as pointers. They are stored as ciphertext — an encoded 64-bit value that must be transformed at load time [VERIFY: whether the transform is symmetric (re-encrypted on store) or one-way at-rest with plaintext writes into a separate live table — the load/store symmetry claim is not established by primary evidence in this project] before the CPU can meaningfully dereference it. The plaintext pointer exists only inside a register, for the lifetime of a single load-use window, and is not persisted to the object graph in cleartext.

Ubisoft's AnvilNext 2.0 [VERIFY: confirm the "2.0" generation label against a citable Ubisoft primary source — internal branding is Scimitar, verified via the export DLL string `scimitar_engine_win64_2022_flto_dx12.exe` at file offset `0x59F625F` in `RainbowSix.exe.fullpe.bin`; the "AnvilNext 2.0" label is journalist shorthand and not internally attested], the engine underlying *Rainbow Six Siege*, is one such engine. During our practical reverse engineering of Siege for CTF Task 121, [UNVERIFIED: the phrase "every attempt to walk what should have been a straightforward object graph produced garbage" describes a dynamic-analysis outcome, but CTF 121 was static-only against the on-disk PE — this framing conflates two distinct observations. Restate as: "the on-disk PE image is 89% packed inside a single high-entropy section (`.UBX1`, entropy 7.994); the compiled `.text`, `.rdata`, and `.data` do not exist on disk at all; and the runtime pointer-encoding pattern is separately attested in accessor-thunk shape as noted in `source/cheat/r6_dma.cpp`."] The pattern is [UNVERIFIED: "consistent enough to rule out ASLR, relocation, or stale dumps, and consistent enough to identify as *deliberate*" — this is the correct conclusion but it needs to be broken into (a) at-rest packing (verified by section-table analysis) and (b) runtime pointer encoding (attested by accessor-thunk convention, not by disassembled bytes)]: an engine-wide invariant that pointers on the heap are encrypted.

This chapter isolates two questions from that observation:

1. **What class of encryption scheme is AnvilNext 2.0 using?** Not the exact key — extracting a live key would cross into operational territory this book explicitly avoids — but the algorithmic class. Is it XOR-with-a-static-mask? Rotate-and-XOR? A per-object key derived from the object's own address? A stronger construction? The class determines the reverse-engineering cost, the detection surface, and, most importantly, the defensive lessons transferable to other titles. [VERIFY: the chapter must not later present the "XOR + rotation" pseudocode as observed disassembly — per CTF 121 §4.0, the routine's bytes are not statically recoverable and the pseudocode is a structural reconstruction, not a translation from bytes.]

2. **What EAC-class detection primitives would catch cheats that operate against this class of scheme?** This is the pivot that gives the chapter its defensive-research framing, and it needs to be stated carefully.

### 2.2 The Framing Pivot: BattlEye Title, EAC Analysis

*Rainbow Six Siege* is protected by BattlEye, not EasyAntiCheat. Any question of the form "how would Siege's anti-cheat detect X" is a BattlEye question, and this book is explicit that BattlEye's runtime is out of scope — we do not reverse it, do not analyze its detection routines, and do not publish anything that would function as a Siege-specific bypass.

What we *do* have, from CTF Task 103 (archived), is a deep static analysis of EAC's architecture: its kernel-mode driver, its user-mode module, the classes of scan it performs, the primitives it exposes to the games it protects, and the invariants it enforces on the address spaces of those games. [VERIFY: confirm CTF 103 archive actually covers all five listed areas (driver, UM module, scan classes, primitives, address-space invariants) before forward-referencing them in later sections.] EAC protects a large slice of the commercial titles that share Siege's structural risk — *Fortnite*, *Apex Legends*, *Rust*, *Squad*, and dozens of others. Some of those titles almost certainly use pointer-encryption schemes of their own; some do not, but structurally could. [UNVERIFIED: the "almost certainly use pointer-encryption schemes of their own" claim is not backed by any specific primary source in this project; soften to "may use analogous schemes" or cite the specific EAC-protected titles for which the pattern has been publicly attested.]

The question this chapter asks is therefore counterfactual: *if* AnvilNext 2.0's pointer-encryption pattern appeared in an EAC-protected title, which of the detection primitives EAC already ships would fire against a cheat built to defeat that pattern, and which would silently pass it? This is a defensive question about EAC's coverage — where its architecture is strong against pointer-encryption-aware adversaries, where it has blind spots, and what a defensive engineer designing the next generation of client-side anti-cheat should add.

The answers illuminate BattlEye and Siege only by analogy. They are actionable for EAC-protected titles.

### 2.3 Relation to Prior Chapters

This chapter is the fourth in an arc:

- **CTF Task 118** — architectural survey of client-side anti-cheat, establishing the taxonomy of scans (integrity, behavioural, environmental) that we use here.
- **CTF Task 120** — the methodology chapter, formalising static-only reverse engineering as our sole analytical tool and defining what "aggressive original RE" is permitted to conclude from a dump alone.
- **CTF Task 121** — the practical R6 Siege engagement: the dumper session, the AnvilNext 2.0 signature discoveries, and [UNVERIFIED: "the pointer-decryption pattern surfaced from disassembly of the accessor thunks" overstates the CTF 121 finding. Per CTF 121 §4.0 and §4.8, the routine file offset is UNCONFIRMED, the raw bytes are UNCONFIRMED, and the pseudocode is an explicit "structural reconstruction from constraints, not a translation from disassembly." Rewrite as: "the pointer-decryption pattern inferred from structural constraints on the packed image, from the shape of the runtime accessor convention, and from prior RE literature on the Scimitar family."]
- **CTF Task 103 (archived)** — the EAC deep-analysis this chapter reaches back into for its defensive primitives.

The reader who has followed the arc will recognise the AnvilNext 2.0 pattern from Chapter 121 and is now asked to generalise: not "how do we read Siege memory" — a question we deliberately decline — but "what does this pattern teach a defender."

### 2.4 Scope and Non-Goals

To make the boundary explicit:

- **In scope.** Static disassembly of the shipped `RainbowSix.exe` binary [VERIFY: given that 11 of 14 sections have zero raw bytes on disk per CTF 121 §3.3, the phrase "static disassembly" applies only to the `.UBX1`, `.reloc`, and `.rsrc` sections — the compiled `.text` cannot be disassembled statically. Restate as "static analysis of the shipped `RainbowSix.exe` binary at the PE-structural level, with pattern-class inference against the encrypted `.UBX1` blob."]; identification of the pointer-encryption *class* by inspection of accessor code paths [VERIFY: "inspection of accessor code paths" implies bytes were read from `.text`. Restate as "inference of the pointer-encryption class from the runtime accessor convention and the packer's trampoline shape."]; class-level pseudocode illustrating what a reverse engineer encounters; mapping of that class against EAC's documented detection primitives; defensive recommendations.
- **Out of scope.** Dynamic instrumentation of a live Siege process. Extraction of the actual encryption key or per-object salt values. Any code that resolves a real in-game pointer. Any discussion of BattlEye's runtime, driver, or detection heuristics. Any pattern intended for use against a live-service title, EAC-protected or otherwise.
- **Pseudocode discipline.** All algorithmic content in this chapter is presented at the class level — enough for a defensive engineer to understand what an adversary would build and what a scanner would need to look for, and deliberately not enough to constitute a callable primitive. Constants are shown as symbolic names (`K_ENGINE`, `S_OBJ`), never as extracted values.

With those boundaries fixed, the chapter proceeds in Section 4 to a class-level description of the AnvilNext 2.0 pointer-encryption pattern as recovered from static analysis. [VERIFY: consistent with the above, restate "recovered from static analysis" as "reconstructed from structural constraints on the packed image."]

---

## 3. Prior Findings Recap and the Structural Wall

### 3.1 What CTF 118, 120, and 121 Established

This chapter sits at the midpoint of a four-part sequence. Before advancing into the structural analysis of `.UBX1` and the mapping onto EAC's detection surface, it is worth being explicit about what the previous three CTFs put on the record, because CTF 122's central claim — that we have hit a *design-level* wall rather than a tooling gap — only lands if the earlier evidence is treated as settled.

**CTF 118** was the architecture case study. It fixed the identity of the engine and the middleware surrounding it. The shipping binary `RainbowSix.exe` is built on Ubisoft's Scimitar / AnvilNext 2.0 branch [VERIFY: sister-title lineage (Assassin's Creed, Ghost Recon Breakpoint, For Honor) is external-corpus attribution flagged as VERIFY-pending in the CTF 118 verification worksheet (tags 2.1-2, 2.1-3, 2.1-4); cite Ubisoft press or postmortem before publication]. The evidence in this project came from an export DLL-name string leaking through the on-disk artifact: `scimitar_engine_win64_2022_flto_dx12.exe`, verified at file offset `0x59F625F` [VERIFY: the .pdb variant of this path referenced in earlier drafts has NOT been directly hex-dumped from the debug directory in this project — CTF 118 verification tag 2.2-1 states 'Only the exe module name is confirmed in archived text'; the section's reference to a PDB path is UNVERIFIED without a direct debug-directory dump]. That string is load-bearing. It confirms (a) the engine family (HIGH), (b) the platform target (Win64, DX12) via the filename (MEDIUM — filename-based not binary-metadata-based), (c) a plausible build year of 2022 [VERIFY: filename-based inference; not confirmed against build metadata], and (d) that the binary was likely produced with LTO [VERIFY: `flto` in the filename is a naming-convention reading; CTF 121 tag 25 and CTF 118 tag 3-P1 flag this as unproven by direct build metadata].

CTF 118 also produced a middleware inventory [VERIFY: several inventory items are flagged in the CTF 118 verification worksheet as needing a live legal-notices snapshot or a full strings scan (tags 3.3-1, 3.9-1, 3.9-3); specifically Umbra, Scaleform, and 'RED for input' rest on incomplete evidence in this project]: BattlEye as the primary anticheat with a kernel driver component (HIGH), EasyAntiCheat integrated as a secondary layer (HIGH — the artifact carries `EasyAntiCheat_EOS.sys` in the shipped tree and this file is directly verifiable), Wwise for audio (HIGH — 662 exports include Wwise/AK symbols), and additional middleware whose presence rests on legal-notices declarations that have not been re-snapshotted in this project.

[UNVERIFIED: an earlier draft asserted 'Denuvo as the executable-layer protector' and characterized 'Denuvo integrated into a Scimitar 2022 build' as 'publicly documented'. CTF 121 §3.6 EXPLICITLY REFUTES a Denuvo attribution: 'No commercial-protector signature matched. File-wide byte-string scans for VMProtect, Themida, Enigma, Oreans, WinLicense, ASPack, Denuvo, Arxan, Irdeto, Sentinel/HASP, SecuROM, StarForce, and SafeDisc all returned zero hits.' The protector is identified in CTF 121 as Ubisoft's *in-house* Scimitar/UBX protector, not Denuvo. Rainbow Six Siege is not publicly known to ship with Denuvo. This paragraph must be rewritten to reflect the in-house UBX identification.]

The identification of the in-house UBX protector matters because it constrains the *class* of protection scheme we should expect: a Ubisoft-family in-house protector with TLS-driven unpack and encrypted sections, not a commercial licensed protector.

**CTF 120** was the methodology chapter. It laid down the ground rules that govern the rest of the sequence: the artifact is only ever examined statically, on a disk copy, on an isolated VM, with no live-game process, no memory read, no debugger attach against a running Ubisoft Connect session, and no bypass of BattlEye's runtime measurements. The chapter's technical contribution was a first pass at globals discovery using the two heuristics the CTF 120 dumper implements — string-xref singleton clustering and pattern-of-life singleton globals. That pass returned candidate offsets, but the candidates were *partial-dump-limited*: the dumper CTF 120 used was reading only the file regions that were both present on disk and successfully mapped by the loader stub it had at the time. It produced hits, and those hits were consistent with what an AnvilNext build should expose (a world/entity manager pointer, a local-player pointer, a camera/view root), but CTF 120 was explicit that the candidates could not be treated as confirmed until the full PE was accounted for.

**CTF 121** did that accounting, and this is the finding that forces CTF 122 to exist. CTF 121 rebuilt the parser to walk every section header directly out of the on-disk PE, without trusting any loader-side normalisation. The result was unambiguous: of the fourteen sections declared in the section table, **eleven have `PointerToRawData = 0`** (HIGH — directly verified in CTF 121 §3.3 section table). The compiled `.text`, the constant pool in `.rdata`, the writable globals in `.data`, and the smaller sections that would normally hold TLS templates, exception tables, and MSVC compiler-artifact structures [VERIFY: the phrasing 'resource stubs' in an earlier draft was imprecise — `.rsrc` IS present on disk with 0x5CE00 bytes at entropy 3.127; only the smaller compiler-artifact sections and the main code/data sections are zero-raw] — none of them exist as bytes on disk. Their section headers declare a `VirtualSize` and a `VirtualAddress`, but the file offset that would let a static tool actually *read* the compiled code is zeroed out.

The bytes are instead consolidated inside a single custom section, `.UBX1`, which occupies roughly 106 MB of the on-disk image (HIGH — raw size 0x06A07000, verified) and measures at **7.9945 bits per byte of Shannon entropy** against a theoretical maximum of 8.000 (HIGH — directly verified in CTF 121 §3.3 and §3.5). That number is within measurement noise of a uniformly random byte stream, which is what you get from either a strong encryption transform, a well-conditioned compression transform, or an encryption transform applied over pre-compressed input. [UNVERIFIED: an earlier draft specifically attributed the entropy to 'a strong stream cipher or a well-conditioned block cipher in a chained mode.' CTF 121 Limitations §3 explicitly notes that entropy alone cannot separate encryption from compression from encryption-of-compressed; the more specific cipher-class attribution is not supported by static evidence and must be softened.]

[UNVERIFIED: an earlier draft claimed 'no meaningful residual structure in .UBX1 at the byte-histogram level, no plaintext strings, no visible import table fragments, no unaligned zero runs.' CTF 121 §3.5 and §4.1.2 DIRECTLY REFUTE this: the export directory at RVA 0x1905C5A8 lives at a virtual address inside .UBX1's range and yields 662 readable export name strings including Wwise/AK symbols and Scimitar engine internals; a 1.4 MiB structural table with a 3-byte periodic pattern is embedded inside the ciphertext; and eight page-aligned zero-heavy islands are enumerated by CTF 121's island scanner as likely runtime key-material backing store. The section under review must be rewritten to acknowledge these known internal structures.]

CTF 121 also traced the entry path that eventually populates the missing sections. The PE's TLS directory points to a callback list containing three real callbacks plus a NULL terminator. TLS callback[0] lives at VA `0x15906749C` inside `.UBX1` and begins with a 10-byte `PUSH imm32 ; CALL rel32` trampoline that dispatches into a routine at **VA `0x159C2B772`** (HIGH — verified in CTF 121 §3.7). The MAIN ENTRY POINT trampoline at RVA `0x193373E7` dispatches into a *different* dispatcher at VA `0x159C4F538` (HIGH — verified in CTF 121 §3.6). [UNVERIFIED: an earlier draft asserted 'the first callback dispatches into a routine at VA 0x159C4F538 in the loader's own residual code.' This conflates two different dispatchers — 0x159C4F538 is the entry-point trampoline's target, not the TLS callback's target — AND misplaces it: the dispatcher at 0x159C4F538 maps to file offset 0x65DF938 which is INSIDE .UBX1, not in the loader's residual code. The only truly on-disk-residual executable bytes are the 10-byte trampolines themselves; both dispatchers live inside encrypted .UBX1.] The dispatcher's job — take `.UBX1`, derive keys, decrypt the payload, and write plaintext bytes into the virtual addresses the eleven empty sections claim — is inference from the trampoline shape and general protector conventions (MEDIUM per CTF 121 §3.2, §3.7, §6.1 tags); direct proof of the multi-stage unpack model requires dynamic observation this project has not performed.

[VERIFY: the phrasing 'so that by the time the OS transfers control to AddressOfEntryPoint, the process image looks in memory like a normal PE that could have been produced by a standard MSVC toolchain' is a reasonable summary of protector behaviour in general but is not directly proven by static analysis of this artifact — flagged as inference per CTF 121 Limitations #4.]

The compiled decrypt routine — the actual x86 that reads `.UBX1` and produces plaintext `.text` — **is not present on disk in an analysable form** (HIGH — CTF 121 §4.1.1). It exists in `.UBX1` itself, encrypted alongside everything else, and it is materialised only when the earlier stages of the unpacker have already run. That is the finding CTF 121 closed on.

### 3.2 The Structural Wall

Stated cleanly: **static analysis on this artifact cannot recover the compiled decrypt routine, because the bytes that implement the decrypt routine only exist after runtime unpacking has already succeeded.**

This is worth being precise about, because it is easy to mistake for a tooling problem. It is not. It would not be solved by a better disassembler, a smarter decompiler, a more aggressive symbolic executor, or a longer analyst budget. There is no arrangement of static tools that can read bytes which are not on disk. The order-of-operations required to produce those bytes — TLS callback fires, dispatcher executes, key derivation runs, `.UBX1` is streamed through the decryption transform, plaintext lands at the virtual addresses of the empty sections — is a *runtime* order-of-operations. It requires a process context, an OS loader, allocated virtual memory backed by real pages, and execution privileges on the CPU. [VERIFY: the specific ordering above is the reasonable default reading of protector behaviour but is inference; CTF 121 explicitly flags the specific unpacker chain as unproven statically.]

Any technique that would break the wall — attaching a debugger after the TLS callback returns, dumping the process image from a running instance, single-stepping the unpacker to snapshot intermediate state, hooking `VirtualAlloc`/`NtProtectVirtualMemory` to catch the moment `.text` becomes executable — is by construction *dynamic*, and by the ground rules established in CTF 120 and the methodology of this book, we do not do dynamic analysis of this artifact. Not because it is technically impossible, but because dynamic analysis against a shipping Ubisoft build carrying BattlEye and EAC crosses the line from defensive research into live-service interference, and that is the line this project does not cross.

The wall is therefore a *design* wall, not a research budget wall. The Ubisoft in-house UBX protector was built such that the property we want — "read the compiled decrypt routine from the file on disk" — is not obtainable without running the file. That is characteristic of a TLS-driven packer with encrypted sections working as designed. [VERIFY: the sharper claim 'built specifically to guarantee' attributes design intent that on-disk evidence alone does not establish; softened here.]

### 3.3 The Pivot for This Chapter

The temptation, having named the wall, is to stop. It is worth resisting.

There is a real difference between "we cannot recover the specific bytes of Ubisoft's specific decrypt routine" and "we cannot say anything useful about what class of scheme this is or how EAC would treat it." The first statement is true and terminal. The second is false, and confusing them is the mistake this chapter exists to prevent.

Two lines of evidence remain available even inside the static-only constraint. The first is the *structure* of `.UBX1` itself: its size, its entropy profile, its placement inside the section table, the relative sizing between it and the empty virtual sections it must populate, the presence of the 662-name export-string island and the eight page-aligned zero-heavy islands inside the ciphertext, and the way the TLS directory hands off to it. Those are all static observations, made on disk, without executing anything. They constrain the space of possible schemes considerably.

The second is *public taxonomy*. Commercial protectors (VMProtect, Themida, Enigma, Arxan, and their smaller siblings) and academic treatments of packer behaviour are extensively documented in the literature. [VERIFY: this project has explicitly refuted a Denuvo attribution for this specific artifact per CTF 121 §3.6; retain Denuvo in the taxonomy discussion only as a comparative reference, not as an attribution to this binary.] Their design idioms — encrypted section layouts, TLS-callback triggering, virtualised handlers over custom bytecode [UNVERIFIED as universal — not every protector in this list uses VM-based handlers; frame as characteristic-of-family rather than universal], and per-invocation re-encryption [UNVERIFIED as universal] — are described at the level of published papers, defence talks, and vendor whitepapers. The class-level behaviour is not a secret.

Combining structural evidence from the file with the public taxonomy is enough to characterise what family `.UBX1` belongs to (a Ubisoft-family in-house UBX protector, HIGH), what invariants that family exposes at runtime, and — crucially for CTF 123 — which of those invariants line up with the primitives EAC is documented to look for. That mapping is the payload of the rest of this chapter and the next.

The wall is real. It is also not the end of the analysis.

---

## 4. Deeper .UBX1 Structural Analysis

### 4.1 Overview

CTF 121 established `.UBX1` as a 106 MiB packed section whose global Shannon entropy was measured at ~7.994 bits per byte and whose byte histogram was statistically flat. That was a summary statistic. It answered one question — *is this section encrypted-or-compressed?* — but it left every other structural question open. Is the section one blob, or many? Are there internal seams? Does the encryption strength vary along the file? Are there recognizable markers from any commercial protector? Are there plaintext islands wedged inside the ciphertext?

Section 4 answers those questions with three additional analysis passes: (a) a sliding-window entropy scan at multiple window sizes, (b) an aligned-boundary and zero-pad scan, and (c) a marker/magic scan over the full section. The findings refine the CTF 121 model in a specific way: `.UBX1` is not a monolithic cipher blob and it is not a container of independently-keyed blocks at any 4 KiB/16 KiB/64 KiB stride either. It is a **large ciphertext body with a small number of embedded, structurally-distinct in-plaintext regions**. [UNVERIFIED: the "structurally-distinct in-plaintext regions" framing generalizes from three data classes (high-entropy plateau boundaries, zero-pad clusters, a single moderate-entropy plateau); the "in-plaintext" characterization is not directly proven — some islands are demonstrably not plaintext but simply lower-entropy structural data.]

### 4.2 Overall Entropy

Overall Shannon entropy of `.UBX1` recomputed on the full raw section:

$$H_{.UBX1} = 7.994495 \text{ bits/byte}$$

[VERIFY: CTF 121 measured 7.9945 to four decimal places; the six-decimal refinement 7.994495 must be reproducible against the archived scan or the source binary before publication.] This matches the CTF 121 figure of 7.994 to four decimal places, confirming the earlier measurement was not a windowing artefact. The section is within 0.000505 bits of the theoretical maximum of 8.0. A byte-histogram of that flatness admits only two families of explanation — a modern stream/block cipher operating in a mode that hides plaintext structure, or a well-conditioned entropy coder (LZMA-class or arithmetic coded) — and the marker scan (§4.6) rules out every named entropy coder we tested.

### 4.3 Per-Window Entropy Distribution

The section was rescanned with a sliding window at five sizes: 4 KiB, 8 KiB, 16 KiB, 32 KiB, and 64 KiB. Table 4.1 shows how the distribution tightens as the window grows. [VERIFY: the specific numeric cells below are not reproduced in the archived CTF 121 evidence; re-generate from the source scan before publication.]

| Window | Min | Median | Max | Std | Windows < 7.9 |
|---|---|---|---|---|---|
| 4 KiB | 0.1754 | 7.9543 | 7.9680 | 0.4632 | 1,779 |
| 8 KiB | 1.6940 | 7.9773 | 7.9845 | 0.4408 | 833 |
| 16 KiB | 5.1479 | 7.9887 | 7.9920 | 0.4192 | 416 |
| 32 KiB | 5.4922 | 7.9944 | 7.9958 | 0.4007 | 208 |
| 64 KiB | 5.4929 | 7.9972 | 7.9979 | 0.3862 | 106 |

Two features of this distribution are diagnostic. First, the median entropy across every window size is above 7.95 and the 64 KiB median is 7.9972 — the ciphertext regime is uniformly high-entropy across the vast majority of the section, not a mix of stronger and weaker sub-regions. Second, the count of "below 7.9" windows approximately halves each time the window doubles (1779 → 833 → 416 → 208 → 106; ratios 2.14, 2.00, 2.00, 1.96 — [VERIFY: the phrase "exactly what one expects" oversells; a factor-2 rule under contiguous low-entropy islands is a heuristic, not an exact prediction]), which is consistent with the low-entropy content being concentrated in a small number of contiguous regions rather than sprinkled through the file — larger windows absorb the anomalies into surrounding ciphertext. If low-entropy bytes were uniformly distributed, the count would fall much more slowly.

The minimum values tell the complementary story. At 4 KiB the minimum is 0.1754 bits — a single window that is essentially plaintext. At 64 KiB the minimum floor rises to 5.4929 bits, meaning there is no 64 KiB region in `.UBX1` that is fully plaintext; every large-scale low-entropy region contains embedded higher-entropy sub-content or is bounded on both sides by ciphertext that leaks into the window. The plateau floor of 5.49 bits at 32 KiB and 64 KiB is not noise — it corresponds to a specific structural table discussed in §4.4. [Consistent with CTF 121's reproduced ~5.51 bits measurement in the 0x61DBB80..0x633F000 island; HIGH confidence in the phenomenon, VERIFY the exact 5.4922 / 5.4929 numeric floors.]

### 4.4 Zero-Pad Regions

The zero-pad scan identified 24 runs of ≥16 consecutive zero bytes inside `.UBX1`, totalling 20,556 bytes — [VERIFY: 20,556 / 0x6A07000 = 0.01849%, which rounds to 0.019%, not 0.018%; adjust the label] ~0.018% of the section. [VERIFY: CTF 121's zero-pad island scan enumerated 8 page-aligned island starts, not 24 raw runs. The two are not directly comparable (different thresholds / alignment). Re-derive the 24-run set from a single canonical scan pass before publication.] The four largest are:

| Offset | Length | Location |
|---|---|---|
| 0x5E127A0 | 6,144 B | Zone 1 (embedded structure) |
| 0x5E09448 | 5,032 B | Zone 1 |
| 0x63466F4 | 3,341 B | Zone 2 tail |
| 0x5E06E08 | 2,832 B | Zone 1 |

[VERIFY: these specific unaligned offsets are not present in the archived CTF 121 evidence; the CTF 121 island scan recorded page-aligned starts at 0x59ED400, 0x5E06400, 0x5E09400, 0x5E12400, 0x61DC400, 0x6346400, 0x6523400, 0x6666400. The offsets here are consistent with pad starts *inside* those aligned buckets but must be reproduced.]

These are not distributed uniformly. Nineteen of the 24 regions cluster inside a ~44 KiB window at file offset `0x5DFEC7F..0x5E14610`. [VERIFY: 0x5E14610 − 0x5DFEC7F = 0x15991 = ~86 KiB, not ~44 KiB — either the bounds are wrong or the label is wrong.] A separate cluster of five regions sits near `0x63466F4..0x634634B` [VERIFY: the range 0x63466F4..0x634634B is inverted (end < start); likely a typo — reconcile] and around `0x666619E..0x66663B9`. Two isolated pads sit at `0x61D5B60` [VERIFY: not in archived evidence] and `0x6A073BC` (the latter is the terminal 68 bytes of the section — confirmed by arithmetic: 0x6A07400 − 0x6A073BC = 68).

The interpretation matters. In a well-conditioned cipher output (CTR-mode AES, ChaCha20, or a modern stream cipher applied to compressed input), the probability of a 6 KiB zero run is astronomically small — of order $2^{-49152}$ under any reasonable byte-independence model. Zero runs of this scale must be **structural**: they are either reserved slots the runtime unpacker fills at load time, or aligned padding between logical sub-objects that were serialized before the outer encryption pass. Their clustering into two zones (one near an export/TLS neighborhood, one near the trailing structural table) says the packer format allocates fixed-size records with slots that are only populated at runtime — the on-disk image reserves the space, and the runtime writes the key material or resolved pointers when the process boots. [UNVERIFIED: "runtime writes key material or resolved pointers" is inference consistent with CTF 121's per-section-key hypothesis; a live trace is required to distinguish key-material from IAT-thunk from arbitrary structural fill.]

[UNVERIFIED: This is direct on-disk evidence for the CTF 121 "per-section runtime key population" hypothesis. The keys are not on disk; the *slots* for the keys are on disk. — Consistent with CTF 121 but explicitly flagged there as inference; carry the same UNVERIFIED status here.]

### 4.5 Block Boundary Candidates

Adjacent-window entropy deltas identify the sharpest structural transitions inside `.UBX1`. The largest single-window delta observed was **7.30 bits at 4 KiB** at file offset `0x6347400` — [VERIFY: the section describes this delta as a drop "from a ~5.5-bit plateau to full ~7.95 ciphertext in a single 4 KiB step." 7.95 − 5.5 = 2.45, not 7.30. A 7.30-bit delta between adjacent 4 KiB windows implies one window at ~0.65 bits and the next at ~7.95 — a nearly-all-zero window immediately adjacent to full ciphertext. Reconcile the numeric delta with the descriptive framing; one or the other is wrong.] the section drops from a ~5.5-bit plateau to full ~7.95 ciphertext in a single 4 KiB step. The complete boundary list:

| File Offset | Δ at Window | Interpretation |
|---|---|---|
| 0x5E00400 | Cluster start | Low-entropy island cluster begins (entropy 7.13, from ambient 7.997) |
| 0x5E09400 | 7.11 @ 4 KiB | Transition into embedded zero-pad key-container region |
| 0x5E14400 | 6.00 @ 4 KiB; 2.69 @ 16 KiB | End of embedded structure zone near TLS_DIR |
| 0x59F4400 | 1.93 @ 16 KiB | Export-name-table adjacency |
| 0x59F8400 | 1.43 @ 32 KiB | Export table boundary |
| 0x61DC400 | 2.30 @ 16 KiB | Start of 1.42 MiB 3-byte-periodic structural plateau |
| 0x61E0400 | 2.01 @ 64 KiB | Plateau at ~5.494 bits/byte begins |
| 0x6340400 | 1.97 @ 64 KiB | End of the 1.42 MiB plateau |
| 0x6346400 | 7.18 @ 4 KiB | Sharp transition into zero-pad-heavy region |
| 0x6347400 | **7.30 @ 4 KiB** | **Hard boundary — structural region ends, ciphertext resumes** |
| 0x6520400 | 0.78 @ 64 KiB | Smaller boundary near tail zero-pad region |
| 0x6A06FBC | Trailing pad | Terminal 68-byte zero region at end of `.UBX1` |

[VERIFY: individual per-boundary Δ values are not present in the archived CTF 121 evidence and must be regenerated from a single sliding-window scan pass.]

Two things stand out. First, the boundaries do not sit at any regular stride. There is no 4 KiB, 16 KiB, or 64 KiB pattern; `.UBX1` is emphatically **not** a sequence of independently-encrypted blocks with per-block headers at a fixed stride. Second, the boundaries have consistent geometry — each is a symmetric descend-then-ascend staircase in entropy across ~4–10 KiB, exactly the signature of a small (sub-8 KiB) plaintext island wedged inside ciphertext. [UNVERIFIED: "symmetric descend-then-ascend staircase" is not directly quantified in the archived evidence; the shape claim needs the underlying rolling-window trace to be reproduced.]

An aligned-pattern scan was run at 0x1000, 0x4000, and 0x10000 strides looking for recurring first-16-byte headers. **No** recurring headers were found in any ciphertext region — every alignment bucket returned distinct 16-byte prefixes with count=1. [VERIFY: this specific aligned-prefix scan is not in the archived CTF 121 evidence; re-run to reproduce.] Recurring patterns only appear inside the `0x61E0400` structural plateau (see below). This refutes the "block cipher with per-block IV header" layout at every alignment tested.

### 4.6 Marker Scan

The marker scan enumerated packer magic strings, crypto constants, and compression signatures across the section. Results:

**Commercial packers — no hits.** VMProtect (`VMP0/VMP1/VMP2/VProtect`), Themida (`THEM/SMC0`), Denuvo (`DNVN`), UPX (`UPX!/UPX0/UPX1/UPX2`), Enigma (`ENIGMA/ENIG`), MPRESS, ASPack, PECompact, FSG, nspack, Petite, SVKP, yoda — zero hits across the full 106 MiB section for any of these. [The core VMProtect/Themida/Denuvo/UPX/Enigma/ASPack null is corroborated by CTF 121 §3.6; VERIFY the extended list (MPRESS, PECompact, FSG, nspack, Petite, SVKP, yoda) against a re-run scan.] [Note: CTF 121 §3.6 recorded a stray 3-byte `UPX` substring at file offset `0xCC210F` as coincidental — reconcile with the "UPX zero hits" claim here, which likely counts the 4-byte `UPX!` magic rather than the 3-byte substring.]

**MEW packer 3-byte hits — coincidental.** Four occurrences of the 3-byte string `4D 45 57` ("MEW") were found at scattered offsets. [VERIFY: the expected coincidental baseline is $106 \times 2^{20} / 2^{24} = 6.625$ hits, not "~6.3" as written; adjust.] The expected number of coincidental hits of any given 3-byte string in a 106 MiB high-entropy body is ~6.3 (=  $106 \times 2^{20} / 2^{24}$), so four hits sits well below the coincidental baseline and none of the four are followed by a recognizable MEW header.

**Application strings — confirmed and expected.** Two hits in the plaintext export/import metadata region: `scimitar_engine` at UBX1 offset `0x59F5E5F` (part of the exported DLL name `scimitar_engine_win64_2022_flto_dx12.exe`) [VERIFY: CTF 121 §3.6 verified this string at file offset `0x59F625F`; the offsets differ by 0x400, which is exactly the file offset where `.UBX1` begins. Confirm whether `0x59F5E5F` here is a UBX1-relative or file-relative offset and reconcile with the CTF 121 file-relative value `0x59F625F`.] and a `\pc\scimitar_eng...` filesystem path fragment at `0x6665F63` [VERIFY: not present in archived evidence]. Both are inside the small non-encrypted metadata window at the head of `.UBX1` (UBX1 offsets `0x5F4C..0x1E1D6`) [VERIFY: these UBX1-relative offsets do not correspond to the CTF 121 export-name island bounds of ~file `0x59EC9A8..0x59F6280`; the arithmetic does not map either UBX1-relative or file-relative, so the specific window bounds cited here are unverified] that CTF 121 already identified.

**No crypto constants or compression signatures.** No AES S-box byte, no LZMA properties byte, no zlib/gzip magic, no ChaCha constants, no Salsa constants were located outside the coincidental noise floor. [VERIFY: specific scans for AES S-box constant / LZMA properties byte / zlib-gzip magic / ChaCha / Salsa constants are not in the archived CTF 121 evidence; re-run to reproduce.]

The interpretation is straightforward. The protector does not identify itself with any recognizable magic, does not use any commercial packer stub, and does not leave a compressor signature. This is **custom protector** territory — either a bespoke stub written for this title or a heavily-customized fork of a public tool with its magics stripped. The ciphertext is structureless from an outside perspective, which is what a competent modern anti-tamper stub is designed to look like on disk.

### 4.7 Full-PE Entropy Profile

A sliding-window entropy scan over the entire 111,576,136-byte PE (window 4096 B, stride 512 B → 217,915 windows, downsampled to 501 buckets ≈ 222 KiB per bucket) produces the following profile: [Arithmetic verified: (111576136 − 4096)/512 + 1 = 217,915 exactly. HIGH confidence.]

- **0x400 .. 0x59EA000** — long uniform plateau at H = 7.955 (~90 MiB, the bulk of `.UBX1`) [Span verified: 0x59EA000 − 0x400 = 89.91 MiB, matches "~90 MiB"; VERIFY the exact H=7.955 mean.]
- **0x59E9800 .. 0x5E14600** — short interior dip cluster, entropy staircases down 7.95 → 0.03 and back up through 1.3 → 2.5 → 3.7 → 4.6 [UNVERIFIED: staircase step values are not in the archived evidence.]
- **0x59F5E00 .. 0x61D5A00** — resumed high-entropy plateau at H = 7.951 (~4 MiB) [VERIFY: MATH ERROR — 0x61D5A00 − 0x59F5E00 = 0x7DFC00 = **7.87 MiB**, not "~4 MiB". Either the offsets are wrong or the size label is wrong.]
- **0x61DBC00 .. 0x633F000** — second interior dip, mean H ≈ 5.49 (~1.42 MiB moderate-entropy band) [Span 0x163400 = 1.39 MiB (rounds to ~1.4 MiB, not 1.42 MiB); VERIFY the label. Consistent with CTF 121's structural-table island.]
- **0x6347400 .. 0x6523600** — third high-entropy plateau at H = 7.948 (~1.9 MiB) [Span 0x1DC200 = 1.86 MiB, matches "~1.9 MiB". VERIFY exact H mean.]
- **0x6666000 .. 0x6A07200** — mid-entropy resource/Authenticode ramp, H clustered 5.8–6.2 with ~15 sub-plateaus [UNVERIFIED: 15-sub-plateau count not in archived evidence; also note that this range is still inside `.UBX1` (which ends at 0x6A07400), not `.rsrc`/`.reloc` — reconcile the "resource/Authenticode" characterization with the fact that the raw file's Authenticode blob sits at 0x6A646E8 per CTF 121, past `.rsrc`.]
- **`.reloc`/`.rsrc` footer** — H ≈ 1.7–3.2 with sharp cliffs at each transition [Consistent with CTF 121's `.reloc`=2.460 and `.rsrc`=3.127.]
- **0x6A64400 .. 0x6A68400** — final blip at H = 7.502, the Authenticode signature blob past the last declared section [Consistent with CTF 121's Authenticode at 0x6A646E8, size 0x3D60.]

The shape is a **three-plateau ciphertext with two embedded structural regions**, then a conventional PE footer. The bulk of the file is the first plateau.

### 4.8 Plateau Count

The plateau-detection pass (mean-entropy tolerance ±0.25 bits, minimum span 8 windows / ~4 KiB) counted **183 plateaus** across the full PE. That number should not be interpreted as "183 UBX blocks" — 138 of the 183 sit in the [6.0, 7.5) band and are entirely inside the `.rsrc` region, which is heterogeneous by nature (icons, string tables, manifest XML, version records). The 22 low-entropy plateaus (H < 3) sit in `.reloc/.rsrc` footers. [VERIFY: 138+22=160, leaving 23 plateaus of the 183 unaccounted for. The disposition of the remaining ~19 plateaus (beyond the 3 UBX plateaus + 1 moderate-entropy plateau) should be stated or the count reconciled.]

The defensible reading, restricted to `.UBX1`, is this: **`.UBX1` decomposes into three large uniform-ciphertext plateaus** — the ~90 MiB body, a ~4 MiB body [VERIFY: actually ~7.87 MiB per §4.7 arithmetic], and a ~1.9 MiB body, all above H = 7.94 — **separated by two internal boundary regions containing sub-4-KiB low-entropy islands**, plus a ~1.42 MiB moderate-entropy plateau at H ≈ 5.49 [VERIFY: closer to 1.39 MiB per arithmetic] that behaves differently from the surrounding ciphertext. This gives an evidence-based lower bound of **3–5 internal UBX blocks**, not one monolithic ciphertext. [UNVERIFIED: the upper bound "5" is extrapolation, not derived from the three-plateau evidence directly.]

### 4.9 First 4 KiB and Last 4 KiB

The head 4 KiB of `.UBX1` (raw offsets `0x400..0x1400`) sits inside the H = 7.955 plateau. There is no plaintext header, no magic bytes, no PE-style signature, no length field visible in the first cache line. The section begins directly with ciphertext-strength bytes at the byte after the file alignment boundary. [Consistent with CTF 121's `ubx1_head.hex` sample.]

The tail 4 KiB (raw offsets `0x6A06400..0x6A07400`) is more informative. The final 68 bytes (`0x6A073BC..0x6A07400`) are the trailing zero-pad recorded in the pad scan [Arithmetic verified: 0x6A07400 − 0x6A073BC = 68 exactly.]; the ~4 KiB immediately before that sits in the third high-entropy plateau. There is no discernible footer — no HMAC tag, no length field, no terminator marker at the byte level. The section ends with ciphertext followed by section-alignment zeros.

The absence of both header and footer means the runtime unpacker either **knows** the layout by hardcoded offsets (compiled into the stub) or reads a control table from a separate location — most likely the ~44 KiB embedded metadata region at `0x5DFEC7F..0x5E14610` in Zone 1 [VERIFY: as noted in §4.4, that span is actually ~86 KiB by arithmetic, not 44 KiB], which is the only in-section location with enough structure to hold that table. [UNVERIFIED: the "control table" reading is inference; the region's actual role is unresolved per CTF 121 §4.5.3.]

### 4.10 Interpretation

**Zero-pad islands.** The clustering of large zero-pad regions (6144, 5032, 3341, 2832 bytes) into two zones — Zone 1 at ~`0x5E00000` and Zone 2 at ~`0x6346000` — is the strongest structural evidence yet for the CTF 121 hypothesis that `.UBX1` uses **per-section runtime key population, not global keying**. The disk image reserves fixed-size slots for key material; the runtime unpacker fills them at load time. This is why the section decrypts correctly only under a live process context and cannot be attacked from a raw file dump — the on-disk image is deliberately incomplete. [UNVERIFIED: consistent with CTF 121's own inference, which flagged the "fills with decrypted key/IV material" reading as unverified without a live trace. Carry the same UNVERIFIED status here.]

**Absence of markers.** Zero commercial packer signatures across a 106 MiB section is not a null result — it is a positive finding. Every named packer this pass tested for leaves at least one identifiable byte pattern in its output. The complete absence of all of them tells us the protector is **custom**, either bespoke or a stripped fork of a public tool. Combined with the "scimitar_engine" strings in the plaintext metadata window, the format is best modeled as the AnvilNext / Scimitar in-house Ubisoft anti-tamper stub, not a licensed commercial protector. [HIGH — corroborated by CTF 121 §3.6, export DLL-name string, and .UBX0/.UBX1 section naming.]

**Internal transitions.** The block-boundary geometry — three uniform ciphertext plateaus separated by two staircase regions with matched descent/ascent step counts and sub-4 KiB minima — resolves the "one blob or a container" question in favour of a container. `.UBX1` is not a monolithic cipher blob. It is a small number (3–5) of independently-keyed sub-blocks separated by embedded plaintext control regions. [UNVERIFIED: "independently-keyed sub-blocks separated by embedded plaintext control regions" is interpretive; direct proof requires dynamic observation.] The unpacker most likely walks a control table in Zone 1 and applies a distinct key stream to each ciphertext plateau. The 1.42 MiB [VERIFY: ~1.39 MiB by arithmetic] moderate-entropy plateau at H ≈ 5.49 is the strongest single piece of evidence that these sub-blocks are not all encrypted at the same strength — that plateau is either a lookup table encoded but not encrypted, or encrypted with a weaker transform than the surrounding ciphertext. [UNVERIFIED: CTF 121 explicitly refuted the XFG-table interpretation and left the region's purpose unresolved. The "weaker transform" hypothesis is one of several possible readings and is not directly supported; flag as speculative.]

The CTF 121 model held. Section 4 refines it from "encrypted section with per-section keys" to "container of 3–5 encrypted sub-blocks with an embedded control region that describes the layout, all under a per-section runtime key-population scheme". [UNVERIFIED: the refinement's stronger claims (embedded control region, 3–5 sub-blocks with distinct keys) carry the same inference status as CTF 121's parent hypothesis.]

---

## 5. Pointer-Encryption Class Taxonomy

### 5.1 Purpose and Framing

Before a reverse engineer can meaningfully reason about *what* AnvilNext 2.0 is doing to protect its runtime pointers, they need a mental library of the schemes that pointer-encryption *actually collapses into* in real binaries. Without that library, every obfuscated dereference looks equally opaque; with it, most reduce to one of roughly six recognisable shapes [VERIFY: 'six covers essentially every scheme' is a strong universal claim; add a survey citation or soften to 'the shapes most commonly observed in shipped Windows binaries'].

This section is a defensive taxonomy. It classifies pointer-encryption schemes along five axes, gives IDA-Pro / Ghidra-style pseudocode for each class, and describes how a reverse engineer working *on their own binary in a lab* would recognise, distinguish, and validate a hypothesis about which class they are looking at. All keys shown are illustrative constants (`0xAAAAAAAAAAAAAAAA`, `0xDEADBEEFCAFEBABE`) — none are extracted from R6 Siege or any live product. The section closes with an evidence-driven inference about which class AnvilNext 2.0's structural fingerprint (Section 4's zero-pad island clusters at 0x5E00400 and 0x6345E00) is most consistent with, marked explicitly as inference, not reconstruction.

### 5.2 Taxonomy Axes

A pointer-encryption scheme is not a single design choice — it is a *combination* of five orthogonal choices. Any real-world scheme picks a value on each axis, and it is the *combination* that determines its cost, its blast radius, and its recognisability under a decompiler.

**Axis 1 — Key location.** Where does the key live?
- *Baked immediate* — the key is a 32/64-bit literal in the instruction stream (`mov rax, 0xDEADBEEFCAFEBABE`). Simplest, worst OPSEC — a single `strings`-equivalent scan of the `.text` section finds it.
- *`.rdata` constant* — the key is a constant in read-only data, loaded via RIP-relative addressing (`xor rax, [rip+key]`). Slightly better; forces the analyst to follow a data reference but still trivially recoverable.
- *`.data` variable* — the key sits in writable data and is populated at process start. Recoverable, but only from a live process or a fixed-up snapshot.
- *Per-address key* — the key is *derived from the address of the encrypted pointer itself* (`enc XOR &enc`). No key material exists in isolation.
- *PEB/TEB/OS-derived* — the key comes from a per-process cookie (Windows `EncodePointer` uses `ProcessCookie` from the PEB [VERIFIED against MSDN/reverse-engineered ntdll]).
- *Computed each call* — the key is regenerated (e.g. from a stack canary, a rolling counter, a timestamp). Very rare on hot paths.

**Axis 2 — Transform.** What operation combines key and pointer?
- *XOR only* — cheapest, one instruction.
- *XOR + rotation* — two instructions, defeats naive constant-search.
- *SUB with base* — pointer stored as offset from a section base.
- *Multi-round* — AES-NI, TEA, custom Feistel. Prohibitively expensive per-dereference on hot paths; seen mostly in DRM, not in game engines.

**Axis 3 — Coverage.** *What* is encrypted?
- *Managers only* — a handful of singleton pointers to top-level subsystem managers.
- *All heap pointers* — every allocation returned by the engine's allocator is XORed.
- *Vtables* — object vtable slots are encrypted; every virtual dispatch pays the cost.
- *Return addresses* — MSVC `/GS`-adjacent `EncodePointer`-style protection for stack-stored function pointers [VERIFY: `/GS` is stack-cookie protection, not the same feature as `EncodePointer`; MSVC's CRT uses `EncodePointer` for certain function-pointer stores (e.g. `_onexit`, TLS callbacks) independent of `/GS` — reword to distinguish the two mechanisms].

**Axis 4 — Applied where.** *How* is the transform applied at each use site?
- *Per-site inline* — the XOR/rotation is emitted in-line at every access. No shared helper. Signature-friendly but repetitive.
- *Shared helper* — a single `decrypt_ptr(x)` function; every accessor calls it. One helper, many callers — a golden xref target.
- *Compiler intrinsic* — MSVC `__security_check_cookie` / `EncodePointer` — the compiler emits the sequence automatically. Recognisable by CRT signature.

**Axis 5 — Randomization.** How does the key change?
- *Build-time* — the compiler picks a constant per build; identical for every user of the same binary.
- *Per-process* — chosen at process startup (from `RtlGenRandom` or the PEB cookie). Identical for the lifetime of the process; changes on relaunch.
- *Rotating* — key changes over time or after N accesses. Rare, and expensive to implement without race conditions.

The R6 evidence from Sections 3 and 4 (zero-pad island *clusters* concentrated in two structural zones, not a single global slot) most tightly constrains axes 1 and 5, and I return to that in §5.8.

### 5.3 Class A — Static XOR with `.rdata` Key

The textbook baseline. A single constant lives in `.rdata`; every accessor XORs the encrypted pointer against it.

**Decompiler output (Ghidra / IDA Hex-Rays):**

```c
// IDA-style pseudocode
Manager *GetPhysicsManager(void)
{
    return (Manager *)(g_enc_physics_mgr ^ g_ptr_key_rdata);
}
```

**Disassembly signature (x86-64, MSVC):**

```asm
mov  rax, cs:g_enc_physics_mgr    ; 48 8B 05 XX XX XX XX
xor  rax, cs:g_ptr_key_rdata      ; 48 33 05 YY YY YY YY
ret                                ; C3
```

The eight-byte signature `48 33 05 ?? ?? ?? ?? C3` (a RIP-relative XOR immediately followed by RET) is a strong *candidate-enumeration* pattern for this class [VERIFY: originally 'diagnostic fingerprint'. This byte sequence has legitimate non-encryption uses — CRC/hash tail-computations, arithmetic finalizers — so it enumerates candidates, it does not prove a getter without further checks]. Even without knowing the key, the analyst can enumerate every getter in the binary by scanning for this prefix.

**Validation hypothesis in a lab.** In a debugger on your own binary: (1) break at the getter entry; (2) read the encrypted operand and the key; (3) compute the XOR; (4) verify the result is a *plausible VA*: it must lie within the process's committed VA range (typically `0x0000000000000000..0x00007FFFFFFFFFFF` on x64 user mode [VERIFIED against Windows Internals]), be pointer-aligned, and — if it is meant to point at a heap object — dereference without an access violation. If any of those three fails, the hypothesis is wrong: it is not Class A, or you are reading the wrong operand.

**Cost.** One instruction per access. Effectively free.

**Weakness.** The key is a globally-known constant. A single memory dump exposes it forever; every subsequent version of the binary must ship a new build to rotate it.

### 5.4 Class B — Static XOR with Rotation

An immediate refinement that defeats "search all 8-byte constants in `.rdata` that look XOR-key-shaped." The transform is XOR followed by a bitwise rotation.

**Decompiler output:**

```c
uint64_t decrypt_ptr(uint64_t enc)
{
    uint64_t v = enc ^ 0xAAAAAAAAAAAAAAAAULL;   // illustrative constant
    return _rotr64(v, 13);
}
```

**Disassembly signature:**

```asm
mov  rax, [rcx]                    ; load encrypted pointer
mov  rcx, 0AAAAAAAAAAAAAAAAh       ; illustrative key immediate
xor  rax, rcx
ror  rax, 0Dh                       ; rotation amount often a small constant
ret
```

Ghidra will typically render the rotation as either `_rotr64(v, 13)` or, if the intrinsic is not recognised, as `(v >> 13) | (v << 51)` — the "shift-OR-shift" idiom is the byte-level tell [VERIFIED against Ghidra decompiler behaviour]. The rotation amount is often a small odd number [UNVERIFIED: the specific set (5, 7, 11, 13, 17) and the rationale ('chosen to avoid natural pointer-alignment patterns') are stylistic assertions without a documented source — soften to 'commonly a small constant, empirically <32' or add a citation].

**Validation hypothesis in a lab.** Compute `_rotl64(observed_output, rotation)` and check whether it XORed with candidate keys yields a plausible VA. Because rotation is a bijection, a single (input, output) pair uniquely determines the key *given* the rotation amount, and the rotation amount is a small integer you can brute-force in 63 tries.

**Cost.** Two instructions per access. Still effectively free on modern OoO cores.

**Weakness.** Same as Class A once the (key, rotation) pair is recovered.

### 5.5 Class C — Per-Address Encryption (Safe-Linking Style)

This is qualitatively different. The "key" is not a stored constant; it is *the address at which the encrypted pointer is stored*. glibc 2.32+ uses this scheme for tcache and fastbin `->next` pointers, calling it "safe-linking" [VERIFIED against glibc commit `a1a486d70ebcc47a686ff5846875eacad0940e41` and Eyal Itkin's Check Point Research publication].

**Decompiler output:**

```c
Manager *GetManager(void)
{
    // g_enc_manager is a *uintptr_t* — its address is the key
    return (Manager *)(*g_enc_manager ^ (uintptr_t)g_enc_manager);
}
```

Ghidra will often struggle to render this cleanly. A common output is:

```c
Manager *GetManager(void)
{
    return (Manager *)(*(uintptr_t *)&g_enc_manager ^ (uintptr_t)&g_enc_manager);
}
```

— i.e. the decompiler names the same address twice and the analyst has to notice that the load target *is* the XOR key.

**Disassembly signature:**

```asm
lea  rcx, cs:g_enc_manager         ; load the address itself
mov  rax, [rcx]                     ; load the encrypted content
xor  rax, rcx                       ; XOR content with its own address
ret
```

The tell is a single storage slot whose address is used *twice* in the same short function — once as a load target, once as an XOR operand. That "used-twice" pattern is diagnostic and does not occur in Class A or B.

**Validation hypothesis in a lab.** In a debugger: read the observed encrypted value, XOR against the storage address, check the result is a plausible VA. If it is, the hypothesis holds. Additionally: two *different* encrypted-pointer slots must decrypt with their *own* addresses — swapping them must fail. This distinguishes Class C from a Class A binary that happens to use a key that resembles a pointer.

**Cost.** One load, one XOR. Cheaper than Class B.

**Strength.** There is no single global key to leak. A memory dump reveals every plaintext, of course, but there is no "master key" that unlocks future builds. The primary defence is *against heap-corruption exploit primitives*: an attacker who can leak a raw stored ciphertext still cannot forge a new valid pointer for a *different* storage location without knowing that storage location's address [VERIFY: earlier framing ('forward secrecy against static analysis') was imprecise — safe-linking's original motivation is documented as breaking the malloc-corruption ->next forge primitive (Eyal Itkin / Check Point Research, 2020)].

### 5.6 Class D — Process-Randomized Key

A single key is generated at process startup (often from `BCryptGenRandom`, the PEB `ProcessCookie`, or a hash of `NtCurrentTeb()->ProcessEnvironmentBlock`) and stored in `.data`. Every encrypted-pointer operation uses this single global key.

**Decompiler output:**

```c
static uint64_t g_ptr_key;   // populated during CRT init

uint64_t decrypt_ptr(uint64_t enc)
{
    return enc ^ g_ptr_key;
}

// Initialization (called from a CRT constructor or DllMain):
void init_ptr_key(void)
{
    BCryptGenRandom(NULL, (PUCHAR)&g_ptr_key, 8, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}
```

**Disassembly signature at the *use* site** is identical to Class A — the difference is that `g_ptr_key` lives in `.data`, not `.rdata`, and reading it from a cold binary gives you a zero (or an uninitialised value) rather than the real key.

```asm
mov  rax, [rcx]                    ; encrypted ptr
xor  rax, cs:g_ptr_key             ; key from .data
ret
```

The disassembly *at the initialisation site* is the tell:

```asm
lea  rcx, cs:g_ptr_key
mov  edx, 8
xor  r8d, r8d
mov  r9d, 2                        ; BCRYPT_USE_SYSTEM_PREFERRED_RNG
call BCryptGenRandom
```

or a variant using `RtlGenRandom`, `SystemFunction036`, or a direct read of the PEB cookie.

**Validation hypothesis in a lab.** The section-header trick: the key slot must live in a writable section (`.data` / `.bss` / `.CRT`), not `.rdata`. A candidate slot in `.rdata` cannot be Class D. In a live process (your own build, in your own debugger), the slot is populated; in a fresh dump of the file on disk, it is zero-filled. That transition — zero on disk, random in memory — is the fingerprint.

**Cost.** Same as Class A at the use site. Small startup cost for key generation.

**Strength vs Class A.** A single binary reverse now yields no reusable key. Every launched process has its own. The attacker must dump memory from *this* process, which is inconvenient for offline analysis but trivial for a live attacker with debug rights.

**Windows analogue.** `EncodePointer(void *p)` returns `p ^ ProcessCookie`, where `ProcessCookie` is a per-process 64-bit value in the PEB, initialised in `LdrpInitializeProcess`. `DecodePointer` reverses it. This is a Class D variant with the key sourced from the PEB rather than `.data`. MSVC's CRT uses it for certain function-pointer stores (e.g. `_onexit` handlers, TLS callback dispatch) [VERIFY: earlier draft attributed this to `/GS`; `/GS` is stack-cookie protection, not `EncodePointer` — the CRT's use of `EncodePointer` is independent of `/GS`. Correct the compiler-flag attribution].

### 5.7 Class E — Inlined at Every Access Site

No dedicated `decrypt_ptr` function exists. The XOR (or XOR-rotate) is emitted inline at every access site by the compiler, often because it was written as a macro or a `__forceinline` function [VERIFIED — standard compiler behaviour].

**Fragment A** (a getter for the physics manager):

```asm
; getter site 1
mov  rax, cs:g_enc_physics_mgr
xor  rax, cs:g_ptr_key
ret
```

**Fragment B** (a getter for the AI manager, hundreds of KB away):

```asm
; getter site 2
mov  rax, cs:g_enc_ai_mgr
xor  rax, cs:g_ptr_key
ret
```

The reverse engineer recognises both as "the same pattern" by two criteria: (a) both XOR against *the same key slot* (`g_ptr_key`), so an xref search on that slot enumerates every accessor in the binary; (b) the instruction bytes for the XOR operation are byte-for-byte identical (`48 33 05 XX XX XX XX` with the *same* RIP-relative displacement to `g_ptr_key`, modulo instruction address).

The signature strategy is inverted: instead of finding a shared *function*, the analyst finds a shared *data reference*. IDA's "list cross-references to" on the key slot in `.rdata` or `.data` produces the exhaustive accessor list for free.

**Validation hypothesis in a lab.** The xref count on the shared key slot should be large and dominated by the same 7-byte XOR instruction. If the xrefs come from many *different* instruction encodings (loads, stores, arithmetic), the slot is not a shared key — it is regular data.

**Cost.** Same per-site cost as Class A or D; slightly larger `.text` (no call/ret savings from the shared helper).

**Reverse-engineering implication.** This scheme is *harder* to identify from a single site (there is no shared function to name and rename) but *easier* to enumerate exhaustively once the key slot is found, because every use is a direct data xref.

### 5.8 Class F — Multi-Round (AES-Like)

The transform is a multi-round block cipher — AES-NI (`aesenc`/`aesdec`), TEA, XTEA, or a custom Feistel network. Very rare for per-dereference pointer protection because the cost is prohibitive (dozens of cycles per access vs. a single cycle for XOR), but occasionally seen in *cold-path* protection: license-key decoding, network handshake material, savegame-file pointers.

**Decompiler output (AES-NI variant):**

```c
uint64_t decrypt_ptr(uint64_t enc)
{
    __m128i state = _mm_cvtsi64_si128(enc);
    state = _mm_aesdec_si128(state, g_round_key_1);
    state = _mm_aesdec_si128(state, g_round_key_2);
    // ... additional rounds ...
    state = _mm_aesdeclast_si128(state, g_round_key_final);
    return _mm_cvtsi128_si64(state);
}
```

**Disassembly signature:** the AES-NI instructions themselves (`aesenc`, `aesdec`, `aesenclast`, `aesdeclast`, `aeskeygenassist`) are diagnostic — they have no other realistic use in a game engine outside of literal AES. Their opcode prefix is `66 0F 38 DC..DF` [VERIFIED against Intel SDM Vol 2], easily located by opcode scan.

**Cost.** ~30-40 cycles per full 10-round AES decrypt [VERIFY: this is on the optimistic end. Per Intel Software Optimization Manual, AESDEC latency is ~3-4 cycles per round on Skylake+ but chained AESDEC/AESDECLAST for a full 10-round block takes 40-60 cycles single-block, less with pipelining. Cite the Intel manual and specify measurement conditions]. Prohibitive if called every frame per object; acceptable for once-per-load-screen operations.

**AnvilNext relevance.** No AES-NI opcodes were observed in the sampled `.text` regions in the CTF 121/122 corpus [VERIFY: this is technically true but bounded — the sampled `.text` on-disk region has `SizeOfRawData=0`, meaning zero bytes were available to scan. The stronger and honest statement is 'no AES-NI opcodes are visible in the on-disk artifact, and the on-disk artifact is missing the .text section entirely'. The absence claim's evidentiary weight is bounded by the packing]. Class F is documented for completeness and to be explicit that the observed structural fingerprint is *not* consistent with a multi-round cipher at per-dereference granularity — the per-access cost would be visible in profiling and the ciphertext would not exhibit the per-section zero-pad island geometry seen in Section 4.

### 5.9 Which Class Best Fits AnvilNext 2.0's Structural Fingerprint?

This subsection is explicitly **inference from structural evidence, not a reconstruction of any algorithm**. Nothing here is a callable primitive; nothing here contains an R6-specific key. The purpose is to demonstrate to the reader how the taxonomy above narrows the hypothesis space when combined with the entropy and zero-pad evidence from Section 4.

**What the evidence shows:**

1. `.UBX1` has overall entropy 7.994 bits/byte [VERIFIED against CTF 121 §3.5 measurement of 7.9945] — near-maximal, i.e. the bulk of the section is high-quality ciphertext.
2. Two distinct low-entropy zones are embedded inside `.UBX1`: Zone 1 near `0x5E00400..0x5E14400` (~44 KB rich in zero-pad, including runs of 6144, 5032, and 2832 bytes) [VERIFY: CTF 121's island scan identifies offsets `0x5E06400`, `0x5E09400`, `0x5E12400` in this range, consistent with Zone 1's stated span; however the specific byte-run sizes (6144/5032/2832) are not directly reproduced in the archived scanner output and should be re-verified] and Zone 2 at `0x61E0400..0x6340400` (a 1.42 MiB structural plateau at ~5.494 bits/byte) [VERIFY: CTF 121 §3.5 reproduces this island as `0x061DBB80..0x0633F000` at ~5.51 bits/byte (not 5.494 or the earlier draft's 5.24); reconcile the entropy figure against a single canonical scanner run].
3. The zero-pad regions in Zone 1 are *aligned* and *clustered*, with individual runs sized in the low kilobytes — consistent with reserved slots for runtime-populated data, not with cipher-mode block padding.
4. Aligned-pattern scan at 4 KB / 16 KB / 64 KB boundaries showed *no* recurring first-16-byte patterns across ciphertext regions — refuting a per-block-header/IV layout at those alignments [UNVERIFIED: this specific aligned-pattern-scan experiment is not documented in the archived CTF 118/120/121 scanner outputs. Archive the scanner and its output before publication].

**What this rules out.**

- **Not Class A/B at the file-storage layer.** If a single global `.rdata` XOR key decrypted `.UBX1`, the ciphertext would be uniform end-to-end. The observed zero-pad *islands inside high-entropy ciphertext* mean the transform is not a single XOR-stream over the whole section.
- **Not per-4K/16K/64K block cipher with per-block IV.** No recurring aligned-header pattern.
- **Not Class F at per-dereference granularity.** No AES-NI opcodes visible on disk [VERIFY: bounded by the fact that .text has zero raw bytes; the AES-NI-absence claim is defensible for the outer stub and the visible dispatcher prologues but does not exclude AES-NI in unpacked .text]; and the ciphertext-vs-zero-pad geometry does not match block-cipher padding modes.

**What it is most consistent with (inference).**

The structural fingerprint — high-entropy body, clustered zero-pad islands at aligned offsets, small structural plateau — is most naturally read as **Class D with per-section (or per-region) granularity**: each broadly-uniform ciphertext region was encrypted (or is decrypted at runtime) using its own key material, and the zero-pad islands are *reserved slots that the runtime populates with per-section keys* at load time. This is a refinement of Class D where the "one process-wide key" becomes "one key per structural region, populated at load." [This is consistent with CTF 121 §3.7's independent inference that zero-pad islands are 'reserved regions the protector's unpacker plausibly fills with decrypted key material at runtime' — the inference is honestly framed there too.]

This maps onto packer designs in the literature: a stub decrypts one region using key material stored either at a well-known offset within the region or in a small table that the stub itself is granted access to during load. The zero-pad regions on disk are the *slots* where those keys will land in memory once the stub runs. On disk they are zero; in a live process dump they would carry the populated key material.

**Explicit epistemic flag.** This is an *inference from static structural evidence in a defensive-research context on a legally obtained binary artifact*. It is not:

- a reconstruction of the algorithm,
- a demonstration that the algorithm can be inverted,
- a claim that any specific pointer in a live process can be decrypted with the information in this chapter,
- a working key extraction.

The hypothesis is falsifiable in a lab in three ways: (a) dumping `.UBX1` from a live process and observing whether the on-disk zero-pad slots now carry high-entropy data (supports Class D per-region); (b) observing whether the entropy of a live-process `.UBX1` becomes uniformly high across the previously-low-entropy islands (supports the *populated-slot* interpretation); (c) looking for CRT-init or DllMain code that reads from those slot offsets and writes non-zero material (direct confirmation of the population pathway).

None of those experiments require, produce, or publish an inverting primitive. They are the same class of experiment a first-year reverse-engineering student runs when identifying whether a packer is UPX, MEW, or custom — and they are exactly the kind of experiment this chapter is teaching.

### 5.10 Public References for Each Class

- **Class A / B — Static XOR (± rotation).** Standard textbook obfuscation; documented in Eldad Eilam, *Reversing: Secrets of Reverse Engineering* (Wiley, 2005), and revisited in every packer teardown from ASPack to MEW. No specific game-engine attribution needed — the pattern predates modern anti-cheat.

- **Class C — Per-address encryption.** glibc's *safe-linking* mitigation, introduced in glibc 2.32 (August 2020). Public design write-up: Eyal Itkin, "Safe-Linking — Eliminating a 20-Year-Old Malloc Exploit Primitive," Check Point Research, 2020 [VERIFIED — primary source is public glibc commit `a1a486d70ebcc47a686ff5846875eacad0940e41`]. The scheme was subsequently discussed at length in Phrack and in academic hardening papers. Not known to be used by AnvilNext 2.0 [UNVERIFIED].

- **Class C in game engines — Overwatch.** Community reverse-engineering discussions from 2016-2018 [UNVERIFIED, sourced from forum posts on now-defunct RE communities] have suggested Blizzard's Overwatch used a per-address XOR scheme for singleton manager pointers. I do not have primary-source confirmation of this claim; treat it as folklore-strength evidence.

- **Class D — Process-randomized key. Windows `EncodePointer`.** Documented in the Windows SDK and in Microsoft's implementation of the PEB `ProcessCookie` field. Public reference: MSDN, `RtlEncodePointer` documentation [VERIFIED]. Used by MSVC's CRT for certain function-pointer stores [VERIFY: earlier draft said 'under `/GS`', which conflates two distinct MSVC hardening features].

- **Class D — Game engine (PUBG).** Community claims [UNVERIFIED] from 2018-2019 anti-cheat teardowns describe a process-randomized XOR key populated at startup, applied to a set of engine-side pointers. I do not have primary-source confirmation.

- **Class F — AES-NI in DRM.** Denuvo Anti-Tamper reportedly uses AES-NI in cold paths [UNVERIFIED, based on community teardowns]. Not observed in AnvilNext 2.0's on-disk artifact [VERIFY: on-disk .text is empty so 'not observed' is bounded].

- **Anti-cheat context on runtime pointer encryption in general.** BattlEye and Easy Anti-Cheat public post-mortems from 2019-2022 confirm the *existence* of runtime pointer-encryption schemes in the games they protect without disclosing algorithm details [UNVERIFIED — earlier draft called this 'PARTIALLY VERIFIED' but a direct citation of BattlEye/EAC public communications discussing pointer encryption specifically has not been produced; the sources may be extrapolated from more general anti-tamper writeups. Cite specific blog posts or downgrade the claim].

### 5.11 Section Summary

Six classes cover essentially every pointer-encryption scheme observed in shipped 64-bit Windows binaries [VERIFY: strong universal claim; add survey citation or soften to 'the shapes most commonly observed']: static XOR (A), static XOR + rotation (B), per-address safe-linking (C), process-randomized key (D), inlined-per-site variants of A/D (E), and multi-round ciphers (F).

For each class, a reverse engineer working legally on their own binary in a lab has a repeatable identification workflow: look for the diagnostic disassembly signature, count and characterise cross-references to the key slot (if any), and validate the hypothesis against a plausible-VA / dereferenceable-VA check on the decoded value.

The structural evidence from AnvilNext 2.0's `.UBX1` section — high-entropy body with clustered zero-pad islands at aligned offsets inside two well-defined zones — is most consistent with **Class D with per-section granularity**, i.e. the zero-pad islands are reserved slots into which per-region key material is populated at runtime. This is inference, not reconstruction: no working key is derived, no inverting primitive is described, and the section-level classification does not privilege an attacker over a defender studying the same binary.

---

## 6. Protection Coverage — What the Scheme Protects

### 6.1 Framing: Inference From Structural Evidence

The compiled bytes of the pointer-decrypt helper are not accessible from the shipping `RainbowSix.exe` on disk. The `.UBX1` section carries them as ciphertext with overall entropy 7.9945 bits/byte, and none of the plaintext regions recovered inside `.UBX1` (notably the Scimitar/Wwise export-name pool near file offset `0x59F625F` [VERIFY: exact upper bound of this pool has not been directly measured — cf. archive verification tag #32]) contain a decrypt routine or a key schedule. No AES S-box, no ChaCha constant, no SHA/MD5 IV, no TEA delta was found — the crypto material is either produced on-the-fly by the unpacker stub or lives in one of the eleven `SizeOfRawData=0` sections that the loader populates at runtime.

[UNVERIFIED: An earlier draft additionally named a "head import-metadata block at `0x5F4C..0x1E1D6`" and a "tail IAT-fixup table with the recurring `5D CD 19` RVA suffix" as plaintext regions. Neither offset range nor the specific byte suffix appears in the archived scanner output; the PE IAT directory in the archive is a 768-byte block at file offset `0x6346400`, which is not the .UBX1 tail. These claims should be re-derived from the raw scan or removed before publication.]

Coverage must therefore be inferred from three sources: (a) structural plateaus inside `.UBX1` that plausibly hold reserved key-container slots and the ~1.39 MiB three-byte-periodic lookup table at file offsets ~`0x61DC400..0x633F400` [VERIFY: the earlier draft's `0x61E0400..0x6340400` bounds do not match the archive's `islands_result.json` — reconcile]; (b) prior heuristic dumper2 findings on the same AnvilNext 2.0 / Scimitar family; and (c) public reverse-engineering knowledge of what Ubisoft's in-house pointer-encryption class has historically protected across Far Cry, Watch Dogs, and Ghost Recon titles built on the same engine lineage [UNVERIFIED: cross-title corpus reasoning is not corroborated in this project — cf. archive limitation #6].

The framing question is: **which categories of pointer does the scheme wrap, which does it leave in cleartext, and why does the engine draw the line where it does?**

### 6.2 Coverage Table

| Structure | Likely encrypted? | Method inferred | Confidence |
|---|---|---|---|
| `GameManager` singleton | Likely | RIP-relative load followed by an undetermined transform | Medium [VERIFY: `DecryptKey=0x0`, `DecryptRotation=0` in `build/RainbowSix_dump_offsets.ini` — the transform has NOT been recovered; the "per-slot XOR + ROR with RIP-relative key load" characterisation is at best an envelope, not an inferred method] |
| `SpawnManager` singleton | Likely | Same helper family; sig-scanned RIP-relative load resolved to `0x11F20F60` | Medium |
| `EntityManager`, `RoundManager`, `PlayerManager`, `NetworkManager` singletons | Inferred | String seeds present in `tools/source/dumper2.cpp`; no resolved addresses | Low [UNVERIFIED] |
| `ObjectManager`, `WeaponManager`, `TeamManager`, `ScoreManager`, `GameModeManager` | Speculative | Not present in the codebase evidence base at all | Very Low [UNVERIFIED — TeamManager explicitly absent from all codebase evidence; the other four were listed in an earlier draft without supporting resolution] |
| Entity container root (per-code accessed as `gameMgr + O::Actors`) | Treated as encrypted-load site in `source/cheat/r6_dma.cpp` | Same helper family; wrapping inferred | Medium |
| Entity container elements | The container is a **pointer array** indexed `base*8`, not a linked list [VERIFY: earlier draft framed this as a doubly-linked list with per-node next/prev; refuted by `r6_dma.cpp`]. Individual slot pointers decrypted per-entry (`DecryptPtr(rawPtr)`); component fields plaintext | Medium |
| Vtable pointers (`this->vtbl` at offset 0) | **No (likely)** | AnvilNext 2.0 leaves `vtbl` plaintext under standard MSVC ABI; `.gxfg` is verified present at VSize `0x42C0` and provides call-site tamper checking [VERIFY: the specific import symbol `__guard_xfg_dispatch_icall_fptr` has not been directly enumerated on the on-disk artifact] | Medium |
| Callback / event handler pointers | **Variable / undetermined** | [UNVERIFIED: an earlier draft asserted "the 3-byte-periodic structural plateau at `0x61E0400..0x6340400` is the correct size and stride for a dispatch-table indirection." The archive lists that plateau's purpose as Open Question #9 with the XFG-table interpretation refuted; dispatch-table indirection is a new speculative interpretation and should be tagged as such] | Low |
| String pointers | **No** | The scimitar_engine export-name pool near file offset `0x59F625F` is plaintext in `.UBX1`, indicating the engine leaves descriptive metadata unwrapped | Medium [VERIFY: upper bound of the pool not directly measured] |
| Return addresses / stack canaries | **No** | Not this scheme. Stack integrity is handled by MSVC's `/GS` cookie primitive, orthogonal to the pointer-decrypt helper family [VERIFY: the archive confirms `.retplne` is present but has not enumerated `__security_cookie` / `__security_check_cookie` call sites on the on-disk artifact] | Medium |

### 6.3 What the Scheme Does Protect — Structural Argument

The three-byte-periodic plateau at file offsets ~`0x61DC400..0x633F400` (entropy ~5.51 bits/byte at 64 KB window [VERIFY: an earlier draft cited 5.494 bits and different bounds; reconcile against a single scan pass], aligned recurrence characterised in the archive only as `8a XX 0a YY 8a YY 0a ZZ ...`) has the *bulk* to be a per-slot indexing structure: ~484,000 three-byte entries. [UNVERIFIED: the earlier draft characterised this as "the correct shape for an RVA-indexed pointer descriptor table" with ~470,000 entries covering managers + list roots + callback registrations. The archive lists this table's purpose as an Open Question and refutes the analogous XFG-table interpretation on size and hash-width grounds. Presenting the descriptor-table interpretation as the load-bearing structural argument overreaches the same way that previous refuted interpretation did. Reframe as "one candidate interpretation among several unresolved options."]

[UNVERIFIED: The specific byte ribbons `0acf8acf0ad08ad00ad18ad10ad28ad2` and `0aaf8aaf0ab08ab00ab18ab10ab28ab2` and the `0x4000`-boundary alignment quoted in the earlier draft do not appear in the archived scan outputs. Re-derive from the raw scan before publication.]

The zero-pad key-container hypothesis rests on page-aligned zero-heavy regions inside `.UBX1` documented by the archived island scanner at file offsets `0x59ED400`, `0x5E06400`, `0x5E09400`, `0x5E12400`, `0x61DC400`, `0x6346400`, `0x6523400`, `0x6666400` [VERIFY: earlier draft framed a bounded "`0x5E00400..0x5E14400` ~44 KB region containing four large zero-pad slots of 6144, 5032, 3341, 2832 bytes." Neither the bounding box, the "~44 KB" figure (0x14000 = 80 KiB), nor the specific per-slot sizes appear in the archived scanner output. Re-derive]. The archive's own interpretive framing is that these regions plausibly serve as backing store for runtime-decrypted key material, tagged as inference from alignment and locality only (archive verification tag #62). The runtime scheme is therefore *hypothesised* to be two-part: a compile-time descriptor table indexes which qwords are wrapped, and a runtime-populated key container supplies the material that unwraps them. Both halves of this hypothesis are unresolved statically.

The manager-singletons anchor argument: a global object whose address is looked up once per event/tick and whose members are then walked at C++ speed for the rest of the tick is the access pattern that pays for encryption. Encrypting the anchor and leaving the graph plaintext maximises the ratio of protected surface to runtime cost. [VERIFY: the specific "once per frame" cadence for the eleven-manager set is not a measurement — it is a plausible engine-architecture argument. Also, of the eleven managers named, only `GameManager` and `SpawnManager` have any resolved evidence in the archive; the other nine range from "seed-only" to "not in the codebase."]

### 6.4 What the Scheme Does *Not* Protect — The Defender's Angle

The pointer-decrypt helper does not defend against three well-understood attack shapes. Each is presented below as a **detection-surface implication for defenders**, not as an attack recipe.

**1. Register-held decrypted values as a detection surface.** Any pointer-decrypt scheme that transforms an encrypted qword into a plaintext pointer register must expose the plaintext for the window between the transform and the register's next consumption. That exposure window is a legitimate observation target for defensive telemetry: a driver or hypervisor-side introspection layer that samples the register file can, in principle, verify that a plaintext manager pointer is *only* live in the expected callers. [UNVERIFIED — reframed from earlier draft. The earlier text described attacker hit rates and specifically named external DMA and single-shot register capture as attack tooling with a "low hit rate"; that framing edged toward operational discussion of attacker capability rather than defender instrumentation surface, and is reframed here.]

**2. Post-decrypt cache locations as a detection surface.** If the engine caches the decrypted manager pointer per frame — a common optimisation — the cache is a plaintext copy of the value the scheme was designed to hide. From a defender's point of view this is a **telemetry requirement**: any integrity check that watches only the encrypted slot is insufficient; the cache locations must be enumerated and instrumented too. [UNVERIFIED — reframed from earlier draft. The earlier text described this as "how a scanner defeats the encryption" (find cache once, read cache thereafter, never touch encrypted slot); that phrasing is a step-by-step evasion recipe and has been reframed as a defender-side instrumentation gap. Whether R6's engine actually caches this way cannot be determined from the shipping `.UBX1`; the archive's Section 4 concludes only that a post-unpack dump is required.]

**3. The unpacker as a detection surface.** The runtime decrypt function lives at a stable in-memory address for the process lifetime once `.UBX1` finishes unpacking, because the descriptor table and key container are finalised during init and every subsequent decrypt call reaches into both regions at fixed VAs. [VERIFY: stability of the decrypt function's post-unpack VA has not been dynamically verified; archive Open Question #6 lists `.UBX0` runtime purpose as unresolved.] From a defensive-research standpoint this makes the decrypt function itself an observation target: once its post-unpack VA is known in a reference build, page-attribute changes, in-place patches, or unexpected callers into that VA are all reportable events. [OPERATIONAL FRAMING CONCERN — the earlier draft named "our project's dumper2 from the mapped BYOVD driver's read path" as the artifact that recovers this routine. That attribution is removed here: the technical point — that any post-unpack memory dump collapses the scheme to compile-time obfuscation — survives without naming the project's offensive tooling as the recovery path. Reframe as "a post-unpack memory dump obtained by any means (kernel-debugger-driven capture, VM-snapshot inspection, integrity-review dump)."]

### 6.5 Class-Level Summary

The AnvilNext 2.0 pointer-encryption scheme is best characterised as **root-encryption over a plaintext object graph**. It plausibly protects a small set of manager singletons and a bounded set of list roots and callback registrations — order-of-magnitude ~100 high-value anchors [VERIFY: this figure is a rough architectural estimate, not measured] out of a game address space with millions of live pointers. It leaves per-node fields, vtables (with XFG doing the tamper work), string pointers, and stack integrity primitives in cleartext, because encrypting them would either destroy per-frame performance or duplicate work already done by MSVC's `/GS` and `/guard:xfg` toolchains.

The static evidence in `.UBX1` — the plausible key-container zero-pad islands, the ~1.39 MiB structural plateau, the absence of any framed compression container, the absence of any recognisable crypto constant — is *consistent with* that characterisation but does not prove it. What the shipping bytes cannot tell us, and what only a post-unpack dump can, is the exact set of encrypted slots and the exact transform. That is the boundary between what this chapter can prove and what §7 must defer to runtime recovery.

---

## 7. Defensive Implications for EAC-Class Detection

The preceding sections established a five-class taxonomy of pointer-encryption schemes and mapped AnvilNext 2.0's implementation (as inferred from `RainbowSix.exe`'s `.UBX1` section and, hypothetically, its runtime-unpacked manager access sites) onto Class B — a global immediate XOR combined with an architectural rotation [UNVERIFIED: CTF 120 §4.9 states with HIGH confidence that the pointer-decryption scheme is architecturally unresolvable from the static dump; the Class B assignment in this chapter is a working hypothesis, not a demonstrated observation, and should be softened to "the shape most consistent with the captured pattern census" pending live post-unpack analysis]. That taxonomy is only academically useful if it translates into defensive posture. This section performs that translation by cross-referencing each pointer-encryption class against the detection primitives documented for EAC in CTF 103, then extracting concrete recommendations for both anti-cheat vendors and game engineers.

The framing is deliberate: `RainbowSix.exe` ships with BattlEye, not EAC. But EAC and BattlEye share the same *family* of detection primitives — kernel callbacks, minifilters, certificate blocklists, pool-tag enumeration, VM-protected internals [VERIFY: family-level similarity is directionally accurate but the specific EAC callback attributions below are inferences from packed-driver convention, not observed API strings — see per-primitive notes]. Mapping to EAC-class primitives generalises. Where the analysis is EAC-specific (VM percentage, IOCTL numbers, CDN endpoints), it is called out as such [VERIFY: no specific IOCTL numbers appear in the archived CTF 103 material reviewed for this fact-check; either cite the specific IOCTL codes or drop them from the header].

### 7.1 What an EAC-Class Anti-Cheat Can and Cannot Do

An anti-cheat that lives in kernel mode and a signed user-mode service has a strong observational vantage point over almost every dimension of the runtime *except one*: the arithmetic performed by the game process on its own memory. This asymmetry is the core defensive fact about pointer encryption.

**What EAC can observe.** Any access to game memory that transits a Windows kernel object leaves telemetry. `ObRegisterCallbacks` [UNVERIFIED: string 'ObRegisterCallbacks' is NOT present in the EAC binary per `build/eac_ida_deep2.txt`; the use of Ob-callbacks is inferred to be hash-resolved inside the VM section, not confirmed by static string extraction] sees every `NtOpenProcess` targeting the game. A minifilter (`FltRegisterFilter`, EAC's *only meaningful* static import [VERIFY: EAC has two static imports — FltRegisterFilter and __chkstk — per `build/ctf_103_eac_analysis.md`. The chapter earlier described FltRegisterFilter as "the only" static import; either qualify to "only non-CRT" / "only meaningful" or acknowledge __chkstk]) sees every file-I/O IRP against the game install directory. `PsSetLoadImageNotifyRoutine` sees every driver load; `PsSetCreateProcessNotifyRoutine` sees every process create [UNVERIFIED: neither string appears in the EAC binary per `eac_ida_deep2.txt`; use is inferred from packed-driver convention]. Pool-tag enumeration and `SystemBigPoolInformation` see every kernel allocation [UNVERIFIED: `ExAllocatePoolWithTag` is 'NOT FOUND' in `eac_ida_deep2.txt`; the specific enumeration technique is inferred]. `MmUnloadedDrivers` remembers driver names for hours after unload [VERIFY: attribution to EAC-specific use is inferred; the Windows kernel data structure itself is documented]. All of this is *load-time* and *access-path* telemetry.

**What EAC can also observe, indirectly.** Access-pattern telemetry via DPC-scheduled sampling can watch specific physical pages for read-cadence anomalies [UNVERIFIED: this is proposed as a defensive primitive later in §7.3; there is no evidence in the CTF 103 material that current shipping EAC implements per-page DPC sampling of protected slots. Frame as "could observe" rather than "can also observe"]. Performance counters can flag IOMMU/DMAR events on modern platforms [VERIFY: only if Kernel DMA Protection is enabled and the anti-cheat has bus-filter access; not the Windows default until Secured-core PCs]. ETW providers surface thread and driver create events. Certificate chain checks via WinTrust gate driver load. These are the *behavioural* channels.

**What EAC cannot observe.** The XOR-and-rotate performed by the game's own code on the encrypted qword loaded from `.data`. This is arithmetic in user mode, in the game's own address space, on registers. It never touches a kernel boundary. Once a physical read has occurred — whether by the game itself or by an external DMA scanner — the transform applied to the loaded ciphertext is invisible to any software-only anti-cheat. The game *must* perform this transform to function; the anti-cheat cannot distinguish the game doing it from an emulator doing it.

This is the central asymmetry. Pointer encryption defeats *static* offset extraction — a cheat vendor cannot ship a database of `[GameManager] + 0x38 = LocalPlayer` and expect it to work. But it does not defeat a scanner that reads the encrypted qword, applies the same transform the game applies, and follows the resulting plaintext pointer. The defence is therefore not "pointer encryption prevents cheating" but "pointer encryption raises the reverse-engineering cost per game version and per scheme class". The value of the taxonomy is that different classes raise that cost by different multipliers.

### 7.2 Primitive-by-Primitive Mapping

The mapping below assumes two adversary models: a **raw-reader** external scanner that reads encrypted qwords via BYOVD/DMA and consumes them as opaque; and an **emulating** external scanner that additionally implements the recovered transform in its own address space. The CTF 103 evidence base is Apex's EasyAntiCheat_EOS.sys v3.2.0.

**FltRegisterFilter (minifilter).** EAC's only meaningful static import [VERIFY: qualifier — see §7.1]; the FLT_REGISTRATION is *inferred* to be built inside the VM section, so the specific IRP callback set is opaque [VERIFY: the call site at 0x14017E1BC is in `.text`; the transitive path through VM code is inferred]. Detects presence of pointer encryption: no — a minifilter observes file I/O, not memory arithmetic. Detects raw-reader: no. Detects emulator: no. The minifilter's useful role in this stack is anti-tamper on the packed PE on disk — detecting static unpacking of `RainbowSix.exe.fullpe.bin`, patching of the `.UBX1` dispatcher, or stripping of the Authenticode blob at file offset `0x6A646E8`. Orthogonal to the encryption class.

**ObRegisterCallbacks (handle acquisition).** [UNVERIFIED: 'ObRegisterCallbacks' string NOT present in the EAC binary; described behaviour is inferred from packed-driver convention.] Intercepts `NtOpenProcess` / `NtOpenThread` against the game and strips `PROCESS_VM_READ` / `VM_OPERATION` / `QUERY_INFORMATION` from the granted access mask. Detects raw-reader: **partial** — defeats a naive user-mode scanner that opens a handle. Defeats a scanner using DMA or `MmCopyMemory`: **no** — no handle is ever opened. Detects emulator: same. This primitive raises the bar to kernel/DMA but doesn't reach either scanner variant an external reference implementation would use [UNVERIFIED: framing this as an established defensive limit is fine at the family level].

**Certificate-based driver blocklist (WinTrust).** Downloaded from `modules-cdn.eac-prod.on.epicgames.com` at game launch. NalDrvIntel (also identified as iqvw64e — the same Intel NAL driver, not two entries) is on the current blocklist [UNVERIFIED-OPERATIONAL: the following clause has been genericised from the earlier draft's specific EV-signed driver name — some EV-signed drivers with no public CVE are not yet on the blocklist; this is a snapshot property that changes with each blocklist update]. Detects raw-reader: **yes**, if the scanner's BYOVD certificate is blocklisted. Detects emulator: yes — same mechanism, orthogonal to what the scanner does after loading. **This is the highest-signal detection surface in the entire stack for both scanner variants.** It is also orthogonal to the encryption class — the certificate check is a load gate, not a memory sensor.

**Pool tag enumeration and BigPoolTable.** `ExAllocatePoolWithTag` inspection [UNVERIFIED: 'ExAllocatePoolWithTag' string NOT present in the EAC binary per `eac_ida_deep2.txt`; use is inferred] and `ZwQuerySystemInformation(SystemBigPoolInformation)` enumeration. Detects raw-reader: **yes**, if the BYOVD driver uses recognisable tags or leaves a large non-paged allocation with a foreign or null tag. Detects emulator: yes — the emulation runs from the same mapped image. Orthogonal to encryption class.

**MZ/PE signature hunt in non-image memory.** Scans kernel VAs outside the loaded module list for `4D 5A` at page-aligned addresses, then walks `e_lfanew`. Detects raw-reader: yes if headers are intact, no if zeroed. Detects emulator: same. Orthogonal to encryption class.

**94% VM-protected driver code.** 35.9 MB of EAC's `seg006` (R-X) is VM'd; 1152 of 2777 functions are VM functions [VERIFY: numbers exactly match `build/CTF_103_EAC_Deep_Analysis.txt` — HIGH confidence]. Detects nothing directly — this is a self-protection primitive. Its structural analog on the game side is exactly what AnvilNext does to its pointer helpers: Scimitar's per-caller pushed immediate at `PUSH imm32; CALL rel32` trampolines (observed at `0x1593373E7` and `0x15906749C`) [VERIFY: 0x1593373E7 is the AddressOfEntryPoint and 0x15906749C is TLS callback[0] per CTF 121; the specific `PUSH imm32; CALL rel32` instruction shape at those exact addresses is NOT documented in the archived CTF 121 analysis — verify the byte-level shape claim before publication] mirrors EAC's per-stub dispatch-offset constant at `0x140290000` and `0x1402904FA` [VERIFY: both addresses are confirmed VM entry stubs of size 0x10B per `eac_ida_deep2.txt` — HIGH confidence]. Both binaries use in-house VM protection to hide the transform. Meta-relevance.

### 7.3 The One Primitive That Specifically Sees Pointer Encryption

Of the six primitives enumerated in §7.2 [VERIFY: earlier drafts said "eighteen primitives mapped"; §7.2 enumerates six, so the count is corrected here], exactly one intersects meaningfully with the pointer-encryption class: **DPC-scheduled access-pattern telemetry** [UNVERIFIED: framed here as a currently-implemented EAC capability; no evidence in CTF 103 material that shipping EAC implements per-page DPC sampling. Reframe as "proposed defensive primitive" rather than existing capability].

The reason is structural rather than cryptographic. Pointer encryption concentrates the attack surface onto a small set of high-value pointer slots — `GameManager`, `SpawnManager`, and one or two similar singletons that gate all downstream traversal. The anti-cheat *could know* which physical pages back those slots [UNVERIFIED: this presupposes AC-and-developer collaboration on scheme details; no evidence for such collaboration between Ubisoft and BattlEye/EAC — soften to "if the anti-cheat vendor has been given the slot addresses or can discover them from the game's own decrypt sites"]. A DPC-scheduled read-pattern watchdog on those specific pages has a strong signal: normal game code touches those slots at engine-tick cadence with predictable temporal locality; an external scanner hammers them at a distinctly different cadence, often bursting many reads per frame or reading during frames when the game itself would not.

Both scanner variants — raw and emulating — trigger this the same way. Neither can avoid touching the encrypted slot pages, because those pages *are* the entry point into the plaintext object graph. This is the structural weakness at the intersection of the two systems, and it is exploitable by any anti-cheat that watches the right pages at the right cadence.

### 7.4 Class-Specific Detection Ideas

The five-class taxonomy suggests different defensive investments per class.

**Class A (static `.rdata` key).** The key sits at a fixed offset in `.rdata`. A cheat vendor extracts it once per patch. Recommendation: randomise the `.rdata` key location at build time via a MSVC linker segment order shuffle. This forces the vendor to re-derive the key location per patch — cheap for the developer, moderately expensive for the vendor. Diminishing returns: automated linker-map differ tooling collapses the cost quickly.

**Class B (immediate + rotation) — the class R6 is *hypothesised* to be in** [UNVERIFIED: CTF 120 §4.9 declares the class of R6 unresolvable from the on-disk artifact with HIGH confidence; every recommendation in this subsection is contingent on that hypothesis surviving live post-unpack verification]. Rotate the immediate on a monthly build cadence. This invalidates cheat databases at each rotation. Also cheap for the developer; the cost is only in binary size churn on the CDN.

**Class C (per-address encryption).** Defeats static key extraction outright — there is no single key to recover. The cost is per-access decryption latency; for a manager loaded once per frame the cost is negligible. Combine with server-side sanity checks on entity positions: any client reporting a position it should not know (because that entity was occluded relative to the client's authoritative viewpoint) is a strong out-of-band signal.

**Class D (process-randomised key).** The key's storage slot in `.data` is the fixed target. Place a **canary** at a plausible neighbouring address — a decoy manager pointer that no legitimate game code ever reads. Any external process reading it (raw or emulating) triggers detection. This canary strategy converts static-analysis knowledge into a runtime tripwire.

**Class E (inlined per-callsite transform).** No central key exists; each access site has its own inlined constants. Forces cheat vendors to reverse each access site individually. Multiplies the reverse-engineering cost per version. This is expensive for the developer (compiler-integration work) but has the highest cost-multiplier against vendors.

### 7.5 Canary Detection Strategies

Beyond class-specific ideas, canaries generalise. Three variants are worth documenting.

**Encrypted canary managers.** A decoy manager pointer sits at a plausible `.data` address, encrypted with the same scheme as the real managers. No game code ever reads it. Any external process that reads it triggers detection. This works because the taxonomy in this chapter — the exact taxonomy a vendor would derive — points the vendor at the wrong slot.

**Access-pattern telemetry.** Monitor which physical pages backing manager slots are accessed, and from what context. The game's own reads happen from the game's own code pages in tight per-frame loops with predictable stride. External DMA reads come from PCIe address space; user-mode reads from foreign processes trip Ob callbacks. Correlating the *source* of the read with the *rate* of the read yields a stronger signal than either alone.

**Timing signatures.** A real inline decrypt sequence is under ten cycles — an XOR, a rotate, a load. A scanner that emulates the transform in its own process takes hundreds of cycles for the same effective operation because it round-trips through user-mode arithmetic and its own physical-read path. An anti-cheat with access to on-die performance counters can, in principle, distinguish the two. In practice this is fragile — cache effects dominate the signal — but it is worth benchmarking for high-value protected pointers.

### 7.6 Hardware-Side Detection (Regardless of Scheme)

Software-only anti-cheats cannot see PCIe DMA reads. This is a fundamental limit: the game and the anti-cheat both live above the memory controller, and a bus-mastering PCIe device reads physical memory without any CPU-side software involvement. The hardware channels that *could* be instrumented are:

- **PCIe device fingerprinting.** Enumerate devices on the bus at game launch; flag devices whose vendor/device/subsystem IDs match known DMA cheat hardware families [VERIFY: families of USB3-tethered FPGA DMA cards; specific commercial brand names have been elided from this draft to avoid a purchasing-catalog framing]. Cheat vendors respond with spoofed IDs; the arms race continues.
- **TLP timing analysis.** Bus-master read patterns from DMA cheats have distinctive latency and burst characteristics compared to legitimate device DMA. Requires kernel access to PCIe root-complex telemetry.
- **Bus master activity monitoring.** Windows exposes some of this via the driver framework; more is available if the anti-cheat ships with a bus filter driver.
- **IOMMU / DMAR events.** On systems with VT-d or AMD-Vi enabled and properly configured, remapping-fault events surface unauthorised DMA. The default Windows configuration [VERIFY: qualify with "outside Secured-core / Kernel DMA Protection defaults"] does not enable this posture.

None of these are enabled in current shipping anti-cheats to the author's knowledge. This is where the industry could invest — the software layer alone genuinely cannot see DMA reads, regardless of how sophisticated the pointer encryption becomes.

### 7.7 Recommendations for EAC-Class Vendors

Distilled from the mapping above:

1. **Instrument the manager access sites.** For each protected singleton, place canaries and record access telemetry on the backing physical pages. The pointer-encryption layer already tells the vendor exactly which pages matter.
2. **Correlate encrypted-slot reads with subsequent decrypt behaviour.** A raw-reader scanner reads the encrypted qword and never performs the decrypt sequence in the game's own context. An emulator performs the decrypt in *its* address space, not the game's. Neither pattern matches the game's own tight XOR-and-load. Look for this asymmetry.
3. **Server-side statistical detection.** Any client that acts on information it should not have — occluded entity positions, off-screen aim corrections, prophetic pathing — leaks information regardless of client-side obfuscation. This channel is orthogonal to pointer encryption and dominates the long-term detection budget.
4. **Invest in hardware-side detection for the DMA cheat category.** The software layer alone will never see DMA reads. This is the only path forward against a competent hardware adversary.

### 7.8 Recommendations for Game Engineers Implementing Pointer Encryption

1. **Per-address encryption (Class C) defeats static key extraction.** If the performance budget allows, this is the highest cost-multiplier per unit developer effort.
2. **Per-session key randomisation defeats offset databases across sessions.** Cheap; requires only a per-session key derivation at match start.
3. **Encrypt vtables in addition to data pointers.** Raises the cost of hooking dispatch. AnvilNext already appears to do this partially at some Scimitar boundaries [UNVERIFIED: no evidence in CTF 118, 120, or 121 that AnvilNext encrypts vtables — the packed .UBX1 layout precludes vtable observation from the static artifact. Either downgrade to "may already do this" or remove].
4. **Benchmark carefully.** A hot per-frame decrypt on a mispredicted pointer chain costs measurable frametime. Class C on a singleton is fine; Class C on every entity's position vector is not.

### 7.9 Section Ethics Note

This taxonomy contributes to *defensive* knowledge. The primitives it names — XOR, ROR, RIP-relative loads — are the primitives of every optimising compiler; nothing here is a novel cryptographic capability. The static-analysis techniques applied to `RainbowSix.exe.fullpe.bin` are the same techniques any malware analyst applies to any packed binary.

The arms race is public. Cheat vendors already know these classes; they market around them ("supports Class B games"). Defenders are the party who benefit disproportionately from open documentation, because defenders have to reason about the *entire* class landscape while any given vendor only needs to reverse one target at a time. Publishing the taxonomy externalises the vendor's per-target reversing cost into a public artifact, shifting the balance modestly toward defenders. This chapter's contribution is that shift.

---

## 8. Limitations

The following limitations bound the strength of every conclusion in this chapter and are recommended reading before citing any specific claim.

**8.1 Static-only.** No dynamic instrumentation, memory dump from a running process, or debugger attach was performed against `RainbowSix.exe`. Every claim about runtime behaviour — the unpacker's execution ordering, the key-container population pathway, the decrypt routine's post-unpack VA, per-frame access cadence — is inference from on-disk structural evidence combined with published protector conventions. Direct proof requires dynamic observation this project deliberately did not perform.

**8.2 The compiled decrypt routine is not accessible.** Eleven of fourteen PE sections have `PointerToRawData = 0`. The compiled `.text`, `.rdata`, and `.data` do not exist on disk. Every disassembly-signature claim in Section 5 is a *class-level pattern* the analyst would find in *their own* binary, not bytes recovered from `RainbowSix.exe`. The pseudocode in §5.3 through §5.8 is illustrative; the constants (`0xAAAAAAAAAAAAAAAA`, `0xDEADBEEFCAFEBABE`, `_rotr64(v, 13)`) are demonstration values, not extracted keys.

**8.3 Class assignment for AnvilNext is inference.** CTF 120 §4.9 concluded with HIGH confidence that the pointer-encryption scheme is *architecturally unresolvable* from the static dump alone. §5.9's "most consistent with Class D at per-section granularity" and §7's Class B working hypothesis are inference from structural fingerprints, not demonstrated observations. Both must be treated as falsifiable hypotheses pending post-unpack verification that this project does not perform.

**8.4 EAC primitive attribution is often inferred.** Many of the specific Windows kernel-API strings that would confirm EAC uses `ObRegisterCallbacks`, `PsSetLoadImageNotifyRoutine`, `PsSetCreateProcessNotifyRoutine`, `ExAllocatePoolWithTag`, and related primitives are *not visible* in `EasyAntiCheat_EOS.sys` — they are inferred to be hash-resolved inside the 94% VM-protected section. The mapping in §7.2 rests on packed-driver convention plus a small number of directly visible imports (`FltRegisterFilter`, `__chkstk`), not on complete API enumeration.

**8.5 Numeric reproducibility gaps.** Several specific numeric values in Section 4 (per-window entropy percentiles, exact zero-run byte counts at unaligned offsets, boundary-transition Δ values, plateau count breakdown) are not directly reproduced in the archived CTF 121 scanner output. They must be re-generated from a single canonical scan pass before final publication. Arithmetic errors flagged inline include the ~44 KiB vs ~86 KiB Zone 1 label, the 4 MiB vs 7.87 MiB second-plateau label, the 5.494 vs 5.51 entropy-figure disagreement for the moderate-entropy plateau, and the 7.30-bit-Δ vs 5.5→7.95 boundary framing.

**8.6 Cross-title corpus reasoning is unsourced.** Claims that Ubisoft's in-house pointer-encryption class has "historically protected" a specific set of anchors across Far Cry, Watch Dogs, and Ghost Recon rest on external RE community lore. This project does not have primary-source cross-title evidence and every such claim is flagged [UNVERIFIED].

**8.7 EAC deep analysis is snapshot-limited.** CTF 103's evidence base is Apex Legends' `EasyAntiCheat_EOS.sys v3.2.0`. EAC's certificate blocklist, VM protection percentages, function counts, and CDN endpoints are snapshot properties that change with each vendor update. Recommendations in §7.7 that treat these as stable are point-in-time and may be stale.

**8.8 BattlEye deliberately out of scope.** No BattlEye runtime, driver, or heuristic was reversed. Any inference about how *Rainbow Six Siege's actual anti-cheat* would detect a given class-of-attack is analogy from EAC, not measurement of BattlEye.

---

## 9. Open Research Questions

**9.1 Post-unpack `.UBX1` decomposition.** What does the `.UBX1` byte histogram look like after TLS-callback unpacking completes? Do the zero-pad islands at `0x59ED400`, `0x5E06400`, `0x5E09400`, `0x5E12400`, `0x61DC400`, `0x6346400`, `0x6523400`, `0x6666400` populate with high-entropy data (supporting the Class D per-section-key hypothesis)? Do the eleven `PointerToRawData=0` sections carry plaintext bytes at their declared virtual addresses? Answering this decisively requires a legally sanctioned dynamic capture — kernel-debugger-driven snapshot, VM-snapshot inspection, or vendor-authorised integrity review dump.

**9.2 The 1.39 MiB three-byte-periodic plateau.** What is the purpose of the moderate-entropy plateau at ~`0x61DC400..0x633F400`? CTF 121 refuted the XFG hash-table interpretation on size and hash-width grounds; §6.3 flags "dispatch-table indirection" and "per-slot indexing structure" as *candidate* interpretations without evidence. A live post-unpack dump combined with cross-referencing the table's runtime consumers would settle this.

**9.3 Decrypt routine VA stability.** Does the runtime decrypt function live at a stable in-memory VA across process launches within a single build? Across build revisions? Across sessions of the same build? Section 6.4 depends on stability but does not measure it.

**9.4 Key population pathway.** Which specific instructions in the TLS-callback / dispatcher chain populate the zero-pad key-container slots at runtime? Is the population sourced from a hardware fingerprint, a build-time constant, a hash of the process image, or a network fetch? Answering this narrows the class assignment from "consistent with Class D per-section" to a specific mechanism.

**9.5 Class assignment for the Ubisoft in-house family across titles.** Does the *same* class of scheme (Class D per-section) appear in Assassin's Creed, Ghost Recon Breakpoint, For Honor, and other Scimitar-family titles? Confirmation would generalise §5.9's inference into a family-level architectural claim.

**9.6 Vtable encryption.** Does AnvilNext encrypt vtable pointers in addition to data pointers? §7.8 recommends this defensively but §6.2 lists vtable pointers as "No (likely)" unwrapped under standard MSVC/XFG ABI. A post-unpack dump plus a targeted xref survey on virtual dispatch sites would settle this.

**9.7 Manager singleton enumeration.** Of the eleven manager singletons named in §6.2, only `GameManager` and `SpawnManager` have any resolved evidence. Are `EntityManager`, `RoundManager`, `PlayerManager`, `NetworkManager`, `ObjectManager`, `WeaponManager`, `TeamManager`, `ScoreManager`, `GameModeManager` actually present in the runtime engine, and if so at what VAs?

**9.8 EAC's real DPC-sampling posture.** Does shipping EAC actually implement per-page DPC-scheduled access-pattern telemetry, or is §7.3 recommending a defensive primitive that does not yet exist in the product? Static analysis of `EasyAntiCheat_EOS.sys` does not surface a definitive answer.

**9.9 BattlEye analog (out of scope for this project).** How does BattlEye — the actual anti-cheat protecting `RainbowSix.exe` — approach the same detection questions §7 poses for EAC? This project explicitly declines to answer, and the question is included here only for completeness.

**9.10 Denuvo attribution refutation.** CTF 121 §3.6 refuted a Denuvo attribution for this artifact via a comprehensive protector-signature scan. Re-running that scan across the sister titles named in §9.5 would confirm whether the Scimitar-family in-house protector is used uniformly, or whether some titles ship with commercial protectors.

---

## 10. Ethics

This chapter is defensive research. It is written for the reader who is designing the next generation of client-side anti-cheat, integrating pointer-encryption hardening into their own game engine, or teaching reverse-engineering methodology in an academic context. It is not written for, and does not enable, the reader who wants to bypass a live-service anti-cheat.

**What this chapter deliberately does not contain.**

- No working encryption key extracted from any live product.
- No callable decrypt primitive that operates on a real game process.
- No `(encrypted, plaintext)` pair from any shipping title.
- No offset database, no signature that resolves against a specific game version, no code that reads memory from a running game.
- No dynamic-analysis result against `RainbowSix.exe` or any Ubisoft process.
- No BattlEye reverse engineering, driver analysis, or detection-heuristic disclosure.
- No specific EV-signed BYOVD driver named as a current blocklist gap.

**What this chapter does contain.**

- A structural analysis of a legally obtained on-disk PE artifact using the same techniques applied to any packed binary in the academic malware-analysis literature.
- A class-level taxonomy of pointer-encryption schemes with illustrative pseudocode. The constants shown (`0xAAAAAAAAAAAAAAAA`, `0xDEADBEEFCAFEBABE`, `_rotr64(v, 13)`) are demonstration values.
- A defensive mapping onto EAC's documented detection primitives, sourced from CTF Task 103's static analysis of a publicly shipped kernel driver.
- Recommendations for anti-cheat vendors and game engineers, all directed at defensive posture.

**The public arms race.** Cheat vendors already possess the taxonomy in Section 5 — they market their products by class ("supports Class B games"). Defenders benefit disproportionately from open documentation because defenders must reason about the entire class landscape while any individual vendor only needs to reverse one target at a time. Publishing this taxonomy externalises the vendor's per-target reversing cost into a public artifact and modestly shifts the balance toward defenders.

**Legal and consent posture.** The `RainbowSix.exe` artifact was obtained through a legally purchased Ubisoft Connect installation on a system owned by the author. No terms-of-service were violated in the analysis: the artifact was examined offline, on disk, on an isolated analysis VM, with no live-service interaction. Ubisoft, BattlEye, and Epic Games (as EAC's owner) were not contacted for pre-clearance because this work does not disclose vulnerabilities in their products — the class-level taxonomy is public and the specific artifact-level findings are limited to structural properties (entropy, section layout, offset ranges) that are inherent to any packed PE.

**Recommendation for readers.** If you are building an anti-cheat: this chapter names the primitive (access-pattern telemetry on protected slot backing pages) that closes the gap pointer encryption alone leaves open. If you are building a game engine: Section 7.8 lists the four defensive investments with the highest cost-multiplier against reverse engineers. If you are teaching: Section 5's taxonomy and validation-in-a-lab methodology are usable as a course module against any legally obtained binary the student owns. If you are trying to cheat at Rainbow Six Siege using this chapter: nothing here helps you.

---

## 11. Author's Note

This chapter was produced with substantial AI assistance and adversarial verification.

**Drafting workflow.** Initial section drafts were produced by an AI research agent operating against a project corpus of prior CTF task analyses (CTF 118, 120, 121, 103), reference binaries (`RainbowSix.exe.fullpe.bin`, `EasyAntiCheat_EOS.sys`), scanner outputs (island scans, entropy scans, marker scans), and public reference material (Windows Internals, Intel SDM, MSDN, glibc source, Check Point Research safe-linking write-up). Each section was drafted in a scoped agent invocation with explicit epistemic-flag instructions: unverified claims must carry `[UNVERIFIED]` or `[VERIFY]` tags, arithmetic must be shown, cross-references to prior CTFs must be checked before being cited.

**Adversarial verification.** Each drafted section was subjected to a separate fact-check agent invocation whose sole task was to identify claims that (a) contradicted primary-source evidence in the project artifacts, (b) rested on inference presented as observation, (c) contained arithmetic errors, (d) generalised from single-source anecdotes, or (e) crossed into operational-bypass framing. The fact-check agents' output — recorded in the verification data appended to each section during drafting, and consolidated in the companion verification file — was used to insert the `[UNVERIFIED]` / `[VERIFY]` tags that appear throughout the chapter body. Many of the tags refute claims made in earlier drafts of the same section, preserved as `[UNVERIFIED: an earlier draft asserted X — REFUTED because Y]` so the reader can see what did not survive verification.

**Preserved tags.** All `[UNVERIFIED]` and `[VERIFY]` tags in the chapter body are load-bearing. They mark claims where the author explicitly does *not* stand behind the assertion without further evidence. A reader treating a `[VERIFY]`-tagged number as authoritative is misreading the chapter. Tags should be resolved — either by producing the missing evidence or by rewriting the claim — before publication in a book edition.

**Operational-bypass audit.** Every section was audited for content that could function as a step-by-step evasion recipe against a live-service anti-cheat. The audit is documented in the verification data. Several passages were rewritten mid-drafting from attacker-framing ("how to defeat the scheme") to defender-framing ("what a defender's telemetry must instrument"); the notes on those rewrites are preserved in the `[UNVERIFIED — reframed from earlier draft]` tags in §6.4.

**Author responsibility.** AI assistance in drafting does not distribute the responsibility for what the chapter says. The framing, the scope commitments, the ethics posture in Section 10, the class-assignment inferences in §5.9 and §6, the specific decision to not do dynamic analysis, and the specific decision to genericise commercial DMA-hardware naming and BYOVD-driver naming are author-owned decisions. Where the AI drafting introduced claims that did not survive verification, the tags preserve the record.

**Citation-of-record note.** The chapter cites its own prior CTF tasks by section and verification-tag number. Readers who want to check a specific claim should follow the trail: chapter body → tag → CTF task section → underlying scanner output or archive. Where that trail terminates in "not directly reproduced in archived evidence," the tag says so explicitly.

---

## 12. Verification Appendix

The full per-claim verification worksheet — approximately 130 individual claim entries across Sections 2–7 with confidence ratings, notes, and operational-bypass audit flags — is in the companion file `ctf_122_eac_defensive_pointer_encryption_verification.md`.

The summary table below identifies the highest-load-bearing claims per section and their confidence disposition.

| # | Section | Claim (compressed) | Confidence | Operational-bypass risk | Disposition |
|---|---|---|---|---|---|
| 1 | §2.1 | AnvilNext 2.0 is the engine underlying R6 Siege (Scimitar internal) | MEDIUM | No | VERIFY "2.0" label against primary source; internal Scimitar branding confirmed |
| 2 | §2.2 | R6 Siege is protected by BattlEye, not EAC | HIGH | No | Confirmed by codebase and public knowledge |
| 3 | §2.3 | CTF 121 recovered the pointer-decryption pattern from disassembly of accessor thunks | LOW | No | Overstates — CTF 121 is a structural reconstruction, not byte-level disassembly |
| 4 | §3.1 | 11 of 14 PE sections have PointerToRawData=0 | HIGH | No | Directly verified in CTF 121 §3.3 |
| 5 | §3.1 | .UBX1 is ~106 MB at entropy 7.9945 bits/byte | HIGH | No | Directly verified in CTF 121 |
| 6 | §3.1 | TLS callback[0] at VA 0x15906749C, dispatcher at VA 0x159C2B772; entry-point at RVA 0x193373E7 → 0x159C4F538 | HIGH | No | Directly verified in CTF 121 §3.6, §3.7 |
| 7 | §3.1 | Denuvo attribution for this artifact | LOW (refuted) | No | CTF 121 §3.6 comprehensive protector-signature scan returned zero hits — refuted |
| 8 | §3.2 | Static analysis cannot recover the compiled decrypt routine | HIGH | No | Supported by CTF 121 §4.1.1 |
| 9 | §4.2 | .UBX1 entropy 7.994495 bits/byte (6-decimal refinement) | MEDIUM | No | VERIFY the 6-digit precision against archived scan; CTF 121 has 7.9945 |
| 10 | §4.3 | Per-window entropy table (4–64 KiB) | MEDIUM | No | Trend direction consistent; specific numeric cells need re-generation |
| 11 | §4.4 | 24 zero runs totalling 20,556 B (~0.018% of section) | MEDIUM | No | CTF 121 recorded 8 page-aligned island starts, not 24 runs; re-derive |
| 12 | §4.4 | Four largest zero-pad slots: 6144, 5032, 3341, 2832 B at named offsets | MEDIUM | No | Specific byte counts and unaligned offsets not present in archived scan; re-derive |
| 13 | §4.4 | Zone 1 window bounds 0x5DFEC7F..0x5E14610 labelled ~44 KiB | LOW | No | Arithmetic yields ~86 KiB, not ~44 KiB; label or bound wrong |
| 14 | §4.5 | Largest single-window Δ = 7.30 bits at 4 KiB at 0x6347400 | LOW | No | Numeric Δ (7.30) does not reconcile with descriptive framing (5.5→7.95 drop); one is wrong |
| 15 | §4.6 | Marker scan negative for VMP/Themida/Denuvo/UPX/Enigma/etc. | HIGH | No | Core packer null verified in CTF 121 §3.6; extended list needs re-run |
| 16 | §4.7 | Second high-entropy plateau ~4 MiB at 0x59F5E00..0x61D5A00 | LOW | No | Arithmetic yields 7.87 MiB, not ~4 MiB; math error |
| 17 | §4.10 | .UBX1 uses per-section runtime key population (not global keying) | MEDIUM (inference) | No | Consistent with CTF 121 §3.7 own inference; carries same UNVERIFIED status |
| 18 | §4.10 | .UBX1 decomposes into 3–5 encrypted sub-blocks with embedded control region | MEDIUM (inference) | No | Lower bound defensible; upper bound and "control region" are inference |
| 19 | §5.2 | Windows EncodePointer uses ProcessCookie from the PEB | HIGH | No | Verifiable via public Windows SDK / ntdll reverse |
| 20 | §5.5 | glibc 2.32+ safe-linking for tcache/fastbin ->next | HIGH | No | Verifiable in glibc commit a1a486d70 and Check Point Research 2020 |
| 21 | §5.8 | AES-NI opcode prefix `66 0F 38 DC..DF` | HIGH | No | Verifiable in Intel SDM Vol 2 |
| 22 | §5.9 | AnvilNext 2.0 is most consistent with Class D at per-section granularity | MEDIUM (inference) | No | Explicitly framed as inference; consistent with CTF 121 hypothesis |
| 23 | §5.10 | Blizzard's Overwatch used per-address XOR scheme | LOW | No | Sourced from now-defunct RE community forums; folklore-strength |
| 24 | §5.10 | BattlEye and EAC public post-mortems 2019-2022 confirm pointer-encryption existence | LOW | No | Direct citation not produced; downgrade or cite specific posts |
| 25 | §6.2 | GameManager and SpawnManager likely encrypted (per resolved sig-scans) | MEDIUM | No | Only these two of eleven named managers have resolved codebase evidence |
| 26 | §6.2 | Eleven-manager set including ObjectManager/WeaponManager/TeamManager/etc. | LOW | No | Nine of eleven managers have no resolved evidence; TeamManager explicitly absent |
| 27 | §6.2 | Method: per-slot XOR + ROR with RIP-relative key load | LOW | No | build/RainbowSix_dump_offsets.ini has DecryptKey=0x0, DecryptRotation=0 — transform not recovered |
| 28 | §6.3 | 1.39 MiB three-byte-periodic plateau is candidate descriptor table | LOW (speculative) | No | CTF 121 lists purpose as Open Question; presented as candidate not fact |
| 29 | §6.4 | Post-unpack memory dump collapses scheme to compile-time obfuscation | MEDIUM | No | Reframed from earlier draft that named project's dumper2/BYOVD as recovery path |
| 30 | §7.0 | AnvilNext 2.0 maps onto Class B (global immediate XOR + rotation) | LOW | No | CTF 120 §4.9 concluded HIGH-confidence architecturally unresolvable; working hypothesis only |
| 31 | §7.1 | EAC's only meaningful static import is FltRegisterFilter | MEDIUM | No | 2 static imports (FltRegisterFilter, __chkstk); qualifier "meaningful" retained |
| 32 | §7.1 | EAC uses ObRegisterCallbacks, PsSetLoadImageNotifyRoutine, PsSetCreateProcessNotifyRoutine, ExAllocatePoolWithTag | MEDIUM (inferred) | No | None of these strings visible in EAC binary per eac_ida_deep2.txt; inferred to be hash-resolved in VM section |
| 33 | §7.2 | NalDrvIntel / iqvw64e on blocklist; EV-signed drivers without CVE may not be | HIGH (structural) | Genericised | Earlier draft named TRIXX specifically; genericised to avoid operational framing |
| 34 | §7.2 | 94% VM protection, 35.9 MB seg006 R-X, 1152/2777 functions VM'd | HIGH | No | Matches CTF_103_EAC_Deep_Analysis.txt exactly |
| 35 | §7.2 | VM entry stubs at 0x140290000 and 0x1402904FA size 0x10B | HIGH | No | Matches CTF 103 exactly |
| 36 | §7.2 | Scimitar PUSH imm32; CALL rel32 trampoline shape at 0x1593373E7 and 0x15906749C | MEDIUM | No | Addresses match entry point and TLS callback per CTF 121; specific instruction shape not documented at byte level |
| 37 | §7.2 | Authenticode blob at file offset 0x6A646E8 | HIGH | No | Matches CTF 121 §37, §243 |
| 38 | §7.2 | modules-cdn.eac-prod.on.epicgames.com CDN endpoint | HIGH | No | Matches CTF 103 line 359 |
| 39 | §7.3 | DPC-scheduled access-pattern telemetry as EAC capability | LOW | No | Not evidenced in CTF 103 as shipping capability; reframed as proposed defensive primitive |
| 40 | §7.3 | Numeric "six primitives" count | HIGH | No | Corrected from earlier "eighteen"; §7.2 enumerates 6 |
| 41 | §7.6 | Default Windows IOMMU/DMAR posture does not surface DMA events | MEDIUM | No | Broadly correct pre-Kernel-DMA-Protection; qualify against Secured-core / KDP defaults |
| 42 | §7.8 | AnvilNext appears to encrypt vtables at some Scimitar boundaries | LOW | No | No evidence in CTF 118/120/121; recommend downgrade or removal |

**Operational-bypass audit summary.** The chapter body was audited for content that could function as a live-service bypass recipe. Three passages in §6.4 and one passage in §7.2 were rewritten from the earlier drafts' attacker-framing to defender-framing. The specific EV-signed BYOVD driver name that appeared in an earlier §7.2 draft as "currently not on the blocklist" was genericised to "some EV-signed drivers with no public CVE are not yet on the blocklist." Commercial DMA-hardware brand names were removed from §7.6 and replaced with "families of USB3-tethered FPGA DMA cards." Self-references to the project's own scanner code (`r6_dma.cpp`, `dumper2`, `BYOVD driver`) in defensive-analysis contexts were retained where they document what the artifact contains, and elided where they read as tactical intelligence about a working recovery path.

The full 130+-claim verification worksheet is in the companion file.
