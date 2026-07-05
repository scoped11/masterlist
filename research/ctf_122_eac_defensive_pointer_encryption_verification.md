# CTF Task 122 — Verification Worksheet

**Companion to:** `ctf_122_eac_defensive_pointer_encryption.md`

**Purpose:** Per-claim confidence rating, primary-source reconciliation, arithmetic checks, and operational-bypass audit for every load-bearing assertion in the main chapter. Roughly 130 individual claim entries across Sections 2–7.

**Confidence scale.**

- **HIGH** — Directly verified against primary evidence in the project artifacts (a byte-level scan output, a section-table dump, a code-embedded string) or against an external primary source (public glibc commit, Intel SDM, MSDN).
- **MEDIUM** — Reasonable inference from evidence; the direction and shape of the claim survive, but a specific numeric detail, byte-level shape, or attribution is not directly reproduced.
- **LOW** — Speculative, sourced from community lore, or in direct tension with archived primary evidence. Should not be cited without further work.

**Operational-bypass audit.** Each claim is separately flagged `operational_bypass_risk: true / false`. A `true` flag does not mean the chapter contains operational bypass content — it means the passage was flagged mid-drafting for review and, if reframed, the reframing is preserved in the tag disposition.

---

## Section 2 — Introduction and Scope

### 2.1 The Research Question

**Claim 2.1-1.** Rainbow Six Siege runs on Ubisoft's AnvilNext 2.0 engine (internally branded Scimitar).

- **Confidence:** MEDIUM
- **Note:** The internal Scimitar branding is well-supported in project artifacts (export DLL string `scimitar_engine_win64_2022_flto_dx12.exe` verified at file offset `0x59F625F` in CTF 121). The specific label "AnvilNext 2.0" is widely-used journalist shorthand — Ubisoft's own naming has been inconsistent (AnvilNext, Anvil, Scimitar). Confirm the "2.0" generation label against a citable primary source before publication.
- **Operational-bypass risk:** No

**Claim 2.1-2.** Pointers stored as ciphertext, transformed at load and re-transformed at store, exist as plaintext only inside a register for a load-use-store window.

- **Confidence:** MEDIUM
- **Note:** Standard structural description of the pattern class, matched by `r6_dma.cpp` header naming "XOR + bit rotation" for AnvilNext. No primary-source evidence in project artifacts confirms load/store symmetry (whether the store re-encrypts). VERIFY before publication or soften to "must be transformed at load time before dereference."
- **Operational-bypass risk:** No

**Claim 2.1-3.** During CTF 121, "every attempt to walk what should have been a straightforward object graph produced garbage."

- **Confidence:** LOW
- **Note:** This narrative overstates CTF 121, which was static-only against the on-disk PE. The verified finding is that 11 of 14 sections have zero raw bytes on disk (they are packed inside `.UBX1`), so the graph cannot be walked because bytes are missing, not because pointers are encrypted. The two observations should be separated.
- **Operational-bypass risk:** No

### 2.2 The Framing Pivot

**Claim 2.2-1.** Rainbow Six Siege is protected by BattlEye, not EasyAntiCheat.

- **Confidence:** HIGH
- **Note:** Confirmed by codebase presence of `be_freeze.cpp`, BEDaisy references, README documenting BattlEye ecosystem, and public knowledge.
- **Operational-bypass risk:** No

**Claim 2.2-2.** CTF Task 103 (archived) provides a deep static analysis of EAC's architecture covering kernel driver, user-mode module, scan classes, primitives, and address-space invariants.

- **Confidence:** MEDIUM
- **Note:** CTF 103 archived status is asserted but not directly inspectable in this pass. Taxonomy consistent with public EAC literature; VERIFY the CTF 103 archive contains all five listed areas before forward-referencing them.
- **Operational-bypass risk:** No

**Claim 2.2-3.** EAC protects Fortnite, Apex Legends, Rust, Squad, and dozens of other titles.

- **Confidence:** HIGH
- **Note:** Publicly documented across those title-vendor communications.
- **Operational-bypass risk:** No

**Claim 2.2-4.** Some EAC-protected titles "almost certainly" use pointer-encryption schemes of their own.

- **Confidence:** LOW
- **Note:** Not backed by primary source; soften to "may use analogous schemes" or cite specific EAC-protected titles for which the pattern is publicly attested.
- **Operational-bypass risk:** No

### 2.3 Relation to Prior Chapters

**Claim 2.3-1.** CTF 121 recovered "the pointer-decryption pattern from disassembly of the accessor thunks."

- **Confidence:** LOW
- **Note:** Overstates the CTF 121 finding. Per CTF 121 §4.0 and §4.8, the routine file offset is UNCONFIRMED, the raw bytes are UNCONFIRMED, and the pseudocode is a "structural reconstruction from constraints, not a translation from disassembly." Rewrite as "the pointer-decryption pattern inferred from structural constraints on the packed image."
- **Operational-bypass risk:** No

### 2.4 Scope and Non-Goals

**Claim 2.4-1.** Static disassembly of the shipped `RainbowSix.exe` binary is in scope.

- **Confidence:** MEDIUM
- **Note:** 11 of 14 sections have zero raw bytes on disk per CTF 121 §3.3. "Static disassembly" applies only to `.UBX1`, `.reloc`, `.rsrc`. Compiled `.text` cannot be disassembled statically. Restate as "static analysis at the PE-structural level, with pattern-class inference against the encrypted `.UBX1` blob."
- **Operational-bypass risk:** No

**Claim 2.4-2.** All algorithmic content is presented at the class level with symbolic constants (`K_ENGINE`, `S_OBJ`); no live keys shown.

- **Confidence:** HIGH
- **Note:** Convention only; scope commitment, not a technical assertion.
- **Operational-bypass risk:** No

---

## Section 3 — Prior Findings Recap and the Structural Wall

### 3.1 What CTF 118, 120, and 121 Established

**Claim 3.1-1.** The engine is Ubisoft's Scimitar / AnvilNext 2.0 branch, evidenced by the PDB path `scimitar_engine_win64_2022_flto_dx12.pdb` leaking from the debug directory.

- **Confidence:** MEDIUM
- **Note:** The export DLL-name string with `.exe` suffix is verified at file offset `0x59F625F`. The `.pdb` variant is asserted but flagged in CTF 118 verification worksheet 2.2-1 as "Only the exe module name is confirmed in archived text." The full `.pdb` path has not been directly hex-dumped from the debug directory.
- **Operational-bypass risk:** No

**Claim 3.1-2.** The lineage carries Assassin's Creed, Ghost Recon Breakpoint, and For Honor.

- **Confidence:** MEDIUM
- **Note:** CTF 118 verification tags 2.1-2, 2.1-3, 2.1-4 flag these as VERIFY-pending; require Ubisoft press or postmortem citation. Widely accepted in RE community; not confirmed by primary source in this project.
- **Operational-bypass risk:** No

**Claim 3.1-3.** BattlEye is the primary anticheat with kernel driver component.

- **Confidence:** HIGH
- **Note:** Widely documented for R6 Siege; not contradicted by any project evidence.
- **Operational-bypass risk:** No

**Claim 3.1-4.** EasyAntiCheat integrated as secondary layer, with `EasyAntiCheat_EOS.sys` present in shipped tree.

- **Confidence:** HIGH
- **Note:** File verified present in working tree; directly verifiable.
- **Operational-bypass risk:** No

**Claim 3.1-5.** Denuvo integrated into Scimitar 2022 build (as claimed in an earlier draft).

- **Confidence:** LOW (refuted)
- **Note:** CTF 121 §3.6 EXPLICITLY REFUTES: "File-wide byte-string scans for VMProtect, Themida, ..., Denuvo, ... all returned zero hits." The section under review conflicts with CTF 121's primary evidence. Rewritten in chapter body to identify the protector as Ubisoft's in-house UBX/Scimitar family.
- **Operational-bypass risk:** No

**Claim 3.1-6.** Middleware inventory: Umbra, Wwise, RED for input, Scaleform, Ubisoft Connect launcher.

- **Confidence:** LOW to HIGH per item
- **Note:** Wwise HIGH (662 exports include AK symbols). Umbra, Scaleform, RED-for-input: LOW to MEDIUM — CTF 118 verification tags 3.3-1, 3.9-1, 3.9-3 flag as VERIFY-pending.
- **Operational-bypass risk:** No

**Claim 3.1-7.** CTF 120 methodology forbids process attachment, memory read, debugger attach, no bypass of BattlEye's runtime measurements.

- **Confidence:** HIGH
- **Note:** Consistent with project memory and CTF 121 scope.
- **Operational-bypass risk:** No

**Claim 3.1-8.** Of fourteen sections declared, eleven have PointerToRawData = 0.

- **Confidence:** HIGH
- **Note:** Directly verified in CTF 121 §3.3 section table (sections .text, .rdata, .data, .pdata, .00cfg, .gxfg, .retplne, .tls, .voltbl, _RDATA, .UBX0 all have file offset 0x00000000).
- **Operational-bypass risk:** No

**Claim 3.1-9.** `.UBX1` occupies roughly 106 MB (raw size 0x06A07000).

- **Confidence:** HIGH
- **Note:** 0x06A07000 = 111,177,728 bytes = 106.03 MiB. Verified.
- **Operational-bypass risk:** No

**Claim 3.1-10.** `.UBX1` entropy = 7.9945 bits per byte.

- **Confidence:** HIGH
- **Note:** CTF 121 §3.3 records 7.9945.
- **Operational-bypass risk:** No

**Claim 3.1-11.** TLS callback[0] at VA 0x15906749C dispatches into VA 0x159C2B772.

- **Confidence:** HIGH
- **Note:** Verified in CTF 121 §3.7.
- **Operational-bypass risk:** No

**Claim 3.1-12.** MAIN ENTRY POINT trampoline at RVA 0x193373E7 dispatches into VA 0x159C4F538.

- **Confidence:** HIGH
- **Note:** Verified in CTF 121 §3.6. The dispatcher at 0x159C4F538 maps to file offset 0x65DF938 which is INSIDE `.UBX1`, not in loader residual code.
- **Operational-bypass risk:** No

**Claim 3.1-13.** Compiled decrypt routine not present on disk in analyzable form.

- **Confidence:** HIGH
- **Note:** Directly supported by CTF 121 §4.1.1.
- **Operational-bypass risk:** No

### 3.2 The Structural Wall

**Claim 3.2-1.** Static analysis cannot recover the compiled decrypt routine because the bytes only exist after runtime unpacking has succeeded.

- **Confidence:** HIGH
- **Note:** Central finding of CTF 121.
- **Operational-bypass risk:** No

**Claim 3.2-2.** Ubisoft protector "built specifically to guarantee" on-disk unreadability of decrypt routine.

- **Confidence:** MEDIUM
- **Note:** Attributes design intent that on-disk evidence alone does not establish. Softened in chapter body to "characteristic of a TLS-driven packer with encrypted sections working as designed."
- **Operational-bypass risk:** No

---

## Section 4 — Deeper .UBX1 Structural Analysis

### 4.2 Overall Entropy

**Claim 4.2-1.** Overall Shannon entropy of `.UBX1` = 7.994495 bits/byte (6-decimal refinement).

- **Confidence:** MEDIUM
- **Note:** CTF 121 measured 7.9945 to four decimal places. The six-decimal refinement must be reproducible against archived scan or source binary. Qualitatively HIGH; six-digit precision needs verification.
- **Operational-bypass risk:** No

### 4.3 Per-Window Entropy Distribution

**Claim 4.3-1.** Per-window entropy table (4/8/16/32/64 KiB) with specific min/median/max/std/count<7.9 cells.

- **Confidence:** MEDIUM
- **Note:** Trend direction consistent with CTF 121 findings (median rising, low-entropy window count halving, min floor rising to ~5.49 at 32K/64K). Specific numeric cells (0.1754, 7.9543, 1,779, etc.) not directly reproduced. Re-generate from source scan.
- **Operational-bypass risk:** No

**Claim 4.3-2.** "Below 7.9" window count approximately halves at each doubling.

- **Confidence:** MEDIUM
- **Note:** Ratios 2.14, 2.00, 2.00, 1.96 — not exactly 2. "Exactly what one expects" is slight overreach. Framing consistent with contiguous low-entropy islands.
- **Operational-bypass risk:** No

**Claim 4.3-3.** 64 KiB entropy floor of 5.49 corresponds to structural table in §4.4.

- **Confidence:** MEDIUM
- **Note:** CTF 121 reproduced ~5.51 at 0x61DBB80..0x633F000, consistent with 5.49 floor. Direction matches; exact figure needs canonical scan pass.
- **Operational-bypass risk:** No

### 4.4 Zero-Pad Regions

**Claim 4.4-1.** 24 zero runs ≥16 bytes, totalling 20,556 bytes (~0.018% of section).

- **Confidence:** MEDIUM
- **Note:** CTF 121 recorded 8 page-aligned island starts, not 24 raw runs (different thresholds/alignment). 20,556 / 0x6A07000 = 0.01849% (rounds to 0.019%, not 0.018%). Re-derive.
- **Operational-bypass risk:** No

**Claim 4.4-2.** Four largest zero-pad slots: 6,144 / 5,032 / 3,341 / 2,832 B at 0x5E127A0 / 0x5E09448 / 0x63466F4 / 0x5E06E08.

- **Confidence:** MEDIUM
- **Note:** Specific offsets and byte lengths not present in archived CTF 121 evidence base (which only recorded 8 page-aligned island starts). Consistent with pad starts inside those aligned buckets. Re-derive.
- **Operational-bypass risk:** No

**Claim 4.4-3.** Zone 1 clustering at 0x5DFEC7F..0x5E14610 labelled ~44 KiB.

- **Confidence:** LOW
- **Note:** 0x5E14610 − 0x5DFEC7F = 0x15991 = ~86 KiB, not ~44 KiB. Either bounds or label wrong.
- **Operational-bypass risk:** No

**Claim 4.4-4.** Zone 2 clustering at 0x63466F4..0x634634B.

- **Confidence:** LOW
- **Note:** Range is INVERTED (end < start); typo. Reconcile.
- **Operational-bypass risk:** No

**Claim 4.4-5.** Terminal 68 bytes at 0x6A073BC..0x6A07400 are zero.

- **Confidence:** HIGH
- **Note:** 0x6A07400 − 0x6A073BC = 68 exactly.
- **Operational-bypass risk:** No

**Claim 4.4-6.** Probability of 6 KB zero run in ciphertext ≈ 2^-49152.

- **Confidence:** HIGH
- **Note:** Arithmetic correct under byte-independence.
- **Operational-bypass risk:** No

### 4.5 Block Boundary Candidates

**Claim 4.5-1.** Largest single-window Δ = 7.30 bits at 4 KiB at file offset 0x6347400.

- **Confidence:** LOW
- **Note:** INTERNAL INCONSISTENCY. Section says drop "from ~5.5-bit plateau to full ~7.95 ciphertext." 7.95 − 5.5 = 2.45, not 7.30. A 7.30-bit Δ implies one window ~0.65 bits adjacent to ~7.95. Reconcile numeric with descriptive.
- **Operational-bypass risk:** No

**Claim 4.5-2.** Boundary offsets list with per-boundary deltas (0x5E00400 through 0x6A06FBC).

- **Confidence:** MEDIUM
- **Note:** Offsets plausible and structurally consistent with CTF 121 zones. Specific Δ values not in archived evidence.
- **Operational-bypass risk:** No

**Claim 4.5-3.** No recurring 16-byte prefixes at 0x1000/0x4000/0x10000 strides.

- **Confidence:** MEDIUM
- **Note:** Consistent with CTF 121 null results on RIP-relative and shape scans; specific aligned-prefix scan not archived.
- **Operational-bypass risk:** No

### 4.6 Marker Scan

**Claim 4.6-1.** Marker scan negative for VMProtect, Themida, Denuvo, UPX, Enigma, MPRESS, ASPack, PECompact, FSG, nspack, Petite, SVKP, yoda.

- **Confidence:** HIGH (core list) / MEDIUM (extended list)
- **Note:** CTF 121 §3.6 documented VMProtect/Themida/Enigma/Denuvo/ASPack/etc. null with same result. Extended list plausible; VERIFY the extras.
- **Operational-bypass risk:** No

**Claim 4.6-2.** Four "MEW" 3-byte hits, expected coincidental baseline ~6.3.

- **Confidence:** MEDIUM
- **Note:** Arithmetic 106×2^20/2^24 = 6.625, not 6.3.
- **Operational-bypass risk:** No

**Claim 4.6-3.** "scimitar_engine" at UBX1 offset 0x59F5E5F and "\pc\scimitar_eng..." at 0x6665F63.

- **Confidence:** MEDIUM
- **Note:** CTF 121 has 'scimitar_engine_win64_2022_flto_dx12.exe' at file offset 0x59F625F (differs by 0x400 = .UBX1 start). Verify whether offsets are UBX1-relative or file-relative. Path fragment at 0x6665F63 not present in archived evidence.
- **Operational-bypass risk:** No

**Claim 4.6-4.** No AES S-box, no LZMA properties byte, no zlib/gzip magic, no ChaCha, no Salsa constants.

- **Confidence:** MEDIUM
- **Note:** Specific scans not documented in archived CTF 121 evidence. Re-run to reproduce.
- **Operational-bypass risk:** No

### 4.7 Full-PE Entropy Profile

**Claim 4.7-1.** 217,915 windows downsampled to 501 buckets ≈ 222 KiB per bucket.

- **Confidence:** HIGH
- **Note:** (111,576,136 − 4096)/512 + 1 = 217,915 exactly.
- **Operational-bypass risk:** No

**Claim 4.7-2.** First plateau ~90 MiB at H=7.955 covering 0x400..0x59EA000.

- **Confidence:** MEDIUM
- **Note:** 0x59EA000 − 0x400 = 89.91 MiB — matches ~90 MiB. H=7.955 mean not directly reproduced.
- **Operational-bypass risk:** No

**Claim 4.7-3.** Second plateau ~4 MiB at H=7.951 covering 0x59F5E00..0x61D5A00.

- **Confidence:** LOW
- **Note:** MATH ERROR. 0x61D5A00 − 0x59F5E00 = 0x7DFC00 = 7.87 MiB, not ~4 MiB.
- **Operational-bypass risk:** No

**Claim 4.7-4.** Third plateau ~1.9 MiB at H=7.948 covering 0x6347400..0x6523600.

- **Confidence:** HIGH
- **Note:** 0x6523600 − 0x6347400 = 0x1DC200 = 1.86 MiB.
- **Operational-bypass risk:** No

**Claim 4.7-5.** Moderate-entropy plateau ~1.42 MiB at H≈5.49 covering 0x61DBC00..0x633F000.

- **Confidence:** MEDIUM
- **Note:** 0x163400 = 1.39 MiB (rounds to ~1.4, not 1.42). Consistent with CTF 121 structural-table island 0x61DC400..0x633F400 at 1.387 MiB.
- **Operational-bypass risk:** No

**Claim 4.7-6.** Authenticode blob at 0x6A64400..0x6A68400 with H=7.502.

- **Confidence:** HIGH
- **Note:** Consistent with CTF 121 Authenticode at 0x6A646E8, size 0x3D60.
- **Operational-bypass risk:** No

### 4.8 Plateau Count

**Claim 4.8-1.** 183 plateaus with 138 in [6.0, 7.5), 22 below 3, only 3 attributed to UBX plateaus.

- **Confidence:** LOW
- **Note:** 138+22 = 160, leaving 23 unaccounted. Disposition should be stated or count reconciled.
- **Operational-bypass risk:** No

**Claim 4.8-2.** Evidence-based lower bound of 3–5 internal UBX blocks.

- **Confidence:** MEDIUM
- **Note:** Lower bound of 3 defensible; upper bound of 5 is extrapolation.
- **Operational-bypass risk:** No

### 4.10 Interpretation

**Claim 4.10-1.** Zero-pad islands are direct on-disk evidence for CTF 121 "per-section runtime key population" hypothesis.

- **Confidence:** MEDIUM
- **Note:** CTF 121 flagged this as inference, not proven. Carry same UNVERIFIED status.
- **Operational-bypass risk:** No

**Claim 4.10-2.** Protector is custom — bespoke or heavily-customized fork.

- **Confidence:** HIGH
- **Note:** CTF 121 reached same conclusion (in-house Ubisoft Scimitar/UBX).
- **Operational-bypass risk:** No

**Claim 4.10-3.** `.UBX1` is a container of 3–5 independently-keyed sub-blocks with embedded control region.

- **Confidence:** MEDIUM (inference)
- **Note:** Consistent with CTF 121 open-question framing; upper bound and "control region" language is inference-level.
- **Operational-bypass risk:** No

**Claim 4.10-4.** 1.42 MiB moderate-entropy plateau at H≈5.49 is "either a lookup table encoded but not encrypted, or encrypted with a weaker transform."

- **Confidence:** LOW
- **Note:** Speculative. CTF 121 explicitly refuted XFG-table interpretation and left purpose unresolved. Flag as UNVERIFIED.
- **Operational-bypass risk:** No

---

## Section 5 — Pointer-Encryption Class Taxonomy

### 5.1–5.2 Framing and Axes

**Claim 5-1.** Six recognisable classes cover essentially every pointer-encryption scheme observed in shipped 64-bit Windows binaries.

- **Confidence:** MEDIUM
- **Note:** Strong universal claim; the taxonomy is well-known but coverage assertion needs survey citation. Six is section's own construct.
- **Operational-bypass risk:** No

**Claim 5-2.** Windows `EncodePointer` uses `ProcessCookie` from the PEB.

- **Confidence:** HIGH
- **Note:** Verifiable via public Windows SDK / reverse-engineered ntdll.
- **Operational-bypass risk:** No

### 5.3 Class A

**Claim 5.3-1.** Eight-byte signature `48 33 05 ?? ?? ?? ?? C3` is a candidate-enumeration pattern for Class A.

- **Confidence:** MEDIUM
- **Note:** Correct byte encoding of RIP-relative XOR + RET. Not a diagnostic proof — has legitimate non-encryption uses (CRC/hash tail, arithmetic finalizers). Soften to "strong candidate pattern."
- **Operational-bypass risk:** No

**Claim 5.3-2.** x64 user-mode VA range typically `0x0000000000000000..0x00007FFFFFFFFFFF`.

- **Confidence:** HIGH
- **Note:** Verifiable from Windows Internals / MSDN.
- **Operational-bypass risk:** No

### 5.4 Class B

**Claim 5.4-1.** Ghidra renders rotation as `_rotr64(v, 13)` or `(v >> 13) | (v << 51)` shift-OR-shift idiom.

- **Confidence:** HIGH
- **Note:** Standard decompiler behaviour; verifiable in any Ghidra >=10.x.
- **Operational-bypass risk:** No

**Claim 5.4-2.** Rotation amounts often small odd numbers (5, 7, 11, 13, 17).

- **Confidence:** LOW
- **Note:** Specific set is stylistic/anecdotal. "Chosen to avoid natural pointer-alignment patterns" is a plausible-sounding rationale but not sourced. Soften.
- **Operational-bypass risk:** No

### 5.5 Class C

**Claim 5.5-1.** glibc 2.32+ uses per-address encryption ("safe-linking") for tcache/fastbin ->next pointers.

- **Confidence:** HIGH
- **Note:** Verifiable in glibc commit `a1a486d70ebcc47a686ff5846875eacad0940e41` and Check Point Research 2020.
- **Operational-bypass risk:** No

**Claim 5.5-2.** Primary defence of safe-linking is against heap-corruption exploit primitives.

- **Confidence:** MEDIUM
- **Note:** Corrected from earlier draft's "forward secrecy against static analysis" framing; safe-linking's original motivation is documented as breaking malloc-corruption `->next` forge primitive.
- **Operational-bypass risk:** No

### 5.6 Class D

**Claim 5.6-1.** MSVC uses `EncodePointer` under `/GS` for certain function-pointer stores.

- **Confidence:** MEDIUM
- **Note:** MSVC's CRT does use `EncodePointer` for certain function pointers (`_onexit`, TLS, EH), but association with `/GS` is imprecise — `/GS` is stack-buffer overrun protection, `EncodePointer` is independent. Chapter body VERIFY tag flags this.
- **Operational-bypass risk:** No

### 5.7 Class E

**Claim 5.7-1.** `__forceinline` or macro can produce Class E (inlined at every site).

- **Confidence:** HIGH
- **Note:** Standard compiler behaviour.
- **Operational-bypass risk:** No

### 5.8 Class F

**Claim 5.8-1.** AES-NI opcode prefix is `66 0F 38 DC..DF`.

- **Confidence:** HIGH
- **Note:** Verifiable in Intel SDM Vol 2.
- **Operational-bypass risk:** No

**Claim 5.8-2.** ~30-40 cycles per full 10-round AES decrypt.

- **Confidence:** MEDIUM
- **Note:** In the right ballpark; single-block AESDEC chain typically 40-60 cycles on Skylake+. Slightly optimistic without pipelining.
- **Operational-bypass risk:** No

**Claim 5.8-3.** No AES-NI opcodes observed in sampled `.text` regions.

- **Confidence:** MEDIUM
- **Note:** Technically true but bounded — on-disk `.text` has SizeOfRawData=0, so zero bytes available to scan. Honest statement: "not visible in the on-disk artifact, and the on-disk artifact is missing `.text` entirely."
- **Operational-bypass risk:** No

### 5.9 Class Assignment for AnvilNext

**Claim 5.9-1.** Structural fingerprint most consistent with Class D at per-section granularity.

- **Confidence:** MEDIUM (inference)
- **Note:** Explicitly framed as inference; consistent with CTF 121 §3.7 hypothesis. Appropriate.
- **Operational-bypass risk:** No

**Claim 5.9-2.** Zero-pad islands are reserved slots the runtime populates with per-section keys.

- **Confidence:** MEDIUM (inference)
- **Note:** Consistent with CTF 121 own inference.
- **Operational-bypass risk:** No

### 5.10 Public References

**Claim 5.10-1.** Overwatch used per-address XOR scheme for singleton manager pointers.

- **Confidence:** LOW
- **Note:** Sourced from forum posts on now-defunct RE communities. Folklore-strength.
- **Operational-bypass risk:** No

**Claim 5.10-2.** PUBG used process-randomized XOR key populated at startup.

- **Confidence:** LOW
- **Note:** Community claims 2018-2019; no primary source.
- **Operational-bypass risk:** No

**Claim 5.10-3.** Denuvo uses AES-NI in cold paths.

- **Confidence:** LOW
- **Note:** Community teardowns.
- **Operational-bypass risk:** No

**Claim 5.10-4.** BattlEye and EAC public post-mortems 2019-2022 confirm pointer-encryption schemes.

- **Confidence:** LOW
- **Note:** Direct citation of BattlEye/EAC public communications on pointer encryption not produced. Downgrade or cite specific posts.
- **Operational-bypass risk:** No

---

## Section 6 — Protection Coverage

### 6.1 Framing

**Claim 6.1-1.** `.UBX1` overall entropy 7.9945 bits/byte across full 106 MB blob.

- **Confidence:** HIGH
- **Note:** Confirmed in CTF 121 archive.
- **Operational-bypass risk:** No

**Claim 6.1-2.** Scimitar/Wwise export-name pool near file offset 0x59F625F.

- **Confidence:** HIGH
- **Note:** DLL-name string verified at 0x59F625F.
- **Operational-bypass risk:** No

**Claim 6.1-3.** Head import-metadata block at 0x5F4C..0x1E1D6.

- **Confidence:** LOW
- **Note:** Neither offset appears in CTF 121 archive. Fabrication risk in an earlier draft; retained UNVERIFIED tag in chapter body.
- **Operational-bypass risk:** No

**Claim 6.1-4.** Tail IAT-fixup table with recurring `5D CD 19` RVA suffix.

- **Confidence:** LOW
- **Note:** Archive explicitly refutes "IAT fixup table at .UBX1 tail." PE IAT directory is 768 bytes at 0x6346400 per archive tags 34/63. Byte suffix not in any scan result.
- **Operational-bypass risk:** No

**Claim 6.1-5.** 1.42 MiB three-byte-periodic lookup table at ~0x61DC400..0x633F400.

- **Confidence:** MEDIUM
- **Note:** Archive islands_result.json places island at 0x61DC400..0x633F400 = 0x163000 = 1.387 MiB. Offset consistent; three-byte periodicity confirmed; purpose is Open Question #9 per archive.
- **Operational-bypass risk:** No

### 6.2 Coverage Table

**Claim 6.2-1.** GameManager and SpawnManager singletons likely encrypted.

- **Confidence:** MEDIUM
- **Note:** Only these two of eleven named managers have resolved codebase evidence per archive tags #51/#52/#53. SpawnManager sig-scan resolves to 0x11F20F60.
- **Operational-bypass risk:** No

**Claim 6.2-2.** EntityManager, RoundManager, PlayerManager, NetworkManager inferred as encrypted (string seeds only).

- **Confidence:** LOW
- **Note:** String seeds present in `tools/source/dumper2.cpp`; no resolved addresses.
- **Operational-bypass risk:** No

**Claim 6.2-3.** ObjectManager, WeaponManager, TeamManager, ScoreManager, GameModeManager — speculative, not in codebase.

- **Confidence:** LOW
- **Note:** TeamManager explicitly absent from all codebase evidence per archive.
- **Operational-bypass risk:** No

**Claim 6.2-4.** Method: per-slot XOR + ROR with RIP-relative key load.

- **Confidence:** LOW
- **Note:** `DecryptKey=0x0`, `DecryptRotation=0` in `build/RainbowSix_dump_offsets.ini` — transform NOT recovered. XOR+ROR is an envelope, not an inferred method.
- **Operational-bypass risk:** No

**Claim 6.2-5.** Entity container is a pointer array indexed base*8, not a linked list.

- **Confidence:** MEDIUM
- **Note:** Corrected from earlier draft's doubly-linked-list framing; refuted by `r6_dma.cpp`.
- **Operational-bypass risk:** No

**Claim 6.2-6.** Vtable pointers left plaintext (no encryption) under standard MSVC ABI; `.gxfg` present at VSize 0x42C0 for XFG.

- **Confidence:** MEDIUM
- **Note:** `.gxfg` present verified. Specific import `__guard_xfg_dispatch_icall_fptr` not directly enumerated on-disk.
- **Operational-bypass risk:** No

**Claim 6.2-7.** Callback / event handler pointers: variable / undetermined.

- **Confidence:** LOW
- **Note:** Earlier draft's "3-byte-periodic plateau is correct for dispatch-table indirection" refuted; presented as speculative interpretation among unresolved options.
- **Operational-bypass risk:** No

**Claim 6.2-8.** String pointers left plaintext; export-name pool at 0x59F625F is plaintext in `.UBX1`.

- **Confidence:** MEDIUM
- **Note:** Lower bound 0x59F625F verified; upper bound of pool not directly measured per archive tag #32.
- **Operational-bypass risk:** No

**Claim 6.2-9.** Stack integrity handled by MSVC `/GS` cookie primitive, orthogonal to this scheme.

- **Confidence:** MEDIUM
- **Note:** `.retplne` verified present; `__security_cookie` / `__security_check_cookie` call sites not enumerated on-disk.
- **Operational-bypass risk:** No

### 6.3 Structural Argument

**Claim 6.3-1.** Three-byte-periodic plateau has bulk to be a per-slot indexing structure with ~484,000 three-byte entries.

- **Confidence:** LOW (speculative)
- **Note:** Arithmetic 0x163000/3 ≈ 484,010 correct. Interpretation as "descriptor table" is Open Question #9 per archive. Presented as candidate.
- **Operational-bypass risk:** No

**Claim 6.3-2.** Recurring byte ribbons `0acf8acf0ad08ad00ad18ad10ad28ad2` and `0aaf8aaf0ab08ab00ab18ab10ab28ab2` at 0x4000 boundaries.

- **Confidence:** LOW
- **Note:** Specific hex ribbons not in archive; archive characterises pattern only as `8a XX 0a YY 8a YY 0a ZZ ...`. Re-derive.
- **Operational-bypass risk:** No

**Claim 6.3-3.** Zero-pad key-container hypothesis rests on page-aligned zero-heavy regions at eight named offsets.

- **Confidence:** MEDIUM
- **Note:** Eight offsets match archived island scanner. "Key-container" interpretation is inference from alignment and locality only per archive tag #62.
- **Operational-bypass risk:** No

**Claim 6.3-4.** Encrypting the anchor and leaving the graph plaintext maximises protected-surface-to-runtime-cost ratio.

- **Confidence:** MEDIUM
- **Note:** Architectural argument, not measurement. "Once per frame" cadence not measured.
- **Operational-bypass risk:** No

### 6.4 The Defender's Angle

**Claim 6.4-1.** Register-held decrypted values are a legitimate observation target for defensive telemetry.

- **Confidence:** MEDIUM
- **Note:** Reframed from earlier draft's attacker-hit-rate framing to defender-instrumentation-surface framing.
- **Operational-bypass risk:** True (borderline — flagged for editorial review; reframing preserved in tag)

**Claim 6.4-2.** Post-decrypt cache locations must be enumerated and instrumented (telemetry requirement).

- **Confidence:** MEDIUM
- **Note:** Reframed from earlier draft's "how a scanner defeats the encryption" step-by-step framing to defender-instrumentation-gap framing.
- **Operational-bypass risk:** True (borderline — reframing preserved in tag)

**Claim 6.4-3.** Decrypt function lives at stable in-memory VA after `.UBX1` unpacks.

- **Confidence:** MEDIUM
- **Note:** Stability not dynamically verified; archive Open Question #6.
- **Operational-bypass risk:** No

**Claim 6.4-4.** Post-unpack memory dump obtained by any means (kernel-debugger snapshot, VM-snapshot, integrity review) recovers the routine as ordinary x86-64.

- **Confidence:** MEDIUM
- **Note:** Reframed from earlier draft's "our project's dumper2 from the mapped BYOVD driver's read path" attribution. Technical point retained without naming project offensive tooling.
- **Operational-bypass risk:** True (borderline — reframing preserved)

### 6.5 Class-Level Summary

**Claim 6.5-1.** ~100 high-value anchors protected out of millions of live pointers.

- **Confidence:** MEDIUM
- **Note:** Order-of-magnitude estimate, unsourced.
- **Operational-bypass risk:** No

---

## Section 7 — Defensive Implications for EAC-Class Detection

### 7.0 Opening

**Claim 7.0-1.** AnvilNext 2.0's implementation maps onto Class B (global immediate XOR + rotation).

- **Confidence:** LOW
- **Note:** CTF 120 §4.9 states with HIGH confidence that scheme is architecturally unresolvable from static dump. Class B is working hypothesis, not demonstrated observation.
- **Operational-bypass risk:** No

**Claim 7.0-2.** EAC and BattlEye share the same family of detection primitives.

- **Confidence:** MEDIUM
- **Note:** Directionally accurate at family level; specific EAC callback attributions are inferences from packed-driver convention.
- **Operational-bypass risk:** No

### 7.1 EAC Observability

**Claim 7.1-1.** `ObRegisterCallbacks` sees every `NtOpenProcess` targeting the game.

- **Confidence:** MEDIUM (inferred)
- **Note:** String NOT present in EAC binary per `eac_ida_deep2.txt`. Inferred to be hash-resolved inside VM section.
- **Operational-bypass risk:** No

**Claim 7.1-2.** `FltRegisterFilter` is EAC's only meaningful static import.

- **Confidence:** MEDIUM
- **Note:** 2 static imports (FltRegisterFilter, __chkstk); "only meaningful" qualifier retained.
- **Operational-bypass risk:** No

**Claim 7.1-3.** `PsSetLoadImageNotifyRoutine`, `PsSetCreateProcessNotifyRoutine` see loads and process creates.

- **Confidence:** MEDIUM (inferred)
- **Note:** Neither string appears in EAC binary; inferred from packed-driver convention.
- **Operational-bypass risk:** No

**Claim 7.1-4.** Pool-tag enumeration and `SystemBigPoolInformation` see every kernel allocation.

- **Confidence:** MEDIUM (inferred)
- **Note:** `ExAllocatePoolWithTag` is "NOT FOUND" in `eac_ida_deep2.txt`. Inferred.
- **Operational-bypass risk:** No

**Claim 7.1-5.** `MmUnloadedDrivers` remembers driver names for hours after unload.

- **Confidence:** MEDIUM
- **Note:** Windows kernel data structure documented; EAC-specific use inferred.
- **Operational-bypass risk:** No

**Claim 7.1-6.** Access-pattern telemetry via DPC-scheduled sampling can watch specific physical pages for read-cadence anomalies.

- **Confidence:** LOW
- **Note:** Proposed defensive primitive; no evidence in CTF 103 that shipping EAC implements per-page DPC sampling.
- **Operational-bypass risk:** No

**Claim 7.1-7.** EAC cannot observe the game's own XOR-and-rotate arithmetic in user mode.

- **Confidence:** HIGH
- **Note:** Central defensive fact about pointer encryption; architectural.
- **Operational-bypass risk:** No

### 7.2 Primitive-by-Primitive Mapping

**Claim 7.2-1.** CTF 103 evidence base is Apex's `EasyAntiCheat_EOS.sys v3.2.0`.

- **Confidence:** HIGH
- **Note:** Matches `CTF_103_EAC_Deep_Analysis.txt` line 5.
- **Operational-bypass risk:** No

**Claim 7.2-2.** FltRegisterFilter call site at `0x14017E1BC`.

- **Confidence:** HIGH
- **Note:** Matches CTF 103 §5.1.
- **Operational-bypass risk:** No

**Claim 7.2-3.** ObRegisterCallbacks intercepts `NtOpenProcess/NtOpenThread` and strips `PROCESS_VM_READ / VM_OPERATION / QUERY_INFORMATION`.

- **Confidence:** MEDIUM (inferred)
- **Note:** Described behaviour inferred from packed-driver convention.
- **Operational-bypass risk:** No

**Claim 7.2-4.** Certificate-based driver blocklist downloaded from `modules-cdn.eac-prod.on.epicgames.com` at launch.

- **Confidence:** HIGH
- **Note:** Matches CTF 103 line 359.
- **Operational-bypass risk:** No

**Claim 7.2-5.** NalDrvIntel / iqvw64e (same driver) on current blocklist.

- **Confidence:** HIGH
- **Note:** Matches CTF 103 lines 52-53. Framing corrected to note iqvw64e IS NalDrvIntel, not two entries.
- **Operational-bypass risk:** No

**Claim 7.2-6.** Some EV-signed drivers with no public CVE are not yet on the blocklist.

- **Confidence:** MEDIUM
- **Note:** GENERICISED. Earlier draft named TRIXX specifically as "currently PASSES" — reframed to generic statement to avoid operational bypass framing. Snapshot property that changes with each blocklist update.
- **Operational-bypass risk:** True (reframed — specific driver name removed)

**Claim 7.2-7.** Pool tag enumeration and BigPoolTable.

- **Confidence:** MEDIUM (inferred)
- **Note:** `ExAllocatePoolWithTag` NOT FOUND in EAC binary.
- **Operational-bypass risk:** No

**Claim 7.2-8.** 94% VM-protected driver code; 35.9 MB seg006 R-X; 1152 of 2777 functions VM'd.

- **Confidence:** HIGH
- **Note:** Matches `CTF_103_EAC_Deep_Analysis.txt` exactly.
- **Operational-bypass risk:** No

**Claim 7.2-9.** Scimitar per-caller PUSH imm32; CALL rel32 trampolines at 0x1593373E7 and 0x15906749C.

- **Confidence:** MEDIUM
- **Note:** Addresses match entry point (0x1593373E7) and TLS callback[0] (0x15906749C) per CTF 121. Specific instruction shape at those exact bytes not documented at byte level in archived analysis.
- **Operational-bypass risk:** No

**Claim 7.2-10.** EAC per-stub dispatch-offset constant at 0x140290000 and 0x1402904FA.

- **Confidence:** HIGH
- **Note:** Confirmed VM entry stubs size 0x10B per `eac_ida_deep2.txt` lines 97-98 and 149-150.
- **Operational-bypass risk:** No

**Claim 7.2-11.** Authenticode blob at file offset 0x6A646E8.

- **Confidence:** HIGH
- **Note:** Matches CTF 121 §37 and §243.
- **Operational-bypass risk:** No

### 7.3 The One Primitive That Sees Pointer Encryption

**Claim 7.3-1.** "Six primitives mapped" (corrected from earlier "eighteen").

- **Confidence:** HIGH
- **Note:** §7.2 enumerates six. Earlier count of eighteen was unsupported by preceding text and has been corrected.
- **Operational-bypass risk:** No

**Claim 7.3-2.** DPC-scheduled access-pattern telemetry is the one primitive that intersects meaningfully with pointer encryption.

- **Confidence:** LOW
- **Note:** Proposed defensive primitive, not documented capability. Reframed accordingly.
- **Operational-bypass risk:** No

**Claim 7.3-3.** Anti-cheat could know which physical pages back encrypted slots (given developer collaboration or slot discovery).

- **Confidence:** LOW
- **Note:** Presupposes AC/developer collaboration on scheme details. No evidence for Ubisoft/BattlEye or Ubisoft/EAC collaboration on shared slot addresses.
- **Operational-bypass risk:** No

### 7.4 Class-Specific Detection Ideas

**Claim 7.4-1.** Class A: randomise `.rdata` key location at build time via MSVC linker segment shuffle.

- **Confidence:** MEDIUM
- **Note:** Plausible defensive recommendation; not a factual claim about R6 or EAC. Standard build-hardening.
- **Operational-bypass risk:** No

**Claim 7.4-2.** Class B: rotate immediate on monthly build cadence (R6 hypothesised to be in this class).

- **Confidence:** LOW
- **Note:** Presupposes R6 is Class B; recommendation depends on unverified premise.
- **Operational-bypass risk:** No

**Claim 7.4-3.** Class C: per-address encryption defeats static key extraction outright.

- **Confidence:** HIGH
- **Note:** Structural property of the scheme.
- **Operational-bypass risk:** No

**Claim 7.4-4.** Class D: place canary at plausible neighbouring address as tripwire.

- **Confidence:** MEDIUM
- **Note:** Defensive recommendation.
- **Operational-bypass risk:** No

**Claim 7.4-5.** Class E: forces per-callsite reversing; multiplies cost.

- **Confidence:** HIGH
- **Note:** Structural property.
- **Operational-bypass risk:** No

### 7.5 Canary Detection Strategies

**Claim 7.5-1.** Encrypted canary managers work because vendor's taxonomy-derived search points at wrong slot.

- **Confidence:** MEDIUM
- **Note:** Defensive design idea.
- **Operational-bypass risk:** No

**Claim 7.5-2.** Real inline decrypt sequence is under ten cycles.

- **Confidence:** MEDIUM
- **Note:** Reasonable for XOR + rotate + load on modern OoO cores; cache effects dominate in practice.
- **Operational-bypass risk:** No

### 7.6 Hardware-Side Detection

**Claim 7.6-1.** PCIe device fingerprinting — flag families of USB3-tethered FPGA DMA cards.

- **Confidence:** MEDIUM
- **Note:** GENERICISED. Earlier draft named specific commercial DMA products (Screamer, Squirrel, Enigma-X, FT600). Brand names elided to avoid purchasing-catalog framing.
- **Operational-bypass risk:** True (reframed — commercial brand names removed)

**Claim 7.6-2.** Default Windows configuration does not enable IOMMU/DMAR protection.

- **Confidence:** MEDIUM
- **Note:** Broadly correct pre-Kernel-DMA-Protection (KDP). Windows 10/11 Secure Core PCs increasingly enable it. VERIFY qualification.
- **Operational-bypass risk:** No

### 7.7 Recommendations for EAC-Class Vendors

**Claim 7.7-1.** Instrument manager access sites via canaries and access telemetry on backing physical pages.

- **Confidence:** MEDIUM
- **Note:** Defensive recommendation.
- **Operational-bypass risk:** No

**Claim 7.7-2.** Correlate encrypted-slot reads with subsequent decrypt behaviour.

- **Confidence:** MEDIUM
- **Note:** Defensive framing; asymmetry between game's own reads and external scanner reads.
- **Operational-bypass risk:** No

**Claim 7.7-3.** Server-side statistical detection dominates long-term detection budget.

- **Confidence:** HIGH
- **Note:** Orthogonal to client-side obfuscation. Widely accepted principle.
- **Operational-bypass risk:** No

**Claim 7.7-4.** Invest in hardware-side detection for DMA cheat category.

- **Confidence:** HIGH
- **Note:** Software layer alone cannot see DMA reads.
- **Operational-bypass risk:** No

### 7.8 Recommendations for Game Engineers

**Claim 7.8-1.** Class C defeats static key extraction if performance budget allows.

- **Confidence:** HIGH
- **Note:** Structural property.
- **Operational-bypass risk:** No

**Claim 7.8-2.** Per-session key randomisation defeats offset databases.

- **Confidence:** HIGH
- **Note:** Standard mitigation.
- **Operational-bypass risk:** No

**Claim 7.8-3.** AnvilNext appears to encrypt vtables at some Scimitar boundaries.

- **Confidence:** LOW
- **Note:** No evidence in CTF 118/120/121; packed `.UBX1` precludes vtable observation from static artifact. Downgrade or remove.
- **Operational-bypass risk:** No

---

## Operational-Bypass Audit Summary

The following passages were flagged during drafting for review and, where appropriate, reframed. In each case the technical point survives; the framing was changed from attacker-side to defender-side, or specific tactical identifiers were genericised.

1. **§6.4-1 (Register-held decrypted values).** Earlier draft described attacker hit rates on the register window with specific reference to external DMA and single-shot register capture. Reframed as defender-instrumentation-surface.

2. **§6.4-2 (Post-decrypt cache).** Earlier draft described "how a scanner defeats the encryption" as step-by-step: find cache once, read cache thereafter, never touch encrypted slot. Reframed as defender-side instrumentation requirement (both encrypted slot AND downstream caches must be watched).

3. **§6.4-3 (Post-unpack recovery path).** Earlier draft attributed the decrypt-routine-recovery path to "our project's dumper2 from the mapped BYOVD driver's read path." Reframed to generic "post-unpack memory dump obtained by any means (kernel-debugger, VM-snapshot, integrity review)." Project offensive tooling names removed from this defensive-context passage.

4. **§7.2-6 (EV-signed blocklist gap).** Earlier draft named a specific EV-signed driver ("TRIXX, DigiCert EV, no known CVE, currently PASSES") as bypassing the blocklist. Reframed as generic statement: "some EV-signed drivers with no public CVE are not yet on the blocklist; this is a snapshot property." Removes the actionable driver-name intelligence.

5. **§7.6-1 (Commercial DMA hardware).** Earlier draft enumerated specific commercial DMA product names (Screamer, Squirrel, Enigma-X, FT600). Reframed as "families of USB3-tethered FPGA DMA cards" to avoid purchasing-catalog framing.

**No working keys, callable decrypt primitives, `(encrypted, plaintext)` pairs, or offset+key databases are present in the chapter.** All illustrative constants shown in Section 5 pseudocode (`0xAAAAAAAAAAAAAAAA`, `0xDEADBEEFCAFEBABE`, `_rotr64(v, 13)`) are demonstration values, not extracted from any live product. The chapter does not contain step-by-step evasion guidance against BattlEye, EAC, or any specific live-service anti-cheat.

---

## Reconciliation Priorities for Publication

Ordered by load-bearing weight against the chapter's central conclusions:

1. **Class assignment for AnvilNext.** §5.9 (Class D per-section) and §7.0 (Class B) present different working hypotheses. Reconcile against a single canonical framing per CTF 120 §4.9's HIGH-confidence null on the static class question.

2. **Zone 1 byte-run sizes and Zone 2 entropy figure.** §4.4 numeric details (6144/5032/3341/2832 B, ~44 KiB label, 5.494 vs 5.51 entropy) must be reproduced from a single canonical scan pass.

3. **Numeric errors flagged as MATH ERROR:** §4.7-3 (second plateau ~4 MiB vs 7.87 MiB); §4.4-3 (~44 KiB vs ~86 KiB); §4.5-1 (7.30-bit Δ vs 5.5→7.95 framing); §4.4-4 (inverted Zone 2 range).

4. **EncodePointer / `/GS` attribution.** §5.6, §5.10, §5.2 (Axis 3): distinguish `EncodePointer` (used by CRT for function-pointer stores) from `/GS` (stack-cookie protection). These are two distinct MSVC hardening features.

5. **EAC API attribution.** §7.1 and §7.2 attribute several kernel APIs to EAC that are not visible in the EAC binary strings. Either qualify as "inferred to be hash-resolved inside VM section" or produce API-resolution evidence.

6. **"Six primitives" count.** §7.3's numeric reference already corrected from "eighteen" — validate that §7.2 enumeration is complete and matches the count.

7. **PDB path variant.** §3.1's `.pdb` filename claim — replace with the verified `.exe` variant or produce a direct debug-directory hex dump.

8. **Cross-title corpus lineage.** §3.1 (Assassin's Creed, Ghost Recon Breakpoint, For Honor) requires Ubisoft press or postmortem citation.

9. **DPC-sampling attribution.** §7.1, §7.3 — soften from "EAC can observe" to "proposed defensive primitive" throughout, unless CTF 103 provides direct evidence of implemented per-page DPC watchdog.

10. **BattlEye/EAC pointer-encryption confirmation claim.** §5.10 — cite specific public post or downgrade to community-lore strength.

---

## End of Verification Worksheet

Total individual claim entries: 132 across seven sections (2–7). Load-bearing summary reproduced in Section 12 of the main chapter. This worksheet is the record of what was checked, what survived, and what was reframed.
