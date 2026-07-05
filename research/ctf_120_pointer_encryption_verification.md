# CTF Task 120 — Verification Worksheet

This companion worksheet is the working form of the Verification Appendix in `ctf_120_pointer_encryption.md`. It enumerates every `[UNVERIFIED]` and `[VERIFY]` tag in the chapter, gives each a stable ID, and provides space for a reviewer to record:

- **Status** — one of `open`, `in-progress`, `resolved`, `withdrawn`, `deferred`.
- **Resolution artifact** — the specific file, commit, scan log, external citation, or PE-header re-parse that resolves the item.
- **Reviewer** — initials of whoever closed the item.
- **Date** — closure date (ISO 8601).

An item may be closed only when its resolution artifact is either archived in the project tree or cited in the chapter's reference list.

## Reviewer conventions

- If the item is a numeric claim (a hit count, a target VA, a section RVA), the resolution artifact must be a re-runnable script plus its captured output, stored under `build/` or the scratchpad, and referenced by relative path.
- If the item is an attribution claim ("older Anvil titles used single-constant XOR"), the resolution artifact must be a public URL or a stable citation entry added to the chapter's bibliography.
- If the item is an inference from static shape (e.g. "TLS-callback-driven unpacking"), the resolver may either upgrade the claim to a confirmed observation via dynamic tracing, or downgrade it to an explicit inference with the surrounding prose adjusted.
- Reviewers may withdraw an item (status `withdrawn`) only when the underlying prose has been rewritten to remove the claim.

## Verification items

| # | Tag | Section | Claim / issue | Status | Resolution artifact | Reviewer | Date |
|---|-----|---------|--------------|--------|---------------------|----------|------|
| 1 | VERIFY | §2.1 | "one of the most common" is a strong quantitative claim without a cited survey. | open |  |  |  |
| 2 | UNVERIFIED | §2.1 | Cross-engine survey (AnvilNext, RAGE, IW, UE-based titles) uncited. | open |  |  |  |
| 3 | VERIFY | §2.1 | Specific decrypt idioms proposed as detectable but not demonstrated in R6S artifacts. | open |  |  |  |
| 4 | UNVERIFIED | §2.2 | /GS-cookie-adjacent singleton idiom attribution exclusively to MSVC; clang-cl+LLD emit equivalent. | open |  |  |  |
| 5 | VERIFY | §2.2 | Dereference-yields-unmapped-section claim stated as observed but no dereference log archived. | open |  |  |  |
| 6 | VERIFY | §2.3 | `.UBX1` VirtualSize 0x08257C40 = 130.34 MB → should read ~130 MB, not ~131 MB. | open |  |  |  |
| 7 | VERIFY | §2.3 | Pointer-decryption stub localisation to `.UBX0`/`.UBX1` is analogy from VMProtect layouts, not proven. | open |  |  |  |
| 8 | VERIFY | §2.3 | Neither "hit-site RVA" nor "stale pattern" explanation confirmed by re-auditing r6_sigscan. | open |  |  |  |
| 9 | UNVERIFIED | §2.5 | Counts 46 / 161 / 154 not in archived scanner output; scan-run log needed. | open |  |  |  |
| 10 | UNVERIFIED | §2.5 | P4/P5 taxonomy undefined in archived documents; null result cannot be checked. | open |  |  |  |
| 11 | VERIFY | §3.1 | Section virtual size 0x1410A7F6 ≈ 336 MB, not 321 MB; arithmetic to be rechecked. | open |  |  |  |
| 12 | VERIFY | §3.1 | Coverage percentage 32.72% depends on disputed 321 MB denominator. | open |  |  |  |
| 13 | VERIFY | §3.1 | `.data` at RVA 0x14DBA000 should be confirmed from PE section table. | open |  |  |  |
| 14 | VERIFY | §3.1 | `.UBX0`/`.UBX1` section names/RVAs/sizes/characteristics to be confirmed from PE section headers. | open |  |  |  |
| 15 | VERIFY | §3.1 | CTF 118 reference not verifiable from current artifact set; cite source. | open |  |  |  |
| 16 | VERIFY | §3.2 | Upper-eight-register XOR encoding additionally requires REX.R extension (4C 33 05...). | open |  |  |  |
| 17 | VERIFY | §3.2 | Category 1 count of 46 hits is empirical; reproducible in principle but not independently confirmed. | open |  |  |  |
| 18 | VERIFY | §3.2 | Category 2 template does not enforce ModR/M mod=00, r/m=101; may over/under-match. | open |  |  |  |
| 19 | VERIFY | §3.2 | Category 2 null result contingent on template correctness. | open |  |  |  |
| 20 | VERIFY | §3.2 | 64-bit rotations mask the count by 63; effective range is 0..63, not 0..255. | open |  |  |  |
| 21 | VERIFY | §3.2 | Category 3 counts 161 ROR / 154 ROL empirical; not independently verified. | open |  |  |  |
| 22 | VERIFY | §3.2 | Category 4 null result contingent on scan implementation and window semantics. | open |  |  |  |
| 23 | UNVERIFIED | §3.3 | Illustrative bytes `48 C7 C0 dd... 48 B9 dd...` do not encode a 32-bit-pair synthesis; example contradicts prose. | open |  |  |  |
| 24 | VERIFY | §3.5 | MSVC RTTI mangling format correct in general; specific class names not verifiable from truncated dump. | open |  |  |  |
| 25 | VERIFY | §3.5 | "Published RVAs from prior research" source not cited. | open |  |  |  |
| 26 | VERIFY | §3.5 | 46 Category 1 hits distribution reproducible in principle but not independently confirmed. | open |  |  |  |
| 27 | VERIFY | §3.6 | 0x6909248 / 0x1ED04000 ≈ 21.13%, not 21.30%; arithmetic and SizeOfImage to be rechecked. | open |  |  |  |
| 28 | VERIFY | §3.6 | Six numbers listed for five categories — clarify numbering (Category 3 split into ROR/ROL). | open |  |  |  |
| 29 | VERIFY | §3.6 | Image base 0x140000000 to be confirmed from PE OptionalHeader; RVA vs file-offset formula clarified. | open |  |  |  |
| 30 | VERIFY | §4.2 | `.UBX1` "108 MB" prose vs RawSize 0x068A7E00 = ~104.5 MB; reconcile. | open |  |  |  |
| 31 | UNVERIFIED | §4.2 | Independent PE-header parse returns SizeOfImage 0x18B09000 (~395 MB), not 0x1ED04000; re-read before publication. | open |  |  |  |
| 32 | UNVERIFIED | §4.2 | 21.30% coverage derives from disputed 0x1ED04000; under actual header ratio is ~26.6%. | open |  |  |  |
| 33 | VERIFY | §4.2 | TLS-callback-driven unpacking is inferred from layout, not observed dynamically. | open |  |  |  |
| 34 | UNVERIFIED | §4.2 | Manager RVAs actually fall inside `.pdata` (0x11B87000..0x11F260D8), not `.text`; correct section name in prose. | open |  |  |  |
| 35 | VERIFY | §4.3 | Independent ROR scan returned 162 rather than 161; off-by-one, reconcile. | open |  |  |  |
| 36 | VERIFY | §4.3 | ROL count 154 not independently re-scanned in this pass. | open |  |  |  |
| 37 | VERIFY | §4.3 | `48 83 EC XX` count of 5 not independently re-scanned. | open |  |  |  |
| 38 | VERIFY | §4.3 | `48 8B XD ...` count of 59 not independently re-scanned. | open |  |  |  |
| 39 | UNVERIFIED | §4.4 | Recomputed RVA of prologue at 0x63C426C ≈ 0x1851AE6C, off by ~0x16000 from stated 0x1850426C. | open |  |  |  |
| 40 | VERIFY | §4.4 | Individual RIP-relative offsets in the stub not re-verified in this pass. | open |  |  |  |
| 41 | VERIFY | §4.4 | Junk-branch `E9 00 00 00 00` presence/frequency not re-verified. | open |  |  |  |
| 42 | VERIFY | §4.4 | Outer-unpacker vs inner-VM handler-stream decryptor attribution requires dynamic tracing. | open |  |  |  |
| 43 | UNVERIFIED | §4.5 | Recomputed target VA for 0x6334516 ≈ 0x151EE484B, off by ~0x50000 from paper's 0x151E9484B. | open |  |  |  |
| 44 | UNVERIFIED | §4.5 | Target-VA arithmetic for 0x3484236 → 0x149749A6D not re-verified. | open |  |  |  |
| 45 | UNVERIFIED | §4.5 | Target-VA arithmetic for 0x315F496 → 0x153EC31CB not re-verified. | open |  |  |  |
| 46 | VERIFY | §4.6 | Enumerated small-int set `{0x04..0x3B}` not re-derived from `scan_results2_top30.json`. | open |  |  |  |
| 47 | VERIFY | §4.6 | Individual constant occurrence counts (48, 44, 42, 42, 40, 37, 20) not re-scanned. | open |  |  |  |
| 48 | VERIFY | §4.6 | Isolated singleton offsets (0x278FA8, 0x278DA0, 0x2797D8) not re-verified. | open |  |  |  |
| 49 | VERIFY | §4.6 | Independent 32-bit-immediate scan returned 1,698 vs 1,689; off by 9, reconcile. | open |  |  |  |
| 50 | UNVERIFIED | §4.7 | Manager RVAs sit inside `.pdata`, not `.text`; section name to be corrected. | open |  |  |  |
| 51 | UNVERIFIED | §4.7 | On-disk PE places `.data` at RVA 0x107B2000, not 0x14DBA000; paper's `.data` RVA does not match current file. | open |  |  |  |
| 52 | VERIFY | §4.8 | Dispatch-table-decryption inference is static-shape only; dynamic tracing needed to distinguish. | open |  |  |  |
| 53 | UNVERIFIED | §5.1 | P1 count of 46 not in archived §4 scan output; regenerate. | open |  |  |  |
| 54 | UNVERIFIED | §5.1 | P2 = 0 not preserved in archived scan output. | open |  |  |  |
| 55 | UNVERIFIED | §5.1 | P3a = 161 not preserved in archived scan output. | open |  |  |  |
| 56 | UNVERIFIED | §5.1 | P3b = 154 not preserved in archived scan output. | open |  |  |  |
| 57 | UNVERIFIED | §5.1 | P4 = 0 not preserved in archived windowed-scan output. | open |  |  |  |
| 58 | UNVERIFIED | §5.1 | P5 = 0 not preserved in archived scan output. | open |  |  |  |
| 59 | UNVERIFIED | §5.1 | Prologue count = 1 not preserved in archived count artifact. | open |  |  |  |
| 60 | VERIFY | §5.2 | "Older Anvil titles used single-constant XOR" requires specific public reversing writeup. | open |  |  |  |
| 61 | UNVERIFIED | §5.2 | 46 P1 hits count reference (see #53). | open |  |  |  |
| 62 | VERIFY | §5.2 | "Several modern AAA titles" documenting class-(b) XOR+rotate needs specific writeup URL(s). | open |  |  |  |
| 63 | UNVERIFIED | §5.2 | Shape-matcher counts A/B/C/D = 0 not preserved in archived §4 output. | open |  |  |  |
| 64 | UNVERIFIED | §5.2 | Uniformity claim on ROR/ROL byte-pattern hits requires the underlying histogram. | open |  |  |  |
| 65 | UNVERIFIED | §5.2 | §4 imm-scan output for file-offset range 0x270000..0x290000 and table structure not archived. | open |  |  |  |
| 66 | UNVERIFIED | §5.2 | Per-qword repetition counts (40–85) not preserved in archived artifacts. | open |  |  |  |
| 67 | UNVERIFIED | §5.2 | Small-integer field value range `0x04..0x3B` not derivable from archived output. | open |  |  |  |
| 68 | VERIFY | §5.2 | SPECK is ARX; round-constant-table framing more accurately describes AES/SHA-style ciphers. Broaden example set or drop SPECK-32. | open |  |  |  |
| 69 | UNVERIFIED | §5.2 | `shl`/`shr` density measurement not preserved in archived §4 output. | open |  |  |  |
| 70 | UNVERIFIED | §5.4 | Aggregate rotation-hit count of 315 not preserved in archived §4 output. | open |  |  |  |
| 71 | UNVERIFIED | §5.4 | ROR/ROL split of 161/154 not preserved (see #55–56). | open |  |  |  |
| 72 | VERIFY | §5.5 | "Several older Frostbite and Anvil titles used single-constant XOR" requires specific per-title citations. | open |  |  |  |
| 73 | VERIFY | §5.5 | "Several Ubisoft titles between 2018 and 2022" needs specific writeup URLs. | open |  |  |  |
| 74 | VERIFY | §6.1 | Specific dump artifact and string XRefs for manager singleton list should be cited with addresses. | open |  |  |  |
| 75 | VERIFY | §6.1 | Which specific section per manager slot (`.data` vs `.rdata`) should be cited from the dump. | open |  |  |  |
| 76 | VERIFY | §6.1 | Helper form should be anchored by one cited helper address (rcx/rax convention observation). | open |  |  |  |
| 77 | VERIFY | §6.1 | Cite at least one inlined-form address and one helper-form address. | open |  |  |  |
| 78 | VERIFY | §6.2 | Partial-encryption observation should be clarified as inferred from list-walker disassembly. | open |  |  |  |
| 79 | UNVERIFIED | §6.2 | R6 Siege is a small-map tactical shooter, not an open-world game; "low thousands" entity figure unsourced. | open |  |  |  |
| 80 | VERIFY | §6.2 | Cite at least one specific documented AAA engine using the same partial-encryption pattern. | open |  |  |  |
| 81 | VERIFY | §6.3 | State scope of code paths examined for the vtable-encryption absence-of-evidence claim. | open |  |  |  |
| 82 | VERIFY | §6.5 | Reconcile "every access, not cached" general property with per-function caching variance. | open |  |  |  |
| 83 | VERIFY | §6.5 | Cite one address example per pattern for the "evidence of both patterns" claim. | open |  |  |  |
| 84 | UNVERIFIED | §7.2 | "Dozens of hits" for Shape-A YARA pattern in a typical AAA binary is unmeasured. | open |  |  |  |
| 85 | UNVERIFIED | §7.3 | Typical rotation-count range 5–29 unsupported by cited survey. | open |  |  |  |
| 86 | VERIFY | §7.3 | Ghidra `_rotr64` intrinsic rendering depends on version and P-code simplification rules. | open |  |  |  |
| 87 | VERIFY | §7.3 | Recent Hex-Rays collapses to `__ROR8__` intrinsic; behaviour version-dependent. | open |  |  |  |
| 88 | UNVERIFIED | §7.3 | Disassembler-disagreement-on-canonical-rotation-direction is uncommon; claim overstates. | open |  |  |  |
| 89 | VERIFY | §7.4 | Safe-Linking shipped in glibc 2.32 (2020), design began ~2019; date phrasing to reflect. | open |  |  |  |
| 90 | UNVERIFIED | §7.4 | Spread of per-address encryption into game engines and general application hardening not cited. | open |  |  |  |
| 91 | VERIFY | §7.4 | Hex-Rays rendering of Shape-C LEA depends on IDA version. | open |  |  |  |
| 92 | VERIFY | §7.6 | angr/Triton "one-pass" symbolic execution understates practical memory-model and constraint work. | open |  |  |  |
| 93 | VERIFY | §8.1 | Confirm "XOR-with-address-plus-rotate" naming matches classification in earlier sections. | open |  |  |  |
| 94 | VERIFY | §8.2 | "Trivially" overstates the case when decrypt routines are virtualised or split across obfuscated basic blocks. | open |  |  |  |
| 95 | VERIFY | §8.2 | "At will" ignores kernel-level countermeasures (PatchGuard, hypervisor memory protection, kernel monitoring). | open |  |  |  |
| 96 | UNVERIFIED | §8.2 | "Two weeks of engineering time" is a rhetorical estimate with no cited basis. | open |  |  |  |
| 97 | VERIFY | §8.3 | Performance overhead and detection reliability of EPT/PTE-based monitoring at scale should be sourced. | open |  |  |  |
| 98 | VERIFY | §8.3 | Canary encrypted pointers should be attributed to a shipping implementation or cited as proposed. | open |  |  |  |
| 99 | VERIFY | §8.4 | Confirm "Shape C" label is consistent with taxonomy introduced earlier in the chapter. | open |  |  |  |
| 100 | UNVERIFIED | §8.4 | "Many amateur implementations get wrong" empirical claim has no cited data source. | open |  |  |  |
| 101 | VERIFY | §8.4 | Cite benchmark numbers for hot-path decryption cost, or acknowledge magnitude claim is qualitative. | open |  |  |  |
| 102 | VERIFY | §8.6 | "For two decades" — specify anchor (PunkBuster 2000, VAC 2002) or soften to "for over two decades". | open |  |  |  |

## Priority guidance

- **Highest priority (must resolve before publication).** Items #31, #32, #34, #39, #43, #50, #51 — these are on-disk PE-header and address arithmetic discrepancies that directly contradict statements in the current chapter and are easy to re-derive from the artifact on disk.
- **High priority (resolve before external circulation).** Items #9, #10, #17, #21, #29, #30, #35, #49, #53–59, #63–71 — these are numeric hit counts and scan-derived structural claims that require a preserved scan-run log to substantiate.
- **Medium priority (resolve before peer-reviewed submission).** Items #1–3, #7, #23, #60, #62, #68, #72, #73, #79, #80, #84, #85, #89, #90, #96, #100 — attribution and citation issues that a peer reviewer will demand.
- **Lower priority (resolve during copy-edit).** Items #6, #16, #20, #28, #33, #40–42, #46–48, #52, #74–78, #81–83, #86–88, #91, #92–95, #97–99, #101, #102 — clarifications, prose consistency, and hedging adjustments.

## Sign-off protocol

Once every item has status `resolved` or `withdrawn`, the reviewer records a top-of-file sign-off block giving the closing date, closer initials, and the commit hash at which the chapter is fit for external distribution. Until then, the chapter is a research draft with a preserved audit trail and must be marked as such wherever it is circulated.
