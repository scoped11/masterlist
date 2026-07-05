# CTF 121 — Verification Worksheet

Companion to `ctf_121_aggressive_pointer_re.md`. One row per `[UNVERIFIED]` or `[VERIFY]` tag in the chapter. Fill the **Result** column with `CONFIRMED` / `REFUTED` / `SUPERSEDED` and the **Evidence** column with the file, command, or observation that closed the tag. Do not remove tags from the chapter until the row below is filled in.

## How to use this worksheet

1. Read the tag in context in `ctf_121_aggressive_pointer_re.md`.
2. Perform the action listed in the **Action Required** column.
3. Record the outcome:
   - **CONFIRMED** — the claim is correct as written; remove the `[VERIFY]` or `[UNVERIFIED]` tag in the chapter.
   - **REFUTED** — the claim is wrong; rewrite the sentence and note the corrected fact.
   - **SUPERSEDED** — the claim has been dropped or replaced during editing.
4. Sign the row (initials + date) once done.
5. Do not close a tag on the strength of memory or general knowledge — close it only against a direct measurement, a cited source, or a live observation.

## Global reconciliations to do first

Two chapter-wide inconsistencies must be resolved before per-tag work:

- **Canonical artifact.** Sections 1–4 and Section 6 measure against `RainbowSix.exe.fullpe.bin` at 111,576,136 bytes. Section 5 in an earlier draft measured a 137,073,224-byte variant. Pick one artifact for the entire chapter, record its SHA-256, and re-verify every size / RVA / VA claim against it.
- **RVA notation.** Ensure every VA range in the chapter resolves against `ImageBase = 0x140000000`. Sections 5–6 in earlier drafts mixed RVA and VA (e.g., `0x1110CB000` is neither an RVA nor a VA in this image).

## Tag table

| # | Section | Tag | Subject | Action Required | Result | Evidence | Signed |
|---|---|---|---|---|---|---|---|
| 1 | 1 | UNVERIFIED | ".rdata most likely" holds key material | Restate as hypothesis in Objectives; do not forward-reference | | | |
| 2 | 2.1 | VERIFY | ".text = 281 MB" | Recompute from OptionalHeader | | | |
| 3 | 2.1 | VERIFY | ".pdata = 3.75 MB" | State unit convention (MiB vs MB) | | | |
| 4 | 2.1 | UNVERIFIED | "eight smaller MSVC compiler-artifact sections" | Correct to 7 (or 6 excluding .UBX0) | | | |
| 5 | 2.1 | UNVERIFIED | Entropy = "encryption plus compression" | Reword to "strong encryption or compression" | | | |
| 6 | 2.2 | VERIFY | Agent 2's "92 matches" | Re-run 16-pattern scan against `.UBX1` | | | |
| 7 | 2.2 | VERIFY | Bucketing 83/9/0 | Regenerate from re-run | | | |
| 8 | 2.2 | VERIFY | Expected match count "several thousand" | Rephrase to tens of thousands per 100 MB | | | |
| 9 | 2.2 | VERIFY | Collision-rate arithmetic | Show 106e6/2^24 × 16 ≈ 100 calculation | | | |
| 10 | 2.2 | VERIFY | 662 export names | Re-enumerate `NumberOfNames` from on-disk copy at RVA 0x1905C5A8 | | | |
| 11 | 3.1 | VERIFY | CTF 120 partial "~105 MB" | Confirm 110,137,928-byte dump.bin identity | | | |
| 12 | 3.1 | UNVERIFIED | Steam-variant hash equivalence | Enumerate chain-of-custody records | | | |
| 13 | 3.1 | VERIFY | Unbacked sections' bytes live inside .UBX1 | Not proven statically; document as inference or dynamically observe | | | |
| 14 | 3.2 | VERIFY | Entry position "88.1% into .UBX1" | Recompute (entry_fo − UBX1_fo) / UBX1_raw_size | | | |
| 15 | 3.2 | UNVERIFIED | Dispatcher uses pushed dword as seed | Dynamic observation required | | | |
| 16 | 3.3 | UNVERIFIED | .UBX0 as "code cave for helper trampolines" | Header attributes only; leave as inference | | | |
| 17 | 3.4 | VERIFY | .rdata/.data content mapped into .UBX1 | Requires dynamic observation | | | |
| 18 | 3.5 | VERIFY | Low-entropy island average "5.24 bits" | Reproduced ~5.51 bits at 64 KB window; correct | | | |
| 19 | 3.5 | UNVERIFIED | Structural table as XFG/CFG | Refuted; leave as "unresolved" | | | |
| 20 | 3.5 | VERIFY | ".reloc handled by protector internally" | Inference only | | | |
| 21 | 3.6 | UNVERIFIED | Anti-VM code generated vs stored encrypted | Two runtime models indistinguishable statically | | | |
| 22 | 3.6 | UNVERIFIED | Pushed dword as per-caller opcode/key | Dynamic proof needed | | | |
| 23 | 3.6 | VERIFY | Cross-title trampoline fingerprint | External corpus comparison; cite sources | | | |
| 24 | 3.6 | VERIFY | ".UBX0/.UBX1" strings both at 0x310 | Correct to 0x310 and 0x338 respectively | | | |
| 25 | 3.6 | VERIFY | "MSVC 2022 full LTO" from `_flto_dx12` | Naming-convention only | | | |
| 26 | 3.7 | UNVERIFIED | 0x9C/0xCC/0xEC/0xED in TLS cb[0] as instructions | Coincidental in ciphertext; drop instruction interpretation | | | |
| 27 | 3.7 | VERIFY | Dispatcher-to-dispatcher distance "~150 KB" | Actual 143.4 KB | | | |
| 28 | 3.7 | VERIFY | cb[0] initialiser vs cb[1]/[2] original callbacks | Layout inference | | | |
| 29 | 3.8 | VERIFY | cb[1]/cb[2] trampoline shape | Not directly verifiable — no on-disk bytes | | | |
| 30 | 3.8 | VERIFY | KERNEL32/USER32 duplicated in import descriptors | Confirm 40/42 count | | | |
| 31 | 3.8 | UNVERIFIED | Hypervisor-detection code generated vs stored | Two models indistinguishable statically | | | |
| 32 | 4.1.2 | VERIFY | Exact byte-count of readable-string portion of export-name island | Measure directly | | | |
| 33 | 4.1.2 | UNVERIFIED | 1.4 MiB structural table as XFG layout | Refuted by size and hash-width | | | |
| 34 | 4.1.2 | UNVERIFIED | 2 KB IAT thunk at tail of .UBX1 | PE IAT dir is 768 B at different offset | | | |
| 35 | 4.2 | VERIFY | Corrected TLS cb[0] bytes | Re-read on-disk bytes at 0x59F789C | | | |
| 36 | 4.4 | UNVERIFIED | Routine size 24–48 B "in older RE literature" | Cite source | | | |
| 37 | 4.5.1 | VERIFY | "26,262 total 48 B8..BF matches" | Recompute from raw scan | | | |
| 38 | 4.5.2 | UNVERIFIED | Four page-aligned zero regions at stated offsets | Not page-aligned; re-derive from actual island scan | | | |
| 39 | 4.5.3 | UNVERIFIED | "0x280 island … length 0x0B … four 8-byte records" | Adjacent to IMAGE_TLS_DIRECTORY; reinterpret | | | |
| 40 | 4.6 | UNVERIFIED | Rotation amount "1–15 bits" from literature | Cite external references | | | |
| 41 | 4.6 | UNVERIFIED | Rotation direction "consistently right (ROR)" | Cite external references | | | |
| 42 | 4.7 | VERIFY | Out-of-line helper vs inlined in this build | Post-OEP scan and cite sister analyses | | | |
| 43 | 4.9.1 | UNVERIFIED | 1.42 MB island as XFG table | Refuted by size and hash-width | | | |
| 44 | 4.9.3 | VERIFY | No RDTSC/CPUID in first 4 KB of any stub | Run explicit byte scan | | | |
| 45 | 4.9.3 | UNVERIFIED | PUSHFQ placement | Actually in dispatcher, not cb[0] proper | | | |
| 46 | 4.9.3 | VERIFY | No plaintext hypervisor-vendor strings | Run explicit strings scan | | | |
| 47 | 4.9.3 | VERIFY | Absence of commercial protector fingerprints | Publish scan output or re-run | | | |
| 48 | 5.1 | VERIFY | File-size discrepancy (111 MB vs 130.7 MB) | Reconcile to canonical artifact | | | |
| 49 | 5.1 | VERIFY | .UBX1 size (106 MB vs 130.3 MB) | Reconcile | | | |
| 50 | 5.1 | VERIFY | Protector stub RVA (0x193373E7 vs 0x16C536DE) | Reconcile | | | |
| 51 | 5.2 | VERIFY | GameManager* decrypt parameters | Currently 0x0 / 0 in offsets.ini — helper not recovered | | | |
| 52 | 5.2 | UNVERIFIED | Entity/Match/Round/TeamManager encryption | Only seeds; no resolved addresses | | | |
| 53 | 5.2 | UNVERIFIED | Input/RenderManager encryption | Not in codebase evidence | | | |
| 54 | 5.2 | VERIFY | Entity container as linked list | Actual container is pointer array indexed base*8 | | | |
| 55 | 5.2 | UNVERIFIED | String-obfuscation helper "~100+ call sites" | No such count captured | | | |
| 56 | 5.4 | UNVERIFIED | Scheme "has no keyed identity" | Inference; helper not reversed here | | | |
| 57 | 5.4 | UNVERIFIED | AnvilNext patch cadence "6–12 weeks" | Common figure; cite | | | |
| 58 | 6.1 | UNVERIFIED | In-line encrypted parameter blob after CALL | Dynamic proof needed | | | |
| 59 | 6.1 | UNVERIFIED | Dispatcher stage-1 constructs routine in memory | Post-OEP artifact needed | | | |
| 60 | 6.1 | UNVERIFIED | Structural table as /guard:xfg or per-page fixup | Refuted; leave as unresolved | | | |
| 61 | 6.2 | VERIFY | Canonical set of zero-pad islands | Re-derive from single scan pass | | | |
| 62 | 6.2 | UNVERIFIED | Zero-pad islands as runtime key/IV backing store | Inference; alignment and locality only | | | |
| 63 | 6.2 | UNVERIFIED | 2 KiB block at 0x6A06C00 as IAT rebuild table | PE IAT directory points elsewhere | | | |
| 64 | 6.2 | VERIFY | Dispatcher delta "~150 KB" | Actual 143.4 KB | | | |
| 65 | 6.2 | VERIFY | Export-name island lower bound | Tighten to export directory header start | | | |
| 66 | 6.3 | UNVERIFIED | TLS cb[0] specifically populates .text | Loader ordering guaranteed; specific unpacker inferred | | | |
| 67 | 6.3 | VERIFY | Corrected .rdata / .data VA ranges | Earlier draft mixed RVA and VA | | | |
| 68 | 6.4 | UNVERIFIED | Loader activity never touches interior .UBX1 pages | Not measured | | | |
| 69 | 6.4 | VERIFY | .UBX1 header offset "0x310" | Actually 0x338; use string-search anchor | | | |
| 70 | 6.5 | VERIFY | No RDTSC/CPUID/SIDT in first 4 KB of any stub | Wider scan not directly logged | | | |
| 71 | 6.5 | UNVERIFIED | Dispatcher reconstructs decoder pointer from immediates | Opcode family right; semantics inferred | | | |
| 72 | 6.6 | VERIFY | "Four" zero-pad islands and cross-build stability | Actually eight in this build; cross-build stability is extrapolation | | | |
| 73 | 6.6 | UNVERIFIED | Post-OEP scan will surface Scimitar helper in top-25 | Prospective; workflow not run to completion | | | |

## Ethics-adjacent claims to reconfirm before publication

These are not `[VERIFY]` tags but need a second pass for defensive framing:

- Section 5.2.4 statement about XFG trapping on callback pointer overwrite — reads defensively as written; confirm.
- Section 5.4 statement that the scheme "raises the bar by exactly the number of days" — softened to "value scales inversely with attacker tooling maturity"; confirm.
- Section 4.9.2 per-address encryption pseudocode — presented as a defender-side observation of a known variant; confirm framing.
- All references to `DecryptPtr(rawPtr)` and `ReadEncPtr` in the coverage table — these name in-codebase helpers by identifier only, without publishing their implementation; confirm.

## Sign-off

- [ ] All 73 tags resolved
- [ ] Global reconciliations complete (canonical artifact, RVA/VA notation)
- [ ] Ethics-adjacent claims re-read
- [ ] External-corpus citations added
- [ ] Chapter re-read end-to-end after tag removal

Reviewer: __________________ Date: __________
