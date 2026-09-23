# Development Journal

Reverse-chronological working log. Records what was built, what was tested, what broke, and what the
measurements actually showed — including results that contradicted the design intent.

---

## 2026-09-22 — Initial implementation, verification harness, first threading benchmark

### What was built

| Component | File | Purpose |
|---|---|---|
| Core types | `include/dsigmatcher/Types.h` | SoA `FunctionTable` over a `StringPool` arena; `Match`; `ProgramInfo` |
| Name rules | `include/dsigmatcher/Naming.h` | `sub_` / `nullsub` classification, `NameCompatible`, `IsPortableSymbol` |
| Ingest | `src/ExportDatabase.cpp` | Reads Diaphora SQLite exports; column set discovered via `pragma table_info` |
| Heuristics | `src/Heuristics.cpp` | 8 of Diaphora's 12 `Best`-category heuristics as native hash joins |
| Resolution | `src/MatchStore.cpp` | Dedup + deterministic strict 1:1 assignment |
| Hashing | `src/Sha256.cpp` | Self-contained SHA-256, no external dependency |
| Provenance | `src/Provenance.cpp` | `diff` / `port` / `info`; chainable labelled output with hop tracking |
| Generator | `src/Synth.cpp` | Synthetic corpus with per-function ground truth |
| CLI | `src/main.cpp` | `dsigmatcher diff|port|info` |
| Tests | `tests/dsigmatcher_tests.cpp` | 82 assertions across 7 suites |
| Benchmark | `bench/dsigmatcher_bench.cpp` | Per-heuristic and per-thread-count timing |

### Reference analysis

Diaphora was read, not guessed at. Established facts that drove the design:

- **Schema** (`db_support/schema.py`): `functions` has 49 columns; 12 supporting tables. The full
  column set is the ingest contract.
- **Cascade** (`diaphora_heuristics.py`): 50 heuristics, 3 categories — `Best` (12), `Partial` (30),
  `Unreliable` (8). Each is a SQL join with a shared `SELECT_FIELDS` projection, a `%POSTFIX%` size
  gate (`and f.instructions > 5 and df.instructions > 5`), a ratio type and flags.
- **Driver** (`diaphora.py:1462+`): parallelism is at *heuristic* granularity via `threads_apply`,
  with all match bookkeeping behind one global `items_lock` and a `cleanup_matches()` pass per
  category. Match record shape is `[ea1, name1, ea2, name2, description, ratio, nodes1, nodes2]`.
- **Small-function policy**: `diaphora.py:3093` states plainly that *"there is a high risk of false
  positives with small functions, therefore it's preferred to miss functions than having false
  positives"*, enforced by `DIFFING_MATCHES_MIN_BBLOCKS = 3`. Diaphora's answer to trivial
  offset-getters producing identical bytecode is to refuse to match them on content and to require
  `nodes >= 3` even for call-graph-propagated matches. Thunks are excluded at export by default
  (`EXPORTING_EXCLUDE_LIBRARY_THUNK = True`).
- **License**: AGPLv3, not GPLv3. Corrected in the README after reading `LICENSE`.

### Bugs found, and what found them

Every one of these was caught by testing or review before it could be relied on. Several were caught
by a test *passing for the wrong reason*, which is the more dangerous failure mode.

| # | Bug | Found by |
|---|---|---|
| 1 | SHA-256 round update read `Working[3]` for `e = d + T1` *after* the shift loop had already overwritten it with `c` | Manual trace of the round function before first run. Confirmed fixed against NIST vectors, including the 1,000,000-byte case. |
| 2 | `output_file_sha256` stored a file's own hash inside that file, invalidating itself on write | Reasoning about the write order. Column removed; the chain is verified instead by hop *N+1* recording hop *N*'s output hash as its `source_file_sha256`. |
| 3 | Hop number derived from the **target's** provenance (always empty, since the output is a byte copy of the raw target), and the reference's hop history was dropped entirely | Two-hop chain test printed `hop = 1` twice. Fixed to derive from the reference and to copy the parent hop rows forward. |
| 4 | `CreateExport` in the test helper inserted into `program` **before** creating that table, so the insert silently failed | Reading the compiler's `C4189 'Schema' is initialized but not referenced` warning led back to the dead code path. |
| 5 | Chain fixture held addresses **constant across versions**, so `Same address and mnemonics` resolved the deliberately-ambiguous pair uniquely at ratio 1.0 instead of 0.5 | Test asserted cumulative 0.5, observed 1.0. Real recompiles shift addresses — win32u measurement below shows 76% move. |
| 6 | `--max-hops 1` expectation was wrong: all three names already sit at hop 1 after the first port, so all three are capped, not two | Test failure. Corrected to `skipped=3, applied=0`. |
| 7 | **The synthetic generator emitted one `Texts` set to both sides**, so even "recompiled" and "ambiguous" functions had byte-identical hashes across versions. The exact-hash tier resolved everything and the cleaned-text heuristics never carried any weight. Reported precision was a meaningless `1.0000` | Noticed the precision was *too* clean and asked why. Fixed with per-side `ReferenceTexts`/`TargetTexts` plus a seeded shuffle of target row order, so greedy 1:1 resolution cannot succeed by index alignment. |
| 8 | Benchmark argument parser read `Argument == "" ? Argv[++Index] : Argv[++Index]` — both branches identical | Caught on review before first run. |
| 9 | Assumed embedding a username in a git remote URL pins the identity. `gh auth git-credential get` serves **only** the active account and returns nothing for any other requested username | Direct probe of the helper. Replaced with a repo-local helper script driven by `gh auth token --user`, which does serve any stored account. Verified by pushing while the other account was active. |
| 10 | Reported "no C++ toolchain on this machine" | Wrong twice. A probe used `set "VS=..." & ... %VS%` on one line; cmd expands `%VS%` at parse time before `set` runs, so every path resolved to nothing. MSVC 14.51, CMake and Ninja were present all along. |

Bug 7 is the important one. A test suite that reports perfect precision is not reassuring — it is
evidence the fixture is leaking the answer. `CHECK(Precision < 0.999)` is now an explicit assertion
so that leak cannot silently return.

### Test results

`build/dsigmatcher_tests.exe` — **82 checks, 0 failed.**

```
[Sha256 known vectors]        empty, "abc", quick-brown-fox, 1e6 x 'a', chunked == whole
[StringPool]                  append, empty slot, view stability, byte accounting
[Naming predicates]           sub_ / nullsub / portable / NameCompatible truth table
[MatchStore resolution]       dedup, ratio preference, strict 1:1, determinism under reversal
[ExportDatabase ingest]       25-row round trip, field fidelity, missing-file rejection
[Heuristics vs ground truth]  3800 per side, precision 0.9375, recall 0.9375, 225 false positives
[Provenance chain]            two hops: 1.0 -> 1.0 stable, 0.5 -> 0.25 ambiguous decay,
                              hop cap and ratio floor both verified
```

Serial and 8-thread runs produce **identical** resolved sets and raw counts, which is the
determinism guarantee the README claims.

Synthetic accuracy after fixing bug 7: **precision 0.9375, recall 0.9375** on 3600 paired functions.
This matches the analytical prediction for a corpus with a 10% genuinely-ambiguous bucket at group
size 6 — those functions are indistinguishable by construction, so roughly 5 of every 6 pairings
inside a group must be wrong. The number is a property of the fixture, not a quality claim about the
matcher.

### Benchmark results

`build/dsigmatcher_bench.exe -n 50000 -r 3` on a 32-thread machine, 47,500 functions per side,
13.8 MiB of interned text per side, best of 3:

```
heuristic (serial)                       ms  raw matches
Same RVA and hash                     10.33        25067
Same order and hash                   12.73        27500
Function Hash                         10.31        27500
Bytes hash                             9.57        27500
Same address and mnemonics             8.38        11351
Same cleaned assembly                 11.26        61490
Same cleaned microcode                11.24        69992
Same cleaned pseudo-code              10.91        65914
sum of heuristics                     84.72
resolve (serial, unavoidable)         14.90        45000

threads         wall ms      speedup   efficiency     resolved
1                 83.70         1.00x       100.0%        45000
2                 74.51         1.12x        56.2%        45000
4                 48.15         1.74x        43.5%        45000
8                 38.57         2.17x        27.1%        45000
16                38.49         2.17x        13.6%        45000
24                39.91         2.10x         8.7%        45000
32                38.11         2.20x         6.9%        45000
```

316,304 raw candidate pairs collapse to 45,000 resolved matches.

### Findings on threading

The premise that parallelising everything is not automatically faster is **confirmed, sharply**.

1. **Peak speedup is 2.20× on 32 hardware threads — 6.9% efficiency.** Scaling is flat past 8
   threads.
2. **The first measurement of this was wrong, and the error was instructive.** An earlier run
   reported 3.48× at 24 threads. That number was an artifact: the serial baseline was inflated to
   124.93 ms because `RunExactHeuristics` spawned and joined a `std::thread` per heuristic even at
   `ThreadCount = 1`. Adding an inline fast path for the single-threaded case dropped the serial
   baseline to 83.70 ms — a 33% improvement in the *baseline*, which is what made the speedup ratios
   collapse to their true values. `sum of heuristics` and `serial wall` now agree (84.72 vs 83.70 ms),
   where before they diverged by 55 ms of pure scheduler overhead. **Lesson: a speedup figure is only
   as trustworthy as its baseline.**
3. **Two-thread scaling is poor (1.12×)** because the scheduler runs heuristics in *waves* with a
   full barrier between them. With per-heuristic costs spread 8.4–12.7 ms, each wave waits for its
   slowest member.
4. **`Resolve` is a serial floor.** At ~15 ms of an 84 ms serial total it is an 18% serial fraction,
   bounding maximum speedup at roughly 5.6× by Amdahl's law regardless of thread count.
5. **The hard ceiling is architectural**: heuristic-level parallelism cannot exceed the number of
   heuristics. With 8 implemented, 8 threads is the maximum useful width.

**Important caveat on finding 5.** Only 8 of Diaphora's 50 heuristics exist so far. Once the
`Partial` (30) and `Unreliable` (8) categories land, the heuristic-level ceiling rises to 50 and this
analysis must be redone. The current 2.2× is partly an artifact of an incomplete cascade, not only of
the scheduler.

**Consequent plan**, in priority order:

- Replace wave scheduling with a persistent pool and a work queue — removes barrier stalls and lets
  short heuristics backfill behind long ones.
- Parallelise or shard `Resolve`; an 18% serial fraction caps everything else.
- Add intra-heuristic parallelism by sharding the probe side of each join. This is the only route
  past the heuristic-count ceiling and matters most for the expensive text-keyed joins.
- Defer threading decisions on the remaining 38 heuristics until they exist and can be measured
  individually. The per-heuristic table above is the instrument for that.

### Real-corpus preparation

A benchmark corpus was assembled from what was already on the machine: two x64 servicing revisions of
`win32u.dll` found in WinSxS (`10.0.26100.9168` and `10.0.26100.9444`), with PDBs fetched from
Microsoft's public symbol server by GUID read out of each PE's RSDS record. `dbghelp` confirms
`SymPdb` with `pdb_unmatched=False`.

Ground truth extracted via `SymEnumSymbols`: 3077 and 3083 public symbols, but only **1538 / 1540
distinct addresses** — nearly every function carries an `Nt*`/`Zw*` alias pair at the same address.
So this is a ~1500-function corpus: good for accuracy, too small for throughput. Public PDBs carry no
function sizes, so ground truth is name-to-RVA only.

Comparing the two symbol sets:

| | |
|---|---|
| Shared names | 3075 |
| Same address | 726 |
| **Moved** | **2349 (76%)** |
| Removed | 2 |
| Added | 8 |

**76% of functions changed address between these two builds.** This is the single most consequential
measurement of the session: it means `Same RVA and hash` and `Same address and mnemonics` — two of
the eight implemented heuristics — will contribute almost nothing on a real corpus, and content-based
matching carries the entire load. It also retroactively justifies fixture bug 5: a test corpus whose
addresses never move flatters exactly the heuristics that matter least in practice.

The churn is explained by the 8 insertions (new syscalls at RVA `3b50`, `3b90`, `9110`, `aaf0`)
shifting everything after them — ordinary patch behaviour.

### Correction: PDB symbols are not export symbols

The real-corpus section above states that win32u carries an `Nt*`/`Zw*` alias pair at nearly every
address. That is **true of the PDB and false of the PE export table**, and conflating the two produced
a wrong requirement that a subagent had to catch.

Measured both ways on build `10.0.26100.9168`:

| Source | Names | Distinct RVAs | `Nt*` | `Zw*` | Forwarders | Unnamed |
|---|---|---|---|---|---|---|
| PDB via `SymEnumSymbols` | 3077 (all distinct) | 1538 | 1541 | **1497** | n/a | n/a |
| PE export table | 1548 | 1506 | 1540 | **0** | 0 | 0 |

The 2.0007 name-to-address ratio in the PDB is genuine and is caused by the `Zw*` aliases. The export
table's ratio is 1.0279. win32u exports the `Nt*` names only; the `Zw*` aliases exist in the compiled
symbol stream and were never exported. A raw byte scan of the DLL finds no `ZwUser` string, which is
consistent — PDB symbol names do not have to appear in the image.

**What went wrong.** That PDB-derived ratio was written into a subagent brief as a property of the
export table, with an instruction to assert a `[1.8, 2.2]` band on names-per-address. The agent
measured 1.03, did *not* assume its parser was broken, cross-checked against `pefile` (independent
implementation, identical numbers) and a raw byte scan, and replaced the fuzzy band with exact
assertions on verified counts. That was the correct response to a bad premise, and it is the second
time in this session that writing a test against an assumed number rather than a measured one caused
trouble — the first was the synthetic generator reporting `precision 1.0000`.

**Where the agent also over-reached.** It concluded that "the Nt/Zw aliasing is an `ntdll.dll`
property, not `win32u.dll`". That is wrong: win32u's PDB contains 1497 `Zw*` symbols. The aliasing is
real for this binary; it is simply absent from the export table. Correcting a false premise does not
make the replacement explanation true, and the replacement was independently checked here rather than
accepted.

**Consequences for the project:**

- Ground truth must come from the **PDB**, not the export table. It is strictly better on both axes:
  more names (3077 vs 1548) and more coverage, since it includes internal functions that were never
  exported (1538 distinct RVAs vs 1506).
- The export table is still useful as a cheap function-entry hint when no PDB exists, but it is not a
  labelling source and must not be used to score matches.
- win32u exercises **no forwarders and no ordinal-only exports**, so those code paths in `PeImage` rest
  on synthetic images alone. That is a real coverage gap, recorded rather than papered over.

### Join fusion and key precomputation: measured

Question raised: when several heuristics key on the same column, is it better to touch that data once
and derive everything from it, rather than re-scanning and re-hashing it per heuristic? Measured with a
standalone microbenchmark (`tools/join_bench.cpp`, 50,000 rows per side, 60% shared keys, best of 3).

**Fusing three heuristics that share one join key into a single index build plus one probe pass:**

| Key length | 3x separate | 1x fused | Speedup |
|---|---|---|---|
| 36 B | 40.72 ms | 12.60 ms | **3.23x** |
| 256 B | 129.66 ms | 38.78 ms | **3.34x** |
| 1024 B | 346.21 ms | 103.96 ms | **3.33x** |
| 4096 B | 1123.94 ms | 363.10 ms | **3.10x** |

Near-linear and flat across two orders of magnitude of key size, because index construction plus probe
*is* essentially the whole cost, and fusion does it once instead of three times.

**Precomputing a 64-bit hash per row and joining on integers instead of strings** (string equality kept
as a confirmation step on candidates only):

| Key length | String join | Precompute pass | Int join | Int total | Speedup |
|---|---|---|---|---|---|
| 36 B | 17.74 ms | 1.72 ms | 3.71 ms | 5.43 ms | 3.27x |
| 256 B | 45.33 ms | 21.10 ms | 5.56 ms | 26.66 ms | 1.70x |
| 1024 B | 116.01 ms | 79.53 ms | 7.70 ms | 87.23 ms | 1.33x |
| 4096 B | 393.24 ms | 305.10 ms | 20.87 ms | 325.97 ms | 1.21x |

Precomputation alone looks weak at long keys because the hashing pass costs the same bytes either way.
That reading is wrong in isolation: **the precompute is paid once per column and amortised across every
heuristic that keys on it.** At 4096 B with three heuristics sharing a column, one precompute (305 ms)
plus three integer joins (3 x 20.87 ms) totals ~367 ms against 1180 ms for three string joins — and it
composes with fusion rather than competing with it.

**Fusion is the larger and cheaper win.** It needs no extra threads, no extra memory, and no new
hashing, and it returns ~3.2x where heuristic-level threading returned 2.2x at 32 threads and 6.9%
efficiency. Redundant work removed beats redundant work parallelised.

Concrete fusion target in the current code: `Same RVA and hash`, `Same order and hash` and `Bytes hash`
all key on `functions.bytes_hash`. Today they build three separate hash indexes over the same column
and probe three times. They should build one index and evaluate three predicates per candidate.

### The synthetic benchmark is unrepresentative, and this is why it matters

`src/Synth.cpp` generates text columns of roughly 36 bytes (`"asm-" + 32 hex chars`). Real Diaphora
exports store the *entire cleaned assembly listing* of a function in `clean_assembly` — for a
50-instruction function that is on the order of 1-4 KB. The measured table above is the reason this
distortion is not cosmetic:

- At 36 B, three separate joins cost 40.72 ms. At 4096 B they cost 1123.94 ms — **27x more**.
- The 84.72 ms "sum of heuristics" reported earlier for 47,500 functions therefore badly understates
  real cost, and understates it *most* for exactly the text-keyed heuristics that dominate on real
  binaries.
- The threading conclusion is also skewed: with trivially cheap keys there is little work to
  distribute, so the measured 2.2x ceiling partly reflects an underloaded benchmark rather than a pure
  architectural limit.

**Action:** regenerate the synthetic corpus with realistic text-column lengths before drawing any
further performance conclusions, and re-run the thread-scaling sweep afterwards. Numbers in the
"Findings on threading" section should be treated as valid for the ordering of heuristics but not for
absolute cost or for the parallel-efficiency ceiling.

Caveat on the microbenchmark itself: it uses `unordered_multimap<std::string, uint32_t>` with owned
strings, whereas the project keys on `std::string_view` into a string arena and should have better
locality. Absolute times here are pessimistic relative to the real code; the *ratios*, which are what
these conclusions rest on, are driven by hashing and map operations that both versions pay.

### SIMD hashing: measured, and it invalidates the precompute conclusion above

Host CPU probed directly (`tools/cpu_features.cpp`, CPUID + `XCR0`): **AMD Ryzen 9 9950X, Zen 5,
16C/32T.** AVX-512 F/BW/VL/DQ/CD/VBMI/VBMI2/VNNI/VPOPCNTDQ all present, OS enables ZMM state, BMI1/2
and POPCNT present, AVX512_BF16 absent. AMD carries no AVX-512 frequency penalty of the kind Intel's
license-based downclocking imposed, so 512-bit code is usable without a throughput cliff.

Probe bug, recorded so the output is not trusted blindly: cache reporting parsed CPUID leaf 4, which
is Intel-only (AMD uses `0x8000001D` for cache topology and `0x80000005` for L1), and applied Intel's
`+1` line-size convention. It printed "L1 data line size: 1 bytes", which is nonsense. The L2 figure
(1024 KB per core) and the true 64-byte line size are correct; the L1 line is not.

Hash throughput measured over 195.3 MiB (50,000 x 4096 B), best of 3 (`tools/hash_bench.cpp`):

| Variant | ms | GB/s | vs FNV-1a |
|---|---|---|---|
| FNV-1a scalar byte | 148.07 | 1.29 | 1.00x |
| scalar 64-bit multiply | 27.51 | 6.93 | 5.38x |
| AVX2 rotate (32 B/iter) | 6.85 | 27.83 | 21.61x |
| **AVX-512 rotate (64 B/iter)** | **3.73** | **51.20** | **39.75x** |
| AVX-512 mullo (64 B/iter) | 3.95 | 48.25 | 37.46x |

Findings:

- **AVX-512 is 1.83x faster than AVX2 here** (3.73 vs 6.85 ms). Zen 5's native 512-bit datapath
  delivers real throughput, not merely ISA compatibility — unlike Zen 4, where 512-bit ops are
  double-pumped over 256-bit units.
- **Rotate-xor beats 64-bit `mullo`** even though AVX512DQ provides native `mullo` (3.73 vs 3.95 ms).
  The multiply is not free on Zen 5, so the cheaper mixer wins.
- At 51.20 GB/s the loop is at or beyond typical single-thread DRAM bandwidth, so this is close to the
  memory wall. Further SIMD gains are bounded; the remaining lever is *touching the data fewer times*,
  which is what fusion does. SIMD and fusion are complementary, not alternatives.

**This invalidates the precompute conclusion in the previous section.** That section reported
precomputation as weak at long keys (305 ms for 4096 B, giving only 1.21x). The 305 ms was measured
with byte-at-a-time FNV-1a at 1.29 GB/s. The same pass with AVX-512 costs **3.73 ms — about 80x
cheaper**. Recomputing the 4096 B row honestly:

| Approach | Cost |
|---|---|
| 3 separate string joins (MSVC `std::hash<std::string>` is FNV-1a) | 1123.94 ms |
| Precompute both sides with AVX-512 (2 x 3.73) + 3 integer joins (3 x 20.87) | ~70 ms |
| | **~16x** |

Precomputing integer keys is not a marginal optimisation. It is the single largest win identified so
far, and it was invisible earlier only because the hashing primitive chosen for the measurement was
deliberately naive. The lesson generalises: **a benchmark that uses a placeholder implementation of a
hot primitive measures the placeholder, not the design.**

**The synthetic corpus hides this too.** At 36-byte keys (what `src/Synth.cpp` generates):

| Variant | ms | GB/s | vs FNV-1a |
|---|---|---|---|
| FNV-1a scalar byte | 0.63 | 2.64 | 1.00x |
| scalar 64-bit multiply | 0.14 | 11.91 | 4.51x |
| AVX2 rotate | 0.11 | 14.90 | 5.64x |
| AVX-512 rotate | 0.12 | 14.04 | 5.31x |
| AVX-512 mullo | 0.42 | 4.00 | **1.51x** |

At 36 bytes AVX-512 gains nothing over AVX2 (a 36-byte key does not fill a 64-byte vector, so the tail
path dominates) and `mullo` is actively **worse than scalar** — loading the 512-bit constants costs
more than the work saved. So the fixture is doubly unrepresentative: it understates absolute cost by
~27x and it makes SIMD look pointless.

### Dispatch design implied by these numbers

Compile-time `/arch:AVX512` is not acceptable: the binary would not run on Intel consumer parts from
Alder Lake onward, which have no AVX-512, and this tool is intended to be handed around as an exe.
Selection must be at runtime, on two axes:

1. **Feature dispatch**, resolved once at startup from CPUID plus an `XCR0` check that the OS actually
   enables ZMM state — CPU support without OS support faults. Order: AVX-512 rotate, AVX2 rotate,
   scalar 64-bit multiply.
2. **Length dispatch**, because vector setup loses below a threshold. Measured crossover is somewhere
   between 36 B (SIMD useless, `mullo` harmful) and 4096 B (SIMD 39.75x). Short keys such as
   `bytes_hash` (32 hex characters) and `kgh_hash` should stay on the scalar path; long keys such as
   `clean_assembly`, `clean_pseudo` and `clean_microcode` should take the vector path. The threshold
   needs measuring rather than guessing, and it is not yet pinned down.

On MSVC, which has no per-function `target` attribute, feature dispatch means separate translation
units compiled with different `/arch` flags behind a function-pointer resolved at init.

**Still unmeasured:** the exact short-key crossover, and whether a vetted third-party hash (XXH3,
BSD-2, which already ships SSE2/AVX2/AVX-512 paths) beats a hand-rolled rotate-xor. Given the
hand-rolled version already reaches 51.20 GB/s — at the memory wall — the expected gain is small, but
it has not been tested, and adopting XXH3 would also remove the dispatch code from this project's
maintenance surface.

### Audit: PeImage cross-checked against pefile

`PeImage` was written by a subagent that also wrote its own 302-check test suite. Self-authored tests
passing is weak evidence, so the parser was audited against `pefile` — an independent implementation
neither the agent nor this session wrote. `tools/dump_pe.cpp` emits the native parser's full view;
`tools/audit_pe_dump.py` compares it field by field.

**Result: 0 mismatches on both corpus binaries.**

| Compared | `10.0.26100.9168` | `10.0.26100.9444` |
|---|---|---|
| Header fields (machine, sections, entry point, image base, alignments, sizes, checksum, characteristics, subsystem, DLL characteristics) | all agree | all agree |
| Section count and every section field (name, VA, VSize, raw ptr, raw size, characteristics) | 6, all agree | 6, all agree |
| Export count | 1548 = 1548 | 1552 = 1552 |
| Export set as `(ordinal, rva, name)` triples | identical | identical |
| Distinct export names | 1548 | 1552 |
| Forwarders | 0 = 0 | 0 = 0 |
| Export directory (ordinal base, function count, name count) | all agree | all agree |
| RVA to offset round-trip, every export | 0 failures | 0 failures |
| CodeView age, PDB name | agree | agree |

Two findings about the audit itself:

- **`pefile` cannot validate a full CodeView GUID.** In the installed version (2024.8.26),
  `CvInfoPDB70.Signature_Data4` is exposed as a single byte, not the 8-byte field — it returned
  `0xEB` where the true Data4 is `EBBCA13F4EC0C4B1`. This also explains an earlier failure in
  `tools/prepare_corpus.py`: `bytes(int)` does not convert an integer to its bytes, it allocates a
  zero-filled buffer of that length, which is why the first attempt produced a GUID with hundreds of
  trailing zeros and a 404 from the symbol server. The audit therefore compares only the 9 GUID bytes
  pefile can actually produce, and validates the full GUID against a stronger oracle.
- **The stronger oracle is the symbol server.** The native GUID `3B99E6AC1E885968EBBCA13F4EC0C4B1`
  with age 1 is the exact key that downloaded the correct 274,432-byte `win32u.pdb`, which `dbghelp`
  then loaded reporting `SymPdb` and `pdb_unmatched=False`. A GUID that resolves the right PDB on
  Microsoft's server and satisfies dbghelp's match check cannot be wrong. Same for
  `6295787D0B7E537E98F77F31F4426D1C1`.

**Coverage gap, unchanged and still real:** win32u has zero forwarders and zero ordinal-only exports,
so both paths rest on synthetic images only. No real PE32 (32-bit) binary and no real `NB10`
(pre-RSDS) debug record has been parsed. Those are the places a latent bug would hide.

### Disassembler selection: Zydis vs Capstone

The native PE loader needs a disassembler, and the choice between Zydis and Capstone is open. How
that question was handled is worth recording because the first two approaches were both wrong.

**A second model opinion was requested and refused.** Claude Code (`claude -p`) was asked a narrowly
technical question about x86-64 decode throughput, structured operand access, and displacement
immediates, with explicit instruction to answer "no reliable data" rather than estimate. It returned:

```
API Error: Opus 4.8's safeguards flagged this message ... Details: [cyber]
```

The question was not reworded to get past the classifier. Rephrasing a request specifically to evade a
safety filter is circumvention, and it would have meant misrepresenting what this project is in order
to extract an answer. The refusal stands and is recorded here rather than worked around.

**The refusal cost nothing, because the question was mis-posed.** "Which disassembler is faster" is
empirical, not advisory. Any answer — vendor benchmark, third-party blog, or model recall — is weaker
evidence than timing both libraries on the actual workload with the actual corpus. Both are free, the
corpus already exists on disk, and the tool to measure them is a few hundred lines.

Decision: **measure, do not ask.** The evaluation will decode the `win32u.dll` corpus with each
library and report instructions/second plus the cost of the two things this project specifically needs
beyond raw decode: structured operand access, and memory-operand displacement immediates (the `0x48`
in `mov rax, [rcx+48h]`, which is how trivial struct getters are identified). Formatting cost is
measured separately, since normalized signature text is generated in-house and a vendor formatter may
be skippable.

Blocked on one unknown: `https://github.com/zyantific/zydis-disassembler.git` returns *Repository not
found*, so the correct Zydis URL is still to be confirmed. `zyantific/zycore-c` (Zydis's dependency)
resolves at `master` = `c1fa01cea7fd457dcec468104d477c8b0ca675f7`, and `capstone-engine/capstone`
resolves at `next` = `2b25a5bf77806b6507c3e54f477b69b2f3ac788b`.

### Disassembler decision: Zydis v4.1.1

Adopted **Zydis**, pinned to tag `v4.1.1` (`a2278f1d254e492f6a6b39f6cb5d1f5d515659dc`), fetched via
`FetchContent` + `add_subdirectory`. Correct repository is `https://github.com/zyantific/zydis.git` —
the `zydis-disassembler` name does not resolve, and GitHub answers renames with a 301 rather than a
404, so that name is simply not the repo.

License: MIT for both Zydis and Zycore-C. No copyleft, so the project's still-unchosen license is
unconstrained. Capstone would have been BSD-3 plus LLVM/NCSA with a REUSE layout that GitHub cannot
auto-detect — not a blocker, but more attribution surface for no benefit here.

The decision rests on API shape rather than throughput, because throughput data is five years stale.
Zydis returns decoded operands unconditionally and performs no dynamic allocation. Capstone leaves
`cs_insn.detail` NULL unless `CS_OPT_DETAIL` is enabled — the header states this explicitly and
`CS_OPT_OFF` is the default — so displacement immediates are unreachable without paying per-instruction
detail work plus a heap allocation. Since displacements are precisely what the struct-getter heuristic
needs, that asymmetry decides it. Zydis also returns granular failure codes
(`NO_MORE_DATA` vs `DECODING_ERROR` vs `INSTRUCTION_TOO_LONG`), where Capstone's iterator returns a
bare boolean; telling a truncated function tail from a genuine decode failure matters when walking
real binaries.

Traps avoided, both worth recording:

- **Capstone's default branch is an alpha presented as stable.** Branch `next` is 6.0.0-Alpha11 and the
  GitHub API reports `prerelease: false`. The maintained stable line is 5.0.9 on branch `v5`. Branch
  `master` is stale at 5.0.0 with `cmake_minimum_required(VERSION 2.8.12)`, which hard-fails on
  CMake >= 4.0 — and the local CMake is **4.2.3-msvc3**, verified, so that failure would have been
  real, not theoretical.
- **Zydis's amalgamation is a trap.** `assets/amalgamate.py` produces a single 17.5 MB / 123,022-line
  `Zydis.c`. One translation unit that large destroys compile parallelism under MSVC. The multi-file
  CMake build is both faster to compile and cleaner.
- **Zycore is a git submodule**, and Zydis's `locate_zycore()` shells out to
  `git submodule update --init --recursive` at *configure* time when `.git` is present — which breaks
  under shallow fetches. Bypassed by fetching Zycore explicitly at pin
  `75a36c45ae1ad382b0f4e0ede0af84c11ee69928` and setting `ZYAN_ZYCORE_PATH` before Zydis is made
  available. Note this pin is *not* Zycore `master` HEAD.
- `project()` had to gain the C language (`LANGUAGES C CXX`); both candidates are C libraries.
- `ZYDIS_MINIMAL_MODE` must stay OFF — `ZydisDecoderDecodeFull` is unavailable in minimal mode.
  `ZYDIS_FEATURE_ENCODER` is OFF since nothing here encodes.

### Three research claims that were wrong, caught only by compiling

The library research was delegated to a subagent and was strong on licenses, version traps and build
integration. Three API details were nevertheless wrong, and none would have surfaced without a compile:

| Claim | Reality in v4.1.1 | How caught |
|---|---|---|
| Zydis exports the alias target `Zydis::Zydis` | No `ALIAS` is declared; `add_subdirectory` consumers must link plain `Zydis`. The namespaced target exists only in the installed package export. | `CMake Error: Zydis::Zydis` at generate time |
| `mem.disp` is `{ ZyanI64 value; ZyanU8 offset; ZyanU8 size; }` | It is `{ ZyanBool has_displacement; ZyanI64 value; }` — no offset, no size | `error C2039: 'size': is not a member of ZydisDecodedOperandMemDisp_` |
| `ZydisMnemonicGetString` returns `const ZyanStaticString*` | Returns `const char*`. The wrapped variant returning `ZydisShortString*` is a separate function, `...GetStringWrapped`. | `error C4430: missing type specifier` |

The alias error is the instructive one: the same report correctly warned that Capstone has *no* in-tree
`capstone::capstone` alias, then did not apply that scrutiny to Zydis. Asymmetric verification.

Lesson recorded: **a research report is a lead, not ground truth.** Its URLs, SHAs and license claims
were checked independently and were all exactly right — `v4.1.1` = `a2278f1d...`, `master` =
`a95bb710...`, Capstone `v5` resolves. But API surface claims must be read out of the fetched headers
or compiled, not trusted. Both were done here before relying on them.

### Disassembler verification

`dsigmatcher_disasm_tests` — **67 checks, 0 failed.** Covers backend identity, `ret` decode, memory
displacement extraction, relative call immediates, truncated input (`no-more-data`), invalid 64-bit
encoding (`decoding-error` — `0x06`, `push es`, is undefined in long mode), null/empty buffers, and
linear-walk offset accumulation with full byte coverage.

The most important case is the struct-getter family, which is the whole reason displacement access was
a selection criterion:

```
four getters: same mnemonic, same length, displacements 0x48 0x50 0x58 0x0
```

Four `mov rax, [rcx+disp8]` encodings — identical mnemonic, identical 4-byte length, distinguishable
only by the displacement. This is the concrete answer to the observation that a trivial offset getter's
bytecode is determined almost entirely by its offset, so byte-hash matching on such functions is weak
evidence and the offset itself plus caller context is what actually identifies them. The primitive is
now available natively.

**Still owed:** the Zydis-versus-Capstone throughput A/B on the win32u `.text` section. The
architectural case is settled, but the speed claim rests on a 2021 benchmark on an i5-6600K and should
be re-measured rather than inherited. Blocked on the PE loader, which is what locates `.text`.

### Thread pool integration, and two measurement corrections

Agent-delivered `ThreadPool` plus a rewritten `MatchStore::Resolve` were integrated into the cascade,
replacing the wave scheduler (spawn N `std::thread`s, full barrier, repeat). The pool is persistent for
the duration of a diff and is injected into `MatchStore` via `SetPool`, so one pool serves both
heuristic execution and resolution.

Whole-cascade benchmark, 47,500 functions per side, 316,304 raw candidates, best of 3:

| | Before | After |
|---|---|---|
| Resolve, forced 1 thread | 14.90 ms | **4.65 ms** |
| Resolve, pooled | n/a | 3.18 ms |
| Cascade wall, 1 thread | 83.70 ms | 86.24 ms |
| Cascade wall, best | 38.11 ms (32T) | **26.77 ms (16T)** |
| Peak speedup | 2.20x | **3.22x** |
| Efficiency at 8 threads | 27.1% | 37.5% |
| Precision / recall | 0.9426 / 0.9426 | 0.9426 / 0.9426 |

**Best-case wall time improved 1.42x; peak speedup improved from 2.20x to 3.22x.** Accuracy is
bit-identical, and resolved counts match exactly at 1, 3, 8 and 32 threads (18,000 of 18,000 on the
20,000-function corpus), so the determinism guarantee held through the rewrite.

The largest single gain was **not** threading. Deduplicating before sorting — duplicates share
`(Index1, Index2)`, so each group's winner is computable without a global sort — cuts the sort input
from 316,304 to 69,992 and takes Resolve from 14.90 ms to 4.65 ms **at one thread**. That is a 3.2x
algorithmic win available without any parallelism at all.

Two corrections, both to my own reasoning or tooling:

1. **I told the agent the sort was the larger cost.** Measured decomposition of the original: copy
   0.57 + `stable_sort` 4.70 + max/assign 0.12 + **greedy loop 7.32 ms**. The greedy loop dominated,
   driven by `unordered_map` per-node allocation (~70k nodes) plus `reserve(2N)` zeroing a 632k-bucket
   array. The brief was wrong and the agent said so with numbers.
2. **My benchmark's "resolve (serial, unavoidable)" row was not serial.** It called `Resolve()` with no
   pool and no thread count, which resolves to `hardware_concurrency()` and constructs a 32-thread pool
   per call. The label was false and the row was measuring parallel resolution with thread-creation
   overhead. Fixed to report `Resolve(1)` and pooled resolution as two separately labelled rows.

**An integration regression I introduced and then found.** Wiring `SetPool` unconditionally made the
1-thread cascade *slower* than the old code: 83.70 ms became 105.63 ms, even though both
sum-of-heuristics and Resolve had individually got faster. Cause: with a pool injected,
`Resolve` takes the partitioned path whenever `Total >= PartitionGrain * WorkerCount`, and at
`WorkerCount == 1` that threshold is trivially met — so a single-threaded run paid for chunking,
multiple passes and per-chunk bookkeeping with no parallelism to show for it. Guarding the injection
with `if (Requested > 1)` restored 86.24 ms, confirming the diagnosis (~19 ms of pure overhead).

The general lesson is the same one the synthetic-corpus distortion produced: **a component that is
faster in isolation can be slower when wired in, and only the integrated measurement reveals it.**
Agent 2 could not run the whole cascade (its files were not in CMake), so it explicitly declined to
claim a cascade figure. That was the right call; the regression would otherwise have shipped.

**Portability landmine recorded by the agent.** A nested-parallelism bug (the calling thread also
drains the queue, so `InWorker_` was unset for it) caused batch-state corruption and a use-after-free
with exit `0xC0000409`. It did **not** deadlock because **MSVC's `std::mutex` is recursive** (backed by
`CRITICAL_SECTION`); the same bug on libstdc++ or libc++ would have hung instead of corrupting. Code
that accidentally relies on recursive mutex behaviour is silently non-portable. Fixed with an RAII
`WorkerScope` around the caller's drain, and covered by a nested-submission test.

**Residual, honestly stated:**

- The survivor sort (~0.91 ms) and greedy pass (~0.23 ms) remain serial — roughly 1.14 ms of the
  2.71 ms best case, a ~44% serial fraction at 16 threads. The agent declined to parallelise the
  greedy pass because first-fit maximal matching in a fixed order couples each decision to all
  previous ones, and it could not construct a provable exact decomposition. Reporting that rather
  than shipping a subtle nondeterminism was correct.
- Scaling is still capped by having only **8 heuristics**. Peak speedup 3.22x on 32 threads is
  consistent with that ceiling plus the serial resolve fraction. Adding the 38 remaining Diaphora
  heuristics raises the ceiling to 46 and this must be re-measured.
- 32 threads is never optimal — 16 and 24 beat it. Thread counts should be tuned, not maxed.
- Timing noise is significant: background load swung the serial baseline 15.4-21.5 ms between
  processes during the agent's work. Two post-integration runs gave 3.75x and 3.22x peak speedup.
  Treat these as approximate and re-measure before relying on small differences.
- `Raw` is nearly sorted in practice (3 ascending runs out of 316,314, since each heuristic emits in
  ascending `Index1`), which `stable_sort` exploits: 5.66 ms as-is versus 25.40 ms shuffled.
  Correctness does not depend on this, only speed, and the shuffled case still improves 4.59x.

### Realistic corpus: the synthetic benchmark was 6x too optimistic

`src/Synth.cpp` now generates text columns sized like real Diaphora exports — `clean_assembly` and
`clean_microcode` scale with instruction count (~29 B/instruction), `clean_pseudo` with pseudocode
line count (~41 B/line), `mnemonics` with instruction count. `TextBytesPerInstruction = 0` restores the
old short-token behaviour, and `dsigmatcher_bench --legacy-text` selects it, so the two regimes can be
compared reproducibly instead of by memory.

Same corpus (19,000 functions per side, 18,000 paired), only text scale changed:

| | Legacy (~36 B keys) | Realistic (KB keys) | Change |
|---|---|---|---|
| Interned text per side | 5.50 MiB | 73.32 MiB | 13.3x |
| Sum of heuristics | 24.91 ms | 151.36 ms | **6.08x** |
| Cascade wall, 1 thread | 27.80 ms | 166.92 ms | **6.00x** |
| Resolve, forced 1 thread | 1.62 ms | 1.66 ms | unchanged |
| Corpus generation | 76.7 ms | 1208.5 ms | 15.8x |

Thread scaling under realistic text (best of 3):

| threads | 1 | 2 | 4 | 8 | 16 | 24 | 32 |
|---|---|---|---|---|---|---|---|
| wall ms | 160.70 | 102.10 | 61.47 | 52.98 | 52.87 | 53.13 | 52.75 |
| speedup | 1.00x | 1.57x | 2.61x | 3.03x | 3.04x | 3.02x | **3.05x** |
| efficiency | 100% | 78.7% | 65.4% | 37.9% | 19.0% | 12.6% | 9.5% |

Precision 0.9322, recall 0.9322, 18,000 resolved identically at every thread count.

Three conclusions, one of which reverses a previous priority:

1. **`Resolve` is no longer the bottleneck.** It is 1.66 ms of a 160.70 ms serial total — about **1%**.
   The Amdahl argument that capped speedup near 5.6x was built on the legacy corpus, where Resolve was
   ~18% of the total. On realistic data that ceiling is irrelevant. Further work on parallelising
   Resolve is not where the remaining time is.
2. **The binding constraint is the heuristic count.** Speedup saturates at 3.05x with 8 heuristics, and
   efficiency at 8 threads is 37.9% because one wave of 8 items is bounded by the slowest. Implementing
   the 38 remaining Diaphora heuristics raises the scheduling ceiling from 8 to 50 and should improve
   scaling more than any scheduler tuning. **Priority inverted: more heuristics before more threading.**
3. **All of the 6x cost increase is in the text-keyed joins.** Resolve, which never touches text, is
   unchanged. That confirms fusion and integer-key precomputation target precisely the right code, and
   that the earlier 3.2x fusion figure was measured in the regime that actually matters.

### The regression guard earned its keep

Making the corpus realistic silently destroyed the ambiguity fixture and precision snapped back to
`1.0000` — the exact meaningless value the guard was written to prevent. `CHECK(Precision < 0.999)`
failed the build immediately.

Cause: `MakeListing` derives output length from `Item.Instructions`, which was randomised per function.
Members of an "ambiguous" group therefore shared a seed but produced different-length strings, so they
were no longer identical and each matched uniquely. The legacy short tokens were length-independent,
which is why the bug did not exist before. Fixed by deriving `Instructions`, `Nodes` and `PseudoLines`
for ambiguous functions from the **group index** rather than the individual function, so group members
are genuinely indistinguishable.

After the fix: precision 0.9314 with 247 false positives at 3,800 functions, 0.9322 with 1,221 false
positives at 19,000 — consistent, and consistent with the analytical expectation for a 10% ambiguous
bucket at group size 6.

This is the third time in this session that a fixture quietly leaked or lost the property a test was
supposed to exercise. The pattern is worth stating: **a test that asserts a number derived from the
same generator it is testing can pass for the wrong reason in both directions** — too perfect, or too
imperfect. Assertions that bound the *shape* of the result (`precision < 0.999`) catch what assertions
on the value alone do not.

### MD5, and a stale-binary trap worth recording

Diaphora computes `bytes_hash` and `function_hash` as MD5 digests (`diaphora_ida.py:2977-2978`), so
exact replication requires an MD5 implementation. Added `include/dsigmatcher/Md5.h` and `src/Md5.cpp`,
self-contained like the existing SHA-256, no external dependency.

Verified two independent ways:

- All eight **RFC 1321** vectors, including the empty string, the 62-character mixed-case alphanumeric
  case, the 80-digit case, and 1,000,000 x `'a'`.
- Cross-checked against Python's `hashlib.md5` on five inputs; all five agree exactly.

The padding logic gets its own coverage because that is where streaming hash implementations break:
99 chunked-versus-single-shot comparisons across 11 input lengths chosen to straddle the 55/56/64-byte
padding boundaries (54, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128) at 9 different chunk sizes. A
separate assertion confirms 56-byte and 64-byte inputs of identical content hash differently, which is
what proves the bit length is actually encoded into the padding. Note MD5 appends the length
**little-endian**, unlike SHA-256's big-endian — an easy place to silently diverge.

The unit suite is now **192 checks, 0 failed**, up from 82.

**Process failure caught during this increment.** A build failed on a compile error, but the chained
command used `&` rather than `&&`, so `ctest` and the test executable still ran — against the
**stale binaries from the previous successful build**. Output read `100% tests passed, 0 tests failed
out of 4` and `82 checks, 0 failed`, i.e. an unambiguously green result on a tree that did not compile.

Only the `FAILED:` line from the build step revealed it. Had that line been filtered out, a broken
commit would have been reported as passing. Two rules follow and are now applied:

1. Chain build and test with `&&`, never `&`, so a failed build cannot reach the test step.
2. Treat a check count that does not move as a signal. The suite had grown by 110 checks; seeing 82
   was the tell that an old binary had run. **A test run whose assertion count does not match
   expectation is evidence about the build, not about the code.**

The underlying compile error was `std::string(1000, "abcdefghij")` — the `(count, char)` constructor
cannot take a `const char*`. This is the second time this exact mistake pattern appeared in test code
in this session (the first was in a SHA-256 chunked-update test), which suggests it is worth being
suspicious of any `std::string(count, literal)` construction on review.

### Koret-Karamitas hash: exact port, and why it needs bignums

Ported `kgh_hash` from `jkutils/graph_hashes.py`. The algorithm multiplies a set of primes, one per
structural feature, and returns `str(hash)` — where `hash` is a **Python arbitrary-precision integer**.
That is why the schema stores `kgh_hash` as TEXT: for a large function the value is thousands of decimal
digits. Any fixed-width accumulator would silently wrap and produce signatures that never match.

All 13 factors are prime, which makes the hash exactly a multiset of exponents:

| Feature | Prime | | Feature | Prime |
|---|---|---|---|---|
| `NODE_ENTRY` | 2 | | `FEATURE_CALL_REF` | 31 |
| `NODE_EXIT` | 3 | | `FEATURE_STRONGLY_CONNECTED` | 37 |
| `NODE_NORMAL` | 5 | | `FEATURE_FUNC_NO_RET` | 41 |
| `EDGE_IN_CONDITIONAL` | 7 | | `FEATURE_FUNC_LIB` | 43 |
| `EDGE_OUT_CONDITIONAL` | 11 | | `FEATURE_FUNC_THUNK` | 47 |
| `FEATURE_LOOP` | 19 | | | |
| `FEATURE_CALL` | 23 | | | |
| `FEATURE_DATA_REFS` | 29 | | | |

So `KghAccumulator` stores 13 `uint64_t` counters and does **no bignum arithmetic while walking a
function** — accumulation is integer increments. `BigUInt` (base 10^9 limbs, binary exponentiation via
`Power`) is only touched once, at render time. That keeps the hot path free of arbitrary-precision
math while remaining bit-exact.

Per-block contribution, from `get_node_value` and `get_edges_value`: `NODE_ENTRY` when a block has no
predecessors, `NODE_EXIT` when it has no successors, `NODE_NORMAL` always, plus
`EDGE_OUT_CONDITIONAL`^successors and `EDGE_IN_CONDITIONAL`^predecessors. The source notes that as of
Nov 2018 *all* edges are treated as conditional, and the unconditional constants 13 and 17 are
deliberately unused — replicated as-is rather than "improved".

### Oracle-based verification, and a bug only a digest could catch

Test vectors were generated by `tools/kgh_vectors.py` using **Python's own bignums**, so the expected
values come from the reference implementation's arithmetic rather than from the code under test. Nine
cases, from all-zero exponents through a realistic five-block function up to `47^100000`.

The first run failed 12 assertions — and the failure pattern immediately localised the bug: **every
digit count was correct, every MD5 digest was wrong.** `BigUInt::ToDecimalString` iterated
`Index = size; Index-- > 1;` after already emitting `Limbs_.back()`, so it re-rendered the top limb and
skipped limb 0. Output length was identical; content was shifted by one limb.

That is the reason the vectors compare digests rather than lengths: **a digit count cannot distinguish
a correct bignum from a shifted one.** Comparing only magnitude would have shipped a renderer that
produces wrong `kgh_hash` values of exactly the right length — the worst kind of failure for a
signature-matching tool, since it would look correct and never match anything.

After the fix: **244 checks, 0 failed**, including the 167,210-digit `47^100000` stress case whose MD5
matches Python's exactly. `BigUInt` also has direct coverage of limb-base boundaries (`999999999`,
`1000000000`), carry propagation (`999999999^2`), 64-bit overflow cases (`2^64`), repeated
`MultiplySmall` versus `Power` agreement, and both zero-operand orders.

Separately caught during test authoring: `std::string("5" "121" "343")` is C++ adjacent-literal
concatenation, producing `"5121343"` — not the intended `5 * 121 * 343 = 207515`. The assertion was
wrong before the code was. Worth remembering that concatenated string literals compile silently.

### Four Partial heuristics: 8 of 50 becomes 12

Added `Same KOKA hash and MD-Index`, `Same constants`, `Same rare KOKA hash` and `Same rare MD Index`,
transcribed from `diaphora_heuristics.py` rather than reconstructed from memory. `MatchCategory` is now
carried per heuristic in the definition table instead of being hardcoded to `Best`, and the
`functions.constants` text column is ingested.

Three details that re-reading the source caught, each of which would have produced plausible but wrong
behaviour:

1. **Rarity is per-database, not combined.** The CTE is `count(*) <= 2` within `diff.functions`
   `UNION` `count(*) <= 2` within `main.functions`. A value appearing 5 times in one database and once
   in the other **is** rare. A combined count across both would give 6 and exclude it. Implemented as
   `rareInReference || rareInTarget`.
2. **The node thresholds apply to the reference side only** — `f.nodes > 5` and `f.nodes > 10`, with no
   corresponding `df.nodes` condition. A symmetric reading would silently drop valid matches.
3. **`kgh_hash != 0` and `md_index != 0` are effectively no-ops in SQLite.** Both columns are TEXT, and
   SQLite's type ordering places every INTEGER before every TEXT, so a TEXT value is never equal to the
   integer `0` and the inequality is always true (for non-NULL). I implemented the evident *intent* —
   skip empty and the literal string `"0"` — rather than the accidental behaviour, because for
   `kgh_hash` the distinction cannot arise anyway (it is a product of primes, so at minimum `"1"`).
   **This is a deliberate divergence, recorded here, and unverified against a real export.**

Not replicated, and flagged rather than papered over: Diaphora's `ORDER BY f.source_file =
df.source_file` feeds its graded ratio assignment, and `HEUR_TYPE_RATIO_MAX` heuristics carry a `min`
threshold (`0.5`, `0.45`, `0.2`). This implementation uses a binary unique-or-ambiguous ratio of 1.0 or
0.5, so those minimums would never bind. Adding the parameters now would be dead code. The graded
similarity function (`compare_function_rows`) is a named follow-up; until it exists, `Partial` matches
are coarser than Diaphora's.

Measured impact at 19,000 functions per side, realistic text scale, 12 heuristics:

| Heuristic | ms | Raw matches |
|---|---|---|
| Same cleaned microcode | 49.44 | 27,992 |
| Same cleaned assembly | 48.97 | 26,577 |
| Same cleaned pseudo-code | 38.24 | 26,359 |
| Same rare KOKA hash | 13.50 | 6,954 |
| Same rare MD Index | 11.27 | 1,924 |
| Same KOKA hash and MD-Index | 7.17 | 9,022 |
| Same constants | 7.07 | 22,992 |
| Same RVA and hash | 6.36 | 10,012 |
| Same order and hash | 4.82 | 11,000 |
| Function Hash | 4.88 | 11,000 |
| Bytes hash | 3.86 | 11,000 |
| Same address and mnemonics | 3.34 | 4,410 |
| **sum** | **198.92** | 171,307 |

Two things worth carrying forward:

- **The three text-keyed heuristics are 136.65 ms of 198.92 — 69% of total heuristic time.** That is a
  direct measurement of where fusion and integer-key precomputation should be aimed, and it is why the
  four new heuristics are comparatively cheap: their keys are 32 hex characters or ~52 bytes, not
  kilobytes.
- `sum of heuristics` (198.92 ms) now essentially equals `serial wall` (196.32 ms), where the wave
  scheduler previously showed a 55 ms gap. The persistent pool removed the scheduler overhead.

Precision 0.9322 and recall 0.9322 are unchanged from the 8-heuristic configuration, and the resolved
count is still exactly 18,000. The new heuristics add raw candidates without changing outcomes on this
corpus, which is expected: on synthetic data the exact-hash tier already resolves everything the
`Partial` tier can. **They will only earn their keep on real binaries where recompilation breaks the
exact hashes** — so this is not yet evidence about their value, only about their correctness and cost.

The heuristic count rising from 8 to 12 also raises the heuristic-level parallelism ceiling by half.
The earlier conclusion that scaling is capped by heuristic count predicts better thread scaling now;
that has not been re-measured.

### Diaphora signature fields: source-verified extraction

A research pass over `diaphora_ida.py`, `diaphora.py`, `jkutils/` and the local IDA 9.2 Python bindings
established exactly how each signature field is computed. These are the rules the native exporter must
reproduce, and several are counter-intuitive enough that implementing from assumption would fail
silently.

**1. The operand-truncation normalization is dead code.** `get_decoded_instruction`
(`diaphora_ida.py:2596-2605`) subtracts `ins.ops[0].offb` and `ins.ops[1].offb` from the decoded length
for `o_mem/o_imm/o_far/o_near/o_displ` operands — clearly intended to strip relocated operand bytes so
a moved function still hashes identically. But `process_basic_block` binds `decoded_size` at line 2828
and **never reads it again**; only `ins` is forwarded. `process_instruction` then recomputes at line
2729:

```python
decoded_size = ins[1] if isinstance(ins, tuple) else ins.size
```

`ins` is an `insn_t`, never a tuple, so this is always `ins.size` — the raw decode length. The tuple
branch is a vestige of an older call convention. **Consequence: `bytes_hash` is relocation-sensitive,
not relocation-invariant.** Implementing the truncation because it looks live would make every
`bytes_hash` differ from a real Diaphora export.

This connects directly to the win32u measurement: 76% of functions changed address between those two
builds, and RIP-relative operands encode a delta, so their bytes change too. Exact-hash heuristics will
miss most moved functions on a real corpus. That is *why* the text and structural heuristics carry the
load, and it is a property of Diaphora itself, not of this port.

**2. `curr_bytes` versus `function_hash_bytes` differ only in length source.**
`curr_bytes = get_bytes(ea, ins.size)`; `function_hash_bytes = get_bytes(ea, get_item_size(ea))`. For an
ordinary code head these are identical. They diverge when the head is not a plain instruction —
`Heads()` yields data items interleaved with code, and for those `decode_insn` gives 0 or garbage while
`get_item_size` gives the real item size. Note the asymmetric guard: only `curr_bytes` is
length-checked (line 2731); a short or `None` read for `function_hash_bytes` would propagate into the
`b"".join(...)` at line 2978.

**3. `FlowChart` block order is the one blocking unknown.** Both hashes concatenate per-instruction
bytes in `FlowChart(func)` iteration order, not address order. Block 0 is the entry block; the rest
follow `qflow_chart_t`'s internal index order, which is native IDA C++ and **not visible in the Python
bindings**. Within a block, order is ascending (`Heads(start, end)`). A native implementation walking
blocks in address order will diverge on any function whose flow-chart order is not address order.
**This must be pinned empirically against a real export before byte-exactness can be claimed.**

**4. `md_index` is 28-digit decimal, not floating point.**

```python
rt2, rt3, rt5, rt7 = (decimal.Decimal(p).sqrt() for p in (2, 3, 5, 7))
emb_tuples = (sum((z0, z1*rt2, z2*rt3, z3*rt5, z4*rt7)) for z0,z1,z2,z3,z4 in tuples)
md_index = sum((1 / emb_t.sqrt() for emb_t in emb_tuples))
md_index = str(md_index)
```

Per edge a 5-vector `(scc_ordinal, src_in, src_out, dst_in, dst_out)` is embedded with √2, √3, √5, √7
weights, then `md_index = Σ 1/√embedding`. Everything is `decimal.Decimal` under **Python's default
context: 28 significant digits, `ROUND_HALF_EVEN`**. There is no `setcontext` anywhere in the
checkout. Computing in `double` and formatting will not reproduce it — intermediate rounding at every
`sqrt`, multiply, divide and the final `sum` all matter. `str(Decimal)` can emit scientific notation.

Degenerate cases are **inconsistently typed**: a falsy `bb_topological` returns the *integer* `0`
(never `str()`-ed, so SQLite INTEGER), while a truthy one with no edges returns `sum(())` → `str(0)` →
the *string* `"0"` (TEXT). Same column, two storage classes, depending on the path taken.

**5. Cyclomatic complexity double-counts edges.** `cc = data['edges'] - data['nodes'] + 2`, but
`edges` is incremented once per successor edge (line 2895) *and* once per predecessor edge (line 2921).
In IDA 9.x both `succs()` and `preds()` are always populated (`FC_PREDS = 0`), so `edges ≈ 2E` and
`cc ≈ 2E − N + 2`. Not the textbook formula. `primes_value = str(primes[cc])`, or the **integer** `0`
via a bare `except` when `cc` is out of range.

**6. `indegree` and `outdegree` are semantically backwards — reproduce as written.** Stored `outdegree`
is (non-flow code refs over all instructions) + (predecessor-block edge count). Stored `indegree` is
seeded from `len(list(CodeRefsTo(f, 1)))` then incremented once per *successor* edge. The comment in
the source does not flag this; it is simply what the code does.

**7. Two different prime tables, easy to conflate.**

| Used by | Table | Size | Index basis |
|---|---|---|---|
| `mnemonics_spp`, `primes_value`, `strongly_connected_spp`, `microcode_spp`, `callgraph_primes` | `primesbelow(2048*2048)` | **295,947** primes, last `[4194277, 4194287, 4194301]` | position in `sorted(GetInstructionList())`, or SCC size, or `cc` |
| `pseudocode_primes` | `primesbelow(4096)` | **564** primes, last `[4079, 4091, 4093]` | Hex-Rays ctree opcode **enum value**, not a name position |

`mnemonics_spp` is the most version-fragile field in the schema: the index is a position in the
*sorted* processor-module instruction name table, so IDA adding one instruction alphabetically early
shifts every subsequent prime and changes every `mnemonics_spp` in the database. Unknown mnemonics
contribute a factor of 1 **silently** in the assembly path (the microcode path logs a warning).

**8. Integer-to-SQLite typing depends on magnitude.** `diaphora.py:719-727`:

```python
if isinstance(prop, int) and (prop > 0xFFFFFFFF or prop < -0xFFFFFFFF):
    prop = str(prop)
```

So `mnemonics_spp`, `strongly_connected_spp` and `bytes_sum` are stored as **TEXT decimal strings when
large and as SQLite INTEGER when small** — same column, two storage classes. `mnemonics_spp` exceeds 32
bits after a handful of instructions so it is TEXT in practice, but `strongly_connected_spp` (1 for
most acyclic functions) and `bytes_sum` for tiny functions are INTEGER. A reader that assumes one type
will silently mis-parse. Note `callgraph_primes` is a `Decimal` *product*, so unlike the exact bignum
`kgh_hash` it is **rounded at 28 digits** after only a few functions.

**9. `constants` is a JSON array with specific formatting.** `json.dumps(list, ensure_ascii=False)`
with **default separators** — `", "` between elements. Integers in base 10 via Python `repr`. Order is
extraction order (flow-chart block order, then ascending address, then operand order), **not sorted**.
Strings are deduplicated; **integers are not**. `constants_count` is `len()` of the unfiltered list.

Extraction rules: `o_imm` → `operand.value` gated by both `is_constant` (value not in
`DataRefsFrom(ea)`) and `constant_filter`; `o_displ` → `operand.addr` gated by `constant_filter`
**only**. `constant_filter` rejects values `< 0x1000`, rejects the four sign-extension masks
(`0xFFFFFF00`, `0xFFFF00`, `0xFFFFFFFFFFFFFF00`, `0xFFFFFFFFFFFF00`), and rejects every single-bit
value across 64 bits. Strings come from `DataRefsFrom` targets outside any function via
`get_strlit_contents(ea,-1,-1)`, decoded UTF-8 with `backslashreplace`.

Two quirks: the `drefs` string block sits **inside** the `for operand in ins.ops` loop, so it runs once
per operand rather than once per instruction — invisible only because strings are deduplicated. And the
separate `constants` **table** drops strings of 4 characters or fewer (`diaphora.py:990`) while the JSON
column retains them, so the two representations of "the constants of this function" genuinely differ.

**10. `mnem` is verbatim `print_insn_mnem`** — no `.lower()`, no `.strip()`, casing is whatever the
processor module emits. `GetDisasm` output (colour tags, comment style, operand digit formatting) is
IDA-version and options dependent and feeds `assembly`/`clean_assembly`.

**11. Microcode is off by default on large databases.** `export_microcode` defaults to
`total_functions <= MIN_FUNCTIONS_TO_CONSIDER_MEDIUM` where that constant is **8001**, so any database
larger than 8001 functions exports `microcode_spp = 1` and no microcode text. This matters for the
win32u corpus (~1500 functions, so microcode would be on) versus anything larger.

**No config flag alters** `bytes_hash`, `function_hash`, `bytes_sum`, `md_index`, `constants`,
`primes_value` or `mnemonics_spp`. The only `IDA_SDK_VERSION` guard in the exporter selects PySide6
versus PyQt5 and does not affect hashing.

### What this means for the native exporter

Byte-exact agreement with a real Diaphora export is **not yet achievable**, for one concrete reason:
the `FlowChart` block ordering is native IDA C++ and was not determined. Everything else above is
specified precisely enough to implement. The plan is therefore:

1. Implement the prime tables, `bytes_sum`, `mnemonics_spp`, `primes_value`, `strongly_connected_spp`,
   `constants` extraction and JSON serialization, and the `md_index` decimal arithmetic — all fully
   specified.
2. Implement `bytes_hash`/`function_hash` with block traversal order as an **explicit, named
   assumption** rather than a hidden one, defaulting to address order.
3. Pin the ordering empirically the first time a real Diaphora export is available, by comparing
   per-function hashes and, where they differ, testing whether a flow-chart order hypothesis explains
   the divergence.

`md_index` additionally depends on `others/tarjan_sort.py` for the SCC *ordinal* assignment that feeds
`z0`; that module was identified but not read. If `md_index` diverges while everything else matches,
that is the place to look.

### Prime tables implemented and oracle-verified

`PrimeTable` (`include/dsigmatcher/PrimeTable.h`, `src/PrimeTable.cpp`) reproduces
`jkutils/factor.py:primesbelow(N)` — a sieve returning primes `2 <= p < N` ascending — for both limits
Diaphora uses, as lazily-initialised singletons (`Main()` = 4194304, `Pseudocode()` = 4096).

Expected values were taken from **Diaphora's own `primesbelow`** via `tools/prime_vectors.py`, not from
a reimplementation, so the oracle is the reference code itself. It confirmed the research report's
figures exactly: 564 primes below 4096, 295,947 below 4194304, last three `[4079, 4091, 4093]` and
`[4194277, 4194287, 4194301]`.

Verification is layered rather than spot-check only:

- Oracle probes at indices 0-7, 10, 47, 100, 1000, 10000, 100000 and the last three, for both tables.
- **Exhaustive** trial-division cross-check of the 4096 table: every integer below 4096 is tested for
  primality and compared against the table position by position, catching both composites admitted and
  primes omitted.
- For the 4194304 table (too large for exhaustive checking in a unit test), 512 sampled entries are
  trial-divided for primality, and every integer *between* each sampled adjacent pair is checked to be
  composite — which catches skipped primes, the failure mode a pure spot-check misses.
- Out-of-range `At()` returns 0 rather than reading past the end, and the prefix of `Main` is asserted
  equal to all of `Pseudocode`.

Unit suite now **290 checks, 0 failed**.

Not yet built on top of these tables: `mnemonics_spp`, `primes_value`, `strongly_connected_spp` and
`microcode_spp`. Each needs inputs the native exporter does not yet produce — the processor module's
sorted instruction-name list for the first, the double-counted edge total for the second, SCC sizes for
the third, and Hex-Rays microcode for the fourth. `microcode_spp` in particular may be unreachable
natively at all, since it indexes `dir(ida_hexrays)` names; that is an open scope question rather than
an implementation task.

### Audit pass

A deliberate audit of the whole tree, run while the CFG work was in flight. It found one semantic bug,
a documentation error that had propagated into the public README, and a scope claim that was wrong in
the flattering direction.

**1. I had the Diaphora counts wrong, publicly.** The README and this journal both said **46
heuristics** and **48 columns**. The real numbers are **50** and **49**, confirmed two independent
ways: `HEURISTICS.append` appears 50 times and there are 50 `NAME =` assignments; the column count
comes from materialising Diaphora's own `TABLES` list in SQLite and reading `pragma
table_info(functions)`.

The error traced back to an early grep over a truncated view of `diaphora_heuristics.py` whose count I
never verified against `HEURISTICS.append`. It then propagated into nine places across two documents,
including a category breakdown that did not sum to its own stated total (12 + 30 + 8 = 50, not 46) —
an arithmetic inconsistency sitting in plain sight in a table I had written.

`tools/schema_coverage.py` now derives both numbers from Diaphora's source at run time, so the counts
in prose can be re-checked rather than trusted. Lesson: **any count quoted in documentation should be
generated, not typed.**

**2. A scope claim was wrong in the flattering direction.** The README said "all eight `Best`-category
exact heuristics", which reads as though `Best` were complete. `Best` has **twelve**; four are missing:

- *Same address, nodes, edges and mnemonics*
- *Same RVA*
- *Equal assembly or pseudo-code*
- *Microcode mnemonics small primes product*

Reworded to "eight of the twelve". Understating remaining work is the more dangerous direction of
documentation error, because it is the one nobody complains about.

**3. Schema coverage is 55.1%.** 27 of 49 `functions` columns are ingested. That is sufficient for the
12 implemented heuristics and insufficient for the remaining 38. Not ingested: `names`, `prototype`,
`primes_value`, `comment`, `pseudocode`, `pseudocode_hash1/2/3`, `pseudocode_primes`,
`function_flags`, `assembly`, `prototype2`, `tarjan_topological_sort`, `strongly_connected_spp`,
`mnemonics_spp`, `switches`, `bytes_sum`, `assembly_addrs`, `userdata`, `microcode`,
`microcode_spp`, `export_time`. Twelve supporting tables (`instructions`, `basic_blocks`,
`bb_relations`, `bb_instructions`, `function_bblocks`, `callgraph`, `constants`,
`compilation_units`, `compilation_unit_functions`, `program_data`, `program`, `version`) are not read
at all beyond `program`. Recorded so it is a known boundary rather than a surprise.

**4. Semantic bug in `port`: names that never travelled were counted as ported.** When the target
already carried the *identical* portable name, the skip guard

```cpp
if (!OverwriteExistingNames && IsPortableSymbol(TargetName) && TargetName != ReferenceName)
```

did not fire, because the final conjunct is false. The name was then "applied" — a no-op `UPDATE` —
counted in `NamesApplied`, given a fresh `dsig_name_origin` row with `hops = parent + 1`, and had its
`cumulative_ratio` multiplied by the match ratio. Three consequences: the applied metric was inflated,
the hop counter overstated staleness for a name that was never inferred, and confidence decayed for no
reason.

Fixed by treating an identical portable name as a **confirmation**, checked before hop and ratio
computation: no `UPDATE`, no origin row, no hop increment, counted separately in `NamesConfirmed`.
Covered by a new fixture function whose name is identical in every version; the chain test now asserts
`Matches == 4`, `NamesApplied == 3`, `NamesConfirmed == 1`, `NamesSkippedExisting == 0`.

`NamesConfirmed` is reported but **not persisted** into `dsig_provenance` — adding a column would
change the provenance schema for databases already labelled. Deliberate scope decision; the persisted
`names_applied` is now accurate, which was the actual defect.

**5. Clean-slate build verified.** Deleted `build/` entirely and reconfigured: `FetchContent`
re-fetched Zycore at its pin and Zydis at tag `v4.1.1`, configured in 22.3 s, built every target with
zero `/W4` warnings, 4/4 suites pass. A fresh clone builds.

**6. Repository hygiene.** `git ls-files` filtered for `.pdb`, `.dll`, `.sqlite`, `.exe`, `.obj`,
`.lib`, `.pyc`, `__pycache__` and `build/`: nothing matched. No binaries, no build output, no Microsoft
corpus files tracked.

Unit suite now **293 checks, 0 failed**.

**Not covered by this audit**, stated so the absence is not mistaken for assurance:

- No sanitiser run. `/RTC1` is Debug-only and this is a Release build; no ASan, no `/analyze`, no
  fuzzing. `PeImage` parses untrusted input and has only targeted malformed-case tests.
- `PeImage` forwarder and ordinal-only export paths remain exercised **only** by synthetic images —
  win32u has neither.
- The 12 implemented heuristics have never been compared against Diaphora's actual output on the same
  input. Correctness so far means "matches the SQL I transcribed", not "matches Diaphora".
- No measurement of memory high-water mark. The realistic corpus interns 73 MiB per side at 19,000
  functions; at 200,000 functions that scales to roughly 770 MiB per side and has not been tested.

### Bug fix: in-place `port` destroyed the target database and reported success

`PortSymbols` begins by copying the target database to the output path:

```cpp
CopyFileBinary(Options.TargetPath, Options.OutputPath)
```

`CopyFileBinary` opens the destination with `std::ios::trunc`. When the output path **is** the target
path — `dsigmatcher port ref.sqlite target.sqlite -o target.sqlite` — the destination is truncated to
zero before the source is read. The copy "succeeds", the subsequent `sqlite3_open_v2` with
`SQLITE_OPEN_CREATE` creates a fresh empty database, the provenance tables are added to it, the
transaction commits, and `PortSymbols` returns `Ok = true`.

**Net effect: the user's target database is destroyed and the tool exits 0.** In-place porting is an
entirely natural thing to try — "update this database with the new labels" — so this was reachable by
ordinary use, not by adversarial input.

Confirmed by test before fixing, not inferred. The failing run showed:

```
FAIL  !InPlaceResult.Ok
FAIL  TargetAfter == TargetBefore
FAIL  std::filesystem::file_size(Target) == TargetSizeBefore
FAIL  Reload.Ok
FAIL  Survivor.Count() == 4
```

`InPlaceResult.Ok` was **true** and the target was left unparseable. Every later case in the suite then
cascaded into `table 'functions' is missing`, including the valid-port case, which is how one
destructive alias turned into nine failures.

**Fix.** All three paths are canonicalised with `std::filesystem::weakly_canonical` and compared before
any I/O; the operation is rejected with a specific error if the output resolves to either input.
`weakly_canonical` is what makes this robust — it resolves `.\` segments, so the alias
`dir\.\safety_target.sqlite` is caught as the same file as `dir\safety_target.sqlite`. A purely textual
comparison would have missed it. `CopyFileBinary` also gained a defensive same-file check so the
primitive cannot be misused by a future caller.

Covered by `TestPortPathSafety`, which asserts the rejection *and* that the target survives bit-for-bit
(SHA-256 and file size before and after) *and* that it still loads with the right row count. Four cases:
output equals target, output equals reference, output equals target through a `.\` alias, and output in
a nonexistent directory (which already failed cleanly, now asserted rather than assumed).

A fixture bug surfaced while writing that test: reference and target were built from the same row set,
so every name matched exactly and `NamesApplied` was legitimately 0 while the assertion expected
positive. The fixture now gives the reference real names and the target `sub_` names for three of four
functions, leaving one identical to exercise the confirmation path. Assertions are now exact:
`Matches == 4`, `NamesApplied == 3`, `NamesConfirmed == 1`, and the ported name is read back out of the
output database to confirm it actually landed.

Unit suite **316 checks, 0 failed**; 4/4 ctest suites pass.

**Still unguarded, noted rather than fixed:** `diff -o <path>` where the path equals one of the inputs
will add `matches` and `symbols_to_port` tables to that input. It does not truncate or destroy anything
— the existing `functions` rows survive — so it is a surprise rather than data loss, but it does mutate
a file the user passed as read-only input. Same canonicalisation should be applied there.

### Continuous integration across three toolchains

`.github/workflows/ci.yml` builds and tests on Ubuntu/GCC, Windows/MSVC and macOS/Clang for every push
to `main`, every tag, and every pull request.

**The reason this exists is portability, not convenience.** Everything so far has been verified on one
toolchain — MSVC 19.51 on Windows x64. The thread-pool work already produced a concrete warning about
that: a nested-`ParallelFor` use-after-free did not deadlock locally **only because MSVC's `std::mutex`
is recursive**, being backed by `CRITICAL_SECTION`. The identical code on libstdc++ or libc++ would have
hung instead of corrupting state. That class of bug is structurally invisible from this machine, and a
Linux job is the only way to see it.

Secondary benefit: it removes the "did I remember to rebuild" failure mode, which produced a genuinely
misleading green result earlier in this session when a broken build was tested through stale binaries.

**Prerequisite that had to be resolved first.** The `kuro1337WStuff` OAuth token carried
`gist, read:org, repo` and no `workflow` scope. GitHub does not merely decline to run a workflow in that
case — it **rejects the entire push** that touches `.github/workflows/`. Committing one prematurely
would have broken every subsequent push until it was removed. Scope added via
`gh auth switch --user kuro1337WStuff` then `gh auth refresh -h github.com -s workflow`, then switched
back; `gh auth refresh` has no `--user` flag and only operates on the active account.

**Coverage caveat, stated plainly.** `dsigmatcher_pe_tests` runs 302 checks with the win32u corpus
present and **198 without it** — 104 checks, including every assertion against a real Microsoft binary
and the CodeView GUID cross-check, only run where the corpus exists. CI runners have no corpus, so CI
covers 198. The synthetic PE images still exercise the malformed-input and forwarder paths. Verified
locally by configuring with `-DDSIG_CORPUS_ROOT` pointing at a nonexistent directory: exit code 0,
`198 checks run, 0 failed, 2 suites skipped`.

That corpus path also drove a small design change. The test originally hardcoded
`C:\Users\Loki\dsig-corpus\...` — a personal absolute path in published source, which both leaked a
username and made the real-binary tests unrunnable for anyone else. It is now a CMake cache option
`DSIG_CORPUS_ROOT` defaulting to the repo-relative `corpus/`, which `.gitignore` already excludes. An
environment variable was the first attempt and was rejected: MSVC flags `getenv` as C4996, and this
project holds a zero-warning line, so the options were a platform-specific `_dupenv_s` branch, a
blanket `_CRT_SECURE_NO_WARNINGS`, or configure-time injection. The last is portable across all three
CI compilers and keeps the source clean.

**Deliberately not enabled: `-Werror`.** GCC and Clang warn on things MSVC does not, so treating
warnings as errors would likely fail the first CI run for reasons unrelated to correctness. The plan is
to run clean once, review whatever the other two compilers report, fix the real findings, and only then
add `-Werror`. Enabling it before knowing what it catches would just produce a red badge and pressure
to suppress rather than fix.

Also not enabled: dependency caching for the `FetchContent` Zydis/Zycore fetch, and any lint or
sanitiser job. Both are worth adding; neither is worth adding before the three-platform build is known
to be green.

### Not yet done

- 38 remaining heuristics: 4 `Best`, 26 `Partial`, 8 `Unreliable`
- Constants and call-graph matching; call-graph match propagation
- Fuzzy/LSH candidate generation, bounded edit-distance verification, maximum-cardinality assignment
- Native PE loader and disassembler — this is what removes the IDA dependency, and it is the gate on
  benchmarking without manual export steps
- Scoring against the win32u ground truth; the `.sqlite` exports do not exist yet
- Persistent thread pool and parallel `Resolve`

### Caveats that should not be forgotten

- Nothing has yet run against a **real** Diaphora export. All accuracy figures come from synthetic
  data whose properties were chosen by the same code being tested. The win32u pair exists but has not
  been through IDA.
- The synthetic corpus is 55% byte-identical functions. Real patched binaries have far fewer exact
  matches, so the exact-hash tier will do much less work and the expensive fuzzy stages will dominate
  — the opposite of what these timings measure.
- No comparison against Diaphora itself has been run. No claim of parity is yet supported by
  measurement.
