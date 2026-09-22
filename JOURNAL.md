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

- **Schema** (`db_support/schema.py`): `functions` has 48 columns; 11 supporting tables. The full
  column set is the ingest contract.
- **Cascade** (`diaphora_heuristics.py`): 46 heuristics, 3 categories — `Best` (12), `Partial` (30),
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

**Important caveat on finding 5.** Only 8 of Diaphora's 46 heuristics exist so far. Once the
`Partial` (30) and `Unreliable` (8) categories land, the heuristic-level ceiling rises to 46 and this
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

### Not yet done

- 38 remaining heuristics (`Partial`, `Unreliable` categories)
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
