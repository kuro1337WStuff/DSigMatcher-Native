# DSigMatcher-Native

**A native C++ binary diffing engine — Diaphora parity, recoded from scratch for speed.**

DSigMatcher-Native does the job [Diaphora](https://github.com/joxeankoret/diaphora) does: take two versions of a binary, determine which function in the new build corresponds to which function in the old build, and then **move names and symbols across** so that a stripped, recompiled, or freshly patched target inherits the annotations that already exist in the reference build.

What differs is the implementation. Diaphora is Python driving a SQLite database that an IDA plugin exported. DSigMatcher-Native is a single native C++ executable — no interpreter, no serialization round-trip, no GIL — with a matching pipeline engineered so the dominant cost scales with the size of the input instead of the square of the function-pair count.

The target is simple: same inputs, same matches, same ported symbols, in a fraction of the wall-clock time.

---

## Why

Function-level binary diffing is the load-bearing step in patch analysis. You have a build with symbols and a build without them, or two builds where only one has been reversed, and you need to transfer what you know from one to the other. The naive formulation is a maximum-weight bipartite matching over `n × m` function pairs, which is `O(n·m)` candidate generation before you have even scored anything — and on a large binary that is hundreds of thousands of pairs.

Diaphora solves this with a staged heuristic cascade and it works well. DSigMatcher-Native keeps the staged cascade, because the staging is the genuinely good idea, and attacks the constant factors and the asymptotics underneath it:

- **Candidate generation is index-driven, not pair-driven.** Functions are bucketed by signature, and only functions that land in a related bucket are ever compared. The `O(n·m)` term never materializes.
- **Every similarity measure is bounded.** Fuzzy comparisons use banded dynamic programming with an early-abort on the distance threshold, so a comparison costs `O(d·s)` for threshold `d` rather than `O(s²)`.
- **The whole pipeline is parallel.** Ingest, hashing, candidate generation and verification are all embarrassingly parallel across functions and buckets. DSigMatcher-Native uses every hardware thread it is given.
- **Allocation is kept out of the hot path.** Arena-backed storage, structure-of-arrays record layout, and zero-copy views over the mapped input.

---

## Scope: what "Diaphora parity" means here

Parity is defined against Diaphora's observable behaviour, not its internals.

| Capability | In scope | Notes |
|---|---|---|
| Two-database diff producing matched function pairs with a confidence score | Yes | Core deliverable. |
| Staged matching cascade (exact → structural → fuzzy → relaxed) | Yes | Same tiering philosophy, rederived implementation. |
| Call-graph-aware match propagation | Yes | A confirmed match constrains and seeds its neighbours. |
| Name / symbol / prototype porting from reference to target | Yes | The primary output artifact. |
| Export of results for application in IDA Pro / Ghidra | Yes | DSigMatcher-Native computes; the disassembler applies. |
| Consuming Diaphora's existing SQLite exports | Yes | Direct compatibility path, so existing workflows keep working. |
| Native PE / ELF / Mach-O loader and built-in disassembler | Roadmap | Removes the IDA dependency entirely. Tracked separately from the parity goal. |
| ML-assisted matching | Roadmap | Diaphora 3 ships an ML engine; a native equivalent is a later milestone. |

Out of scope: reproducing Diaphora's Python plugin surface, and bit-for-bit reproducing its scoring weights. Scores will be *comparable*, not identical.

---

## Matching pipeline

Matching runs as an ordered cascade. Each stage consumes the unmatched residue left by the stage before it, so expensive comparisons are only ever paid for on the small set of functions that cheap comparisons could not resolve.

**Stage 0 — Ingest and normalize.**
Load both inputs, build function records, canonicalize instructions. Register allocation and address-relative operands are normalized away so that a function that merely moved or got re-allocated does not stop matching itself.

**Stage 1 — Exact signature.**
Hash the normalized instruction stream and the raw byte stream per function. Identical hashes are a match. This is a single pass over both sides through an open-addressing hash table; it typically disposes of the large majority of untouched functions immediately.

**Stage 2 — Symbol and name.**
Where both sides carry names, exact name equality is a high-confidence match. Demangled forms are compared as well as mangled, so a change in mangling scheme does not defeat the stage.

**Stage 3 — Constants and references.**
Inverted index from constant value, string reference and import reference to the functions that use it. Distinctive constants are strong evidence; high-frequency values (`0`, `1`, small integers, common masks) are suppressed by a frequency stop-list so they do not explode the candidate sets.

**Stage 4 — Structural / call-graph.**
Build both call graphs, then propagate. A function whose set of already-matched callees is identical on both sides is matched even if its own body changed. This is where the cascade earns its keep on rebuilt code — it converts local certainty into global certainty at `O(V + E)`.

**Stage 5 — Fuzzy candidates via LSH.**
For everything still unmatched, generate candidates with multi-probe locality-sensitive hashing over instruction n-gram shingles. This is the stage that replaces brute-force pairwise comparison: index build is linear, and each probe returns at most `k` candidates.

**Stage 6 — Verification.**
Score each candidate pair properly — bounded-band edit distance on the instruction sequence, basic-block count and shape comparison, cyclomatic complexity delta, callee-overlap. Early-abort the moment the running cost exceeds the acceptance threshold.

**Stage 7 — Assignment and conflict resolution.**
Fuzzy stages can propose several targets for one function. DSigMatcher-Native resolves this to a strict one-to-one assignment using Hopcroft–Karp on the bipartite candidate graph, `O(E·√V)`, restricted to edges above the confidence floor. Below the floor, matches are emitted as *partial / best-effort* rather than silently forced.

---

## Complexity budget

`n` = functions in the reference build, `m` = functions in the target build, `N = n + m`, `s` = mean instructions per function, `E` = call-graph edges, `d` = edit-distance threshold, `k` = candidates per probe.

| Stage | Asymptotic | Comment |
|---|---|---|
| 0. Ingest + normalize | `O(N · s)` | Parallel over functions. |
| 1. Exact signature | `O(N · s)` | Hashing dominates; lookup is `O(1)` amortized. |
| 2. Symbol / name | `O(N)` | Single indexed pass. |
| 3. Constants + refs | `O(N · c)` | `c` = refs per function; stop-list bounds bucket size. |
| 4. Call-graph propagation | `O(V + E)` | BFS over matched neighbourhoods. |
| 5. LSH candidate gen | `O(N · s + m · k)` | Replaces the `O(n · m)` pairwise term. |
| 6. Verification | `O(P · d · s)` | `P` = candidate pairs, `P ≪ n·m`. Banded DP, early-abort. |
| 7. Assignment | `O(E'·√V)` | `E'` = surviving high-confidence edges. |

The headline is stage 5: **`O(n·m)` is removed from the pipeline entirely.** Verification only ever runs on pairs that an index nominated.

---

## Concurrency model

- **Work-stealing thread pool** sized to the hardware concurrency, with an explicit oversubscription override for benchmarking.
- **Parallel-for** over function records in stages 0–3. Each thread accumulates into thread-local hash shards; shards are merged once at the barrier. No contention on the hot path, no shared mutable index.
- **Sharded candidate queues** feeding stage 6, so verification workers pull without a global lock.
- **Per-bucket parallelism** in stages 5 and 6 — buckets are independent by construction.
- **Deterministic output.** Parallelism must not change results. Every intermediate is tagged with a stable sort key and reductions are order-independent, so the emitted match set is byte-identical whether DSigMatcher-Native runs on 4 threads or 128. A single-threaded mode exists specifically to make this auditable.

## Memory model

- Input is memory-mapped; records hold views, not copies.
- Arena allocation per stage, bulk-freed at the barrier. No `new`/`delete` inside inner loops.
- Function records are stored structure-of-arrays so the scan-heavy stages stream linearly through cache.
- Peak resident set is targeted at a small multiple of the input size, independent of thread count.

---

## Status

**Working vertical slice — exact-match tier only.**

What is implemented and verified:

- Ingest of Diaphora SQLite exports into structure-of-arrays records over a string arena, with column detection so older or partial exports still load.
- Twelve of Diaphora's 46 heuristics, reimplemented as native hash-indexed joins rather than SQL. All eight `Best`-category exact heuristics (*Same RVA and hash*, *Same order and hash*, *Function Hash*, *Bytes hash*, *Same address and mnemonics*, *Same cleaned assembly*, *Same cleaned microcode*, *Same cleaned pseudo-code*), plus four `Partial` heuristics (*Same KOKA hash and MD-Index*, *Same constants*, *Same rare KOKA hash*, *Same rare MD Index*). Predicates, size gates, rarity CTE semantics and `sub_`/`nullsub` name handling follow Diaphora's definitions.
- MD5 and SHA-256, both self-contained. MD5 is verified against RFC 1321 and cross-checked against Python's `hashlib`; SHA-256 against NIST vectors.
- The Koret–Karamitas graph hash, including the arbitrary-precision integer rendering that Diaphora's `str(hash)` implies. Verified against nine oracle vectors generated with Python's bignums, up to a 167,210-digit value.
- A native PE32/PE32+ reader (headers, sections, exports with forwarder detection, CodeView RSDS), independently audited field-by-field against `pefile` with zero mismatches on two real Microsoft binaries.
- An x86-64 disassembler backend over Zydis v4.1.1, behind a narrow interface that exposes operand displacements — the discriminator needed to tell struct getters apart.
- Deterministic resolution of raw candidate pairs into a strict one-to-one match set, highest ratio first.
- Output of a `matches` table plus a `symbols_to_port` table — the name/symbol move-over artifact.
- Chainable `port`: writes a labelled copy of the target that is itself a valid Diaphora export, so symbols roll forward release after release without returning to IDA. Each hop is recorded with both binaries' md5, both files' SHA-256, and a per-name cumulative confidence that decays multiplicatively.
- Heuristic-level parallelism over a persistent thread pool, matching Diaphora's execution model. Measured scaling reaches roughly 3.0–3.2× on 32 threads and is bounded primarily by the heuristic count. See `JOURNAL.md`.

What is **not** implemented yet: the remaining 34 heuristics of the `Partial` and `Unreliable` categories, the separate `constants` table joins, call-graph matching and propagation, fuzzy/LSH candidate generation, bounded edit-distance verification, maximum-cardinality assignment, Diaphora's graded similarity ratio (`compare_function_rows`) and its per-heuristic `min` thresholds, and the native PE/ELF loader path end to end.

No benchmark against Diaphora has been run, and no timings are quoted here as parity evidence. Correctness is established by four native test suites — 244 assertions in `dsigmatcher_tests`, 67 in `dsigmatcher_disasm_tests`, 302 in `dsigmatcher_pe_tests`, 825 in `dsigmatcher_resolve_tests` — against synthetic corpora with known ground truth, plus oracle vectors from Python for the cryptographic and bignum code, plus an independent `pefile` cross-audit for the PE reader. **No suite has yet run against a real Diaphora export**, so byte-level agreement with what IDA's Diaphora writes remains unproven. Real-corpus numbers will be published once the cascade is complete enough to produce a full match set.

Note also that the pipeline described above is the *target* design. The current implementation follows Diaphora's heuristic-cascade structure for parity; the LSH and maximum-cardinality-assignment stages are additions intended to replace parts of that cascade, and are not built yet.

## Build

Requires a C++20 compiler, CMake 3.20+, Ninja, and the SQLite development headers and library. Verified with MSVC 19.51 (VS 2026) on Windows x64.

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=<prefix containing include/sqlite3.h and lib/sqlite3.lib>
cmake --build build
```

On Windows with Visual Studio, run `vcvars64.bat` first; CMake and Ninja ship with the IDE.

## Usage

```
dsigmatcher diff <reference.sqlite> <target.sqlite> [options]
dsigmatcher port <reference.sqlite> <target.sqlite> -o <output.sqlite> [options]
dsigmatcher info <database.sqlite>

diff options:
  -o, --output <path>          write match results to a SQLite database
  -t, --threads <n>            worker threads (default: hardware concurrency)
      --ignore-small-functions apply the instructions > 5 size gate
      --assume-same-cpu        run processor specific heuristics unconditionally

port options (in addition to the above):
  -o, --output <path>          required; labelled copy of the target database
      --min-ratio <r>          drop names whose cumulative confidence falls below r
      --max-hops <n>           drop names that have travelled through more than n diffs
      --overwrite-existing     replace real names already present in the target
```

`reference` is the database carrying the symbols you want; `target` is the one that receives them. `diff` writes `matches` (every resolved pair with ratio and category) and `symbols_to_port` (only rows where the reference name is a real symbol and differs from the target's current name). `info` prints a database's identity, provenance chain and name-confidence histogram.

## Rolling symbols forward across releases

`port` is the chainable operation. Its output is **itself a valid Diaphora-schema database** — a byte copy of the target with names updated and provenance tables added — so the output of one release becomes the reference for the next, without going back through IDA:

```
dsigmatcher port v1_labelled.sqlite v2.sqlite -o v2_labelled.sqlite
dsigmatcher port v2_labelled.sqlite v3.sqlite -o v3_labelled.sqlite
```

You label once in IDA, export, and then roll the symbols forward indefinitely as new builds ship.

Each hop is recorded in `dsig_provenance` with both binaries' `program.md5sum` (Diaphora's `GetInputFileMD5()`, i.e. the version identity), the SHA-256 of both database files, the timestamp, the tool version, and the full match and skip counts. The `lineage` column accumulates the md5 chain, so any labelled database can state exactly which releases its names travelled through. Hop *N+1* records the SHA-256 of hop *N*'s output as its `source_file_sha256`, which makes the chain tamper-evident without the self-reference of storing a file's own hash inside itself.

Per-name provenance lives in `dsig_name_origin`: the address and name in the *original* hand-labelled database, how many hops the name has travelled, and a `cumulative_ratio` that multiplies the confidence of every hop it survived. A name matched at 0.5 twice is recorded at 0.25, not 0.5 — so `--min-ratio` and `--max-hops` can prune stale labels before they propagate further.

By default a real symbol already present in the target is **preserved**, not overwritten; hand-labelling always beats inference. Use `--overwrite-existing` to force it.

## Tests

`dsigmatcher_tests` is a self-contained native suite — no external test framework, no Python. It builds Diaphora-schema SQLite databases in temp files and exercises the library end to end:

```
cmake --build build
ctest --test-dir build --output-on-failure
```

82 assertions across 7 suites: SHA-256 against NIST vectors (including the 1,000,000-byte case and chunked-versus-whole equivalence), string-arena behaviour, the `sub_`/`nullsub`/portability predicates, `MatchStore` dedup and strict 1:1 resolution, ingest round-trip with field fidelity, matcher accuracy against synthetic ground truth, and a two-hop provenance chain.

The synthetic generator (`src/Synth.cpp`) carries per-function ground truth, so accuracy is measured as precision and recall rather than as a match count. It deliberately emits **different bytes per side** for recompiled and ambiguous functions and **shuffles target row order**, so greedy 1:1 resolution cannot succeed by index alignment. One assertion exists purely to keep that honest: `CHECK(Precision < 0.999)` fails the build if the fixture ever starts leaking the answer again. An earlier version of the generator did exactly that and reported a meaningless `precision 1.0000`.

The two-hop chain test verifies that a name matched at 0.5 twice is recorded at 0.25, that stable names hold at 1.0, and that `--max-hops` and `--min-ratio` both prune as documented.

## Benchmark

`dsigmatcher_bench` measures per-heuristic cost and whole-cascade scaling so that parallelism is applied on evidence rather than by default:

```
build/dsigmatcher_bench -n 50000 -r 3 -t 1,2,4,8,16,24,32
```

It reports each heuristic's serial cost and raw match count, the serial `Resolve` floor, accuracy against ground truth, and wall time / speedup / efficiency at every requested thread count, taking the best of `-r` repetitions.

On a 32-thread machine at 47,500 functions per side, heuristic-level parallelism peaks near **2.2×** and is bounded both by the heuristic count and by the serial `Resolve` pass. Parallelising everything is measurably *not* the fastest option here; `JOURNAL.md` has the numbers and the analysis.

## Journal

`JOURNAL.md` is the working log: what was built, what was tested, what broke, what the measurements showed, and which findings contradicted the design intent. Read it before trusting any number in this README.


## Prior art

DSigMatcher-Native is a clean-room reimplementation of the binary diffing approach pioneered by **Diaphora**, copyright Jose Miguel Escribano and contributors, distributed under the **GNU Affero General Public License v3.0**. Diaphora established that a staged heuristic cascade with call-graph propagation is the right shape for this problem; this project rederives that shape in native code with different data structures, different scoring and a different execution model.

No Diaphora source code is incorporated, copied, or translated. What is reused is the *observable interface*: the SQLite schema that Diaphora's exporters emit, and the taxonomy of matching heuristics it applies. Consuming a documented file format and reimplementing an algorithmic approach independently does not create a derivative work, so Diaphora's AGPLv3 does not propagate to this project. Licensing for DSigMatcher-Native has not yet been chosen.

SQLite is located with CMake's `find_package(SQLite3)` and linked as `SQLite::SQLite3`; nothing is vendored. SQLite itself is public domain.
