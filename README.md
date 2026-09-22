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

**Design and scaffolding.** The pipeline, complexity budget and concurrency model above are the committed design. Implementation is in progress — there is no build yet, and no benchmark numbers are quoted anywhere in this README because none exist yet. Numbers will be published against Diaphora on a fixed corpus once the exact-signature and call-graph stages are complete enough to produce a full match set.

## Prior art

DSigMatcher-Native is a clean-room reimplementation of the binary diffing approach pioneered by **Diaphora**, copyright Jose Miguel Escribano and contributors, distributed under the GPLv3. Diaphora established that a staged heuristic cascade with call-graph propagation is the right shape for this problem; this project rederives that shape in native code with different data structures, different scoring and a different execution model. No Diaphora source is incorporated. Licensing for DSigMatcher-Native has not yet been chosen.
