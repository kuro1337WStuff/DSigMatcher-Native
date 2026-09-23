# Design notes for after v1.0 (roadmap)

> **Status: roadmap, not a description of v1.0.0.** This is the original design sketch for
> DSigMatcher Native, moved here from the old README. None of the pipeline below (LSH candidates,
> banded edit distance, Hopcroft–Karp assignment, arenas, memory mapping) is what v1.0.0 runs.
> v1.0.0 runs a C++ port of Diaphora 3.4.2's own diff, which executes Diaphora's SQL through
> SQLite and reproduces its results row for row (see the README). Any future accelerator must
> keep that guarantee: its output has to equal the ported engine's output exactly, including row
> order, or it does not ship. The planned first step, *fusion* of heuristic queries that share
> join keys, is inventoried in [`docs/fusion/INVENTORY.md`](fusion/INVENTORY.md) and has not
> started.

---

## Why

Function-level binary diffing is the load-bearing step in patch analysis. You have a build with
symbols and a build without them, or two builds where only one has been reversed, and you need to
transfer what you know from one to the other. The naive formulation is a maximum-weight bipartite
matching over `n × m` function pairs, which is `O(n·m)` candidate generation before anything has
been scored, and on a large binary that is hundreds of thousands of pairs.

Diaphora solves this with a staged heuristic cascade, and it works well. The idea was to keep the
staged cascade, because the staging is the genuinely good idea, and to attack the constant factors
and the asymptotics underneath it:

- **Index-driven candidate generation.** Functions are bucketed by signature, and only functions
  that land in a related bucket are ever compared, so the `O(n·m)` term never materialises.
- **Bounded similarity measures.** Fuzzy comparisons use banded dynamic programming with an early
  abort on the distance threshold, so a comparison costs `O(d·s)` for threshold `d` rather than
  `O(s²)`.
- **A parallel pipeline.** Ingest, hashing, candidate generation and verification are all
  parallel across functions and buckets.
- **No allocation in the hot path.** Arena-backed storage, structure-of-arrays records, and
  zero-copy views over the mapped input.

What v1.0 taught: Diaphora's results depend on the order in which SQLite's query planner returns
rows, and its matcher is an order-sensitive state machine (first writer wins; ties become
multimatches). An engine that finds "the same kind of matches" by other means produces different
results. That is why v1.0 ports Diaphora literally, and why every idea below is now framed as an
accelerator that must reproduce the ported engine's rows exactly.

---

## Scope once the IDA dependency is removed

| Capability | Status | Notes |
|---|---|---|
| Two-database diff with Diaphora's categories and ratios | **Done in v1.0** | Row-for-row identical to Diaphora 3.4.2. |
| Name porting from reference to target, chainable across releases | **Done in v1.0** | `port --results`, with provenance. |
| Consuming Diaphora's SQLite exports | **Done in v1.0** | Exports come from Diaphora's own exporter under IDA's idalib. |
| Fusion of heuristic queries that share join keys | Planned | See `docs/fusion/INVENTORY.md`. Must keep Path A's row order. |
| Native PE / ELF / Mach-O loader and disassembler | Roadmap | Would remove the IDA dependency for `ingest`. The PE reader, the Zydis backend and the control-flow-graph extractor exist in the library but do not yet produce Diaphora exports. |
| ML-assisted matching | Roadmap | Diaphora 3 ships an ML engine, which is off in its default configuration. |

---

## Matching pipeline (original sketch)

Matching runs as an ordered cascade. Each stage consumes the unmatched residue left by the stage
before it, so expensive comparisons are only paid for on the small set of functions that cheap
comparisons could not resolve.

**Stage 0: ingest and normalise.** Load both inputs, build function records, canonicalise
instructions. Register allocation and address-relative operands are normalised away, so a function
that merely moved or was re-allocated still matches itself.

**Stage 1: exact signature.** Hash the normalised instruction stream and the raw byte stream per
function. Identical hashes are a match. This is a single pass over both sides through an
open-addressing hash table.

**Stage 2: symbol and name.** Where both sides carry names, exact name equality is a
high-confidence match. Demangled forms are compared as well as mangled ones.

**Stage 3: constants and references.** An inverted index from constant value, string reference
and import reference to the functions that use it. Distinctive constants are strong evidence;
high-frequency values (`0`, `1`, small integers, common masks) are suppressed by a frequency
stop-list.

**Stage 4: structural / call graph.** Build both call graphs, then propagate. A function whose set
of already-matched callees is identical on both sides is matched even if its own body changed,
at `O(V + E)`.

**Stage 5: fuzzy candidates via LSH.** For everything still unmatched, generate candidates with
multi-probe locality-sensitive hashing over instruction n-gram shingles. Index build is linear,
and each probe returns at most `k` candidates.

**Stage 6: verification.** Score each candidate pair: bounded-band edit distance on the
instruction sequence, basic-block count and shape, cyclomatic complexity delta, callee overlap.
Abort early the moment the running cost exceeds the acceptance threshold.

**Stage 7: assignment and conflict resolution.** Resolve proposals to a strict one-to-one
assignment with Hopcroft–Karp on the bipartite candidate graph, `O(E·√V)`, restricted to edges
above the confidence floor.

---

## Complexity budget (original sketch)

`n` = functions in the reference build, `m` = functions in the target build, `N = n + m`, `s` =
mean instructions per function, `E` = call-graph edges, `d` = edit-distance threshold, `k` =
candidates per probe.

| Stage | Asymptotic | Comment |
|---|---|---|
| 0. Ingest + normalise | `O(N · s)` | Parallel over functions. |
| 1. Exact signature | `O(N · s)` | Hashing dominates; lookup is `O(1)` amortised. |
| 2. Symbol / name | `O(N)` | Single indexed pass. |
| 3. Constants + refs | `O(N · c)` | `c` = refs per function; the stop-list bounds bucket size. |
| 4. Call-graph propagation | `O(V + E)` | BFS over matched neighbourhoods. |
| 5. LSH candidate generation | `O(N · s + m · k)` | Replaces the `O(n · m)` pairwise term. |
| 6. Verification | `O(P · d · s)` | `P` = candidate pairs, `P ≪ n·m`. Banded DP, early abort. |
| 7. Assignment | `O(E'·√V)` | `E'` = surviving high-confidence edges. |

Measured reality in v1.0 is different: on the two long oracle pairs, most of the ported engine's
time goes to Diaphora's "Related compilation unit" pass and to SQLite building wide result rows
for three constants joins. `docs/fusion/INVENTORY.md` has the measured profile.

---

## Concurrency model (original sketch)

- A work-stealing thread pool sized to the hardware concurrency.
- Parallel-for over function records in stages 0–3, with thread-local hash shards merged once at
  the barrier.
- Sharded candidate queues feeding verification.
- Per-bucket parallelism in stages 5 and 6.
- **Deterministic output.** Parallelism must not change results: every intermediate carries a
  stable sort key and reductions are order-independent, so the output is byte-identical on any
  thread count.

Standalone Diaphora runs its heuristics one at a time, and the v1.0 engine does the same, because
its output order is part of the parity contract.

## Memory model (original sketch)

- Input memory-mapped; records hold views, not copies.
- Arena allocation per stage, freed in bulk at the barrier.
- Structure-of-arrays function records, so scan-heavy stages stream through cache.
- Peak resident set a small multiple of the input size, independent of thread count.
