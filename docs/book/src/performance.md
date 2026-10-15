# Performance

Repeated MCP-style investigation passes are cheap on small inputs and
dominated by response serialization on large ones. This chapter records
the method and the measured numbers behind that statement, so the
optimization decision (recorded separately) rests on data. Nothing here
is a speedup claim, a deadline, or a CI gate.

## Method

The harness is `tests/mcp_workflow_perf.rs`. Every test is `#[ignore]`:
default `cargo test` never runs it, and no assertion depends on
wall-clock speed. The one functional assertion is exact equality of the
canonical workflow output across scenarios. Canonical run:

```sh
cargo test --release --test mcp_workflow_perf -- --ignored --nocapture
```

Debug builds run the same harness but are slower and not comparable to
the release numbers below.

Each test performs one warm-up rep (discarded), then 6 measured reps,
and prints min/median/mean/max of wall time (via `std::time::Instant`)
plus serialized response bytes. The workflow under test is one agent
investigation pass using the bounded views:

`project_info → functions → func → blocks → block_insns → xrefs → strings`

mapped to `project_info`, `functions_resolved(0, 1024)`,
`func_meta`, `func_blocks_page(_, 0, 1024)`,
`func_block_insns_page(_, first_block, 0, 1024)`,
`query_xrefs(None, None, None, 0, 1024)`, and
`query_strings(&StringsFilter::default())`. Every response is serialized
to JSON; the byte count covers the path-free canonical output so
fresh/cached runs are comparable exactly.

Three scenarios isolate the stages without any measurement hook in
`src/`:

- **cold/no-sidecar**: fresh fixture bytes and a nonexistent sidecar per
  rep — open time covers file read, content hash, and full analysis.
- **saved-sidecar/new-process**: one analyzed project is saved, then
  each rep opens a new `Project` over the same paths — open time covers
  file read, hash, sidecar read, and layout replay, with no analysis.
- **repeated/same-process**: one open, then repeated workflow passes —
  measures in-memory queries plus serialization only.

## Fixtures

Both are deterministic and synthetic; no proprietary binary is involved.

- **small**: `pe32-basic.exe` builder fixture, 2048 file bytes —
  1 function, 1 block, 5 instructions, 4 xrefs, 4 strings.
- **large**: raw x86-64 blob at base `0x1000` (`nop` × 1500, `jmp +0` ×
  1200, `ret`; the same shape as the `function_pages` stress fixture) —
  3901 file bytes, 1 function, 1201 blocks, 2701 instructions,
  1200 xrefs, 0 strings (a code-only blob has no string hits; the
  `strings` step still runs and returns empty).

## Results

Platform: macOS 27.0.1, arm64 (Apple Silicon), rustc 1.99.0,
`cargo test --release`, 1 warm-up + 6 measured reps per cell.
Response bytes are the serialized canonical workflow output.

| Fixture | Scenario | Open ms (median, min–max) | Workflow ms (median, min–max) | Total ms (median) | Response bytes |
|---|---|---|---|---|---|
| small | cold/no-sidecar | 0.06 (0.05–0.08) | 0.03 (0.03–0.04) | 0.10 | 2,461 |
| small | saved-sidecar/new-process | 0.06 (0.06–0.06) | 0.02 (0.02–0.03) | 0.08 | 2,461 |
| small | repeated/same-process | — | 0.02 (0.02–0.02) | 0.02 | 2,461 |
| large | cold/no-sidecar | 1.47 (1.40–1.55) | 2.82 (2.75–2.86) | 4.28 | 368,129 |
| large | saved-sidecar/new-process | 1.35 (1.33–1.37) | 2.82 (2.69–2.84) | 4.16 | 368,129 |
| large | repeated/same-process | — | 2.87 (2.74–2.91) | 2.87 | 368,129 |

Repeated runs vary ±10–15% run to run (machine noise); the table shows
one representative run, not best-of-N.

Fresh and cached canonical outputs agree exactly in every rep of every
scenario (asserted by the harness); only host paths differ.

Read plainly: at these scales the whole pass costs single milliseconds.
On the small fixture everything is near timer resolution — the only
sound reading is "negligible". On the large fixture the workflow pass
(~2.9 ms serializing ~368 KB: 1201 block rows, 1024 instruction rows,
1200 xrefs) exceeds either open path (~1.4–1.5 ms), and saved-sidecar
reopen costs about the same as cold analysis — layout replay is not
observably cheaper than reanalysis for a 3.9 KB input. Whether any of
this matters for real-world binaries (megabytes, not kilobytes) is
unresolved by this data.

## Limitations

- **No in-process peak RSS.** The harness has no platform memory API
  without a new dependency, so resident size is an external step, e.g.
  `/usr/bin/time -l target/release/binscout <args>` (macOS reports
  `maximum resident set size`). No RSS numbers are recorded here.
- **Warm page cache.** Reps run back-to-back on one machine, so "cold"
  means no-sidecar, not cold-boot I/O. File read/hash costs are
  best-case.
- **Timer resolution.** Small-fixture cells sit at tens of microseconds;
  treat the distribution as order-of-magnitude only.
- **No generalization.** Two synthetic fixtures do not predict real
  binaries. Do not cite these numbers as guarantees, do not encode them
  as CI timing assertions, and do not claim any speedup from them.
