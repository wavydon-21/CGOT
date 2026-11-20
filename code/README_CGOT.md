# CGOT minimal prototype (package `causalguard`)

Step 10 of the Chapter 4 plan. Reconstruction part only, on the **made-up campaign** of Expected Outcomes Part B (Section B2).
No SWaT data is read. The 2015 pilot (`pilot\`) is separate and unchanged.

## Run it (PowerShell, from `FYP\code`)

```
python -m causalguard make-synthetic
python -m causalguard all --config configs/synthetic.yaml
python -m pytest tests/test_causalguard.py -q
```

1. `make-synthetic` writes the made-up files to `tests\data_synthetic\`.
2. `all` = `run` + `score` + `compare`. It writes `runs\<timestamp>_<config-hash>_synthetic\`.
3. Open `report.html` in that folder (Figure 4.7 is a screenshot of it).
4. `part_b_comparison.md` in the same folder lists every Part B number against the run.

The run stops if `research\chapter-4\Expected_Outcomes_Part_B.md` is missing or its SHA-256 differs from the config (freeze gate).

## What each file does

| File | Module (Ch3 §3.5) | Design |
|---|---|---|
| `synthetic.py` | fixture generator | Part B §B2 |
| `ingest.py` | 1 data ingestion: files, hashes, row/flow IDs, capture gaps | F1, F2 |
| `events.py` | 3 event abstraction: fixed bands, 5-s merge, one event per flow | Algorithm 4.1 lines 10–25 |
| `linking.py` | 4 typed linking; temporal-only = same module, rules off | Algorithm 4.2 |
| `paths.py` | 5 top-3 path search | Algorithm 4.3 |
| `export.py`, `recheck.py` | 6 explanation export: CSV, JSON, HTML, unknown steps, four-principle checklist | F13, F15, F16 |
| `groundtruth.py`, `scorer.py` | evaluation: step assignment and measures | Algorithm 4.4 |
| `compare.py` | checks a run against `tests\part_b_key.yaml` | Plan §8a |

Module 2 (preprocessing) is not needed here: the made-up flows are already one row per flow.

## Decision D9 in the code

- `ingest`, `events`, `linking` and `paths` never import `groundtruth` and never get the documented-steps file name.
- `groundtruth.load` needs the hash that `paths.fix()` returns. No fixed paths, no ground truth.
- Two tests check this, one of them by changing the documented steps and comparing the output hashes.

## Choices made inside the written rules (all 10 accepted by the student, 17 Nov 2026)

1. **Unusual volume with no reference.** If the host pair and port have no pre-attack flow, volume is not checked (the rule compares with a pre-attack flow of the same pair and port). Detail says "volume not checked".
2. **Provenance reason.** Accepted on a shared host (Algorithm 4.2 line 12). Reason is "same host", "same connection" (same source, destination and port) or "next later event on host" (long link). There is no "download then new traffic" reason, because no rule says how to recognise a download.
3. **Host pair** is compared without direction; the port is the destination port.
4. **Volume** = bytes ÷ flow duration. A flow with zero duration is not checked.
5. **Network → process domain link** needs a flow that is a CIP write to a PLC in the layout table.
6. **Step assignment.** If an event falls in two steps and §3.4.3 gives no rule for that case, the scorer stops with an error instead of guessing.
7. **Capture gap** = a break of 1 s or more between two capture files (`ingestion.min_capture_gap_s`).
8. **`detector_score`** = how far the value or change is outside its band, as a share of the band width.
9. **Last tie-break.** If two paths are still tied after the two written rules (two events in the same millisecond), event IDs decide.
10. **Extra output files** beyond Part B §B8: `unknown_steps.csv`, `checklist.json`, `scores.json`, `step_assignment.csv`, `score_summary.txt`, `part_b_comparison.csv/.md`.

## Not in this prototype (FYP2)

Threshold learning and calibration, frozen-value and dependency-violation events, PCMCI+, the 2019 preprocessing, Parquet conversion, and any run on SWaT data.
