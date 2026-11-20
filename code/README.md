# CausalGuard-OT FYP1: 2015 detection pilot (code)

Implements the 2015 detection pilot of the Chapter 4 plan (Section 0.4, step 1) from the rules in
Chapter 3 (Sections 3.5.1-3.5.3, 3.6, 3.7.1; Tables 3.5 and 3.6): convert the workbooks once, audit
the labels and timing, split in time order 70/15/15, run the **rule baseline** and the **isolation
forest** (100 trees, seeds 0-4, threshold = 1% of calibration rows), and score them.

It does **not** include CausalGuard-OT's own detection stage or anything on the 2019 data (FYP2).

## Set up (once)

```powershell
cd code
pip install -r requirements.txt
```

## Commands

| What | Command | Reads |
|---|---|---|
| Unit and end-to-end tests (about 35 s) | `python -m unittest discover -s tests` | made-up files only |
| Make the made-up smoke files | `python -m pilot make-smoke-data` | `..\research\chapter-3\analysis\tag_mapping_2015_2019.csv` |
| Smoke run | `python -m pilot run --config configs/smoke_test.yaml` | made-up files only |
| **Development run** | `python -m pilot run --config configs/dev_2015.yaml` | training + calibration part of the normal file only |
| **The pilot** (step 4 of the plan) | `python -m pilot run --config configs/pilot_2015.yaml` | everything, **only after the freeze gate passes** |

Results go to `runs\<date-time>_<config-hash>_<stage>\`. Converted Parquet files and the hash
manifest go to `cache\`. The first run converts the two big workbooks (a few minutes each); later
runs reuse them after re-checking the SHA-256 of the source. If a source file has changed, the run
stops.

## The freeze gate (Chapter 4 Plan, Section 8a)

`pilot_2015.yaml` has `stage: pilot`. That stage refuses to start until
`..\research\chapter-4\Expected_Outcomes.md` exists and its SHA-256 equals
`expected_outcomes.sha256` in the config. So, after you have read and approved Part A:

1. `Get-FileHash "…\research\chapter-4\Expected_Outcomes.md"` in PowerShell.
2. Write the hash and the date in the logbook.
3. Paste the same hash into `configs/pilot_2015.yaml` under `expected_outcomes: sha256:`.
4. Run the pilot. If Part A is edited afterwards the hash no longer matches and the run stops.

The `dev` stage never loads the attack file or the normal hold-out (the hold-out rows are dropped
before any statistic is computed). The `smoke` stage only accepts files under `tests\data`.

## What a run writes

| File | Content |
|---|---|
| `table_4_9_draft.md` | Draft of Table 4.9: row-level P/R/F1/FPR (isolation forest mean ± sample SD), point-adjusted F1, false alarms per hour, time per step, hardware |
| `metrics_rowlevel.csv` | Confusion counts and measures per detector, seed and split (calibration, normal_holdout, attack_file) |
| `metrics_point_adjusted.csv`, `per_attack_recall.csv`, `attacks_not_scored.csv` | Secondary results, each with its counting rule (below) |
| `false_alarms.csv` | Alarm rows and alarm episodes per hour on the normal hold-out |
| `audit.json` | TC1-TC5 and the example rows 1756-1757 (PASS / FAIL / NOT_RUN, with details) |
| `thresholds.json` | Rule baseline min/max per tag and learned delays; isolation-forest thresholds per seed |
| `rule_range_share_by_tag.csv` | Share of rows each tag is outside its training range, per split |
| `predictions.parquet` | Row-level alarms and scores (every row keeps its Excel row number, `src_row`) |
| `timings.csv`, `environment.json`, `manifest.json`, `config_used.yaml` | Time per step; Python and package versions, CPU, memory; SHA-256 of every source; the exact config |

## Counting rules and choices made inside the Chapter 3 rules (please confirm)

Chapter 3 does not fix these, so they are stated here and recorded in the config:

1. **Row ID** = the Excel row number (header on row 2, data from row 3). This is the numbering used for "rows 1756-1757" in Section 3.4.1.
2. **Gap** = a step of more than 1.5 s between two rows. Gaps are left as gaps; a run of "actuator on" is cut at a gap.
3. **Rule baseline range check** = training min/max of each of the 42 kept tags (actuators included), widened by 5% of each tag's span (decision D7, below).
4. **Rule baseline delay** = the smallest lag (1-120 s) after which no training row breaks the rule. "Flow above zero" means above `flow_above: 0.1`, as in the Chapter 3 invariant check. Valve open and pump on are state code 2.
5. **Isolation forest** uses the same 42 kept tags, raw values, scikit-learn defaults except `n_estimators=100` and the seed. Anomaly score = −`score_samples`. Threshold = the (k+1)-th highest calibration score, k = floor(1% × rows), so at most 1% of calibration rows are flagged.
6. **Per-attack recall** = share of rows inside the logged window that raise an alarm; "detected" = at least one alarm. Windows come from `List_of_attacks_Final.xlsx`: the five entries with no end time are listed in `attacks_not_scored.csv`, and entries dated January 2015 are moved to January 2016 and flagged `year_corrected`. That leaves 36 attacks.
7. **Point-adjusted F1**: if any alarm falls inside a run of Attack-labelled rows, the whole run counts as detected.
8. **False alarms per hour** are reported two ways on the normal hold-out: alarm rows per hour, and alarm episodes per hour (alarm rows 5 s apart or less count as one episode, the same merge gap as design problem P1).
9. **SD** of the isolation forest over the 5 seeds is the sample SD (n − 1).
10. **Missing values** in a kept tag (none were found in the normal file) would be filled forward and the row flagged; no row is removed.

## Decision D8 (student, 14 Nov 2026): diagnostic rule output

The configs set `rule_baseline.diagnostic_exclude_tags: [AIT402, AIT502]`. The run then also saves the rule baseline's alarm with the range check on those two drifting tags ignored:

- column `rule_alarm_excl_drift` in `predictions.parquet`;
- detector `rule_baseline_excl_drift` in `metrics_rowlevel.csv`, `metrics_point_adjusted.csv`, `per_attack_recall.csv` and `false_alarms.csv`;
- one "Diagnostic only" line under the table in `table_4_9_draft.md`.

This is a diagnostic only. The primary rule baseline result (detector `rule_baseline`) is unchanged; Table 4.9 uses it. The diagnostic is used to check the predictions marked † in Expected Outcomes Part A. On the development run it flags 0 calibration rows, so all 285 primary calibration alarms (0.38%) come from AIT-402 and AIT-502.

## Decision D7: rule baseline range margin (14 Nov 2026)

On the training/calibration part of the normal file, the rule baseline with a plain training min/max
flagged **30.9% of calibration rows**, because the analysers AIT402 and AIT502 drift below their
training minimum later in the normal week (per-tag shares in `rule_range_share_by_tag.csv`).
The student chose to widen each tag's range by **5% of its span** (`range_margin_fraction: 0.05`),
the same 5% used in the tag-mapping check (Chapter 3, Section 3.5.2). With it, and the zero-violation delays
(1, 6 and 6 s), the rule baseline flags 0.38% of calibration rows. Chapter 3, Section 3.6 is updated to match. `range_exclude_tags` stays empty.
