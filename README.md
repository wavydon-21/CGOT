# CGOT — CausalGuard-OT

**A Causal Reasoning Framework for Explainable Multi-Stage Cyberattack Detection in Operational Technology Networks**

Final Year Project (FYP1), Bachelor of Computer Science (Cyber Security), Universiti Tenaga Nasional (UNITEN).
Author: Kavines Ravi (CS01085170).

CGOT turns alerts from an industrial control network and its process sensors into a short, explained attack story.
It finds suspicious **events** in network flows and process (historian) data, links them with typed rules
(**provenance**, **plant-layout/domain** and **statistical** links), searches for the top-3 attack **paths**,
and writes an HTML/CSV/JSON report in which every link carries the rule and record that justify it.

> **Status: FYP1 prototype.** This repository holds the minimal prototype and the 2015 detection pilot described in
> Chapter 4 of the FYP1 report. The prototype runs on a **made-up (synthetic) campaign** with a known answer.
> Learning thresholds, PCMCI+ and the run on the SWaT Dec 2019 (A6) campaign are planned for FYP2.

## What is in the repository

| Folder | Content |
|---|---|
| `code/causalguard/` | CGOT minimal prototype: ingestion, event abstraction, typed linking, top-3 path search, explanation export, scorer |
| `code/pilot/` | 2015 detection pilot: rule baseline and isolation forest on SWaT Dec 2015 (needs the SWaT data, not included) |
| `code/configs/` | Run settings (`synthetic.yaml` for the prototype; `pilot_2015.yaml`, `dev_2015.yaml`, `smoke_test.yaml` for the pilot) |
| `code/tests/` | Tests, the frozen answer key (`part_b_key.yaml`) and the made-up campaign (`data_synthetic/`) |
| `research/` | The frozen expected-outcome file the prototype checks before it runs (freeze gate) |
| `docs/example_report_synthetic.html` | Example output report from the synthetic campaign (download and open in a browser) |

Details: [`code/README_CGOT.md`](code/README_CGOT.md) (prototype) and [`code/README.md`](code/README.md) (pilot).

## Quick start (prototype on the made-up campaign)

Python 3.11.

```bash
cd code
pip install -r requirements.txt
python -m causalguard make-synthetic
python -m causalguard all --config configs/synthetic.yaml
python -m pytest tests/test_causalguard.py -q
```

The run writes `code/runs/<timestamp>_<config-hash>_synthetic/` with `report.html`, `events.csv`, `links.csv`,
`paths.json` and a comparison of every number against the frozen answer key.
Expected: 41 tests pass and **239 of 242** answer-key checks match; the 3 differences are wording only and are
explained in `code/tests/part_b_known_differences.yaml`.

## Data

**No SWaT data is included.** The Secure Water Treatment (SWaT) datasets belong to iTrust, Singapore University of
Technology and Design, and are available on request from iTrust under their terms. The files in
`code/tests/data_synthetic/` are made up (dated 1 January 2000); they borrow SWaT tag names only so the example reads
like the real case.

## Contact

Kavines Ravi — kavines0206@gmail.com
