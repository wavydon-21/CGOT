# Expected Outcomes — Part B: prototype on the synthetic campaign

**Status: reviewed by the student on 15 Nov 2026 (21:53); decisions recorded in B9. Ready to freeze. Not frozen yet.**
Drafted by Claude on Sun 15 Nov 2026 for Kavines (CS01085170) to review. Freezing is done by the student (Section B10).

This file is the answer key for the minimal prototype (Chapter 4 Plan, decision D2) before any prototype code exists. It is Part B of the expected-outcomes rule (Plan Section 8a). Part A (`Expected_Outcomes.md`, frozen 14 Nov) is a separate file and is not touched.

Part B is also the test oracle for test cases TC6–TC11 and TC13 (Plan Section 7). After it is frozen, the prototype is run on the synthetic campaign and every number below is compared with the prototype's output. A mismatch means either the code or this key is wrong; both are checked, and the mismatch is reported, not hidden.

---

## B1. What was known when this was written

- **No prototype code exists.** No linking, path-search or scoring code has been written or run. Every result below was worked out by hand from the design.
- **The synthetic campaign is made up.** Its hosts and tag names follow SWaT conventions so the example reads like the real case, but every value, time and flow is invented (date: 1 January 2000). No 2019 attack-period data were opened or used.
- **Design sources:** Chapter 3 of the report (§3.4.3, §3.5.3–3.5.6, §3.7.2, Tables 3.3–3.5) and the Chapter 4 plan (P1–P6).
- **Arithmetic** (sums, shares, Kendall's τ) was checked twice by hand.
- **Design details fixed here.** Chapter 3 leaves a few small details open. The values used below are listed in Section B9 for you to confirm **before** freezing.

---

## B2. The synthetic campaign

### B2.1 Documented steps (the synthetic "event log")

| Step | Logged time | What happens | Scored? |
|---|---|---|---|
| S0 | 09:05 | Malware put on the SCADA workstation (WS) by USB | No: capture gap 09:05:00–09:07:00 (unobserved, like S0 in 2019) |
| A | 09:10–09:15 | Historian data copied to WS and sent to the exfiltration server | Yes |
| B | log says 09:40; capture interval 09:40:10.0–09:40:12.0 | Second malware downloaded from the malware server | Yes (interval from the capture, like step C in 2019) |
| C | 09:40–09:43 | WS sends a CIP write to PLC-1 that closes valve MV-101 | Yes |

Reference step graph: S0→A (not scored), A→B, B→C. **2 scorable links, 3 evaluable steps.**

Widened intervals (±60 s tolerance, Ch3 §3.4.3), in seconds after 09:00:00:
- A: 09:09:00–09:16:00 (540–960 s)
- B: 09:39:10–09:41:12 (2350–2472 s)
- C: 09:39:00–09:44:00 (2340–2640 s)

B and C overlap, as C and D1 do in 2019. The Chapter 3 rule applies: events of the download connection (WS ↔ 192.168.1.181:6001) go to B; all other events in the overlap go to C.

### B2.2 Hosts (synthetic host role table)

| Address | Role | In testbed component list? |
|---|---|---|
| 192.168.1.10 | PLC-1 (stage 1) | Yes |
| 192.168.1.20 | PLC-2 (stage 2) | Yes |
| 192.168.1.200 | Historian (HIST) | Yes |
| 192.168.1.201 | SCADA workstation (WS) | Yes |
| 192.168.1.99 | Undocumented poller | No (kept, role unknown) |
| 192.168.1.219 | Exfiltration server (EXF) | No |
| 192.168.1.181 | Malware server (MAL) | No |
| 8.8.8.8 | Public DNS server | No |

### B2.3 Historian records (process data)

One row per second from 09:00:00 to 09:44:59 (2,700 rows). Second *s* (seconds after 09:00:00) is workbook row *s* + 2 (row 1 is the header). Three tags:

| Tag | Normal value | Attack and noise changes |
|---|---|---|
| MV101 | 2 (open) | 1 (closed) from s = 2467 (09:41:07) to the end |
| FIT101 | 2.50 when *s* is even, 2.51 when odd | 0.00 at s = 1800, 1801 and 1806 (noise glitch); 0.00 from s = 2469 (09:41:09) to the end |
| LIT101 | 600.0 when *s* is even, 600.2 when odd, up to s = 2468 | from s = 2469: 600.0 − 0.5 × (s − 2468) up to s = 2489 (589.5); from s = 2490: falls 1.5 mm per second (588.0 at s = 2490, 274.5 at s = 2699) |

The campaign ends with the valve still closed. This keeps the event count at 10.

### B2.4 Network records (one row per flow, as exported by preprocessing)

Two capture files: `syn_00000` covers 09:00:00–09:05:00 (pre-attack reference) and `syn_00001` covers 09:07:00–09:45:00. The gap 09:05:00–09:07:00 is the S0 gap.

| Flow | Time | From → to (port) | Protocol / CIP service | Bytes | Note |
|---|---|---|---|---|---|
| f01 | 09:00:10–09:04:50 | HIST → PLC-1 (44818) | CIP read | 120,000 | pre-attack routine polling |
| f02 | 09:00:12–09:04:52 | HIST → PLC-2 (44818) | CIP read | 118,000 | pre-attack routine polling |
| f03 | 09:01:00–09:01:05 | WS → HIST (1433) | TCP | 40,000 | pre-attack routine query |
| f04 | 09:02:00–09:02:01 | PLC-1 → PLC-2 (44818) | CIP write | 600 | pre-attack routine PLC-to-PLC write |
| f05 | 09:08:00–09:44:50 | HIST → PLC-1 (44818) | CIP read | 1,000,000 | routine polling continues |
| f06 | 09:10:05–09:14:30 | WS → HIST (1433) | TCP | 52,000,000 | historian data pulled to WS |
| f07 | 09:10:20–09:14:55 | WS → EXF (443) | TCP | 51,000,000 | data sent out |
| f08 | 09:22:00–09:22:01 | .99 → PLC-2 (44818) | CIP read | 900 | noise: new poller |
| f09 | 09:41:00–09:41:01 | PLC-1 → PLC-2 (44818) | CIP write | 600 | routine PLC-to-PLC write |
| f10 | 09:39:50.0–09:39:50.2 | WS → 8.8.8.8 (53) | UDP (DNS) | 150 | lookup just before the download |
| f11 | 09:40:10.0–09:40:12.0 | WS → MAL (6001) | TCP | 10,000,000 | second-malware download (defines B) |
| f12 | 09:41:05–09:41:06 | WS → PLC-1 (44818) | CIP write | 700 | attack command |

### B2.5 Fixed inputs that stand in for learned ones

The minimal prototype does not learn thresholds or run PCMCI+ on the synthetic campaign. These values are given in the synthetic configuration instead (the learning steps are tested on 2015 data, TC5):

- **Abrupt-change bands:** FIT101 value 2.0–3.0 and 1-s change within ±0.2; LIT101 value 500–800 and 1-s change within ±1.0. A row is flagged if the value **or** its 1-s change is outside the band. The first row has no 1-s change, so only its value is checked.
- **Frozen-value check:** off for this campaign (tested on 2015 attack 21 in FYP2; Plan §4.8.6 lesson 5).
- **Event merge gap:** 5 s (Table 3.5). Two flagged seconds of the same tag merge if the later one is at most 5 s after the earlier one.
- **Unusual volume:** a flow's bytes per second exceed 10 × the highest bytes per second of the same host pair and port in the pre-attack capture.
- **Plant-layout (domain) table, synthetic excerpt:**

  | Row | From | Relation | To |
  |---|---|---|---|
  | D-1 | PLC-1 (192.168.1.10) | controls stage | stage 1: MV101, FIT101, LIT101 |
  | D-2 | PLC-2 (192.168.1.20) | controls stage | stage 2: FIT201 |
  | D-3 | MV101 | sets flow at | FIT101 |
  | D-4 | MV101 | feeds | LIT101 (tank T-101) |
  | D-5 | FIT101 | feeds | LIT101 (tank T-101) |

- **Statistical rule table (stands in for the PCMCI+ output):** one row, FIT101 → LIT101, lags 5–30 s, positive sign.

---

## B3. Expected events (event abstraction, F8 and F9)

| Event | Start | End | Source | Type | Record reference | Detail |
|---|---|---|---|---|---|---|
| ev01 | 09:10:05 | 09:14:30 | flow f06, WS → HIST:1433 | Unusual volume | syn_00001, f06 | 196,226 B/s vs limit 80,000 B/s (f03: 8,000 B/s × 10) |
| ev02 | 09:10:20 | 09:14:55 | flow f07, WS → EXF:443 | Undocumented host | syn_00001, f07 | also a new connection and unusual volume |
| ev03 | 09:22:00 | 09:22:01 | flow f08, .99 → PLC-2:44818 | New connection | syn_00001, f08 | pair and port not in 09:00–09:05 |
| ev04 | 09:30:00 | 09:30:07 | FIT101 | Abrupt change | rows 1802–1809 | flagged s = 1800, 1801, 1802, 1806, 1807; gap 1802→1806 is 4 s, so one event |
| ev05 | 09:39:50.0 | 09:39:50.2 | flow f10, WS → 8.8.8.8:53 | Undocumented host | syn_00001, f10 | DNS lookup |
| ev06 | 09:40:10.0 | 09:40:12.0 | flow f11, WS → MAL:6001 | Undocumented host | syn_00001, f11 | download; also new connection and unusual volume |
| ev07 | 09:41:05 | 09:41:06 | flow f12, WS → PLC-1:44818 | CIP control write | syn_00001, f12 | write sent by WS |
| ev08 | 09:41:07 | 09:41:07 | MV101 | Actuator state change | row 2469 | 2 → 1 (closed) |
| ev09 | 09:41:09 | 09:44:59 | FIT101 | Abrupt change | rows 2471–2701 | 2.50 → 0.00, stays 0 |
| ev10 | 09:41:30 | 09:44:59 | LIT101 | Abrupt change | rows 2492–2701 | falls 1.5 mm/s from 09:41:30 |

When a flow matches more than one network type, the event takes the first in this order: CIP control write, undocumented host, new connection, unusual volume (B9, item 4). Event IDs are given in order of start time.

**Records that must not become events (5 checks):**
1. f01–f04: pre-attack reference, never events.
2. f05: same pair and port as f01; 452 B/s is below the limit of 4,286 B/s.
3. f09: a CIP write between two PLCs (only writes from WS are events, Ch3 §3.5.3).
4. FIT101 at s = 2467 and 2468: valve already closed but flow still 2.51 and 2.50 (in band).
5. LIT101 from s = 2469 to 2489: falls 0.5 mm/s, inside the ±1.0 band.

**Event count:** 10 (6 network, 4 process). Noise: ev03 and ev04.

---

## B4. Expected step assignment (scorer, F19)

| Event | Start (s) | Inside widened interval of | Assigned to | Why |
|---|---|---|---|---|
| ev01 | 605 | A | A | |
| ev02 | 620 | A | A | |
| ev03 | 1320 | none | — (unassigned) | in the rest period |
| ev04 | 1800 | none | — (unassigned) | in the rest period |
| ev05 | 2390 | B and C | **C** | in the overlap but not the download connection |
| ev06 | 2410 | B and C | **B** | the download connection |
| ev07 | 2465 | B and C | C | not the download connection |
| ev08 | 2467 | B and C | C | |
| ev09 | 2469 | B and C | C | |
| ev10 | 2490 | C | C | |

---

## B5. Expected links (typed linking, F11–F13)

### B5.1 Temporal-only linker

Every ordered pair with 0 < Δt ≤ 900 s (Δt = later start − earlier start). **25 links.**

| From | To (Δt in seconds) | Count |
|---|---|---|
| ev01 | ev02 (15), ev03 (715) | 2 |
| ev02 | ev03 (700) | 1 |
| ev03 | ev04 (480) | 1 |
| ev04 | ev05 (590), ev06 (610), ev07 (665), ev08 (667), ev09 (669), ev10 (690) | 6 |
| ev05 | ev06, ev07, ev08, ev09, ev10 | 5 |
| ev06 | ev07, ev08, ev09, ev10 | 4 |
| ev07 | ev08, ev09, ev10 | 3 |
| ev08 | ev09, ev10 | 2 |
| ev09 | ev10 | 1 |

Pairs just outside the window, so **no** link: ev01→ev04 (1195), ev02→ev04 (1180), ev03→ev05 (1070). No link ever goes from a later event to an earlier one (TC7).

### B5.2 CausalGuard-OT candidates

The same 25 pairs, plus one long same-host provenance candidate:
- ev02 shares host WS with later events ev05, ev06 and ev07. The **next** later event on WS is ev05, 1,770 s later. So the long candidate is **ev02→ev05**, and ev02 does not reach ev06 or ev07 (TC8).
- ev01's next later event on WS is ev02 (15 s, already inside the window), so ev01 gets no long candidate.
- No other event has a later event on the same host beyond 900 s.

**26 candidates.**

### B5.3 CausalGuard-OT accepted links (12)

| Link | Rule(s) | Reason (stored with the link) | Status | Score | Correct? |
|---|---|---|---|---|---|
| ev01→ev02 | Provenance | same host 192.168.1.201 (f06, f07) | Observed | 1 | Yes (A→A) |
| ev02→ev05 | Provenance (long) | next later event on host 192.168.1.201 (f07, f10) | Observed | 1 | **No (A→C)** |
| ev04→ev10 | Domain | D-5: FIT101 feeds LIT101 | Inferred | 1 | **No (ev04 unassigned)** |
| ev05→ev06 | Provenance | same host 192.168.1.201 (f10, f11) | Observed | 1 | **No (C→B, wrong order)** |
| ev05→ev07 | Provenance | same host 192.168.1.201 (f10, f12) | Observed | 1 | Yes (C→C) |
| ev06→ev07 | Provenance | download then new traffic from 192.168.1.201 (f11, f12) | Observed | 1 | Yes (B→C) |
| ev07→ev08 | Domain | D-1: PLC-1 controls stage 1 (MV101) | Inferred | 1 | Yes |
| ev07→ev09 | Domain | D-1: PLC-1 controls stage 1 (FIT101) | Inferred | 1 | Yes |
| ev07→ev10 | Domain | D-1: PLC-1 controls stage 1 (LIT101) | Inferred | 1 | Yes |
| ev08→ev09 | Domain | D-3: MV101 sets flow at FIT101 | Inferred | 1 | Yes |
| ev08→ev10 | Domain | D-4: MV101 feeds LIT101 | Inferred | 1 | Yes |
| ev09→ev10 | Domain + statistical | D-5; FIT101→LIT101 at 21 s (table lags 5–30 s) | Inferred | 2 | Yes |

### B5.4 CausalGuard-OT rejected candidates (14), with reasons

| Candidates | Reason |
|---|---|
| ev01→ev03, ev02→ev03 | no shared host; no other rule |
| ev03→ev04 | network→process needs a CIP write to the PLC of that stage; f08 is a read to PLC-2 (stage 2) |
| ev04→ev05, ev04→ev06, ev04→ev07 | process→network: no rule type applies |
| ev04→ev08 | no layout row FIT101 → MV101 |
| ev04→ev09 | same tag; no rule |
| ev05→ev08, ev05→ev09, ev05→ev10 | network→process, but f10 is not a CIP write |
| ev06→ev08, ev06→ev09, ev06→ev10 | network→process, but f11 is not a CIP write |

12 accepted + 14 rejected = 26. Every rejected pair that the temporal-only linker accepts is a TC6 case (for example ev05→ev08).

---

## B6. Expected top-3 paths (path scoring, F14; TC10)

Path score = sum of link scores. A path has at least one link. Ties: the path whose first event starts earlier ranks higher; if still tied, compare the start times of the events one position at a time, and the earlier event at the first differing position ranks higher (B9, item 1).

### CausalGuard-OT

| Rank | Events | Score | Why this rank |
|---|---|---|---|
| 1 | ev01→ev02→ev05→ev06→ev07→ev08→ev09→ev10 | 8 | 1+1+1+1+1+1+2 |
| 2 | ev01→ev02→ev05→ev06→ev07→ev09→ev10 | 7 | tie at 7 with ranks 3 and 4; starts at ev01; at position 4, ev06 (09:40:10) is earlier than ev07 |
| 3 | ev01→ev02→ev05→ev07→ev08→ev09→ev10 | 7 | starts at ev01; loses to rank 2 at position 4 |
| (4) | ev02→ev05→ev06→ev07→ev08→ev09→ev10 | 7 | starts at ev02 (09:10:20), later than ev01; **not exported** |

This tests both tie rules: rank 4 loses on start time, and ranks 2 and 3 are separated at position 4.

### Temporal-only

All links score 1, so the score is the number of links.

| Rank | Events | Score |
|---|---|---|
| 1 | ev01→ev02→ev03→ev04→ev05→ev06→ev07→ev08→ev09→ev10 | 9 |
| 2 | ev01→…→ev09 (ends at ev09) | 8 |
| 3 | ev01→…→ev08→ev10 (skips ev09) | 8 |

Eight paths score 8. Ranks 2 and 3 are the two that differ only at the last position. The other six (skipping ev02, ev05, ev06, ev07 or ev08, or starting at ev02) lose at an earlier position or start later. Skipping ev03 or ev04 is not possible: ev02→ev04 and ev03→ev05 are longer than 15 minutes.

---

## B7. Expected measures (scorer, F19; TC11)

| Measure | CausalGuard-OT | Temporal-only | Working |
|---|---|---|---|
| Candidate links | 26 | 25 | B5 |
| Accepted links | 12 | 25 | B5 |
| Correct accepted links | 9 | 15 | B5.3; temporal: 1 (ev01→ev02) + 4 (ev05→C) + 4 (ev06→C) + 3 + 2 + 1 |
| **Link precision** | **9/12 = 0.750** | **15/25 = 0.600** | |
| Link recall (2 scorable links) | 1/2 = 0.50 (B→C only) | 1/2 = 0.50 (B→C only) | Neither has an A-event → B-event link |
| Step coverage, top path (3 steps) | 3/3 = 1.00 | 3/3 = 1.00 | both top paths hold A, B and C events |
| Step order in top path | A, C, B | A, C, B | ev05 (C) comes before ev06 (B) |
| Step pairs in the right order | 2/3 = 66.7% | 2/3 = 66.7% | (A,B) and (A,C) right; (B,C) reversed |
| **Kendall's τ** | **(2 − 1)/3 = +0.333** | **+0.333** | 3 pairs: 2 concordant, 1 discordant |
| Observed links in top path | 4/7 = 57.1% | 0/9 = 0% | provenance links are observed |

**Success rule applied to the synthetic campaign (§3.7.2):** precision 0.750 > 0.600 ✔; coverage 1.00 ≥ 1.00 ✔; τ 0.333 not lower than 0.333 ✔. **Expected: holds.**

This is a check that the scorer applies the rule correctly. It is **not** evidence for the research question: the campaign was designed by hand.

---

## B8. Expected explanation output (F15, F16; TC9, TC13)

- **Data gap listed:** capture gap 09:05:00–09:07:00 (seen by ingestion from the capture files; needs no ground truth).
- **Unknown steps per CausalGuard-OT path** (written after the paths are fixed, B9 item 6):
  - Path 1: S0.
  - Path 2: S0.
  - Path 3: S0 and **B** (path 3 has no ev06).
  - Temporal-only paths 1–3: S0.
- **Four-principle checklist (TC13), CausalGuard-OT paths 1–3:** all four principles pass on all three paths:
  1. every link has a type and a reason;
  2. every event is named by host or tag and time;
  3. every stored reason still holds when re-checked against its record (12 of 12 accepted links);
  4. S0 and the data gap are listed, and inferred links are marked.
- **Files written:** `events.csv` (10 rows), `links.csv` (CausalGuard-OT 12 accepted + 14 rejected with reason; temporal-only 25), `paths.json` (3 paths per linker), `report.html`, `timings.csv`, `manifest.json`.
- **TC12:** running the same configuration twice gives identical `events.csv`, `links.csv` and `paths.json` (same SHA-256). `timings.csv` and the run folder name are expected to differ.

### B8.1 One extra check (merge gap)

With a merge gap of 2 s instead of 5 s, ev04 splits into two events: 09:30:00–09:30:02 and 09:30:06–09:30:07, because the gap between them is 4 s. Every other event is unchanged. Only the event list is predicted for this variant.

---

## B9. Design details fixed by this file (please confirm before freezing)

Chapter 3 states the rules but leaves these details open. Each is needed to write the code and this key.

1. **Second tie-break.** If two paths have the same score and start at the same event, compare the start times of their events position by position. Reason: keeps "earlier start wins" (Ch3 §3.5.5) and makes the ranking unique.
2. **"Same host".** Two network events share a host if they share any IP address. Process events have no host, so they never get provenance links.
3. **Domain rule scope.**
   - Process → process: one layout row, one step (no chains).
   - Network → process: only a CIP write to a PLC, and only to process events in that PLC's stage (Ch3 §3.5.4).
   - No rule links a process event to a later network event.
4. **Network event type order.** One event per flow. If a flow matches several types, the type is the first of: CIP control write, undocumented host, new connection, unusual volume. The other matches are kept in the detail field.
5. **Statistical lag match.** Δt must lie within the table's lag range widened by one 5-s block on each side (here 0–35 s). The sign is not checked.
6. **Unknown steps and the R5 rule (proposed decision D9).** Ch3 §3.5.1 passes the event log only to the evaluation code. Ch3 §3.5.6 also lists documented steps with no matching event as unknown. Proposal: modules 1–5 never read the documented-steps file. Explanation export reads it only **after** the paths are fixed, to list unknown steps. The code checks this, so the file cannot affect any link or score.

**Known weakness this campaign exposes (not a fix):** the "next later event on the same host" rule (Ch3 §3.5.4) makes ev02 link to the DNS lookup ev05 instead of the download ev06. So CausalGuard-OT misses the A→B link and gains a wrong A→C link. Real traffic from the workstation (for example DNS) can do the same in 2019. Options:
- (a) keep the rule as written and report this (recommended for now);
- (b) change the rule before the FYP2 freeze, on design grounds only, with its own expected outcome.

**Decisions (student, 15 Nov 2026, 21:53):**
- Items 1–5: confirmed as written.
- Item 6: D9 accepted. Modules 1–5 never read the documented-steps file; explanation export reads it only after the paths are fixed.
- Known weakness: option (a). The Chapter 3 rule is kept as written, and the result is reported as it comes. The answer key above is not changed to suit any outcome.

---

## B10. Freezing (done by the student)

1. Read this file. Confirm or change the six details in B9 and decide D9. Ask for changes before freezing; once frozen, it is not edited.
2. In PowerShell, run:
   `Get-FileHash -Algorithm SHA256 "C:\Users\kavin\OneDrive - Universiti Tenaga Nasional\UNITEN SEM 7\FYP\research\chapter-4\Expected_Outcomes_Part_B.md"`
3. Write the hash and the date in the logbook.
4. The prototype's synthetic configuration will hold the same hash. The prototype refuses to run its tests if the file has changed.

---

### Addenda (dated; added after freezing only)

*(none)*
