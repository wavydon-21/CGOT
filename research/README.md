# research/

Two files from the FYP research folder that the code reads. Paths match the FYP folder, so the code is unchanged.

- `chapter-4/Expected_Outcomes_Part_B.md` — the frozen answer key for the synthetic campaign, written **before** any
  prototype code existed. `code/configs/synthetic.yaml` holds its SHA-256
  (`5F438DD4547113E631523CA9D26628E92E44E556981A5978C4C92E15286B7193`); the prototype refuses to run if the file
  changes. Do not edit it (line endings included; see `.gitattributes`).
- `chapter-3/analysis/tag_mapping_2015_2019.csv` — the SWaT 2015 → 2019 tag mapping, **reduced to tag names, kind
  and status**. The per-tag value ranges of the full file come from the SWaT data and are left out. The pilot's
  smoke-data generator uses only `tag_2015`, `kind` and `status`.
