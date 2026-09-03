# Canonical Ground Truth

This directory contains the repository-canonical Ground Truth used by the RQ2
and RQ3 runners.

- `ground_truth.csv`: 2,038 Ground Truth records; 158 CPE-bearing and 1,880
  without a Ground Truth CPE.
- `incorrect_cpe_fields.csv`: 345 Ground Truth-to-field relations.

Research loaders read the canonical CSVs from this directory. The historical
`.ground-truth/FINAL_GT_20260828/` archive is retained separately and is not a
runtime dependency.
