# Canonical Ground Truth

This directory contains the repository-canonical Ground Truth export frozen as
`FINAL_GT_20260828`.

- `ground_truth.csv`: 2,038 Ground Truth records; 158 CPE-bearing and 1,880
  without a Ground Truth CPE.
- `incorrect_cpe_fields.csv`: 345 Ground Truth-to-field relations.

The preserved source archive, hashes, manifests, audit files, evidence, and
policy remain under `.ground-truth/FINAL_GT_20260828/`. The canonical CSV files
are byte-identical to the corresponding frozen archive payloads:

- `ground_truth.csv` SHA-256:
  `ff6ad72e50278052199bd006afd88a2f51442e379c8b63dbf1a8232fd06aa8c2`
- `incorrect_cpe_fields.csv` SHA-256:
  `3e7a3776067cab0b12d8133a82af4cdf690e97c89fc46e8fd09f423d3c546c16`

Research loaders must read the canonical CSVs from this directory. The frozen
archive remains the provenance and integrity source and must not be removed.
