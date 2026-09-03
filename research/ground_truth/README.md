# Canonical Ground Truth

This directory contains the repository-canonical Ground Truth used by the RQ2
and RQ3 runners.

- `ground_truth.csv`: 2,038 Ground Truth records; 158 CPE-bearing and 1,880
  without a Ground Truth CPE.
- `incorrect_cpe_fields.csv`: 345 Ground Truth-to-field relations.
- `GROUND_TRUTH_POLICY.md`: the policy used to construct and freeze the dataset.
- `special_case_evidence.csv`: focused evidence summaries for 19 special cases.
- `CPE_UPDATE_QUALIFIER_POLICY.md`: the fixed CPE UPDATE-field policy and its
  supporting analysis.
- `family_evidence.csv`: same-family UPDATE evidence supporting that policy.

Research loaders read the canonical CSVs from this directory. Supporting policy
and evidence files are retained here for Ground Truth interpretation and review;
they are not runtime inputs for the RQ2 or RQ3 runners.
