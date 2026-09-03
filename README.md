# CPE Validation for Industrial Firmware SBOMs

This repository supports an empirical study of Common Platform Enumeration
(CPE) reliability in software bills of materials (SBOMs) for industrial
firmware. It contains the canonical component-level Ground Truth, the fixed CPE
candidate universe, and the implementation used to evaluate CPE family
retrieval.

The experiments measure both the ability of string-similarity methods to
identify the correct CPE family (RQ2) and the change in NVD-based CVE
identification when original SBOM CPEs are replaced by validated Ground Truth
CPEs (RQ3).

## Repository Structure

- `backend/` — Django application, dataset models, matchers, and experiment
  management commands.
- `research/ground_truth/` — canonical Ground Truth and incorrect-field
  relations.
- `data/cpe_candidate_universe/` — fixed CPE product-family candidate universe.
- `analysis/figures/` — scripts and outputs for paper figures.

## Requirements

The verified environment uses:

- Python 3.14.4 (`.python-version`)
- Django 6.0.7 and psycopg 3.3.4 (`backend/requirements.txt`)
- PostgreSQL 18.4 (`postgres:18.4-trixie` in `compose.yaml`)

Create the Python environment and start PostgreSQL from the repository root:

```bash
cp .env.example .env
python3 -m venv backend/.venv
backend/.venv/bin/python -m pip install -r backend/requirements.txt
docker compose up -d db
```

Set `CPE_DICTIONARY_SNAPSHOT_ID=20260819T035002Z` and
`NVD_CVE_SNAPSHOT_ID=20260820T110357Z` in `.env`. Large research inputs may not
be included in Git. Before running the experiments, prepare the fixed CPE
Dictionary snapshot under `data/cpe-dictionary/20260819T035002Z/`, the fixed
NVD snapshot under `data/nvd-cve/20260820T110357Z/`, the four industrial
firmware SBOMs under `data/uploaded-sboms/`, and source evidence under
`data/source-artifacts/`.

Import the prepared snapshots and SBOM components into the configured database;
full reproduction requires both snapshots and all 2,038 study components. RQ2
can be run directly from the repository CSV inputs, while candidate universe
generation and RQ3 additionally query the database.

Output directories in the commands below must not already exist.

## Dataset

- Firmware images: 4
- Components: 2,038
- CPE Dictionary snapshot: `20260819T035002Z`
- NVD Configuration snapshot: `20260820T110357Z`

## Ground Truth

The canonical dataset is in `research/ground_truth/`:

- Components: 2,038
- CPE-bearing components: 158
- GT NULL components: 1,880
- Incorrect CPE Field relations: 345

The primary files are `ground_truth.csv` and `incorrect_cpe_fields.csv`.

## Reproducing the Experiments

Run all commands from the repository root.

### 1. Generate Candidate Universe

```bash
backend/.venv/bin/python backend/manage.py generate_cpe_candidate_universe \
  --cpe-snapshot 20260819T035002Z \
  --nvd-snapshot 20260820T110357Z \
  --output-directory reproduced/candidate_universe
```

Expected output:

- Total candidate families: 181,493
- Searchable candidate families: 181,484

### 2. RQ2 — CPE Family Retrieval

```bash
backend/.venv/bin/python backend/manage.py run_rq2_benchmarks \
  --ground-truth research/ground_truth/ground_truth.csv \
  --candidate-universe reproduced/candidate_universe/candidate_families.csv \
  --output-directory reproduced/rq2
```

The Candidate Universe CSV may not be included in Git. It can be regenerated
with `generate_cpe_candidate_universe` as shown above. If it is already prepared
at `data/cpe_candidate_universe/candidate_families.csv`, that path can instead be
passed to `--candidate-universe`.

| Method | Top-1 | Recall@5 | Recall@10 | MRR |
| --- | ---: | ---: | ---: | ---: |
| Length-normalized Levenshtein | 63/158 | 124/158 | 127/158 | 0.556541716461 |
| Jaro-Winkler | 69/158 | 134/158 | 140/158 | 0.608261225509 |
| Character Trigram-Dice | 79/158 | 136/158 | 142/158 | 0.652324405775 |
| Ratcliff–Obershelp | 72/158 | 130/158 | 132/158 | 0.605803762785 |

### 3. RQ3 — CVE Identification

```bash
backend/.venv/bin/python backend/manage.py run_rq3_matching \
  --ground-truth research/ground_truth/ground_truth.csv \
  --nvd-snapshot 20260820T110357Z \
  --output-directory reproduced/rq3
```

Expected component–CVE relation counts:

- Original: 14,750
- Ground Truth: 15,299
- COMMON: 14,697
- ADDED: 512
- REMOVED: 53
- INDETERMINATE: 1,747

To reproduce the ADDED-cause analysis, add
`--analyze-added-causes` to the command. Expected counts are:

- `VENDOR_ONLY`: 173
- `MULTI_FIELD`: 328
- `VERSION_EXACT_ONLY`: 10
- `VERSION_RANGE_ONLY`: 1

RQ3 identifies CVEs from NVD CPE criteria and version constraints. It does not
evaluate runtime applicability or VEX statements.

## Citation

Citation information will be added after the publication details are finalized.
