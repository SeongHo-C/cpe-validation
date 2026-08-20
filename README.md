# CPE Validation System

## 1. Overview

CPE Validation System is a local research workbench for evaluating CPE
evidence produced by SBOM tools. It imports Syft CycloneDX SBOMs, compares
Primary CPE strings with an official NVD CPE Dictionary snapshot by exact,
case-sensitive string equality, and supports independent Ground Truth review
using Component metadata.

Exact Dictionary membership is evidence, not a semantic correctness decision.
A CPE can be present in the Dictionary and still be wrong for a Component, or
absent while remaining a plausible Ground Truth candidate.

## 2. Key Features

- Import digest-pinned Docker image and CycloneDX SBOM metadata.
- Browse SBOM Components, provenance, package URLs, Primary CPEs, and package
  properties.
- Download, verify, and import an NVD CPE Dictionary snapshot.
- Evaluate raw-string CPE exact matches against one selected snapshot.
- Search active and deprecated official Dictionary records.
- Record a Dictionary CPE, a structurally valid Manual CPE, or no direct
  official CPE as Ground Truth.
- Derive Resolution Outcome on the server.
- Assign multiple managed Correction Types when the outcome permits them.

## 3. Technology Stack

The following versions are fixed by project files or were verified in the
current WSL/Linux development environment:

| Technology | Version |
| --- | --- |
| Python | 3.14.4 |
| Django | 6.0.7 |
| Django REST Framework | 3.17.1 |
| PostgreSQL | 18.4 (`postgres:18.4-trixie`) |
| Node.js | 22.22.1 |
| npm | 9.2.0 |
| React | 19.2.7 |
| TypeScript | 6.0.3 |
| Vite | 8.1.5 |
| Syft | 1.49.0 (`linux/amd64`) |
| SBOM format | CycloneDX JSON |

Python and Node.js compatibility outside these verified versions has not been
tested.

## 4. Repository Structure

```text
backend/    Django, DRF, SBOM import, Dictionary import, and analysis
frontend/   React and TypeScript user interface
pilot/      Fixed Docker image inputs, digest resolution, and SBOM generation
data/       NVD CPE Dictionary snapshot provenance
analysis/   Generated research analysis results
```

## 5. Prerequisites

- Git
- Docker Engine or Docker Desktop with Docker Compose
- Python 3.14.4
- Node.js 22.22.1 and npm 9.2.0
- Syft 1.49.0 when regenerating pilot SBOMs

The commands below were verified in WSL/Linux. Other environments may require
equivalent path or virtual-environment commands.

## 6. Environment Configuration

From the repository root, create the local environment file:

```bash
cp .env.example .env
```

The variables are:

| Variable | Purpose |
| --- | --- |
| `POSTGRES_DB` | PostgreSQL database name |
| `POSTGRES_USER` | PostgreSQL user |
| `POSTGRES_PASSWORD` | Local PostgreSQL password; replace the example value |
| `POSTGRES_PORT` | Host port bound to the PostgreSQL container |
| `CPE_DICTIONARY_SNAPSHOT_ID` | COMPLETE snapshot selected by the API |

This is a local, single-researcher prototype. Authentication and authorization
are not implemented. Keep Django and Vite bound to loopback and do not expose
them to an untrusted network.

## 7. Quick Start

Run these commands from the repository root unless a step says otherwise.

### 7.1 Clone and configure

```bash
git clone REPOSITORY_URL cpe-validation
cd cpe-validation
cp .env.example .env
```

Edit `.env` and replace the example PostgreSQL password.

### 7.2 Start PostgreSQL

```bash
docker compose up -d db
docker compose ps
```

### 7.3 Prepare the Backend

```bash
python3 -m venv backend/.venv
backend/.venv/bin/python -m pip install -r backend/requirements.txt
backend/.venv/bin/python backend/manage.py migrate
```

### 7.4 Prepare and import the CPE Dictionary

The current tracked manifest describes snapshot `20260725T035002Z`. Place its
matching archive as described in [CPE Dictionary Data](#8-cpe-dictionary-data),
then validate and import it:

```bash
backend/.venv/bin/python backend/manage.py import_cpe_dictionary \
  --snapshot-id 20260725T035002Z \
  --dry-run
backend/.venv/bin/python backend/manage.py import_cpe_dictionary \
  --snapshot-id 20260725T035002Z
```

Alternatively, download the current NVD feed as a new snapshot:

```bash
backend/.venv/bin/python backend/manage.py download_cpe_dictionary
```

Use the snapshot ID printed by the command for both import commands and update
`CPE_DICTIONARY_SNAPSHOT_ID` in `.env`. The current NVD URL is mutable and is
not guaranteed to reproduce the tracked historical snapshot.

### 7.5 Import the tracked pilot SBOMs

```bash
backend/.venv/bin/python backend/manage.py import_sboms
```

### 7.6 Start the Backend

```bash
backend/.venv/bin/python backend/manage.py runserver 127.0.0.1:8000
```

### 7.7 Install and start the Frontend

In another terminal:

```bash
cd frontend
npm ci
npm run dev
```

Open <http://127.0.0.1:5173>.

## 8. CPE Dictionary Data

The verified snapshot manifest is:

```text
data/cpe-dictionary/20260725T035002Z/manifest.json
```

The matching NVD archive is intentionally excluded from Git and must be placed
at:

```text
data/cpe-dictionary/20260725T035002Z/nvdcpe-2.0.tar.gz
```

The manifest records the source URLs, retrieval time, archive SHA-256, aggregate
content SHA-256, and the hashes of all 17 JSON members. Import fails if these
values, archive structure, record counts, or timestamps are invalid.

The official feed can be inspected without creating a snapshot:

```bash
backend/.venv/bin/python backend/manage.py \
  download_cpe_dictionary --dry-run
```

Download and verify the current feed:

```bash
backend/.venv/bin/python backend/manage.py download_cpe_dictionary
```

Then run `import_cpe_dictionary --dry-run` before the real import. Only COMPLETE
snapshots are selectable. If `CPE_DICTIONARY_SNAPSHOT_ID` is empty, selection
succeeds only when the database contains exactly one COMPLETE snapshot.

## 9. NVD CVE Snapshot Data

Freeze the complete NVD CVE JSON 2.0 yearly feed set, from 2002 through the
current UTC year, as a verified filesystem artifact:

```bash
backend/.venv/bin/python backend/manage.py download_nvd_cve_snapshot
```

The command preserves every original META and `.json.gz` file under
`data/nvd-cve/<SNAPSHOT_ID>/`, validates every feed, detects duplicate CVE IDs,
rechecks all META documents, and publishes the snapshot atomically. It does not
write to the database.

## 10. SBOM Data

The pilot uses ten Docker Official Images listed in `pilot/images.yaml`. All
images target `linux/amd64`; their platform manifest digests and pinned
references are stored in `pilot/results/image-digests.json`.

The tracked SBOMs were generated with Syft 1.49.0 from pinned remote-registry
references, using `squashed` scope, disabled online enrichment, and CycloneDX
JSON output. Import them with:

```bash
backend/.venv/bin/python backend/manage.py import_sboms
```

To regenerate pilot inputs, work from `pilot/`:

```bash
cd pilot
python3 -m pip install -r requirements.txt
python3 scripts/resolve_image_digest.py --input images.yaml
python3 scripts/generate_sbom.py
```

The scripts do not overwrite existing results unless overwrite behavior is
explicitly requested.

## 11. Running the Application

Start or inspect PostgreSQL from the repository root:

```bash
docker compose up -d db
docker compose ps
```

Start Django from the repository root:

```bash
backend/.venv/bin/python backend/manage.py runserver 127.0.0.1:8000
```

The Backend is available at <http://127.0.0.1:8000/api/>. It provides health,
image and Component inventory, Dictionary search and detail, exact-match
status, Ground Truth review, and Correction Type management endpoints.

Start Vite from `frontend/`:

```bash
cd frontend
npm run dev
```

The Frontend is available at <http://127.0.0.1:5173>. Vite proxies relative
`/api/...` requests to Django at `http://127.0.0.1:8000`.

The main routes are:

- `/images`
- `/components`
- `/cpe-dictionary`
- `/ground-truth`
- `/ground-truth/components/<component_id>`

Ground Truth Status indicates whether a review record exists. A record contains
one of these server-derived Resolution Outcomes:

- `ORIGINAL_OFFICIAL_CONFIRMED` — Original CPE confirmed
- `CORRECTED_TO_DICTIONARY` — Corrected to official CPE
- `MANUAL_FROM_OFFICIAL_FAMILY` — Manual CPE from official family
- `DIRECT_OFFICIAL_NOT_CONFIRMED` — Direct official CPE not confirmed

Correction Types are multi-valued. They are available for corrected Dictionary
CPEs and Manual CPEs, but not for original-confirmed or no-direct-official-CPE
outcomes. The Ground Truth list keeps the Exact Match filter, while the review
screen keeps Exact Match evidence in Component Context.

## 12. Testing and Build

Backend checks and tests, from the repository root:

```bash
backend/.venv/bin/python backend/manage.py check
backend/.venv/bin/python backend/manage.py \
  makemigrations --check --dry-run
backend/.venv/bin/python backend/manage.py test
backend/.venv/bin/python -m pip check
```

Frontend tests, lint, and production build:

```bash
cd frontend
npm test -- --run
npm run lint
npm run build
```

Pilot tests do not contact a registry:

```bash
cd pilot
python3 -m unittest discover -s tests -v
```

## 13. Current Limitations

- This is a local, single-researcher prototype without authentication or
  authorization.
- Raw-string exact match does not establish semantic CPE correctness.
- `NOT_IN_DICTIONARY` does not by itself prove that an SBOM CPE is wrong.
- Ground Truth has no reviewer identity, approval workflow, or revision
  history.
- Candidate ranking, BM25 search, CVE configuration evaluation, and AI
  suggestions are outside the current scope.
- The historical NVD archive is not stored in Git; the tracked manifest and
  hashes cannot guarantee that the same bytes remain downloadable later.
