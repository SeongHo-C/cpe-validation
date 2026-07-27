# CPE Validation

## Overview

CPE Validation is a research workbench for evaluating CPE evidence emitted by
external SBOM generators. The current pipeline preserves digest-pinned Docker
image inputs, imports Syft CycloneDX SBOMs, validates the structure of Primary
CPE 2.3 formatted strings, and imports a verified official NVD CPE Dictionary
snapshot.

Raw-string exact matching against the Dictionary is the next research step. It
is not implemented yet. Semantic review, candidate ranking, and Ground Truth
decisions remain later work.

## Research Scope

The current evaluation population is the set of SBOM Components whose
CycloneDX `component.cpe` field is non-empty. Syft `syft:cpe23` properties are
preserved separately as candidate evidence and are not promoted to Primary
CPEs.

A raw CPE appearing in the official Dictionary will not prove that it is
semantically correct for a Component. Likewise, absence from the Dictionary
will not by itself prove that a CPE is incorrect. Dictionary exact matching is
therefore a reproducible structural signal, not Ground Truth.

## Current Pipeline

1. Select ten Docker Official Images in `pilot/images.yaml`.
2. Resolve and preserve each `linux/amd64` platform manifest digest.
3. Generate Syft 1.49.0 CycloneDX JSON SBOMs from digest-pinned references.
4. Import image, SBOM, Component, Primary CPE, and Syft property evidence into
   PostgreSQL.
5. Profile Primary CPE structure without changing imported records.
6. Download, verify, and import an immutable NVD CPE Dictionary snapshot.
7. Browse the image and Primary CPE Component inventory through a read-only
   Django REST Framework API and React UI.

## Repository Structure

```text
backend/     Django, DRF, SBOM, and CPE Dictionary processing
frontend/    React research UI
pilot/       Docker image selection, digest pinning, and SBOM generation
analysis/    Generated research analysis results
data/        NVD CPE Dictionary snapshot provenance
```

## Requirements

The repository currently fixes or records these versions:

| Tool | Project version or image | Locally verified version |
| --- | --- | --- |
| Python | Not separately pinned | 3.14.4 |
| Django | 6.0.7 | 6.0.7 |
| Django REST Framework | 3.17.1 | 3.17.1 |
| PostgreSQL | `postgres:18.4-trixie` | 18.4 image configuration |
| Node.js | No `engines` constraint | 22.22.1 |
| npm | Lockfile version 3 | 9.2.0 |
| Syft | 1.49.0 | 1.49.0, `linux/amd64` |
| Docker | Not pinned | 29.5.2 |
| Docker Compose | Not pinned | 5.1.4 |

The backend uses `backend/requirements.txt`; the pilot has the separate
`pilot/requirements.txt`; and the frontend uses `frontend/package-lock.json`.
The commands below assume WSL or Linux.

## Quick Start

Create the local environment file and start PostgreSQL:

```bash
cp .env.example .env
docker compose up -d db
```

Create the backend environment, install its dependencies, and apply committed
migrations:

```bash
python3 -m venv backend/.venv
backend/.venv/bin/python -m pip install -r backend/requirements.txt
backend/.venv/bin/python backend/manage.py migrate
```

Import the tracked pilot SBOMs:

```bash
backend/.venv/bin/python backend/manage.py import_sboms
```

The current verified Dictionary import requires the corresponding
Git-excluded archive to be present beside its tracked manifest:

```bash
backend/.venv/bin/python backend/manage.py import_cpe_dictionary \
  --snapshot-id 20260725T035002Z \
  --dry-run
backend/.venv/bin/python backend/manage.py import_cpe_dictionary \
  --snapshot-id 20260725T035002Z
```

Start the backend:

```bash
backend/.venv/bin/python backend/manage.py runserver 127.0.0.1:8000
```

In another terminal, install and start the frontend:

```bash
cd frontend
npm ci
npm run dev
```

Open <http://127.0.0.1:5173>. Vite proxies relative `/api/...` requests to the
Django server at `http://127.0.0.1:8000`.

## Docker SBOM Pilot

The fixed pilot input contains ten Docker Official Images recorded as the
latest stable tags for the pilot on 2026-07-24:

| Repository | Tag |
| --- | --- |
| memcached | 1.6.45 |
| nginx | 1.30.4 |
| busybox | 1.38.0 |
| alpine | 3.24.1 |
| postgres | 18.4 |
| redis | 8.8.0 |
| ubuntu | 26.04 |
| python | 3.14.6 |
| node | 24.18.0 |
| mysql | 9.7.1 |

All scans target `linux/amd64`. `pilot/results/image-digests.json` records the
platform manifest digests and pinned references. Syft 1.49.0 scans the remote
registry source with online enrichment disabled, a `squashed` scope, and
CycloneDX JSON output.

From `pilot/`, install the one pilot Python dependency and run the commands:

```bash
python3 -m pip install -r requirements.txt
python3 scripts/resolve_image_digest.py --input images.yaml
python3 scripts/generate_sbom.py
```

Both scripts protect existing result files; they do not silently overwrite the
tracked pilot artifacts.

## NVD CPE Dictionary

The current snapshot ID is `20260725T035002Z`. Its tracked provenance manifest
is:

```text
data/cpe-dictionary/snapshots/20260725T035002Z/manifest.json
```

Inspect the current official Feed metadata without creating a snapshot:

```bash
backend/.venv/bin/python backend/manage.py \
  download_cpe_dictionary --dry-run
```

Download and verify the current official Feed:

```bash
backend/.venv/bin/python backend/manage.py download_cpe_dictionary
```

The command derives the snapshot ID from the Feed's last-modified timestamp.
Use the emitted ID for dry-run validation and PostgreSQL import:

```bash
backend/.venv/bin/python backend/manage.py import_cpe_dictionary \
  --snapshot-id SNAPSHOT_ID \
  --dry-run
backend/.venv/bin/python backend/manage.py import_cpe_dictionary \
  --snapshot-id SNAPSHOT_ID
```

The large `nvdcpe-2.0.tar.gz` archive is not committed to Git. The original
META file and verified manifest preserve source URLs, timestamps, archive and
content hashes, and per-chunk provenance. A source timestamp with an explicit
offset is converted to UTC. An NVD `created` or `lastModified` timestamp with
no offset is interpreted as UTC without rounding or changing millisecond
precision; invalid timestamps fail the import.

## Backend

The API is mounted at `/api/` and currently provides:

- database health;
- pilot image list and detail;
- dashboard summary;
- paginated Primary CPE Component list and detail.

The DRF endpoints are read-only. The Component endpoint supports image,
Primary CPE presence, search, ordering, page, and page-size parameters.

## Frontend

The desktop-oriented React UI provides:

- `/images` for the Docker image inventory and Primary CPE coverage;
- `/components` for the server-filtered Primary CPE queue and read-only
  Component evidence panel.

The Components route supports `image_id`, `search`, `ordering`, `page`,
`page_size`, and `component_id` query parameters. The application uses
`BrowserRouter`; a production static host would need an SPA fallback for
frontend routes.

The Validation Workbench remains disabled. The current detail API returns the
placeholder Dictionary status `UNVALIDATED`.

## CPE Profiling

Print the deterministic profile summary without writing output files:

```bash
backend/.venv/bin/python backend/manage.py profile_cpes --stdout-only
```

Regenerate the six known outputs under `analysis/results/cpe-profile/`:

```bash
backend/.venv/bin/python backend/manage.py profile_cpes
```

The profiler reads imported records and does not modify them.

## Tests

Run backend checks and tests from `backend/`:

```bash
cd backend
.venv/bin/python manage.py check
.venv/bin/python manage.py makemigrations --check --dry-run
.venv/bin/python manage.py test
```

Run frontend checks:

```bash
cd frontend
npm run lint
npm test -- --run
npm run build
```

Run the pilot unit tests without contacting a registry:

```bash
cd pilot
python3 -m unittest discover -s tests -v
```

## Current Pilot Dataset

The following counts apply to the tracked pilot and the
`20260725T035002Z` Dictionary snapshot:

| Measure | Count |
| --- | ---: |
| Docker images | 10 |
| SBOM documents | 10 |
| Components | 87,411 |
| Components with Primary CPEs | 1,769 |
| Unique Primary CPEs | 1,337 |
| Imported NVD CPE records | 1,786,125 |
| Active NVD CPE records | 1,687,483 |
| Deprecated NVD CPE records | 98,642 |

## Limitations

- The Dictionary raw-string exact-match API is not implemented.
- `UNVALIDATED` remains a placeholder Dictionary status.
- Dictionary membership is not a semantic correctness decision or Ground
  Truth.
- Semantic review and Ground Truth storage are later research stages.
- Candidate generation and ranking are outside the current implementation.
- Authentication, review history, exports, and frontend containerization are
  not implemented.
- The current NVD archive is excluded from Git; the tracked manifest and
  hashes preserve provenance but do not contain the archive bytes.
