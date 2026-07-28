# CPE Validation

## Overview

CPE Validation is a research workbench for evaluating CPE evidence emitted by
external SBOM generators. The current pipeline preserves digest-pinned Docker
image inputs, imports Syft CycloneDX SBOMs, validates the structure of Primary
CPE 2.3 formatted strings, and imports a verified official NVD CPE Dictionary
snapshot. It also compares Primary CPEs with that snapshot by exact,
case-sensitive raw-string equality.

The Workbench supports snapshot-specific, human-reviewed expected Ground
Truth annotations. Candidate ranking, approval workflows, and semantic
automation remain later work.

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
7. Evaluate raw Primary CPE strings against one explicitly selected COMPLETE
   Dictionary snapshot.
8. Browse the image and Primary CPE Component inventory through a read-only
   Django REST Framework API and React UI.
9. Search and inspect the selected official Dictionary snapshot through a
   read-only Dictionary surface in the Workbench.
10. Build snapshot-specific expected Ground Truth independently from future
    candidate-generation algorithms, using an official Dictionary CPE, a
    structurally valid manual CPE 2.3 string, or no CPE.

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

Set `CPE_DICTIONARY_SNAPSHOT_ID=20260725T035002Z` in `.env` to make the
snapshot used by the Component Detail API explicit. If this setting is empty,
automatic selection is allowed only when the database contains exactly one
COMPLETE snapshot.

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

Only COMPLETE snapshots can be used for exact matching. An explicit snapshot
ID must exist and be COMPLETE. Without an explicit ID, zero COMPLETE snapshots
is an error and multiple COMPLETE snapshots are ambiguous; the application
never selects the newest snapshot by timestamp or database ID.

## Backend

The API is mounted at `/api/` and currently provides:

- database health;
- pilot image list and detail;
- dashboard summary;
- paginated Primary CPE Component list and detail;
- raw-string Dictionary status and snapshot provenance for Component detail;
- paginated CPE Dictionary search and CPE record detail;
- Component- and snapshot-specific expected Ground Truth retrieval and
  upsert;
- a filtered, paginated Ground Truth review queue.

The inventory, Component, and CPE Dictionary endpoints are read-only. The
Component list endpoint supports image, Primary CPE presence, Dictionary
status, search, ordering, page, and page-size parameters. List rows contain
`dictionary_status` but omit per-record Dictionary provenance; Component
detail provides the selected snapshot and matched NVD CPE record. The
dedicated Ground Truth endpoint is the only write API in this workflow.

Filter the list before pagination with:

```text
GET /api/components/?dictionary_status=NOT_IN_DICTIONARY
```

Supported values are `OFFICIAL_ACTIVE`, `OFFICIAL_DEPRECATED`,
`NOT_IN_DICTIONARY`, and `NOT_PRESENT`. The default list retains its existing
`has_cpe=true` scope. `dictionary_status=NOT_PRESENT` uses the missing-Primary-
CPE scope; explicitly contradictory `has_cpe` and `dictionary_status` values
return HTTP 400.

The Dictionary endpoints are:

```text
GET /api/cpe-dictionary/
GET /api/cpe-dictionary/snapshot/
GET /api/cpe-dictionary/<cpe_name_id>/
```

Search accepts `q`, `part`, `vendor`, `product`, `version`, optional exact
`cpe_name`, `deprecated`, `page`, and `page_size`. `q` searches raw CPE,
vendor, product, version, and stored title JSON case-insensitively. Structured
vendor, product, and version filters use case-insensitive exact equality;
there is no alias or version normalization. A keyword or structured search
term is required, the default status is active, and page sizes are limited to
25, 50, or 100. All Dictionary endpoints use the same explicit-or-unique
COMPLETE snapshot contract as exact matching and permit GET only.

The Component Ground Truth endpoint is:

```text
GET /api/components/<component_id>/cpe-ground-truth/
PUT /api/components/<component_id>/cpe-ground-truth/
```

The server selects the current COMPLETE snapshot. `PUT` creates or updates
the single annotation for that Component and snapshot. An optional selected
`CpeName` must belong to the same snapshot; `decision_type` is required
free text with outer whitespace removed, and `note` is optional. A manual
`manual_cpe` may be stored instead of a Dictionary record when it passes the
existing CPE 2.3 structural parser. Dictionary and manual values are mutually
exclusive. The imported `Component.cpe` value is never replaced or modified.

The review queue and filtered navigation endpoints are:

```text
GET /api/ground-truth/components/
GET /api/ground-truth/components/<component_id>/navigation/
```

The queue defaults to Components with a non-empty Primary CPE. It supports
image, Ground Truth record presence, exact-match status, keyword, stable ID
ordering, page, and page-size parameters. Review status is derived from
record existence rather than stored as a workflow field.

## Frontend

The desktop-oriented React UI provides:

- `/images` for the Docker image inventory and Primary CPE coverage;
- `/components` for the server-filtered Primary CPE queue and read-only
  Component evidence panel;
- `/ground-truth` for the independent human review queue;
- `/ground-truth/components/<component_id>` for Component evidence,
  Dictionary lookup, and expected Ground Truth entry;
- `/cpe-dictionary` for independent read-only official Dictionary search and
  record inspection.

The Components route supports `image_id`, `search`, `ordering`, `page`,
`page_size`, `dictionary_status`, and `component_id` query parameters. Its
table shows structural and Dictionary status side by side. The Dictionary
filter is preserved in the URL, composes with the existing image and search
filters, and requests `has_cpe=false` for `NOT_PRESENT`. Component detail shows
a summary status badge at the top and keeps snapshot and UUID provenance in
the detailed Dictionary section. Status indicates raw-string presence in the
selected NVD snapshot, not semantic correctness. The application uses
`BrowserRouter`; a production static host would need an SPA fallback for
frontend routes.

The Ground Truth list keeps filters and pagination in the URL and distinguishes
raw-string exact-match evidence from whether a human annotation exists. Its
editor restores the list queue for previous, next, and save-then-next
navigation. Component evidence and the write panel remain visible with a
desktop sticky layout. Dictionary selection changes only local editor state
until explicit save; the reviewer can instead copy and edit a raw CPE as a
manual structurally validated value, or save no CPE. Notes remain optional
and collapsed by default.

The generic Dictionary route has no Component or Ground Truth state. Its
search form and pagination state remain in the URL, and background page
fetches retain prior results behind a loading overlay. The record drawer
exposes all CPE 2.3 fields, titles, references, raw-string and UUID copy
controls. Candidate ranking, BM25, fuzzy matching, aliases, normalization,
AI, automatic CPE replacement, controlled decision taxonomies, approval, and
revision history remain outside this implementation.

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

## Dictionary Exact Match

The exact-match service compares only:

```text
Component.cpe == CpeName.cpe_name
```

It does not trim, normalize case or escapes, apply aliases, replace deprecated
CPEs, or parse the string as a prerequisite. Results use four statuses:

- `OFFICIAL_ACTIVE`: an identical active Dictionary record exists;
- `OFFICIAL_DEPRECATED`: an identical deprecated Dictionary record exists;
- `NOT_IN_DICTIONARY`: a Primary CPE exists but no identical record exists;
- `NOT_PRESENT`: the Component has no Primary CPE.

These statuses are automated evidence, not a semantic correctness decision or
Ground Truth. Reproduce the unique-CPE and Component-level evaluation with:

```bash
backend/.venv/bin/python backend/manage.py evaluate_cpe_exact_matches \
  --snapshot-id 20260725T035002Z
```

The default output directory is
`analysis/results/cpe-exact-match/20260725T035002Z/` and contains
`summary.json`, `unique_cpe_matches.csv`, and `component_matches.csv`. Use
`--output-dir` to choose another directory. Existing known output files are
protected unless `--overwrite` is supplied. The command reads the database but
does not create or update match records.

## Dictionary Mismatch Profiling

Profile unique `NOT_IN_DICTIONARY` Primary CPEs against the selected
Dictionary snapshot with exact equality at three structured-field levels:

```text
part + vendor + product + version
part + vendor + product
part + product
```

The mutually exclusive statuses are
`SAME_PART_VENDOR_PRODUCT_VERSION`, `SAME_PART_VENDOR_PRODUCT`,
`SAME_PART_PRODUCT`, `NO_STRUCTURED_MATCH`, and `UNPARSABLE`. The comparison
does not normalize fields, apply aliases, rank candidates, or decide semantic
correctness or Ground Truth.

Run the read-only analysis with:

```bash
backend/.venv/bin/python backend/manage.py \
  profile_cpe_dictionary_mismatches \
  --snapshot-id 20260725T035002Z
```

The default snapshot-specific directory is
`analysis/results/cpe-dictionary-mismatch/20260725T035002Z/`. It contains
`summary.json`, `unique_cpe_mismatch_profiles.csv`, and
`field_value_counts.json`; existing known files require `--overwrite`.

For snapshot `20260725T035002Z`, the 1,331 unique raw mismatches profile as 3
`SAME_PART_VENDOR_PRODUCT_VERSION`, 44 `SAME_PART_VENDOR_PRODUCT`, 149
`SAME_PART_PRODUCT`, 1,135 `NO_STRUCTURED_MATCH`, and 0 `UNPARSABLE`. These
counts measure exact structured-field presence only and do not identify a
correct replacement CPE.

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

For raw-string exact matching against snapshot `20260725T035002Z`, the 1,337
unique Primary CPEs contain 6 `OFFICIAL_ACTIVE`, 0
`OFFICIAL_DEPRECATED`, and 1,331 `NOT_IN_DICTIONARY` results. At Component
level, the counts are 6, 0, 1,763, and 85,642 respectively for
`OFFICIAL_ACTIVE`, `OFFICIAL_DEPRECATED`, `NOT_IN_DICTIONARY`, and
`NOT_PRESENT`.

## Limitations

- Dictionary search is deterministic field/keyword lookup, not candidate
  ranking or semantic matching.
- Dictionary membership is not a semantic correctness decision or Ground
  Truth.
- Stored Ground Truth is a single expected human annotation per Component
  and snapshot; there is no reviewer identity, approval state, or revision
  history.
- Candidate generation and ranking are outside the current implementation.
- Authentication, review history, exports, and frontend containerization are
  not implemented.
- The current NVD archive is excluded from Git; the tracked manifest and
  hashes preserve provenance but do not contain the archive bytes.
