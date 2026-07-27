# NVD CPE Dictionary snapshots

This directory stores immutable, reproducible snapshots of the official
[NVD CPE Dictionary 2.0](https://nvd.nist.gov/products/cpe).

Each snapshot ID comes from the Feed META `lastModifiedDate`, converted to
UTC and formatted as `YYYYMMDDTHHMMSSZ`. It is not based on the local
download time.

The official Feed archive contains one or more JSON chunks named exactly
like:

```text
nvdcpe-2.0-chunks/nvdcpe-2.0-chunk-00001.json
```

The downloader requires sequences to begin at 1 and remain contiguous. It
orders chunks by their numeric sequence, reads their original bytes without
JSON parsing or reserialization, and joins them conceptually with no
separator. Before a snapshot is finalized, it verifies:

- compressed archive size against META `gzSize`;
- aggregate raw chunk byte size against META `size`;
- aggregate raw chunk SHA-256 against META `sha256`;
- every archive member's name, type, path, and sequence safety.

The final directory is renamed into place only after every check succeeds.
Verified snapshots are immutable: a matching rerun is a no-op, while an
incomplete or conflicting directory is never overwritten automatically.
The schema version 2 manifest records each member's sequence, name, byte
size, and SHA-256 as well as the aggregate values. Any mismatch prevents
snapshot finalization.

The large `nvdcpe-2.0.tar.gz` archive and partial work files are excluded
from Git. The original `nvdcpe-2.0.meta` and generated `manifest.json` may
be committed as provenance records. The uncompressed JSON chunks are not
written to disk by the downloader.

Run from the repository root:

```bash
backend/.venv/bin/python backend/manage.py download_cpe_dictionary
```

Inspect the current META and planned path without downloading the Feed:

```bash
backend/.venv/bin/python backend/manage.py \
  download_cpe_dictionary --dry-run
```

Snapshots are not updated automatically during the experiment. Loading
Dictionary entries into PostgreSQL is a separate 5B step. Import a specific
VERIFIED snapshot from the repository root with:

```bash
backend/.venv/bin/python backend/manage.py \
  import_cpe_dictionary \
  --snapshot-id 20260725T035002Z
```

Validate every chunk and CPE record without database writes:

```bash
backend/.venv/bin/python backend/manage.py \
  import_cpe_dictionary \
  --snapshot-id 20260725T035002Z \
  --dry-run
```

The importer parses one JSON chunk at a time, inserts CPE names with batched
`bulk_create`, and wraps the complete snapshot import in one database
transaction. Any error rolls back both the snapshot row and all CPE rows.
Reimporting a consistent COMPLETE snapshot is a no-op.

NVD `created` and `lastModified` timestamps are stored as timezone-aware UTC
datetimes. An explicit source offset is applied before conversion to UTC.
Official Feed timestamps without an offset are interpreted as UTC without
altering or rounding their date, time, or millisecond precision. Invalid
ISO-8601 timestamps stop and roll back the import.

The 5A step verifies and preserves the official Feed snapshot; 5B loads that
VERIFIED snapshot into PostgreSQL. Exact matching against SBOM Primary CPEs
is deferred to 5C. The CPE Match Feed and incremental CPE API synchronization
remain outside the current scope.
