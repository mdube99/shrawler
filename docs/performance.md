# Performance and concurrency

Shrawler parallelizes independent hosts. Shares on one host remain sequential,
and one share tree is not traversed by several workers at once.

## Profiles

| Profile | Host workers | Permission checks | Default recursive view | Content mode |
| :--- | ---: | :--- | :--- | :--- |
| `quiet` | 1 | Non-invasive read/write | Matches | Relayed |
| `balanced` | 4 | Non-invasive read/write | Matches | Relayed |
| `fast` | 8 | Non-invasive read/write | Summary | Relayed |

Explicit arguments override profile defaults.

## Host concurrency

```bash
shrawler shares TARGET --hosts-file hosts.txt --workers 4
```

`shares` always prints one contiguous block per host. Blocks appear in
completion order, which may differ from hosts-file order.

Recursive `spider --view tree` and `snaffle --view tree` scans use one effective
host worker so terminal trees do not interleave. Select `progress`, `matches`,
or `summary` to retain host concurrency during recursive scans.

```bash
shrawler spider TARGET \
  --hosts-file hosts.txt \
  --workers 8 \
  --view progress
```

## Bounding work

Use these controls to limit network and local resource consumption:

| Option | Limit |
| :--- | :--- |
| `--max-depth N` | Recursive directory depth |
| `--delay SECONDS` | Pause between directory requests |
| `--max-content-reads N` | Files opened for content analysis |
| `--content-read-budget SIZE` | Bytes read for content analysis |
| `--max-file-size SIZE` | Per-file download size |
| `--download-budget SIZE` | Total bytes downloaded during the run |
| `--limits PRESET` | Combined download preset |

Snaffler's relayed content mode avoids opening files unless a metadata rule
passes them to content evaluation. Content already read by Snaffler is reused
if the file is downloaded.

## WebUI retrievals

The WebUI keeps a small per-host SMB session pool and permits two concurrent
retrievals. Table results are queried and paginated in SQLite. Tree branches are
loaded only when expanded.

Scan discoveries are committed to `shrawler.db` in bounded batches. This avoids
rewriting a growing JSON document for each file and permits concurrent WebUI
reads through SQLite WAL mode.

## Storage footprint

The inventory stores each discovered file once. `files.search_text` and
`files.readable_size` are virtual generated columns, so they cost no pages, and
`scan_files` keeps only the per-scan observation (size, readable size, mtime,
scan timestamp) plus its scan/share/file keys instead of a second copy of the
whole payload. Ranking and the WebUI rebuild that payload from the inventory.
The review database keeps only family membership, joining the inventory for
file details. Per-directory listings and the optional Jev audit documents are
zlib-compressed per row.

Measured on a 100,000-file synthetic inventory (20,000 directories, long
paths): a fresh inventory fell from 191 MiB to 125 MiB (-35%), and a schema-1
inventory shrank to 116 MiB (-39%, plus an ~8 MiB FTS index that the WebUI
rebuilds on demand) after the in-place migration and its one-time `VACUUM`. A
2,322-file Jev assessment database fell from 9.65 MiB to 6.48 MiB (-33%). The
remaining inventory size is dominated by the WebUI sort indexes and the FTS5
substring index.

Opening a schema-1 database migrates it in place; a scan, the WebUI, ranking,
review, or coverage can trigger the migration. Back up an inventory before the
first open with a newer build if it is irreplaceable.
