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
shrawler shares TARGET --hosts-file hosts.txt --workers 4 --view tree
```

In `shares --view tree`, each completed host prints as one contiguous block.
Blocks appear in completion order, which may differ from hosts-file order.

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
retrievals. Table results are paginated. Tree data contains the complete
filtered inventory, but the browser renders only expanded branches.
