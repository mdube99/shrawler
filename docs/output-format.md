# Output formats

Shrawler always writes JSON. `--format csv` adds flat CSV reports for analysis
in other tools.

## JSON

`shrawler_results.json` uses schema version 3:

```json
{
  "_schema": {"name": "shrawler-results", "version": 3},
  "_summary": {
    "hosts_attempted": 1,
    "shares_enumerated": 1,
    "files_seen": 1
  },
  "fileserver.example.test": {
    "status": "completed",
    "error": null,
    "shares": {
      "Finance": {
        "permissions": {
          "read": true,
          "write": false,
          "write_status": "denied",
          "write_check": "access-mask"
        },
        "unc_path": "\\\\fileserver.example.test\\Finance",
        "discovered_files": [
          {
            "remote_path": "/Reports/Q3.xlsx",
            "unc_path": "\\\\fileserver.example.test\\Finance\\Reports\\Q3.xlsx",
            "file_name": "Q3.xlsx",
            "size_bytes": 4096,
            "readable_size": "4KB",
            "mtime_utc": "2026-09-01T12:00:00+00:00",
            "scan_timestamp_utc": "2026-09-03T12:00:00+00:00"
          }
        ],
        "downloaded_files": []
      }
    }
  }
}
```

Hosts and shares may include additional status, permission, cleanup, and timing
fields. Download records include actual size and SHA-256 digest. Nemesis-enabled
runs add delivery status, attempts, response ID, and last error.

Version 2 resume state remains loadable. Legacy permission aggregates remain in
place when granular rights were not recorded.

## Checkpoints

`scan-events.jsonl` is an append-only event stream. `scan-state.json` is the
latest atomic checkpoint used by `--resume`. The final consolidated JSON is
written when the run completes.

## CSV files

| File | Main contents |
| :--- | :--- |
| `shrawler_shares.csv` | Host, share, comments, permissions, write rights, cleanup evidence |
| `shrawler_files.csv` | Every file discovered during recursive traversal |
| `shrawler_downloads.csv` | Local path, size, digest, source metadata, Nemesis state |
| `shrawler_snaffler_matches.csv` | Matching rule and file evidence |

CSV timestamps use UTC fields. Boolean permission columns remain scalar so they
can be filtered without parsing nested JSON.

## Downloads

Downloaded names are sanitized for local filesystems. Invalid characters are
replaced, repeated underscores are collapsed, and empty names become
`unnamed_file`. The JSON and CSV records retain the original UNC and remote
paths.
