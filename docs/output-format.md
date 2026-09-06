# Output formats

Shrawler always writes JSON. `--format csv` adds flat CSV reports for analysis
in other tools.

## JSON

Each run's `runs/<run>/shrawler_results.json` uses schema version 3:

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

## Live state and resume

`shrawler.db` is the live multi-scan inventory and resume source. Discovered
files are committed in batches and can be searched by the WebUI while scanning.
The consolidated JSON is exported after normal completion and on Ctrl+C.

## CSV files

| File | Main contents |
| :--- | :--- |
| `shrawler_shares.csv` | Host, share, comments, permissions, write rights, cleanup evidence |
| `shrawler_files.csv` | Every file discovered during recursive traversal |
| `shrawler_downloads.csv` | Local path, size, digest, source metadata, Nemesis state |
| `shrawler_snaffler_matches.csv` | Matching rule and file evidence |

CSV timestamps use UTC fields. Boolean permission columns remain scalar so they
can be filtered without parsing nested JSON.

Share rows include `status` and `skip_reason`, including shares omitted by the
default exclusions, explicit exclusions, share selection, or classification rules.
Skipped shares have no inferred permission result: they were not checked.

CSV string cells that could be interpreted as spreadsheet formulas are prefixed
with an apostrophe. This also applies when the formula follows whitespace or
control characters. JSON retains the original evidence values without this
presentation escaping. Terminal output renders control characters as visible
escape sequences so remote names cannot issue terminal commands.

## Downloads

Downloaded names are sanitized for local filesystems. Invalid characters are
replaced, repeated underscores are collapsed, and empty names become
`unnamed_file`. JSON records retain the original UNC and remote paths; CSV
retains them with the spreadsheet protection described above when necessary.
