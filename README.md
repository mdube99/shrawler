# Shrawler

Shrawler inventories SMB shares, checks effective access, recursively maps
files, applies Snaffler classification rules, and saves results for later review
through a local WebUI.

## What it does

- Enumerates shares on one host or a list of hosts
- Authenticates with passwords, NTLM hashes, Kerberos, or null sessions
- Reports read, write, ACL, and ownership rights separately
- Recursively inventories files without downloading them
- Applies Snaffler rules to file metadata and eligible content
- Downloads selected files within explicit size and run budgets
- Saves atomic checkpoints that support interrupted-scan recovery
- Produces schema-versioned JSON and optional CSV reports
- Uploads selected evidence to Nemesis when configured
- Browses saved inventories in Table and Tree views

## Installation

Shrawler requires Python 3.8 or newer.

### uv

```bash
git clone https://github.com/mdube99/shrawler.git
cd shrawler
uv tool install .
```

Reinstall after updating the working tree:

```bash
uv tool install --force .
```

### pipx

```bash
git clone https://github.com/mdube99/shrawler.git
cd shrawler
pipx install .
```

## Quick start

Shrawler prompts for the password when it is omitted from the target string.
This keeps passwords out of shell history and process listings.

Enumerate shares:

```bash
shrawler shares 'DOMAIN/user@server'
```

Recursively inventory readable shares:

```bash
shrawler spider 'DOMAIN/user@server' --output ./results
```

Classify files with Snaffler rules:

```bash
shrawler snaffle 'DOMAIN/user@server' \
  --rules ./SnaffRules/DefaultRules \
  --output ./results
```

Open the saved inventory:

```bash
shrawler web ./results/shrawler_results.json 'DOMAIN/user@server'
```

## Commands

| Command | Purpose |
| :--- | :--- |
| `shares` | Enumerate shares and assess permissions without recursion |
| `spider` | Recursively inventory files on readable shares |
| `snaffle` | Inventory files and apply Snaffler classification rules |
| `report` | Summarize results or retry failed Nemesis uploads |
| `web` | Browse saved results and retrieve selected files |
| `config` | Create and inspect persistent configuration |

Run `shrawler <command> --help` for the complete options accepted by a command.
The older `shrawler TARGET [options]` form remains available for compatibility,
but new scripts should use the task-oriented commands above.

## Authentication

The target format is:

```text
[[domain/]username[:password]@]<host>
```

### Password prompt

```bash
shrawler shares 'DOMAIN/user@server'
```

### NTLM hash

```bash
shrawler shares 'DOMAIN/user@server' -H ':NTHASH'
```

### Kerberos

```bash
shrawler spider 'DOMAIN/user@server' -k -no-pass
```

### Null session

```bash
shrawler shares '@server' -no-pass
```

Use `--host` to override the host embedded in the target while keeping its
credential context. Use `--hosts-file` to scan one host per non-empty line.
Lines may contain comments beginning with `#`.

More examples are in [docs/cli.md](docs/cli.md).

## Common workflows

### Scan several hosts

```text
# hosts.txt
192.0.2.10
192.0.2.11
fileserver.example.test
```

```bash
shrawler spider 'DOMAIN/user@dc.example.test' \
  --hosts-file hosts.txt \
  --output ./results
```

### Limit the scan to selected shares

```bash
shrawler spider 'DOMAIN/user@server' \
  --share Finance \
  --share Backups
```

### Download selected file types

```bash
shrawler spider 'DOMAIN/user@server' \
  --download-ext '.config,.txt,.xlsx' \
  --limits conservative
```

Omit the value after `--download-ext` to download every file that fits the
configured limits. Use `--download-ext default` for Shrawler's default set.

### Resume an interrupted scan

```bash
shrawler spider 'DOMAIN/user@server' --resume ./results
```

Shrawler appends discoveries to `scan-events.jsonl` and atomically publishes
`scan-state.json`. Completed hosts and shares are skipped during resume, and
previously recorded file paths are not processed twice.

### Use a low-noise profile

```bash
shrawler spider 'DOMAIN/user@server' --profile quiet --view progress
```

The available profiles are `quiet`, `balanced`, and `fast`. They select host
concurrency and terminal output defaults. Explicit options override the profile.

## Permission checks and OPSEC

The default `--permission-check read-write` mode lists the share root and asks
the SMB server for access masks on the existing root. It does not create,
modify, rename, or delete remote objects.

The result reports these rights separately:

- Generic write access
- File creation
- Subdirectory creation
- ACL modification
- Ownership control

An allowed access mask does not prove that a write will complete. AV or EDR,
quotas, application policy, and deeper directory ACLs can change the effective
result.

Use `--file-write-check` only when the assessment permits active verification:

```bash
shrawler shares 'DOMAIN/user@server' --file-write-check
```

This option creates and deletes recognizable randomized file and directory
names beginning with `shrawler_write_test_`. Interrupted or denied cleanup can
leave artifacts. No scan profile enables this option implicitly.

See [docs/opsec.md](docs/opsec.md) for permission semantics, traffic controls,
and operational guidance.

## Local WebUI

```bash
shrawler web ./results/shrawler_results.json 'DOMAIN/user@server'
```

Shrawler prints the local URL without opening a browser.

The WebUI provides:

- Paginated Table view for dense file review
- Complete filtered Tree view grouped by host, share, and folder
- Search by filename, path, host, share, or extension
- Inline file metadata and copyable UNC paths
- Conservative text, image, and PDF previews
- Live file retrieval from the recorded SMB source

The server binds to `127.0.0.1`. Local browser access does not require a WebUI
token by default. Add `--token-auth` to require a random bearer token:

```bash
shrawler web ./results/shrawler_results.json 'DOMAIN/user@server' --token-auth
```

SMB credentials stay in the server process and are never sent to the browser.
The browser can request only opaque file identifiers from the loaded inventory,
not arbitrary SMB coordinates.

### Try the interface without scanning

The repository includes a synthetic schema-v3 inventory:

```bash
shrawler web ./test_shrawler_results.json 'user@127.0.0.1' -no-pass
```

Search, filtering, pagination, and Tree navigation work without live SMB hosts.
Preview and Download fail as expected because the fixture refers to nonexistent
test systems.

See [docs/webui.md](docs/webui.md) for preview types, size limits, and security
details.

## Output and recovery

| Path | Contents |
| :--- | :--- |
| `shrawler_results.json` | Schema-versioned consolidated results |
| `scan-events.jsonl` | Append-only discovery and checkpoint events |
| `scan-state.json` | Latest atomic resume state |
| `shrawler_shares.csv` | Share permissions when CSV output is enabled |
| `shrawler_files.csv` | Discovered files when CSV output is enabled |
| `shrawler_downloads.csv` | Download metadata when CSV output is enabled |
| `shrawler_snaffler_matches.csv` | Snaffler matches when CSV output is enabled |
| `downloads/` | Files downloaded from SMB |

JSON output currently uses schema version 3. It contains `_schema` and
`_summary`, per-host status, per-share permissions, discovered files, download
digests, and Nemesis delivery state when configured.

Exit codes:

- `0`: every requested host completed successfully
- `1`: at least one host failed, rejected authentication, or had port 445 closed
- `130`: the scan was interrupted

The full schema and CSV columns are documented in
[docs/output-format.md](docs/output-format.md).

## Persistent configuration

```bash
shrawler config init
shrawler config show
shrawler config path
shrawler config options
```

Configuration precedence is command line, TOML file, Nemesis environment
variables, then mode and profile defaults.

```toml
profile = "quiet"
view = "progress"
format = "console"
output = "./results"

[snaffle]
rules = "./SnaffRules/DefaultRules"
interest = 1

[nemesis]
url = "https://nemesis:7443/api"
project = "assessment"
mode = "off"
upload_workers = 2
retries = 2
queue_size = 100
```

Shrawler creates the configuration file with mode `0600` because it may contain
Nemesis credentials. Prefer the `NEMESIS_AUTH` environment variable when you do
not want to store those credentials in the file.

## Snaffler and Nemesis

Snaffler mode loads TOML rules recursively and supports share, directory, file,
content, and post-match scopes. Content inspection defaults to relayed mode so
metadata rules decide which eligible files are read.

Nemesis is optional. It can receive Snaffler matches or every locally downloaded
file through a bounded background queue. Failed uploads preserve the local file
and can be retried without rescanning SMB:

```bash
shrawler report ./results/shrawler_results.json --retry-failed
```

See [docs/snaffler.md](docs/snaffler.md) and
[docs/nemesis.md](docs/nemesis.md) for supported rules and delivery behavior.

## Development

```bash
uv sync --extra dev
uv run ruff check shrawler tests shrawler.py
uv run ruff format --check shrawler tests shrawler.py
uv run pyright
uv run pytest -q
uv build
```

The package supports Python 3.8 and newer. Development currently targets the
strict type and lint configuration in `pyproject.toml`.

## Documentation

- [CLI workflows and options](docs/cli.md)
- [Permission checks and OPSEC](docs/opsec.md)
- [Local WebUI](docs/webui.md)
- [Snaffler support](docs/snaffler.md)
- [Nemesis integration](docs/nemesis.md)
- [Output formats](docs/output-format.md)
- [Performance and concurrency](docs/performance.md)
