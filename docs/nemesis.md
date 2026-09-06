# Nemesis integration

Nemesis delivery is optional. You can explicitly send an indexed file from the
WebUI or CLI without first downloading it yourself, or use the existing
scan-time delivery modes.

## Send an indexed file

Configure the URL, authentication, and project as described below. Start the
WebUI with SMB credentials, select a file, and choose one of three actions:

- **View file** opens a supported preview inside Shrawler.
- **Download** saves the file through your browser.
- **Send to Nemesis** retrieves and submits the file without a browser download.

Ranked review includes a **View / download / Nemesis** link to the same file
actions. These actions use the inventory's latest observation for that path;
an older ranking remains a historical snapshot.

```bash
shrawler web 'DOMAIN/user@server' ./results/shrawler.db

# FILE_ID is the public ID from inventory or triage results.
shrawler nemesis send ./results/shrawler.db FILE_ID 'DOMAIN/user@server'

# Retry a failed upload from its staged bytes; no SMB credentials needed.
shrawler nemesis send ./results/shrawler.db FILE_ID

# Inspect up to 1000 recent receipts without contacting SMB or Nemesis.
shrawler nemesis list ./results/shrawler.db
```

Sending reads the selected remote file into a private `<stem>.nemesis/` spool,
then uploads those bytes. It does not enumerate directories. The staged copy
is removed after an acknowledged upload; failures retain it for retry, including
across restarts. Receipts preserve the original filename, UNC path, observed
timestamps, SHA-256, destination/project, byte count, attempts, and response ID.
Nemesis receives the original filename rather than the spool's opaque filename.
Credentials are not saved in receipts.

Repeated sends for the same observed file and destination reuse the receipt or
staged bytes. A new observation or destination is a new delivery. Existing
browser downloads and collection-manifest evidence are separate from this spool;
they are not automatically reused. Upload retries verify staged hashes and refuse
missing or changed evidence instead of silently fetching replacement bytes.

An interrupted request or connection failure can leave the server's acceptance
unknown. Shrawler retains the bytes and blocks automatic resubmission. Check
Nemesis first, then use `shrawler nemesis send ... --retry-unknown` if needed;
this explicit retry may produce a duplicate. `uploaded` means API acceptance,
not completed enrichment or analyst review.

Direct sends are serialized per workspace and perform one upload attempt per
action. The WebUI limit is `--nemesis-max-size` (default 50 MiB); the CLI uses
`--max-file-size`. Both check the observed size and bytes received. A changed
file size aborts delivery, and partial retrievals are deleted. These are file
limits, not strict SMB wire-byte ceilings. Each separately requested preview or
browser download may read the file again.

In `web --offline` mode, configured Nemesis delivery can retry already staged
files, but cannot retrieve new remote files. Scan-time `--nemesis-mode off` does
not disable an explicit Send action. Delivery does not mark a collection
manifest item collected or an analyst decision reviewed.

## Scan-time modes

Available modes:

| Mode | Behavior |
| :--- | :--- |
| `off` | Keep evidence local and make no Nemesis requests |
| `matches` | Upload files downloaded because of a Snaffler match |
| `downloads` | Upload every file selected for download |

`matches` is available in `snaffle` mode. `downloads` is available in `spider`
and `snaffle` modes.

## Configuration

```bash
export NEMESIS_URL='https://nemesis:7443/api'
export NEMESIS_AUTH='username:password'
export NEMESIS_PROJECT='assessment'
```

```bash
shrawler snaffle TARGET \
  --rules ./SnaffRules/DefaultRules \
  --nemesis-mode matches
```

The same values can be supplied with `--nemesis-url`, `--nemesis-auth`, and
`--nemesis-project`, or stored under `[nemesis]` in the configuration file.

## Scan-time delivery behavior

Uploads run through a bounded background queue. SMB traversal continues while
workers submit files until the queue reaches capacity, at which point Shrawler
applies backpressure. Configure the queue with:

```text
--nemesis-upload-workers N
--nemesis-retries N
--nemesis-queue-size N
```

Failures use exponential backoff. Shrawler keeps the local file when delivery
fails and records status, attempt count, response ID, and the last error in JSON
and CSV output.

Nemesis uploads currently accept self-signed and otherwise untrusted TLS
certificates. Use this behavior only on a trusted assessment network.

## Retry failed scan-time uploads

```bash
shrawler report ./results/runs/RUN/shrawler_results.json --retry-failed
```

The report command reads locally downloaded files and retries failed or
interrupted uploads without reconnecting to SMB.
