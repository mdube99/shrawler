# Local WebUI

The WebUI searches a live Shrawler SQLite workspace and retrieves selected files
from SMB using credentials held by the server process.

The interface is designed for desktop browsers. Windows narrower than the
desktop layout retain the full data grid and scroll horizontally.

## Start the server

```bash
shrawler web 'DOMAIN/user@server' ./results/shrawler.db
```

For browsing and ranking without remote retrieval:

```bash
shrawler web --offline ./results/shrawler.db
```

Offline mode requires no SMB credentials and disables remote previews and
downloads in both the interface and API.

Options:

| Option | Purpose |
| :--- | :--- |
| `--offline` | Browse and rank saved metadata without SMB credentials or retrieval |
| `--port PORT` | Select the local port, default `8765` |
| `--token-auth` | Require a random bearer token for API requests |
| `--preview-max-size SIZE` | Set the per-file preview limit, default 1 MiB |
| `--download-max-size SIZE` | Set the per-file download limit, default 50 MiB |
| `--nemesis-max-size SIZE` | Set the per-file Nemesis transfer limit, default 50 MiB |
| `--nemesis-url`, `--nemesis-auth`, `--nemesis-project` | Configure explicit Nemesis delivery; also accepts existing config/environment values |
| `--page-size N` | Set Table view page size, from 1 through 500 |

The server binds only to `127.0.0.1` and prints its URL without opening a browser.
Token authentication is disabled by default. With `--token-auth`, Shrawler
prints a URL containing a random token in the fragment. The browser removes the
fragment from the visible URL, keeps the token in memory, and sends it as a
bearer credential.

## Views

**Ranked review** opens a separate page for scan-specific priorities, category
filters, saved ranking history, and explanations. Its rule builder supports
filename fragments, extensions, directory labels, and sibling filename patterns.
Preview rules against the saved inventory, export their TOML for the CLI, or run
and save a ranking for paginated review. Jobs report progress and can be cancelled.
See [Offline metadata triage](triage.md) for rule semantics and limitations.

Table view displays one paginated result set. Select a file to open its UNC
path, remote path, indexed time, and file actions beneath the row.

File actions offer **View file**, **Download**, and **Send to Nemesis** separately.
Sending requires no prior browser download: Shrawler stages the remote bytes,
uploads them, and deletes the staged copy after success. Failed uploads retain
their staged copy for local retry. See [Nemesis delivery](nemesis.md) for limits,
receipts, and recovery. Ranked review links to these same actions.

Tree view groups the inventory by host, share, and folder. Branches are queried
only when expanded so large workspaces are not transferred as one hierarchy.

Search and host, share, file-type, Snaffler rule, triage, permission, and
collection-status filters apply to both views. File details show matching rules,
share-root read/write permissions, collection status, and the indexed evidence
timestamp. In cumulative database mode these fields come from the latest file
observation scan, so findings and permissions from separate scanner identities
are not combined. A file with no recorded download is shown as
`not_collected`; that does not imply that collection was attempted and failed.
Permission fields are share-root observations: read/write access plus tested
rights such as add file, add directory, write DAC, and write owner. They do not
replace an ACL review on the file itself.

After a ranking run completes, the main inventory automatically selects the
latest completed run. The Ranking filter chooses another saved run; Rank category
switches from overall priority to a category score; Minimum rating filters the
selected score; and Sort can order table rows and expanded tree files by rating.
The displayed rating is a snapshot from that run. Files discovered after the
ranking remain unranked until the ranking is run again.

## Preview handling

Text previews accept UTF-8 files with these extensions:

```text
.txt .log .csv .json .xml .ini .conf .config .cnf .properties .prop
.yaml .yml .md .rst .py .js .ts .jsx .tsx .java .cs .go .rs .rb
.php .ps1 .bat .cmd .vbs .sh .sql .pem .key
```

PNG, JPEG, GIF, WebP, and PDF previews require matching magic bytes. HTML and
SVG are not rendered. Text containing null bytes, invalid UTF-8, or too many
non-printable characters is rejected.

PDF previews run in a sandboxed frame. The server sends a restrictive Content
Security Policy, disables MIME sniffing, denies browser device permissions, and
marks all responses as non-cacheable.

## File retrieval

Browser requests identify files by random opaque IDs stored in the inventory.
The browser cannot submit arbitrary host, share, or path values.

Files are fetched live and may differ from crawl metadata. Shrawler maintains a
small SMB session pool and limits concurrent retrievals. Preview and browser
download files use a private temporary directory and are removed after transfer
or disconnect. Nemesis delivery uses its separate persistent retry spool.

One SMB credential context is tried against every host recorded in the database.
The optional host in `AUTH` provides authentication and Kerberos context. Each
inventory record supplies the actual destination.

The browser polls the database revision while a scan is active, so newly
committed files appear without restarting the server.

## Stopping the server

Press `Ctrl+C` in the terminal that started Shrawler. An active ranking job is
asked to cancel during shutdown; completed rankings remain in the local triage
database.

The **Ranked review** page also provides a persistent [collection queue](collection.md): select candidates, save and review a manifest, then collect or retry failed files. CLI and WebUI share the same manifests. Offline sessions support creation and review only.

**Ranked review → File families** groups saved metadata, expands family members, records file/family review decisions, and supports undo. New rankings apply those decisions. Local evidence hashing confirms duplicate content without remote reads. See [File-family review](families.md).
