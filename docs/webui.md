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

## Screens

The interface has two screens: **Explore** at `/` and **Score** at `/score`.
`/triage` and `/assessment` redirect to `/score`, so older bookmarks still work.

## Explore

Explore is the landing screen and the default view. The table is the product;
everything else ranks it.

Search sits above the grid with `/` to focus it. Filters live behind a single
trigger that shows the active count (`Filters · 3`) and open as a popover, or a
bottom sheet on narrow viewports. Host, share, file type, Snaffler rule, triage,
share-root permission, collection state, transfer state, rank category, and
minimum rule rating are all filterable. Active filters also appear as removable
chips.

**Engine run selection** is a dedicated control rather than one more filter.
`Ranking` and `AI` each select a saved run or none, and Combined is their
weighted blend. Deselecting either engine re-weights Combined to the other
alone instead of filtering rows away, so "focus on AI only" is expressed by
turning the rule run off. Both engines keep their own column at all times, in
their own hues, for whichever runs are selected.

Every piece of view state lives in the URL, so any table state can be shared as a
link. Nothing is kept in `localStorage`.

Table view displays one paginated result set. Select a file to open its UNC
path, remote path, indexed time, and file actions beneath the row. Severity is
shown as a left rail on the row plus a chip on the Combined score, rather than a
tinted row background that would hurt the legibility of the path text.

File actions offer **View file**, **Download**, and **Queue for collection**.
Queueing saves a [collection manifest](collection.md) with byte caps and retry;
it is the only path for anything acting on more than one file.

**Percentage actions** act on a share of a ranked set rather than a hand-picked
selection. Choose the filtered set or the whole scan, a percentage, and a
destination. Before anything commits, the preflight reports the file count, the
bytes, and any files over the per-file cap.

Tree view groups the inventory by host, share, and folder. Branches are queried
only when expanded so large workspaces are not transferred as one hierarchy.

Search and the filters apply to both views. File details show matching rules,
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
switches from overall priority to a category score; Minimum rule rating filters
the selected score; and Sort can order table rows and expanded tree files by
rule rating. The displayed **Rule Rating** is a snapshot from that run. Files
discovered after the ranking remain unranked until the ranking is run again.

## Combined priority

The table and tree also show a **Combined** column that blends the rule-based
**Rule Rating** with the model's **AI Rating** on a common 0-100 scale:

```text
r = min(rating / 80, 1)          # 80 is the strongest built-in rule signal
j = clamp(jev, 0, 4) / 4
combined = round(100 * (0.5*r + 0.5*j) / (0.5*active_r + 0.5*active_j))
```

A component only counts when its run is selected, so the metric works with a
ranking alone, an AI run alone, or both. When both are selected but a file has
no result for one of them, the missing side counts as zero rather than being
renormalized away, so a partial assessment never inflates a score. With both
runs selected, an agreeing strong signal lands high (an SSH key rated 45 by the
rules and level 4 by AI reads 78), while a signal from only one side lands mid
scale (a rules-missed credential the AI rates 4 reads 50; a rule maximum the AI
rates 0 reads 50). If neither run is selected the column shows `—`.

The chip carries a coverage marker for which components fed the number: `●`
both, `◐` rules only, `○` AI only. Sort by **Combined** orders the page by this
score. Weights and the rating anchor are configurable under `[scoring]` in the
configuration file (`rating_full`, `rating_weight`, `jev_weight`).

Combined is mapped onto four severity bands, applied as a left rail on the row
and a chip in the score cell: 0-25 Minimal, 26-50 Likely, 51-75 Strong, 76-100
Immediate. Rule and AI keep their own hues rather than reusing the bands, so hue
says which engine produced a number and the rail says how urgent it is.

## Score

**Score** covers both engines and is reached at `/score`. A status strip stays
visible above the tabs whichever tab is open, because the two engines run
independently: an AI run started on one tab keeps reporting while you work on
the other. While a job runs it reports observed files, batches, pending, failed,
in-flight, reused, and retried requests. Cancel is available for either engine.

**Rule ranking** takes a source scan and optional starter rules. The rule builder
is a drawer that generates TOML into the editor below it; the editor is the
honest interface and can be edited directly or imported and exported. Candidates
list score, file, observed location, reasons, and per-file explanations. Match
counts and directory examples sit behind a disclosure.

**AI assessment** takes a source scan, staging choice, time budget, and a
question cap, and can probe the configured endpoint. Coverage reports per-run
totals, batch progress, latency, and the real billed token and cost figures.
Candidates can be filtered to strong values the rules missed, which is the
clearest statement of what the rule engine did not find.

**Collection queue** is shared. Manifests are created from the selected ranking,
run with retry, and report a per-file outcome. File families group saved metadata
by possible dates and versions and record review decisions, which a later ranking
applies. See [File-family review](families.md).

Assets are served from disk through an allow-list of extensions and validated
with `ETag` and `Last-Modified`, so a reload revalidates instead of re-downloading.
API responses are never cached and are compressed when the client accepts gzip.


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

Press `Ctrl+C` in the terminal that started Shrawler. Active ranking and
assessment jobs are asked to cancel during shutdown; completed runs remain in
their local databases.

Collection manifests are shared with the CLI: select candidates, save and review
a manifest, then collect or retry failed files. Offline sessions support creation
and review only.
