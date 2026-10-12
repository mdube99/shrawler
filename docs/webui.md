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
minimum rule rating are all filterable.

The filter panel lists the fields on the left and the selected field's values on
the right. Type to narrow the values, then click one to **include** it or press
**−** beside it to **exclude** it. Enter includes the top match and Shift+Enter
excludes it. Each field shows `+n` / `−n` counts, and **Invert** swaps a field's
included and excluded values. The panel stays open while you build a filter, and
the table updates as you go.

- Several included values in one field match any of them (host is `alpha` *or*
  `bravo`).
- An excluded value is always removed, whatever else matches.
- Different fields combine with *and*.
- Rule and triage includes must hold on the same Snaffler match. A rule or
  triage exclusion removes a file if *any* of its matches carries the value.
  Files with no matches are kept.

Active filters appear as chips. Excluded chips are red, read `not`, strike the
value through, and lead with a `−` sign. Click the sign to flip a chip between
include and exclude, or `×` to remove it. **Clear filters** removes them all.
An expanded row also has a **Filter by this file** band. Use **+** to show only
that host, share, file type, or rule, or **−** to hide it. This drops noise such
as a domain controller's `SYSVOL` in one click.

Rank category and minimum rule rating stay single-value and need a ranking run.

### Filter URL contract

Filters are part of the shareable URL and use the same parameters as
`/api/files`, `/api/tree`, and `/api/tree/branch`:

| Parameter | Meaning |
| --- | --- |
| `host=a&host=b` | Include: host is `a` or `b`. A single `host=a` (the older link form) works as before. |
| `not_host=c&not_host=d` | Exclude: host is neither `c` nor `d`. |

The same pattern applies to `share`, `extension`, `rule`, `triage`,
`permission`, `collection`, and `activity`. Blank values are ignored. Values for
`permission`, `collection`, and `activity` must come from their fixed
vocabularies, for include and exclude alike. An unknown value, or more than 50
values for one parameter, returns `400` with code `invalid_query`. `q`,
`ranking_run`, `ranking_category`, and `ranking_min` stay single-valued. When
`/api/tree/branch` gets `level=shares`, it lists a host's shares and treats
`share` as a filter, not as the share to open.

**Engine run selection** is a dedicated control rather than one more filter.
`Ranking` and `AI` each select a saved run or none, and Overall is their
weighted blend. Deselecting either engine re-weights Overall to the other
alone instead of filtering rows away, so "focus on AI only" is expressed by
turning the rule run off. Both engines keep their own column at all times, in
their own hues, for whichever runs are selected.

The three score columns form one cluster under a shared **Scores** header: a
larger severity-coloured **Overall** pill, then smaller **Rule** and **AI 0–4**
pills in each engine's hue. The explanation of what each number is lives in the
column header's tooltip rather than a second line of text. The Overall header's
tooltip follows the engine selection exactly like the note beside the selectors,
so a column never claims a blend that is not active. Chip tooltips carry the same
statements as sentences, with the severity band for Overall.

Every piece of view state lives in the URL, so any table state can be shared as a
link. Nothing is kept in `localStorage`.

Table view displays one paginated result set. Each row leads with the file name
(with its type badge) over a path that is truncated from the middle on wide rows
and shortened to its last two segments on narrow ones, so the file name always
survives; location follows, then the score cluster. Each row carries two actions
— **Nemesis** and **Download**. A file already downloaded or sent keeps both
actions available; a small badge on the action records the history (a check for
one send, a count for repeat sends, `!` for a failure) and the detail panel
spells out `Downloaded 2×` or `Sent 2×`. A second send is a deliberate upload of
another copy, not a deduplicated no-op. The expanded detail panel adds **View
file** and the paths. A selection raises a sticky bar at the bottom of the
viewport with the bulk actions. Select a file to open a detail panel beneath the
row. The panel leads
with the paths and the file actions — **View file**, **Download**, and **Send to
Nemesis** — because retrieving a file and copying its UNC path are the
primary things you do once a file matters. Below that come **Assessment**, which
restates the three scores as colour-coded cards (Overall on the four-band
severity ramp, Rule in violet, AI in cyan), a **Collection** section, and a
disclosure for permissions and scan metadata. The panel carries the same
severity rail as its row, so expanding a file never drops the at-a-glance
signal. The row itself keeps severity as a left rail plus a chip on the Overall
score, rather than a tinted
background that would hurt the legibility of the path text.

File actions offer **View file**, **Download**, and **Send to Nemesis**.
Sending to Nemesis retrieves each file from SMB and uploads it to the configured
server in one request, with the per-file size cap and the persistent retry spool
described in [Nemesis delivery](nemesis.md). There is no manifest in this path:
clicking send is the send. A selection is sent one file at a time, and the
toast reports how many uploaded, failed, or came back ambiguous. The selection
does not need a rule rating; a file the selected ranking run never covered sends
like any other file. If Nemesis is not configured, the send buttons are disabled
with a note to configure it.

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

## Overall priority

The table and tree also show an **Overall** column that blends the rule-based
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

The tooltip names which components fed the number, e.g. `Overall priority
78/100 · Strong · rated by static rules + AI`. Rule and AI chips explain their
own scale and source on hover (rule weights, where 80+ fully alarms; the 0–4
Jev model rating). Sort by **Overall** orders the page
by this score. Weights and the rating anchor are configurable under
`[scoring]` in the configuration file (`rating_full`, `rating_weight`,
`jev_weight`).

Overall is mapped onto four severity bands, applied as a left rail on the row
and a chip in the score cell: 0-25 Minimal, 26-50 Likely, 51-75 Strong, 76-100
Immediate. Rule and AI keep their own hues rather than reusing the bands, so hue
says which engine produced a number and the rail says how urgent it is.

## Score

**Score** covers both engines and is reached at `/score`. The page opens on a
run console: one card per engine, side by side, Rule ranking in violet and AI
assessment in cyan. Each card is that engine's status and its controls.

- **State.** The card starts at `Checking…` and shows nothing until the server
  has answered. An idle engine is one muted line with its last outcome, such as
  `Last saved ranking 3m ago · 41,200 files`. A running engine takes on its hue
  and shows the phase, a large percentage, a progress meter, and its counts:
  scored or assessed files, plus batches, pending, failed, in-flight, reused,
  and retried requests for AI. Elapsed time comes from the job's `started_at`,
  and an estimate of the time left appears once there is a real rate. Starting,
  staging, planning, and the final rule save are not measured, so they show a
  moving stripe rather than a guessed or full bar.
- **Staleness.** After two failed polls in a row a card reads
  `Connection lost · last update Ns ago` and its spinner stops. When a counted
  phase's `updated_at` stops moving for a minute, the card reads
  `No progress for Ns`. If every engine is unreachable, a single page banner says
  the server cannot be reached.
- **Start and cancel.** The primary button (**Run ranking** or **Start
  assessment**) becomes **Cancel** in place while its engine runs. Only the
  essential inputs are on the card: the source scan, the starter-rules toggle
  for rules, and the time budget for AI. A refused start or a failed cancel is
  reported inside that card; it never clears or overwrites the other engine.
- **Outcome.** A finished run says how it ended, for example
  `Ranking saved · just now · 41,200 scored · 312 positive`, with **View
  candidates** and **Open in Explore** (which opens Explore with that run
  selected). Success, warning, and danger colours are kept for outcomes. Failed,
  partial, and paused runs raise a notification that stays until dismissed.
- **Configure** opens a drawer under the console. The rule drawer holds the TOML
  editor, Import/Export, the rule builder, and the preview workbench. The AI
  drawer holds the per-request question cap, the staging choice, and **Check
  endpoint**.
- An engine the server does not provide shows a permanent explanation in place
  of its controls instead of an error.

When the console scrolls out of view and an engine is busy, a one-line bar under
the header carries the state (`Rule: Scoring files 43% · AI: idle`) with Cancel.
The header shows the same jobs on every screen.

### Rule preview

**Run ranking** always saves. Previewing is a rule-iteration tool, so it lives
in the rule drawer beside the editor. **Preview ranking (not saved)** (or
`Ctrl+Enter` / `⌘↵` in the editor) scores every observed file with the editor's
rules into a separate preview database. Nothing is written to the saved
rankings. The server keeps the latest successful preview until it is saved,
discarded, or replaced by a newer preview, or until the server stops. A reload
shows it again, and its rules, starter-rule setting, and scan are known.

The pane beside the editor shows the preview's progress, its counts
(`41,200 scored · 312 positive`, with the change from the previous preview), and
its top hits. It notes when the preview is behind:
`Rules edited since this preview · Re-preview (⌘↵)` when the editor, starter
rules, or scan differ from what was previewed; also when a newer scan has
completed or review decisions have changed since.

**Show the full preview** opens it under **Rule candidates** as **Unsaved
preview**. The view has a dashed warning frame and a banner, and is never listed
among saved rankings. It reads the preview the same way as a saved run, with full
paging, Category, Min score, and **Explain**. Explanations are marked
`Previewed rules · not saved` and open "Why other rules did not match". A
**custom rule matches** disclosure lists each custom rule with its match count.
A custom rule that matched nothing is flagged with a hint to use Explain.
Selecting files for Nemesis or a manifest needs a saved ranking, so it is
disabled on preview rows.

**Compare with** sets a saved run to compare against. It defaults to the latest
saved run on the same scan, or None. With a run selected the table adds **Was**
(the saved run's priority) and **Δ**, and **Sort** switches between preview
priority and biggest change. The counts above the table (`changed`, `raised`,
`lowered`, `newly positive`, `no longer positive`) are filters. Raised, lowered,
and the positive transitions are applied in the browser over the changed files,
so a page may need to read several server pages. Comparing a different scan is
flagged. The first comparison reads both rankings in full and can take a while
on a large inventory.

**Save preview (rules as of HH:MM)** promotes the preview. The saved run gets
exactly the previewed scores; nothing is re-run. The card shows
`Saving preview` with a meter while rows are copied, then `Ranking saved · from preview`, and
the new run opens in Rule candidates. Saving asks for confirmation only when
there is a reason to hesitate: the editor has changed, a newer scan has
completed, or review decisions have changed since the preview. **Discard**
deletes the preview from the server. A new preview asks before replacing an
unsaved one. If a preview disappears (saved or discarded elsewhere, replaced, or
the server restarted), the page says so and returns to the saved ranking.

### Results

Results sit below the console in three tabs:

- **Rule candidates** lists score, file, observed location, reasons, and
  per-file explanations for a saved ranking (or the unsaved preview). Match
  counts and directory examples sit behind a disclosure.
- **AI candidates** shows coverage for the selected assessment run (per-run
  totals, batch progress, latency, and the real billed token and cost figures)
  and the assessed files by priority. Coverage refreshes every 5 seconds while an
  assessment runs.
- **Missed by rules** lists files the rule engine scored low that the model
  still judged worth strong review. It is the clearest statement of what the
  rule engine did not find.

Candidate links open Explore searched to that file.

**Collection & file families** sits in a closed disclosure at the bottom of the
page and loads when opened. Manifests are created from the selected saved
ranking, run with retry, and report a per-file outcome. File families group
saved metadata by possible dates and versions and record review decisions,
which a later ranking applies. See [File-family review](families.md).

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
committed files appear without restarting the server. The "new captures"
banner is keyed to the inventory revision, not to a diff between the
inventory size and the current result count: a search or filter that hides
files from the table never reports them as new captures, and the banner does
not promise a count. Show updates reloads the view, which clears it.

## Stopping the server

Press `Ctrl+C` in the terminal that started Shrawler. Active ranking and
assessment jobs are asked to cancel during shutdown; completed runs remain in
their local databases.

Collection manifests are shared with the CLI: on the Score page, select
candidates, save and review a manifest, then collect or retry failed files. This
is the advanced staging path with a total byte budget; the **Send to Nemesis**
actions on Explore and the Rule candidates tab do not create a manifest. Offline
sessions are read-only: they can review saved manifests, but creating or running
one requires a connection.
