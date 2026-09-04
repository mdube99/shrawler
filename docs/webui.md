# Local WebUI

The WebUI opens a saved schema-v3 inventory and retrieves selected files from
SMB using credentials held by the server process.

The interface is designed for desktop browsers. Windows narrower than the
desktop layout retain the full data grid and scroll horizontally.

## Start the server

```bash
shrawler web ./results/shrawler_results.json 'DOMAIN/user@server'
```

Options:

| Option | Purpose |
| :--- | :--- |
| `--port PORT` | Select the local port, default `8765` |
| `--token-auth` | Require a random bearer token for API requests |
| `--preview-max-size SIZE` | Set the per-file preview limit, default 1 MiB |
| `--download-max-size SIZE` | Set the per-file download limit, default 50 MiB |
| `--page-size N` | Set Table view page size, from 1 through 500 |

The server binds only to `127.0.0.1` and prints its URL without opening a browser.
Token authentication is disabled by default. With `--token-auth`, Shrawler
prints a URL containing a random token in the fragment. The browser removes the
fragment from the visible URL, keeps the token in memory, and sends it as a
bearer credential.

## Views

Table view displays one paginated result set. Select a file to open its UNC
path, remote path, indexed time, and file actions beneath the row.

Tree view loads the complete filtered inventory and groups it by host, share,
and folder. Only expanded branches are rendered into the document, which keeps
large collapsed trees fast without a frontend framework.

Search and host, share, and file-type filters apply to both views.

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

Browser requests identify files by random opaque IDs assigned when the results
file is loaded. The browser cannot submit arbitrary host, share, or path values.

Files are fetched live and may differ from crawl metadata. Shrawler maintains a
small SMB session pool, limits concurrent retrievals, writes data to a private
temporary directory, and removes temporary files after transfer or disconnect.

One SMB credential context is tried against every host recorded in the results.
The optional host in `AUTH` provides authentication and Kerberos context. Each
inventory record supplies the actual destination.

## Test fixture

```bash
shrawler web ./test_shrawler_results.json 'user@127.0.0.1' -no-pass
```

The fixture exercises Table view, Tree view, filters, long paths, Unicode, and
file-type tags. Its hosts do not exist, so Preview and Download fail normally.

## Stopping the server

Press `Ctrl+C` in the terminal that started Shrawler.
