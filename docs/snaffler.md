# Snaffler support

Snaffler mode recursively inventories readable shares and applies TOML
classification rules inside Shrawler. It does not launch Snaffler.exe or another
external classification executable. Supported rules are interpreted by the
Python engine; this is not execution of the original Snaffler program.

```bash
shrawler snaffle 'DOMAIN/user@server' \
  --rules ./SnaffRules/DefaultRules \
  --interest 1 \
  --output ./results
```

## Rule support

Supported scopes:

- `ShareEnumeration`
- `DirectoryEnumeration`
- `FileEnumeration`
- `ContentsEnumeration`
- `PostMatch`

Supported actions:

- `Discard`
- `Snaffle`
- `Relay`

Supported word-list types:

- `Exact`
- `Contains`
- `Regex`
- `StartsWith`
- `EndsWith`

Supported locations:

- `ShareName`
- `FilePath`
- `FileName`
- `FileExtension`
- `FileContentAsString`
- `FileLength`

The first implementation does not execute `CheckForKeys`, `EnterArchive`,
`SendToNextScope`, `FileContentAsBytes`, or `FileMD5`. Unsupported or invalid
rules are warned and skipped. Use `--snaffler-strict` to fail instead.

## Content inspection

The default `--snaffler-content-mode relayed` schedules content rules when a
metadata rule relays a file to content evaluation. Content-based `PostMatch`
rules can also request content for an already matched candidate. Directory
listing and filename/path/extension checks do not themselves require reading
each file's contents. Broad relay rules can still select many files for reads.

When inspection needs content, the current implementation retrieves the full
file over SMB using `getFile` and evaluates it locally. The size gate and content
budget checks use the file size observed during enumeration; they are not a
streaming byte cap if a remote file grows afterward.

```bash
shrawler snaffle TARGET \
  --rules ./SnaffRules/DefaultRules \
  --max-content-reads 500 \
  --content-read-budget 256MiB
```

Use `--snaffler-content-mode all` for exhaustive content-rule evaluation. This
can generate substantially more SMB traffic. Content fetched for classification
is reused if the same file is downloaded.

`--snaffler-max-size-to-grep` sets the largest file eligible for content
matching. The default is 1 MiB.

## Matches and downloads

Matched files are downloaded automatically unless
`--snaffler-no-auto-download` is set. The result records the rule name, scope,
interest level, action, and file metadata. CSV output adds
`shrawler_snaffler_matches.csv`.

`--snaffler-no-auto-download` does not disable content inspection. Set
`--max-content-reads 0` to prevent classification content reads as well. Explicit
download filters can still request downloads independently; omit those when
using these options for metadata-only classification. Offline `shrawler triage`
operates solely on saved inventory and performs no SMB access.

Use `--interest 0` through `--interest 3` to set the minimum reported interest
level. Level 0 includes all matches.
