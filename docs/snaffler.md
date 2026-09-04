# Snaffler support

Snaffler mode recursively inventories readable shares and applies TOML
classification rules.

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

The default `--snaffler-content-mode relayed` reads content only when a metadata
rule relays a file to content evaluation. This avoids opening every eligible
file on the share.

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

Use `--interest 0` through `--interest 3` to set the minimum reported interest
level. Level 0 includes all matches.
