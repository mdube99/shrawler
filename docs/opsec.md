# Permission checks and OPSEC

Shrawler performs network enumeration and may retrieve remote content. Choose
options that match the assessment rules of engagement.

## Permission modes

`--permission-check read-write` is the default for every profile. It:

1. Lists the existing share root to test read access.
2. Reuses that listing if recursive spidering follows.
3. Opens the existing share root and asks the server for individual write,
   directory creation, ACL, and ownership rights.

These access-mask checks do not create, rename, modify, or delete remote
objects. IPC, printer, device, and other non-filesystem shares are not write
probed.

Use read-only checks when write rights are outside scope:

```bash
shrawler shares TARGET --permission-check read
```

Disable permission checks when only share discovery is required:

```bash
shrawler shares TARGET --permission-check none
```

## Interpreting write rights

Shrawler reports these rights independently:

| Right | Meaning |
| :--- | :--- |
| `generic_write` | Broad write access granted by the server |
| `add_file` | Permission to create files in the tested directory |
| `add_subdirectory` | Permission to create directories |
| `write_dac` | Permission to change the discretionary ACL |
| `write_owner` | Permission to change ownership |

A granted access mask does not guarantee a completed write. AV or EDR,
application policy, quotas, and deeper ACLs can still deny an operation.
Writable subdirectories may also exist beneath a root that denies writes.

## Empirical write verification

```bash
shrawler shares TARGET --file-write-check
```

This check creates and deletes randomized file and directory names beginning
with `shrawler_write_test_`. Shrawler records cleanup results and residual UNC
paths. Interruption or denied cleanup can leave artifacts.

The check never runs as a fallback from an inconclusive access-mask request,
and no profile enables it. It requires `--permission-check read-write`.

## Traffic controls

- `--profile quiet` uses one host worker.
- `--workers N` controls parallel hosts, not parallel shares on one host.
- `--delay SECONDS` pauses between directory requests.
- `--max-depth N` limits recursive traversal.
- `--max-content-reads N` limits files opened for content analysis.
- `--content-read-budget SIZE` limits bytes read for content analysis.
- Download presets and budgets limit evidence retrieval.

Start with share enumeration, review access, then enable recursive or content
operations that the assessment permits.

## Credential handling

Omit passwords from the target string when possible. Shrawler then prompts in
the terminal. A password placed in the command may be visible in shell history
and process listings.

Nemesis credentials can be stored in the configuration file, which Shrawler
creates with mode `0600`, or supplied through `NEMESIS_AUTH`.
