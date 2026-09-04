# CLI workflows and options

`shrawler <command> --help` is the authoritative option reference. This page
collects the combinations used most often during an assessment.

## Commands

```text
shrawler shares TARGET [options]
shrawler spider TARGET [options]
shrawler snaffle TARGET --rules DIR [options]
shrawler report RESULTS [--retry-failed]
shrawler web RESULTS AUTH [options]
shrawler config [init|show|path|options]
```

`TARGET` and WebUI `AUTH` use this format:

```text
[[domain/]username[:password]@]<host>
```

Omit the password to receive a terminal prompt.

## Target selection

Scan the host embedded in the target:

```bash
shrawler shares 'DOMAIN/user@fileserver'
```

Use the target only for credentials and Kerberos context, then select another
host:

```bash
shrawler shares 'DOMAIN/user@dc.example.test' --host fileserver.example.test
```

Scan a list of hosts:

```bash
shrawler spider 'DOMAIN/user@dc.example.test' \
  --hosts-file hosts.txt \
  --workers 4
```

Blank lines and `#` comments in the hosts file are ignored. `--host` and
`--hosts-file` are mutually exclusive.

## Authentication

NTLM hash:

```bash
shrawler shares 'DOMAIN/user@server' -H ':NTHASH'
```

Kerberos credential cache:

```bash
shrawler shares 'DOMAIN/user@server' -k -no-pass
```

Kerberos AES key:

```bash
shrawler shares 'DOMAIN/user@server' -aesKey HEX_KEY -no-pass
```

Null session:

```bash
shrawler shares '@server' -no-pass
```

## Share selection

`--share` may be repeated:

```bash
shrawler spider 'DOMAIN/user@server' --share Finance --share Backups
```

Exclude shares:

```bash
shrawler spider 'DOMAIN/user@server' \
  --exclude-share Print$ \
  --exclude-share Software
```

`--shares` and `--add-share` remain available as comma-separated compatibility
forms.

## Downloads and analysis

Download the default interesting extension set:

```bash
shrawler spider 'DOMAIN/user@server' --download-ext default
```

Download selected extensions and names under conservative limits:

```bash
shrawler spider 'DOMAIN/user@server' \
  --download-ext '.txt,.config,.xlsx' \
  --download-name 'password,backup,secret' \
  --limits conservative
```

Available limit presets are `conservative`, `standard`, and `unlimited`.
`--max-file-size` and `--download-budget` override the preset values.

Count files without downloading them:

```bash
shrawler spider 'DOMAIN/user@server' \
  --count-ext '.txt,.pdf,.xlsx' \
  --count-string 'password,secret,backup' \
  --unique
```

## Output and progress

```bash
shrawler spider 'DOMAIN/user@server' \
  --output ./results \
  --format csv \
  --view progress
```

JSON results are always written. `--format csv` adds CSV files. Available views
depend on the command and include `summary`, `progress`, `matches`, and `tree`.

## Resume

```bash
shrawler spider 'DOMAIN/user@server' --resume ./results
```

When `--resume` has no value, Shrawler uses the current directory.

## Legacy invocation

The pre-command syntax remains available:

```bash
shrawler 'DOMAIN/user@server' --spider
```

Use the task-oriented commands for new automation.
