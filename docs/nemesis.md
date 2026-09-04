# Nemesis integration

Nemesis delivery is optional and disabled by default. It runs after Shrawler
selects a file for local acquisition.

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

## Delivery behavior

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

## Retry failed uploads

```bash
shrawler report ./results/shrawler_results.json --retry-failed
```

The report command reads locally downloaded files and retries failed or
interrupted uploads without reconnecting to SMB.
