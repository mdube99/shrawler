# Offline metadata triage

Shrawler can rank a saved SQLite inventory for analyst review without SMB
credentials or remote file reads. The CLI and WebUI share the same scoring
engine, including substring matching, bounded directory labels, and context
inferred from observed sibling filenames. See [collection manifests](collection.md) for selective retrieval and
[file-family review](families.md) for reversible analyst decisions. Snaffler
rule import is not included.

A score is **review priority**, not a probability or confirmation that a file
contains sensitive information. Zero-score files remain available. Ranking
only describes observed files; it does not establish coverage of unlisted paths.

## Quick start

```bash
# Score the latest completed spider/snaffle scan with the starter rules.
shrawler triage run ./results/shrawler.db

# Or select a full/short scan ID explicitly.
shrawler triage run ./results/shrawler.db --scan SCAN_ID

# Review a category, highest score first.
shrawler triage list ./results/shrawler.db --category infrastructure --limit 100

# Explain a file using its FILE ID from the list output.
shrawler triage explain ./results/shrawler.db -- FILE_ID
```

`run`, `list`, `explain`, and `rules test` accept `--json` for machine-readable
output. `list` accepts `--min-score N`. `list` and `explain` accept `--run RUN_ID`
to review a previous ranking; their default is the latest completed ranking
for the given inventory path. `--limit` is bounded to 1–10000.

Opaque file IDs may begin with a hyphen. The `--` before `FILE_ID` ends option
parsing; place options such as `--json` and `--run` before that separator.

The inventory is opened read-only. Results are stored beside it in
`shrawler.triage.db` (generally `<inventory-stem>.triage.db`). The directory must
be writable for ranking. The original scan database and downloaded evidence are
not modified.

## Ranked review in the WebUI

```bash
shrawler web --offline ./results/shrawler.db
```

Open the printed URL and select **Ranked review**. Offline mode requires no
SMB credentials and rejects remote preview/download requests. Ranked review is
also available in a normal authenticated WebUI session; scoring itself always
uses saved metadata.

Select a source scan, then preview or save a ranking. **Customize rules** provides
a small builder for filename fragments, extensions, nearby directory names,
sibling markers, and exact subtree labels. Its output goes into an editable TOML
document. Import/export uses the same custom-rule format as the CLI. Exported
custom rules do not include starter rules; use the CLI's `--no-builtins` when
reproducing a browser run that had **Include starter rules** unchecked.

Preview results show positive-file counts, per-rule match counts, examples from
up to 20 different observed directories, and the first 100 ranked candidates.
They are temporary and are not retained as a saved ranking. Save a ranking to
browse all its candidates, filter by category or minimum score, and inspect
persisted explanations. Saved pages use score/file-ID cursors so tied scores do
not cause files to repeat or disappear between pages.

The server permits one ranking job at a time, reports the sibling-indexing and
scoring phases, and supports cancellation. The browser's rule editor is not
autosaved; export custom TOML before leaving the page. Saved runs retain the
effective rules and scoring evidence. Preview is not a statistical sample or a
before/after comparison, and analyst review dispositions are managed separately through file-family review.

## Scoring behavior

Rules are evaluated against the selected scan's saved observations, including
its historical sizes and names, rather than the mutable latest-file metadata.

- All conditions within a rule are ANDed.
- Values within an `*_any` condition are ORed.
- Each matching rule produces an explanation with observed matching values.
- Within each category/signal group, only the highest rule weight contributes.
  Equal weights credit the lexically first rule ID. Other matches remain in the
  explanation with zero `credited_points` and a `capped_by_rule` reference.
- A category score is the sum of its independent group contributions.
- Overall priority is the highest category score, not the sum across categories.
  A category-filtered list orders by that category's score.
- Ties in list output are ordered by stable file ID.

`explain` includes matched signals, their weights and credited contributions,
context source paths and distances, and failed condition names for unmatched
rules. It preserves stored explanations even if the engine changes; diagnostics
are recalculated only when the saved engine version matches the current one.

The starter rules recognize configuration near deployment/release directories
or deployment sibling markers, production-named configuration, password database
extensions, credential filename tokens, and the filename fragments `cred`,
`pass`, and `ssn`. Fragment matches contribute 15 points: `cred` and `pass` to
credentials, and `ssn` to personal information. Credential token and fragment
matches share a signal group, so `credentials.txt` receives the stronger token
weight without double-counting. A broad fragment can also match ordinary words
such as `compass`; its explanation records exactly which fragment matched.
These weights are initial heuristics, not calibrated findings.
There are no automatic downloads, content classifiers, or network actions.

### Credential signals, operational scripts, and extension fallback

The default rules retain broad `cred`, `pass`, and `ssn` filename matches across
all extensions. Explicit credential names score 25; a credential-related name
with `.config`, `.ini`, `.bat`, `.ps1`, `.json`, or `.xml` gains 5 points. Name
fragments and stronger tokens share a group so they do not double-count.
Payment-card names have their own `payment-data` category (30 points); explicit
SSN or identity-document names score 25 in `personal-information`. Broad names
remain heuristic: `cred` may mean credit and `pass` may occur in ordinary words.

Operational `.ps1` and `.bat` names such as `AD Join`, `DomainJoin`, `Install`,
`Deploy`, `Provision`, `MapDrive`, `Backup`, and `ScheduledTask` score 10. Scripts
inside automation, scripts, or deployment directories score 20, including
arbitrarily named scripts. That context replaces the weaker purpose-name signal
rather than adding it again, and applies at most one directory level below the
matched directory. Configuration context rules also recognize `.xml` and the
singular `Deployment` directory.

Extension alone contributes **zero priority**. The `extension-fallback` category
shows unreviewed, zero-priority files with your six extensions, such as
`123.ps1` or `package.json`. Files with positive name, context, rarity, or other
signals appear in the ranked shortlist instead. Files with recorded analyst
decisions are omitted from fallback review. To review and queue a bounded slice:

```bash
# Create a new ranking to pick up the updated defaults.
shrawler triage run results/shrawler.db
shrawler triage list results/shrawler.db --min-score 1 --limit 100
shrawler triage list results/shrawler.db --category extension-fallback --limit 100
shrawler collect create results/shrawler.db --category extension-fallback --limit 25
```

In the WebUI, save a new ranking and select `extension-fallback` in the category
selector with minimum score **0**. Review candidates and save selected files to
a manifest as usual. The fallback reason is shown even though it contributes no
points. Existing rankings and collection manifests keep their saved rules and
selections. These weights express review order, not confirmation of credentials.

## Rules and engagement-specific context

Rules use their own versioned TOML schema. They do not accept Snaffler TOML
syntax. Unknown fields, unsupported versions, duplicate IDs, undefined context
tags, empty conditions, and invalid values fail validation before evaluation.

Supply files or directories (directories load `*.toml` recursively). Repeat
`--rules` to combine them. Built-ins are included unless `--no-builtins` is set.
IDs must be unique across all loaded files; there is no implicit override order.
Contexts may be referenced from other files in the same combined ruleset.

```bash
shrawler triage run ./results/shrawler.db --rules ./engagement-rules
shrawler triage run ./results/shrawler.db --rules ./custom.toml --no-builtins

# Preview candidate rules using temporary local storage; no ranking is retained.
shrawler triage rules test ./results/shrawler.db ./candidate.toml --limit 20
```

Rule previews process the selected inventory and display its top candidates.
They are not a before/after comparison or an estimate of precision. Temporary
results may require substantial disk space on large inventories.

A complete custom rule file:

```toml
version = 1

[[contexts]]
id = "engagement.deployment-directories"
tag = "engagement-deployment"
directory_name_any = ["deploy", "deployments", "release"]
apply_to_descendants = 2

# Explicit analyst label for an otherwise opaque subtree.
[[contexts]]
id = "engagement.orion"
tag = "engagement-deployment"
host = "fileserver"
share = "Shared"
path = "/Orion"
apply_to_descendants = 1

[[rules]]
id = "engagement.deployment-config"
description = "Configuration in an identified deployment area"
category = "infrastructure"
signal_group = "configuration"
points = 30

[rules.when]
extension_any = [".config", ".ini", ".yaml", ".yml", ".json", ".env"]
context_any = ["engagement-deployment"]

[[rules]]
id = "engagement.production-config"
description = "Production environment configuration filename"
category = "infrastructure"
signal_group = "environment"
points = 20

[rules.when]
filename_glob_any = ["appsettings.production.json", "*.prod.config"]
max_size_bytes = 1048576
```

A context uses exactly one of `directory_name_any`,
`directory_name_contains_any`, `sibling_name_any`, or the complete
`host`/`share`/`path` triple. Explicit paths start at the share root. Context
matching is case-insensitive and segment-based: `/Orion` does not match
`/Orion2`. A share name does not act as a directory name.

`apply_to_descendants = 0` applies to files directly inside the matched
directory. A value of 2 also includes files whose parent directory is one or two
edges below it. Maximum depth is 64. Each context definition reports its nearest
matching ancestor. Multiple definitions can assign the same tag. Labels do not
propagate across hosts/shares or infer other labels.

### Sibling context

```toml
[[contexts]]
id = "engagement.application-markers"
tag = "engagement-deployment"
sibling_name_any = ["web.config", "deploy.ps1", "appsettings.*.json"]
minimum_distinct_patterns = 2
apply_to_descendants = 1
```

Sibling patterns are case-insensitive filename globs evaluated within each
observed directory. The threshold requires distinct patterns matched by distinct
filenames. One file matching two patterns does not satisfy a threshold of two;
case aliases of the same filename also count once. A context can contain up to
64 distinct patterns, with a threshold from one to the pattern count.

An initial metadata pass builds a temporary disk-backed marker index from the
same scan snapshot used for scoring. It retains at most the threshold number of
witnesses per pattern and directory. This bounds evidence storage per directory
even for broad globs. Scoring then attaches the marker names, patterns, source
directory, and inheritance distance to its explanations.

Only positive observations are used. Missing markers in an incomplete inventory
do not establish their absence on the share. Names from other directories,
hosts, shares, or later scans cannot provide sibling evidence for this snapshot.

Supported file conditions:

| Condition | Meaning |
| :--- | :--- |
| `extension_any` | Exact extensions including the dot; `.env` itself also matches `.env` |
| `filename_any` | Exact filename |
| `filename_glob_any` | Filename shell-style glob (`*`, `?`, character classes); no regex |
| `filename_token_any` | Exact filename tokens split at punctuation, underscores, and lower-to-upper camelCase boundaries |
| `filename_contains_any` | Literal substring anywhere in the filename; e.g. `cred`, `pass`, `ssn` |
| `parent_name_any` | Exact immediate parent directory name |
| `parent_name_contains_any` | Literal substring in the immediate parent directory name |
| `context_any` | Any applicable context tag (tag identifiers are case-sensitive) |
| `host_any` | Exact recorded host name; no hostname resolution or alias inference |
| `share_any` | Exact share name |
| `min_size_bytes` | Inclusive minimum observed size |
| `max_size_bytes` | Inclusive maximum observed size |

All string matching except context-tag identifiers is case-insensitive. Literal
conditions do not interpret regex or glob metacharacters. Only
`filename_glob_any` interprets file-condition globs; `sibling_name_any` interprets
context-marker globs. The original metadata remains intact.
Rule points are nonnegative integers up to 1000000. Negative weights and discard
actions are deliberately unsupported in this version.

## Reproducibility, interruption, and scale

Each ranking run saves the selected scan's metadata, ruleset document and SHA-256,
engine version, timestamps, and a SHA-256 of the ordered observations used.
Every file's observed metadata and computed evidence are preserved with that
run. Changing rules creates a new run; earlier rankings remain reviewable.

The default scan selection requires a completed inventory scan. An explicit
`--scan` can select an interrupted or active scan; Shrawler scores only the
committed observations visible in a single SQLite read snapshot. The run output
reports the source scan status. This does not make an incomplete inventory
complete.

Evaluation streams files and commits result batches of 1000. Sibling rules add
an initial metadata pass before scoring. Directory context
uses a bounded 4096-entry cache. Ranked retrieval uses score indexes and a
bounded result limit. Evaluation cost grows with the number of observations and
rules; this version does not provide an incremental rule evaluator or full-text
search index. A long read snapshot during an active scan may retain its SQLite
WAL until evaluation finishes; completed scans are the preferred input.

Ctrl+C returns exit code 130 and marks the ranking interrupted. Ordinary failures
return 1. Partial ranking runs are excluded from review commands. A process killed
without cleanup may leave a run marked `running`; it is also excluded. Rerun the
command to create a fresh ranking; ranking resume is not implemented.

Preserved observations and explanations consume disk space for each run. No
ranking retention or automatic pruning is performed. Inventory association uses
the resolved database path; keep the inventory at that path when reviewing its
saved ranking runs.

## Historical initial scale check

A local synthetic benchmark evaluated 2,000,000 observations with the six starter
rules, sibling context enabled, and 100 files per directory:

| Measurement | Result |
| :--- | :--- |
| Sibling indexing, ranking, and persistence | 56.5 seconds |
| Top 100 retrieval | 1.2 ms |
| Infrastructure top 100 retrieval | 1.5 ms |
| Peak process RSS (including fixture generation) | 106.9 MiB |
| Ranking database size | 2093.6 MiB |

The fixture mixed ordinary text files, production configuration, and password
database filenames, plus `web.config`/`deploy.ps1` sibling markers, across
deployment and document directories. Expected top
scores, result counts, and explanations were checked. Storage was memory-backed
`/tmp`, and queries ran immediately after ranking with warm caches. These results
demonstrate bounded process memory for that fixture, not guaranteed disk-backed
performance or ranking quality. Larger rulesets and denser match evidence require
their own measurements.

## Rarity and review feedback

Ranking engine version 3 adds financial-data and customer-information starter
categories based on filename tokens. It also compares extensions within each
observed directory: with at least 20 files, an extension occurring in at most 5%
of files receives an unusual-files score of 10 when a dominant extension accounts
for at least 80%. Explanations preserve those counts. This detects an unusual
extension, not sensitive content or absence from an unlisted area. Rarity is
active when built-in rules are included; custom-only rules do not add it.

[Analyst decisions](families.md) are snapshotted when ranking starts. Relevant
files receive an analyst-review score of 100; reviewed, deferred, and excluded
files move to score 0 while retaining original scores in explanations. These
explicit decisions apply even with custom-only rules. Existing ranking runs
remain unchanged. The historical benchmark above predates rarity indexing and
review feedback and does not measure their additional cost.

## Engine 3 scale check

The reproducible [benchmark script](../scripts/benchmark_triage.py) generated
2,000,000 observations in 20,000 directories, each with 99 numbered CSV reports
and one configuration file. Ranking included the eight starter rules, sibling
indexing, rarity indexing, and review lookup. Family normalization collapsed
this deliberately repetitive fixture into two large families.

| Measurement | Result |
| --- | --- |
| Ranking and persistence | 76.9 seconds |
| Ranked top 100 | 2.1 ms |
| Family build | 20.5 seconds |
| Family summary page | 2.07 seconds |
| Ranking/family process peak RSS, including fixture generation | 72.9 MiB |
| Inventory / ranking / review database sizes | 1802.9 / 1361.8 / 1125.0 MiB |
| Inventory first page, including count | 0.31 seconds |
| Inventory substring search, including count | 0.52 seconds |
| Inventory page 19999 at 100 rows/page | 3.44 seconds |

Measurements used memory-backed `/tmp` and warm caches. Inventory WebUI queries
were measured in a separate process against the same fixture while the
ranking/family benchmark was running; its RSS is not included above. The current
script runs those queries sequentially in the benchmark process. Scores, rarity
evidence, file counts, and nonempty result pages were checked. These measurements
are not predictions for physical disks, diverse family keys, large review
histories, or live SMB latency. Deep inventory offset pagination and on-demand
family aggregates remain measurable costs.
