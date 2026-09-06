# Large-share triage and collection proposal

Status: The agreed #4 → #3 → finish #1 implementation is complete, alongside the existing collection queue. Section numbers are retained for continuity; documented scope and limits are linked below.

## Problem and intended workflow

File shares containing millions of files make sensitive-file discovery difficult during penetration tests and red-team engagements. Filename and extension filters can produce excessive downloads, while content inspection may exceed the engagement's operational constraints. Analysts also need a reliable record of which hosts, shares, and directories have been covered.

The biggest improvement would be making Shrawler an **inventory → triage → selective collection** workflow. The useful output is a defensible shortlist, a record of coverage, and a way to collect the shortlist without traversing everything again.

Shrawler's SQLite storage, budgets, resume support, offline ranking, and collection queue provide a foundation for these changes.

## 1. Rank the saved inventory without touching SMB

Implemented: offline CLI/WebUI ranking, custom rules, directory and sibling context, unusual-extension signals, analyst review feedback, financial/customer categories, and saved explanations. See [Offline metadata triage](triage.md). Snaffler metadata-rule reuse remains an optional extension.

Add an offline classification command that uses already collected filenames, paths, sizes, and timestamps. Changing rules or searching for a new assessment objective should require no additional remote access.

Go beyond extension matching by combining signals:

- Filename and parent-directory context.
- Assessment-specific categories: credentials, infrastructure configuration, financial data, and customer information.
- Unusual files within otherwise repetitive directories.
- Previously reviewed files and analyst feedback.

Show an explanation for every recommendation, such as “configuration file inside an application deployment directory.” Keep **priority separate from confidence**: metadata suggests relevance; it cannot establish what the file contains.

Existing Snaffler metadata rules could supply some signals, provided this offline mode cannot invoke content reads or automatic downloads.

## 2. Build a collection queue independent of scanning

Implemented: see [Collection queue](collection.md) for CLI and WebUI usage, persistence, and budget semantics.

Discovery and download decisions are currently closely coupled in `shrawler/core.py`, particularly `_process_and_display_file`. That lets traversal order determine which files consume the download budget.

Let an analyst save a query, review its candidates, and generate a collection manifest containing:

- Exact source paths and reasons for selection.
- Expected file count and bytes.
- Previously collected status.
- Per-file and total limits.

Collection should retrieve those paths directly, persist individual outcomes, and resume failed items without a new recursive scan. CLI and WebUI should share the same queue.

This would make “collect the most promising 100 files from this inventory” practical.

## 3. Group repetitive files so analysts review families

Implemented: see [File-family review](families.md) for provisional numeric-version grouping, scoped decisions, undo, and local hash confirmation.

A million rows remain overwhelming even with pagination. Group likely versions, repeated directory structures, and similarly named files; show representative candidates and let analysts expand the group.

For example, present a recurring report as one family with its date range and version count. Support decisions such as “reviewed,” “relevant,” “defer,” and “exclude this family,” with scope and undo.

Metadata grouping must remain provisional. Identical names, sizes, or timestamps do **not** prove identical contents. Use content hashes for confirmed deduplication after collection; remote hashing itself would require reads.

## 4. Track directory-level coverage from the terminal

Implemented: see [Directory coverage](coverage.md) for saved listings, pending work, identity-aware resume, terminal views, and staged expansion.

“Host scanned” is too coarse. Record:

- Identity used and scan scope.
- Shares discovered and directories successfully listed.
- Pending directories, access failures, exclusions, and depth limits.
- Enumeration, collection, and analyst review as separate states.

Add terminal views for “what remains,” “what failed,” and “what was covered under this identity.”

There is a concrete resume opportunity: the current traversal in `build_tree_structure` lists directories before `_process_and_display_file` checks whether individual files were previously recorded. Persisting pending directory work and completed listings could avoid repeating completed traversal within an interrupted scan.

A later freshness scan is a separate operation. Cached completion does not prove the share is unchanged.

## Shares too large to enumerate fully

Add staged traversal: a bounded initial pass, directory summaries, then operator-selected expansion. Process each directory's immediate files before descending deeply, and persist the remaining work.

Explicitly show unexplored areas. Prioritization trades coverage for earlier useful results.

## Agreed implementation order (completed)

1. **#4 — Directory-level coverage:** persist pending directory work and listing outcomes, resume without repeating completed listings, and expose terminal coverage views. Include staged traversal and explicit unexplored scope.
2. **#3 — File-family review:** group repetitive files, support scoped review decisions and undo, and confirm duplicate content using hashes of collected evidence.
3. **Finish #1 — Offline ranking:** use unusual-file signals and saved analyst feedback, and expand assessment-specific category coverage.

**#2 — Collection queue is implemented.** Shared remote-activity accounting/local-first previews (former #5) and Nemesis feedback integration (former #6) are removed from this roadmap.

A two-million-record synthetic benchmark now covers ranking, family grouping, inventory counts, substring search, and deep offset pagination. See [Engine 3 scale check](triage.md#engine-3-scale-check) for results and fixture limitations.

## Success measures

- Useful findings per file collected.
- Analyst time to a useful shortlist.
- Repeated remote reads avoided.
- Clearly documented coverage and unexplored scope.

## Open questions

- When Snaffler is off limits, is the main concern running its executable, remote file reads and authentication volume, content inspection, or something else?
- What most often limits the engagement: enumeration time, download/storage limits, analyst review time, or confidence that important files were found?

These answers can refine the implementation details within the agreed order: #4, #3, then finish #1.
