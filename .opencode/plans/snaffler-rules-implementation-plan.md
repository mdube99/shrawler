# Snaffler Rules Integration Plan for Shrawler

## Objectives

- Add first-class support for Snaffler TOML rules in Shrawler.
- Preserve existing Shrawler behavior when Snaffler mode is not enabled.
- Implement core Snaffler rule semantics: scope, action, list type, relay chaining, and post-match filtering.
- Provide clear output in console, CSV, and JSON for Snaffler-driven matches.

## Scope for v1

### Supported Enumerations

- `EnumerationScope`: `ShareEnumeration`, `DirectoryEnumeration`, `FileEnumeration`, `ContentsEnumeration`, `PostMatch`
- `MatchAction`: `Discard`, `Snaffle`, `Relay`
- `WordListType`: `Exact`, `Contains`, `Regex`, `EndsWith`, `StartsWith`
- `MatchLocation`: `ShareName`, `FilePath`, `FileName`, `FileExtension`, `FileContentAsString`, `FileLength`

### Deferred/Unsupported in v1 (warn and skip, or fail in strict mode)

- `CheckForKeys`
- `EnterArchive`
- `SendToNextScope`
- `FileContentAsBytes`
- `FileMD5`

## CLI Additions

- `--snaffler-rules-dir <path>`
  - Recursively load all `.toml` files from the provided directory.
- `--snaffler-interest-level <0-3>`
  - Filter rules similarly to Snaffler interest-level behavior.
- `--snaffler-max-size-to-grep <bytes>`
  - Maximum file size for content matching in Snaffler mode.
- `--snaffler-strict`
  - Fail fast on unsupported/malformed rules instead of warning and skipping.
- Optional follow-up: `--snaffler-no-auto-download`
  - Keep report-only behavior for Snaffler matches.

## Internal Architecture

### Rule Model

Create normalized Python rule objects containing:

- Rule identity: `rule_name`, `description`
- Behavior: `scope`, `action`, `triage`
- Matching: `match_location`, `word_list_type`, `word_list`, `compiled_patterns`
- Chaining: `relay_targets`
- Optional fields: `match_length`, `match_md5`

### Rule Loading and Compilation

1. Read all TOML files under `--snaffler-rules-dir` recursively.
2. Parse all `[[ClassifierRules]]` entries.
3. Validate required fields and enum values.
4. Compile matchers using Snaffler-like semantics:
   - `Regex`: compile as-is
   - `Contains`: compile pattern as regex (case-insensitive)
   - `Exact`: wrap with `^...$`
   - `StartsWith`: wrap with `^...`
   - `EndsWith`: wrap with `...$`
5. Build indexes:
   - Rules by scope
   - Rule lookup by name
   - Relay graph

### Runtime State

Add Snaffler-related runtime containers:

- `self.snaffler_enabled`
- `self.snaffler_rules`
- `self.snaffler_rules_by_scope`
- `self.snaffler_rule_lookup`
- `self.snaffler_matches`

## Execution Flow Integration

### Share Scope

Integrate in `get_shares()`:

- Build `share_name` and UNC path context.
- Evaluate `ShareEnumeration` rules.
- If discard rule matches, skip share.
- If snaffle matches, annotate/share-result metadata and continue scan based on current behavior.

### Directory Scope

Integrate in `build_tree_structure()`:

- Evaluate `DirectoryEnumeration` rules against full path.
- If discard matches, do not recurse into directory.
- Optionally log/track matched rule for visibility.

### File Scope

Integrate in `_process_and_display_file()` and `_process_and_display_file_root()`:

- Construct file context once (name, extension, path, UNC, size).
- Evaluate `FileEnumeration` rules in precedence order.
- Handle actions:
  - `Discard`: stop processing this file.
  - `Snaffle`: mark candidate match.
  - `Relay`: enqueue relay targets for downstream evaluation.

### Relay Processing

- Resolve relay targets using rule lookup.
- Support multi-hop relays.
- Maintain `visited` set to prevent cycles.
- Route relay targets by scope:
  - `FileEnumeration`: evaluate immediately on file metadata.
  - `ContentsEnumeration`: queue for content evaluation.

### Content Scope

- Evaluate content rules only when needed:
  - Direct content rule entrypoints
  - Relay from file rules
- Apply max-size gate using `--snaffler-max-size-to-grep`.
- Read and decode file once per file in Snaffler path.
- Evaluate all queued content rules against decoded text.

### Post-Match Scope

- If a file is matched as candidate, run `PostMatch` rules.
- If post-match discard fires, suppress the candidate.
- Otherwise keep match and continue output/download logic.

## Output and Reporting

### Console

- Add inline marker for Snaffler matches in tree rows, example:
  - `[SNAFFLER: KeepPassOrKeyInCode/Red]`

### CSV

Add `shrawler_snaffler_matches.csv` with fields such as:

- `host`
- `share_name`
- `remote_path`
- `unc_path`
- `rule_name`
- `triage`
- `scope`
- `match_location`
- `matched_string`
- `timestamp_utc`

### JSON

Add per-share and/or top-level Snaffler match structures with:

- Rule metadata
- File path metadata
- Match details

### Summary

Print end-of-run Snaffler summary:

- total Snaffler matches
- unique matched files
- top matched rules

## Behavior with Existing Features

- `--content-search` remains functional and unchanged.
- If both engines run:
  - run both matchers
  - deduplicate downloads by UNC/path key
  - keep both match records
- Existing non-Snaffler scans should behave exactly as before.

## Testing Strategy

### Unit Tests

- TOML parser and loader:
  - valid/invalid files
  - missing fields
  - unknown enum values
  - multi-file merge behavior
- Matcher behavior:
  - `Exact`, `Contains`, `Regex`, `StartsWith`, `EndsWith`
  - case-insensitive behavior
  - match locations (`FileName`, `FilePath`, etc.)
- Relay behavior:
  - single-hop and multi-hop relays
  - cycle protection
- Post-match behavior:
  - candidate accepted vs discarded
- Interest-level filtering behavior

### Integration Tests

- Simulated scan contexts to validate end-to-end rule application order.
- Ensure Snaffler mode does not alter results when disabled.
- Verify output artifacts (console markers, CSV rows, JSON blocks).

## Implementation Phases

### Phase 1: Foundation

- Add CLI args.
- Add rule data structures and loader.
- Add rule compilation and validation.

### Phase 2: Rule Engine

- Implement scope evaluators (share, dir, file).
- Implement action handling and rule ordering.

### Phase 3: Relay + Content + Post-Match

- Implement relay resolver with cycle protection.
- Implement content evaluation path and max-size gate.
- Implement post-match filtering.

### Phase 4: Output Integration

- Add console annotations.
- Add CSV and JSON match outputs.
- Add summary reporting.

### Phase 5: Tests and Docs

- Add unit and integration tests.
- Update README with usage examples.
- Add support matrix and known limitations.

## Risks and Mitigations

- Performance cost from regex-heavy content rules
  - Mitigation: scan on-demand only, precompile patterns, short-circuit discards.
- Relay loops in custom rule sets
  - Mitigation: visited-rule tracking.
- Incomplete action parity with Snaffler
  - Mitigation: explicit support matrix, `--snaffler-strict` option.
- Python TOML compatibility on older versions
  - Mitigation: `tomllib` with `tomli` fallback when needed.

## Acceptance Criteria

- Rules load from Snaffler TOML directory and are applied during spidering.
- Relay to content rules works with on-demand content reads.
- Post-match discard suppresses matched candidates correctly.
- Snaffler matches appear in console, CSV, and JSON outputs.
- No behavior change for existing workflows when Snaffler mode is off.

## Recommended Defaults

- Treat Snaffler `Snaffle` as auto-download by default.
- Use warn-and-skip for unsupported actions by default.
- Allow concurrent operation with existing `--content-search` and dedupe downloads.
