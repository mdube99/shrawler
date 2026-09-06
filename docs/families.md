# File-family review and ranking feedback

Group saved observations and review families without SMB access:

```bash
shrawler review build results/shrawler.db --scan SCAN_ID
shrawler review list results/shrawler.db --scan FULL_SCAN_ID
shrawler review list results/shrawler.db --scan FULL_SCAN_ID --family FAMILY_ID
shrawler review decide results/shrawler.db family FAMILY_ID exclude --note 'Reviewed report series'
shrawler review decide results/shrawler.db file FILE_ID relevant --note 'Assessment objective'
shrawler review undo results/shrawler.db EVENT_ID
shrawler triage run results/shrawler.db --scan SCAN_ID
```

`build` defaults to the latest completed inventory scan; explicit selection also permits incomplete scans. Its output includes the full scan ID needed by `list`. Family pages contain representative paths, member counts, total observed bytes, and the range of observed modification timestamps. Expand a family with `--family`; use `--limit` (1–1000) and `--offset` to page families or members.

The WebUI's **Ranked review → File families** section exposes the same grouping, member expansion, family/file decisions, and undo. Choose a source scan before building. Decisions return event IDs, and the undo field is filled with the most recently saved ID.

Grouping is provisional: numeric runs in paths are replaced with placeholders, while host, share, and all other path text remain part of the key. For example, `/Reports/report-2025-01.csv` and `/Reports/report-2026-02.csv` form a family; numbered directory versions can also group. This can merge unrelated numbered names. Non-numeric naming variants are not automatically merged. Modification-date ranges are observed timestamps, not inferred report periods. Nothing in this grouping establishes identical content.

Decisions are `reviewed`, `relevant`, `defer`, or `exclude`. They apply either to one stable file ID or one family key across subsequent scans. An explicit file decision takes precedence over a family decision. The latest active decision within that scope wins. Undo marks an event inactive and exposes the preceding active decision, retaining history. Notes and review events live in `<inventory-stem>.review.db`, separate from the inventory.

Run a new ranking to incorporate decisions:

- `relevant` supplies an analyst-review priority of 100; larger existing scores remain larger.
- `reviewed`, `defer`, and `exclude` move candidates to priority 0, including category-filtered review. Original scores remain in saved explanations.
- `exclude` also prevents selection into new collection manifests created from that ranking.

Scores express review order, not content confidence. Saved rankings freeze the applied review event and scores; undo does not rewrite them. Existing collection manifests also keep their saved selection. Re-rank and create a new manifest when a review decision should change collection.

To confirm identical bytes after collection:

```bash
shrawler review hashes results/shrawler.db
```

This streams SHA-256 over existing successful collection-queue evidence and reports duplicate hash/size groups with local paths. It performs no SMB reads and deletes no evidence. The WebUI's **Find duplicates in local collection** action runs the same operation. Missing local evidence is skipped, and the hash index is rebuilt each time so old missing-file records do not remain. Hashes describe the local bytes at the time of this operation.
