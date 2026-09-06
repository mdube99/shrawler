# Directory coverage and staged traversal

SQLite-backed `spider` and `snaffle` scans save each successful directory listing and its discovered child directories before processing files. They process a directory's immediate files before advancing breadth-first through its children. A listing includes saved names, sizes, and file timestamps so interrupted work can be replayed locally.

```bash
# Bounded first pass, counting additional listing calls across hosts/shares.
shrawler spider 'DOMAIN/user@server' --output results --directory-budget 25

# Offline views; JSON output includes scan identity, original scope, and share records.
shrawler coverage results/shrawler.db --view remaining
shrawler coverage results/shrawler.db --view failed --host server --share DATA
shrawler coverage results/shrawler.db --view covered --scan SCAN_ID

# Resume the same scan, expanding only the selected subtree and its ancestors.
shrawler spider 'DOMAIN/user@server' --output results --resume SCAN_ID \
  --share DATA --expand-directory /Projects --directory-budget 100 --max-depth 8
```

Repeat `--expand-directory` for more subtrees. Selection is case-insensitive; `/` selects the whole share. Paths are share-relative, so combine selection with `--share` when needed. The root is depth 0. `--max-depth 0` lists root files and records its child directories as depth-limited. A directory budget must be positive; omitting it permits all remaining work within the depth limit. Cached listings do not consume the additional-listing budget. This budget covers inventory directory listings, not every SMB operation or Snaffler content read.

The directory states are:

| State | Meaning |
| --- | --- |
| `pending` | Discovered but not listed, or held by budget/expansion selection |
| `listed` | Listing saved; local file processing may still be incomplete |
| `complete` | Listing and immediate file processing finished; children have their own states |
| `failed` | Listing or local processing failed; the error is recorded |
| `depth_limit` | Observed directory beyond the selected depth |
| `excluded` | Directory rejected by a Snaffler discard rule |

Scans with outstanding directory work finish as `partial` and remain resumable. Completed hosts/shares with pending child work are revisited; successfully saved listings are reused and failed listings retried. Scan resume requires the original domain and username. A new scan under another identity or for freshness starts independent coverage. Existing inventories cannot reconstruct historical directory coverage from file rows alone.

`coverage` defaults to the latest scan. `--scan` accepts its full or short ID; `--limit` (1–10000) and `--offset` bound output. `covered` means a saved listing exists, even if later processing failed. Share rows include exclusions and permission information; their pagination is separate from directory rows. Coverage describes enumeration. Collection manifests and analyst review decisions maintain their own states.

Listings do not prove that remote contents are unchanged. Unlisted descendants remain unknown. Resume reuses historical root listings for read-access evidence; it does not repeat that permission probe. Original scan scope is preserved, while each pending directory records its current stop reason. A single very wide directory still needs to be listed and serialized in full; the directory budget cannot split one SMB listing.

Legacy non-SQLite scanning retains its existing traversal behavior.
