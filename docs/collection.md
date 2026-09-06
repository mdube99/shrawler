# Collection queue

Collection manifests separate saved-inventory review from SMB retrieval. Rank an inventory first, review candidates, then save a bounded query as a manifest:

```bash
shrawler triage run shrawler.db
shrawler triage list shrawler.db --limit 100 --min-score 1
shrawler collect create shrawler.db --name 'Top 100' --limit 100 --min-score 1 \
  --max-file-size 20MB --max-total-bytes 500MB
shrawler collect list shrawler.db
shrawler collect show shrawler.db MANIFEST_ID > manifest.json
shrawler collect run shrawler.db MANIFEST_ID 'DOMAIN/user@server'
```

`create`, `list`, and `show` are offline and emit JSON. `create` accepts `--run`, `--category`, `--min-score`, and `--limit` (1–10000). Repeat `--file-id` to select a subset of the query's candidates. The saved query pins the ranking run, scan, filters, and selected IDs. The manifest freezes exact paths, reasons, expected sizes, prior collection status, and byte limits; it never reevaluates rules during retrieval. Files outside the limits remain visible as `excluded_limit`. Expected counts and bytes describe the initially eligible retrievals, not the remaining work.

On the WebUI's **Ranked review** page, select candidates, set byte limits, and choose **Save selected candidates**. Review the saved manifest's table, export it if needed, then choose **Collect / retry failed files**. Offline WebUI sessions can create and review manifests, but cannot retrieve files. Selection is limited to the first 10000 matching candidates. CLI and WebUI share `shrawler.collection.db` beside `shrawler.db` and store evidence under `shrawler.collection/MANIFEST_ID/`. Exported JSON is a review artifact, not an executable/importable queue.

`run` calls SMB `getFile` for each exact host/share/path without enumerating hosts, shares, or directories. Each pending or failed item gets one attempt per invocation. Run the same command again to retry failures or resume an interrupted run; successful items are skipped. Attempts, outcomes, received bytes, errors, and local evidence paths are persisted. Retrieved files have generated names and mode 0600 inside private directories. One collection runs at a time per inventory, including across CLI and WebUI processes.

Historical scan downloads and successful queue items are marked previously collected when a manifest is created and excluded from retrieval. This does not prove the remote file is unchanged or that old local evidence still exists. A manifest is a snapshot: other manifests created before a collection finishes can still include the same paths.

Byte limits apply to actual content as well as saved estimates. Failed attempts consume the persistent total budget, and retries cannot reset it. A callback chunk that crosses a limit has already arrived from SMB: its bytes are counted, the transfer stops, and the partial local file is deleted. These limits are therefore content/storage controls, not strict SMB wire-byte ceilings. A hard process kill can leave an unreferenced partial evidence file; interrupted items are retried in full, never appended. Budget-exhausted manifests require a new, reviewed manifest for additional retrieval. No Nemesis upload is triggered by queue collection.
