# Local test workspace

Generate a synthetic workspace for exercising the ranking, coverage, family-review, and collection features without an SMB server:

```bash
.venv/bin/python scripts/create_test_workspace.py
cd test-workspace
```

The generator refuses to overwrite an existing directory. Use `--output PATH` to create it elsewhere. It creates a completed `shrawler.db` inventory for ranking, a partial scan with saved directory coverage, a triage run, provisional family groups, one deferred family decision, a collection manifest, and local collection evidence with both successful and failed outcomes. No network connection or credentials are used. The generated directory is mode 0700 and its SQLite files are mode 0600.

The generated `FIXTURE.json` contains the IDs needed by the commands below. The completed scan is the ranking source; the partial scan is useful for coverage views.

```bash
shrawler triage list shrawler.db --run RANKING_RUN --limit 20
shrawler web --offline shrawler.db

shrawler coverage shrawler.db --scan PARTIAL_SCAN --view all
shrawler coverage shrawler.db --scan PARTIAL_SCAN --view failed
shrawler coverage shrawler.db --scan PARTIAL_SCAN --view covered

shrawler review list shrawler.db --scan COMPLETED_SCAN
shrawler review list shrawler.db --scan COMPLETED_SCAN --family FAMILY_ID
shrawler review hashes shrawler.db

shrawler collect list shrawler.db
shrawler collect show shrawler.db COLLECTION_MANIFEST
```

Replace the uppercase placeholders with values from `FIXTURE.json`. To test retry behavior, run `shrawler collect run` only with real SMB credentials and a real matching source; the fixture’s failed item is intentionally synthetic and its saved outcome can be inspected without retrieval.
