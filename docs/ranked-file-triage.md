I’d build one offline ranking engine, expose it fully through the CLI, and
  use the WebUI for interactive tuning and review. Both interfaces would
  operate on the same saved results and rule definitions.

  Your concern about context is right: a rule like “anything inside a
  directory named IT is sensitive” would produce terrible results. The way
  to make this useful is to define context narrowly, combine independent
  signals, and make every decision explainable.

  1. Start with information Shrawler already has

  The database already stores file_name, parent_path, remote_path,
  extension, size, and modification time in shrawler/store.py:321. Basic
  parent-directory context needs no additional enumeration.

  For this example:

  \\fileserver\Departments\IT\Deployments\PayrollApp\production.config

  We can derive:

   Feature                     Value
  ━━━━━━━━━━━━━━━━━━━━━━━━━━  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Filename                    production.config
  ──────────────────────────  ─────────────────────────────
   Filename tokens             production, config
  ──────────────────────────  ─────────────────────────────
   Immediate parent            PayrollApp
  ──────────────────────────  ─────────────────────────────
   Ancestors, nearest first    PayrollApp, Deployments, IT
  ──────────────────────────  ─────────────────────────────
   Extension                   .config
  ──────────────────────────  ─────────────────────────────
   Share                       Departments

  Retain the original path for evidence. Build separate normalized fields
  for matching, with explicit rules for case, separators, and token
  boundaries.

  That lets rules distinguish:

  - The immediate parent is named Deployments.
  - A directory within three levels is named Deployments.
  - The full path contains a particular expression.

  Those are different conditions. Making the distinction explicit prevents
  accidental matches from a vague substring search across the entire UNC
  path.

  2. Separate context labels from file-ranking rules

  I’d use two stages:

  Directory metadata → context labels
  File metadata + applicable context labels → ranking signals

  A context rule might label a directory as deployment-area. A file rule can
  then ask whether a configuration file sits inside that context.

  Illustrative TOML—not existing syntax:

  [[contexts]]
  id = "deployment-area"
  directory_name_any = ["deploy", "deployments", "release"]
  tag = "deployment-area"
  apply_to_descendants = 2

  [[rules]]
  id = "config-in-deployment-area"
  description = "Configuration file near a deployment directory"
  category = "infrastructure"
  signal_group = "deployment-config"
  points = 30

  [rules.when]
  extension_any = [".config", ".ini", ".yaml", ".yml"]
  context_any = ["deployment-area"]

  The conditions in when are ANDed; values within an *_any list are ORed.

  apply_to_descendants = 2 would have a precise definition: the tagged
  directory’s immediate files and files in directories up to two edges below
  it.

  This creates reusable context without writing one enormous regex for every
  file rule. It also lets you change the vocabulary used to recognize
  deployment directories without editing every rule that uses that context.

  For the first version, context rules would read metadata only. They would
  not depend on other inferred context labels, avoiding circular inference
  and difficult-to-explain propagation.

  3. Add sibling context carefully

  Names alone won’t handle directories like:

  \\fileserver\Apps\Project42\
      web.config
      deploy.ps1
      appsettings.Production.json
      notes.txt

  Even though Project42 says little, the observed sibling names suggest an
  application deployment directory. An optional context rule could require
  two distinct markers:

  [[contexts]]
  id = "application-deployment-markers"
  tag = "deployment-area"
  sibling_name_any = ["web.config", "deploy.ps1", "appsettings.*.json"]
  minimum_distinct_patterns = 2
  apply_to_descendants = 1

  This uses names already present in the inventory. It does not open those
  files.

  However, I would introduce this after the basic version. It adds important
  edge cases:

  - An incomplete listing can establish that a marker exists, but not that
    another marker is absent.

  - Context must be scoped to the host, share, directory, and selected
    inventory snapshot.

  - A new sibling can change the context of existing files, so those files
    may need reevaluation.

  - Thousands of copies of one marker should not count as thousands of
    independent signals.

  The explanation would identify the actual evidence: “Directory context
  inferred from web.config and deploy.ps1.”

  4. Make scores useful without pretending they are probabilities

  For a file, the engine might report:

  Priority: 50 — infrastructure

  +30 Configuration file in deployment context
      Context source: /IT/Deployments
      Distance: 1 directory

  +20 Filename contains production-environment token
      Matched: production

  Evidence: metadata only

  Those numbers would initially be tunable weights, not a 50% probability of
  sensitivity.

  I would also:

  - Cap contributions within a signal group, so five overlapping filename
    rules don’t overwhelm one strong independent signal.

  - Keep category scores separate. Financial-data relevance and
    infrastructure relevance serve different objectives.

  - Treat age as an optional signal, not a universal penalty; older files
    may still matter.

  - Keep analyst disposition separate from the computed score.
  - Keep low-ranked files searchable.

  The difficult part is calibration. We’d need a reviewed sample of real
  inventories to learn whether the highest-ranked results are actually
  useful. Synthetic data can validate correctness and speed, but cannot
  establish ranking quality.

  5. Make “dynamic” mean easy to adjust and test

  I’d support three layers:

  1. Built-in rules: broadly useful filename and context patterns.
  2. Engagement rules: local terminology, application names, and assessment
     priorities.

  3. Explicit analyst labels: “this particular subtree contains deployment
     material.”

  Suppose an organization stores application releases under \
  \server\Shared\Orion. You could label that exact subtree as deployment-
  area, with a chosen depth. Existing file rules would immediately become
  useful there.

  That is more manageable than anticipating every organization’s naming
  conventions.

  The WebUI should offer a small rule builder:

  > Extension is one of …
  > AND nearby directory has context …
  > THEN add … priority points in category …

  Before saving, it should show:

  - Matching file count.
  - Representative matches across several hosts and directories.
  - Files newly promoted by the change.
  - Existing reviewed examples affected by the change.

  A “why didn’t this match?” view is as valuable as “why did this match?” It
  should identify failed conditions.

  The builder would export the same TOML accepted by the CLI, so interactive
  work stays reproducible.

  6. Give the CLI complete functionality

  Proposed commands could look like:

  # Evaluate a particular saved scan, entirely offline
  shrawler triage run ./results/shrawler.db \
    --scan SCAN_ID \
    --rules ./triage-rules

  # Read the ranked shortlist
  shrawler triage list ./results/shrawler.db \
    --category infrastructure \
    --limit 100

  # Explain one file's ranking
  shrawler triage explain ./results/shrawler.db FILE_ID

  # Preview a rule's effect
  shrawler triage rules test ./results/shrawler.db ./candidate.toml

  These commands would require no SMB target or credentials.

  The WebUI would start the same ranking jobs and query their stored
  results. Opening a table page would not reevaluate every rule. A separate
  offline review mode should work without configuring live retrieval.

  I’d implement the engine and CLI first because they provide a
  straightforward way to validate behavior; the WebUI would follow as the
  main interface for exploring and adjusting results.

  7. Reuse Snaffler selectively

  The current Snaffler engine (shrawler/snaffler/engine.py:46) combines rule
  handling with crawler behavior. I’d extract reusable parsing and metadata
  matching into components that have no SMB access.

  An adapter could import compatible Snaffler metadata predicates and
  translate their classifications into ranking signals. Compatibility needs
  explicit reporting:

  - A filename match can be evaluated offline.
  - A relay to a content rule means “content inspection required,” not
    “confirmed match.”

  - A discard can become a visible suppression decision without removing
    inventory records.

  - Download actions are outside the ranking engine.

  I’d preserve imported matching semantics rather than silently reinterpret
  existing rules. Shrawler’s new contextual rules would have their own
  versioned schema.

  8. Design evaluation around millions of files

  The engine would process bounded batches, compute directory context once
  per directory, and use indexed metadata conditions to narrow candidates
  before expensive matching.

  For interactive substring search, SQLite’s FTS5 trigram index is an option
  worth benchmarking; it supports indexed LIKE and GLOB searches under
  documented conditions. SQLite FTS5 documentation
  (https://www.sqlite.org/fts5.html#the_trigram_tokenizer)

  Each ranking run should record the inventory snapshot, ruleset hash,
  engine version, and evaluation time. Store scores and their evidence
  separately from original scan observations. A changed ruleset creates a
  new ranking result, preserving the ability to explain an earlier
  shortlist.

  I’d validate the first release with path-boundary cases, bounded context
  inheritance, overlapping-rule scores, partial inventories, reproducible
  results, and a check that offline evaluation cannot initiate network
  activity.

  My first implementation would include direct metadata rules, bounded
  ancestor context, explicit subtree labels, explanations, and CLI
  evaluation. Sibling inference and the WebUI rule builder would come next.
  That first slice is already substantially more expressive than extension
  filtering, while remaining small enough to understand and tune.
