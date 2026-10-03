"""Model-assisted full-coverage file assessment over a pinned inventory scan.

The deterministic rule engine ranks metadata; this package adds a separate,
resumable enrichment pass that asks a decision model about every observed file
using directory context shared across bounded batches. It never replaces rule
results and never samples the inventory.
"""
