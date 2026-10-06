// Score vocabulary.
//
// Combined, Rule, and AI each render the same way on every screen, so the
// bands and hues are defined once here. The rule the whole app follows:
// rail colour = severity (Combined only), hue = which engine spoke.
//
// Colouring all three columns with the same four-band traffic light produces a
// rainbow table and destroys the "Combined is primary" hierarchy, so Rule and AI
// get a single hue each and vary only in intensity.

import { el, severity } from './core.js';

// The coverage marker says which engines contributed to Combined, so one number
// can always be traced back to its sources. The words name the engines the way
// the column sub-labels do (see components.css .sort-sub).
export const COVERAGE = { both: 'static rules + AI', rules: 'static rules', jev: 'AI model' };
export const COVERAGE_MARK = { both: '●', rules: '◐', jev: '○' };

export const ruleScore = (item) => (item.ranking_run_id ? (item.ranking_score ?? item.ranking_priority ?? 0) : null);

export const aiScore = (item) =>
  item.jev_run_id && item.jev_score !== null && item.jev_score !== undefined ? item.jev_score : null;

export const combinedScore = (item) =>
  item.combined_coverage && item.combined_coverage !== 'none' && item.combined_score !== null && item.combined_score !== undefined
    ? item.combined_score
    : null;

/** Combined owns the severity ramp; the row shows the number alone. */
export function combinedChip(item) {
  const score = combinedScore(item);
  const band = severity(score);
  const chip = el('span', score === null ? 'score score--combined score--empty' : 'score score--combined');
  chip.dataset.severity = band.band;
  chip.textContent = score === null ? '—' : String(score);
  chip.title =
    score === null
      ? 'No rating — select a ranking or AI run above'
      : `Overall priority ${score}/100 · ${band.label} · rated by ${COVERAGE[item.combined_coverage] || item.combined_coverage}`;
  return chip;
}

/**
 * Rule and AI chips. `strong` bumps the weight so a high single-engine score is
 * noticeable without borrowing the severity ramp. A missing value renders as the
 * same-size dashed pill so the column never jumps, with a tooltip that says why.
 */
export function engineChip(kind, score, label) {
  const chip = el('span', score === null ? `score score--${kind} score--empty` : `score score--${kind}`);
  chip.dataset.strong = String((score ?? 0) >= 76);
  chip.textContent = score === null ? '-' : String(score);
  chip.title =
    score === null
      ? kind === 'rule'
        ? 'Not rated · run a ranking on the Score screen'
        : 'Not assessed'
      : kind === 'rule'
        ? `${label} ${score} · matched static filename, path, and metadata rules · 80+ fully alarmed`
        : `${label} ${score}/4 · Jev-style decision model`;
  return chip;
}

/** Long-form values for the row detail panel, so a number always has a source. */
export const describe = {
  combined: (item) => {
    const score = combinedScore(item);
    return score === null
      ? 'No rating — select a ranking or AI run'
      : `${score}/100 · ${severity(score).label} · ${COVERAGE[item.combined_coverage] || item.combined_coverage}`;
  },
  rule: (item) => (item.ranking_run_id ? String(ruleScore(item)) : 'No ranking selected'),
  ai: (item) =>
    aiScore(item) === null
      ? 'Not assessed by AI'
      : `${aiScore(item)} of 4${item.jev_priority_name ? ` · ${item.jev_priority_name}` : ''}`,
};