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
// can always be traced back to its sources.
export const COVERAGE = { both: 'rules + AI', rules: 'rules only', jev: 'AI only' };
const COVERAGE_MARK = { both: '●', rules: '◐', jev: '○' };

export const ruleScore = (item) => (item.ranking_run_id ? (item.ranking_score ?? item.ranking_priority ?? 0) : null);

export const aiScore = (item) =>
  item.jev_run_id && item.jev_score !== null && item.jev_score !== undefined ? item.jev_score : null;

export const combinedScore = (item) =>
  item.combined_coverage && item.combined_coverage !== 'none' && item.combined_score !== null && item.combined_score !== undefined
    ? item.combined_score
    : null;

/** Combined owns the severity ramp; the coverage dot says which engines spoke. */
export function combinedChip(item) {
  const score = combinedScore(item);
  const chip = el('span', score === null ? 'score score--empty' : 'score score--combined');
  chip.dataset.severity = severity(score).band;
  chip.textContent = score === null ? '—' : String(score);
  const mark = COVERAGE_MARK[item.combined_coverage];
  if (mark) {
    const dot = el('span', 'coverage-dot', mark);
    dot.setAttribute('aria-hidden', 'true');
    chip.append(dot);
  }
  chip.title =
    score === null
      ? 'No rule rating or AI assessment for this file'
      : `Combined ${score}/100 (${COVERAGE[item.combined_coverage] || item.combined_coverage})`;
  return chip;
}

/**
 * Rule and AI chips. `strong` bumps the weight past 76 so a high single-engine
 * score is noticeable without borrowing the severity ramp.
 */
export function engineChip(kind, score, label) {
  const chip = el('span', `score score--${kind}`);
  chip.dataset.strong = String((score ?? 0) >= 76);
  chip.textContent = score === null ? '—' : String(score);
  chip.title = score === null ? `No ${label.toLowerCase()} for this file` : `${label} ${score}`;
  return chip;
}

/** Long-form values for the row detail panel, so a number always has a source. */
export const describe = {
  combined: (item) => {
    const score = combinedScore(item);
    return score === null
      ? 'Unavailable — run a ranking or AI assessment'
      : `${score}/100 · ${COVERAGE[item.combined_coverage] || item.combined_coverage}`;
  },
  rule: (item) => (item.ranking_run_id ? String(ruleScore(item)) : 'No ranking selected'),
  ai: (item) =>
    aiScore(item) === null ? 'Not assessed by AI' : `${aiScore(item)}${item.jev_priority_name ? ` ${item.jev_priority_name}` : ''}`,
};