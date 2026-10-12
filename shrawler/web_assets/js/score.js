// Score screen shell: the run console, the result tabs, the compact sticky
// bar, and the polling of both job endpoints.
//
// Each engine owns one card at the top of the page, and the card *is* the
// engine's status: what it is doing, how far it has got, how long it has been
// at it, how the last run ended, and the one button that starts it or, while
// it runs, cancels it. Run state never lives anywhere the analyst is not
// already looking. When the console scrolls away, a one-line bar takes over.

import { button, el, fill, fmt, href, icon, json, mountShell, on, post, renderShellStatus, setBusy, shellError } from './core.js';
import { toast } from './overlay.js';
import { createRuleEngine } from './score-rule.js';
import { createAiEngine } from './score-ai.js';
import { createCollection } from './collection.js';

const $ = (id) => document.getElementById(id);
const shell = mountShell('/score');

const IDLE_MS = 4000;
const BUSY_MS = 1200;
// The 202 body is painted at once, but only a GET proves the server is
// publishing that job. Poll hard until it does instead of leaving the first
// confirmation a full busy interval away, and give up after a bounded window
// so a server that never echoes the job cannot pin the loop at this rate.
const CONFIRM_MS = 250;
const CONFIRM_WINDOW_MS = 5000;
// Consecutive failed polls before an engine is reported as unreachable. One
// miss is a hiccup; two in a row is a connection the analyst should know about
// instead of a "running" display that silently froze.
const LOST_AFTER = 2;
// How long updated_at may stand still before the card says so. Quiet phases
// report only when they finish, so they get a longer leash and a neutral tone.
const STALL_MS = 60_000;
const QUIET_STALL_MS = 5 * 60_000;
// An estimate from a few seconds of samples is noise; wait for a real rate.
const ETA_MIN_MS = 5000;

// Services emit terse internal phase names. The analyst sees what the engine
// is doing; `counted` marks phases whose processed/total is a real measure.
// `meter: false` keeps a counted phase off the meter: saving really has scored
// every file, but the write itself is unmeasured, so a full bar would read as
// "done" while the slowest step is still running. `quiet` phases publish no
// intermediate progress at all.
const PHASES = {
  starting: { label: 'Starting', counted: false, quiet: true },
  'indexing sibling names': { label: 'Indexing sibling names', counted: true, verb: 'indexed' },
  scoring: { label: 'Scoring files', counted: true, verb: 'scored' },
  saving: { label: 'Saving results', counted: true, verb: 'scored', meter: false, quiet: true },
  'staging ledger': { label: 'Staging ledger', counted: false, quiet: true },
  'planning batches': { label: 'Planning batches', counted: false, quiet: true },
  dispatching: { label: 'Assessing files', counted: true, verb: 'assessed' },
};

const OUTCOMES = {
  completed: 'Completed',
  partial: 'Partially assessed',
  paused: 'Paused at time budget',
  failed: 'Failed',
  cancelled: 'Cancelled',
};

// Outcome tones. Success, warn, and danger are reserved for how a run ended;
// a running engine speaks only in its own hue.
const OUTCOME_TONES = { completed: 'success', partial: 'warn', paused: 'warn', failed: 'danger', cancelled: '' };

// `status` stays null until /api/status answers, which is what keeps the cards
// in "Checking…" instead of claiming an idle engine nobody has asked about.
const state = { status: null, tab: 'rule', consoleVisible: true, unreachable: false };

const engines = {
  rule: {
    name: 'Rule ranking',
    short: 'Rule',
    noun: 'ranking',
    startLabel: 'Run ranking',
    endpoint: '/api/triage/job',
    cancelPath: '/api/triage/cancel',
    enabled: () => Boolean(state.status?.triage_enabled),
    unavailable: 'Rule ranking is unavailable for this inventory.',
  },
  ai: {
    name: 'AI assessment',
    short: 'AI',
    noun: 'assessment',
    startLabel: 'Start assessment',
    endpoint: '/api/assessment/job',
    cancelPath: '/api/assessment/cancel',
    enabled: () => Boolean(state.status?.assessment_enabled),
    unavailable:
      'AI assessment is disabled for this server. Set enabled = true under [jev] in the Shrawler configuration, with a model endpoint, and restart the server.',
  },
};

for (const engine of Object.values(engines)) {
  Object.assign(engine, {
    job: null,
    // Job IDs whose outcome has already been acted on. Settling once per ID is
    // what lets a run that was watched while running still fire its completion
    // handler, without replaying an old outcome on every page load.
    settled: new Set(),
    awaiting: null,
    awaitingUntil: 0,
    cancelling: null,
    requesting: false,
    requested: 0,
    applied: 0,
    // Connection health, per engine: one endpoint can fail while the other
    // still answers.
    seen: false,
    failures: 0,
    lastOkAt: Date.now(),
    // When updated_at last moved, by the browser's clock, so a stalled job is
    // detected without trusting the two clocks to agree.
    stamp: null,
    changedAt: Date.now(),
    // Rate samples for the remaining-time estimate, reset on every phase.
    track: null,
    error: '',
  });
}

const sentence = (text) => (text ? text[0].toUpperCase() + text.slice(1) : '');
const ago = (ms) => fmt.duration(Math.max(0, ms) / 1000);

/* -- The job model ----------------------------------------------------------- */

/**
 * One reading of an engine, shared by its card, the sticky bar, and the
 * header pill, so no two surfaces can disagree about what it is doing.
 */
function describe(key) {
  const engine = engines[key];
  const job = engine.job;
  const base = {
    state: 'idle',
    active: false,
    jobActive: false,
    requesting: engine.requesting,
    label: 'Idle',
    detail: '',
    fraction: 0,
    meter: false,
    percent: '',
    tone: '',
    timing: '',
    warning: null,
    finished: false,
  };
  let view;
  if (!state.status) {
    view = { ...base, state: 'unknown', label: 'Checking…' };
  } else if (!engine.enabled()) {
    view = { ...base, state: 'unavailable', label: 'Unavailable', detail: engine.unavailable };
  } else if (engine.requesting && job?.status !== 'running') {
    // The click is acknowledged in the card before the server has answered.
    view = { ...base, state: 'starting', active: true, label: 'Starting', detail: 'Sending the request…', fraction: null, meter: true };
  } else if (!job) {
    const history = engine.module?.history?.();
    view = engine.seen
      ? { ...base, detail: history?.text || `No ${engine.noun} has run yet.` }
      : { ...base, state: 'unknown', label: 'Checking…' };
  } else if (job.status === 'running') {
    view = running(key, job, base);
  } else {
    view = {
      ...base,
      state: key === 'rule' && job.status === 'completed' && job.preview ? 'preview' : job.status,
      label: outcomeLabel(key, job),
      detail: outcomeDetail(key, job),
      tone: key === 'rule' && job.preview && job.status === 'completed' ? 'neutral' : OUTCOME_TONES[job.status] ?? '',
      finished: true,
    };
  }
  if (engine.failures >= LOST_AFTER && engine.enabled()) {
    // Never keep painting a frozen "running": say the reading is stale, stop
    // the spinner, and keep the last known numbers for context.
    view = {
      ...view,
      state: 'lost',
      active: false,
      label: 'Connection lost',
      tone: 'warn',
      warning: { text: `Connection lost · last update ${ago(Date.now() - engine.lastOkAt)} ago · retrying`, tone: 'warn' },
      timing: '',
    };
  }
  view.headline = view.label;
  view.summary = [view.percent, view.detail].filter(Boolean).join(' · ');
  return view;
}

function running(key, job, base) {
  const engine = engines[key];
  const processed = Number(job.processed || 0);
  const total = Number(job.total || 0);
  const phase = PHASES[job.phase] || { label: sentence(job.phase || 'running'), counted: false };
  const cancelling = engine.cancelling === job.id;
  // "Starting" is the window between the 202 and the first progress report.
  // It, the uncounted phases, and the unmeasured write all run an
  // indeterminate stripe: nothing has been measured, so nothing is guessed.
  const measured = phase.counted && phase.meter !== false && total > 0;
  const fraction = measured ? Math.min(1, processed / total) : null;
  const quiet = phase.quiet || !phase.counted;
  const silent = Date.now() - engine.changedAt;
  let warning = null;
  if (silent > (quiet ? QUIET_STALL_MS : STALL_MS)) {
    warning = quiet
      ? { text: `No update for ${ago(silent)} · this step reports only when it finishes`, tone: '' }
      : { text: `No progress for ${ago(silent)}`, tone: 'warn' };
  }
  return {
    ...base,
    state: cancelling ? 'cancelling' : job.phase === 'starting' ? 'starting' : 'running',
    active: true,
    jobActive: true,
    label: cancelling ? 'Cancelling' : key === 'rule' && job.preview ? `${phase.label} · preview` : phase.label,
    detail: job.phase === 'starting' ? 'Accepted · waiting for the first progress report' : runningDetail(key, job, phase, processed, total),
    fraction,
    meter: true,
    percent: fraction === null ? '' : `${Math.floor(fraction * 100)}%`,
    timing: timing(engine, job, phase, total, processed),
    warning,
  };
}

function runningDetail(key, job, phase, processed, total) {
  if (key === 'rule') {
    if (!total) return `${fmt.count(processed)} ${phase.verb || 'processed'}`;
    if (job.phase === 'saving') return `${fmt.count(processed)} scored · writing the ranked tables`;
    return `${fmt.count(processed)} / ${fmt.count(total)} ${phase.verb || 'processed'}`;
  }
  if (!phase.counted) return total ? `${fmt.count(total)} observed` : 'Preparing the run';
  // Every one of these numbers is already published by the service. Showing
  // them is the difference between "something is happening" and knowing how
  // much is left, what is failing, and what the cache saved.
  const batches =
    job.completed_batches === undefined
      ? null
      : `${fmt.count(job.completed_batches)} / ${fmt.count((job.completed_batches || 0) + (job.active_batches || 0) + (job.pending_batches || 0))} batches`;
  return [
    `${fmt.count(processed)} / ${fmt.count(total)} assessed`,
    batches,
    job.pending !== undefined ? `${fmt.count(job.pending)} pending` : null,
    job.failed ? `${fmt.count(job.failed)} failed` : null,
    job.in_flight ? `${fmt.count(job.in_flight)} in flight` : null,
    job.reused_requests ? `${fmt.count(job.reused_requests)} reused` : null,
    job.retried_requests ? `${fmt.count(job.retried_requests)} retried` : null,
  ]
    .filter(Boolean)
    .join(' · ');
}

function timing(engine, job, phase, total, processed) {
  const parts = [];
  const started = Date.parse(job.started_at || '');
  if (!Number.isNaN(started)) parts.push(`${fmt.duration((Date.now() - started) / 1000)} elapsed`);
  const track = engine.track;
  if (phase.counted && phase.meter !== false && total > 0 && track && track.id === job.id && track.phase === job.phase) {
    const span = track.t1 - track.t0;
    const done = track.p1 - track.p0;
    if (span >= ETA_MIN_MS && done > 0) {
      const left = ((total - processed) / done) * span - (Date.now() - track.t1);
      parts.push(`~${fmt.duration(Math.max(0, left) / 1000)} left`);
    }
  }
  return parts.join(' · ');
}

function outcomeLabel(key, job) {
  if (key === 'rule' && job.status === 'completed') return job.preview ? 'Unsaved preview' : 'Ranking saved';
  return OUTCOMES[job.status] || sentence(job.status);
}

function outcomeDetail(key, job) {
  const when = job.finished_at ? fmt.relative(job.finished_at) : null;
  if (job.status === 'failed') return [when, job.error || 'The run stopped with an error'].filter(Boolean).join(' · ');
  if (key === 'rule') {
    if (job.status === 'cancelled') return [when, 'stopped · nothing saved'].filter(Boolean).join(' · ');
    const result = job.result || {};
    const positive = result.summary?.positive_files ?? job.candidates?.summary?.positive_files;
    return [
      when,
      `${fmt.count(result.files_scored ?? job.processed)} scored`,
      positive === undefined ? null : `${fmt.count(positive)} positive`,
      job.preview ? 'nothing written' : null,
      result.scan_status && result.scan_status !== 'completed' ? `source scan ${result.scan_status}` : null,
    ]
      .filter(Boolean)
      .join(' · ');
  }
  const counts = job.counts || {};
  return [
    when,
    `${fmt.count(counts.assessed ?? job.processed)} assessed`,
    job.total ? `of ${fmt.count(job.total)}` : null,
    counts.failed ? `${fmt.count(counts.failed)} failed` : null,
  ]
    .filter(Boolean)
    .join(' · ');
}

/* -- Engine cards ------------------------------------------------------------ */

function buildCard(key) {
  const engine = engines[key];
  const root = $(`card-${key}`);
  const head = root.querySelector('.engine-card__head');
  const drawer = $(`drawer-${key}`);

  const spinner = el('span', 'spinner');
  spinner.setAttribute('aria-hidden', 'true');
  // Only the state label is a live region. Counts change on every poll and
  // would turn a screen reader into a ticker; transitions are what matter.
  const label = el('span', 'engine-card__label', 'Checking…');
  label.setAttribute('role', 'status');
  const percent = el('span', 'engine-card__percent');
  const track = el('div', 'engine-card__meter');
  track.setAttribute('role', 'progressbar');
  track.setAttribute('aria-label', `${engine.name} progress`);
  track.setAttribute('aria-valuemin', '0');
  track.setAttribute('aria-valuemax', '100');
  const bar = el('div', 'meter__fill');
  track.append(bar);
  const detail = el('p', 'engine-card__detail');
  const timingLine = el('p', 'engine-card__timing');
  const warning = el('p', 'engine-card__warning');
  const status = el('div', 'engine-card__status', el('div', 'engine-card__line', spinner, label, percent), track, detail, timingLine, warning);

  const view = button('View candidates', { size: 'sm', onClick: () => showResults(key) });
  const explore = el('a', 'btn btn--sm', icon('table'), el('span', undefined, 'Open in Explore'));
  // Only a rule preview can be promoted, so only the Rule card carries Save.
  const save = key === 'rule' ? button('Save this ranking', { size: 'sm', variant: 'primary', onClick: () => engine.module?.savePreview?.() }) : null;
  const outcome = el('div', 'engine-card__outcome btn-row', view, explore, save);

  const error = el('div', 'engine-card__error');
  error.setAttribute('role', 'alert');
  const notice = el('div', 'engine-card__notice');
  const meta = el('p', 'engine-card__meta');
  const inputs = el('div', 'engine-card__inputs');

  const start = button(engine.startLabel, { variant: 'primary', onClick: () => engine.module?.start() });
  const cancel = button(`Cancel ${engine.noun}`, { variant: 'danger', onClick: () => cancelEngine(key) });
  const configure = button('Configure', { name: 'chevron', size: 'sm', onClick: () => toggleDrawer(key) });
  configure.classList.add('engine-card__configure');
  configure.setAttribute('aria-expanded', 'false');
  configure.setAttribute('aria-controls', drawer.id);
  const actions = el('div', 'engine-card__actions', start, cancel, configure);

  fill(root, head, meta, status, outcome, error, notice, inputs, actions);
  engine.card = { root, label, spinner, percent, track, bar, detail, timing: timingLine, warning, outcome, view, explore, save, error, notice, meta, inputs, start, cancel, configure, drawer };
}

function toggleDrawer(key, open) {
  const card = engines[key].card;
  const next = open ?? card.drawer.hidden;
  card.drawer.hidden = !next;
  card.configure.setAttribute('aria-expanded', String(next));
  if (next) card.drawer.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}

function paint(key) {
  const engine = engines[key];
  const card = engine.card;
  if (!card) return;
  const view = describe(key);
  const root = card.root;
  root.dataset.state = view.state;
  root.dataset.active = String(view.active);
  root.dataset.tone = view.tone;
  if (card.label.textContent !== view.label) card.label.textContent = view.label;
  card.percent.textContent = view.percent;

  // An unmeasured run drops aria-valuenow, which is how a progressbar says
  // "indeterminate", and runs a moving stripe instead of a guessed width.
  card.track.hidden = !view.meter;
  card.track.dataset.indeterminate = String(view.fraction === null);
  if (view.fraction === null) {
    card.track.removeAttribute('aria-valuenow');
    card.bar.style.width = '';
  } else {
    const percent = Math.floor(Math.min(1, view.fraction) * 100);
    card.track.setAttribute('aria-valuenow', String(percent));
    card.bar.style.width = `${percent}%`;
  }

  card.detail.textContent = view.detail;
  card.detail.title = view.detail;
  card.detail.hidden = !view.detail || view.state === 'unavailable';
  card.timing.textContent = view.timing;
  card.timing.hidden = !view.timing;
  card.warning.textContent = view.warning?.text || '';
  card.warning.dataset.tone = view.warning?.tone || '';
  card.warning.hidden = !view.warning;

  paintOutcome(key, view);

  // Capability is a permanent fact about this server, not an error to
  // dismiss, so it replaces the card's controls with an empty state.
  const unavailable = view.state === 'unavailable';
  card.notice.hidden = !unavailable;
  card.notice.textContent = unavailable ? engine.unavailable : '';
  card.inputs.hidden = unavailable;
  card.meta.hidden = unavailable || !card.meta.textContent;
  card.root.querySelector('.engine-card__actions').hidden = unavailable;
  if (unavailable) toggleDrawer(key, false);

  paintError(key);

  // The start button becomes Cancel in place: one control, where the click
  // happened, for the whole life of the run.
  card.start.hidden = view.jobActive;
  card.cancel.hidden = !view.jobActive;
  if (engine.requesting) setBusy(card.start, true, 'Starting…');
  else {
    setBusy(card.start, false);
    card.start.disabled = view.state === 'unknown' || unavailable;
  }
  setBusy(card.cancel, view.state === 'cancelling', 'Cancelling…');

  engine.module?.renderJob?.(engine.job, view);
  paintBar();
  syncHeader();
}

function paintOutcome(key, view) {
  const engine = engines[key];
  const card = engine.card;
  const job = engine.job;
  let run = null;
  let preview = false;
  if (view.finished && job) {
    if (key === 'rule') {
      preview = Boolean(job.preview) && job.status === 'completed';
      run = !job.preview && job.status === 'completed' ? job.result?.run_id : null;
    } else if (job.status !== 'failed') {
      run = job.assessment_run_id;
    }
  } else if (!view.active && !job && view.state === 'idle') {
    run = engine.module?.history?.()?.run || null;
  }
  const exploreParam = key === 'rule' ? 'ranking_run' : 'jev_run';
  card.view.hidden = !(run || preview);
  card.view.querySelector('span').textContent = preview ? 'View preview' : 'View candidates';
  card.explore.hidden = !run;
  if (run) card.explore.href = href(`/?${exploreParam}=${encodeURIComponent(run)}`);
  if (card.save) {
    card.save.hidden = !(preview && engine.module?.canSave?.(job.id));
    card.save.disabled = view.jobActive || engine.requesting;
  }
  card.outcome.hidden = card.view.hidden && card.explore.hidden && (!card.save || card.save.hidden);
}

/** Engine-scoped errors: a refused start, a cancel that failed. */
function paintError(key) {
  const engine = engines[key];
  const node = engine.card.error;
  node.hidden = !engine.error;
  if (!engine.error) {
    node.replaceChildren();
    return;
  }
  if (node.dataset.message === engine.error && node.childElementCount) return;
  node.dataset.message = engine.error;
  const dismiss = button('Dismiss', { size: 'sm', onClick: () => setError(key, '') });
  dismiss.classList.add('banner__action');
  fill(node, el('div', 'banner', icon('alert'), el('span', undefined, engine.error), dismiss));
}

function setError(key, message) {
  engines[key].error = message || '';
  paint(key);
}

const paintAll = () => Object.keys(engines).forEach(paint);

/* -- Sticky bar -------------------------------------------------------------- */

const bar = buildBar();

function buildBar() {
  const node = el('div', 'console-bar');
  node.hidden = true;
  node.setAttribute('aria-label', 'Scoring status');
  const jump = el('button', 'console-bar__jump');
  jump.type = 'button';
  jump.title = 'Back to the run console';
  on(jump, 'click', () => $('console').scrollIntoView({ behavior: 'smooth', block: 'start' }));
  const parts = {};
  const cancels = {};
  for (const [key, engine] of Object.entries(engines)) {
    const text = el('span', 'console-bar__text');
    parts[key] = el('span', 'console-bar__engine', el('span', 'console-bar__dot'), text);
    parts[key].dataset.engine = key;
    cancels[key] = button(`Cancel ${key === 'ai' ? 'AI' : 'rule'} run`, { size: 'sm', variant: 'danger', onClick: () => cancelEngine(key) });
  }
  jump.append(parts.rule, el('span', 'console-bar__sep', '·'), parts.ai);
  node.append(el('div', 'console-bar__inner', jump, cancels.rule, cancels.ai));
  document.body.append(node);
  return { node, parts, cancels };
}

function paintBar() {
  if (!bar) return;
  let any = false;
  for (const [key, engine] of Object.entries(engines)) {
    const view = describe(key);
    const busy = view.jobActive || view.requesting || view.state === 'lost';
    any ||= busy;
    const part = bar.parts[key];
    part.dataset.state = view.state;
    part.dataset.active = String(view.active);
    part.lastChild.textContent = `${engine.short}: ${busy ? [view.label, view.percent].filter(Boolean).join(' ') : view.state === 'unavailable' ? 'off' : 'idle'}`;
    bar.cancels[key].hidden = !view.jobActive;
    setBusy(bar.cancels[key], view.state === 'cancelling', 'Cancelling…');
  }
  bar.node.hidden = state.consoleVisible || !any;
}

// The bar appears only once both cards have scrolled out from under the
// header; while either card is on screen it already carries the state.
const visibleCards = new Set();
const observer = new IntersectionObserver(
  (entries) => {
    for (const entry of entries) {
      if (entry.isIntersecting) visibleCards.add(entry.target);
      else visibleCards.delete(entry.target);
    }
    state.consoleVisible = visibleCards.size > 0;
    paintBar();
  },
  { rootMargin: '-52px 0px 0px 0px' },
);

/* -- Header and page banner -------------------------------------------------- */

function syncHeader() {
  if (!state.status || state.unreachable) return;
  renderShellStatus(shell, { ...state.status, jobs: { rule: engines.rule.job, ai: engines.ai.job } });
}

function pageBanner(message) {
  const node = $('page-banner');
  node.hidden = !message;
  if (message) fill(node, icon('alert'), el('span', undefined, message));
  else node.replaceChildren();
}

/** Only an outage of every enabled engine is a page-level problem. */
function paintConnection() {
  const enabled = Object.values(engines).filter((engine) => engine.enabled());
  const down = enabled.length > 0 && enabled.every((engine) => engine.failures >= LOST_AFTER);
  if (down) {
    const last = Math.max(...enabled.map((engine) => engine.lastOkAt));
    state.unreachable = true;
    pageBanner(`Can't reach the Shrawler server · last contact ${ago(Date.now() - last)} ago · retrying every ${IDLE_MS / 1000}s. Run state below is the last known reading.`);
    shellError(shell, 'Server unreachable');
  } else if (state.unreachable) {
    state.unreachable = false;
    pageBanner('');
    syncHeader();
  }
}

/* -- Polling ----------------------------------------------------------------- */

/** Accept a job reading from either a 202 body or a poll. */
async function receive(key, job, { quiet = false } = {}) {
  const engine = engines[key];
  const now = Date.now();
  if (job?.updated_at !== engine.stamp || job?.id !== engine.job?.id) {
    engine.stamp = job?.updated_at ?? null;
    engine.changedAt = now;
  }
  if (job?.status === 'running') {
    const processed = Number(job.processed || 0);
    const track = engine.track;
    if (!track || track.id !== job.id || track.phase !== job.phase) {
      engine.track = { id: job.id, phase: job.phase, t0: now, p0: processed, t1: now, p1: processed };
    } else if (processed !== track.p1) {
      Object.assign(track, { t1: now, p1: processed });
    }
  }
  engine.job = job;
  if (engine.cancelling && (engine.cancelling !== job?.id || job.status !== 'running')) engine.cancelling = null;
  paint(key);
  if (!job || job.status === 'running' || engine.settled.has(job.id)) return;
  engine.settled.add(job.id);
  // A job that finished before this page loaded is shown, not re-announced:
  // its toast and result reload belonged to the page that ran it. A module
  // may still adopt what it left behind, such as an unsaved preview.
  if (quiet) engine.module?.adopt?.(job);
  else await engine.onSettle(job);
  paint(key);
}

async function pollEngine(key, options) {
  const engine = engines[key];
  if (!engine.enabled()) return;
  const sequence = ++engine.requested;
  let job;
  try {
    job = (await json(engine.endpoint)).job;
  } catch {
    if (sequence < engine.applied) return;
    engine.applied = sequence;
    engine.failures += 1;
    paint(key);
    paintConnection();
    return;
  }
  // Forced polls can overlap the timed one; never let an older answer paint
  // over a newer one.
  if (sequence < engine.applied) return;
  engine.applied = sequence;
  engine.failures = 0;
  engine.lastOkAt = Date.now();
  engine.seen = true;
  paintConnection();
  if (engine.awaiting) {
    // A poll that left before the POST landed still describes the previous
    // job. Keep the 202 paint until the server echoes the new ID.
    if (job?.id !== engine.awaiting && Date.now() < engine.awaitingUntil) return;
    engine.awaiting = null;
  }
  try {
    await receive(key, job, options);
  } catch (error) {
    // A paint or completion-handler bug must surface, not vanish into the
    // fetch error path the way a missing import once did.
    console.error(error);
  }
}

let timer = 0;
let generation = 0;

function nextDelay() {
  const list = Object.values(engines);
  if (list.some((engine) => engine.failures >= LOST_AFTER)) return IDLE_MS;
  if (list.some((engine) => engine.awaiting)) return CONFIRM_MS;
  if (list.some((engine) => engine.job?.status === 'running')) return BUSY_MS;
  return IDLE_MS;
}

/** Poll both engines now and reschedule. Safe to call at any time. */
async function poll(options) {
  clearTimeout(timer);
  // The most recent call owns the timer chain, so a forced poll during a timed
  // one cannot fork the loop into two.
  const own = ++generation;
  await Promise.all(Object.keys(engines).map((key) => pollEngine(key, options)));
  if (own === generation) timer = setTimeout(poll, nextDelay());
}

/* -- Starting and cancelling ------------------------------------------------- */

/**
 * Start a job. The card is busy before the request leaves, so the click is
 * acknowledged even while the server is still parsing, and a second click
 * cannot reach the server as a 409. Refusals land in the engine's own card.
 */
async function startJob(key, path, body, { accepted } = {}) {
  const engine = engines[key];
  if (engine.requesting || engine.job?.status === 'running') return null;
  engine.requesting = true;
  engine.error = '';
  paint(key);
  try {
    const job = await post(path, body);
    engine.requesting = false;
    accepted?.(job);
    engine.awaiting = job.id;
    engine.awaitingUntil = Date.now() + CONFIRM_WINDOW_MS;
    receive(key, job);
    poll();
    return job;
  } catch (error) {
    engine.requesting = false;
    setError(key, error.message);
    // Re-sync after a refused start, for example a run begun in another window.
    poll();
    return null;
  }
}

async function cancelEngine(key) {
  const engine = engines[key];
  const id = engine.job?.id;
  if (!id || engine.cancelling) return;
  engine.cancelling = id;
  paint(key);
  try {
    await post(engine.cancelPath, {});
  } catch (error) {
    engine.cancelling = null;
    setError(key, `Cancel failed: ${error.message}`);
  }
  poll();
}

/* -- Result tabs ------------------------------------------------------------- */

const TABS = ['rule', 'ai', 'missed'];

/** The active result tab rides in the fragment, so a Score link lands on one. */
function setTab(tab, { focus = false } = {}) {
  state.tab = TABS.includes(tab) ? tab : 'rule';
  for (const name of TABS) {
    const selected = name === state.tab;
    const control = $(`tab-${name}`);
    control.setAttribute('aria-selected', String(selected));
    control.tabIndex = selected ? 0 : -1;
    $(`results-${name}`).hidden = !selected;
    if (selected && focus) control.focus();
  }
  if (location.hash.slice(1) !== state.tab) history.replaceState(null, '', `${location.pathname}${location.search}#${state.tab}`);
}

for (const name of TABS) on($(`tab-${name}`), 'click', () => setTab(name));
on(document.querySelector('.results .tabs'), 'keydown', (event) => {
  const step = { ArrowRight: 1, ArrowLeft: -1 }[event.key];
  if (!step) return;
  event.preventDefault();
  setTab(TABS[(TABS.indexOf(state.tab) + step + TABS.length) % TABS.length], { focus: true });
});

/** Completion is actionable: jump straight to what the run produced. */
function showResults(key) {
  if (key === 'rule') rule.revealLatest?.();
  setTab(key === 'rule' ? 'rule' : 'ai');
  document.querySelector('.results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* -- Modules ----------------------------------------------------------------- */

for (const key of Object.keys(engines)) buildCard(key);
for (const key of Object.keys(engines)) observer.observe(engines[key].card.root);

const collectionError = el('div', 'collection-error');
$('panel-collection').before(collectionError);
const collection = createCollection($('panel-collection'));
const disclosure = $('collection-disclosure');

const rule = createRuleEngine({
  meta: engines.rule.card.meta,
  inputs: engines.rule.card.inputs,
  drawer: engines.rule.card.drawer,
  results: $('results-rule'),
});
const ai = createAiEngine({
  meta: engines.ai.card.meta,
  inputs: engines.ai.card.inputs,
  drawer: engines.ai.card.drawer,
  results: $('results-ai'),
  missed: $('results-missed'),
});
engines.rule.module = rule;
engines.ai.module = ai;

engines.rule.onSettle = async (job) => {
  if (job.status === 'completed') await rule.onComplete(job);
  else if (job.status === 'failed') toast(`Rule ranking failed · ${job.error || 'see the Rule card'}`, 'error', { sticky: true });
  else if (job.status === 'cancelled') toast('Rule ranking cancelled · nothing saved');
};

engines.ai.onSettle = async (job) => {
  if (job.status === 'failed') {
    toast(`AI assessment failed · ${job.error || 'see the AI card'}`, 'error', { sticky: true });
    return;
  }
  // Partial, paused, and cancelled runs still wrote answers to the ledger, so
  // coverage is refreshed for every outcome that has a run behind it.
  await ai.onComplete(job);
};

function context(key) {
  return {
    get status() {
      return state.status || {};
    },
    collection,
    /** Start this engine's job; resolves to the accepted job or null. */
    start: (path, body, options) => startJob(key, path, body, options),
    /** Report an engine-scoped error in the card; '' clears it. */
    fail: (message) => setError(key, message),
    repaint: () => paint(key),
    refresh: () => poll(),
    showResults: () => showResults(key),
    /** Read the shared job model, for module surfaces that mirror it. */
    view: () => describe(key),
    get job() {
      return engines[key].job;
    },
  };
}

let collectionMounted = false;
const collectionContext = {
  get status() {
    return state.status || {};
  },
  fail(message) {
    fill(collectionError, message ? el('div', 'banner', icon('alert'), el('span', undefined, message)) : null);
  },
  clearError() {
    collectionError.replaceChildren();
  },
};

// The collection surface sits behind a closed disclosure and loads only when
// opened, so it can never hold up the console or the first job poll.
on(disclosure, 'toggle', () => {
  if (!disclosure.open || collectionMounted || !state.status) return;
  collectionMounted = true;
  collection.mount(collectionContext);
});

collection.onChange(() => {
  rule.renderCollectBar();
  const count = collection.size;
  disclosure.querySelector('.collection-disclosure__hint').textContent = count
    ? `${fmt.count(count)} candidate${count === 1 ? '' : 's'} selected · staged Nemesis manifests and review decisions`
    : 'Staged Nemesis manifests and review decisions';
});

const initial = location.hash.slice(1);
setTab(initial === 'collection' ? 'rule' : initial);
if (initial === 'collection') disclosure.open = true;

// Relative times ("3m ago", "1m 20s elapsed", "last update 9s ago") move on
// their own; a once-a-second repaint keeps them honest between polls.
setInterval(() => {
  if (document.hidden) return;
  paintAll();
  if (state.unreachable) paintConnection();
}, 1000);

paintAll();
await boot();

async function boot() {
  try {
    state.status = await json('/api/status');
  } catch (error) {
    shellError(shell, error.message);
    pageBanner(`Can't reach the Shrawler server: ${error.message}. Retrying…`);
    setTimeout(boot, IDLE_MS);
    return;
  }
  pageBanner('');
  renderShellStatus(shell, state.status);
  // Paint what the status payload already says about each job, then poll at
  // once: the first full reading must not wait on catalogs or tab mounts.
  for (const [key, summary] of Object.entries(state.status.jobs || {})) {
    if (engines[key] && summary && !engines[key].job) {
      engines[key].job = summary;
      engines[key].stamp = summary.updated_at ?? null;
    }
  }
  rule.mount(context('rule'));
  ai.mount(context('ai'));
  paintAll();
  poll({ quiet: true });
  if (disclosure.open && !collectionMounted) {
    collectionMounted = true;
    collection.mount(collectionContext);
  }
  await Promise.all([rule.load(), ai.load()]);
  paintAll();
  // The endpoint probe is a real network call to the configured model gateway.
  // It runs after the loads, under a bounded budget, so an unreachable
  // endpoint cannot stall the surfaces that work without it.
  if (state.status.assessment_enabled) ai.checkEndpoint({ timeout: 8000 });
}
