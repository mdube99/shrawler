// Score screen shell. Owns the tabs, the always-visible status strip, and the
// polling of both job endpoints.
//
// The strip is deliberately outside the tabs. The two engines run
// independently and concurrently, so an AI run started on one tab has to keep
// reporting while the analyst works on the other.

import { fmt, json, mountShell, on, post, renderShellStatus, setBusy, shellError } from './core.js';
import { errorLine, toast } from './overlay.js';

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

// Services emit terse internal phase names. The analyst sees what the engine
// is doing; `counted` marks phases whose processed/total is a real measure.
// Saving is counted (every file really is scored) but long on a big
// inventory, so it shows no percentage that would read as "done".
const PHASES = {
  starting: { label: 'Starting', counted: false },
  'indexing sibling names': { label: 'Indexing sibling names', counted: true, verb: 'indexed' },
  scoring: { label: 'Scoring files', counted: true, verb: 'scored' },
  saving: { label: 'Saving results', counted: true, verb: 'scored', percent: false },
  'staging ledger': { label: 'Staging ledger', counted: false },
  'planning batches': { label: 'Planning batches', counted: false },
  dispatching: { label: 'Assessing files', counted: true, verb: 'assessed' },
};

const OUTCOMES = {
  completed: 'Completed',
  partial: 'Partially assessed',
  paused: 'Paused at time budget',
  failed: 'Failed',
  cancelled: 'Cancelled',
};

const state = { status: {}, tab: 'rule' };

const engines = {
  rule: {
    name: 'Rule ranking',
    endpoint: '/api/triage/job',
    cancelPath: '/api/triage/cancel',
    enabled: () => state.status.triage_enabled,
    root: $('status-rule'),
    cancel: $('cancel-rule'),
  },
  ai: {
    name: 'AI assessment',
    endpoint: '/api/assessment/job',
    cancelPath: '/api/assessment/cancel',
    enabled: () => state.status.assessment_enabled,
    root: $('status-ai'),
    cancel: $('cancel-ai'),
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
    requested: 0,
    applied: 0,
  });
}

const sentence = (text) => (text ? text[0].toUpperCase() + text.slice(1) : '');

/**
 * One reading of a job, shared by the strip and the in-panel indicator so the
 * two can never disagree about what an engine is doing.
 */
function describe(key) {
  const engine = engines[key];
  const job = engine.job;
  if (!job) {
    const detail = key === 'rule' ? 'Metadata only' : state.status.assessment_enabled ? '' : 'Endpoint not configured';
    return { state: 'idle', active: false, label: 'Idle', detail, fraction: 0, tone: '', headline: '', summary: '' };
  }
  const processed = Number(job.processed || 0);
  const total = Number(job.total || 0);
  const active = job.status === 'running';
  const phase = PHASES[job.phase] || { label: sentence(job.phase || 'running'), counted: false };
  let view;
  if (active) {
    const cancelling = engine.cancelling === job.id;
    // "Starting" is the window between the 202 and the first progress report.
    // It gets an activity spinner and no meter fill: nothing has been measured.
    const starting = job.phase === 'starting';
    const measured = phase.counted && total > 0;
    view = {
      state: cancelling ? 'cancelling' : starting ? 'starting' : 'running',
      active: true,
      label: cancelling ? 'Cancelling' : phase.label,
      detail: starting ? 'Accepted · waiting for the first progress report' : runningDetail(key, job, phase, processed, total),
      fraction: measured ? processed / total : null,
      tone: '',
    };
  } else {
    view = {
      state: job.status,
      active: false,
      label: outcomeLabel(key, job),
      detail: outcomeDetail(key, job, processed),
      fraction: job.status === 'completed' ? 1 : total > 0 ? processed / total : 0,
      tone: job.status === 'failed' ? 'danger' : job.status === 'completed' ? 'success' : '',
    };
  }
  const percent =
    view.fraction !== null && view.active && phase.percent !== false ? `${Math.floor(Math.min(1, view.fraction) * 100)}%` : '';
  view.headline = view.label;
  view.summary = [percent, view.detail].filter(Boolean).join(' · ');
  return view;
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

function outcomeLabel(key, job) {
  if (key === 'rule' && job.status === 'completed') return job.preview ? 'Preview ready' : 'Ranking saved';
  return OUTCOMES[job.status] || sentence(job.status);
}

function outcomeDetail(key, job, processed) {
  if (job.status === 'failed' && job.error) return job.error;
  if (key === 'rule') {
    if (job.status === 'cancelled') return 'Stopped · nothing saved';
    return [
      `${fmt.count(job.result?.files_scored ?? processed)} scored`,
      job.preview ? 'not saved' : null,
      job.result?.scan_status ? `source scan ${job.result.scan_status}` : null,
    ]
      .filter(Boolean)
      .join(' · ');
  }
  const counts = job.counts || {};
  return [
    `${fmt.count(counts.assessed ?? processed)} assessed`,
    job.total ? `of ${fmt.count(job.total)}` : null,
    counts.failed ? `${fmt.count(counts.failed)} failed` : null,
  ]
    .filter(Boolean)
    .join(' · ');
}

function paint(key) {
  const engine = engines[key];
  const view = describe(key);
  const root = engine.root;
  root.dataset.state = view.state;
  root.dataset.active = String(view.active);
  root.querySelector('.engine-status__label').textContent = view.label;
  root.querySelector('.engine-status__detail').textContent = view.detail;
  root.querySelector('.engine-status__detail').title = view.detail;
  const track = root.querySelector('.engine-status__meter');
  const bar = track.querySelector('.meter__fill');
  // An unmeasured run drops aria-valuenow, which is how a progressbar says
  // "indeterminate", instead of painting a guessed width.
  if (view.fraction === null) {
    track.removeAttribute('aria-valuenow');
    bar.style.width = '0%';
  } else {
    const percent = Math.round(Math.min(1, view.fraction) * 100);
    track.setAttribute('aria-valuenow', String(percent));
    bar.style.width = `${percent}%`;
  }
  track.dataset.measured = String(view.fraction !== null);
  bar.dataset.tone = view.tone;
  engine.cancel.hidden = !view.active;
  setBusy(engine.cancel, view.state === 'cancelling', 'Cancelling…');
  engine.tab?.renderJob(engine.job, view);
}

/** Accept a job reading from either a 202 body or a poll. */
async function receive(key, job, { quiet = false } = {}) {
  const engine = engines[key];
  engine.job = job;
  if (engine.cancelling && (engine.cancelling !== job?.id || job.status !== 'running')) engine.cancelling = null;
  paint(key);
  if (!job || job.status === 'running' || engine.settled.has(job.id)) return;
  engine.settled.add(job.id);
  if (!quiet) await engine.onSettle(job);
}

async function pollEngine(key, options) {
  const engine = engines[key];
  if (!engine.enabled()) return;
  const sequence = ++engine.requested;
  let job;
  try {
    job = (await json(engine.endpoint)).job;
  } catch {
    /* The tab that needs the data reports its own failures. */
    return;
  }
  // Forced polls can overlap the timed one; never let an older answer paint
  // over a newer one.
  if (sequence < engine.applied) return;
  engine.applied = sequence;
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

// The endpoint probe reaches the configured gateway, so give it a bounded
// budget rather than letting a hung connection stall the strip's paint loop.
const withTimeout = (promise, ms) =>
  Promise.race([promise, new Promise((resolve) => setTimeout(resolve, ms))]).catch(() => null);

/** The active tab rides in the fragment, so a Score link lands on one tab. */
function setTab(tab) {
  state.tab = tab;
  const isRule = tab === 'rule';
  $('tab-rule').setAttribute('aria-selected', String(isRule));
  $('tab-ai').setAttribute('aria-selected', String(!isRule));
  $('panel-rule').hidden = !isRule;
  $('panel-ai').hidden = isRule;
  if (location.hash.slice(1) !== tab) history.replaceState(null, '', `${location.pathname}${location.search}#${tab}`);
}

on($('tab-rule'), 'click', () => setTab('rule'));
on($('tab-ai'), 'click', () => setTab('ai'));

for (const [key, engine] of Object.entries(engines)) {
  on(engine.cancel, 'click', async () => {
    const id = engine.job?.id;
    if (!id) return;
    engine.cancelling = id;
    paint(key);
    try {
      await post(engine.cancelPath, {});
      toast(`Cancelling ${engine.name.toLowerCase()}`);
    } catch (error) {
      engine.cancelling = null;
      paint(key);
      toast(error.message, 'error');
    }
    poll();
  });
}

on(document, 'keydown', (event) => {
  if (event.metaKey || event.ctrlKey || event.altKey) return;
  if (event.key !== '1' && event.key !== '2') return;
  if (event.target.closest('input, textarea, select')) return;
  event.preventDefault();
  setTab(event.key === '1' ? 'rule' : 'ai');
});

// The strip is sticky, so anything focused or scrolled to by fragment must
// clear it as well as the header. Its height changes with wrapping and the
// cancel buttons, so it is measured rather than assumed.
new ResizeObserver(([entry]) => {
  const sticky = getComputedStyle(entry.target).position === 'sticky';
  document.documentElement.style.setProperty('--status-strip-height', sticky ? `${entry.target.offsetHeight}px` : '0px');
}).observe(document.querySelector('.status-strip'));

/* -- Tabs ------------------------------------------------------------------ */

const ruleTab = (await import('./score-rule.js')).createRuleTab($('panel-rule'));
const aiTab = (await import('./score-ai.js')).createAiTab($('panel-ai'));
const collection = (await import('./collection.js')).createCollection($('panel-collection'));

engines.rule.tab = ruleTab;
engines.ai.tab = aiTab;

engines.rule.onSettle = async (job) => {
  if (job.status === 'completed') await ruleTab.onComplete(job);
  else if (job.status === 'failed') {
    context.fail(job.error || 'Rule ranking failed');
    toast('Rule ranking failed', 'error');
  } else if (job.status === 'cancelled') toast('Rule ranking cancelled');
};

engines.ai.onSettle = async (job) => {
  if (job.status === 'failed') {
    context.fail(job.error || 'AI assessment failed');
    toast('AI assessment failed', 'error');
    return;
  }
  // Partial, paused, and cancelled runs still wrote answers to the ledger, so
  // coverage is refreshed for every outcome that has a run behind it.
  await aiTab.onComplete(job);
};

const context = {
  get status() {
    return state.status;
  },
  collection,
  fail(message) {
    errorLine($('error-banner'), message);
  },
  clearError() {
    errorLine($('error-banner'), '');
  },
  /** A tab reports the 202 body of a job it just started. */
  started(key, job) {
    const engine = engines[key];
    engine.awaiting = job.id;
    engine.awaitingUntil = Date.now() + CONFIRM_WINDOW_MS;
    receive(key, job);
    poll();
  },
  /** Re-sync after a refused start, for example a run begun in another window. */
  refresh() {
    poll();
  },
};

await boot();

async function boot() {
  try {
    state.status = await json('/api/status');
    renderShellStatus(shell, state.status);
  } catch (error) {
    shellError(shell, error.message);
    errorLine($('error-banner'), error.message);
    return;
  }
  const missing = [];
  if (!state.status.triage_enabled) missing.push('Rule ranking is unavailable for this inventory.');
  if (!state.status.assessment_enabled) missing.push('AI assessment is disabled. Start Shrawler with a model endpoint to enable it.');
  if (missing.length) errorLine($('error-banner'), missing.join(' '));

  // Both tabs mount regardless, so the reason a surface is empty is visible in
  // place instead of hiding behind a missing nav item.
  ruleTab.mount(context);
  aiTab.mount(context);
  for (const key of Object.keys(engines)) paint(key);
  collection.onChange(() => ruleTab.renderCollectBar());
  await collection.mount(context);
  setTab(location.hash.slice(1) === 'ai' ? 'ai' : 'rule');
  // A job that already finished before this page loaded is shown, not
  // re-announced: its toast and result reload belonged to the page that ran it.
  await Promise.all([ruleTab.load(), aiTab.load(), poll({ quiet: true })]);
  // The endpoint probe is a real network call to the configured model gateway.
  // It runs after the tab loads, under a bounded budget, so an unreachable
  // endpoint cannot stall the surfaces that work without it.
  if (state.status.assessment_enabled) withTimeout(aiTab.checkEndpoint(), 8000);
}
