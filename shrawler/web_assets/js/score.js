// Score screen shell. Owns the tabs, the always-visible status strip, and the
// polling of both job endpoints.
//
// The strip is deliberately outside the tabs. The two engines run
// independently and concurrently, so an AI run started on one tab has to keep
// reporting while the analyst works on the other.

import { json, mountShell, on, post, renderShellStatus, shellError } from './core.js';
import { errorLine, toast } from './overlay.js';

const $ = (id) => document.getElementById(id);
const shell = mountShell('/score');

const RUNNING = new Set(['running', 'starting', 'staging', 'dispatching', 'planning']);
const IDLE_MS = 4000;
const BUSY_MS = 1200;

const state = { status: {}, ruleJob: null, aiJob: null, tab: 'rule' };

const engines = {
  rule: { root: $('status-rule'), cancel: $('cancel-rule') },
  ai: { root: $('status-ai'), cancel: $('cancel-ai') },
};

function paintStrip(key, job) {
  const engine = engines[key];
  const label = engine.root.querySelector('.engine-status__state');
  const detail = engine.root.querySelector('.engine-status__detail');
  const bar = engine.root.querySelector('.meter__fill');
  const running = job?.status === 'running' || RUNNING.has(job?.phase);
  engine.root.dataset.state = job ? job.status : 'idle';
  label.textContent = running ? `${job.phase || 'running'}` : job ? job.status : 'idle';
  const processed = Number(job?.processed || 0);
  const total = Number(job?.total || 0);
  const fraction = total > 0 ? processed / total : running ? 0.02 : 0;
  bar.style.width = `${Math.round(Math.min(1, fraction) * 100)}%`;
  bar.dataset.tone = job?.status === 'failed' ? 'danger' : job?.status === 'completed' ? 'success' : '';
  engine.cancel.hidden = !running;
  if (!job) {
    detail.textContent = key === 'rule' ? 'Metadata only' : state.status.assessment_enabled ? '' : 'Endpoint not configured';
    return;
  }
  if (running) {
    // Every one of these numbers is already published by the two services.
    // Showing them is the difference between "something is happening" and
    // knowing how much is left, what is failing, and what the cache saved.
    const batches =
      job.completed_batches === undefined
        ? null
        : `${fmt.count(job.completed_batches)} / ${fmt.count((job.completed_batches || 0) + (job.active_batches || 0) + (job.pending_batches || 0))} batches`;
    detail.textContent = [
      `${fmt.count(processed)} / ${fmt.count(total)} observed`,
      batches,
      job.pending !== undefined ? `${fmt.count(job.pending)} pending` : null,
      job.failed ? `${fmt.count(job.failed)} failed` : null,
      job.in_flight ? `${fmt.count(job.in_flight)} in flight` : null,
      job.reused_requests ? `${fmt.count(job.reused_requests)} reused` : null,
      job.retried_requests ? `${fmt.count(job.retried_requests)} retried` : null,
    ]
      .filter(Boolean)
      .join(' · ');
  } else if (job.status === 'completed') {
    detail.textContent = [
      `${fmt.count(job.result?.files_scored ?? processed)} scored`,
      job.result?.scan_status ? `source scan ${job.result.scan_status}` : null,
      `${fmt.count(job.counts?.assessed ?? processed)} assessed`,
      job.counts?.failed ? `${fmt.count(job.counts.failed)} failed` : null,
    ]
      .filter(Boolean)
      .join(' · ');
  } else {
    detail.textContent = job.error || job.status;
  }
}

async function pollRuleJob() {
  if (!state.status.triage_enabled) return;
  try {
    const payload = await json('/api/triage/job');
    const previous = state.ruleJob;
    state.ruleJob = payload.job;
    paintStrip('rule', state.ruleJob);
    if (!state.ruleJob) return;
    if (state.ruleJob.status === 'completed' && previous?.id !== state.ruleJob.id) await ruleTab.onComplete(state.ruleJob);
    if (state.ruleJob.status === 'failed' && previous?.id !== state.ruleJob.id) context.fail(state.ruleJob.error || 'Rule ranking failed');
  } catch {
    /* The tab that needs the data reports its own failures. */
  }
}

async function pollAiJob() {
  if (!state.status.assessment_enabled) return;
  try {
    const payload = await json('/api/assessment/job');
    const previous = state.aiJob;
    state.aiJob = payload.job;
    paintStrip('ai', state.aiJob);
    if (!state.aiJob) return;
    if (state.aiJob.status === 'completed' && previous?.id !== state.aiJob.id) await aiTab.onComplete(state.aiJob);
    if (state.aiJob.error && previous?.id !== state.aiJob.id) context.fail(state.aiJob.error);
  } catch {
    /* The tab that needs the data reports its own failures. */
  }
}

async function poll() {
  await Promise.all([pollRuleJob(), pollAiJob()]);
  const busy = [state.ruleJob, state.aiJob].some((job) => job && (job.status === 'running' || RUNNING.has(job.phase)));
  setTimeout(poll, busy ? BUSY_MS : IDLE_MS);
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

on($('cancel-rule'), 'click', async () => {
  try {
    await post('/api/triage/cancel', {});
    toast('Cancellation requested');
  } catch (error) {
    toast(error.message, 'error');
  }
});

on($('cancel-ai'), 'click', async () => {
  try {
    await post('/api/assessment/cancel', {});
    toast('Cancellation requested');
  } catch (error) {
    toast(error.message, 'error');
  }
});

on(document, 'keydown', (event) => {
  if (event.metaKey || event.ctrlKey || event.altKey) return;
  if (event.key !== '1' && event.key !== '2') return;
  if (event.target.closest('input, textarea, select')) return;
  event.preventDefault();
  setTab(event.key === '1' ? 'rule' : 'ai');
});

/* -- Tabs ------------------------------------------------------------------ */

const ruleTab = (await import('./score-rule.js')).createRuleTab($('panel-rule'));
const aiTab = (await import('./score-ai.js')).createAiTab($('panel-ai'));
const collection = (await import('./collection.js')).createCollection($('panel-collection'));

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
  collection.onChange(() => ruleTab.renderCollectBar());
  await collection.mount(context);
  setTab(location.hash.slice(1) === 'ai' ? 'ai' : 'rule');
  await Promise.all([ruleTab.load(), aiTab.load(), pollRuleJob(), pollAiJob()]);
  // The endpoint probe is a real network call to the configured model gateway.
  // It runs after the tab loads, under a bounded budget, so an unreachable
  // endpoint cannot stall the surfaces that work without it.
  if (state.status.assessment_enabled) withTimeout(aiTab.checkEndpoint(), 8000);
  setTimeout(poll, IDLE_MS);
}