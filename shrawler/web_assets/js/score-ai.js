// AI assessment engine: the essential inputs on its console card, the
// Configure drawer (question cap, staging, endpoint check), coverage with real
// token and cost figures, and two result tabs: AI candidates, and the strong
// values the rules missed, which answers "what did the rule engine not find".

import { button, checkbox, clear, el, field, fill, fmt, href, icon, json, number, on, option, select, setBusy, severity } from './core.js';
import { panel, toast } from './overlay.js';

const PRIORITIES = [
  ['', 'All priorities'],
  ['4', '4 Immediate'],
  ['3', '3 Strong'],
  ['2', '2 Likely'],
  ['1', '1 Possible'],
  ['0', '0 Minimal'],
];

const PAGE = 100;
// Coverage is re-read this often while a run is active, so the numbers below
// the console move with the card instead of waiting for the run to end.
const LIVE_COVERAGE_MS = 5000;

export function createAiEngine(slots) {
  // Held by reference: the shell's `status` and `job` are live getters.
  let ctx = { status: {}, start: async () => null, repaint() {}, showResults() {}, view: () => ({}), job: null };
  const nodes = {};
  let catalog = { runs: [], scans: [], endpoint: '', model: '' };
  let directoriesVisible = false;
  let mounted = false;
  let liveAt = 0;
  let liveBusy = false;
  let usage = null;
  let endpointNote = '';
  const tables = {};

  function mount(context) {
    ctx = context;
    if (mounted) return;
    mounted = true;
    buildInputs();
    buildDrawer();
    buildResults();
    tables.missed = candidateTable(slots.missed, { missed: true });
    paintMeta();
  }

  /* -- Card inputs ----------------------------------------------------------- */

  function buildInputs() {
    nodes.scan = select([['', 'Latest completed inventory scan']]);
    nodes.budget = number('0', 0);
    nodes.budget.classList.add('input--num');
    nodes.budget.title = 'Seconds; 0 means unlimited';
    fill(slots.inputs, field('Source scan', nodes.scan), field('Time budget (s, 0 = none)', nodes.budget));
  }

  /** Endpoint, model, and the run's billed cost, folded into the card. */
  function paintMeta() {
    const parts = [];
    if (catalog.model) parts.push(`Model ${catalog.model}`);
    if (endpointNote) parts.push(endpointNote);
    if (usage?.billed_input_tokens) parts.push(`$${(usage.estimated_cost_usd || 0).toFixed(2)} billed on the selected run`);
    slots.meta.textContent = parts.join(' · ') || 'Every observed file, with shared directory context.';
    slots.meta.dataset.tone = endpointNote.startsWith('Endpoint unreachable') ? 'warn' : '';
    ctx.repaint();
  }

  function start() {
    const budget = Number(nodes.budget.value || 0);
    return ctx.start('/api/assessment/jobs', {
      scan_id: nodes.scan.value || null,
      prepare: nodes.prepare.firstChild.checked,
      budget_seconds: Number.isFinite(budget) && budget >= 0 ? Math.floor(budget) : 0,
      max_questions: Number(nodes.maxQuestions.value || 200),
    });
  }

  /* -- Configure drawer ------------------------------------------------------ */

  function buildDrawer() {
    nodes.prepare = checkbox('Stage ledger and directory context first', true);
    nodes.maxQuestions = number('200', 1);
    nodes.maxQuestions.classList.add('input--num');
    nodes.gateway = el('p', 'panel__hint', 'Checking the configured decision endpoint…');
    nodes.check = button('Check endpoint', { size: 'sm', name: 'refresh', onClick: () => checkEndpoint() });
    const grid = el('div', 'field-grid');
    fill(
      grid,
      field('Max questions per request', nodes.maxQuestions),
      el('div', 'field', el('span', 'field__label', 'Preparation'), nodes.prepare),
    );
    fill(
      slots.drawer,
      el(
        'header',
        'engine-drawer__head',
        el('h3', 'engine-drawer__title', 'Configure AI assessment'),
        el('span', 'field__hint', 'Probabilistic. Model priority is metadata-based review value, not confirmed content.'),
      ),
      grid,
      el('div', 'btn-row endpoint-row', nodes.check, nodes.gateway),
    );
  }

  /* -- Results --------------------------------------------------------------- */

  function buildResults() {
    nodes.resultsError = el('div', 'results-error');
    nodes.run = select([['', 'Latest assessment run']]);
    const controls = el('div', 'field-grid');
    fill(
      controls,
      field('Assessment run', nodes.run),
      button('Refresh', { size: 'sm', name: 'refresh', onClick: () => Promise.all([loadCoverage(), tables.ai.load(), tables.missed.load()]) }),
      button('Per-directory coverage', { size: 'sm', onClick: () => toggleDirectories() }),
    );
    nodes.coverageSummary = el('p', 'panel__hint');
    nodes.coverageStats = el('div', 'stat-row');
    nodes.directories = el('div', 'coverage-directories');
    nodes.directories.hidden = true;
    nodes.empty = el('div', 'empty');
    nodes.empty.hidden = true;
    nodes.coverage = panel('Coverage', 'Unfinished coverage is always reported.', [
      controls,
      nodes.coverageSummary,
      nodes.coverageStats,
      nodes.directories,
    ]).node;
    fill(slots.results, nodes.resultsError, nodes.empty, nodes.coverage);
    tables.ai = candidateTable(slots.results, { missed: false });
    on(nodes.run, 'change', () => {
      tables.ai.reset();
      tables.missed.reset();
      usage = null;
      loadCoverage().catch((error) => resultsError(error.message));
      tables.ai.load();
      tables.missed.load();
    });
  }

  function resultsError(message) {
    fill(nodes.resultsError, message ? el('div', 'banner', icon('alert'), el('span', undefined, message)) : null);
  }

  /** One candidate table. The missed view is the same query with missed=1. */
  function candidateTable(root, { missed }) {
    const table = { offset: 0, token: 0 };
    const label = missed ? null : select(PRIORITIES);
    const summary = el('p', 'panel__hint');
    const error = el('div', 'results-error');
    const rows = el('tbody');
    const grid = el('table', 'data-grid score-grid');
    fill(
      grid,
      el(
        'thead',
        {},
        el('tr', {}, el('th', 'numeric', 'Priority'), el('th', undefined, 'File'), el('th', undefined, 'Observed location'), el('th', undefined, 'Distribution')),
      ),
      rows,
    );
    const page = {
      prev: button('Previous', { size: 'sm', onClick: () => step(-PAGE) }),
      next: button('Next', { size: 'sm', onClick: () => step(PAGE) }),
      label: el('span', undefined, 'Page 1'),
    };
    const pager = el('div', 'pagination');
    fill(pager, page.prev, page.label, page.next);
    const controls = el('div', 'field-grid');
    if (label) controls.append(field('Priority', label));
    controls.append(button('Refresh', { size: 'sm', name: 'refresh', onClick: () => table.load() }));
    const source = el('p', 'field__hint');
    const { node } = panel(
      missed ? 'Missed by rules' : 'AI candidates',
      missed
        ? 'Files the rule engine scored low that the model still judged worth strong review: the clearest statement of what the rules did not find.'
        : 'Model priority is metadata-based review value, not confirmed content.',
      [error, missed ? source : null, controls, summary, el('div', 'grid-shell score-grid-shell', grid), pager],
    );
    root.append(node);
    if (label) {
      on(label, 'change', () => {
        table.offset = 0;
        table.load();
      });
    }

    function step(delta) {
      table.offset = Math.max(0, table.offset + delta);
      table.load();
    }

    table.reset = () => {
      table.offset = 0;
    };

    table.empty = (message) => {
      clear(rows);
      summary.textContent = message;
      page.prev.disabled = true;
      page.next.disabled = true;
    };

    table.load = async () => {
      if (!ctx.status.assessment_enabled) return table.empty('AI assessment is disabled for this server.');
      if (!nodes.run.value) return table.empty('No assessment run yet. Start one from the AI card above.');
      const token = ++table.token;
      const params = new URLSearchParams({ limit: String(PAGE), offset: String(table.offset), run: nodes.run.value });
      if (label?.value) params.set('label', label.value);
      if (missed) params.set('missed', '1');
      source.textContent = `Assessment run ${nodes.run.selectedOptions[0]?.textContent || nodes.run.value}`;
      try {
        const data = await json(`/api/assessment/files?${params}`);
        if (token !== table.token) return;
        fill(error);
        render(data);
      } catch (failure) {
        if (token === table.token) fill(error, el('div', 'banner', icon('alert'), el('span', undefined, failure.message)));
      }
    };

    function render(data) {
      clear(rows);
      for (const item of data.items) {
        const row = el('tr', 'rail');
        row.dataset.severity = severity(item.priority).band;
        const priority = el('td', 'numeric');
        const text = item.priority_name ? `${item.priority} ${item.priority_name}` : String(item.priority ?? item.choice ?? '—');
        // The AI chip keeps the AI hue; its weight tracks how strong the call was.
        const chip = el('span', 'score score--ai');
        chip.dataset.strong = String(Number(item.priority) >= 3);
        chip.textContent = text;
        chip.title = text;
        priority.append(chip);
        const link = el('a', 'candidate-link', item.file_name);
        link.href = href(`/?q=${encodeURIComponent(item.unc_path)}`);
        const distribution = item.distribution
          ? Object.entries(item.distribution)
              .map(([key, value]) => `${key} ${Number(value).toFixed(2)}`)
              .join(', ')
          : '—';
        fill(row, priority, el('td', undefined, link), el('td', 'score-path', item.unc_path), el('td', 'score-reasons', distribution));
        rows.append(row);
      }
      if (!data.items.length) {
        const row = el('tr');
        const cell = el('td', 'empty', missed ? 'Nothing the rules missed in this run.' : 'No assessed candidates match this filter.');
        cell.colSpan = 4;
        row.append(cell);
        rows.append(row);
      }
      summary.textContent = `Showing ${fmt.count(data.items.length)} ${missed ? 'rule-missed' : 'assessed'} file${data.items.length === 1 ? '' : 's'}.`;
      page.label.textContent = `Page ${Math.floor(table.offset / PAGE) + 1}`;
      page.prev.disabled = table.offset === 0;
      page.next.disabled = data.items.length < PAGE;
    }

    return table;
  }

  async function loadCatalog(preferred) {
    catalog = await json('/api/assessment/catalog');
    const scan = nodes.scan.value;
    fill(
      nodes.scan,
      option('', 'Latest completed inventory scan'),
      ...catalog.scans.map((item) => option(item.id, `${item.short_id} · ${item.status} · ${fmt.count(item.file_count)} files · ${fmt.stamp(item.started_at_utc)}`)),
    );
    if (catalog.scans.some((item) => item.id === scan)) nodes.scan.value = scan;
    const chosen = preferred || nodes.run.value;
    fill(
      nodes.run,
      option('', catalog.runs.length ? 'Latest assessment run' : 'No assessment run yet'),
      ...catalog.runs.map((item) => option(item.id, `${fmt.stamp(item.created_at)} · ${fmt.count(item.total_observed)} files · ${item.status}`)),
    );
    if (catalog.runs.some((item) => item.id === chosen)) nodes.run.value = chosen;
    else nodes.run.value = catalog.runs.length ? catalog.runs[0].id : '';
    paintMeta();
  }

  async function loadCoverage() {
    if (!nodes.run.value) {
      nodes.coverageSummary.textContent = 'No assessment run yet. Start one from the AI card above.';
      clear(nodes.coverageStats);
      return;
    }
    const run = nodes.run.value;
    const status = await json(`/api/assessment/status?${new URLSearchParams({ run })}`);
    if (run !== nodes.run.value) return;
    nodes.coverageSummary.textContent = `${fmt.count(status.total_observed)} observed · ${fmt.count(status.assessed)} assessed · ${fmt.count(status.in_flight)} in flight · ${fmt.count(status.pending)} pending · ${fmt.count(status.failed)} failed · reconciled ${status.reconciled ? 'yes' : 'NO'}`;
    const batches = status.batches || {};
    usage = status.usage || {};
    const latency = status.latency_ms || {};
    const stats = [
      ['batches', `${fmt.count(batches.completed || 0)} / ${fmt.count(batches.total || 0)} done`],
      ['active', fmt.count(batches.active || 0)],
      ['packing', status.packing_scope || 'directory'],
      ['workers', status.workers ?? '?'],
      latency.p50 != null ? ['p50', `${latency.p50} ms`] : null,
      latency.p95 != null ? ['p95', `${latency.p95} ms`] : null,
      status.metrics?.reused_requests ? ['reused requests', fmt.count(status.metrics.reused_requests)] : null,
      status.metrics?.retried_requests ? ['retried requests', fmt.count(status.metrics.retried_requests)] : null,
      // Real billed usage from the gateway, not a local estimate.
      ['input tokens', fmt.count(usage.billed_input_tokens || 0)],
      ['output tokens', fmt.count(usage.output_tokens || 0)],
      usage.billed_input_tokens ? ['estimated cost', `$${(usage.estimated_cost_usd || 0).toFixed(2)}`] : null,
    ].filter(Boolean);
    clear(nodes.coverageStats);
    for (const [label, value] of stats) {
      const entry = el('span');
      entry.append(el('b', undefined, `${label} `), document.createTextNode(String(value)));
      nodes.coverageStats.append(entry);
    }
    paintMeta();
  }

  async function toggleDirectories() {
    directoriesVisible = !directoriesVisible;
    nodes.directories.hidden = !directoriesVisible;
    if (!directoriesVisible || !nodes.run.value) return;
    fill(nodes.directories, el('span', 'spinner'), el('span', 'field__hint', 'Loading directory coverage…'));
    try {
      const data = await json(`/api/assessment/coverage?${new URLSearchParams({ run: nodes.run.value })}`);
      clear(nodes.directories);
      if (!data.directories.length) {
        nodes.directories.append(el('p', 'field__hint', 'No directory context stored for this run yet.'));
        return;
      }
      for (const entry of data.directories.slice(0, 500)) {
        const counts = Object.entries(entry.counts)
          .map(([key, value]) => `${key} ${value}`)
          .join(', ');
        nodes.directories.append(el('p', undefined, `${entry.host || ''}\\${entry.share || ''}${entry.directory || ''} — ${counts} (${entry.enumeration || ''})`));
      }
    } catch (error) {
      clear(nodes.directories);
      nodes.directories.append(el('p', 'field__hint', error.message));
    }
  }

  /* -- Endpoint -------------------------------------------------------------- */

  /**
   * Probe the configured gateway. It is a real network call, so it runs under
   * a bounded budget and reports in place rather than as a page error.
   */
  async function checkEndpoint({ timeout = 15000 } = {}) {
    setBusy(nodes.check, true, 'Checking…');
    try {
      const report = await Promise.race([
        json('/api/assessment/check'),
        new Promise((_, reject) => setTimeout(() => reject(new Error(`no answer within ${timeout / 1000}s`)), timeout)),
      ]);
      if (!report.reachable) {
        nodes.gateway.textContent = `Endpoint unreachable: ${report.error}`;
        endpointNote = 'Endpoint unreachable · see Configure';
      } else {
        nodes.gateway.textContent = `Endpoint HTTP ${report.http_status} in ${report.latency_ms} ms · model ${report.resolved_model} · answers ${report.returns_answers} · usage ${report.returns_usage}`;
        endpointNote = `endpoint OK in ${report.latency_ms} ms`;
      }
    } catch (error) {
      nodes.gateway.textContent = `Endpoint check failed: ${error.message}`;
      endpointNote = 'Endpoint unreachable · see Configure';
    } finally {
      setBusy(nodes.check, false);
      paintMeta();
    }
  }

  /* -- Lifecycle ------------------------------------------------------------- */

  async function load() {
    if (!ctx.status.assessment_enabled) {
      nodes.coverage.hidden = true;
      nodes.empty.hidden = false;
      fill(
        nodes.empty,
        el('strong', undefined, 'AI assessment is disabled'),
        el('span', undefined, 'Enable [jev] with a model endpoint in the Shrawler configuration and restart the server.'),
      );
      tables.ai.empty('AI assessment is disabled for this server.');
      tables.missed.empty('AI assessment is disabled for this server.');
      return;
    }
    try {
      await loadCatalog();
    } catch (error) {
      resultsError(error.message);
      return;
    }
    nodes.gateway.textContent = `Endpoint: ${catalog.endpoint} · model: ${catalog.model}`;
    try {
      await Promise.all([loadCoverage(), tables.ai.load(), tables.missed.load()]);
    } catch (error) {
      resultsError(error.message);
    }
  }

  /** Keep coverage live while a run is active, at a bounded rate. */
  async function tick(job) {
    if (!job?.assessment_run_id || liveBusy || Date.now() - liveAt < LIVE_COVERAGE_MS) return;
    liveBusy = true;
    liveAt = Date.now();
    try {
      if (!catalog.runs.some((run) => run.id === job.assessment_run_id)) await loadCatalog(job.assessment_run_id);
      if (nodes.run.value === job.assessment_run_id) await loadCoverage();
    } catch {
      /* The next tick retries; the card already reports connection loss. */
    } finally {
      liveBusy = false;
    }
  }

  function renderJob(job, view) {
    if (view?.jobActive) tick(job);
  }

  async function onComplete(job) {
    const outcome = {
      completed: ['Assessment complete', 'ok', false],
      partial: ['Assessment finished with unassessed files', 'warn', true],
      paused: ['Assessment paused at its time budget', 'warn', true],
      cancelled: ['Assessment cancelled · answers so far are kept', 'ok', false],
    };
    const [message, tone, sticky] = outcome[job.status] || ['Assessment finished', 'ok', false];
    const assessed = job.counts?.assessed ?? job.processed;
    toast(`${message} · ${fmt.count(assessed)} assessed`, tone, {
      sticky,
      action: job.assessment_run_id ? { label: 'View candidates', onClick: () => ctx.showResults() } : undefined,
    });
    if (!job.assessment_run_id) return;
    try {
      await loadCatalog(job.assessment_run_id);
      tables.ai.reset();
      tables.missed.reset();
      await Promise.all([loadCoverage(), tables.ai.load(), tables.missed.load()]);
    } catch (error) {
      resultsError(error.message);
    }
  }

  function history() {
    const run = catalog.runs[0];
    if (!run) return { text: 'No assessment run yet.' };
    return { text: `Last assessment ${fmt.relative(run.created_at)} · ${fmt.count(run.total_observed)} files · ${run.status}`, run: run.id };
  }

  return { mount, load, start, onComplete, renderJob, history, checkEndpoint };
}
