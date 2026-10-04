// AI assessment tab: run form, endpoint check, coverage with real token and
// cost figures, and candidates including the "strong value missed by rules"
// view that answers "what did the rules miss".

import { button, checkbox, clear, el, field, fill, fmt, json, number, on, option, post, select, severity } from './core.js';
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

export function createAiTab(root) {
  const ctx = { status: {}, fail() {}, clearError() {}, collection: null };
  const nodes = {};
  let catalog = { runs: [], scans: [], endpoint: '', model: '' };
  let offset = 0;
  let loadToken = 0;
  let directoriesVisible = false;

  function mount(context) {
    Object.assign(ctx, context);
    build();
  }

  function build() {
    nodes.scan = select([['', 'Latest completed inventory scan']]);
    nodes.prepare = checkbox('Stage ledger and directory context first', true);
    nodes.budget = number('0', 0);
    nodes.budget.classList.add('input--num');
    nodes.budget.title = 'Seconds; 0 means unlimited';
    nodes.maxQuestions = number('200', 1);
    nodes.maxQuestions.classList.add('input--num');
    nodes.gateway = el('p', 'panel__hint', 'Checking the configured decision endpoint…');

    const form = el('div', 'field-grid');
    fill(
      form,
      field('Source scan', nodes.scan),
      field('Time budget (seconds, 0 = unlimited)', nodes.budget),
      field('Max questions per request', nodes.maxQuestions),
    );
    const stage = el('div', 'field', el('span', 'field__label', 'Preparation'), nodes.prepare);

    const run = panel(
      'Run an AI assessment',
      'Probabilistic. Every observed file, with shared directory context.',
      [
        nodes.gateway,
        form,
        stage,
        el(
          'div',
          'btn-row',
          button('Check endpoint', { onClick: () => checkEndpoint() }),
          button('Prepare and assess', { variant: 'primary', onClick: () => start() }),
        ),
      ],
    );
    fill(root, run.node);
    buildCoverage();
    buildCandidates();
  }

  function buildCoverage() {
    nodes.run = select([['', 'Latest assessment run']]);
    const controls = el('div', 'field-grid');
    fill(controls, field('Assessment run', nodes.run));
    controls.append(
      button('Refresh', { size: 'sm', onClick: () => loadCoverage() }),
      button('Per-directory coverage', { size: 'sm', onClick: () => toggleDirectories() }),
    );
    nodes.coverageSummary = el('p', 'panel__hint');
    nodes.coverageStats = el('div', 'stat-row');
    nodes.directories = el('div', 'coverage-directories');
    nodes.directories.hidden = true;
    root.append(
      panel('Coverage', 'Unfinished coverage is always reported.', [
        controls,
        nodes.coverageSummary,
        nodes.coverageStats,
        nodes.directories,
      ]).node,
    );
    on(nodes.run, 'change', () => {
      offset = 0;
      loadCoverage();
      loadResults();
    });
  }

  function buildCandidates() {
    nodes.label = select(PRIORITIES);
    nodes.missed = checkbox('Only strong value missed by rules', false);
    const controls = el('div', 'field-grid');
    fill(controls, field('Priority', nodes.label), el('div', 'field', el('span', 'field__label', 'Comparison'), nodes.missed));
    controls.append(button('Refresh', { size: 'sm', onClick: () => loadResults() }));
    nodes.resultSummary = el('p', 'panel__hint');
    nodes.rows = el('tbody');

    const table = el('table', 'data-grid score-grid');
    fill(
      table,
      el(
        'thead',
        {},
        el(
          'tr',
          {},
          el('th', 'numeric', 'Priority'),
          el('th', undefined, 'File'),
          el('th', undefined, 'Observed location'),
          el('th', undefined, 'Distribution'),
        ),
      ),
      nodes.rows,
    );
    nodes.page = {
      prev: button('Previous', { size: 'sm', onClick: () => step(-PAGE) }),
      next: button('Next', { size: 'sm', onClick: () => step(PAGE) }),
      label: el('span', undefined, 'Page 1'),
    };
    const pager = el('div', 'pagination');
    fill(pager, nodes.page.prev, nodes.page.label, nodes.page.next);

    root.append(
      panel('AI candidates', 'Model priority is metadata-based review value, not confirmed content.', [
        controls,
        nodes.resultSummary,
        el('div', 'grid-shell score-grid-shell', table),
        pager,
      ]).node,
    );
    on(nodes.label, 'change', () => {
      offset = 0;
      loadResults();
    });
    on(nodes.missed.firstChild, 'change', () => {
      offset = 0;
      loadResults();
    });
  }

  function step(delta) {
    offset = Math.max(0, offset + delta);
    loadResults();
  }

  async function start() {
    ctx.clearError();
    try {
      const budget = Number(nodes.budget.value || 0);
      await post('/api/assessment/jobs', {
        scan_id: nodes.scan.value || null,
        prepare: nodes.prepare.firstChild.checked,
        budget_seconds: Number.isFinite(budget) ? budget : 0,
        max_questions: Number(nodes.maxQuestions.value || 200),
      });
      toast('Assessment started');
    } catch (error) {
      ctx.fail(error.message);
    }
  }

  async function checkGateway() {
    try {
      const report = await json('/api/assessment/check');
      if (!report.reachable) {
        nodes.gateway.textContent = `Endpoint unreachable: ${report.error}`;
        return;
      }
      nodes.gateway.textContent = `Endpoint HTTP ${report.http_status} in ${report.latency_ms} ms · model ${report.resolved_model} · answers ${report.returns_answers} · usage ${report.returns_usage}`;
    } catch (error) {
      ctx.fail(error.message);
    }
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
      option('', 'Latest assessment run'),
      ...catalog.runs.map((item) => option(item.id, `${fmt.stamp(item.created_at)} · ${fmt.count(item.total_observed)} files · ${item.status}`)),
    );
    if (catalog.runs.some((item) => item.id === chosen)) nodes.run.value = chosen;
    else nodes.run.value = catalog.runs.length ? catalog.runs[0].id : '';
    nodes.gateway.textContent = `Endpoint: ${catalog.endpoint} · model: ${catalog.model}`;
  }

  async function loadCoverage() {
    if (!nodes.run.value) return;
    const params = new URLSearchParams({ run: nodes.run.value });
    const status = await json(`/api/assessment/status?${params}`);
    nodes.coverageSummary.textContent = `${fmt.count(status.total_observed)} observed · ${fmt.count(status.assessed)} assessed · ${fmt.count(status.in_flight)} in flight · ${fmt.count(status.pending)} pending · ${fmt.count(status.failed)} failed · reconciled ${status.reconciled ? 'yes' : 'NO'}`;
    const batches = status.batches || {};
    const usage = status.usage || {};
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
      entry.append(el('b', undefined, `${label} `), document.createTextNode(value));
      nodes.coverageStats.append(entry);
    }
  }

  async function toggleDirectories() {
    directoriesVisible = !directoriesVisible;
    nodes.directories.hidden = !directoriesVisible;
    if (!directoriesVisible) return;
    clear(nodes.directories);
    fill(nodes.directories, el('span', 'spinner'), el('span', 'field__hint', 'Loading directory coverage…'));
    try {
      const data = await json(`/api/assessment/coverage?run=${nodes.run.value}`);
      clear(nodes.directories);
      if (!data.directories.length) {
        nodes.directories.append(el('p', 'field__hint', 'No directory context stored for this run yet.'));
        return;
      }
      for (const entry of data.directories.slice(0, 500)) {
        const counts = Object.entries(entry.counts).map(([key, value]) => `${key} ${value}`).join(', ');
        nodes.directories.append(el('p', undefined, `${entry.host || ''}\\${entry.share || ''}${entry.directory || ''} — ${counts} (${entry.enumeration || ''})`));
      }
    } catch (error) {
      clear(nodes.directories);
      nodes.directories.append(el('p', 'field__hint', error.message));
    }
  }

  async function loadResults() {
    const token = ++loadToken;
    const params = new URLSearchParams({ limit: String(PAGE), offset: String(offset) });
    if (nodes.run.value) params.set('run', nodes.run.value);
    if (nodes.label.value) params.set('label', nodes.label.value);
    if (nodes.missed.firstChild.checked) params.set('missed', '1');
    try {
      const data = await json(`/api/assessment/files?${params}`);
      if (token !== loadToken) return;
      renderResults(data);
    } catch (error) {
      if (token === loadToken) ctx.fail(error.message);
    }
  }

  function renderResults(data) {
    clear(nodes.rows);
    for (const item of data.items) {
      const row = el('tr', 'rail');
      row.dataset.severity = severity(item.priority).band;
      const priority = el('td', 'numeric');
      const label = item.priority_name ? `${item.priority} ${item.priority_name}` : String(item.priority ?? item.choice ?? '—');
      // The AI chip keeps the AI hue; its weight tracks how strong the call was.
      const chip = el('span', 'score score--ai');
      chip.dataset.strong = String(Number(item.priority) >= 3);
      chip.textContent = label;
      chip.title = label;
      priority.append(chip);
      const link = el('a', 'candidate-link', item.file_name);
      link.href = `/?q=${encodeURIComponent(item.unc_path)}`;
      const distribution = item.distribution
        ? Object.entries(item.distribution).map(([key, value]) => `${key} ${Number(value).toFixed(2)}`).join(', ')
        : '—';
      fill(
        row,
        priority,
        el('td', undefined, link),
        el('td', 'score-path', item.unc_path),
        el('td', 'score-reasons', distribution),
      );
      nodes.rows.append(row);
    }
    if (!data.items.length) {
      const row = el('tr');
      const cell = el('td', 'empty', 'No assessed candidates match this filter.');
      cell.colSpan = 4;
      row.append(cell);
      nodes.rows.append(row);
    }
    const missed = nodes.missed.firstChild.checked;
    nodes.resultSummary.textContent = missed
      ? 'Files the rule engine gave a low score and the model still judged worth strong review. Model priority is review value, not confirmed content.'
      : `Showing ${fmt.count(data.items.length)} assessed file${data.items.length === 1 ? '' : 's'}. Model priority is review value, not confirmed content.`;
    nodes.page.label.textContent = `Page ${Math.floor(offset / PAGE) + 1}`;
    nodes.page.prev.disabled = offset === 0;
    nodes.page.next.disabled = data.items.length < PAGE;
  }

  async function load() {
    if (!ctx.status.assessment_enabled) return;
    try {
      await loadCatalog();
    } catch (error) {
      ctx.fail(error.message);
      return;
    }
    // No run means no assessment database to query. The endpoints resolve a
    // run implicitly and 400 when none exists, so the tab says so rather than
    // firing a request that cannot succeed.
    if (!nodes.run.value) {
      nodes.coverageSummary.textContent = 'No assessment run yet. Start one above.';
      nodes.resultSummary.textContent = 'No assessed candidates yet.';
      clear(nodes.rows);
      return;
    }
    try {
      await Promise.all([loadCoverage(), loadResults()]);
    } catch (error) {
      ctx.fail(error.message);
    }
  }

  async function onComplete(job) {
    ctx.clearError();
    if (!job.assessment_run_id) return;
    try {
      await loadCatalog(job.assessment_run_id);
      await Promise.all([loadCoverage(), loadResults()]);
      toast('Assessment finished');
    } catch (error) {
      ctx.fail(error.message);
    }
  }

  async function checkEndpoint() {
    try {
      const report = await json('/api/assessment/check');
      if (!report.reachable) {
        nodes.gateway.textContent = `Endpoint unreachable: ${report.error}`;
        return;
      }
      nodes.gateway.textContent = `Endpoint HTTP ${report.http_status} in ${report.latency_ms} ms · model ${report.resolved_model} · answers ${report.returns_answers} · usage ${report.returns_usage}`;
    } catch (error) {
      ctx.fail(error.message);
    }
  }

  return { mount, load, onComplete, checkEndpoint };
}