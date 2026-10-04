// Rule ranking tab: run form, demoted rule builder, candidates, match counts,
// and the per-file scoring explanation.

import {
  button,
  checkbox,
  clear,
  el,
  field,
  fill,
  fmt,
  json,
  number,
  on,
  option,
  post,
  select,
  severity,
} from './core.js';
import { dialogShell, openOverlay, panel, toast } from './overlay.js';
import { engineChip } from './scores.js';

const CONTEXT_MODES = [
  ['none', 'No context required'],
  ['named', 'Nearby directory names'],
  ['siblings', 'Sibling filename patterns'],
  ['subtree', 'Label an exact subtree'],
];

export function createRuleTab(root) {
  const ctx = { status: {}, fail() {}, clearError() {}, collection: null };
  const nodes = {};
  let catalog = { runs: [], scans: [] };
  let cursors = [null];
  let nextCursor = null;
  let preview = null;
  let loadToken = 0;

  /* -- Run form ------------------------------------------------------------ */

  function mount(context) {
    Object.assign(ctx, context);
    buildRunPanel();
    buildCandidatesPanel();
  }

  function buildRunPanel() {
    nodes.scan = select([['', 'Latest completed inventory scan']]);
    nodes.builtins = checkbox('Include starter rules', true);
    const editor = el('textarea', 'textarea');
    editor.rows = 9;
    editor.spellcheck = false;
    editor.value = 'version = 1\n';
    editor.setAttribute('aria-label', 'Custom rules (TOML)');
    nodes.editor = editor;

    nodes.summary = el('p', 'panel__hint');
    const controls = el('div', 'field-grid');
    fill(controls, field('Source scan', nodes.scan), el('div', 'field', el('span', 'field__label', 'Starter rules'), nodes.builtins));

    const { node, body } = panel(
      'Run a rule ranking',
      'Deterministic. Reads saved metadata only, never file content.',
      [
        controls,
        el('p', 'panel__hint', 'Scores guide review; they do not confirm sensitive content.'),
        ruleBuilder(editor),
        el('label', 'field__label', 'Custom rules (TOML)'),
        editor,
        importExport(editor),
        el(
          'div',
          'btn-row',
          button('Preview ranking', { onClick: () => start(true) }),
          button('Run and save ranking', { variant: 'primary', onClick: () => start(false) }),
        ),
        nodes.summary,
      ],
    );
    fill(root, node);
  }

  function importExport(editor) {
    const picker = el('input');
    picker.type = 'file';
    picker.accept = '.toml,text/plain';
    picker.hidden = true;
    on(picker, 'change', async () => {
      const file = picker.files?.[0];
      if (!file) return;
      if (file.size > 65536) {
        ctx.fail('Custom rules must be at most 64 KiB.');
        return;
      }
      editor.value = await file.text();
    });
    const wrap = el('div', 'btn-row');
    wrap.append(
      button('Export TOML', {
        size: 'sm',
        onClick: () => {
          const url = URL.createObjectURL(new Blob([editor.value], { type: 'text/plain' }));
          const link = el('a');
          link.href = url;
          link.download = 'shrawler-rules.toml';
          link.click();
          setTimeout(() => URL.revokeObjectURL(url), 1000);
        },
      }),
      button('Import TOML', { size: 'sm', onClick: () => picker.click() }),
      picker,
    );
    return wrap;
  }

  /**
   * The rule builder is demoted, not deleted. The TOML textarea is the honest
   * interface; this drawer is a convenience layer that generates into it.
   */
  function ruleBuilder(editor) {
    const values = {};
    const add = (label, control, id, hint) => {
      values[id] = control;
      control.id = id;
      return field(label, control, hint);
    };
    const mode = select(CONTEXT_MODES);
    const grid = el('div', 'field-grid');
    fill(
      grid,
      add('Rule ID', el('input', 'input'), 'b-id'),
      add('Category', el('input', 'input'), 'b-category'),
      add('Signal group', el('input', 'input'), 'b-group'),
      add('Weight', number('15', 0), 'b-points'),
      add('Filename contains any', placeholder('cred, pass, ssn'), 'b-fragments'),
      add('Extensions (optional)', placeholder('.txt, .xlsx, .config'), 'b-extensions'),
      add('Directory context', mode, 'b-mode'),
    );
    values['b-id'].value = 'engagement.filename';
    values['b-category'].value = 'credentials';
    values['b-group'].value = 'credential-name';

    // Only the fields the chosen context mode uses stay visible.
    const conditional = [
      ['Levels below context', number('1', 0), 'b-depth', (value) => value !== 'none'],
      ['Directory names, exact', placeholder('deployments, release'), 'b-names', (value) => value === 'named'],
      ['Sibling filename globs', placeholder('web.config, deploy.ps1'), 'b-siblings', (value) => value === 'siblings'],
      ['Distinct patterns required', number('2', 1), 'b-minimum', (value) => value === 'siblings'],
      ['Recorded host', placeholder('fileserver'), 'b-host', (value) => value === 'subtree'],
      ['Share', placeholder('Shared'), 'b-share', (value) => value === 'subtree'],
      ['Subtree path in share', placeholder('/Orion'), 'b-path', (value) => value === 'subtree'],
    ];
    const applyMode = () => {
      for (const [label, control, id, visible] of conditional) control.parentElement.hidden = !visible(mode.value);
    };
    for (const [label, control, id] of conditional) grid.append(add(label, control, id));
    on(mode, 'change', applyMode);
    applyMode();

    const list = (id) =>
      values[id].value
        .split(',')
        .map((value) => value.trim())
        .filter(Boolean);
    const quote = JSON.stringify;
    const array = (items) => `[${items.map(quote).join(', ')}]`;

    const generate = () => {
      const id = values['b-id'].value.trim();
      const chosen = list('b-fragments');
      const extensions = list('b-extensions');
      if (!chosen.length && !extensions.length && mode.value === 'none') {
        ctx.fail('Choose a filename, extension, or context condition.');
        return;
      }
      let text = '\n';
      const tag = `${id}.context`;
      if (mode.value !== 'none') {
        text += `[[contexts]]\nid = ${quote(tag)}\ntag = ${quote(tag)}\napply_to_descendants = ${Number(values['b-depth'].value)}\n`;
        if (mode.value === 'named') text += `directory_name_any = ${array(list('b-names'))}\n`;
        if (mode.value === 'siblings') {
          text += `sibling_name_any = ${array(list('b-siblings'))}\nminimum_distinct_patterns = ${Number(values['b-minimum'].value)}\n`;
        }
        if (mode.value === 'subtree') {
          text += `${['b-host', 'b-share', 'b-path'].map((key) => `${key.slice(2)} = ${quote(values[key].value.trim())}`).join('\n')}\n`;
        }
      }
      text += `\n[[rules]]\nid = ${quote(id)}\ndescription = ${quote(`Custom review rule: ${id}`)}\n`;
      text += `category = ${quote(values['b-category'].value.trim())}\nsignal_group = ${quote(values['b-group'].value.trim())}\n`;
      text += `points = ${Number(values['b-points'].value)}\n[rules.when]\n`;
      if (chosen.length) text += `filename_contains_any = ${array(chosen)}\n`;
      if (extensions.length) text += `extension_any = ${array(extensions)}\n`;
      if (mode.value !== 'none') text += `context_any = [${quote(tag)}]\n`;
      editor.value += text;
      editor.focus();
      ctx.clearError();
    };

    const details = el('details', 'disclosure rule-drawer');
    fill(
      details,
      el('summary', undefined, 'Rule builder — generate TOML'),
      el('p', 'field__hint', 'The editor below is the source of truth. This form generates into it; edit the result freely.'),
      grid,
      button('Add to rule editor', { size: 'sm', variant: 'primary', onClick: generate }),
    );
    return details;
  }

  function placeholder(text) {
    const node = el('input', 'input');
    node.placeholder = text;
    return node;
  }

  async function start(wantsPreview) {
    ctx.clearError();
    try {
      await post('/api/triage/jobs', {
        scan_id: nodes.scan.value || null,
        rules_toml: nodes.editor.value,
        builtins: nodes.builtins.firstChild.checked,
        preview: wantsPreview,
      });
      nodes.summary.textContent = wantsPreview ? 'Starting preview…' : 'Ranking and saving…';
    } catch (error) {
      ctx.fail(error.message);
    }
  }

  /* -- Candidates ---------------------------------------------------------- */

  function buildCandidatesPanel() {
    nodes.run = select([['', 'Select a saved ranking']]);
    nodes.category = select([['', 'Highest category score']]);
    nodes.minimum = number('0', 0);
    nodes.minimum.classList.add('input--num');
    nodes.resultSummary = el('p', 'panel__hint');
    nodes.rows = el('tbody');
    nodes.counts = el('details', 'disclosure');
    nodes.collectBar = el('div', 'score-collect-bar');

    const controls = el('div', 'field-grid');
    fill(controls, field('Saved ranking', nodes.run), field('Category', nodes.category), field('Min score', nodes.minimum));
    controls.append(button('Refresh', { size: 'sm', onClick: () => loadResults() }));

    nodes.page = { prev: button('Previous', { size: 'sm', onClick: () => step(-1) }), next: button('Next', { size: 'sm', onClick: () => step(1) }), label: el('span', undefined, 'Page 1') };
    const pager = el('div', 'pagination');
    fill(pager, nodes.page.prev, nodes.page.label, nodes.page.next);

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
          el('th', undefined, 'Reasons'),
          el('th', undefined, 'Review'),
        ),
      ),
      nodes.rows,
    );
    const { node } = panel('Review candidates', 'Metadata evidence only. Nothing here is confirmed content.', [
      controls,
      nodes.resultSummary,
      nodes.collectBar,
      el('div', 'grid-shell score-grid-shell', table),
      pager,
      nodes.counts,
    ]);
    root.append(node);

    on(nodes.run, 'change', () => {
      if (nodes.run.value === '__preview') return;
      preview = null;
      nodes.run.querySelector('option[value="__preview"]')?.remove();
      resetPages();
      fillCategories();
      loadResults();
    });
    for (const control of [nodes.category, nodes.minimum]) {
      on(control, 'change', () => {
        preview = null;
        resetPages();
        loadResults();
      });
    }
    renderCollectBar();
  }

  function fillCategories() {
    const run = catalog.runs.find((item) => item.id === nodes.run.value);
    fill(nodes.category, option('', 'Highest category score'), ...(run?.categories || []).map((category) => option(category, category)));
  }

  function resetPages() {
    cursors = [null];
    nextCursor = null;
  }

  function step(direction) {
    if (direction < 0 && cursors.length === 1) return;
    if (direction > 0 && !nextCursor) return;
    if (direction < 0) cursors.pop();
    else cursors.push(nextCursor);
    loadResults();
  }

  async function refreshCatalog(preferred) {
    catalog = await json('/api/triage/catalog');
    const scan = nodes.scan.value;
    fill(
      nodes.scan,
      option('', 'Latest completed inventory scan'),
      ...catalog.scans.map((item) =>
        option(item.id, `${item.short_id} · ${item.status} · ${fmt.count(item.file_count)} files · ${fmt.stamp(item.started_at_utc)}`),
      ),
    );
    if (catalog.scans.some((item) => item.id === scan)) nodes.scan.value = scan;
    const chosen = preferred || nodes.run.value;
    fill(
      nodes.run,
      option('', 'Select a saved ranking'),
      ...catalog.runs
        .filter((item) => item.status === 'completed')
        .map((item) => option(item.id, `${fmt.stamp(item.started_at)} · ${fmt.count(item.file_count)} files · scan ${item.scan_id.slice(0, 8)}`)),
    );
    if (catalog.runs.some((item) => item.id === chosen && item.status === 'completed')) nodes.run.value = chosen;
    else if (nodes.run.options.length > 1) nodes.run.value = nodes.run.options[1].value;
    fillCategories();
  }

  async function loadResults() {
    if (preview) return renderResults(preview, true);
    const run = nodes.run.value;
    if (!run) return;
    const token = ++loadToken;
    const minimum = Number(nodes.minimum.value);
    if (!Number.isInteger(minimum) || minimum < 0) {
      ctx.fail('Minimum score must be a nonnegative integer.');
      return;
    }
    const params = new URLSearchParams({ run, category: nodes.category.value, min_score: String(minimum) });
    const cursor = cursors[cursors.length - 1];
    if (cursor) {
      params.set('after_score', String(cursor[0]));
      params.set('after_id', cursor[1]);
    }
    try {
      const data = await json(`/api/triage/files?${params}`);
      if (token !== loadToken) return;
      ctx.clearError();
      renderResults(data, false);
    } catch (error) {
      if (token === loadToken) ctx.fail(error.message);
    }
  }

  function renderResults(data, isPreview) {
    clear(nodes.rows);
    for (const item of data.items) nodes.rows.append(candidateRow(item, isPreview));
    if (!data.items.length) {
      const row = el('tr');
      const cell = el('td', 'empty', 'No files match this ranking filter.');
      cell.colSpan = 5;
      row.append(cell);
      nodes.rows.append(row);
    }
    nodes.category.disabled = isPreview;
    nodes.minimum.disabled = isPreview;
    nextCursor = isPreview ? null : data.next_cursor;
    nodes.page.prev.disabled = isPreview || cursors.length === 1;
    nodes.page.next.disabled = !nextCursor;
    nodes.page.label.textContent = isPreview ? 'Preview · first 100' : `Page ${cursors.length}`;
    // The collection queue resolves manifests against this saved ranking, so
    // tell it which query the visible candidates came from.
    ctx.collection?.setSource({
      run: nodes.run.value,
      category: nodes.category.value,
      minScore: Number(nodes.minimum.value) || 0,
    });
    nodes.resultSummary.textContent = `${isPreview ? 'Unsaved preview' : 'Saved ranking'} · ${fmt.count(data.files_scored)} observed files scored${
      data.summary?.positive_files !== undefined ? ` · ${fmt.count(data.summary.positive_files)} with positive priority` : ''
    }`;
    renderCounts(data.summary);
  }

  function candidateRow(item, isPreview) {
    const positive = item.signals.filter((signal) => signal.credited_points > 0).map((signal) => signal.description);
    const fallback = item.signals.filter((signal) => signal.category === 'extension-fallback').map((signal) => signal.description);
    const row = el('tr', 'rail');
    row.dataset.severity = severity(item.review_score).band;
    const score = el('td', 'numeric');
    score.append(engineChip('rule', item.review_score, 'Rule priority'));
    const link = el('a', 'candidate-link', item.file_name);
    link.href = `/?q=${encodeURIComponent(item.unc_path)}`;
    const file = el('td', undefined, link);
    const review = el('td');
    const actions = el('div', 'btn-row');
    actions.append(button('Explain', { size: 'sm', onClick: () => showExplanation(item, isPreview) }));
    if (!isPreview) {
      const collect = el('label', 'checkbox');
      const box = el('input');
      box.type = 'checkbox';
      box.checked = ctx.collection?.has(item.file_id) || false;
      on(box, 'change', () => {
        ctx.collection?.toggle(item.file_id, box.checked);
        renderCollectBar();
      });
      collect.append(box, el('span', undefined, 'Queue'));
      actions.append(collect);
    }
    review.append(actions);
    fill(
      row,
      score,
      file,
      el('td', 'score-path', item.unc_path),
      el('td', 'score-reasons', (positive.length ? positive : fallback).join('; ') || 'No supporting evidence'),
      review,
    );
    return row;
  }

  function renderCollectBar() {
    const count = ctx.collection?.size || 0;
    fill(
      nodes.collectBar,
      el('span', 'panel__hint', `${fmt.count(count)} candidate${count === 1 ? '' : 's'} selected for collection`),
      button('Save selected to queue', { size: 'sm', onClick: () => ctx.collection?.createFromSelection() }),
    );
    nodes.collectBar.lastChild.disabled = count === 0;
  }

  function renderCounts(summary) {
    clear(nodes.counts);
    nodes.counts.hidden = !summary?.rule_matches;
    if (!summary?.rule_matches) return;
    nodes.counts.append(el('summary', undefined, 'Rule match counts and directory examples'));
    const list = el('ul', 'score-list');
    for (const [id, count] of Object.entries(summary.rule_matches).sort()) list.append(el('li', undefined, `${id}: ${fmt.count(count)} matches`));
    nodes.counts.append(list, el('p', 'panel__hint', 'Examples from up to 20 different observed directories (not a statistical sample):'));
    const samples = el('ul', 'score-list');
    for (const item of summary.samples || []) samples.append(el('li', undefined, `${item.priority} · ${item.unc_path}`));
    nodes.counts.append(samples);
  }

  async function showExplanation(item, isPreview) {
    const body = el('div');
    const handle = openOverlay(
      dialogShell({ title: item.file_name, subtitle: item.unc_path, body, onClose: () => handle.close() }).node,
    );
    fill(body, el('span', 'spinner'), el('span', 'field__hint', 'Loading explanation…'));
    try {
      const params = new URLSearchParams({ run: nodes.run.value, file_id: item.file_id });
      const detail = isPreview ? item : await json(`/api/triage/explain?${params}`);
      clear(body);
      body.append(el('p', 'panel__hint', `Overall priority ${detail.priority}. Metadata evidence only.`));
      body.append(el('pre', 'code-block', JSON.stringify(detail.category_scores, null, 2)));
      if (!detail.signals.length) body.append(el('p', 'panel__hint', 'No ranking rule matched this file.'));
      for (const signal of detail.signals) {
        const section = el('section', 'explain-section');
        section.append(el('strong', undefined, `+${signal.credited_points} · ${signal.description}`));
        section.append(
          el(
            'p',
            'panel__hint',
            `${signal.category} / ${signal.signal_group} · ${signal.rule_id}${signal.capped_by_rule ? ` · capped by ${signal.capped_by_rule}` : ''}`,
          ),
        );
        section.append(el('pre', 'code-block', JSON.stringify(signal.evidence, null, 2)));
        body.append(section);
      }
      if (detail.rule_diagnostics) {
        const missed = detail.rule_diagnostics.filter((rule) => !rule.matched);
        const details = el('details', 'disclosure');
        details.append(el('summary', undefined, 'Why other rules did not match'));
        details.append(el('pre', 'code-block', missed.map((rule) => `${rule.rule_id}: ${rule.failed_conditions.join(', ')}`).join('\n') || 'Every rule matched.'));
        body.append(details);
      }
    } catch (error) {
      clear(body);
      body.append(el('p', 'panel__hint', error.message));
    }
  }

  async function load() {
    if (!ctx.status.triage_enabled) return;
    try {
      await refreshCatalog();
      await loadResults();
    } catch (error) {
      ctx.fail(error.message);
    }
  }

  async function onComplete(job) {
    ctx.clearError();
    nodes.summary.textContent = job.preview
      ? 'Preview finished; no ranking saved.'
      : `Ranking saved. Source scan status: ${job.result.scan_status}.`;
    if (job.preview && job.candidates) {
      preview = job.candidates;
      if (!nodes.run.querySelector('option[value="__preview"]')) nodes.run.append(option('__preview', 'Unsaved preview (first 100)'));
      nodes.run.value = '__preview';
      fillCategories();
      renderResults(preview, true);
    } else if (!job.preview) {
      preview = null;
      resetPages();
      await refreshCatalog(job.result.run_id);
      await loadResults();
    }
    toast(job.preview ? 'Preview ranking ready' : 'Ranking saved');
  }

  return { mount, load, onComplete, renderCollectBar };
}