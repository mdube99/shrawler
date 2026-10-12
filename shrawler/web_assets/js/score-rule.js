// Rule ranking engine: the essential inputs on its console card, the
// Configure drawer (TOML editor, rule builder, and the preview workbench),
// and the Rule candidates results with saved and unsaved-preview views.
//
// A preview is a first-class, deliberately transient result. It scores every
// observed file with the editor's rules but keeps only the top 100 in memory;
// nothing is written. It is labelled as unsaved everywhere it appears, it
// survives rule edits so iteration stays fast, and "Save this ranking" turns
// it into a saved run by re-running exactly the request that produced it.

import {
  button,
  checkbox,
  clear,
  el,
  field,
  fill,
  fmt,
  href,
  icon,
  json,
  number,
  on,
  option,
  select,
  setBusy,
  severity,
} from './core.js';
import { dialogShell, openOverlay, panel, toast } from './overlay.js';
import { sendSummary, sendToNemesis } from './actions.js';
import { engineChip } from './scores.js';

const CONTEXT_MODES = [
  ['none', 'No context required'],
  ['named', 'Nearby directory names'],
  ['siblings', 'Sibling filename patterns'],
  ['subtree', 'Label an exact subtree'],
];

const TOP_HITS = 8;

export function createRuleEngine(slots) {
  // The shell's context, held by reference: `job` and `status` are live
  // getters, and copying them would freeze the first reading.
  let ctx = { status: {}, start: async () => null, repaint() {}, showResults() {}, view: () => ({}), job: null, collection: null };
  const nodes = {};
  let catalog = { runs: [], scans: [] };
  let cursors = [null];
  let nextCursor = null;
  let loadToken = 0;
  let mounted = false;

  // The unsaved preview, if any: { jobId, data, result, request, finishedAt, previous }.
  // `request` is the exact body that produced it, known only for previews
  // started from this page; it is what Save re-submits.
  let preview = null;
  let view = 'saved';
  const requests = new Map();
  // The job ID of a save started from the preview, so its completion can
  // retire the preview it promoted.
  let promoting = null;
  let skipReplaceConfirm = false;

  function mount(context) {
    ctx = context;
    if (mounted) return;
    mounted = true;
    buildInputs();
    buildDrawer();
    buildResults();
    // Leaving the page drops an unsaved preview. Ask first, but only for one
    // this page produced and could still save.
    on(window, 'beforeunload', (event) => {
      if (!unsaved()) return;
      event.preventDefault();
      event.returnValue = '';
    });
  }

  const unsaved = () => Boolean(preview?.request) && !promoting;

  /* -- Card inputs ----------------------------------------------------------- */

  function buildInputs() {
    slots.meta.textContent = 'Reads saved metadata only, never file content. Scores guide review; they do not confirm sensitive content.';
    nodes.scan = select([['', 'Latest completed inventory scan']]);
    nodes.builtins = checkbox('Include starter rules', true);
    nodes.rulesHint = el('span', 'field__hint');
    fill(
      slots.inputs,
      field('Source scan', nodes.scan),
      el('div', 'field', el('span', 'field__label', 'Rules'), nodes.builtins, nodes.rulesHint),
    );
    on(nodes.builtins.firstChild, 'change', () => {
      describeRules();
      renderPreviewMeta();
    });
    on(nodes.scan, 'change', renderPreviewMeta);
  }

  /** Summarise the rule set on the card, so the drawer can stay closed. */
  function describeRules() {
    const custom = (nodes.editor.value.match(/^\s*\[\[rules\]\]/gm) || []).length;
    const parts = [nodes.builtins.firstChild.checked ? 'Starter rules' : 'No starter rules'];
    parts.push(custom ? `${custom} custom rule${custom === 1 ? '' : 's'}` : 'no custom rules');
    nodes.rulesHint.textContent = `${parts.join(' + ')} · edit in Configure`;
  }

  function body(wantsPreview) {
    return {
      scan_id: nodes.scan.value || null,
      rules_toml: nodes.editor.value,
      builtins: nodes.builtins.firstChild.checked,
      preview: wantsPreview,
    };
  }

  /** The card's primary action always saves. Previewing lives in the drawer. */
  function start() {
    return ctx.start('/api/triage/jobs', body(false));
  }

  async function startPreview() {
    drawerError('');
    if (preview && unsaved() && !skipReplaceConfirm && !(await confirmReplace())) return;
    const request = body(true);
    await ctx.start('/api/triage/jobs', request, { accepted: (job) => requests.set(job.id, request) });
  }

  /** Replacing an unsaved preview loses it; say so once, with an opt-out. */
  function confirmReplace() {
    return new Promise((resolve) => {
      let settled = false;
      const remember = checkbox("Don't ask again on this page", false);
      const finish = (value) => {
        if (settled) return;
        settled = true;
        if (value && remember.firstChild.checked) skipReplaceConfirm = true;
        handle.close();
        resolve(value);
      };
      const replace = button('Replace preview', { size: 'sm', variant: 'primary', onClick: () => finish(true) });
      replace.setAttribute('autofocus', '');
      const shell = dialogShell({
        title: 'Replace the unsaved preview?',
        body: el(
          'div',
          undefined,
          el('p', undefined, `The current preview (${previewCounts()}) was never saved. A new preview replaces it.`),
          el('p', 'field__hint', 'Use Save this ranking first to keep it as a saved run.'),
          remember,
        ),
        footer: el('div', 'btn-row', button('Keep current preview', { size: 'sm', onClick: () => finish(false) }), replace),
        onClose: () => finish(false),
      });
      const handle = openOverlay(shell.node);
      handle.dialog.addEventListener('close', () => finish(false));
    });
  }

  /* -- Configure drawer ------------------------------------------------------ */

  function buildDrawer() {
    const editor = el('textarea', 'textarea rule-editor');
    editor.rows = 16;
    editor.spellcheck = false;
    editor.value = 'version = 1\n';
    editor.setAttribute('aria-label', 'Custom rules (TOML)');
    nodes.editor = editor;
    on(editor, 'input', () => {
      describeRules();
      renderPreviewMeta();
    });
    describeRules();

    nodes.drawerError = el('div', 'drawer-error');
    const tools = el('div', 'btn-row');
    importExport(editor, tools);
    const editorColumn = el(
      'div',
      'rule-workbench__editor',
      el('div', 'rule-workbench__bar', el('label', 'field__label', 'Custom rules (TOML)'), tools),
      editor,
      el('p', 'field__hint', 'The editor is the source of truth. Starter rules apply on top unless switched off on the card.'),
      ruleBuilder(editor),
    );

    nodes.previewButton = button('Preview ranking (not saved)', { onClick: () => startPreview() });
    nodes.paneState = el('p', 'preview-pane__state');
    nodes.paneMeter = el('div', 'engine-card__meter');
    nodes.paneMeter.append(el('div', 'meter__fill'));
    nodes.paneMeter.hidden = true;
    nodes.paneCounts = el('p', 'preview-pane__counts');
    nodes.paneStale = el('p', 'preview-pane__stale');
    nodes.paneList = el('ol', 'preview-pane__list');
    nodes.paneShow = button('Show the full preview', { size: 'sm', onClick: () => revealPreview() });
    nodes.paneSave = button('Save this ranking', { size: 'sm', variant: 'primary', onClick: () => savePreview() });
    nodes.pane = el(
      'aside',
      'preview-pane',
      el('div', 'preview-pane__head', el('span', 'preview-pane__tag', 'Preview'), el('span', 'field__hint', 'Nothing is written')),
      el('p', 'field__hint', 'Scores every observed file with these rules and keeps the top 100 in memory. Iterate here, then save the version you want.'),
      el('div', 'btn-row', nodes.previewButton),
      nodes.paneState,
      nodes.paneMeter,
      nodes.paneCounts,
      nodes.paneStale,
      nodes.paneList,
      el('div', 'btn-row', nodes.paneShow, nodes.paneSave),
    );

    fill(
      slots.drawer,
      el(
        'header',
        'engine-drawer__head',
        el('h3', 'engine-drawer__title', 'Configure rule ranking'),
        el('span', 'field__hint', 'Edit rules, preview the result, then save it from here or with Run ranking on the card.'),
      ),
      nodes.drawerError,
      el('div', 'rule-workbench', editorColumn, nodes.pane),
    );
    renderPreviewMeta();
  }

  function drawerError(message) {
    fill(nodes.drawerError, message ? el('div', 'banner', icon('alert'), el('span', undefined, message)) : null);
  }

  function importExport(editor, target) {
    const picker = el('input');
    picker.type = 'file';
    picker.accept = '.toml,text/plain';
    picker.hidden = true;
    on(picker, 'change', async () => {
      const file = picker.files?.[0];
      picker.value = '';
      if (!file) return;
      if (file.size > 65536) {
        drawerError('Custom rules must be at most 64 KiB.');
        return;
      }
      editor.value = await file.text();
      drawerError('');
      editor.dispatchEvent(new Event('input'));
    });
    target.append(
      button('Import TOML', { size: 'sm', name: 'upload', onClick: () => picker.click() }),
      button('Export TOML', {
        size: 'sm',
        name: 'download',
        onClick: () => {
          const url = URL.createObjectURL(new Blob([editor.value], { type: 'text/plain' }));
          const link = el('a');
          link.href = url;
          link.download = 'shrawler-rules.toml';
          link.click();
          setTimeout(() => URL.revokeObjectURL(url), 1000);
        },
      }),
      picker,
    );
  }

  /**
   * The rule builder is demoted, not deleted. The TOML textarea is the honest
   * interface; this disclosure is a convenience layer that generates into it.
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
      for (const [, control, , visible] of conditional) control.parentElement.hidden = !visible(mode.value);
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
        drawerError('Choose a filename, extension, or context condition.');
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
      editor.dispatchEvent(new Event('input'));
      drawerError('');
    };

    const details = el('details', 'disclosure rule-drawer');
    fill(
      details,
      el('summary', undefined, 'Rule builder — generate TOML'),
      el('p', 'field__hint', 'Generates into the editor above; edit the result freely.'),
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

  /* -- Preview state --------------------------------------------------------- */

  const positiveOf = (data) => data?.result?.summary?.positive_files ?? data?.data?.summary?.positive_files;

  function previewCounts(target = preview) {
    if (!target) return '';
    const positive = positiveOf(target);
    return [
      `${fmt.count(target.result?.files_scored ?? target.data?.files_scored)} scored`,
      positive === undefined ? null : `${fmt.count(positive)} positive`,
    ]
      .filter(Boolean)
      .join(' · ');
  }

  function setPreview(job, request) {
    const previous = preview && preview.jobId !== job.id ? positiveOf(preview) : preview?.previous;
    preview = {
      jobId: job.id,
      data: job.candidates,
      result: job.result || {},
      request,
      finishedAt: job.finished_at,
      previous,
    };
  }

  /** Have the rules, starter toggle, or scan moved on since the preview ran? */
  function previewStale() {
    if (!preview?.request) return false;
    const now = body(true);
    return now.rules_toml !== preview.request.rules_toml || now.builtins !== preview.request.builtins || now.scan_id !== preview.request.scan_id;
  }

  function renderPreviewMeta() {
    if (!nodes.pane) return;
    const job = ctx.job;
    const live = ctx.view();
    const previewing = live.jobActive && job?.preview;
    nodes.pane.dataset.state = previewing ? 'running' : preview ? 'ready' : 'empty';

    // Mirror the card while a preview runs, so the analyst editing rules sees
    // it progress without scrolling back up.
    nodes.paneMeter.hidden = !previewing;
    if (previewing) {
      nodes.paneState.textContent = [live.label, live.percent, live.timing].filter(Boolean).join(' · ');
      nodes.paneMeter.dataset.indeterminate = String(live.fraction === null);
      nodes.paneMeter.firstChild.style.width = live.fraction === null ? '' : `${Math.floor(live.fraction * 100)}%`;
    } else if (live.jobActive) {
      nodes.paneState.textContent = promoting === job?.id ? 'Saving this preview as a ranking…' : 'A saved ranking is running. Preview again when it finishes.';
    } else if (preview) {
      nodes.paneState.textContent = `Unsaved preview · finished ${fmt.relative(preview.finishedAt)}`;
    } else {
      nodes.paneState.textContent = 'No preview yet.';
    }

    nodes.paneCounts.replaceChildren();
    if (preview) {
      nodes.paneCounts.append(previewCounts());
      const now = positiveOf(preview);
      if (preview.previous !== undefined && now !== undefined) {
        const delta = now - preview.previous;
        const mark = el('span', 'preview-pane__delta', delta === 0 ? ' · same positive count as the previous preview' : ` · ${delta > 0 ? '+' : '−'}${fmt.count(Math.abs(delta))} positive vs previous preview`);
        mark.dataset.direction = delta > 0 ? 'up' : delta < 0 ? 'down' : 'same';
        nodes.paneCounts.append(mark);
      }
    }
    const stale = previewStale();
    nodes.paneStale.hidden = !stale;
    nodes.paneStale.textContent = stale ? 'Rules changed since this preview. Save keeps the rules that produced it; preview again to see your edits.' : '';
    if (!preview?.request && preview) {
      nodes.paneStale.hidden = false;
      nodes.paneStale.textContent = 'This preview was produced before this page loaded, so its rules are unknown here. Preview again to save a version.';
    }

    if (nodes.paneList.dataset.job !== String(preview?.jobId || '')) renderTopHits();
    nodes.paneShow.hidden = !preview;
    nodes.paneSave.hidden = !preview;
    nodes.paneSave.disabled = !canSave(preview?.jobId) || live.jobActive || live.requesting;

    const blocked = live.jobActive || live.requesting || live.state === 'unknown' || live.state === 'unavailable';
    if (previewing) setBusy(nodes.previewButton, true, 'Previewing…');
    else {
      setBusy(nodes.previewButton, false);
      nodes.previewButton.disabled = blocked;
    }
    nodes.previewButton.title = live.jobActive ? 'A rule ranking is already running' : '';
    renderPreviewBanner();
  }

  function renderTopHits() {
    nodes.paneList.dataset.job = String(preview?.jobId || '');
    clear(nodes.paneList);
    for (const item of (preview?.data?.items || []).slice(0, TOP_HITS)) {
      const entry = el('li', 'preview-pane__item', engineChip('rule', item.review_score ?? item.priority, 'Rule priority'), el('span', 'preview-pane__name', item.file_name));
      entry.title = item.unc_path;
      nodes.paneList.append(entry);
    }
    nodes.paneList.hidden = !preview?.data?.items?.length;
  }

  function canSave(jobId) {
    return Boolean(preview?.request) && preview.jobId === jobId && !promoting;
  }

  /** Promote the preview by re-running exactly the request that produced it. */
  function savePreview() {
    if (!preview?.request) return null;
    const request = { ...preview.request, scan_id: preview.result?.scan_id || preview.request.scan_id, preview: false };
    return ctx.start('/api/triage/jobs', request, {
      accepted: (job) => {
        promoting = job.id;
      },
    });
  }

  function discardPreview() {
    preview = null;
    setView('saved');
  }

  function revealPreview() {
    if (!preview) return;
    setView('preview');
    ctx.showResults();
  }

  /** Called by the card's View action: show whatever the last run produced. */
  function revealLatest() {
    const job = ctx.job;
    if (job?.preview && preview?.jobId === job.id) setView('preview');
    else if (job && !job.preview && job.result?.run_id && catalog.runs.some((run) => run.id === job.result.run_id)) {
      nodes.run.value = job.result.run_id;
      setView('saved', { reload: true });
    } else setView('saved');
  }

  /* -- Results --------------------------------------------------------------- */

  function buildResults() {
    nodes.resultsError = el('div', 'results-error');
    nodes.sourceSaved = el('button', undefined, 'Saved ranking');
    nodes.sourcePreview = el('button', undefined, 'Unsaved preview');
    for (const [node, name] of [
      [nodes.sourceSaved, 'saved'],
      [nodes.sourcePreview, 'preview'],
    ]) {
      node.type = 'button';
      on(node, 'click', () => setView(name));
    }
    nodes.source = el('div', 'segmented', nodes.sourceSaved, nodes.sourcePreview);
    nodes.source.setAttribute('aria-label', 'Result source');
    nodes.run = select([['', 'Select a saved ranking']]);
    nodes.runField = field('Saved ranking', nodes.run);
    nodes.category = select([['', 'Highest category score']]);
    nodes.minimum = number('0', 0);
    nodes.minimum.classList.add('input--num');
    nodes.resultSummary = el('p', 'panel__hint');
    nodes.previewBanner = el('div', 'preview-banner');
    nodes.rows = el('tbody');
    nodes.counts = el('details', 'disclosure');
    nodes.collectBar = el('div', 'score-collect-bar');
    nodes.refresh = button('Refresh', { size: 'sm', name: 'refresh', onClick: () => loadResults() });

    const controls = el('div', 'field-grid');
    fill(controls, nodes.runField, field('Category', nodes.category), field('Min score', nodes.minimum), nodes.refresh);

    nodes.page = {
      prev: button('Previous', { size: 'sm', onClick: () => step(-1) }),
      next: button('Next', { size: 'sm', onClick: () => step(1) }),
      label: el('span', undefined, 'Page 1'),
    };
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
    nodes.empty = el('div', 'empty');
    nodes.body = el('div', 'results-body', controls, nodes.resultSummary, nodes.collectBar, el('div', 'grid-shell score-grid-shell', table), pager, nodes.counts);
    nodes.empty.hidden = true;
    buildPreviewBanner();
    const { node } = panel('Rule candidates', 'Metadata evidence only. Nothing here is confirmed content.', [
      nodes.resultsError,
      nodes.source,
      nodes.previewBanner,
      nodes.empty,
      nodes.body,
    ]);
    nodes.panel = node;
    fill(slots.results, node);

    on(nodes.run, 'change', () => {
      resetPages();
      fillCategories();
      loadResults();
    });
    for (const control of [nodes.category, nodes.minimum]) {
      on(control, 'change', () => {
        resetPages();
        loadResults();
      });
    }
    renderCollectBar();
    renderSource();
  }

  function resultsError(message) {
    fill(nodes.resultsError, message ? el('div', 'banner', icon('alert'), el('span', undefined, message)) : null);
  }

  function setView(next, { reload = true } = {}) {
    view = next === 'preview' && preview ? 'preview' : 'saved';
    resetPages();
    fillCategories();
    renderSource();
    if (reload) loadResults();
  }

  function renderSource() {
    const isPreview = view === 'preview';
    nodes.panel.dataset.view = view;
    nodes.source.hidden = !preview;
    nodes.sourceSaved.setAttribute('aria-pressed', String(!isPreview));
    nodes.sourcePreview.setAttribute('aria-pressed', String(isPreview));
    nodes.runField.hidden = isPreview;
    nodes.collectBar.hidden = isPreview;
    nodes.counts.hidden = isPreview || !nodes.counts.childElementCount;
    renderPreviewBanner();
  }

  /** The unsaved view announces itself in tone, label, and counts. */
  function buildPreviewBanner() {
    nodes.bannerCounts = el('strong');
    nodes.bannerText = el('span');
    nodes.bannerSave = button('Save this ranking', { size: 'sm', variant: 'primary', onClick: () => savePreview() });
    fill(
      nodes.previewBanner,
      el('span', 'preview-banner__tag', 'Unsaved preview'),
      el('div', 'preview-banner__text', nodes.bannerCounts, nodes.bannerText),
      el('div', 'btn-row', button('Discard', { size: 'sm', variant: 'ghost', onClick: () => discardPreview() }), nodes.bannerSave),
    );
  }

  // Painted on every poll, so it updates text in place: rebuilding the
  // buttons once a second would steal keyboard focus.
  function renderPreviewBanner() {
    if (!nodes.bannerSave) return;
    const show = view === 'preview' && Boolean(preview);
    nodes.previewBanner.hidden = !show;
    if (!show) return;
    const live = ctx.view();
    nodes.bannerSave.disabled = !canSave(preview.jobId) || live.jobActive || live.requesting;
    nodes.bannerSave.title = preview.request ? '' : 'Produced before this page loaded; its rules are unknown here';
    nodes.bannerCounts.textContent = `${previewCounts()} · top 100 shown`;
    const stale = previewStale() ? ' Rules have changed since; Save keeps the rules that produced this preview.' : '';
    nodes.bannerText.textContent = promoting
      ? 'Saving: re-running these rules as a saved ranking…'
      : `Nothing was written. Explore, collection, and Nemesis cannot use it until it is saved.${stale}`;
  }

  function categories() {
    if (view === 'preview') {
      const names = new Set();
      for (const item of preview?.data?.items || []) for (const name of Object.keys(item.category_scores || {})) names.add(name);
      return [...names].sort();
    }
    return catalog.runs.find((item) => item.id === nodes.run.value)?.categories || [];
  }

  function fillCategories() {
    const chosen = nodes.category.value;
    const names = categories();
    fill(nodes.category, option('', 'Highest category score'), ...names.map((category) => option(category, category)));
    if (names.includes(chosen)) nodes.category.value = chosen;
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
    const completed = catalog.runs.filter((item) => item.status === 'completed');
    fill(
      nodes.run,
      option('', completed.length ? 'Select a saved ranking' : 'No saved ranking yet'),
      ...completed.map((item) => option(item.id, `${fmt.stamp(item.started_at)} · ${fmt.count(item.file_count)} files · scan ${item.scan_id.slice(0, 8)}`)),
    );
    if (completed.some((item) => item.id === chosen)) nodes.run.value = chosen;
    else if (completed.length) nodes.run.value = completed[0].id;
    fillCategories();
    ctx.repaint();
  }

  async function loadResults() {
    const token = ++loadToken;
    resultsError('');
    if (view === 'preview' && preview) return renderResults(previewPage(), true);
    const run = nodes.run.value;
    if (!run) {
      renderEmpty();
      return;
    }
    const minimum = Number(nodes.minimum.value);
    if (!Number.isInteger(minimum) || minimum < 0) {
      resultsError('Minimum score must be a nonnegative integer.');
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
      renderResults(data, false);
    } catch (error) {
      if (token === loadToken) resultsError(error.message);
    }
  }

  /**
   * The same filters, applied in the browser: a preview has no database
   * behind it to query, only the top 100 rows it kept.
   */
  function previewPage() {
    const category = nodes.category.value;
    const minimum = Math.max(0, Number(nodes.minimum.value) || 0);
    const items = (preview.data?.items || [])
      .map((item) => ({ ...item, review_score: category ? (item.category_scores?.[category] ?? null) : (item.review_score ?? item.priority) }))
      .filter((item) => item.review_score !== null && item.review_score >= minimum)
      .sort((a, b) => b.review_score - a.review_score || String(a.file_id).localeCompare(String(b.file_id)));
    return { ...preview.data, items, files_scored: preview.result?.files_scored ?? preview.data?.files_scored, next_cursor: null };
  }

  function renderEmpty() {
    nodes.empty.hidden = false;
    nodes.body.hidden = true;
    ctx.collection?.setSource({ run: '', category: '', minScore: 0 });
    if (!ctx.status.triage_enabled) {
      nodes.source.hidden = true;
      fill(nodes.empty, el('strong', undefined, 'Rule ranking is unavailable'), el('span', undefined, 'This inventory has no ranking engine attached.'));
      return;
    }
    fill(
      nodes.empty,
      el('strong', undefined, 'No saved ranking yet'),
      el('span', undefined, preview ? 'Switch to the unsaved preview above, or save it to rank every file.' : 'Choose Run ranking on the Rule card to rank every observed file.'),
    );
    renderSource();
  }

  function renderResults(data, isPreview) {
    nodes.empty.hidden = true;
    nodes.body.hidden = false;
    clear(nodes.rows);
    for (const item of data.items) nodes.rows.append(candidateRow(item, isPreview));
    if (!data.items.length) {
      const row = el('tr');
      const cell = el('td', 'empty', isPreview ? 'No previewed file matches this filter.' : 'No files match this ranking filter.');
      cell.colSpan = 5;
      row.append(cell);
      nodes.rows.append(row);
    }
    nextCursor = isPreview ? null : data.next_cursor;
    nodes.page.prev.disabled = isPreview || cursors.length === 1;
    nodes.page.next.disabled = !nextCursor;
    nodes.page.label.textContent = isPreview ? 'Preview · top 100 only' : `Page ${cursors.length}`;
    // The collection queue resolves manifests against a saved ranking, so it
    // only ever hears about one. A preview has nothing to resolve against.
    ctx.collection?.setSource(
      isPreview
        ? { run: '', category: '', minScore: 0 }
        : { run: nodes.run.value, category: nodes.category.value, minScore: Number(nodes.minimum.value) || 0 },
    );
    const positive = data.summary?.positive_files;
    nodes.resultSummary.textContent = isPreview
      ? `Showing ${fmt.count(data.items.length)} of the top 100 previewed files${nodes.category.value ? ` with a ${nodes.category.value} score` : ''}.`
      : `Saved ranking · ${fmt.count(data.files_scored)} observed files scored${positive !== undefined ? ` · ${fmt.count(positive)} with positive priority` : ''}`;
    if (isPreview) clear(nodes.counts);
    else renderCounts(data.summary);
    renderSource();
  }

  function candidateRow(item, isPreview) {
    const positive = item.signals.filter((signal) => signal.credited_points > 0).map((signal) => signal.description);
    const fallback = item.signals.filter((signal) => signal.category === 'extension-fallback').map((signal) => signal.description);
    const row = el('tr', 'rail');
    row.dataset.severity = severity(item.review_score).band;
    const score = el('td', 'numeric');
    score.append(engineChip('rule', item.review_score, 'Rule priority'));
    const link = el('a', 'candidate-link', item.file_name);
    link.href = href(`/?q=${encodeURIComponent(item.unc_path)}`);
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
        ctx.collection?.toggle(item.file_id, box.checked, item);
        renderCollectBar();
      });
      collect.append(box, el('span', undefined, 'Nemesis'));
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
    if (!nodes.collectBar) return;
    const count = ctx.collection?.size || 0;
    const hint = el('span', 'panel__hint', `${fmt.count(count)} candidate${count === 1 ? '' : 's'} selected for Nemesis`);
    const send = button('Send selected to Nemesis', { size: 'sm', onClick: () => sendSelection(send, hint) });
    send.disabled = count === 0 || ctx.status.nemesis_enabled === false;
    if (ctx.status.nemesis_enabled === false) send.title = 'Configure Nemesis URL, authentication, and project first';
    fill(nodes.collectBar, hint, send);
  }

  /**
   * Send the selected candidates straight to Nemesis. No manifest is created:
   * the direct delivery path retrieves each file and uploads it in one request,
   * and its persistent spool holds failures for retry.
   */
  async function sendSelection(trigger, hint) {
    const rows = ctx.collection?.items() || [];
    if (!rows.length) return;
    trigger.disabled = true;
    try {
      const summary = await sendToNemesis(rows, {
        status: ctx.status,
        confirmFirst: rows.length > 1,
        onProgress: (message) => {
          hint.textContent = message;
        },
      });
      if (summary) toast(sendSummary(summary), summary.failed || summary.unknown ? 'error' : 'ok');
    } catch (error) {
      toast(error.message, 'error');
    } finally {
      renderCollectBar();
    }
  }

  function renderCounts(summary) {
    clear(nodes.counts);
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
    const content = el('div');
    const handle = openOverlay(
      dialogShell({
        title: item.file_name,
        subtitle: isPreview ? `Unsaved preview · ${item.unc_path}` : item.unc_path,
        body: content,
        onClose: () => handle.close(),
      }).node,
    );
    fill(content, el('span', 'spinner'), el('span', 'field__hint', 'Loading explanation…'));
    try {
      const params = new URLSearchParams({ run: nodes.run.value, file_id: item.file_id });
      const detail = isPreview ? item : await json(`/api/triage/explain?${params}`);
      clear(content);
      content.append(el('p', 'panel__hint', `Overall priority ${detail.priority}. Metadata evidence only.`));
      content.append(el('pre', 'code-block', JSON.stringify(detail.category_scores, null, 2)));
      if (!detail.signals.length) content.append(el('p', 'panel__hint', 'No ranking rule matched this file.'));
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
        content.append(section);
      }
      if (detail.rule_diagnostics) {
        const missed = detail.rule_diagnostics.filter((rule) => !rule.matched);
        const details = el('details', 'disclosure');
        details.append(el('summary', undefined, 'Why other rules did not match'));
        details.append(el('pre', 'code-block', missed.map((rule) => `${rule.rule_id}: ${rule.failed_conditions.join(', ')}`).join('\n') || 'Every rule matched.'));
        content.append(details);
      }
    } catch (error) {
      clear(content);
      content.append(el('p', 'panel__hint', error.message));
    }
  }

  /* -- Lifecycle ------------------------------------------------------------- */

  async function load() {
    if (!ctx.status.triage_enabled) {
      renderEmpty();
      return;
    }
    try {
      await refreshCatalog();
    } catch (error) {
      resultsError(error.message);
      return;
    }
    await loadResults();
  }

  async function onComplete(job) {
    if (job.preview) {
      if (!job.candidates) return;
      setPreview(job, requests.get(job.id) || null);
      requests.delete(job.id);
      setView('preview');
      toast(`Preview ready · ${previewCounts()} · not saved`, 'info', { action: { label: 'View', onClick: () => revealPreview() } });
      return;
    }
    const promoted = promoting === job.id;
    if (promoted) {
      preview = null;
      promoting = null;
    }
    resetPages();
    try {
      await refreshCatalog(job.result?.run_id);
    } catch (error) {
      resultsError(error.message);
    }
    setView('saved');
    const positive = job.result?.summary?.positive_files;
    toast(
      `${promoted ? 'Preview saved as a ranking' : 'Ranking saved'} · ${fmt.count(job.result?.files_scored)} scored${positive === undefined ? '' : ` · ${fmt.count(positive)} positive`}`,
      'ok',
      { action: { label: 'View candidates', onClick: () => ctx.showResults() } },
    );
  }

  /** A preview left by an earlier page is still useful: show it, unsaveable. */
  function adopt(job) {
    if (job.preview && job.status === 'completed' && job.candidates && !preview) {
      setPreview(job, null);
      renderSource();
      renderPreviewMeta();
    }
  }

  /** Mirror the shared job model into the drawer's preview pane and banner. */
  function renderJob(job) {
    if (promoting && job?.id === promoting && job.status !== 'running' && job.status !== 'completed') promoting = null;
    renderPreviewMeta();
  }

  function history() {
    const run = catalog.runs.find((item) => item.status === 'completed');
    if (!run) return { text: preview ? `Unsaved preview only · ${previewCounts()} · nothing saved yet` : 'No saved ranking yet.' };
    return { text: `Last saved ranking ${fmt.relative(run.started_at)} · ${fmt.count(run.file_count)} files`, run: run.id };
  }

  return { mount, load, start, onComplete, adopt, renderJob, renderCollectBar, history, canSave, savePreview, revealLatest };
}
