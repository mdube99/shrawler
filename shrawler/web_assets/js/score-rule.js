// Rule ranking engine: the essential inputs on its console card, the
// Configure drawer (TOML editor, rule builder, and the preview workbench),
// and the Rule candidates results with saved and unsaved-preview views.
//
// A preview is a first-class, deliberately transient result kept by the
// server: it scores every observed file with the editor's rules into its own
// database and writes nothing to the saved rankings. It survives reloads
// (until it is saved, discarded, replaced by a newer preview, or the server
// stops), reads through the same paging, filters, and explanations as a saved
// run, compares against a saved run, and saves by promotion: the saved run
// carries exactly the previewed scores, nothing is re-run.

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
  number,
  on,
  option,
  select,
  setBusy,
  severity,
  token,
} from './core.js';
import { confirm, dialogShell, openOverlay, panel, toast } from './overlay.js';
import { sendSummary, sendToNemesis } from './actions.js';
import { engineChip } from './scores.js';

const CONTEXT_MODES = [
  ['none', 'No context required'],
  ['named', 'Nearby directory names'],
  ['siblings', 'Sibling filename patterns'],
  ['subtree', 'Label an exact subtree'],
];

const PAGE = 100;
const TOP_HITS = 8;
// Editor change detection runs on every keystroke; the status it drives does
// not need to repaint faster than this.
const EDIT_DEBOUNCE_MS = 200;
// A compare filter the server cannot apply (raised, lowered, newly or no
// longer positive, a minimum score) is applied here, reading forward through
// changed files until a page is full or this many server pages were read.
const COMPARE_SCAN_PAGES = 20;

// Compare filters. `server` is what `changed` the request needs; `match` is
// the client-side test on top of it.
const COMPARE_FILTERS = [
  ['all', 'All files', '0', () => true],
  ['changed', 'changed', '1', (item) => item.delta !== 0],
  ['raised', 'raised', '1', (item) => item.delta > 0],
  ['lowered', 'lowered', '1', (item) => item.delta < 0],
  ['newly_positive', 'newly positive', '1', (item) => (item.preview_priority ?? 0) > 0 && (item.base_priority ?? 0) <= 0],
  ['no_longer_positive', 'no longer positive', '1', (item) => (item.base_priority ?? 0) > 0 && (item.preview_priority ?? 0) <= 0],
];

const GONE = 'The preview is no longer available: it was saved, discarded, or replaced elsewhere, or the server restarted.';
const MAC = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || '');
const SHORTCUT = MAC ? '⌘↵' : 'Ctrl+↵';

/**
 * JSON request that keeps the HTTP status and error code. The preview
 * endpoints answer 410 `preview_gone`, which has to be told apart from an
 * ordinary failure, and the shared helper only keeps the message.
 */
async function request(path, { method = 'GET', body } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    headers['X-Shrawler-Request'] = '1';
  }
  const response = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  let data = null;
  try {
    data = await response.json();
  } catch {
    /* Non-JSON body: the status carries the meaning. */
  }
  if (!response.ok) {
    const error = new Error(data?.error || `Request failed (${response.status})`);
    error.status = response.status;
    error.code = data?.code || '';
    throw error;
  }
  return data;
}

const gone = (error) => error?.status === 410 || error?.code === 'preview_gone';

/** Local wall-clock time, for "rules as of 14:05". */
function clock(value) {
  const date = new Date(value || '');
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

/** IDs of the custom rules in a TOML rule set, in file order. */
function customRuleIds(text) {
  const ids = [];
  let inRule = false;
  for (const line of String(text || '').split('\n')) {
    const trimmed = line.trim();
    if (trimmed.startsWith('[')) {
      inRule = trimmed.replace(/\s+/g, '') === '[[rules]]';
      continue;
    }
    const match = inRule && trimmed.match(/^id\s*=\s*(?:"((?:[^"\\]|\\.)*)"|'([^']*)')/);
    if (match) {
      ids.push(match[1] ?? match[2]);
      inRule = false;
    }
  }
  return ids;
}

export function createRuleEngine(slots) {
  // The shell's context, held by reference: `job` and `status` are live
  // getters, and copying them would freeze the first reading.
  let ctx = { status: {}, start: async () => null, repaint() {}, showResults() {}, selectTab() {}, view: () => ({}), job: null, collection: null };
  const nodes = {};
  let catalog = { runs: [], scans: [] };
  let cursors = [null];
  let nextCursor = null;
  let loadToken = 0;
  let mounted = false;

  // The server's retained preview, as GET /api/triage/preview returns it, or
  // null. It is the single source of truth; nothing is cached beside it.
  let preview = null;
  // Positive-file count of the preview this one replaced, for the delta line.
  let previousPositive;
  let goneNote = '';
  // True once the server has answered GET /api/triage/preview at least once,
  // so "no preview" is a fact and not merely "not asked yet".
  let previewKnown = false;
  // Previews that answered 410. One is never adopted again, so a reader that
  // races a replacement cannot bounce between "gone" and "back" forever.
  const goneIds = new Set();
  let view = 'saved';
  // While a save runs, the preview it is promoting.
  let saving = null;
  let skipReplaceConfirm = false;
  let editTimer = 0;
  const compare = { base: '', forPreview: null, order: 'preview', filter: 'all', summary: null, loading: false, scanned: 0 };

  function mount(context) {
    ctx = context;
    if (mounted) return;
    mounted = true;
    buildInputs();
    buildDrawer();
    buildResults();
  }

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
      edited();
    });
    on(nodes.scan, 'change', edited);
  }

  /** Summarise the rule set on the card, so the drawer can stay closed. */
  function describeRules() {
    const custom = customRuleIds(nodes.editor.value).length;
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
    const live = ctx.view();
    if (live.jobActive || live.requesting || live.state === 'unknown' || live.state === 'unavailable') return;
    if (preview && !skipReplaceConfirm && !(await confirmReplace())) return;
    await ctx.start('/api/triage/jobs', body(true));
  }

  /** Replacing a preview loses it; say so once, with an opt-out. */
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
          el('p', undefined, `The current preview (${previewCounts()}, rules as of ${clock(preview.created_at)}) was never saved. A new preview replaces it when it finishes.`),
          el('p', 'field__hint', 'Use Save first to keep it as a saved ranking.'),
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
    editor.setAttribute('aria-keyshortcuts', MAC ? 'Meta+Enter' : 'Control+Enter');
    nodes.editor = editor;
    on(editor, 'input', () => {
      describeRules();
      edited();
    });
    on(editor, 'keydown', (event) => {
      if (event.key === 'Enter' && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        startPreview();
      }
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
      el('p', 'field__hint', `The editor is the source of truth. Starter rules apply on top unless switched off on the card. ${SHORTCUT} previews.`),
      ruleBuilder(editor),
    );

    nodes.previewButton = button('Preview ranking (not saved)', { title: `Preview with the editor's rules (${SHORTCUT})`, onClick: () => startPreview() });
    nodes.paneState = el('p', 'preview-pane__state');
    nodes.paneMeter = el('div', 'engine-card__meter');
    nodes.paneMeter.append(el('div', 'meter__fill'));
    nodes.paneMeter.hidden = true;
    nodes.paneCounts = el('p', 'preview-pane__counts');
    nodes.paneNotes = el('ul', 'preview-pane__notes');
    nodes.paneList = el('ol', 'preview-pane__list');
    nodes.paneShow = button('Show the full preview', { size: 'sm', onClick: () => revealPreview() });
    nodes.paneSave = button('Save preview', { size: 'sm', variant: 'primary', onClick: () => savePreview() });
    nodes.pane = el(
      'aside',
      'preview-pane',
      el('div', 'preview-pane__head', el('span', 'preview-pane__tag', 'Preview'), el('span', 'field__hint', 'Nothing is written to saved rankings')),
      el('p', 'field__hint', 'Scores every observed file with these rules and keeps the result on the server until you save or discard it. Iterate here, then save the version you want.'),
      el('div', 'btn-row', nodes.previewButton),
      nodes.paneState,
      nodes.paneMeter,
      nodes.paneCounts,
      nodes.paneNotes,
      nodes.paneList,
      el('div', 'btn-row', nodes.paneShow, nodes.paneSave),
    );

    fill(
      slots.drawer,
      el(
        'header',
        'engine-drawer__head',
        el('h3', 'engine-drawer__title', 'Configure rule ranking'),
        el('span', 'field__hint', 'Edit rules, preview the result, then save the preview, or use Run ranking on the card to rank and save in one step.'),
      ),
      nodes.drawerError,
      el('div', 'rule-workbench', editorColumn, nodes.pane),
    );
    renderPreviewMeta();
  }

  function drawerError(message) {
    fill(nodes.drawerError, message ? el('div', 'banner', icon('alert'), el('span', undefined, message)) : null);
  }

  /** Debounced repaint of everything that says "rules changed". */
  function edited() {
    clearTimeout(editTimer);
    editTimer = setTimeout(() => {
      renderPreviewMeta();
      ctx.repaint();
    }, EDIT_DEBOUNCE_MS);
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

  const positiveOf = (record) => record?.summary?.positive_files;

  function previewCounts(record = preview) {
    if (!record) return '';
    const positive = positiveOf(record);
    return [`${fmt.count(record.files_scored)} scored`, positive === undefined ? null : `${fmt.count(positive)} positive`].filter(Boolean).join(' · ');
  }

  const saveLabel = () => (preview ? `Save preview (rules as of ${clock(preview.created_at)})` : 'Save preview');

  /** The latest completed scan with files, which a blank scan choice means. */
  function resolvedScan() {
    return nodes.scan.value || catalog.scans.find((scan) => scan.status === 'completed' && Number(scan.file_count) > 0)?.id || '';
  }

  /** Has the editor, starter toggle, or scan moved on since the preview ran? */
  function editorChanged() {
    if (!preview) return false;
    const scan = resolvedScan();
    return (
      nodes.editor.value !== preview.rules_toml ||
      nodes.builtins.firstChild.checked !== Boolean(preview.builtins) ||
      Boolean(scan && preview.scan_id && scan !== preview.scan_id)
    );
  }

  /** Read the server's retained preview and reconcile the views with it. */
  async function loadPreview() {
    if (!ctx.status.triage_enabled) return null;
    let record;
    try {
      record = (await request('/api/triage/preview')).preview;
    } catch (error) {
      drawerError(`Could not read the preview: ${error.message}`);
      return preview;
    }
    previewKnown = true;
    adoptPreview(record);
    return preview;
  }

  function adoptPreview(found) {
    const record = found && !goneIds.has(found.id) ? found : null;
    const changed = (record?.id || null) !== (preview?.id || null);
    if (changed && preview && record) previousPositive = positiveOf(preview);
    if (changed && !record) previousPositive = undefined;
    preview = record || null;
    if (preview) goneNote = '';
    if (changed) {
      resetCompare();
      loadTopHits();
      if (!preview && view === 'preview') setView('saved');
      else if (view === 'preview') setView('preview');
    }
    renderPreviewMeta();
    renderSource();
    ctx.repaint();
  }

  /** A read or write answered 410: the preview went away under us. */
  function previewGone() {
    if (!preview) return;
    goneIds.add(preview.id);
    preview = null;
    previousPositive = undefined;
    goneNote = GONE;
    resetCompare();
    loadTopHits();
    setView('saved');
    renderPreviewMeta();
    toast(GONE, 'warn');
    ctx.repaint();
    // A newer preview may have replaced it; pick that up if so.
    loadPreview();
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
    } else if (saving) {
      nodes.paneState.textContent = `Saving this preview as a ranking · ${[live.percent, live.timing].filter(Boolean).join(' · ')}`;
    } else if (live.jobActive) {
      nodes.paneState.textContent = 'A ranking is running. Preview again when it finishes.';
    } else if (preview) {
      nodes.paneState.textContent = `Unsaved preview · rules as of ${clock(preview.created_at)} · finished ${fmt.relative(preview.finished_at)} · scan ${preview.scan_short_id || String(preview.scan_id || '').slice(0, 8)}`;
    } else {
      nodes.paneState.textContent = goneNote || 'No preview yet.';
    }

    nodes.paneCounts.replaceChildren();
    if (preview) {
      nodes.paneCounts.append(previewCounts());
      const now = positiveOf(preview);
      if (previousPositive !== undefined && now !== undefined) {
        const delta = now - previousPositive;
        const mark = el(
          'span',
          'preview-pane__delta',
          delta === 0 ? ' · same positive count as the previous preview' : ` · ${delta > 0 ? '+' : '−'}${fmt.count(Math.abs(delta))} positive vs previous preview`,
        );
        mark.dataset.direction = delta > 0 ? 'up' : delta < 0 ? 'down' : 'same';
        nodes.paneCounts.append(mark);
      }
    }

    clear(nodes.paneNotes);
    if (preview && !saving) {
      if (editorChanged()) {
        const again = el('button', 'link-button', `Re-preview (${SHORTCUT})`);
        again.type = 'button';
        again.disabled = live.jobActive || live.requesting;
        on(again, 'click', () => startPreview());
        // el() appends text after nodes, so the sentence is built in order here.
        const note = el('li', 'preview-pane__note');
        note.append('Rules edited since this preview · ', again);
        nodes.paneNotes.append(note);
      }
      if (preview.stale?.newer_scan) nodes.paneNotes.append(el('li', 'preview-pane__note', 'A newer scan has completed since this preview.'));
      if (preview.stale?.reviews_changed) nodes.paneNotes.append(el('li', 'preview-pane__note', 'Review decisions changed since this preview; they are not in its scores.'));
    }
    nodes.paneNotes.hidden = !nodes.paneNotes.childElementCount;

    nodes.paneShow.hidden = !preview;
    nodes.paneSave.hidden = !preview;
    nodes.paneSave.lastChild.textContent = saveLabel();
    nodes.paneSave.disabled = !canSave(preview?.id) || live.jobActive || live.requesting;

    const blocked = live.jobActive || live.requesting || live.state === 'unknown' || live.state === 'unavailable';
    if (previewing) setBusy(nodes.previewButton, true, 'Previewing…');
    else {
      setBusy(nodes.previewButton, false);
      nodes.previewButton.disabled = blocked;
    }
    nodes.previewButton.title = live.jobActive ? 'A rule ranking is already running' : `Preview with the editor's rules (${SHORTCUT})`;
    renderPreviewBanner();
  }

  /** The drawer's short list of top previewed files, read from the server. */
  async function loadTopHits() {
    if (!nodes.paneList) return;
    const id = preview?.id || '';
    nodes.paneList.dataset.preview = id;
    clear(nodes.paneList);
    nodes.paneList.hidden = true;
    if (!id) return;
    try {
      const data = await request(`/api/triage/files?${new URLSearchParams({ preview: id, limit: String(TOP_HITS) })}`);
      if (nodes.paneList.dataset.preview !== id) return;
      for (const item of data.items) {
        const entry = el('li', 'preview-pane__item', engineChip('rule', item.review_score, 'Preview priority'), el('span', 'preview-pane__name', item.file_name));
        entry.title = item.unc_path;
        nodes.paneList.append(entry);
      }
      nodes.paneList.hidden = !data.items.length;
    } catch (error) {
      if (gone(error)) previewGone();
    }
  }

  function canSave(id) {
    return Boolean(preview) && preview.id === id && !saving;
  }

  /**
   * Promote the preview: the server copies its scores into the saved
   * rankings. Confirmation is asked only when there is a real reason to
   * hesitate, and says plainly that nothing is re-run.
   */
  async function savePreview() {
    if (!preview || saving) return null;
    await loadPreview();
    if (!preview) return null;
    const record = preview;
    const as = clock(record.created_at);
    const warnings = [];
    if (editorChanged()) warnings.push(`The editor has changed since this preview. Saving keeps the previewed rules as of ${as}, not the editor's current rules.`);
    if (record.stale?.newer_scan) warnings.push(`A newer scan has completed. The saved ranking covers the previewed scan ${record.scan_short_id || ''}.`.replace(' .', '.'));
    if (record.stale?.reviews_changed) warnings.push('Review decisions changed since this preview and are not in its scores. Preview again to include them.');
    if (
      warnings.length &&
      !(await confirm({
        title: 'Save this preview?',
        message: `This saves the previewed rules as of ${as}, with exactly the previewed scores (${previewCounts(record)}). Nothing is re-run.`,
        detail: warnings.join(' '),
        confirmLabel: 'Save previewed rules',
      }))
    ) {
      return null;
    }
    if (preview?.id !== record.id) return null;
    return ctx.start(
      '/api/triage/preview/save',
      { id: record.id },
      {
        send: () => request('/api/triage/preview/save', { method: 'POST', body: { id: record.id } }),
        accepted: () => {
          saving = record.id;
        },
        onError: (error) => {
          if (!gone(error)) return false;
          previewGone();
          return true;
        },
      },
    );
  }

  async function discardPreview() {
    if (!preview) {
      setView('saved');
      return;
    }
    const record = preview;
    const ok = await confirm({
      title: 'Discard this preview?',
      message: `The preview (${previewCounts(record)}, rules as of ${clock(record.created_at)}) was never saved. Discarding deletes it from the server.`,
      detail: 'Your rules stay in the editor; preview again at any time.',
      confirmLabel: 'Discard preview',
      tone: 'danger',
    });
    if (!ok || preview?.id !== record.id) return;
    try {
      await request('/api/triage/preview/discard', { method: 'POST', body: { id: record.id } });
    } catch (error) {
      resultsError(error.message);
      return;
    }
    preview = null;
    previousPositive = undefined;
    resetCompare();
    loadTopHits();
    setView('saved');
    renderPreviewMeta();
    ctx.repaint();
    toast('Preview discarded');
  }

  function revealPreview() {
    if (!preview) return;
    setView('preview');
    ctx.showResults();
  }

  /** Called by the card's View action: show whatever the last run produced. */
  function revealLatest() {
    const job = ctx.job;
    if (job?.preview && preview?.id === job.id) setView('preview');
    else if (job && !job.preview && job.result?.run_id && catalog.runs.some((run) => run.id === job.result.run_id)) {
      nodes.run.value = job.result.run_id;
      setView('saved');
    } else setView('saved');
  }

  /* -- Compare --------------------------------------------------------------- */

  function resetCompare() {
    compare.summary = null;
    compare.filter = 'all';
    compare.order = 'preview';
    compare.forPreview = null;
    defaultBase();
  }

  /** Default base: the latest saved run on the preview's scan, else none. */
  function defaultBase() {
    if (!preview || compare.forPreview === preview.id) return;
    const completed = catalog.runs.filter((run) => run.status === 'completed');
    compare.base = completed.find((run) => run.scan_id === preview.scan_id)?.id || '';
    compare.forPreview = preview.id;
    fillBases();
  }

  function fillBases() {
    if (!nodes.base) return;
    const completed = catalog.runs.filter((run) => run.status === 'completed');
    fill(
      nodes.base,
      option('', 'None'),
      ...completed.map((run) =>
        option(run.id, `${fmt.stamp(run.started_at)} · ${fmt.count(run.file_count)} files · scan ${run.scan_id.slice(0, 8)}${preview && run.scan_id !== preview.scan_id ? ' (other scan)' : ''}`),
      ),
    );
    nodes.base.value = completed.some((run) => run.id === compare.base) ? compare.base : '';
    compare.base = nodes.base.value;
  }

  const comparing = () => view === 'preview' && Boolean(preview) && Boolean(compare.base);

  function renderCompareBar() {
    const show = comparing();
    nodes.compareBar.hidden = !show;
    if (!show) return;
    clear(nodes.compareBar);
    if (compare.loading && !compare.summary) {
      nodes.compareBar.append(
        el(
          'p',
          'compare-bar__loading',
          el('span', 'spinner spinner--inline'),
          ' Comparing with the saved run… The first comparison reads both rankings in full, which can take a while on a large inventory. Paging after that is quick.',
        ),
      );
      return;
    }
    const summary = compare.summary;
    if (!summary) return;
    if (!summary.same_scan) {
      nodes.compareBar.append(
        el(
          'div',
          'banner banner--warn',
          icon('alert'),
          el(
            'span',
            undefined,
            `The saved run scored a different scan, so changes include files added or removed between scans (${fmt.count(summary.only_in_preview)} only in the preview, ${fmt.count(summary.only_in_base)} only in the saved run).`,
          ),
        ),
      );
    }
    const chips = el('div', 'compare-chips');
    chips.setAttribute('role', 'group');
    chips.setAttribute('aria-label', 'Show files that');
    for (const [name, label] of COMPARE_FILTERS) {
      const count = name === 'all' ? Number(preview.files_scored) + Number(summary.only_in_base || 0) : summary[name];
      const chip = el('button', 'compare-chip', el('b', undefined, fmt.count(count)), ` ${label}`);
      chip.type = 'button';
      chip.dataset.filter = name;
      chip.setAttribute('aria-pressed', String(compare.filter === name));
      on(chip, 'click', () => {
        compare.filter = name;
        resetPages();
        renderSource();
        loadResults();
      });
      chips.append(chip);
    }
    nodes.compareBar.append(chips);
    if (compare.loading) nodes.compareBar.append(el('p', 'field__hint', el('span', 'spinner spinner--inline'), ' Loading…'));
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
    nodes.base = select([['', 'None']]);
    nodes.baseField = field('Compare with', nodes.base);
    nodes.category = select([['', 'Highest category score']]);
    nodes.categoryField = field('Category', nodes.category);
    nodes.minimum = number('0', 0);
    nodes.minimum.classList.add('input--num');
    nodes.orderPreview = el('button', undefined, 'Preview priority');
    nodes.orderDelta = el('button', undefined, 'Biggest change');
    for (const [node, order] of [
      [nodes.orderPreview, 'preview'],
      [nodes.orderDelta, 'delta'],
    ]) {
      node.type = 'button';
      on(node, 'click', () => {
        compare.order = order;
        resetPages();
        renderSource();
        loadResults();
      });
    }
    nodes.order = el('div', 'segmented', nodes.orderPreview, nodes.orderDelta);
    nodes.order.setAttribute('aria-label', 'Sort');
    nodes.orderField = el('div', 'field', el('span', 'field__label', 'Sort'), nodes.order);
    nodes.resultSummary = el('p', 'panel__hint');
    nodes.previewBanner = el('div', 'preview-banner');
    nodes.compareBar = el('div', 'compare-bar');
    nodes.matches = el('details', 'disclosure rule-matches');
    nodes.matches.open = true;
    nodes.head = el('thead');
    nodes.rows = el('tbody');
    nodes.counts = el('details', 'disclosure');
    nodes.collectBar = el('div', 'score-collect-bar');
    nodes.refresh = button('Refresh', { size: 'sm', name: 'refresh', onClick: () => loadResults() });

    const controls = el('div', 'field-grid');
    fill(controls, nodes.runField, nodes.baseField, nodes.categoryField, field('Min score', nodes.minimum), nodes.orderField, nodes.refresh);

    nodes.page = {
      prev: button('Previous', { size: 'sm', onClick: () => step(-1) }),
      next: button('Next', { size: 'sm', onClick: () => step(1) }),
      label: el('span', undefined, 'Page 1'),
    };
    const pager = el('div', 'pagination');
    fill(pager, nodes.page.prev, nodes.page.label, nodes.page.next);

    const table = el('table', 'data-grid score-grid');
    fill(table, nodes.head, nodes.rows);
    nodes.empty = el('div', 'empty');
    nodes.empty.hidden = true;
    nodes.body = el(
      'div',
      'results-body',
      controls,
      nodes.compareBar,
      nodes.matches,
      nodes.resultSummary,
      nodes.collectBar,
      el('div', 'grid-shell score-grid-shell', table),
      pager,
      nodes.counts,
    );
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
    on(nodes.base, 'change', () => {
      compare.base = nodes.base.value;
      compare.summary = null;
      compare.filter = 'all';
      resetPages();
      renderSource();
      loadResults();
    });
    for (const control of [nodes.category, nodes.minimum]) {
      on(control, 'change', () => {
        resetPages();
        loadResults();
      });
    }
    renderHead();
    renderCollectBar();
    renderSource();
  }

  function resultsError(message) {
    fill(nodes.resultsError, message ? el('div', 'banner', icon('alert'), el('span', undefined, message)) : null);
  }

  function setView(next) {
    view = next === 'preview' && preview ? 'preview' : 'saved';
    if (view === 'preview') defaultBase();
    resetPages();
    fillCategories();
    renderSource();
    loadResults();
  }

  function renderSource() {
    if (!nodes.panel) return;
    const isPreview = view === 'preview';
    const comparison = comparing();
    nodes.panel.dataset.view = view;
    nodes.source.hidden = !preview;
    nodes.sourceSaved.setAttribute('aria-pressed', String(!isPreview));
    nodes.sourcePreview.setAttribute('aria-pressed', String(isPreview));
    nodes.runField.hidden = isPreview;
    nodes.baseField.hidden = !isPreview;
    nodes.orderField.hidden = !comparison;
    nodes.orderPreview.setAttribute('aria-pressed', String(compare.order === 'preview'));
    nodes.orderDelta.setAttribute('aria-pressed', String(compare.order === 'delta'));
    // Category scores are not part of a comparison; the overall priority is.
    nodes.category.disabled = comparison;
    nodes.categoryField.title = comparison ? 'Compare reads overall priority. Set Compare with to None to filter by category.' : '';
    nodes.collectBar.hidden = isPreview;
    nodes.counts.hidden = isPreview || !nodes.counts.childElementCount;
    renderCompareBar();
    renderMatches();
    renderPreviewBanner();
  }

  /** The unsaved view announces itself in tone, label, and counts. */
  function buildPreviewBanner() {
    nodes.bannerCounts = el('strong');
    nodes.bannerText = el('span');
    nodes.bannerSave = button('Save preview', { size: 'sm', variant: 'primary', onClick: () => savePreview() });
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
    nodes.bannerSave.lastChild.textContent = saveLabel();
    nodes.bannerSave.disabled = !canSave(preview.id) || live.jobActive || live.requesting;
    nodes.bannerCounts.textContent = `${previewCounts()} · rules as of ${clock(preview.created_at)}`;
    const notes = [];
    if (editorChanged()) notes.push(`Rules edited since this preview; Save keeps the previewed rules. Re-preview (${SHORTCUT}) to see your edits.`);
    if (preview.stale?.newer_scan) notes.push('A newer scan has completed since.');
    if (preview.stale?.reviews_changed) notes.push('Review decisions changed since.');
    nodes.bannerText.textContent = saving
      ? 'Saving: copying these exact scores into the saved rankings…'
      : `Nothing has been written to the saved rankings. Explore, collection, and Nemesis can use it once it is saved.${notes.length ? ` ${notes.join(' ')}` : ''}`;
  }

  /**
   * Custom rules and how often each matched. A custom rule that matched
   * nothing is the most common rule-writing mistake, so it is called out.
   */
  function renderMatches() {
    const show = view === 'preview' && Boolean(preview);
    nodes.matches.hidden = !show;
    if (!show) return;
    const counts = preview.summary?.rule_matches || {};
    const pairs = compare.summary && comparing() ? compare.summary.rule_matches || {} : null;
    const custom = customRuleIds(preview.rules_toml);
    const starter = Object.keys(counts)
      .filter((id) => !custom.includes(id))
      .sort();
    const row = (id) => {
      const count = Number(counts[id] || 0);
      const base = pairs?.[id] ? Number(pairs[id][0]) : pairs ? 0 : null;
      const delta = base === null ? '' : ` (${count - base >= 0 ? '+' : '−'}${fmt.count(Math.abs(count - base))})`;
      const entry = el('li', 'rule-match', el('code', undefined, id), el('span', 'rule-match__count', `${fmt.count(count)}${delta}`));
      if (!count && custom.includes(id)) {
        entry.dataset.tone = 'warn';
        entry.append(el('span', 'rule-match__hint', 'No file matched. Open Explain on a file you expected it to match: "Why other rules did not match" lists the failed conditions.'));
      }
      return entry;
    };
    const list = el('ul', 'rule-match-list');
    for (const id of custom) list.append(row(id));
    const children = [el('summary', undefined, custom.length ? `Custom rule matches · ${custom.length} rule${custom.length === 1 ? '' : 's'}` : 'Rule matches')];
    if (custom.length) children.push(list);
    else children.push(el('p', 'field__hint', 'This preview has no custom rules; these are the starter rules that matched.'));
    if (starter.length) {
      const others = el('ul', 'rule-match-list');
      for (const id of starter) others.append(row(id));
      if (custom.length) {
        const nested = el('details', 'disclosure');
        nested.append(el('summary', undefined, `Starter rule matches · ${starter.length}`), others);
        children.push(nested);
      } else children.push(others);
    }
    if (pairs) children.push(el('p', 'field__hint', 'Counts in brackets are the change from the compared saved run.'));
    fill(nodes.matches, ...children);
  }

  function categories() {
    if (view === 'preview') return [];
    return catalog.runs.find((item) => item.id === nodes.run.value)?.categories || [];
  }

  function fillCategories() {
    const chosen = nodes.category.value;
    const names = view === 'preview' ? previewCategories() : categories();
    fill(nodes.category, option('', 'Highest category score'), ...names.map((category) => option(category, category)));
    if (names.includes(chosen)) nodes.category.value = chosen;
  }

  /** Categories a preview's rules declare, read from its TOML and the starter set. */
  function previewCategories() {
    const names = new Set();
    for (const match of String(preview?.rules_toml || '').matchAll(/^\s*category\s*=\s*"([^"]+)"/gm)) names.add(match[1]);
    // Starter-rule categories come from any saved run that used them.
    if (preview?.builtins) for (const run of catalog.runs) for (const name of run.categories || []) names.add(name);
    return [...names].sort();
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
    catalog = await request('/api/triage/catalog');
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
    fillBases();
    defaultBase();
    fillCategories();
    ctx.repaint();
  }

  async function loadResults() {
    const token = ++loadToken;
    resultsError('');
    if (view === 'preview' && preview) {
      return comparing() ? loadCompare(token) : loadFiles(token, { preview: preview.id });
    }
    if (!nodes.run.value) {
      renderEmpty();
      return;
    }
    return loadFiles(token, { run: nodes.run.value });
  }

  /** One page of a saved run or the preview, through the same endpoint. */
  async function loadFiles(token, source) {
    const minimum = Number(nodes.minimum.value);
    if (!Number.isInteger(minimum) || minimum < 0) {
      resultsError('Minimum score must be a nonnegative integer.');
      return;
    }
    const params = new URLSearchParams({ ...source, category: nodes.category.value, min_score: String(minimum) });
    const cursor = cursors[cursors.length - 1];
    if (cursor) {
      params.set('after_score', String(cursor[0]));
      params.set('after_id', cursor[1]);
    }
    try {
      const data = await request(`/api/triage/files?${params}`);
      if (token !== loadToken) return;
      renderResults(data.items, { next: data.next_cursor, summary: data.summary, filesScored: data.files_scored });
    } catch (error) {
      if (token !== loadToken) return;
      if (source.preview && gone(error)) previewGone();
      else resultsError(error.message);
    }
  }

  /**
   * One page of the comparison. Filters the server cannot apply are applied
   * here by reading forward through its pages, so a page is still up to 100
   * matching files and Next resumes exactly where this page stopped.
   */
  async function loadCompare(token) {
    const minimum = Math.max(0, Number(nodes.minimum.value) || 0);
    const [, , changed, match] = COMPARE_FILTERS.find(([name]) => name === compare.filter) || COMPARE_FILTERS[0];
    const keep = (item) => match(item) && (minimum === 0 || (item.preview_priority ?? 0) >= minimum);
    const keyOf = (item) => (compare.order === 'delta' ? Math.abs(item.delta ?? 0) : (item.preview_priority ?? 0));
    const id = preview.id;
    compare.loading = true;
    renderCompareBar();
    if (!compare.summary) clear(nodes.rows);
    let cursor = cursors[cursors.length - 1];
    const items = [];
    let next = null;
    let scanned = 0;
    try {
      for (let page = 0; page < COMPARE_SCAN_PAGES; page += 1) {
        const params = new URLSearchParams({ preview: id, base: compare.base, order: compare.order, changed, limit: String(PAGE) });
        if (cursor) {
          params.set('after_score', String(cursor[0]));
          params.set('after_id', cursor[1]);
        }
        const data = await request(`/api/triage/compare?${params}`);
        if (token !== loadToken) return;
        compare.summary = data.summary;
        let stop = false;
        next = null;
        for (const [index, item] of data.items.entries()) {
          scanned += 1;
          // Sorted by preview priority, nothing below the minimum can follow.
          if (compare.order === 'preview' && minimum && (item.preview_priority ?? 0) < minimum) {
            stop = true;
            break;
          }
          if (keep(item)) items.push(item);
          if (items.length === PAGE) {
            // Resume right after this item, mid-page if need be.
            const last = index === data.items.length - 1;
            next = last ? data.next_cursor : [keyOf(item), item.file_id];
            stop = true;
            break;
          }
        }
        if (stop || !data.next_cursor) break;
        // Not full yet: keep reading. If the page budget runs out here,
        // Next resumes from this cursor.
        cursor = data.next_cursor;
        next = cursor;
      }
    } catch (error) {
      if (token !== loadToken) return;
      compare.loading = false;
      if (gone(error)) previewGone();
      else {
        renderCompareBar();
        resultsError(error.message);
      }
      return;
    }
    // Ran out of pages to read without filling this one: Next keeps reading.
    compare.loading = false;
    compare.scanned = scanned;
    renderSource();
    renderResults(items, { next, compared: true, scanned });
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
      el('span', undefined, preview ? 'Switch to the unsaved preview above, or save it to keep it.' : 'Choose Run ranking on the Rule card to rank every observed file.'),
    );
    renderSource();
  }

  function renderHead(compared = false) {
    fill(
      nodes.head,
      el(
        'tr',
        {},
        el('th', 'numeric', 'Priority'),
        compared ? el('th', 'numeric', 'Was') : null,
        compared ? el('th', 'numeric', 'Δ') : null,
        el('th', undefined, 'File'),
        el('th', undefined, 'Observed location'),
        el('th', undefined, 'Reasons'),
        el('th', undefined, 'Review'),
      ),
    );
  }

  function renderResults(items, { next = null, summary, filesScored, compared = false, scanned = 0 } = {}) {
    const isPreview = view === 'preview';
    nodes.empty.hidden = true;
    nodes.body.hidden = false;
    renderHead(compared);
    clear(nodes.rows);
    for (const item of items) nodes.rows.append(candidateRow(item, { isPreview, compared }));
    if (!items.length) {
      const row = el('tr');
      const cell = el('td', 'empty', compared ? 'No compared file matches this filter on this page.' : isPreview ? 'No previewed file matches this filter.' : 'No files match this ranking filter.');
      cell.colSpan = compared ? 7 : 5;
      row.append(cell);
      nodes.rows.append(row);
    }
    nextCursor = next;
    nodes.page.prev.disabled = cursors.length === 1;
    nodes.page.next.disabled = !nextCursor;
    nodes.page.label.textContent = `Page ${cursors.length}`;
    const positive = (isPreview ? preview?.summary : summary)?.positive_files;
    if (compared) {
      const filter = COMPARE_FILTERS.find(([name]) => name === compare.filter);
      const partial = compare.filter !== 'all' && compare.filter !== 'changed' && items.length < PAGE && nextCursor;
      nodes.resultSummary.textContent = `Unsaved preview compared with a saved run · ${fmt.count(items.length)} ${filter[1] === 'All files' ? 'files' : `${filter[1]} files`} on this page${
        partial ? ` · read ${fmt.count(scanned)} changed files so far; Next keeps reading` : ''
      }`;
    } else if (isPreview) {
      nodes.resultSummary.textContent = `Unsaved preview · ${fmt.count(preview.files_scored)} observed files scored${positive !== undefined ? ` · ${fmt.count(positive)} with positive priority` : ''}`;
    } else {
      nodes.resultSummary.textContent = `Saved ranking · ${fmt.count(filesScored)} observed files scored${positive !== undefined ? ` · ${fmt.count(positive)} with positive priority` : ''}`;
      // The collection queue resolves manifests against a saved ranking, so it
      // only ever hears about one; the preview view never sets its source.
      ctx.collection?.setSource({ run: nodes.run.value, category: nodes.category.value, minScore: Number(nodes.minimum.value) || 0 });
    }
    if (isPreview) clear(nodes.counts);
    else renderCounts(summary);
    renderSource();
  }

  function deltaCell(item) {
    const cell = el('td', 'numeric compare-delta');
    const delta = Number(item.delta || 0);
    cell.dataset.direction = delta > 0 ? 'up' : delta < 0 ? 'down' : 'same';
    cell.textContent = delta === 0 ? '0' : `${delta > 0 ? '+' : '−'}${Math.abs(delta)}`;
    if (item.preview_priority === null || item.preview_priority === undefined) cell.title = 'Only in the saved run';
    else if (item.base_priority === null || item.base_priority === undefined) cell.title = 'Only in the preview';
    return cell;
  }

  function candidateRow(item, { isPreview, compared }) {
    const signals = item.signals || [];
    const positive = signals.filter((signal) => signal.credited_points > 0).map((signal) => signal.description);
    const fallback = signals.filter((signal) => signal.category === 'extension-fallback').map((signal) => signal.description);
    const score = compared ? (item.preview_priority ?? null) : item.review_score;
    const row = el('tr', 'rail');
    // severity() has no band below zero, and a rule can push a file negative.
    row.dataset.severity = severity(score === null || score === undefined ? score : Math.max(0, score)).band;
    const scoreCell = el('td', 'numeric');
    scoreCell.append(engineChip('rule', score, isPreview ? 'Preview priority' : 'Rule priority'));
    const link = el('a', 'candidate-link', item.file_name || item.file_id);
    link.href = href(`/?q=${encodeURIComponent(item.unc_path || '')}`);
    const review = el('td');
    const actions = el('div', 'btn-row');
    const explain = button('Explain', { size: 'sm', onClick: () => showExplanation(item, isPreview) });
    // A file only the saved run has cannot be explained from the preview.
    if (compared && (item.preview_priority === null || item.preview_priority === undefined)) {
      explain.disabled = true;
      explain.title = 'Not in the preview';
    }
    actions.append(explain);
    const collect = el('label', 'checkbox');
    const box = el('input');
    box.type = 'checkbox';
    if (isPreview) {
      // Collection resolves files against a saved ranking; a preview has none.
      box.disabled = true;
      collect.title = 'Save the ranking to queue files from it';
    } else {
      box.checked = ctx.collection?.has(item.file_id) || false;
      on(box, 'change', () => {
        ctx.collection?.toggle(item.file_id, box.checked, item);
        renderCollectBar();
      });
    }
    collect.append(box, el('span', undefined, 'Nemesis'));
    actions.append(collect);
    review.append(actions);
    fill(
      row,
      scoreCell,
      compared ? el('td', 'numeric', engineChip('rule', item.base_priority ?? null, 'Saved run priority')) : null,
      compared ? deltaCell(item) : null,
      el('td', undefined, link),
      el('td', 'score-path', item.unc_path || ''),
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
        title: item.file_name || item.file_id,
        subtitle: isPreview ? `Unsaved preview · ${item.unc_path || ''}` : item.unc_path,
        body: content,
        onClose: () => handle.close(),
      }).node,
    );
    fill(content, el('span', 'spinner'), el('span', 'field__hint', 'Loading explanation…'));
    const source = isPreview ? { preview: preview?.id || '' } : { run: nodes.run.value };
    try {
      const detail = await request(`/api/triage/explain?${new URLSearchParams({ ...source, file_id: item.file_id })}`);
      clear(content);
      if (isPreview) content.append(el('p', 'explain-source', `Previewed rules · not saved · rules as of ${clock(preview?.created_at)}`));
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
        // Open in a preview: "why did my new rule not fire" is the question.
        details.open = isPreview;
        details.append(el('summary', undefined, 'Why other rules did not match'));
        details.append(el('pre', 'code-block', missed.map((rule) => `${rule.rule_id}: ${rule.failed_conditions.join(', ')}`).join('\n') || 'Every rule matched.'));
        content.append(details);
      }
    } catch (error) {
      clear(content);
      content.append(el('p', 'panel__hint', isPreview && gone(error) ? GONE : error.message));
      if (isPreview && gone(error)) previewGone();
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
    await loadPreview();
    await loadResults();
  }

  async function onComplete(job) {
    if (job.preview) {
      await loadPreview();
      if (preview?.id !== job.id) return;
      setView('preview');
      toast(`Preview ready · ${previewCounts()} · not saved`, 'info', { action: { label: 'View', onClick: () => revealPreview() } });
      return;
    }
    const promoted = Boolean(job.result?.saved_from_preview);
    if (promoted) {
      saving = null;
      if (preview?.id === job.result.saved_from_preview) {
        preview = null;
        previousPositive = undefined;
        resetCompare();
        loadTopHits();
      }
    }
    resetPages();
    try {
      await refreshCatalog(job.result?.run_id);
    } catch (error) {
      resultsError(error.message);
    }
    if (job.result?.run_id) nodes.run.value = job.result.run_id;
    setView('saved');
    if (promoted) ctx.selectTab();
    await loadPreview();
    const positive = job.result?.summary?.positive_files;
    toast(
      `${promoted ? 'Ranking saved · from preview · scores identical to the preview' : 'Ranking saved'} · ${fmt.count(job.result?.files_scored)} scored${positive === undefined ? '' : ` · ${fmt.count(positive)} positive`}`,
      'ok',
      { action: { label: 'View candidates', onClick: () => ctx.showResults() } },
    );
  }

  /** Any other rule outcome (failed, cancelled) may still leave a preview. */
  async function onSettle(job) {
    if (job.saving_preview_id) saving = null;
    await loadPreview();
  }

  /** Mirror the shared job model into the drawer's preview pane and banner. */
  function renderJob(job) {
    const next = job?.status === 'running' ? job.saving_preview_id || null : null;
    if (next) saving = next;
    else if (saving && job?.status !== 'running' && !(job?.status === 'completed' && job.result?.saved_from_preview)) saving = null;
    renderPreviewMeta();
  }

  function onDrawer(open) {
    if (open) loadPreview();
  }

  function history() {
    const run = catalog.runs.find((item) => item.status === 'completed');
    if (!run) return { text: preview ? `Unsaved preview only · ${previewCounts()} · nothing saved yet` : 'No saved ranking yet.' };
    return { text: `Last saved ranking ${fmt.relative(run.started_at)} · ${fmt.count(run.file_count)} files`, run: run.id };
  }

  return {
    mount,
    load,
    start,
    onComplete,
    onSettle,
    onDrawer,
    renderJob,
    renderCollectBar,
    history,
    canSave,
    saveLabel,
    savePreview,
    revealLatest,
    previewState: () => ({ known: previewKnown, id: preview?.id || null }),
  };
}
