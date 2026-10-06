// Explore screen. Owns the query contract, the data grid, row expand, selection,
// and the percentage actions. Filters and engine run selection live in
// explore-filters.js; the score vocabulary and every commit-to-disk action
// live in actions.js.
//
// All view state lives in the URL, so any table state is shareable as a link
// and there is no second source of truth to desync from what is on screen.

import {
  clear,
  delegate,
  el,
  fill,
  fmt,
  icon,
  json,
  mountShell,
  on,
  onPopState,
  readParams,
  renderShellStatus,
  serverParams,
  severity,
  shellError,
  writeParams,
} from './core.js';
import {
  detailPanel,
  downloadOne,
  downloadRows,
  findingText,
  pathLabel,
  pathTail,
  percentageDialog,
  queueRows,
  rowActions,
  typeTag,
} from './actions.js';
import { AUTO, createFilters, NONE } from './explore-filters.js';
import { errorLine, toast } from './overlay.js';
import { aiScore, combinedChip, combinedScore, describe, engineChip, ruleScore } from './scores.js';
import { createTree } from './tree.js';

const SERVER_KEYS = [
  'q',
  'host',
  'share',
  'extension',
  'rule',
  'triage',
  'permission',
  'collection',
  'ranking_run',
  'ranking_category',
  'ranking_min',
  'jev_run',
  'sort',
  'direction',
  'activity',
];

// Defaults double as the URL contract: a value equal to its default is dropped
// from the query, which keeps shared links short.
const DEFAULTS = {
  ...Object.fromEntries(SERVER_KEYS.map((key) => [key, ''])),
  sort: 'combined',
  direction: 'desc',
  page: '1',
  per_page: '',
  view: 'table',
};

// "No ranking selected" is spelled `none` in the URL so a pasted link keeps
// showing no rule ratings. An absent parameter means "pick the newest".

const SORTS = {
  path: 'Path',
  type: 'Type',
  file: 'File',
  location: 'Location',
  combined: 'Overall',
  priority: 'Rule Rating',
  jev: 'AI Rating',
  size: 'Size',
  modified: 'Modified',
};

const sortLabel = (key) => SORTS[key] || 'Path';
const $ = (id) => document.getElementById(id);
const shell = mountShell('/');

// The URL distinguishes three states for a run: absent (pick the newest),
// "none" (explicitly no run, so a pasted link keeps showing no ratings), or an
// id. AUTO is a read-time placeholder only.
const state = readParams({ ...DEFAULTS, ranking_run: AUTO });
const selection = new Map();
const runs = { ranking: [], jev: [] };
let status = {};
let facets = null;
let page = { items: [], total: 0, has_next: false, per_page: 0 };
let expandedId = null;
let tableController = null;
let searchTimer = null;
let anchorRow = null;
let busy = false;
let lastKey = '';
// Inventory revision the view currently reflects. The scanner bumps the
// database revision on commit, so the "new captures" banner keys off a change
// past this value, never off a diff between the inventory size and a filtered
// page total — a search that hides files must not look like new captures.
let lastRevision = null;

// AUTO and NONE are URL spellings, never API ones: the server is told an empty
// run id for "off" and left to resolve "the latest" when nothing is named.
const selectedRun = () => (state.ranking_run === AUTO || state.ranking_run === NONE ? '' : state.ranking_run);
const selectedAiRun = () => (state.jev_run === NONE ? '' : state.jev_run);
const query = () => serverParams({ ...state, ranking_run: selectedRun(), jev_run: selectedAiRun() }, SERVER_KEYS);

/** Every interaction writes the URL first, then refetches if the contract moved. */
function commit(patch, { keepPage = false, push = false } = {}) {
  Object.assign(state, patch);
  if (!keepPage && !('page' in patch)) state.page = '1';
  writeParams({ ...state, ranking_run: state.ranking_run || NONE }, DEFAULTS, { replace: !push });
  reload();
}

const filters = createFilters({
  root: { toggle: $('filter-toggle'), chips: $('active-filters'), ranking: $('ranking-run'), jev: $('jev-run'), note: $('engine-note'), combinedHeader: $('combined-header') },
  state,
  defaults: DEFAULTS,
  runs,
  facets: () => facets,
  commit,
});

/* -- Grid ------------------------------------------------------------------ */

function selectionBox(item) {
  const box = el('input', 'file-checkbox');
  box.type = 'checkbox';
  box.checked = selection.has(item.id);
  box.setAttribute('aria-label', `Select ${item.file_name}`);
  // The modifier state has to be read from the click: the change event that
  // follows carries no keyboard or shift state.
  let extend = false;
  on(box, 'click', (event) => {
    event.stopPropagation();
    extend = event.shiftKey;
  });
  on(box, 'change', () => {
    toggle(item, box.checked, extend);
    anchorRow = Number(box.closest('tr').dataset.index);
  });
  return box;
}

/** Shift-click selects the contiguous block between the last anchor and here. */
function toggle(item, selected, range) {
  if (range && anchorRow !== null) {
    const target = page.items.indexOf(item);
    const [start, end] = anchorRow < target ? [anchorRow, target] : [target, anchorRow];
    for (const row of page.items.slice(start, end + 1)) {
      if (selected) selection.set(row.id, row);
      else selection.delete(row.id);
    }
  } else if (selected) selection.set(item.id, item);
  else selection.delete(item.id);
  render();
}

function rowFor(item, index) {
  const open = expandedId === item.id;
  const row = el('tr', 'file-row');
  row.classList.toggle('selected', open);
  row.classList.toggle('checked', selection.has(item.id));
  row.dataset.index = String(index);

  // The severity rail lives on the first cell: a left rule the eye catches in
  // peripheral vision without tinting the path text the analyst is reading.
  const checkCell = el('td', 'check-cell rail');
  checkCell.dataset.severity = severity(combinedScore(item)).band;
  checkCell.append(selectionBox(item));

  // The score cluster leads the row: three fixed-width columns that rank the
  // file before its name is even read.
  const combinedCell = el('td', 'score-cell');
  combinedCell.append(combinedChip(item));
  const ruleCell = el('td', 'score-cell');
  ruleCell.append(engineChip('rule', ruleScore(item), 'Rule rating'));
  const aiCell = el('td', 'score-cell');
  aiCell.append(engineChip('ai', aiScore(item), 'AI rating'));

  const fileCell = el('td');
  const trigger = el('button', 'file-trigger');
  trigger.type = 'button';
  trigger.dataset.fileId = item.id;
  trigger.setAttribute('aria-expanded', String(open));
  trigger.setAttribute('aria-controls', `details-${item.id}`);
  const head = el('span', 'file-head', el('span', 'file-name', item.file_name), typeTag(item.extension));
  const fullPath = el('span', 'file-path file-path--full', pathLabel(item.remote_path));
  const tailPath = el('span', 'file-path file-path--tail', pathTail(item.remote_path));
  fullPath.title = item.remote_path || '';
  tailPath.title = item.remote_path || '';
  const sub = el('span', 'file-sub', fullPath, tailPath);
  // Evidence is only worth a badge when there is evidence: a "No findings" tag
  // on every row is noise that trains the eye to ignore the column.
  if ((item.rule_matches || []).length) {
    sub.append(el('span', 'evidence-tag', findingText(item)));
  }
  fill(trigger, head, sub);
  trigger.title = item.file_name;
  fileCell.append(trigger);

  const locationCell = el('td');
  locationCell.append(el('span', 'location', `${item.host || 'Unknown host'} › ${item.share || 'Unknown share'}`));

  const sizeCell = el('td', 'numeric');
  sizeCell.append(el('span', 'size-value', item.readable_size || fmt.bytes(item.size_bytes)));

  const dateCell = el('td', 'numeric');
  const time = el('time', 'date-value', fmt.relative(item.mtime_utc));
  if (item.mtime_utc) time.dateTime = item.mtime_utc;
  time.title = fmt.date(item.mtime_utc);
  dateCell.append(time);

  const actionsCell = el('td', 'actions-cell');
  actionsCell.append(...rowActions(item, actionContext()));

  const chevronCell = el('td', 'chevron-cell');
  chevronCell.append(icon('chevron'));

  fill(
    row,
    checkCell,
    fileCell,
    locationCell,
    combinedCell,
    ruleCell,
    aiCell,
    sizeCell,
    dateCell,
    actionsCell,
    chevronCell,
  );
  return row;
}

function renderTable() {
  const body = $('rows');
  clear(body);
  if (!page.items.length) {
    const row = el('tr');
    const cell = el('td', 'empty');
    cell.colSpan = 10;
    fill(cell, el('strong', undefined, 'No files match these filters.'), el('span', undefined, 'Try a broader search or clear an active filter.'));
    row.append(cell);
    body.append(row);
    renderSelectionBar();
    return;
  }
  page.items.forEach((item, index) => {
    body.append(rowFor(item, index));
    if (expandedId !== item.id) return;
    const detail = el('tr', 'detail-row');
    detail.id = `details-${item.id}`;
    const cell = el('td');
    cell.colSpan = 10;
    cell.append(detailPanel(item, actionContext()));
    detail.append(cell);
    body.append(detail);
  });
  renderSelectionBar();
}

function renderSelectionBar() {
  const files = [...selection.values()];
  const bytes = files.reduce((sum, item) => sum + (Number(item.size_bytes) || 0), 0);
  $('selection-bar').hidden = files.length === 0;
  $('selection-count').textContent = `${fmt.count(files.length)} selected`;
  $('selection-size').textContent = files.length ? fmt.bytes(bytes) : '';
  const retrievable = status.retrieval_enabled !== false && !busy;
  $('download-selection').disabled = !retrievable;
  $('queue-selection').disabled = !retrievable;
  const offlineTitle = status.retrieval_enabled === false ? 'Remote retrieval is disabled in offline mode' : '';
  $('download-selection').title = offlineTitle;
  $('queue-selection').title = offlineTitle;
  const onPage = page.items.filter((item) => selection.has(item.id)).length;
  $('select-page').checked = !!page.items.length && onPage === page.items.length;
  $('select-page').indeterminate = onPage > 0 && onPage < page.items.length;
}

function renderSortHeaders() {
  for (const header of document.querySelectorAll('.sort-btn')) {
    const cell = header.closest('th');
    // A column with no run behind it cannot be sorted by; disabling the button
    // is clearer than accepting a click that does nothing.
    header.disabled = !filters.columnAvailable(header.dataset.sort);
    if (header.dataset.sort === state.sort) cell.setAttribute('aria-sort', state.direction === 'desc' ? 'descending' : 'ascending');
    else cell.removeAttribute('aria-sort');
  }
}

function renderSkeleton() {
  const body = $('rows');
  clear(body);
  for (let index = 0; index < 8; index += 1) {
    const row = el('tr', 'skeleton-row');
    for (let column = 0; column < 10; column += 1) {
      const cell = el('td');
      cell.append(el('div', 'skeleton'));
      row.append(cell);
    }
    body.append(row);
  }
}

function setBusy(value) {
  busy = value;
  $('search-spinner').hidden = !value;
  $('search-icon').hidden = value;
}

/* -- Loading --------------------------------------------------------------- */

async function loadTable() {
  if (tableController) tableController.abort();
  tableController = new AbortController();
  const signal = tableController.signal;
  setBusy(true);
  errorLine($('error-banner'), '');
  const params = query();
  params.set('page', state.page || '1');
  if (state.per_page) params.set('per_page', state.per_page);
  params.set('include_total', '1');
  // query() already omits jev_run when the AI run is off, which is what makes
  // Combined the rule rating alone.
  const key = params.toString();
  if (key !== lastKey) renderSkeleton();
  lastKey = key;
  try {
    const data = await json(`/api/files?${params}`, { signal });
    page = data;
    lastRevision = data.revision;
    expandedId = null;
    renderTable();
    renderPagination();
    const start = data.items.length ? (Number(data.page) - 1) * data.per_page + 1 : 0;
    $('summary').textContent = start
      ? `${fmt.count(start)}–${fmt.count(start + data.items.length - 1)} of ${fmt.count(data.total)} files · ${sortLabel(state.sort)} ${state.direction === 'desc' ? '↓' : '↑'}`
      : 'No matching files';
  } catch (error) {
    if (error.name !== 'AbortError') {
      errorLine($('error-banner'), error.message);
      $('summary').textContent = 'Inventory unavailable';
    }
  } finally {
    if (tableController && tableController.signal === signal) {
      tableController = null;
      setBusy(false);
    }
  }
}

function renderPagination() {
  $('previous').disabled = Number(state.page) <= 1;
  $('next').disabled = !page.has_next;
  $('page').textContent = `Page ${state.page}`;
}

/* -- Actions --------------------------------------------------------------- */

function actionContext() {
  return {
    status,
    describe,
    // One file the analyst can see the size of: a plain browser download.
    // Sets of files go through the queue, which brings caps and retry.
    onDownload: async (item, trigger) => {
      if (trigger) {
        trigger.disabled = true;
        fill(trigger, el('span', undefined, 'Retrieving…'));
      }
      try {
        const name = await downloadOne(item);
        toast(`Download started: ${name}`);
      } catch (error) {
        toast(error.message, 'error');
      } finally {
        if (trigger) {
          trigger.disabled = false;
          fill(trigger, icon('download'), el('span', undefined, 'Download'));
        }
        render();
      }
    },
    onQueue: (items) => queue(items, 'Explore selection'),
    onClose: () => toggleExpanded(null),
  };
}

async function queue(items, name) {
  try {
    await queueRows(items, { rankingRun: selectedRun(), rankingCategory: state.ranking_category, name, status });
    render();
  } catch (error) {
    toast(error.message, 'error');
  }
}

function toggleExpanded(id) {
  const wasOpen = expandedId;
  expandedId = expandedId === id ? null : id;
  renderTable();
  if (expandedId) document.getElementById(`details-${expandedId}`)?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  else if (wasOpen) document.querySelector(`.file-trigger[data-file-id="${CSS.escape(wasOpen)}"]`)?.focus({ preventScroll: true });
}

/** Percentage actions. The preflight lives in actions.js with the rest of the flow. */
function openPercentageDialog() {
  const run = selectedRun();
  percentageDialog({
    params: { ...state, ranking_run: run },
    sortKey: state.sort,
    sortName: sortLabel(state.sort),
    status,
    rankingRun: run,
    rankingCategory: state.ranking_category,
    onDone: render,
  });
}

/* -- Tree ------------------------------------------------------------------ */

// Structure and interaction are frozen; the tree only inherits the new tokens
// and the fixed row height.
const tree = createTree({
  root: $('tree'),
  loadingNode: $('tree-loading'),
  params: query,
  selection,
  scoreFor: (item) => combinedChip(item),
  onSelect: (item, checked) => {
    if (checked) selection.set(item.id, item);
    else selection.delete(item.id);
    render();
  },
  detailFor: (item) => detailPanel(item, actionContext()),
  onSummary: (text, limited, revision) => {
    $('summary').textContent = text;
    $('expand-tree').disabled = limited;
    $('expand-tree').title = limited ? 'Expand branches individually for inventories over 5,000 files' : 'Expand every branch';
    if (revision !== undefined) lastRevision = revision;
  },
});

/* -- Render orchestration -------------------------------------------------- */

function renderView() {
  const isTree = state.view === 'tree';
  $('table-view-root').hidden = isTree;
  $('tree-view-root').hidden = !isTree;
  $('tree-actions').hidden = !isTree;
  $('view-table').setAttribute('aria-pressed', String(!isTree));
  $('view-tree').setAttribute('aria-pressed', String(isTree));
  $('clear-query').hidden = !state.q;
}

function render() {
  renderSelectionBar();
  if (state.view === 'tree') tree.render();
  else renderTable();
}

function reload() {
  filters.renderRuns();
  filters.renderChips();
  renderSortHeaders();
  renderView();
  if (state.view === 'tree') tree.load();
  else loadTable();
}

/* -- Events ---------------------------------------------------------------- */

delegate($('rows'), 'click', '.file-trigger', (event, trigger) => toggleExpanded(trigger.dataset.fileId));

// Clicking anywhere else on the row opens it too, as the previous table did.
delegate($('rows'), 'click', '.file-row', (event, row) => {
  if (event.target.closest('button, input, a')) return;
  const trigger = row.querySelector('.file-trigger');
  if (trigger) toggleExpanded(trigger.dataset.fileId);
});

for (const header of document.querySelectorAll('.sort-btn')) {
  on(header, 'click', () => {
    if (header.disabled) {
      toast('Select the matching engine run first', 'error');
      return;
    }
    const column = header.dataset.sort;
    if (state.sort === column) state.direction = state.direction === 'desc' ? 'asc' : 'desc';
    else {
      state.sort = column;
      state.direction = ['combined', 'priority', 'jev', 'size', 'modified'].includes(column) ? 'desc' : 'asc';
    }
    commit({ sort: state.sort, direction: state.direction });
  });
}

on($('query'), 'input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => commit({ q: $('query').value }), 250);
});

on($('clear-query'), 'click', () => {
  $('query').value = '';
  commit({ q: '' });
  $('query').focus();
});

on($('view-table'), 'click', () => commit({ view: 'table' }, { keepPage: true }));
on($('view-tree'), 'click', () => commit({ view: 'tree' }, { keepPage: true }));

on($('select-page'), 'change', () => {
  const checked = $('select-page').checked;
  for (const item of page.items) {
    if (checked) selection.set(item.id, item);
    else selection.delete(item.id);
  }
  render();
});

on($('clear-selection'), 'click', () => {
  selection.clear();
  render();
});

on($('download-selection'), 'click', async () => {
  busy = true;
  renderSelectionBar();
  const stats = await downloadRows([...selection.values()], (message) => {
    $('selection-size').textContent = message;
  });
  busy = false;
  toast(`${fmt.count(stats.total - stats.failed)} downloads started${stats.failed ? ` · ${stats.failed} failed` : ''}`, stats.failed ? 'error' : 'ok');
  render();
});

on($('queue-selection'), 'click', () => queue([...selection.values()], 'Explore selection'));
on($('select-percent'), 'click', openPercentageDialog);

on($('previous'), 'click', () => commit({ page: String(Math.max(1, Number(state.page) - 1)) }, { keepPage: true, push: true }));
on($('next'), 'click', () => commit({ page: String(Number(state.page) + 1) }, { keepPage: true, push: true }));

on($('expand-tree'), 'click', () => tree.expandAll());
on($('collapse-tree'), 'click', () => tree.collapseAll());
on($('show-updates'), 'click', () => reload());

on(document, 'keydown', (event) => {
  if (event.key !== '/' || ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) return;
  if (document.querySelector('dialog[open]')) return;
  event.preventDefault();
  $('query').focus();
  $('query').select();
});

onPopState(() => {
  Object.assign(state, readParams({ ...DEFAULTS, ranking_run: AUTO }));
  $('query').value = state.q;
  reload();
});

/* -- Boot ------------------------------------------------------------------ */

async function pollStatus() {
  try {
    const latest = await json('/api/status');
    const changed =
      JSON.stringify((latest.ranking_runs || []).map((run) => [run.id, run.status, run.file_count])) !==
        JSON.stringify(runs.ranking.map((run) => [run.id, run.status, run.file_count])) ||
      JSON.stringify((latest.jev_runs || []).map((run) => [run.id, run.status, run.total_observed])) !==
        JSON.stringify(runs.jev.map((run) => [run.id, run.status, run.total_observed]));
    // Captures are "new" when the scanner committed anything since the view
    // was last loaded. The inventory-wide size minus a filtered page total is
    // not a count of new captures — it is a count of hidden files.
    const fresh = lastRevision !== null && Number(latest.revision) > lastRevision;
    status = latest;
    renderShellStatus(shell, latest);
    $('pending-updates').hidden = !(changed || fresh);
    $('pending-label').textContent = changed ? 'New rankings available' : 'New captures available';
  } catch {
    /* Polling failures are surfaced by the actions that need the data. */
  }
}

async function boot() {
  status = await json('/api/status');
  lastRevision = Number.isInteger(status.revision) ? status.revision : null;
  renderShellStatus(shell, status);
  fill($('search-icon'), icon('search'));
  fill($('clear-query'), icon('close'));
  fill($('mode-badge'), el('span', undefined, status.retrieval_enabled ? 'Live retrieval from SMB' : 'Offline metadata only'));
  runs.ranking = status.ranking_runs || [];
  runs.jev = status.jev_runs || [];
  $('query').value = state.q;
  renderView();
  reload();
  json('/api/facets')
    .then((value) => {
      facets = value;
    })
    .catch(() => {
      /* Facets only populate the filter panel; the table stays usable. */
    });
  setInterval(pollStatus, 4000);
}

boot().catch((error) => {
  shellError(shell, error.message);
  errorLine($('error-banner'), `${error.message} — check the Shrawler server is still running.`);
  $('summary').textContent = 'Inventory unavailable';
});