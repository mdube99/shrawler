// Selection -> action. Everything that turns a set of files into bytes on disk
// lives here: the per-file detail panel, the percentage target resolver, the
// byte preflight, download, and the collection queue hand-off. It also owns the
// row vocabulary (file type, permission, evidence), because the grid and the
// detail panel both read it. The score vocabulary lives in scores.js.

import {
  api,
  button,
  checkbox,
  clear,
  el,
  field,
  fill,
  fmt,
  icon,
  json,
  on,
  post,
  serverParams,
  severity,
} from './core.js';
import { confirm, dialogShell, openOverlay, toast } from './overlay.js';
import { canPreview, openPreview } from './preview.js';
import { aiScore, combinedScore, COVERAGE, COVERAGE_MARK, ruleScore } from './scores.js';

const SENSITIVE = new Set('.env .pem .key .kdbx .pst .ost .sql .bak .config .conf .ini .yaml .yml .pfx .p12 .kirbi .ccache'.split(' '));
const EXECUTABLE = new Set('.zip .7z .rar .tar .gz .exe .dll .msi .ps1 .bat .cmd .vbs .sh .jar'.split(' '));

// Share-root rights, in the order the API validates and returns them.
export const PERMISSIONS = ['read', 'write', 'add_file', 'add_subdirectory', 'write_dac', 'write_owner'];

export function typeLabel(extension) {
  return (extension || 'file').replace(/^\./, '').slice(0, 5).toUpperCase() || 'FILE';
}

export function typeTag(extension) {
  const tier = SENSITIVE.has(extension) ? 'sensitive' : EXECUTABLE.has(extension) ? 'executable' : 'neutral';
  const node = el('span', 'type-tag', typeLabel(extension));
  node.dataset.tier = tier;
  node.title = `${extension || 'Unknown'} file`;
  return node;
}

export const permissionName = (key) =>
  ({
    read: 'List share root',
    write: 'Write-related access',
    add_file: 'Create files',
    add_subdirectory: 'Create directories',
    write_dac: 'Modify ACL',
    write_owner: 'Change owner',
  })[key] || key;

export function permissionLabel(permissions, key) {
  const rights = ['read', 'write'].includes(key) ? permissions : permissions && permissions.write_rights;
  if (!rights || rights[key] === undefined) return 'Unknown';
  return rights[key] === true ? 'Yes' : 'No';
}

export const activityLabel = (key) =>
  ({
    downloaded: 'Downloaded',
    not_downloaded: 'Not downloaded',
    nemesis_sent: 'Sent to Nemesis',
    not_nemesis_sent: 'Not sent to Nemesis',
    nemesis_failed: 'Nemesis failed',
  })[key] || key;

const NEMESIS = {
  uploaded: 'Sent',
  pending: 'Pending',
  staged: 'Staged',
  retrieving: 'Retrieving',
  uploading: 'Sending',
  unknown: 'Unknown',
  upload_failed: 'Failed',
  retrieval_failed: 'Failed',
  failed: 'Failed',
};

/** A collected file, as a chip. Used by the detail panel. */
function downloadChip(item) {
  if (item.collection_status !== 'collected') return null;
  const count = Number(item.download_count) || 0;
  const chip = el('span', 'chip chip--download', count > 1 ? `Downloaded ${count}×` : 'Downloaded');
  chip.title = item.downloaded_at_utc ? `Downloaded ${fmt.date(item.downloaded_at_utc)}` : 'Downloaded';
  return chip;
}

/** Nemesis delivery state, as a chip. Used by the detail panel. */
function nemesisChip(item) {
  if (!item.nemesis_status) return null;
  const tone = item.nemesis_status === 'uploaded' ? 'sent' : ['failed', 'upload_failed', 'retrieval_failed'].includes(item.nemesis_status) ? 'failed' : 'pending';
  const chip = el('span', `chip chip--${tone}`, `Nemesis ${NEMESIS[item.nemesis_status] || item.nemesis_status}`);
  chip.title = item.nemesis_error || chip.textContent;
  return chip;
}

/* -- Row vocabulary -------------------------------------------------------- */

const QUEUED_STATES = new Set(['pending', 'staged', 'retrieving', 'uploading', 'uploaded']);

/** Downloaded/sent state for the row's status chip. Null when neither. */
function collectionState(item) {
  if (item.collection_status === 'collected') return { key: 'downloaded', label: 'Downloaded' };
  if (item.nemesis_status && QUEUED_STATES.has(item.nemesis_status)) return { key: 'queued', label: 'Sent', title: 'Sent to Nemesis' };
  return null;
}

/**
 * Truncate a path from the middle so its root and its file name both survive,
 * e.g. /Reports/Finance/Payroll/passwords.kdbx → /Reports/…/passwords.kdbx. The
 * full path stays available in the element's tooltip.
 */
export function pathLabel(path) {
  if (!path) return 'Path unavailable';
  const sep = path.includes('\\') ? '\\' : '/';
  const lead = path.startsWith(sep) ? sep : '';
  const parts = path.split(sep).filter(Boolean);
  if (parts.length <= 3) return path;
  return `${lead}${parts[0]}${sep}…${sep}${parts[parts.length - 1]}`;
}

/**
 * A shorter form for narrow rows: drop everything but the last two segments, so
 * the parent directory and the file name survive rather than the root.
 * /Reports/Finance/Payroll/passwords.kdbx → …/Payroll/passwords.kdbx
 */
export function pathTail(path) {
  if (!path) return 'Path unavailable';
  const sep = path.includes('\\') ? '\\' : '/';
  const parts = path.split(sep).filter(Boolean);
  if (parts.length <= 2) return path;
  return `…${sep}${parts.slice(-2).join(sep)}`;
}

export function findingText(item) {
  const matches = item.rule_matches || [];
  if (!matches.length) return 'No findings';
  const names = [...new Set(matches.map((match) => match.rule_name || 'Unnamed rule'))];
  const triages = [...new Set(matches.map((match) => match.triage).filter(Boolean))];
  return `${names.slice(0, 2).join(', ')}${names.length > 2 ? ` +${names.length - 2}` : ''}${triages.length ? ` · ${triages.join(', ')}` : ''}`;
}

/* -- Per-file detail ------------------------------------------------------- */

/** A labelled key/value row: `value` nodes lay out inline in the value cell. */
function kv(label, ...value) {
  return el('div', 'kv', el('dt', 'kv__key', label), el('dd', 'kv__val', ...value));
}

/** A key/value block. One row per div keeps the dl valid and the gap even. */
function kvList(rows) {
  return el('dl', 'kv-table', ...rows);
}

/** A titled section. Headers are what let the eye land on one group at a time. */
function section(modifier, title, ...children) {
  return el('section', `detail-section detail-${modifier}`, el('h3', 'detail-section__title', title), ...children);
}

/** A code path with an optional copy affordance, laid out on one line. */
function pathLine(value, copyLabel) {
  const line = el('div', 'path-line', el('code', undefined, value || 'Path unavailable'));
  if (value) line.append(copyButton(value, copyLabel));
  return line;
}

function copyButton(value, label = 'Copy path') {
  const btn = el('button', 'copy-btn', icon('copy'));
  btn.type = 'button';
  btn.setAttribute('aria-label', label);
  on(btn, 'click', () => copyText(value, btn));
  return btn;
}

function scoreValue(score, scale) {
  // Text must be appended before the scale node: el() defers text children to
  // the end, which would otherwise render "/100" ahead of the number.
  const value = el('div', 'score-card__value', score === null ? '—' : String(score));
  if (score !== null && scale) value.append(el('span', 'score-card__scale', scale));
  return value;
}

/**
 * One score, as a card: the value, its band, and which engine spoke. Colour
 * follows the app contract — Combined owns the severity ramp, Rule and AI each
 * keep their own hue — so the panel teaches the same vocabulary as the grid.
 */
function scoreCard(kind, item, describe) {
  const card = el('div', `score-card score-card--${kind}`);
  card.title = describe[kind](item);
  const label = { combined: 'Overall priority', rule: 'Rule rating', ai: 'AI rating' }[kind];
  const parts = [el('div', 'score-card__label', label)];

  if (kind === 'combined') {
    const score = combinedScore(item);
    const band = severity(score);
    card.dataset.severity = band.band;
    const mark = COVERAGE_MARK[item.combined_coverage];
    parts.push(
      scoreValue(score, '/100'),
      el('div', 'score-card__band', score === null ? 'No rating' : band.label),
      el(
        'div',
        'score-card__source',
        score === null ? 'Select a ranking or AI run' : [COVERAGE[item.combined_coverage] || item.combined_coverage, mark].filter(Boolean).join(' '),
      ),
    );
  } else if (kind === 'rule') {
    const score = ruleScore(item);
    card.dataset.strong = String((score ?? 0) >= 76);
    parts.push(scoreValue(score), el('div', 'score-card__band', item.ranking_run_id ? 'Static rules' : 'No ranking selected'));
  } else {
    const score = aiScore(item);
    card.dataset.strong = String((score ?? 0) >= 3);
    parts.push(
      scoreValue(score, '/4'),
      el('div', 'score-card__band', score === null ? 'Not assessed' : item.jev_priority_name || 'Assessed'),
    );
  }

  fill(card, ...parts);
  return card;
}

function downloadValue(item) {
  const chip = downloadChip(item);
  if (!chip) return [el('span', 'kv__muted', 'No')];
  const note = item.downloaded_at_utc ? el('span', 'kv__note', fmt.date(item.downloaded_at_utc)) : null;
  return [chip, note];
}

function nemesisValue(item) {
  const chip = nemesisChip(item);
  if (!chip) return [el('span', 'kv__muted', 'Not sent')];
  const note = [item.nemesis_updated_at_utc ? fmt.date(item.nemesis_updated_at_utc) : null, item.nemesis_error || item.nemesis_response_id || null]
    .filter(Boolean)
    .join(' · ');
  return [chip, note ? el('span', 'kv__note', note) : null];
}

/**
 * The row-expand detail panel. Shared by the table and the tree so both views
 * describe a file identically.
 */
export function detailPanel(item, ctx) {
  const { status, describe, onDownload, onQueue, onClose } = ctx;
  const panel = el('div', 'detail-panel');
  panel.setAttribute('role', 'region');
  panel.setAttribute('aria-label', `Details for ${item.file_name}`);
  panel.dataset.severity = severity(combinedScore(item)).band;

  const head = el(
    'header',
    'detail-head',
    el(
      'div',
      'detail-identity',
      typeTag(item.extension),
      el(
        'div',
        undefined,
        el('div', 'detail-title', item.file_name),
        el('div', 'detail-subtitle', `${fmt.bytes(item.size_bytes)} · Modified ${fmt.date(item.mtime_utc)}`),
      ),
    ),
    (() => {
      const close = el('button', 'copy-btn', icon('close'));
      close.type = 'button';
      close.setAttribute('aria-label', 'Close file details');
      on(close, 'click', onClose);
      return close;
    })(),
  );

  // The paths and the action buttons are why anyone expands a row: they are what
  // you do once a file matters. They lead the panel in their own band, ahead of
  // the scores.
  const actions = el('div', 'detail-actions');
  // Every control here reaches the environment, so offline the band carries
  // only the explanation. There is no stage-only path in the panel.
  if (status.retrieval_enabled) {
    const previewable = canPreview(item, true);
    const previewButton = button('View file', {
      name: 'eye',
      onClick: () => {
        if (previewable) openPreview(item, (target) => onDownload(target));
        else toast('Preview is not available for this file type', 'error');
      },
    });
    if (!previewable) previewButton.setAttribute('aria-disabled', 'true');
    actions.append(
      previewButton,
      button('Download', {
        name: 'download',
        variant: 'primary',
        onClick: (event) => onDownload(item, event.currentTarget),
      }),
      button('Send to Nemesis', { name: 'upload', onClick: () => onQueue([item]) }),
    );
  } else {
    actions.append(el('span', 'field__hint', 'Offline session: remote retrieval is disabled.'));
  }

  const primary = el(
    'div',
    'detail-primary',
    actions,
    kvList([kv('UNC path', pathLine(item.unc_path, 'Copy UNC path')), kv('Remote path', pathLine(item.remote_path, 'Copy remote path'))]),
  );

  const assessment = section(
    'assessment',
    'Assessment',
    el('div', 'score-cards', scoreCard('combined', item, describe), scoreCard('rule', item, describe), scoreCard('ai', item, describe)),
  );

  const collection = section(
    'collection',
    'Collection',
    kvList([kv('Downloaded', ...downloadValue(item)), kv('Nemesis', ...nemesisValue(item))]),
  );

  const technical = el(
    'details',
    'disclosure detail-technical',
    el('summary', undefined, 'Permissions and scan metadata'),
    kvList([
      kv('Indexed', fmt.date(item.scan_timestamp_utc)),
      kv('Evidence observed', fmt.date(item.metadata_scan_timestamp_utc || item.scan_timestamp_utc)),
      ...PERMISSIONS.map((key) => kv(permissionName(key), permissionLabel(item.permissions, key))),
    ]),
  );

  fill(panel, head, primary, assessment, collection, technical);
  return panel;
}

async function copyText(value, button) {
  try {
    await navigator.clipboard.writeText(value || '');
    fill(button, icon('check'));
    toast(`${(button.getAttribute('aria-label') || 'Copy path').replace(/^Copy /i, '')} copied`);
    setTimeout(() => fill(button, icon('copy')), 1600);
  } catch {
    // No clipboard permission: select the path so the browser's own copy
    // shortcut still works, rather than failing silently.
    const code = button.parentElement && button.parentElement.querySelector('code');
    if (!code) {
      toast('Clipboard unavailable', 'error');
      return;
    }
    const range = document.createRange();
    range.selectNodeContents(code);
    const selection = getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    toast('Clipboard unavailable. Path selected — press Ctrl+C.', 'error');
  }
}

/* -- Row actions ----------------------------------------------------------- */

/** An icon-only button, named for the file so it reads out of context. */
function iconButton(name, label, onClick) {
  const btn = el('button', 'row-action', icon(name));
  btn.type = 'button';
  btn.setAttribute('aria-label', label);
  btn.title = label;
  on(btn, 'click', onClick);
  return btn;
}

/**
 * The row's two actions: Nemesis (primary) and Download. Both reach the
 * environment, so both are disabled offline. A file already downloaded or sent
 * shows a status chip and has its Nemesis button disabled.
 */
export function rowActions(item, ctx) {
  const { status, onDownload, onQueue } = ctx;
  const offline = !status.retrieval_enabled;
  const state = collectionState(item);
  const cluster = [];

  const queue = button('Nemesis', {
    name: 'upload',
    variant: 'primary',
    size: 'sm',
    onClick: () => {
      if (!queue.disabled) onQueue([item]);
    },
  });
  queue.setAttribute('aria-label', `Send ${item.file_name} to Nemesis`);
  if (offline) {
    queue.disabled = true;
    queue.title = 'Remote retrieval is disabled in offline mode';
  } else if (state) {
    queue.disabled = true;
    queue.title = state.key === 'downloaded' ? 'Already downloaded' : 'Already sent to Nemesis';
  } else {
    queue.title = 'Send to Nemesis';
  }

  const download = iconButton('download', `Download ${item.file_name}`, async () => {
    if (download.disabled) return;
    // onDownload() is called without a trigger: its own re-render resets the
    // row, so the button only has to show that work is underway.
    fill(download, el('span', 'spinner spinner--inline'));
    await onDownload(item);
  });
  if (offline) {
    download.disabled = true;
    download.title = 'Remote retrieval is disabled in offline mode';
  }

  if (state) {
    const chip = el('span', `row-status row-status--${state.key}`, state.label);
    chip.title = state.title || state.label;
    cluster.push(chip);
  }
  cluster.push(queue, download);
  return cluster;
}

/* -- Percentage targets ---------------------------------------------------- */

// The queue refuses more than 10,000 files, so the preflight refuses to
// describe a larger selection as if it were actionable.
export const QUEUE_CEILING = 10000;
const PAGE = 500;

/**
 * Resolve a percentage of a ranked set into concrete files.
 *
 * `scope` is either the current filters or the whole scan; `percent` is 1-100.
 * Rows come back ordered by the requested sort, so "top 25% by Combined" means
 * what it says. The walk is bounded by QUEUE_CEILING: a percentage action on a
 * 200,000-file scan is reported as over the ceiling, not silently truncated.
 */
export async function resolveTarget({ params, scope, percent, sortKey, signal }) {
  const query = new URLSearchParams(
    serverParams(params, [
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
      'activity',
    ]),
  );
  if (scope === 'scan') {
    for (const key of [
      'q',
      'host',
      'share',
      'extension',
      'rule',
      'triage',
      'permission',
      'collection',
      'activity',
    ]) {
      query.delete(key);
    }
  }
  query.set('sort', sortKey);
  query.set('direction', 'desc');
  query.set('include_total', '1');
  query.set('per_page', String(PAGE));
  query.set('page', '1');
  const first = await json(`/api/files?${query}`, { signal });
  const total = Number(first.total) || 0;
  const wanted = Math.min(total, Math.ceil((total * percent) / 100));
  const rows = first.items.slice(0, wanted);
  let page = 1;
  while (rows.length < wanted && page * PAGE < wanted) {
    page += 1;
    query.set('page', String(page));
    const next = await json(`/api/files?${query}`, { signal });
    if (!next.items.length) break;
    rows.push(...next.items);
  }
  return {
    total,
    wanted,
    rows: rows.slice(0, wanted),
    overCeiling: wanted > QUEUE_CEILING,
  };
}

/** Describe a target in bytes, because bytes are the consequence of a percentage. */
export function preflight(rows, status) {
  const cap = Number(status.nemesis_max_bytes) || Number(status.download_max_bytes) || 50 * 1024 ** 2;
  let bytes = 0;
  let overCap = 0;
  let biggest = 0;
  for (const row of rows) {
    const size = Number(row.size_bytes) || 0;
    bytes += size;
    biggest = Math.max(biggest, size);
    if (size > cap) overCap += 1;
  }
  return { count: rows.length, bytes, cap, overCap, biggest };
}

/**
 * The preflight read-out. A percentage is an abstraction; this is what it
 * actually costs. Shown before anything commits, because queueing hundreds of
 * files to Nemesis is a real side effect on an engagement.
 */
export function preflightLines(target, plan) {
  const lines = [
    `${fmt.count(plan.count)} of ${fmt.count(target.total)} files · ${fmt.bytes(plan.bytes)}`,
    `largest file ${fmt.bytes(plan.biggest)} · per-file cap ${fmt.bytes(plan.cap)}`,
  ];
  if (plan.overCap) {
    lines.push(
      `${fmt.count(plan.overCap)} file${plan.overCap === 1 ? '' : 's'} exceed the per-file cap and will be skipped`,
    );
  }
  if (target.overCeiling) {
    lines.push(
      `selection exceeds the ${fmt.count(QUEUE_CEILING)}-file queue ceiling; narrow the filters or take a smaller percentage`,
    );
  }
  return lines;
}

/* -- Committing ------------------------------------------------------------ */

export async function downloadRows(rows, onProgress) {
  let failed = 0;
  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    onProgress?.(`Retrieving ${index + 1} of ${rows.length}: ${row.file_name}`, (index / rows.length) * 100);
    try {
      const response = await api(`/api/files/${row.id}/download`);
      const url = URL.createObjectURL(await response.blob());
      const link = el('a');
      link.href = url;
      link.download = row.file_name;
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      row.collection_status = 'collected';
      row.download_count = (Number(row.download_count) || 0) + 1;
      row.downloaded_at_utc = new Date().toISOString();
      // Paced so a large selection does not open hundreds of download prompts
      // in the same tick.
      await new Promise((resolve) => setTimeout(resolve, 120));
    } catch {
      failed += 1;
    }
  }
  return { total: rows.length, failed };
}

/**
 * Queue rows through the collection manifest path. Every collection goes
 * through here so it gets byte caps, a saved manifest, and retry; there is no
 * second, direct-send path.
 */
export async function queueRows(rows, { rankingRun, rankingCategory, name, status }) {
  if (!rankingRun) {
    throw new Error('Sending to Nemesis needs a saved rule ranking. Run one on the Score screen first.');
  }
  if (!rows.length) throw new Error('No files selected.');
  const fileIds = rows.slice(0, QUEUE_CEILING).map((row) => row.id);
  const cap = Number(status.nemesis_max_bytes) || 50 * 1024 ** 2;
  const accepted = await confirm({
    title: `Send ${fmt.count(fileIds.length)} files to Nemesis?`,
    message: 'The manifest is saved before retrieval starts, so it can be re-run and retried from the Score screen.',
    detail: `Per-file cap ${fmt.bytes(cap)} · total cap ${fmt.bytes(cap * 20)} · source ranking ${rankingRun.slice(0, 8)}`,
    confirmLabel: 'Save manifest',
  });
  if (!accepted) return null;
  const manifest = await post('/api/collection/create', {
    run_id: rankingRun,
    category: rankingCategory || null,
    min_score: 0,
    limit: QUEUE_CEILING,
    file_ids: fileIds,
    name: name || 'Explore selection',
    max_file_size: cap,
    max_total_bytes: cap * 20,
  });
  toast(`Saved manifest ${manifest.name} · ${fmt.count(manifest.expected_files)} files to send to Nemesis`);
  return manifest;
}

/* -- Single-file download -------------------------------------------------- */

/**
 * Retrieve one file and hand it to the browser as a download.
 *
 * This is a plain browser download, not a collection: no queue, no manifest, no
 * caps. It is offered only where retrieval is enabled and the analyst is acting
 * on a single file whose size is on screen. Anything that acts on a set goes
 * through queueRows, so every multi-file transfer keeps its caps and retry.
 */
export async function downloadOne(item) {
  const response = await api(`/api/files/${item.id}/download`);
  const url = URL.createObjectURL(await response.blob());
  const link = el('a');
  link.href = url;
  link.download = item.file_name;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  item.collection_status = 'collected';
  item.download_count = (Number(item.download_count) || 0) + 1;
  item.downloaded_at_utc = new Date().toISOString();
  return item.file_name;
}

/* -- Percentage dialog ----------------------------------------------------- */

/**
 * Ask for scope and percentage, then hand the caller a resolved target so it
 * can show the preflight before anything commits. The dialog never performs
 * the action itself: the destination is always an explicit second click.
 */
export function percentageControl({ onApply }) {
  const node = el('div', 'percentage-control');

  const radios = el('div', 'btn-row');
  const filtered = checkbox('Filtered set', true);
  const whole = checkbox('Whole scan');
  for (const [index, node] of [filtered, whole].entries()) {
    node.firstChild.type = 'radio';
    node.firstChild.name = 'percentage-scope';
    node.firstChild.value = index === 0 ? 'filtered' : 'scan';
  }
  radios.append(filtered, whole);
  node.append(field('Act on', radios, 'ranked by Overall'));

  const presets = el('div', 'btn-row');
  const custom = el('input', 'input');
  custom.type = 'number';
  custom.min = '1';
  custom.max = '100';
  custom.placeholder = 'custom';
  custom.setAttribute('aria-label', 'Custom percentage');
  custom.classList.add('input--num');
  on(custom, 'input', () => {
    for (const other of presets.children) other.removeAttribute('aria-pressed');
  });
  for (const value of [10, 25, 50, 100]) {
    const preset = button(`${value}%`, {
      size: 'sm',
      variant: value === 25 ? 'primary' : '',
      onClick: () => {
        for (const other of presets.children) other.removeAttribute('aria-pressed');
        preset.setAttribute('aria-pressed', 'true');
        custom.value = '';
      },
    });
    presets.append(preset);
  }
  const apply = button('Preflight', { name: 'chevron', size: 'sm', variant: 'primary' });
  apply.classList.add('icon-chevron-left');
  on(apply, 'click', () => {
    const raw = custom.value.trim();
    const percent = raw === '' ? 25 : Number(raw);
    if (!Number.isFinite(percent) || percent < 1 || percent > 100) {
      toast('Percentage must be between 1 and 100', 'error');
      return;
    }
    onApply({ scope: whole.firstChild.checked ? 'scan' : 'filtered', percent });
  });
  presets.append(custom);
  node.append(field('Top', presets));
  node.append(apply);
  return node;
}

/**
 * The whole percentage flow: scope and percentage inputs, the byte preflight,
 * then an explicit destination. The dialog never commits on its own — the
 * preflight is shown first and the destination is always a second click,
 * because queueing hundreds of files to Nemesis is a real side effect.
 */
export function percentageDialog({ params, sortKey, sortName, status, rankingRun, rankingCategory, onDone }) {
  const report = el('div', 'preflight');
  const handle = openOverlay(
    dialogShell({
      title: 'Act on a percentage',
      subtitle: 'Percentages resolve to files and bytes before anything is committed.',
      body: [percentageControl({ onApply: resolve }), report],
      footer: el('span', 'field__hint', `Ranked by ${sortName} unless another sort is active.`),
      onClose: () => handle.close(),
    }).node,
  );
  const SCOPE = { filtered: 'filtered set', scan: 'whole scan' };

  async function resolve({ scope, percent }) {
    const where = SCOPE[scope] || SCOPE.filtered;
    clear(report);
    fill(report, el('span', 'spinner'), el('span', 'field__hint', `Resolving the top ${percent}% of the ${where}…`));
    try {
      const target = await resolveTarget({ params, scope, percent, sortKey });
      const plan = preflight(target.rows, status);
      clear(report);
      for (const line of preflightLines(target, plan)) report.append(el('p', undefined, line));
      if (target.overCeiling) {
        report.append(el('p', 'field__hint', 'Narrow the filters or take a smaller percentage to act on this set.'));
        return;
      }
      const offline = status.retrieval_enabled === false;
      const progress = el('p', 'field__hint');
      const downloadButton = button('Download', {
        size: 'sm',
        onClick: async () => {
          const stats = await downloadRows(target.rows, (message) => {
            progress.textContent = message;
          });
          toast(
            `${fmt.count(stats.total - stats.failed)} downloads started${stats.failed ? ` · ${stats.failed} failed` : ''}`,
            stats.failed ? 'error' : 'ok',
          );
          handle.close();
          onDone?.();
        },
      });
      const nemesisButton = button('Send to Nemesis', {
        size: 'sm',
        variant: 'primary',
        onClick: async () => {
          const manifest = await queueRows(target.rows, {
            rankingRun,
            rankingCategory,
            name: `Top ${percent}% of the ${where}`,
            status,
          });
          if (manifest) {
            handle.close();
            onDone?.();
          }
        },
      });
      // Both destinations reach the environment, so offline neither is offered.
      if (offline) {
        for (const control of [downloadButton, nemesisButton]) {
          control.disabled = true;
          control.title = 'Remote retrieval is disabled in offline mode';
        }
      }
      report.append(el('div', 'btn-row', downloadButton, nemesisButton), progress);
      if (offline) report.append(el('p', 'field__hint', 'Offline session: remote retrieval is disabled.'));
    } catch (error) {
      clear(report);
      report.append(el('p', 'field__hint', error.message));
    }
  }

  return handle;
}