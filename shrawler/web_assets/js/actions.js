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
} from './core.js';
import { confirm, dialogShell, openOverlay, toast } from './overlay.js';
import { canPreview, openPreview } from './preview.js';
import { describe } from './scores.js';

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

export function nemesisText(item) {
  if (!item.nemesis_status) return 'Not sent';
  const label = NEMESIS[item.nemesis_status] || item.nemesis_status;
  const when = item.nemesis_updated_at_utc ? ` · ${fmt.date(item.nemesis_updated_at_utc)}` : '';
  const detail = item.nemesis_error
    ? ` — ${item.nemesis_error}`
    : item.nemesis_response_id
      ? ` · ${item.nemesis_response_id}`
      : '';
  return `${label}${when}${detail}`;
}

/** Collection state chips: downloaded count and Nemesis delivery state. */
export function transferChips(item) {
  const wrap = el('span', 'chip-list');
  if (item.collection_status === 'collected') {
    const count = Number(item.download_count) || 0;
    const chip = el('span', 'chip chip--download', count > 1 ? `Downloaded ${count}×` : 'Downloaded');
    chip.title = item.downloaded_at_utc ? `Downloaded ${fmt.date(item.downloaded_at_utc)}` : 'Downloaded';
    wrap.append(chip);
  }
  if (item.nemesis_status) {
    const tone = item.nemesis_status === 'uploaded' ? 'sent' : ['failed', 'upload_failed', 'retrieval_failed'].includes(item.nemesis_status) ? 'failed' : 'pending';
    const chip = el('span', `chip chip--${tone}`, `Nemesis ${NEMESIS[item.nemesis_status] || item.nemesis_status}`);
    chip.title = item.nemesis_error || chip.textContent;
    wrap.append(chip);
  }
  return wrap;
}

export function findingText(item) {
  const matches = item.rule_matches || [];
  if (!matches.length) return 'No findings';
  const names = [...new Set(matches.map((match) => match.rule_name || 'Unnamed rule'))];
  const triages = [...new Set(matches.map((match) => match.triage).filter(Boolean))];
  return `${names.slice(0, 2).join(', ')}${names.length > 2 ? ` +${names.length - 2}` : ''}${triages.length ? ` · ${triages.join(', ')}` : ''}`;
}

/* -- Per-file detail ------------------------------------------------------- */

function meta(label, value) {
  return el('dl', 'meta', el('dt', undefined, label), el('dd', undefined, value || '—'));
}

/**
 * The row-expand detail panel. Shared by the table and the tree so both views
 * describe a file identically.
 */
export function detailPanel(item, ctx) {
  const { status, onDownload, onQueue, onClose } = ctx;
  const panel = el('div', 'detail-panel');
  panel.setAttribute('role', 'region');
  panel.setAttribute('aria-label', `Details for ${item.file_name}`);

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

  const copy = el('button', 'copy-btn', icon('copy'));
  copy.type = 'button';
  copy.setAttribute('aria-label', 'Copy UNC path');
  on(copy, 'click', () => copyText(item.unc_path, copy));
  const unc = meta('UNC path');
  unc.append(el('div', 'path-line', el('code', undefined, item.unc_path || 'Path unavailable'), copy));
  const paths = el('div', 'detail-paths', unc, meta('Remote path', item.remote_path));

  const evidence = el('div', 'detail-evidence');
  fill(
    evidence,
    meta('Combined priority', ctx.describe.combined(item)),
    meta('Rule Rating', ctx.describe.rule(item)),
    meta('AI Rating', ctx.describe.ai(item)),
    meta('Downloaded', item.collection_status === 'collected' ? `Yes${Number(item.download_count) > 1 ? ` · ${item.download_count}×` : ''}` : 'No'),
    meta('Nemesis', nemesisText(item)),
  );

  // Preview and single-file download need live retrieval. Queueing is always
  // available because it writes a manifest, not the file.
  const actions = el('div', 'detail-actions');
  if (status.retrieval_enabled) {
    const previewable = canPreview(item, true);
    const previewButton = button('View file', {
      name: 'eye',
      size: 'sm',
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
        size: 'sm',
        variant: 'primary',
        onClick: (event) => onDownload(item, event.currentTarget),
      }),
    );
  }
  actions.append(button('Queue for collection', { name: 'upload', size: 'sm', onClick: () => onQueue([item]) }));
  if (!status.retrieval_enabled) {
    actions.append(el('span', 'field__hint', 'Offline session: remote retrieval is disabled.'));
  }

  const technical = el(
    'details',
    'disclosure detail-technical',
    el('summary', undefined, 'Permissions and scan metadata'),
    el(
      'div',
      'detail-meta-grid',
      meta('Indexed', fmt.date(item.scan_timestamp_utc)),
      meta('Evidence observed', fmt.date(item.metadata_scan_timestamp_utc || item.scan_timestamp_utc)),
      ...PERMISSIONS.map((key) => meta(permissionName(key), permissionLabel(item.permissions, key))),
    ),
  );

  fill(panel, head, paths, actions, evidence, technical);
  return panel;
}

async function copyText(value, button) {
  try {
    await navigator.clipboard.writeText(value || '');
    fill(button, icon('check'));
    toast('UNC path copied');
    setTimeout(() => fill(button, icon('copy')), 1600);
  } catch {
    // No clipboard permission: select the path so the browser's own copy
    // shortcut still works, rather than failing silently.
    const range = document.createRange();
    range.selectNodeContents(button.parentElement.querySelector('code'));
    const selection = getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    toast('Clipboard unavailable. Path selected — press Ctrl+C.', 'error');
  }
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
    throw new Error('Queueing needs a saved rule ranking. Run one on the Score screen first.');
  }
  if (!rows.length) throw new Error('No files selected.');
  const fileIds = rows.slice(0, QUEUE_CEILING).map((row) => row.id);
  const cap = Number(status.nemesis_max_bytes) || 50 * 1024 ** 2;
  const accepted = await confirm({
    title: `Queue ${fmt.count(fileIds.length)} files?`,
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
  toast(`Saved manifest ${manifest.name} · ${fmt.count(manifest.expected_files)} files to collect`);
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
  node.append(field('Act on', radios, 'ranked by Combined'));

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
      const progress = el('p', 'field__hint');
      report.append(
        el(
          'div',
          'btn-row',
          button('Download', {
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
          }),
          button('Queue for collection', {
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
          }),
        ),
        progress,
      );
    } catch (error) {
      clear(report);
      report.append(el('p', 'field__hint', error.message));
    }
  }

  return handle;
}