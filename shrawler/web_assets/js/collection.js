// Collection queue, file families, and review decisions.
//
// Shared by both engines and by the Explore screen: every collection in the
// application is a saved manifest, so caps, retry, and per-file outcomes
// behave identically no matter where the selection was made. Single analyst,
// so no attribution anywhere.

import { button, clear, el, field, fill, fmt, json, number, on, option, post, select } from './core.js';
import { panel, toast } from './overlay.js';

const QUEUE_CEILING = 10000;
const FAMILY_PAGE = 100;

export function createCollection(root) {
  const ctx = { status: {}, fail() {}, clearError() {} };
  const nodes = {};
  const selected = new Set();
  const listeners = [];
  let manifests = [];
  let scans = [];
  let source = { run: '', category: '', minScore: 0 };
  let familyScan = '';
  let familyOffset = 0;

  const notify = () => listeners.forEach((listener) => listener());

  async function mount(context) {
    Object.assign(ctx, context);
    buildQueue();
    buildFamiliesPanel();
    try {
      // The scan list is shared with the rule tab's run form; one fetch here
      // keeps the module independent of the tab that happens to be visible.
      const catalog = await json('/api/triage/catalog');
      scans = catalog.scans || [];
      fill(nodes.familyScan, ...scans.map((item) => option(item.id, `${item.short_id} · ${item.status} · ${fmt.count(item.file_count)} files`)));
      await refresh();
    } catch (error) {
      ctx.fail(error.message);
    }
  }

  /* -- Queue --------------------------------------------------------------- */

  function buildQueue() {
    nodes.manifest = select([]);
    nodes.name = el('input', 'input');
    nodes.name.value = 'Selected candidates';
    nodes.name.maxLength = 200;
    nodes.fileLimit = number(52428800, 1);
    nodes.fileLimit.classList.add('input--bytes');
    nodes.totalLimit = number(524288000, 1);
    nodes.totalLimit.classList.add('input--bytes');
    nodes.status = el('p', 'panel__hint');
    nodes.items = el('tbody');

    const controls = el('div', 'field-grid');
    fill(
      controls,
      field('Saved manifest', nodes.manifest),
      field('Name for new manifests', nodes.name),
      field('Per-file limit (bytes)', nodes.fileLimit),
      field('Total limit (bytes)', nodes.totalLimit),
    );
    const actions = el('div', 'btn-row');
    fill(
      actions,
      button('Save selected candidates', { onClick: () => create([...selected]) }),
      button('Add all matching', { onClick: () => create() }),
      button('Add all with supporting evidence', {
        title: 'Candidates with a positive ranking score; excludes zero-score extension-only matches',
        onClick: () => create(undefined, true),
      }),
      button('Refresh', { size: 'sm', onClick: () => refresh() }),
      button('Export manifest', { size: 'sm', onClick: () => exportManifest() }),
      button('Collect / retry failed files', { variant: 'primary', onClick: () => run() }),
    );

    const table = el('table', 'data-grid score-grid');
    fill(
      table,
      el(
        'thead',
        {},
        el(
          'tr',
          {},
          el('th', undefined, 'Source path'),
          el('th', 'numeric', 'Expected bytes'),
          el('th', undefined, 'Reasons'),
          el('th', undefined, 'Outcome'),
          el('th', undefined, 'Evidence / error'),
        ),
      ),
      nodes.items,
    );
    const { node } = panel(
      'Collection queue',
      'One story: byte caps, a saved manifest, retry, and a per-file outcome.',
      [controls, actions, nodes.status, el('div', 'grid-shell score-grid-shell', table)],
    );
    fill(root, node);
    on(nodes.manifest, 'change', renderManifest);
  }

  async function refresh(preferred) {
    const payload = await json('/api/collection');
    manifests = payload.items || [];
    const chosen = preferred || nodes.manifest.value;
    fill(nodes.manifest, ...manifests.map((item) => option(item.id, `${item.name} · ${fmt.stamp(item.created_at)}`)));
    if (manifests.some((item) => item.id === chosen)) nodes.manifest.value = chosen;
    renderManifest();
  }

  function renderManifest() {
    clear(nodes.items);
    const manifest = manifests.find((item) => item.id === nodes.manifest.value);
    nodes.status.textContent = manifest
      ? `${fmt.count(manifest.expected_files)} planned files · ${fmt.bytes(manifest.expected_bytes)} expected · ${fmt.bytes(manifest.consumed_bytes)} received · limits ${fmt.bytes(manifest.max_file_size)} per file and ${fmt.bytes(manifest.max_total_bytes)} total. Previously collected files are skipped; status does not establish freshness.${
          ctx.status.retrieval_enabled ? '' : ' Offline session: retrieval disabled.'
        }`
      : 'No saved manifests yet. Select candidates on the Rule ranking tab, or use a percentage action on Explore.';
    if (!manifest) return;
    for (const item of manifest.items) nodes.items.append(manifestRow(item));
    if (!manifest.items.length) {
      const row = el('tr');
      const cell = el('td', 'empty', 'This manifest has no eligible files.');
      cell.colSpan = 5;
      row.append(cell);
      nodes.items.append(row);
    }
  }

  function manifestRow(item) {
    const outcome = el('span', 'outcome-chip');
    outcome.dataset.status = String(item.status).replaceAll('_', '-');
    outcome.textContent = String(item.status).replaceAll('_', ' ');
    const cell = el('td');
    cell.append(outcome);
    if (item.attempts?.length) cell.append(el('p', 'panel__hint', `${item.attempts.length} attempt${item.attempts.length === 1 ? '' : 's'}`));
    return el(
      'tr',
      {},
      el('td', 'score-path', item.unc_path),
      el('td', 'numeric size-value', fmt.count(item.size_bytes)),
      el('td', 'score-reasons', item.reasons.join('; ') || 'No additional notes'),
      cell,
      el('td', 'score-path', item.error || item.local_path || '—'),
    );
  }

  async function create(fileIds, requireScore = false) {
    try {
      if (!source.run || source.run === '__preview') throw new Error('Select a saved rule ranking first.');
      if (fileIds && !fileIds.length) throw new Error('Select candidates from the ranking first.');
      const manifest = await post('/api/collection/create', {
        run_id: source.run,
        category: source.category || null,
        min_score: requireScore ? Math.max(1, source.minScore) : source.minScore,
        limit: QUEUE_CEILING,
        name: nodes.name.value || 'Collection',
        max_file_size: Number(nodes.fileLimit.value),
        max_total_bytes: Number(nodes.totalLimit.value),
        ...(fileIds ? { file_ids: fileIds.slice(0, QUEUE_CEILING) } : {}),
      });
      ctx.clearError();
      await refresh(manifest.id);
      toast(`Saved ${manifest.name} · ${fmt.count(manifest.expected_files)} files to collect`);
      return manifest;
    } catch (error) {
      ctx.fail(error.message);
      return null;
    }
  }

  async function run() {
    const id = nodes.manifest.value;
    if (!id) return;
    nodes.status.textContent = 'Collecting exact paths from SMB. Outcomes are saved after each file.';
    try {
      await post('/api/collection/run', { id });
      ctx.clearError();
      await refresh(id);
    } catch (error) {
      ctx.fail(error.message);
      renderManifest();
    }
  }

  function exportManifest() {
    const manifest = manifests.find((item) => item.id === nodes.manifest.value);
    if (!manifest) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(manifest, null, 2)], { type: 'application/json' }));
    const link = el('a');
    link.href = url;
    link.download = `collection-${manifest.id}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  /* -- Families and review decisions --------------------------------------- */

  function buildFamiliesPanel() {
    nodes.familyScan = select([]);
    nodes.undoId = number('', 1);
    nodes.undoId.classList.add('input--num');
    nodes.familiesStatus = el('p', 'panel__hint');
    nodes.families = el('div', 'family-list');

    const controls = el('div', 'field-grid');
    fill(controls, field('Scan', nodes.familyScan), field('Review event ID to undo', nodes.undoId));
    const actions = el('div', 'btn-row');
    fill(
      actions,
      button('Build families', { onClick: () => buildFamilies() }),
      button('Refresh families', { onClick: () => loadFamilies() }),
      button('Previous', { size: 'sm', onClick: () => stepFamilies(-FAMILY_PAGE) }),
      button('Next', { size: 'sm', onClick: () => stepFamilies(FAMILY_PAGE) }),
      button('Find duplicates in local collection', { onClick: () => findDuplicates() }),
      button('Undo decision', { size: 'sm', onClick: () => undo() }),
    );
    const { node } = panel(
      'File families',
      'Provisional groups by possible numeric dates and versions. Matching names do not prove matching contents. Run a new ranking to apply a decision.',
      [controls, actions, nodes.familiesStatus, nodes.families],
    );
    root.append(node);
  }

  async function loadFamilies() {
    familyScan = nodes.familyScan.value || familyScan || scans.find((item) => item.status === 'completed')?.id || '';
    if (!familyScan) {
      nodes.familiesStatus.textContent = 'Select a scan first.';
      return;
    }
    const payload = await json(`/api/review/families?${new URLSearchParams({ scan: familyScan, offset: String(familyOffset) })}`);
    clear(nodes.families);
    if (!payload.items.length) nodes.families.append(el('p', 'panel__hint', 'No families on this page.'));
    for (const family of payload.items) nodes.families.append(familySection(family));
  }

  function familySection(family) {
    const details = el('details', 'disclosure family');
    const label = `${fmt.count(family.file_count)} files · ${family.representative} · ${family.first_mtime} — ${family.last_mtime}`;
    details.append(el('summary', undefined, label + (family.review ? ` · ${family.review.disposition} (event ${family.review.id})` : '')));
    details.append(reviewControls('family', family.family_id));
    const members = el('div', 'family-members');
    let offset = 0;
    const more = button('Load members', { size: 'sm', onClick: async () => {
      try {
        const page = await json(`/api/review/families?${new URLSearchParams({ scan: familyScan, family: family.family_id, offset: String(offset) })}`);
        for (const item of page.items) {
          const member = el('div', 'family-member');
          member.append(el('p', 'score-path', item.unc_path), reviewControls('file', item.file_id));
          members.append(member);
        }
        offset += page.items.length;
        more.disabled = page.items.length < FAMILY_PAGE;
        more.textContent = 'Load more members';
      } catch (error) {
        ctx.fail(error.message);
      }
    } });
    details.append(members, more);
    return details;
  }

  function reviewControls(scope, target) {
    const wrap = el('div', 'btn-row');
    const disposition = select(['reviewed', 'relevant', 'defer', 'exclude'].map((value) => option(value, value)));
    disposition.setAttribute('aria-label', 'Review disposition');
    const note = el('input', 'input');
    note.placeholder = 'Review note';
    note.maxLength = 4000;
    note.setAttribute('aria-label', 'Review note');
    const save = button(`Save ${scope} decision`, { size: 'sm', onClick: async () => {
      try {
        const event = await post('/api/review/decide', { scope, target, disposition: disposition.value, note: note.value });
        nodes.undoId.value = String(event.event_id);
        nodes.familiesStatus.textContent = `Saved ${scope} decision ${event.event_id}: ${event.disposition}. Run a new ranking to apply it. Existing manifests keep their reviewed selection.`;
        ctx.clearError();
      } catch (error) {
        ctx.fail(error.message);
      }
    } });
    fill(wrap, disposition, note, save);
    return wrap;
  }

  function stepFamilies(delta) {
    familyOffset = Math.max(0, familyOffset + delta);
    loadFamilies().catch((error) => ctx.fail(error.message));
  }

  async function buildFamilies() {
    nodes.familiesStatus.textContent = 'Grouping saved metadata…';
    try {
      const result = await post('/api/review/build', { scan_id: nodes.familyScan.value || null });
      familyScan = result.scan_id;
      familyOffset = 0;
      await loadFamilies();
      nodes.familiesStatus.textContent = `${fmt.count(result.files)} files in ${fmt.count(result.families)} provisional families.`;
    } catch (error) {
      ctx.fail(error.message);
    }
  }

  async function undo() {
    try {
      await post('/api/review/undo', { event_id: Number(nodes.undoId.value) });
      nodes.familiesStatus.textContent = 'Decision undone. Run a new ranking to apply the change.';
      await loadFamilies();
    } catch (error) {
      ctx.fail(error.message);
    }
  }

  async function findDuplicates() {
    nodes.familiesStatus.textContent = 'Hashing locally collected evidence…';
    try {
      const result = await post('/api/review/hashes', {});
      clear(nodes.families);
      nodes.families.append(el('pre', 'code-block', JSON.stringify(result.duplicates, null, 2)));
      nodes.familiesStatus.textContent = `${fmt.count(result.hashed_files)} local files hashed; ${fmt.count(result.duplicates.length)} confirmed duplicate groups.`;
    } catch (error) {
      ctx.fail(error.message);
    }
  }

  /* -- Public surface ------------------------------------------------------ */

  return {
    mount,
    refresh,
    onChange(listener) {
      listeners.push(listener);
    },
    /** The rule tab publishes which saved ranking the candidates came from. */
    setSource(next) {
      source = { ...source, ...next };
    },
    has(fileId) {
      return selected.has(fileId);
    },
    toggle(fileId, checked) {
      if (checked) selected.add(fileId);
      else selected.delete(fileId);
      notify();
    },
    get size() {
      return selected.size;
    },
    createFromSelection() {
      return create([...selected]);
    },
  };
}