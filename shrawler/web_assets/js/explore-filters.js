// Explore: the filter panel and the engine run selection.
//
// Both live here rather than in explore.js because they answer the same
// question — "which slice of the inventory am I looking at?" — and because the
// active-filter chips have to render identically wherever the state lives.
//
// Run selection is the primitive that expresses "focus on one engine".
// Deselecting the rule run re-weights Combined instead of filtering rows away,
// which is why there is one control row instead of five separate selects.

import { button, clear, el, fill, fmt, icon, on, option, select, writeParams } from './core.js';
import { activityLabel, permissionName } from './actions.js';
import { openPopover } from './overlay.js';

// In-progress runs are selectable: assessed files appear as batches land, so
// the analyst sees useful results before the whole inventory is done.
export const JEV_USABLE = ['completed', 'partial', 'running', 'paused'];

const FIELD_LABELS = {
  host: 'Host',
  share: 'Share',
  extension: 'File type',
  rule: 'Rule',
  triage: 'Triage',
  permission: 'Share-root permission',
  collection: 'Collection state',
  activity: 'Transfer state',
  ranking_category: 'Rank category',
  ranking_min: 'Min rule rating',
  ranking_run: 'Ranking run',
  jev_run: 'AI run',
  q: 'Search',
};

// "No ranking selected" has to be sayable in the URL, because every table state
// survives as a pasted link. An absent parameter cannot carry it: the empty
// string is dropped, so a shared link would silently re-select the newest run and
// show scores the analyst had deliberately turned off.
export const NONE = 'none';

// AUTO is a read-time placeholder meaning "the URL did not say". It is never
// written back, so a load with no ranking named stays distinguishable from one
// that was explicitly deselected.
export const AUTO = 'auto';

const asParam = (value) => (value ? value : NONE);

// The URL query names each facet in the singular because it reads as a value
// ("host=fileserver"); /api/facets returns the plural list for that name. The
// mapping lives here so the two contracts never have to be made to match.
const FACET_KEYS = {
  host: 'hosts',
  share: 'shares',
  extension: 'extensions',
  rule: 'rules',
  triage: 'triages',
  permission: 'permissions',
  collection: 'collections',
  activity: 'activities',
};

const GROUPS = [
  ['Source', ['host', 'share', 'extension']],
  ['Evidence', ['rule', 'triage']],
  ['Access', ['permission']],
  ['Activity', ['collection', 'activity']],
  ['Score', ['ranking_category', 'ranking_min']],
];

const FILTER_KEYS = [
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
];

export function createFilters({ root, state, defaults, runs, facets, commit }) {
  let closePopover = null;
  // Guards the one-time "the URL named no run, so pick the newest" decision.
  let resolved = false;

  const aiUsable = () => runs.jev.some((run) => JEV_USABLE.includes(run.status));
  const blending = () => state.blend !== '0' && aiUsable();

  function facetOptions(key) {
    // Keys without a formatter show the facet value verbatim.
    const labels = {
      extension: (value) => (value || '').replace(/^\./, '').slice(0, 5).toUpperCase(),
      permission: permissionName,
      activity: activityLabel,
      collection: (value) => (value === 'collected' ? 'Collected' : 'Not collected'),
    };
    const label = labels[key] || ((value) => value);
    const values =
      key === 'ranking_category'
        ? runs.ranking.find((run) => run.id === state.ranking_run)?.categories || []
        : key === 'ranking_min'
          ? ['75', '50', '25', '1']
          : (facets() || {})[FACET_KEYS[key]] || [];
    return [['', key === 'ranking_min' ? 'Any rating' : 'Any'], ...values.map((value) => [value, label(value)])];
  }

  function filterValue(key) {
    if (key === 'q') return `“${state.q}”`;
    if (key === 'extension') return state.extension.toUpperCase();
    if (key === 'permission') return permissionName(state.permission);
    if (key === 'activity') return activityLabel(state.activity);
    if (key === 'collection') return state.collection === 'collected' ? 'Collected' : 'Not collected';
    if (key === 'ranking_min') return `${state.ranking_min}+`;
    if (key === 'ranking_run' || key === 'jev_run') return 'Selected';
    return state[key];
  }

  function buildPanel(close) {
    const panel = el('div');
    for (const [legend, keys] of GROUPS) {
      const group = el('fieldset', 'popover__group');
      group.append(el('legend', 'popover__legend', legend));
      const grid = el('div', 'filter-grid');
      for (const key of keys) {
        const label = el('label', 'field');
        label.append(el('span', 'field__label', FIELD_LABELS[key]));
        const control = select(facetOptions(key));
        control.value = state[key];
        control.disabled = key.startsWith('ranking_') && !state.ranking_run;
        on(control, 'change', () => {
          close();
          commit({ [key]: control.value });
        });
        label.append(control);
        grid.append(label);
      }
      group.append(grid);
      panel.append(group);
    }
    const foot = el('div', 'btn-row popover__foot');
    foot.append(
      button('Reset filters', {
        size: 'sm',
        onClick: () => {
          close();
          commit(Object.fromEntries(FILTER_KEYS.filter((key) => !['ranking_run', 'jev_run', 'q'].includes(key)).map((key) => [key, ''])));
        },
      }),
    );
    panel.append(foot);
    return panel;
  }

  function renderChips() {
    const chips = [];
    for (const key of FILTER_KEYS) {
      // Run selection has its own controls above the grid, so repeating it as a
      // filter chip would say the same thing twice in two different places.
      if (!state[key] || key === 'ranking_run' || key === 'jev_run') continue;
      const chip = el('span', 'filter-chip');
      fill(chip, el('b', undefined, `${FIELD_LABELS[key]}:`), el('span', undefined, filterValue(key)));
      const remove = el('button');
      remove.type = 'button';
      remove.setAttribute('aria-label', `Remove ${FIELD_LABELS[key].toLowerCase()} filter`);
      remove.append(icon('close'));
      on(remove, 'click', () => commit({ [key]: '' }));
      chip.append(remove);
      chips.push(chip);
    }
    clear(root.chips);
    root.chips.append(...chips);
    root.chips.hidden = chips.length === 0;
    clear(root.toggle);
    fill(root.toggle, icon('filter'), el('span', undefined, chips.length ? `Filters · ${chips.length}` : 'Filters'));
  }

  function toggle() {
    if (closePopover) {
      closePopover();
      closePopover = null;
      root.toggle.setAttribute('aria-expanded', 'false');
      return;
    }
    closePopover = openPopover(root.toggle, buildPanel(shut));
    root.toggle.setAttribute('aria-expanded', 'true');
  }

  function shut() {
    closePopover = null;
    root.toggle.setAttribute('aria-expanded', 'false');
  }

  /* -- Engine run selection ------------------------------------------------ */

  function renderRuns() {
    const completed = runs.ranking.filter((run) => run.status === 'completed');
    fill(root.ranking, option(NONE, 'No ranking selected'), ...completed.map((run) => option(run.id, `${fmt.stamp(run.started_at)} · ${fmt.count(run.file_count)} files`)));
    if (completed.some((run) => run.id === state.ranking_run)) {
      root.ranking.value = state.ranking_run;
    } else if (state.ranking_run === AUTO) {
      // The URL did not name a run, so pick the newest saved one. This runs once
      // the catalog is known: before that there is nothing to pick, and
      // resolving now would record "none" for an inventory that does have runs.
      if (!resolved) {
        resolved = true;
        state.ranking_run = completed.length ? completed[0].id : '';
        root.ranking.value = completed.length ? completed[0].id : NONE;
        write();
        return;
      }
      root.ranking.value = NONE;
    } else {
      // Either the URL said "none" or it named a run that no longer exists.
      // Either way, fall back to nothing rather than quietly ranking by a
      // different run than the link asked for.
      state.ranking_run = '';
      root.ranking.value = NONE;
    }

    const usable = runs.jev.filter((run) => JEV_USABLE.includes(run.status));
    fill(root.jev, option('', 'Latest AI assessment'), ...usable.map((run) => option(run.id, `${fmt.stamp(run.created_at)} · ${fmt.count(run.total_observed)} files · ${run.status}`)));
    if (usable.some((run) => run.id === state.jev_run)) root.jev.value = state.jev_run;
    root.jev.disabled = !blending();
    root.blend.checked = blending();
    root.blend.disabled = !usable.length;

    // Unchecking the blend is the same primitive pointed the other way: no AI
    // run is selected, so Combined is the rule rating on its own.
    const notes = [];
    if (!state.ranking_run) notes.push('rule ratings hidden');
    if (!blending()) notes.push('AI scores not blended');
    if (!notes.length) notes.push('Combined blends both engines');
    root.note.textContent = notes.join(' · ');
  }

  function columnAvailable(column) {
    const rule = !!state.ranking_run;
    const ai = blending();
    if (column === 'priority') return rule;
    if (column === 'jev') return ai;
    if (column === 'combined') return rule || ai;
    return true;
  }

  /** Persist the current selection, spelling "nothing selected" as NONE. */
  function write() {
    writeParams({ ...state, ranking_run: asParam(state.ranking_run) }, defaults);
  }

  on(root.toggle, 'click', toggle);
  on(root.ranking, 'change', () => commit({ ranking_run: root.ranking.value === NONE ? '' : root.ranking.value, ranking_category: '' }));
  on(root.jev, 'change', () => commit({ jev_run: root.jev.value }));
  on(root.blend, 'change', () => commit({ blend: root.blend.checked ? '1' : '0', jev_run: root.blend.checked ? root.jev.value : '' }));

  // Runs are not rendered here: the caller has not loaded the catalog yet, and
  // resolving "the URL named no run" against an empty list would pin the page
  // to "none" before it ever learns there are runs to pick from.
  renderChips();

  return { renderRuns, renderChips, columnAvailable, blending, close: shut, write };
}