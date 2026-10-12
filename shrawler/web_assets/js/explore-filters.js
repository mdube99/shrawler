// Explore: the filter panel and the engine run selection.
//
// Both live here rather than in explore.js because they answer the same
// question — "which slice of the inventory am I looking at?" — and because the
// active-filter chips have to render identically wherever the state lives.
//
// Every facet is a list. Values the analyst includes are ORed within a facet;
// values they exclude are removed whatever else matches; different facets are
// ANDed. Includes live under the facet's own URL key (`host=a&host=b`) and
// exclusions under `not_` (`not_host=c`), so a filtered view is still a link.
//
// Run selection is the primitive that expresses "focus on one engine".
// Deselecting the rule run re-weights Combined instead of filtering rows away,
// which is why there is one control row instead of five separate selects.

import { button, clear, el, EXCLUDE_PREFIX, FACET_PARAMS, FACETS, fill, fmt, href, icon, on, option, writeParams } from './core.js';
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

// Single-value filters that need a ranking run; they keep their scalar URL keys.
const SCORE_KEYS = ['ranking_category', 'ranking_min'];

// Rendering every host of a large inventory would make the list unusable and
// slow; typing narrows it, which is the expected way to find one.
const LIST_LIMIT = 200;

const VALUE_LABELS = {
  extension: (value) => value.replace(/^\./, '').toUpperCase(),
  permission: permissionName,
  activity: activityLabel,
  collection: (value) => (value === 'collected' ? 'Collected' : 'Not collected'),
  ranking_min: (value) => `${value}+`,
};

const valueLabel = (key, value) => (VALUE_LABELS[key] || String)(value);

export function createFilters({ root, state, defaults, runs, facets, commit, onRunRanking, rankingEnabled }) {
  let closePopover = null;
  let panel = null;
  let activeFacet = FACETS[0];
  let search = '';
  let activeFilterCount = 0;
  let ratingFull = 80;

  const aiUsable = () => runs.jev.some((run) => JEV_USABLE.includes(run.status));

  /**
   * Whether an AI run contributes at all.
   *
   * There is no way to show AI scores without blending them: the server joins
   * the assessment tables only when a run id is passed, and Combined is derived
   * from that join. So "AI on" and "AI in Combined" are one state, and the run
   * selector is the whole control surface for it.
   */
  const aiEnabled = () => state.jev_run !== NONE && aiUsable();

  /* -- Facet state --------------------------------------------------------- */

  const included = (key) => state[key] || [];
  const excluded = (key) => state[EXCLUDE_PREFIX + key] || [];

  function modeOf(key, value) {
    if (included(key).includes(value)) return 'include';
    if (excluded(key).includes(value)) return 'exclude';
    return '';
  }

  /**
   * Put one value into a mode: 'include', 'exclude', '' (neither), or 'only'
   * (the sole include). A value is never both, so switching mode moves it.
   */
  function apply(key, value, mode) {
    const include = included(key).filter((item) => item !== value);
    const exclude = excluded(key).filter((item) => item !== value);
    if (mode === 'include') include.push(value);
    if (mode === 'exclude') exclude.push(value);
    commit({ [key]: mode === 'only' ? [value] : include, [EXCLUDE_PREFIX + key]: exclude });
  }

  function facetValues(key) {
    const known = (facets() || {})[FACET_KEYS[key]] || [];
    // Selected values stay listed even if the inventory no longer has them, so
    // a stale link can still be undone from the panel.
    const selected = [...included(key), ...excluded(key)];
    return [...new Set([...selected, ...known])].filter(Boolean);
  }

  function scoreOptions(key) {
    const values =
      key === 'ranking_category' ? runs.ranking.find((run) => run.id === state.ranking_run)?.categories || [] : ['75', '50', '25', '1'];
    return [['', key === 'ranking_min' ? 'Any rating' : 'Any'], ...values.map((value) => [value, valueLabel(key, value)])];
  }

  function resetPatch() {
    return {
      ...Object.fromEntries(FACET_PARAMS.map((key) => [key, []])),
      ...Object.fromEntries(SCORE_KEYS.map((key) => [key, ''])),
    };
  }

  /* -- Panel --------------------------------------------------------------- */

  /** A control that survives a re-render keeps focus via this key. */
  function focusKey(node, key) {
    node.dataset.focusKey = key;
    return node;
  }

  function counts(key) {
    if (SCORE_KEYS.includes(key)) return state[key] ? [el('span', 'filter-count', '1')] : [];
    const parts = [];
    if (included(key).length) parts.push(el('span', 'filter-count', `+${included(key).length}`));
    if (excluded(key).length) parts.push(el('span', 'filter-count filter-count--exclude', `−${excluded(key).length}`));
    return parts;
  }

  function navigation() {
    const nav = el('div', 'filter-nav');
    nav.setAttribute('role', 'tablist');
    nav.setAttribute('aria-orientation', 'vertical');
    nav.setAttribute('aria-label', 'Filter fields');
    for (const [legend, keys] of GROUPS) {
      nav.append(el('div', 'filter-nav__legend', legend));
      for (const key of keys) {
        const tab = focusKey(el('button', 'filter-nav__item'), `tab:${key}`);
        tab.type = 'button';
        tab.id = `filter-tab-${key}`;
        tab.setAttribute('role', 'tab');
        tab.setAttribute('aria-selected', String(key === activeFacet));
        tab.setAttribute('aria-controls', 'filter-pane');
        tab.tabIndex = key === activeFacet ? 0 : -1;
        tab.append(el('span', 'filter-nav__label', FIELD_LABELS[key]), ...counts(key));
        // A click lands in the value search, ready to type; arrow keys below
        // keep focus on the tabs so keyboard users can keep moving.
        on(tab, 'click', () => select(key, 'search'));
        nav.append(tab);
      }
    }
    // Arrow keys move between fields, as in any vertical tab list.
    on(nav, 'keydown', (event) => {
      if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
      const tabs = [...nav.querySelectorAll('[role="tab"]')];
      const index = tabs.indexOf(document.activeElement);
      if (index < 0) return;
      event.preventDefault();
      const next =
        event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (index + (event.key === 'ArrowDown' ? 1 : -1) + tabs.length) % tabs.length;
      const key = tabs[next].id.replace('filter-tab-', '');
      select(key, `tab:${key}`);
    });
    return nav;
  }

  function select(key, focus) {
    activeFacet = key;
    search = '';
    renderPanel(focus);
  }

  function optionRow(key, value) {
    const mode = modeOf(key, value);
    const label = valueLabel(key, value);
    const row = el('li', `facet-option${mode ? ` facet-option--${mode}` : ''}`);

    const main = focusKey(el('button', 'facet-option__main'), `include:${value}`);
    main.type = 'button';
    main.setAttribute('aria-pressed', String(mode === 'include'));
    main.title = mode === 'include' ? `Stop including ${label}` : `Include ${label}`;
    const mark = el('span', 'facet-option__mark', mode === 'include' ? icon('check') : mode === 'exclude' ? '⊘' : null);
    mark.setAttribute('aria-hidden', 'true');
    main.append(mark, el('span', 'facet-option__label', label));
    if (mode === 'exclude') main.append(el('span', 'facet-option__tag', 'excluded'));
    on(main, 'click', () => apply(key, value, mode === 'include' ? '' : 'include'));

    const exclude = focusKey(el('button', 'facet-option__exclude', icon('minus')), `exclude:${value}`);
    exclude.type = 'button';
    exclude.setAttribute('aria-pressed', String(mode === 'exclude'));
    exclude.setAttribute('aria-label', mode === 'exclude' ? `Stop excluding ${label}` : `Exclude ${label}`);
    exclude.title = exclude.getAttribute('aria-label');
    on(exclude, 'click', () => apply(key, value, mode === 'exclude' ? '' : 'exclude'));

    row.append(main, exclude);
    return row;
  }

  function facetPane(key) {
    const label = FIELD_LABELS[key];
    const include = included(key);
    const exclude = excluded(key);
    const any = include.length + exclude.length > 0;

    const invert = focusKey(button('Invert', { size: 'sm', title: `Swap included and excluded ${label.toLowerCase()} values` }), 'invert');
    invert.disabled = !any;
    on(invert, 'click', () => commit({ [key]: [...exclude], [EXCLUDE_PREFIX + key]: [...include] }));
    const reset = focusKey(button('Clear', { size: 'sm', title: `Clear the ${label.toLowerCase()} filter` }), 'clear');
    reset.disabled = !any;
    on(reset, 'click', () => commit({ [key]: [], [EXCLUDE_PREFIX + key]: [] }));

    const head = el('div', 'filter-pane__head', el('span', 'filter-pane__title', label), el('span', 'btn-row', invert, reset));

    const input = focusKey(el('input', 'input filter-pane__search'), 'search');
    input.type = 'search';
    input.placeholder = `Find ${label.toLowerCase()}…`;
    input.value = search;
    input.setAttribute('aria-label', `Find ${label.toLowerCase()} values`);
    input.setAttribute('aria-controls', 'filter-options');

    const list = el('ul', 'facet-options');
    list.id = 'filter-options';
    list.setAttribute('aria-label', `${label} values`);
    const status = el('p', 'filter-pane__status');
    status.setAttribute('aria-live', 'polite');

    let visible = [];
    function renderList() {
      const needle = search.trim().toLowerCase();
      const values = facetValues(key);
      const matches = values.filter((value) => !needle || `${value} ${valueLabel(key, value)}`.toLowerCase().includes(needle));
      // Selected values lead, so what is active is never scrolled out of view.
      const rank = (value) => ({ include: 0, exclude: 1 })[modeOf(key, value)] ?? 2;
      matches.sort((a, b) => rank(a) - rank(b));
      visible = matches.slice(0, LIST_LIMIT);
      fill(list, ...visible.map((value) => optionRow(key, value)));
      status.textContent = !facets()
        ? 'Loading values…'
        : !values.length
          ? 'No values in this inventory.'
          : !matches.length
            ? 'No values match.'
            : matches.length > visible.length
              ? `Showing ${fmt.count(visible.length)} of ${fmt.count(matches.length)} · keep typing to narrow`
              : '';
    }
    on(input, 'input', () => {
      search = input.value;
      renderList();
    });
    // Enter includes the first match and Shift+Enter excludes it, so a value
    // can be picked without leaving the keyboard.
    on(input, 'keydown', (event) => {
      if (event.key !== 'Enter' || !visible.length) return;
      event.preventDefault();
      const value = visible[0];
      const mode = event.shiftKey ? 'exclude' : 'include';
      search = '';
      apply(key, value, modeOf(key, value) === mode ? '' : mode);
    });
    renderList();

    const hint = el('p', 'field__hint', 'Click a value to include it, or − to exclude it. Several includes match any of them; an excluded value is always hidden. Enter includes the top match, Shift+Enter excludes it.');
    return [head, input, list, status, hint];
  }

  function scorePane(key) {
    const label = FIELD_LABELS[key];
    const items = [el('div', 'filter-pane__head', el('span', 'filter-pane__title', label))];
    if (!state.ranking_run) {
      const hint = el('p', 'field__hint', 'Select a ranking run above to filter by rule rating. ');
      const link = el('a', 'link', 'Rank this inventory');
      link.href = href('/score');
      hint.append(link);
      items.push(hint);
      return items;
    }
    const list = el('ul', 'facet-options');
    list.setAttribute('aria-label', `${label} values`);
    for (const [value, text] of scoreOptions(key)) {
      const chosen = (state[key] || '') === value;
      const row = el('li', `facet-option${chosen ? ' facet-option--include' : ''}`);
      const choice = focusKey(el('button', 'facet-option__main'), `score:${value}`);
      choice.type = 'button';
      choice.setAttribute('aria-pressed', String(chosen));
      const mark = el('span', 'facet-option__mark', chosen ? icon('check') : null);
      mark.setAttribute('aria-hidden', 'true');
      choice.append(mark, el('span', 'facet-option__label', text));
      on(choice, 'click', () => commit({ [key]: value }));
      row.append(choice);
      list.append(row);
    }
    items.push(list);
    return items;
  }

  /** Rebuild the open panel from state, keeping focus on the same control. */
  function renderPanel(focus) {
    if (!panel) return;
    const active = document.activeElement;
    const target = focus || (panel.contains(active) ? active.dataset.focusKey : null);
    const caret = active && active.tagName === 'INPUT' ? active.selectionStart : null;
    const pane = el('div', 'filter-pane');
    pane.id = 'filter-pane';
    pane.setAttribute('role', 'tabpanel');
    pane.setAttribute('aria-labelledby', `filter-tab-${activeFacet}`);
    pane.append(...(FACETS.includes(activeFacet) ? facetPane(activeFacet) : scorePane(activeFacet)));
    const foot = el('div', 'btn-row popover__foot');
    foot.append(
      button('Clear all filters', {
        size: 'sm',
        onClick: () => {
          search = '';
          commit(resetPatch());
        },
      }),
    );
    fill(panel, el('div', 'filter-panel__body', navigation(), pane), foot);
    const next = target && panel.querySelector(`[data-focus-key="${CSS.escape(target)}"]`);
    if (next && !next.disabled) {
      next.focus({ preventScroll: true });
      if (caret !== null && next.tagName === 'INPUT') next.setSelectionRange(caret, caret);
    } else if (target) {
      (panel.querySelector('.filter-pane__search') || panel.querySelector('[role="tab"][aria-selected="true"]'))?.focus({ preventScroll: true });
    }
  }

  function buildPanel() {
    panel = el('div', 'filter-panel');
    renderPanel('search');
    return panel;
  }

  /* -- Chips --------------------------------------------------------------- */

  function chip(name, value, { exclude = false, onRemove, onFlip } = {}) {
    const node = el('span', `filter-chip${exclude ? ' filter-chip--exclude' : ''}`);
    if (onFlip) {
      const flip = el('button', 'filter-chip__sign', icon('swap'));
      flip.type = 'button';
      const label = `${exclude ? 'Include' : 'Exclude'} ${name.toLowerCase()} ${value} instead`;
      flip.setAttribute('aria-label', label);
      flip.title = label;
      on(flip, 'click', onFlip);
      node.append(flip);
    }
    node.append(el('b', undefined, `${name}:`));
    if (exclude) node.append(el('span', 'filter-chip__not', 'not'));
    node.append(el('span', 'filter-chip__value', value));
    const remove = el('button');
    remove.type = 'button';
    remove.setAttribute('aria-label', `Remove ${exclude ? 'exclusion' : 'filter'} ${name.toLowerCase()} ${value}`);
    remove.append(icon('close'));
    on(remove, 'click', onRemove);
    node.append(remove);
    return node;
  }

  function renderChips() {
    const chips = [];
    if (state.q) chips.push(chip(FIELD_LABELS.q, `“${state.q}”`, { onRemove: () => commit({ q: '' }) }));
    for (const key of FACETS) {
      for (const [values, exclude] of [
        [included(key), false],
        [excluded(key), true],
      ]) {
        for (const value of values) {
          chips.push(
            chip(FIELD_LABELS[key], valueLabel(key, value), {
              exclude,
              onRemove: () => apply(key, value, ''),
              onFlip: () => apply(key, value, exclude ? 'include' : 'exclude'),
            }),
          );
        }
      }
    }
    // Run selection has its own controls above the grid, so repeating it as a
    // filter chip would say the same thing twice in two different places.
    for (const key of SCORE_KEYS) {
      if (state[key]) chips.push(chip(FIELD_LABELS[key], valueLabel(key, state[key]), { onRemove: () => commit({ [key]: '' }) }));
    }
    const count = chips.length;
    activeFilterCount = count;
    if (count > 1) chips.push(button('Clear filters', { size: 'sm', variant: 'ghost', onClick: () => commit(resetPatch()) }));
    clear(root.chips);
    root.chips.append(...chips);
    root.chips.hidden = count === 0;
    clear(root.toggle);
    fill(root.toggle, icon('filter'), el('span', undefined, count ? `Filters · ${count}` : 'Filters'));
    renderPanel();
  }

  function toggle() {
    if (closePopover) {
      closePopover();
      shut();
      return;
    }
    closePopover = openPopover(root.toggle, buildPanel());
    root.toggle.setAttribute('aria-expanded', 'true');
    panel.querySelector('.filter-pane__search')?.focus({ preventScroll: true });
    // The popover closes itself on Escape or an outside click; drop the panel
    // reference when it leaves the document so state changes stop re-rendering it.
    const watcher = new MutationObserver(() => {
      if (panel && !panel.isConnected) {
        watcher.disconnect();
        shut();
      }
    });
    watcher.observe(document.body, { childList: true });
  }

  function shut() {
    closePopover = null;
    panel = null;
    root.toggle.setAttribute('aria-expanded', 'false');
  }

  /* -- Engine run selection ------------------------------------------------ */

  function renderRuns() {
    const completed = runs.ranking.filter((run) => run.status === 'completed');
    fill(
      root.ranking,
      option(NONE, 'No ranking selected'),
      ...completed.map((run, index) => option(run.id, `${index === 0 ? 'Latest · ' : ''}${fmt.stamp(run.started_at)} · ${fmt.count(run.file_count)} files`)),
    );
    const namedRule = completed.some((run) => run.id === state.ranking_run);
    if (!namedRule && state.ranking_run === AUTO) {
      // The URL did not name a run, so adopt the newest saved one: Combined then
      // means something on arrival. With no runs yet, stay on AUTO so creating a
      // ranking later selects it automatically instead of pinning the URL to
      // "none" on the first unrelated interaction.
      state.ranking_run = completed.length ? completed[0].id : AUTO;
      if (state.ranking_run !== AUTO) write();
    } else if (!namedRule) {
      // The URL said "none", or named a run that is gone. Fall back to nothing
      // rather than quietly ranking by a different run than the link asked for.
      state.ranking_run = '';
    }
    root.ranking.value = state.ranking_run || NONE;

    const usable = runs.jev.filter((run) => JEV_USABLE.includes(run.status));
    fill(
      root.jev,
      option(NONE, 'No AI run'),
      // "Latest" resolves server-side against the run catalog, so it stays
      // correct as new runs land without the URL having to name one. Offered
      // only once there is something to resolve.
      ...(usable.length ? [option('', 'Latest AI assessment')] : []),
      ...usable.map((run) => option(run.id, `${fmt.stamp(run.created_at)} · ${fmt.count(run.total_observed)} files · ${run.status}`)),
    );
    if (usable.some((run) => run.id === state.jev_run)) {
      root.jev.value = state.jev_run;
    } else if (state.jev_run === '') {
      // Nothing named in the URL and a run exists to fall back to.
      root.jev.value = usable.length ? '' : NONE;
    } else {
      // "none", or a run that is gone. Do not substitute a different run than
      // the link named.
      if (state.jev_run !== NONE) {
        state.jev_run = NONE;
        write();
      }
      root.jev.value = NONE;
    }
    root.jev.disabled = !usable.length;
    const mix = composition();
    if (!runs.ranking.length && !runs.jev.length) {
      // Nothing to select yet. Point at Score, and offer the safe metadata-only
      // ranking right here so the landing page can fill its own score columns.
      const link = el('a', 'link', 'Run a rule ranking');
      link.href = href('/score');
      clear(root.note);
      root.note.append('No scores yet · ', link);
      if (onRunRanking && (rankingEnabled ? rankingEnabled() : true)) {
        root.note.append(
          ' ',
          button('Rank now', {
            size: 'sm',
            variant: 'primary',
            title: 'Rank this inventory with the built-in rules. Metadata only; no file content is read.',
            onClick: (event) => onRunRanking(event.currentTarget),
          }),
        );
      }
    } else {
      root.note.textContent = mix.note;
    }
    // The Combined column header must never claim a blend that is not active.
    if (root.combinedHeader) root.combinedHeader.title = `Overall priority 0–100 · ${mix.header}`;
  }

  /**
   * One line explaining how Combined is currently composed, so the table never
   * leaves the reader guessing why a column is blank. The same truth also
   * drives the Combined header sub-label, which is a fragment rather than a
   * sentence and is appended with the scale.
   */
  function composition() {
    const rule = !!state.ranking_run;
    const ai = aiEnabled();
    if (rule && ai) return { note: 'Overall blends the rule rating and the AI score', header: 'rules and AI' };
    if (rule) return { note: `Overall scales the rule rating so ${ratingFull} = 100 · no AI run selected`, header: 'rules only' };
    if (ai) return { note: 'Overall uses the AI score · no rule rating', header: 'AI only' };
    const anyRuns = runs.ranking.length > 0 || runs.jev.length > 0;
    return {
      note: anyRuns ? 'Overall unavailable · no engine selected' : 'Overall unavailable · no runs saved yet',
      header: '—',
    };
  }

  function columnAvailable(column) {
    const rule = !!state.ranking_run;
    const ai = aiEnabled();
    if (column === 'priority') return rule;
    if (column === 'jev') return ai;
    if (column === 'combined') return rule || ai;
    return true;
  }

  /** Persist the current selection, spelling "nothing selected" as NONE. */
  function write() {
    // AUTO means the URL never named a run; omitting it keeps a later ranking
    // selectable instead of pinning "none" into the link.
    writeParams({ ...state, ranking_run: state.ranking_run === AUTO ? '' : asParam(state.ranking_run) }, defaults);
  }

  on(root.toggle, 'click', toggle);
  on(root.ranking, 'change', () => commit({ ranking_run: root.ranking.value === NONE ? '' : root.ranking.value, ranking_category: '' }));
  on(root.jev, 'change', () => commit({ jev_run: root.jev.value }));

  // Runs are not rendered here: the caller has not loaded the catalog yet, and
  // resolving "the URL named no run" against an empty list would pin the page
  // to "none" before it ever learns there are runs to pick from.
  renderChips();

  return { renderRuns, renderChips, columnAvailable, aiEnabled, compositionHeader: () => composition().header, apply, close: shut, write, activeCount: () => activeFilterCount, clear: () => commit(resetPatch()), setRatingFull: (value) => { ratingFull = Number(value) || 80; } };
}