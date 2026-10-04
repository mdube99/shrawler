// Core primitives. Every other module imports from here; nothing here imports
// from a screen module. Owns DOM construction, HTTP, formatting, URL state, a
// tiny observable store, and the shared application shell.

// The bearer token arrives in the fragment so it never lands in a server log or
// a Referer header, then the fragment is scrubbed from the visible URL.
const fragment = new URLSearchParams(location.hash.slice(1));
export const token = fragment.get('token') || '';
if (fragment.has('token')) history.replaceState(null, '', location.pathname + location.search);

/* -- DOM ------------------------------------------------------------------- */

/**
 * Create an element. Children are always appended as nodes or assigned as text;
 * nothing is ever parsed as markup. Any number of children may be passed, which
 * removes the need to reach for fill() at every call site.
 */
export function el(tag, className, ...children) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  let text = '';
  for (const child of children.flat()) {
    if (child === undefined || child === null || child === false) continue;
    if (child instanceof Node) node.append(child);
    else text += String(child);
  }
  if (text) node.append(document.createTextNode(text));
  return node;
}

export function on(target, type, handler, options) {
  target.addEventListener(type, handler, options);
  return () => target.removeEventListener(type, handler, options);
}

/** One listener on a container, dispatched by selector. Used for grids and rows. */
export function delegate(root, type, selector, handler) {
  return on(root, type, (event) => {
    const match = event.target.closest(selector);
    if (match && root.contains(match)) handler(event, match);
  });
}

export function clear(node) {
  node.replaceChildren();
  return node;
}

/** Replace a node's children in one shot. */
export function fill(node, ...children) {
  node.replaceChildren(...children.flat().filter(Boolean));
  return node;
}

export function option(value, label) {
  const node = el('option', undefined, label);
  node.value = value;
  return node;
}

// Inline path geometry beats an SVG sprite: one source of truth, no duplicated
// <symbol> block in both documents, and icons inherit currentColor for free.
const PATHS = {
  network: ['M5 7.5h14M7.5 5v5m9-5v5M12 7.5V14m-7 0h5v5H5zm9 0h5v5h-5z'],
  search: ['M10.5 4a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13z', 'm15.5 15.5 5 5'],
  close: ['m6 6 12 12M18 6 6 18'],
  check: ['m5 12 4 4L19 6'],
  chevron: ['m9 6 6 6-6 6'],
  'chevron-left': ['m15 6-6 6 6 6'],
  'chevron-down': ['m6 9 6 6 6-6'],
  file: ['M6 3h8l4 4v14H6z', 'M14 3v5h5'],
  folder: ['M3 6h7l2 2h9v11H3z'],
  server: ['M3 4h18v6H3z', 'M3 14h18v6H3z', 'M7 7h.01M7 17h.01'],
  share: ['M18 5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z', 'M6 12a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z', 'M18 19a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z', 'm8.3 10.8 7.4-4.4m-7.4 6.8 7.4 4.4'],
  eye: ['M2.5 12S6 6 12 6s9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6z', 'M12 9.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5z'],
  download: ['M12 3v12m-5-5 5 5 5-5', 'M5 21h14'],
  upload: ['M12 17V3m-5 5 5-5 5 5', 'M5 21h14'],
  copy: ['M8 8h11v11H8z', 'M16 8V5H5v11h3'],
  table: ['M3 4h18v16H3z', 'M3 9h18M9 9v11'],
  tree: ['M6 4v12m0-8h6m-6 8h6', 'M12 5h8v6h-8z', 'M12 13h8v6h-8z'],
  filter: ['M3 5h18l-7 8v6l-4 2v-8z'],
  alert: ['M12 3 2.5 20h19z', 'M12 9v5m0 3h.01'],
  refresh: ['M20 12a8 8 0 1 1-2.4-5.7', 'M20 4v4h-4'],
  shield: ['M12 3 5 5.5v6c0 4.7 2.8 8 7 9.5 4.2-1.5 7-4.8 7-9.5v-6z', 'm9 12 2 2 4-4'],
  clock: ['M12 4a8 8 0 1 0 0 16 8 8 0 0 0 0-16z', 'M12 8v4l3 2'],
  plus: ['M12 5v14M5 12h14'],
  minus: ['M5 12h14'],
};

export function icon(name) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  for (const d of PATHS[name] || PATHS.file) {
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', d);
    svg.append(path);
  }
  return svg;
}

export function button(label, options = {}) {
  const { name, variant = '', size = '', onClick, type = 'button', title } = options;
  const classes = ['btn', variant && `btn--${variant}`, size && `btn--${size}`];
  const node = el('button', classes.filter(Boolean).join(' '));
  node.type = type;
  if (title) node.title = title;
  if (name) node.append(icon(name));
  node.append(el('span', undefined, label));
  if (onClick) on(node, 'click', onClick);
  return node;
}

export function field(label, control, hint) {
  const wrap = el('label', 'field');
  wrap.append(el('span', 'field__label', label), control);
  if (hint) wrap.append(el('span', 'field__hint', hint));
  return wrap;
}

export function select(options = []) {
  const node = el('select', 'select');
  fill(node, options.map(([value, label]) => option(value, label)));
  return node;
}

export function checkbox(label, checked = false) {
  const wrap = el('label', 'checkbox');
  const input = el('input');
  input.type = 'checkbox';
  input.checked = checked;
  wrap.append(input, el('span', undefined, label));
  return wrap;
}

export function number(value, min = 0) {
  const node = el('input', 'input');
  node.type = 'number';
  node.min = String(min);
  node.value = String(value);
  return node;
}

/* -- HTTP ------------------------------------------------------------------ */

export async function api(path, { method = 'GET', body, signal } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    // The server requires this header on every write, so cross-origin form
    // posts cannot reach the API.
    headers['X-Shrawler-Request'] = '1';
  }
  const response = await fetch(path, {
    method,
    headers,
    signal,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      message = (await response.json()).error || message;
    } catch {
      /* Non-JSON error body: keep the status message. */
    }
    throw new Error(message);
  }
  return response;
}

export async function json(path, options) {
  return (await api(path, options)).json();
}

export async function post(path, body) {
  return json(path, { method: 'POST', body });
}

/* -- Formatting ------------------------------------------------------------ */

const NUMBER = new Intl.NumberFormat();
const DATE = new Intl.DateTimeFormat(undefined, {
  year: 'numeric',
  month: 'short',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
});

export const fmt = {
  count(value) {
    return NUMBER.format(Number(value) || 0);
  },
  bytes(value) {
    const size = Number(value) || 0;
    if (size < 1024) return `${size} B`;
    const units = ['KB', 'MB', 'GB', 'TB'];
    let amount = size;
    let unit = -1;
    do {
      amount /= 1024;
      unit += 1;
    } while (amount >= 1024 && unit < units.length - 1);
    return `${amount >= 10 ? amount.toFixed(0) : amount.toFixed(1)} ${units[unit]}`;
  },
  date(value) {
    if (!value) return 'Unknown';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : DATE.format(date);
  },
  /** Run timestamps arrive as full ISO strings; selectors only need the part
   * that tells one run from another. */
  stamp(value) {
    return String(value || '').replace('T', ' ').replace(/(\+00:00|Z)$/, '').slice(0, 16);
  },
  duration(seconds) {
    const total = Math.max(0, Math.round(Number(seconds) || 0));
    if (total < 60) return `${total}s`;
    const minutes = Math.floor(total / 60);
    return `${minutes}m ${String(total % 60).padStart(2, '0')}s`;
  },
  percent(value) {
    const amount = Number(value) || 0;
    return `${amount >= 10 ? amount.toFixed(0) : amount.toFixed(1)}%`;
  },
};

/* -- Severity -------------------------------------------------------------- */

const BANDS = [
  [76, 'immediate', 'Immediate'],
  [51, 'strong', 'Strong'],
  [26, 'likely', 'Likely'],
  [0, 'minimal', 'Minimal'],
];

/** Map a 0-100 score onto the four-band ramp. null means "no result yet". */
export function severity(score) {
  if (score === null || score === undefined || Number.isNaN(score)) {
    return { band: 'none', label: 'No score' };
  }
  const value = Number(score);
  const match = BANDS.find(([floor]) => value >= floor);
  return { band: match[1], label: match[2] };
}

/* -- URL state ------------------------------------------------------------- */

/** Read the query string, substituting defaults for absent or blank values. */
export function readParams(defaults) {
  const search = new URLSearchParams(location.search);
  const state = {};
  for (const [key, fallback] of Object.entries(defaults)) {
    const raw = search.get(key);
    state[key] = raw === null || raw === '' ? fallback : raw;
  }
  return state;
}

/**
 * Write state back to the URL, dropping anything still at its default so a
 * shared link stays short and readable. This is the only state store: there is
 * no localStorage copy to desync from what is on screen.
 */
export function writeParams(state, defaults, { replace = true } = {}) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(state)) {
    const text = value === undefined || value === null ? '' : String(value);
    if (text === '' || text === String(defaults[key] ?? '')) continue;
    search.set(key, text);
  }
  const url = `${location.pathname}${search.size ? `?${search}` : ''}`;
  if (url === `${location.pathname}${location.search}`) return;
  if (replace) history.replaceState(null, '', url);
  else history.pushState(null, '', url);
}

/** The server-side slice of the state: everything except pure client concerns. */
export function serverParams(state, keys) {
  const params = new URLSearchParams();
  for (const key of keys) {
    const value = state[key];
    if (value !== undefined && value !== null && value !== '') params.set(key, String(value));
  }
  return params;
}

export function onPopState(handler) {
  return on(window, 'popstate', handler);
}

/* -- Store ----------------------------------------------------------------- */

/** Observable value object. 40 lines, no framework, no magic. */
export function createStore(initial) {
  let value = { ...initial };
  const listeners = new Set();
  return {
    get() {
      return value;
    },
    set(patch) {
      value = { ...value, ...patch };
      for (const listener of listeners) listener(value);
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}

/* -- Shared shell ---------------------------------------------------------- */

/**
 * Build the header. Both screens render the identical chrome from this one
 * function, which is what stops the two pages drifting apart the way their
 * separately declared headers had.
 */
export function mountShell(current) {
  const header = el('header', 'app-header');
  const inner = el('div', 'app-header__inner');

  const brand = el('a', 'brand');
  brand.href = '/';
  brand.setAttribute('aria-label', 'Shrawler file inventory');
  const mark = el('span', 'brand__mark');
  mark.append(icon('network'));
  brand.append(mark, el('span', 'brand__name', 'Shrawler'), el('span', 'brand__scope', 'SMB inventory'));

  const nav = el('nav', 'screen-nav');
  nav.setAttribute('aria-label', 'Screen');
  for (const [href, label] of [['/', 'Explore'], ['/score', 'Score']]) {
    const link = el('a', undefined, label);
    link.href = href + (token ? `#token=${encodeURIComponent(token)}` : '');
    if (href === current) link.setAttribute('aria-current', 'page');
    nav.append(link);
  }

  // One status region with one dot: today's connection dot, status text, and
  // optimization slot were three channels competing for the same corner.
  const status = el('div', 'header-status');
  status.id = 'shell-status';
  status.setAttribute('role', 'status');
  status.setAttribute('aria-live', 'polite');
  status.dataset.tone = 'pending';
  const text = el('span', 'header-status__text', 'Connecting…');
  const note = el('span', 'header-status__note');
  note.hidden = true;
  status.append(el('span', 'header-status__dot'), text, note);

  inner.append(brand, nav, status);
  header.append(inner);
  document.body.prepend(header);
  return { status, text, note };
}

/** Render one line of live inventory state into the shared status region. */
export function renderShellStatus(shell, status) {
  shell.text.textContent = `${fmt.count(status.file_count)} files · ${fmt.count(status.host_count)} hosts`;
  shell.status.dataset.tone = 'ready';
  const optimization = status.index_optimization || {};
  const busy = !['idle', 'completed'].includes(optimization.status);
  shell.note.hidden = !busy;
  shell.note.dataset.tone = optimization.status === 'failed' ? 'error' : 'warn';
  shell.note.textContent = busy
    ? optimization.status === 'failed'
      ? `Index optimization failed · ${optimization.error || 'see terminal'}`
      : optimization.status === 'running'
        ? `Indexing ${optimization.current} · ${optimization.completed}/${optimization.total}`
        : `Index maintenance queued · ${optimization.total} steps`
    : '';
}

export function shellError(shell, message) {
  shell.status.dataset.tone = 'error';
  shell.text.textContent = message;
}