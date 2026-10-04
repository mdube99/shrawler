// Tree view.
//
// Structure and interaction are frozen per the rewrite decision: same
// hierarchy, same expansion model, same branch fetching, same detail panel,
// same selection, same keyboard handling, same indentation. Only the tokens
// and the row height changed. Two things did change, both consistency fixes
// rather than redesign: jev_run now reaches /api/tree the way it already
// reached its two siblings, and rows inherit the fixed density.

import { clear, el, fill, fmt, icon, json, on } from './core.js';
import { toast } from './overlay.js';

const EXPAND_LIMIT = 5000;

const joinKey = (path) => path.join('\u001f');

function children(type, node) {
  if (type === 'host') return node.shares.map((child) => ['share', child]);
  return [...node.folders.map((child) => ['folder', child]), ...node.files.map((child) => ['file', child])];
}

/**
 * @param {object} options
 * @param {() => URLSearchParams} options.params current filters as a query string
 * @param {Set<string>} options.selection selected file ids
 * @param {(node: HTMLElement) => void} options.onSelect checkbox change
 * @param {(item: object) => HTMLElement} options.detailFor detail panel factory
 */
export function createTree({ root, loadingNode, params, selection, onSelect, scoreFor, detailFor, onSummary }) {
  const cache = new Map();
  const expanded = new Set();
  let data = null;
  let key = '';
  let focusKey = null;
  let selectedId = null;
  let pending = 0;
  let controller = null;
  let expandLimitExceeded = false;

  function currentKey() {
    return params().toString();
  }

  function branchQuery(type, node) {
    const query = new URLSearchParams(params());
    if (type === 'host') query.set('host', node.name);
    else {
      query.set('host', node.host);
      query.set('share', node.share || node.name);
      if (type === 'folder') query.set('parent', node.path);
    }
    return query;
  }

  async function loadBranch(type, node) {
    if (node.loaded) return;
    const payload = await json(`/api/tree/branch?${branchQuery(type, node)}`);
    if (type === 'host') node.shares = payload.shares;
    else {
      node.folders = payload.folders;
      node.files = payload.files;
    }
    node.loaded = true;
  }

  function renderNode(type, node, path, level, position, setSize) {
    const item = el('li', `tree-item level-${Math.min(level, 8)}`);
    item.setAttribute('role', 'none');
    const nodeKey = type === 'file' ? `file:${node.id}` : joinKey(path);
    const line = el('button', `tree-node ${type}`);
    line.type = 'button';
    line.setAttribute('role', 'treeitem');
    line.setAttribute('aria-level', String(level));
    line.setAttribute('aria-posinset', String(position));
    line.setAttribute('aria-setsize', String(setSize));
    line.dataset.key = nodeKey;
    line.dataset.level = String(level);
    line.tabIndex = focusKey === nodeKey ? 0 : -1;

    if (type === 'file') {
      line.classList.toggle('checked', selection.has(node.id));
      const box = el('input', 'file-checkbox');
      box.type = 'checkbox';
      box.checked = selection.has(node.id);
      box.setAttribute('aria-label', `Select ${node.file_name}`);
      on(box, 'click', (event) => event.stopPropagation());
      on(box, 'change', () => onSelect(node, box.checked));
      const label = el('span', 'tree-label tree-label--file');
      label.append(el('span', 'type-tag', (node.extension || 'file').replace(/^\./, '').slice(0, 5).toUpperCase()), el('span', undefined, node.file_name));
      const meta = el('span', 'tree-file-meta');
      fill(meta, scoreFor ? scoreFor(node) : null, el('span', undefined, node.readable_size || fmt.bytes(node.size_bytes)), el('span', undefined, fmt.date(node.mtime_utc)));
      line.append(box, icon('file'), label, meta);
      line.setAttribute('aria-expanded', String(selectedId === node.id));
      on(line, 'click', () => toggleFile(node, nodeKey));
    } else {
      const open = expanded.has(nodeKey);
      const chevron = icon('chevron');
      chevron.classList.add('tree-chevron');
      line.append(chevron);
      const kind = icon(type === 'host' ? 'server' : type === 'share' ? 'share' : 'folder');
      kind.classList.add('tree-kind-icon');
      line.append(
        kind,
        el('span', 'tree-label', node.name),
        el('span', 'tree-count', `${fmt.count(node.file_count)} files · ${fmt.bytes(node.size_bytes)}`),
      );
      line.setAttribute('aria-expanded', String(open));
      on(line, 'click', () => toggleBranch(type, node, nodeKey));
      if (open) {
        const group = el('ul', 'tree-group');
        group.setAttribute('role', 'group');
        const kids = children(type, node);
        kids.forEach(([childType, child], index) =>
          group.append(renderNode(childType, child, [...path, child.name || child.id], level + 1, index + 1, kids.length)),
        );
        item.append(line, group);
        return item;
      }
    }

    item.append(line);
    if (type === 'file' && selectedId === node.id) {
      const details = el('div', 'tree-detail');
      details.id = `tree-details-${node.id}`;
      details.append(detailFor(node));
      item.append(details);
    }
    return item;
  }

  function render() {
    clear(root);
    if (!data || !data.hosts.length) {
      root.append(el('li', 'empty', 'No files match these filters.'));
      return;
    }
    data.hosts.forEach((host, index) =>
      root.append(renderNode('host', host, [`host:${host.name}`], 1, index + 1, data.hosts.length)),
    );
    const focusables = [...root.querySelectorAll('[role="treeitem"]')];
    if (focusables.length && !focusables.some((node) => node.tabIndex === 0)) focusables[0].tabIndex = 0;
  }

  function restoreFocus(selector) {
    requestAnimationFrame(() => document.querySelector(selector)?.focus({ preventScroll: true }));
  }

  async function toggleBranch(type, node, nodeKey) {
    if (expanded.has(nodeKey)) {
      expanded.delete(nodeKey);
      focusKey = nodeKey;
      render();
      return;
    }
    expanded.add(nodeKey);
    focusKey = nodeKey;
    render();
    try {
      await loadBranch(type, node);
      // Re-render after the fetch: the first pass drew the branch empty
      // because its children had not arrived yet.
      render();
    } catch (error) {
      expanded.delete(nodeKey);
      render();
      toast(error.message, 'error');
    }
    restoreFocus(`[data-key="${CSS.escape(nodeKey)}"]`);
  }

  function toggleFile(item, nodeKey) {
    selectedId = selectedId === item.id ? null : item.id;
    focusKey = nodeKey;
    render();
    restoreFocus(`[data-key="${CSS.escape(nodeKey)}"]`);
    if (selectedId) {
      requestAnimationFrame(() => {
        const panel = document.getElementById(`tree-details-${item.id}`);
        if (!panel) return;
        const bottom = panel.getBoundingClientRect().bottom;
        if (bottom > innerHeight) window.scrollBy({ top: bottom - innerHeight + 20, behavior: 'smooth' });
      });
    }
  }

  async function load({ preserveContext = false } = {}) {
    if (controller) controller.abort();
    controller = new AbortController();
    const signal = controller.signal;
    const next = currentKey();
    if (cache.has(next) && !preserveContext) {
      data = cache.get(next);
      key = next;
      selectedId = null;
      render();
      report();
      return;
    }
    loadingNode.hidden = false;
    try {
      const payload = await json(`/api/tree?${next}`, { signal });
      cache.set(next, payload);
      if (cache.size > 8) cache.delete(cache.keys().next().value);
      data = payload;
      key = next;
      if (!preserveContext) expanded.clear();
      render();
      report();
    } catch (error) {
      if (error.name !== 'AbortError') toast(error.message, 'error');
    } finally {
      if (controller && controller.signal === signal) {
        controller = null;
        loadingNode.hidden = true;
      }
    }
  }

  function report() {
    if (!data) return;
    expandLimitExceeded = data.total > EXPAND_LIMIT;
    onSummary?.(`${fmt.count(data.total)} files across ${fmt.count(data.hosts.length)} hosts`, expandLimitExceeded);
  }

  async function expandAll() {
    if (!data || expandLimitExceeded) return;
    const seen = new Set();
    pending = 0;
    const walk = async (type, node, path) => {
      const nodeKey = joinKey(path);
      seen.add(nodeKey);
      pending += 1;
      try {
        await loadBranch(type, node);
      } finally {
        pending -= 1;
      }
      for (const [childType, child] of children(type, node)) {
        if (childType !== 'file') await walk(childType, child, [...path, child.name]);
      }
    };
    try {
      for (const host of data.hosts) await walk('host', host, [`host:${host.name}`]);
      expanded.clear();
      seen.forEach((nodeKey) => expanded.add(nodeKey));
      render();
    } catch (error) {
      toast(error.message, 'error');
    }
  }

  function collapseAll() {
    expanded.clear();
    selectedId = null;
    render();
  }

  function invalidate() {
    cache.clear();
  }

  function keydown(event) {
    const current = event.target.closest('[role="treeitem"]');
    if (!current) return;
    const nodes = [...root.querySelectorAll('[role="treeitem"]')];
    const index = nodes.indexOf(current);
    let target = null;
    if (event.key === 'ArrowDown') target = nodes[Math.min(index + 1, nodes.length - 1)];
    if (event.key === 'ArrowUp') target = nodes[Math.max(index - 1, 0)];
    if (event.key === 'Home') target = nodes[0];
    if (event.key === 'End') target = nodes[nodes.length - 1];
    if (event.key === 'ArrowRight' && current.hasAttribute('aria-expanded')) {
      if (current.getAttribute('aria-expanded') === 'false') current.click();
      else target = nodes[index + 1];
    }
    if (event.key === 'ArrowLeft') {
      if (current.getAttribute('aria-expanded') === 'true' && !current.dataset.key.startsWith('file:')) current.click();
      else {
        const level = Number(current.dataset.level);
        for (let cursor = index - 1; cursor >= 0; cursor -= 1) {
          if (Number(nodes[cursor].dataset.level) < level) {
            target = nodes[cursor];
            break;
          }
        }
      }
    }
    if (target) {
      event.preventDefault();
      current.tabIndex = -1;
      target.tabIndex = 0;
      focusKey = target.dataset.key;
      target.focus();
    } else if (['ArrowRight', 'ArrowLeft'].includes(event.key)) event.preventDefault();
  }

  on(root, 'keydown', keydown);

  return {
    render,
    load,
    expandAll,
    collapseAll,
    invalidate,
    closeDetails() {
      if (selectedId === null) return false;
      selectedId = null;
      render();
      return true;
    },
    get busy() {
      return pending > 0;
    },
  };
}