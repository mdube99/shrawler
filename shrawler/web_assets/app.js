(() => {
  'use strict';

  const fragment = new URLSearchParams(location.hash.slice(1));
  const token = fragment.get('token') || '';
  history.replaceState(null, '', `${location.pathname}${location.search}`);

  const $ = id => document.getElementById(id);
  const previewable = new Set('.txt .log .csv .json .xml .ini .conf .config .cnf .properties .prop .yaml .yml .md .rst .py .js .ts .jsx .tsx .java .cs .go .rs .rb .php .ps1 .bat .cmd .vbs .sh .sql .pem .key .png .jpg .jpeg .gif .webp .pdf'.split(' '));
  const sensitiveTypes = new Set('.env .pem .key .kdbx .pst .ost .sql .bak .config .conf .ini .yaml .yml .pfx .p12 .kirbi .ccache'.split(' '));
  const executableTypes = new Set('.zip .7z .rar .tar .gz .exe .dll .msi .ps1 .bat .cmd .vbs .sh .jar'.split(' '));

  const state = {
    view: localValue('shrawler-view', 'table'),
    compact: localValue('shrawler-density', 'default') === 'compact',
    page: 1,
    perPage: 0,
    total: 0,
    hasNext: false,
    items: [],
    selectedId: null,
    treeData: null,
    treeKey: '',
    expanded: new Set(),
    treeFocusKey: null
  };

  let searchTimer = null;
  let toastTimer = null;
  let tableController = null;
  let treeController = null;
  let previewController = null;
  let objectUrl = null;
  let previewItem = null;
  let modalOpener = null;
  const treeCache = new Map();

  function localValue(key, fallback) {
    try { return localStorage.getItem(key) || fallback; } catch (_) { return fallback; }
  }

  function saveLocal(key, value) {
    try { localStorage.setItem(key, value); } catch (_) { /* Storage is optional. */ }
  }

  const api = async (path, options = {}) => {
    options.headers = Object.assign({}, options.headers);
    if (token) options.headers.Authorization = `Bearer ${token}`;
    const response = await fetch(path, options);
    if (!response.ok) {
      let message = `Request failed (${response.status})`;
      try { message = (await response.json()).error || message; } catch (_) { /* Non-JSON error. */ }
      throw new Error(message);
    }
    return response;
  };

  const element = (tag, className, value) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined) node.textContent = value;
    return node;
  };

  const icon = name => {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    use.setAttribute('href', `#icon-${name}`);
    svg.append(use);
    return svg;
  };

  const extensionLabel = extension => (extension || 'file').replace(/^\./, '').slice(0, 5).toUpperCase() || 'FILE';
  const riskTier = extension => sensitiveTypes.has(extension) ? 'sensitive' : executableTypes.has(extension) ? 'executable' : 'neutral';

  const specimenTag = extension => {
    const tag = element('span', `specimen-tag ${riskTier(extension)}`, extensionLabel(extension));
    tag.title = `${extension || 'Unknown'} file`;
    return tag;
  };

  const formatDate = value => {
    if (!value) return 'Unknown';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return new Intl.DateTimeFormat(undefined, {year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'}).format(date);
  };

  const formatBytes = value => {
    const size = Number(value) || 0;
    if (size < 1024) return `${size} B`;
    const units = ['KB', 'MB', 'GB', 'TB'];
    let amount = size;
    let unit = -1;
    do { amount /= 1024; unit += 1; } while (amount >= 1024 && unit < units.length - 1);
    return `${amount >= 10 ? amount.toFixed(0) : amount.toFixed(1)} ${units[unit]}`;
  };

  const locationText = item => `${item.host || 'Unknown host'} › ${item.share || 'Unknown share'}`;

  function showToast(message, isError = false) {
    clearTimeout(toastTimer);
    $('toast-message').textContent = message;
    $('toast').classList.toggle('error', isError);
    $('toast').setAttribute('role', isError ? 'alert' : 'status');
    $('toast').hidden = false;
    toastTimer = setTimeout(hideToast, 4000);
  }

  function hideToast() {
    clearTimeout(toastTimer);
    $('toast').hidden = true;
  }

  function filters() {
    return {q: $('query').value, host: $('host').value, share: $('share').value, extension: $('extension').value};
  }

  function filterParams(includePage = false) {
    const params = new URLSearchParams(filters());
    if (includePage) params.set('page', String(state.page));
    return params;
  }

  function appendOptions(id, values) {
    values.forEach(value => {
      const option = document.createElement('option');
      option.value = value;
      option.textContent = id.includes('extension') ? extensionLabel(value) : (value || '(none)');
      $(id).append(option);
    });
  }

  function setSearching(active) {
    $('search-spinner').hidden = !active;
    document.querySelector('.search-icon').hidden = active;
  }

  function renderFilters() {
    const values = filters();
    const entries = [
      ['q', 'Search', values.q ? `“${values.q}”` : ''],
      ['host', 'Host', values.host],
      ['share', 'Share', values.share],
      ['extension', 'Type', values.extension ? extensionLabel(values.extension) : '']
    ].filter(entry => entry[2]);
    $('clear').hidden = entries.length === 0;
    $('clear-query').hidden = !values.q;
    $('active-filters').hidden = entries.length === 0;
    $('active-filters').replaceChildren();
    entries.forEach(([id, label, value]) => {
      const chip = element('span', 'filter-chip');
      chip.append(document.createTextNode(`${label}: ${value}`));
      const remove = element('button');
      remove.type = 'button';
      remove.setAttribute('aria-label', `Remove ${label.toLowerCase()} filter`);
      remove.append(icon('close'));
      remove.addEventListener('click', () => {
        $(id === 'q' ? 'query' : id).value = '';
        scheduleRefresh();
      });
      chip.append(remove);
      $('active-filters').append(chip);
    });
  }

  function clearFilters() {
    $('query').value = '';
    ['host', 'share', 'extension'].forEach(id => { $(id).value = ''; });
    scheduleRefresh();
  }

  function metadataField(label, value) {
    const field = element('div', 'metadata-field');
    const list = document.createElement('dl');
    list.append(element('dt', '', label), element('dd', '', value || '—'));
    field.append(list);
    return field;
  }

  async function copyPath(item, button, pathNode) {
    try {
      await navigator.clipboard.writeText(item.unc_path);
      button.replaceChildren(icon('check'));
      showToast('UNC path copied');
      setTimeout(() => button.replaceChildren(icon('copy')), 1600);
    } catch (_) {
      const range = document.createRange();
      range.selectNodeContents(pathNode);
      const selection = getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      showToast('Clipboard unavailable. Path selected—press Ctrl+C.', true);
    }
  }

  function actionButton(label, iconName, className, handler) {
    const button = element('button', `button ${className}`);
    button.type = 'button';
    button.append(icon(iconName), document.createTextNode(label));
    button.addEventListener('click', handler);
    return button;
  }

  function detailPanel(item, closeHandler) {
    const panel = element('div', 'detail-panel');
    panel.setAttribute('role', 'region');
    panel.setAttribute('aria-label', `Details for ${item.file_name}`);

    const paths = element('div', 'detail-paths');
    const uncField = element('div', 'metadata-field');
    uncField.append(element('dt', '', 'UNC path'));
    const pathLine = element('div', 'path-line');
    const path = element('code', '', item.unc_path || 'Path unavailable');
    const copy = element('button', 'copy-button');
    copy.type = 'button';
    copy.setAttribute('aria-label', 'Copy UNC path');
    copy.append(icon('copy'));
    copy.addEventListener('click', () => copyPath(item, copy, path));
    pathLine.append(path, copy);
    uncField.append(pathLine);
    paths.append(uncField, metadataField('Remote path', item.remote_path));

    const evidence = element('div', 'detail-evidence');
    evidence.append(metadataField('Indexed', formatDate(item.scan_timestamp_utc)));

    const actions = element('div', 'detail-actions');
    const canPreview = previewable.has(item.extension);
    const previewButton = actionButton('Preview', 'eye', 'preview-action', () => {
      if (canPreview) openPreview(item);
      else showToast('Preview is not available for this file type', true);
    });
    if (!canPreview) {
      previewButton.setAttribute('aria-disabled', 'true');
      actions.append(previewButton, element('span', 'unavailable-note', 'Preview unavailable for this type.'));
    } else actions.append(previewButton);
    let downloadButton;
    downloadButton = actionButton('Download', 'download', 'primary', () => download(item, downloadButton));
    const close = element('button', 'panel-close');
    close.type = 'button';
    close.setAttribute('aria-label', 'Close file details');
    close.append(icon('close'));
    close.addEventListener('click', closeHandler);
    actions.append(downloadButton, close);
    panel.append(paths, evidence, actions);
    return panel;
  }

  function restoreFocus(selector) {
    requestAnimationFrame(() => {
      const target = document.querySelector(selector);
      if (target) target.focus({preventScroll: true});
    });
  }

  function toggleTableDetails(item) {
    state.selectedId = state.selectedId === item.id ? null : item.id;
    renderTable();
    restoreFocus(`[data-file-id="${CSS.escape(item.id)}"]`);
    if (state.selectedId) revealPanel(`details-${item.id}`);
  }

  function revealPanel(id) {
    requestAnimationFrame(() => {
      const panel = document.getElementById(id);
      if (!panel) return;
      const bottom = panel.getBoundingClientRect().bottom;
      if (bottom > innerHeight) window.scrollBy({top: bottom - innerHeight + 20, behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth'});
    });
  }

  function renderTable() {
    const body = $('results');
    body.replaceChildren();
    if (!state.items.length) {
      const row = document.createElement('tr');
      const cell = element('td', 'empty-message');
      cell.colSpan = 6;
      cell.append(element('strong', '', 'No files match these filters.'), element('span', '', 'Try a broader search or clear an active filter.'));
      row.append(cell);
      body.append(row);
      return;
    }

    state.items.forEach((item, index) => {
      const row = element('tr', 'file-row');
      const selected = state.selectedId === item.id;
      row.classList.toggle('selected', selected);

      const tagCell = document.createElement('td');
      tagCell.append(specimenTag(item.extension));
      const fileCell = document.createElement('td');
      const trigger = element('button', 'file-trigger');
      trigger.type = 'button';
      trigger.dataset.fileId = item.id;
      trigger.setAttribute('aria-expanded', String(selected));
      trigger.setAttribute('aria-controls', `details-${item.id}`);
      trigger.append(element('span', 'file-name', item.file_name), element('span', 'file-path', item.remote_path || 'Path unavailable'));
      trigger.title = item.file_name;
      trigger.addEventListener('click', () => toggleTableDetails(item));
      trigger.addEventListener('keydown', event => tableKeydown(event, index));
      fileCell.append(trigger);

      const locationCell = document.createElement('td');
      const location = element('span', 'location-strip', locationText(item));
      location.title = locationText(item);
      locationCell.append(location);
      const sizeCell = element('td', 'numeric');
      sizeCell.append(element('span', 'size-value', item.readable_size || formatBytes(item.size_bytes)));
      const dateCell = element('td', 'numeric');
      const time = element('time', 'date-value', formatDate(item.mtime_utc));
      if (item.mtime_utc) time.dateTime = item.mtime_utc;
      dateCell.append(time);
      const chevronCell = element('td', 'row-chevron');
      chevronCell.append(icon('chevron'));
      row.append(tagCell, fileCell, locationCell, sizeCell, dateCell, chevronCell);
      row.addEventListener('click', event => { if (!event.target.closest('button')) toggleTableDetails(item); });
      body.append(row);

      if (selected) {
        const detailRow = element('tr', 'detail-row');
        detailRow.id = `details-${item.id}`;
        const detailCell = document.createElement('td');
        detailCell.colSpan = 6;
        detailCell.append(detailPanel(item, () => toggleTableDetails(item)));
        detailRow.append(detailCell);
        body.append(detailRow);
      }
    });
  }

  function tableKeydown(event, index) {
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const triggers = [...document.querySelectorAll('.file-trigger')];
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? triggers.length - 1 : Math.max(0, Math.min(triggers.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1)));
    triggers[next].focus();
  }

  function renderSkeleton() {
    const body = $('results');
    body.replaceChildren();
    for (let rowIndex = 0; rowIndex < 7; rowIndex += 1) {
      const row = element('tr', 'skeleton-row');
      for (let column = 0; column < 6; column += 1) {
        const cell = document.createElement('td');
        cell.append(element('div', 'skeleton'));
        row.append(cell);
      }
      body.append(row);
    }
  }

  function treeKey(path) { return path.join('\u001f'); }

  function branchChildren(type, node) {
    if (type === 'host') return node.shares.map(child => ['share', child]);
    return [...node.folders.map(child => ['folder', child]), ...node.files.map(child => ['file', child])];
  }

  function renderBranch(type, node, path, level, position = 1, setSize = 1) {
    const key = type === 'file' ? `file:${node.id}` : treeKey(path);
    const item = element('li', `tree-item level-${Math.min(level, 8)}`);
    item.setAttribute('role', 'none');
    const line = element('button', `tree-node ${type}${state.selectedId === node.id ? ' selected' : ''}`);
    line.type = 'button';
    line.setAttribute('role', 'treeitem');
    line.setAttribute('aria-level', String(level));
    line.setAttribute('aria-posinset', String(position));
    line.setAttribute('aria-setsize', String(setSize));
    line.dataset.key = key;
    line.dataset.level = String(level);
    line.tabIndex = state.treeFocusKey === key ? 0 : -1;

    if (type === 'file') {
      line.append(element('span'), icon('file'));
      const label = element('span', 'tree-label file-label');
      label.append(specimenTag(node.extension), element('span', '', node.file_name));
      const meta = element('span', 'tree-file-meta');
      meta.append(element('span', '', node.readable_size || formatBytes(node.size_bytes)), element('span', '', formatDate(node.mtime_utc)));
      line.append(label, meta);
      line.setAttribute('aria-expanded', String(state.selectedId === node.id));
      line.addEventListener('click', () => toggleTreeFile(node, key));
    } else {
      const open = state.expanded.has(key);
      const chevron = element('span');
      chevron.append(icon('chevron'));
      chevron.firstChild.classList.add('tree-chevron');
      line.append(chevron);
      const kind = element('span', 'tree-kind-icon');
      kind.append(icon(type === 'host' ? 'server' : type === 'share' ? 'share' : 'folder'));
      line.append(kind, element('span', 'tree-label', node.name), element('span', 'tree-count', `${node.file_count.toLocaleString()} files · ${formatBytes(node.size_bytes)}`));
      line.setAttribute('aria-expanded', String(open));
      line.addEventListener('click', () => toggleBranch(key));
      if (open) {
        const group = element('ul', 'tree-group');
        group.setAttribute('role', 'group');
        const children = branchChildren(type, node);
        children.forEach(([childType, child], index) => group.append(renderBranch(childType, child, [...path, child.name || child.id], level + 1, index + 1, children.length)));
        item.append(line, group);
        return item;
      }
    }
    item.append(line);
    if (type === 'file' && state.selectedId === node.id) {
      const details = element('div', 'tree-detail');
      details.id = `tree-details-${node.id}`;
      details.append(detailPanel(node, () => toggleTreeFile(node, key)));
      item.append(details);
    }
    return item;
  }

  function renderTree() {
    const root = $('tree');
    root.replaceChildren();
    if (!state.treeData || !state.treeData.hosts.length) {
      root.append(element('li', 'empty-message', 'No files match these filters.'));
      return;
    }
    state.treeData.hosts.forEach((host, index) => root.append(renderBranch('host', host, [`host:${host.name}`], 1, index + 1, state.treeData.hosts.length)));
    const focusables = [...root.querySelectorAll('[role="treeitem"]')];
    if (focusables.length && !focusables.some(node => node.tabIndex === 0)) focusables[0].tabIndex = 0;
  }

  function toggleBranch(key) {
    if (state.expanded.has(key)) state.expanded.delete(key);
    else state.expanded.add(key);
    state.treeFocusKey = key;
    renderTree();
    restoreFocus(`[data-key="${CSS.escape(key)}"]`);
  }

  function toggleTreeFile(item, key) {
    state.selectedId = state.selectedId === item.id ? null : item.id;
    state.treeFocusKey = key;
    renderTree();
    restoreFocus(`[data-key="${CSS.escape(key)}"]`);
    if (state.selectedId) revealPanel(`tree-details-${item.id}`);
  }

  function treeKeydown(event) {
    const current = event.target.closest('[role="treeitem"]');
    if (!current) return;
    const nodes = [...$('tree').querySelectorAll('[role="treeitem"]')];
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
          if (Number(nodes[cursor].dataset.level) < level) { target = nodes[cursor]; break; }
        }
      }
    }
    if (target) {
      event.preventDefault();
      current.tabIndex = -1;
      target.tabIndex = 0;
      state.treeFocusKey = target.dataset.key;
      target.focus();
    } else if (['ArrowRight', 'ArrowLeft'].includes(event.key)) event.preventDefault();
  }

  function collectBranches() {
    const keys = [];
    const walk = (type, node, path) => {
      const key = treeKey(path);
      keys.push(key);
      branchChildren(type, node).forEach(([childType, child]) => { if (childType !== 'file') walk(childType, child, [...path, child.name]); });
    };
    if (state.treeData) state.treeData.hosts.forEach(host => walk('host', host, [`host:${host.name}`]));
    return keys;
  }

  async function searchTable() {
    if (tableController) tableController.abort();
    tableController = new AbortController();
    const request = tableController;
    setSearching(true);
    $('error-banner').hidden = true;
    $('summary').textContent = 'Loading…';
    renderSkeleton();
    try {
      const data = await (await api(`/api/files?${filterParams(true)}`, {signal: request.signal})).json();
      state.items = data.items;
      state.total = data.total;
      state.perPage = data.per_page;
      state.hasNext = data.has_next;
      renderTable();
      renderPagination();
      const start = data.total ? (state.page - 1) * state.perPage + 1 : 0;
      const end = Math.min(state.page * state.perPage, data.total);
      $('summary').textContent = data.total ? `${start.toLocaleString()}–${end.toLocaleString()} of ${data.total.toLocaleString()} files` : 'No matching files';
    } catch (error) {
      if (error.name !== 'AbortError') showError(error.message);
    } finally {
      if (tableController === request) {
        tableController = null;
        if (state.view === 'table') setSearching(false);
      }
    }
  }

  async function loadTree() {
    if (treeController) treeController.abort();
    const key = filterParams(false).toString();
    state.treeKey = key;
    state.selectedId = null;
    $('error-banner').hidden = true;
    if (treeCache.has(key)) {
      state.treeData = treeCache.get(key);
      renderTree();
      renderTreeSummary();
      return;
    }
    treeController = new AbortController();
    const request = treeController;
    setSearching(true);
    $('tree').replaceChildren();
    $('tree-loading').hidden = false;
    $('summary').textContent = 'Building complete hierarchy…';
    try {
      const data = await (await api(`/api/tree?${key}`, {signal: request.signal})).json();
      treeCache.set(key, data);
      if (treeCache.size > 8) treeCache.delete(treeCache.keys().next().value);
      state.treeData = data;
      state.expanded.clear();
      if (data.hosts.length === 1) {
        const host = data.hosts[0];
        state.expanded.add(treeKey([`host:${host.name}`]));
        if (host.shares.length === 1) state.expanded.add(treeKey([`host:${host.name}`, host.shares[0].name]));
      }
      renderTree();
      renderTreeSummary();
    } catch (error) {
      if (error.name !== 'AbortError') showError(error.message);
    } finally {
      if (treeController === request) {
        treeController = null;
        $('tree-loading').hidden = true;
        if (state.view === 'tree') setSearching(false);
      }
    }
  }

  function renderTreeSummary() {
    if (!state.treeData) return;
    $('summary').textContent = `${state.treeData.total.toLocaleString()} files across ${state.treeData.hosts.length.toLocaleString()} hosts`;
    $('expand-tree').disabled = state.treeData.total > 5000;
    $('expand-tree').title = state.treeData.total > 5000 ? 'Expand branches individually for inventories over 5,000 files' : 'Expand every branch';
  }

  function renderPagination() {
    $('previous').disabled = state.page === 1;
    $('next').disabled = !state.hasNext;
    $('page').textContent = `Page ${state.page}`;
  }

  function showError(message) {
    $('error-message').textContent = message;
    $('error-banner').hidden = false;
    $('summary').textContent = 'Inventory unavailable';
    setSearching(false);
  }

  function refresh() {
    renderFilters();
    state.selectedId = null;
    if (state.view === 'tree') loadTree();
    else searchTable();
  }

  function scheduleRefresh() {
    state.page = 1;
    renderFilters();
    clearTimeout(searchTimer);
    searchTimer = setTimeout(refresh, 250);
  }

  function setView(view) {
    if (view === 'tree' && tableController) tableController.abort();
    if (view === 'table' && treeController) treeController.abort();
    state.view = view;
    state.selectedId = null;
    saveLocal('shrawler-view', view);
    $('table-view').setAttribute('aria-pressed', String(view === 'table'));
    $('tree-view').setAttribute('aria-pressed', String(view === 'tree'));
    $('table-container').hidden = view !== 'table';
    $('tree-container').hidden = view !== 'tree';
    $('pagination').hidden = view !== 'table';
    $('tree-actions').hidden = view !== 'tree';
    $('density').hidden = view !== 'table';
    refresh();
  }

  function closeObject() {
    if (objectUrl) URL.revokeObjectURL(objectUrl);
    objectUrl = null;
    $('preview-pdf').removeAttribute('src');
    $('preview-image').removeAttribute('src');
  }

  function resetPreview(item) {
    closeObject();
    $('preview-title').textContent = item.file_name;
    $('preview-tag').textContent = extensionLabel(item.extension);
    $('preview-tag').className = `specimen-tag ${riskTier(item.extension)}`;
    $('preview-meta').textContent = `${item.readable_size || formatBytes(item.size_bytes)}   ${formatDate(item.mtime_utc)}`;
    $('preview-text').textContent = '';
    $('preview-text').hidden = true;
    $('preview-image').hidden = true;
    $('preview-pdf').hidden = true;
    $('preview-error').hidden = true;
    $('preview-loading').hidden = false;
  }

  async function openPreview(item) {
    if (previewController) previewController.abort();
    previewController = new AbortController();
    const request = previewController;
    modalOpener = document.activeElement;
    previewItem = item;
    resetPreview(item);
    $('preview-dialog').showModal();
    $('close-preview').focus();
    try {
      const response = await api(`/api/files/${item.id}/preview`, {signal: request.signal});
      const type = response.headers.get('content-type') || '';
      $('preview-loading').hidden = true;
      if (type.startsWith('application/json')) {
        $('preview-text').textContent = (await response.json()).content;
        $('preview-text').hidden = false;
      } else {
        objectUrl = URL.createObjectURL(await response.blob());
        if (type === 'application/pdf') { $('preview-pdf').src = objectUrl; $('preview-pdf').hidden = false; }
        else { $('preview-image').src = objectUrl; $('preview-image').alt = `Preview of ${item.file_name}`; $('preview-image').hidden = false; }
      }
    } catch (error) {
      if (error.name === 'AbortError') return;
      $('preview-loading').hidden = true;
      $('preview-message').textContent = error.message;
      $('preview-error').hidden = false;
    } finally {
      if (previewController === request) previewController = null;
    }
  }

  function cleanupPreview() {
    if (previewController) previewController.abort();
    previewController = null;
    closeObject();
    if (modalOpener && modalOpener.isConnected) modalOpener.focus();
    modalOpener = null;
  }

  function closePreview() {
    if ($('preview-dialog').open) $('preview-dialog').close();
  }

  async function download(item, button) {
    const original = [...button.childNodes].map(node => node.cloneNode(true));
    button.disabled = true;
    button.replaceChildren(document.createTextNode('Retrieving…'));
    try {
      const response = await api(`/api/files/${item.id}/download`);
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement('a');
      link.href = url;
      link.download = item.file_name;
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      showToast(`Download started: ${item.file_name}`);
    } catch (error) {
      showToast(error.message, true);
    } finally {
      button.replaceChildren(...original);
      button.disabled = false;
    }
  }

  Promise.all([api('/api/status').then(response => response.json()), api('/api/facets').then(response => response.json())]).then(([status, facets]) => {
    $('status').textContent = `Connected — ${status.file_count.toLocaleString()} files indexed`;
    $('connection-status').classList.add('ready');
    appendOptions('host', facets.hosts);
    appendOptions('share', facets.shares);
    appendOptions('extension', facets.extensions);
    document.body.classList.toggle('compact', state.compact);
    $('density').setAttribute('aria-pressed', String(state.compact));
    setView(state.view === 'tree' ? 'tree' : 'table');
  }).catch(error => {
    $('status').textContent = error.message;
    $('connection-status').classList.add('error');
    showError(error.message);
  });

  $('query').addEventListener('input', scheduleRefresh);
  ['host', 'share', 'extension'].forEach(id => $(id).addEventListener('change', scheduleRefresh));
  $('clear-query').addEventListener('click', () => { $('query').value = ''; scheduleRefresh(); $('query').focus(); });
  $('clear').addEventListener('click', clearFilters);
  $('retry').addEventListener('click', refresh);
  $('table-view').addEventListener('click', () => setView('table'));
  $('tree-view').addEventListener('click', () => setView('tree'));
  $('density').addEventListener('click', () => {
    state.compact = !state.compact;
    document.body.classList.toggle('compact', state.compact);
    $('density').setAttribute('aria-pressed', String(state.compact));
    saveLocal('shrawler-density', state.compact ? 'compact' : 'default');
  });
  $('previous').addEventListener('click', () => { if (state.page > 1) { state.page -= 1; searchTable(); } });
  $('next').addEventListener('click', () => { if (state.hasNext) { state.page += 1; searchTable(); } });
  $('tree').addEventListener('keydown', treeKeydown);
  $('expand-tree').addEventListener('click', () => { state.expanded = new Set(collectBranches()); renderTree(); });
  $('collapse-tree').addEventListener('click', () => { state.expanded.clear(); state.selectedId = null; renderTree(); });
  $('close-preview').addEventListener('click', closePreview);
  $('preview-dialog').addEventListener('click', event => { if (event.target === $('preview-dialog')) closePreview(); });
  $('preview-dialog').addEventListener('close', cleanupPreview);
  $('preview-download').addEventListener('click', () => { if (previewItem) download(previewItem, $('preview-download')); });
  $('close-toast').addEventListener('click', hideToast);
  $('toast').addEventListener('mouseenter', () => clearTimeout(toastTimer));
  $('toast').addEventListener('mouseleave', () => { toastTimer = setTimeout(hideToast, 2000); });
  document.addEventListener('keydown', event => {
    if (event.key === '/' && document.activeElement !== $('query') && !$('preview-dialog').open) { event.preventDefault(); $('query').focus(); }
    if (event.key === 'Escape' && state.selectedId && !$('preview-dialog').open) {
      const id = state.selectedId;
      state.selectedId = null;
      if (state.view === 'tree') renderTree(); else renderTable();
      restoreFocus(state.view === 'tree' ? `[data-key="file:${CSS.escape(id)}"]` : `[data-file-id="${CSS.escape(id)}"]`);
    }
  });
})();
