// File preview: text with find and font sizing, image with zoom and fit, PDF in
// a sandboxed iframe, plus copy and download. Capability is unchanged from the
// previous dialog; it is rebuilt on the shared overlay primitives.

import { api, button, clear, el, fill, fmt, icon, on } from './core.js';
import { dialogShell, openOverlay, toast } from './overlay.js';

const PREVIEWABLE = new Set(
  '.txt .log .csv .json .xml .ini .conf .config .cnf .properties .prop .yaml .yml .md .rst .py .js .ts .jsx .tsx .java .cs .go .rs .rb .php .ps1 .bat .cmd .vbs .sh .sql .pem .key .png .jpg .jpeg .gif .webp .pdf'.split(
    ' ',
  ),
);

export function canPreview(item, retrievalEnabled) {
  return retrievalEnabled && PREVIEWABLE.has(item.extension);
}

export const previewableExtensions = PREVIEWABLE;

let controller = null;
let objectUrl = null;
let content = '';
let matches = [];
let matchIndex = -1;
let fontSize = 12;
let zoom = 1;

function releaseObjectUrl() {
  if (objectUrl) URL.revokeObjectURL(objectUrl);
  objectUrl = null;
}

export function closePreview() {
  document.querySelector('dialog[data-preview]')?.close();
}

export async function openPreview(item, onDownload) {
  if (controller) controller.abort();
  controller = new AbortController();
  const signal = controller.signal;

  matches = [];
  matchIndex = -1;
  content = '';
  fontSize = 12;
  zoom = 1;

  const title = el('h2', 'dialog__title', item.file_name);
  const subtitle = el('p', 'dialog__sub', item.unc_path || item.remote_path || '');
  const findInput = el('input', 'input');
  findInput.type = 'search';
  findInput.placeholder = 'Find in file…';
  findInput.setAttribute('aria-label', 'Find in file');
  findInput.classList.add('input--find');
  const findStatus = el('span', 'field__hint', 'No matches');
  const prevMatch = button('Previous', { name: 'chevron', size: 'sm', onClick: () => find(-1) });
  const nextMatch = button('Next', { name: 'chevron', size: 'sm', onClick: () => find(1) });
  prevMatch.classList.add('icon-chevron-left');
  nextMatch.classList.add('icon-chevron-down');
  const wrapToggle = button('Wrap', { size: 'sm', onClick: () => toggleWrap() });
  wrapToggle.setAttribute('aria-pressed', 'true');
  const fontDown = button('A−', { size: 'sm', onClick: () => setFont(fontSize - 1) });
  const fontUp = button('A+', { size: 'sm', onClick: () => setFont(fontSize + 1) });
  const toolbar = el('div', 'dialog__toolbar');
  fill(toolbar, findInput, findStatus, prevMatch, nextMatch, el('span', 'field__hint', ''), wrapToggle, fontDown, fontUp);
  toolbar.style.display = 'none';

  const stage = el('div', 'preview-stage');
  const loading = el('div', 'preview-loading');
  loading.append(el('span', 'spinner'), el('span', undefined, 'Loading preview…'));
  const failure = el('div', 'banner');
  failure.hidden = true;
  const textView = el('ol', 'preview-text');
  textView.hidden = true;
  const imageShell = el('div', 'preview-image-shell');
  imageShell.hidden = true;
  const image = el('img');
  image.alt = `Preview of ${item.file_name}`;
  const zoomLabel = el('span', 'field__hint', '100%');
  const controls = el('div', 'image-controls');
  fill(
    controls,
    button('Fit', { size: 'sm', onClick: () => setZoom(1) }),
    button('−', { size: 'sm', onClick: () => setZoom(zoom - 0.25) }),
    zoomLabel,
    button('+', { size: 'sm', onClick: () => setZoom(zoom + 0.25) }),
  );
  imageShell.append(image, controls);
  const pdf = el('iframe', 'preview-pdf');
  pdf.title = 'PDF preview';
  // The frame is sandboxed with no allow-scripts, so a hostile PDF cannot run
  // code or reach this origin.
  pdf.setAttribute('sandbox', '');
  pdf.hidden = true;
  fill(stage, loading, failure, textView, imageShell, pdf);

  const meta = el('span', 'field__hint', `${fmt.bytes(item.size_bytes)} · ${fmt.date(item.mtime_utc)}`);
  const copyButton = button('Copy text', { size: 'sm', variant: 'primary', onClick: () => copyContent() });
  copyButton.hidden = true;
  const downloadButton = button('Download', {
    name: 'download',
    size: 'sm',
    variant: 'primary',
    onClick: () => onDownload(item),
  });
  const shell = dialogShell({
    title: item.file_name,
    subtitle: item.unc_path || item.remote_path || '',
    toolbar,
    body: stage,
    footer: [meta, el('div', 'btn-row', copyButton, downloadButton)],
    wide: true,
    flush: true,
    onClose: () => handle.close(),
  });
  // The shell composes its own title node; reuse the richer one built above.
  shell.node.querySelector('.dialog__title').replaceWith(title);
  shell.node.querySelector('.dialog__sub').replaceWith(subtitle);
  const handle = openOverlay(shell.node, { wide: true });
  handle.dialog.dataset.preview = '1';

  on(findInput, 'input', () => find(0));
  on(findInput, 'keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      find(event.shiftKey ? -1 : 1);
    }
  });
  on(handle.dialog, 'close', cleanup);

  try {
    const response = await api(`/api/files/${item.id}/preview`, { signal });
    const type = response.headers.get('content-type') || '';
    loading.hidden = true;
    if (type.startsWith('application/json')) {
      content = (await response.json()).content || '';
      renderText();
      textView.hidden = false;
      toolbar.style.display = '';
      copyButton.hidden = false;
    } else {
      releaseObjectUrl();
      objectUrl = URL.createObjectURL(await response.blob());
      if (type === 'application/pdf') {
        pdf.src = objectUrl;
        pdf.hidden = false;
      } else {
        image.src = objectUrl;
        imageShell.hidden = false;
        setZoom(1);
      }
    }
  } catch (error) {
    if (error.name === 'AbortError') return;
    loading.hidden = true;
    failure.hidden = false;
    failure.className = 'banner';
    failure.append(icon('alert'), el('span', undefined, error.message));
  } finally {
    if (controller && controller.signal === signal) controller = null;
  }

  function renderText() {
    const fragment = document.createDocumentFragment();
    for (const line of content.split('\n')) fragment.append(el('li', undefined, line || ' '));
    clear(textView);
    textView.append(fragment);
    textView.style.fontSize = `${fontSize}px`;
  }

  function setFont(value) {
    fontSize = Math.max(10, Math.min(20, value));
    renderText();
  }

  function toggleWrap() {
    const wrapped = textView.classList.toggle('nowrap');
    wrapToggle.setAttribute('aria-pressed', String(wrapped));
  }

  function find(step) {
    const needle = findInput.value.toLocaleLowerCase();
    matches = [];
    if (needle) {
      [...textView.children].forEach((line, index) => {
        if (line.textContent.toLocaleLowerCase().includes(needle)) matches.push(index);
      });
    }
    if (!matches.length) matchIndex = -1;
    else if (step) matchIndex = (matchIndex + step + matches.length) % matches.length;
    else matchIndex = 0;
    for (const line of textView.children) line.classList.remove('search-match');
    if (matchIndex >= 0) {
      const line = textView.children[matches[matchIndex]];
      line.classList.add('search-match');
      line.scrollIntoView({ block: 'center' });
    }
    findStatus.textContent = matches.length
      ? `${matchIndex + 1} of ${matches.length}`
      : needle
        ? 'No matches'
        : 'No search';
  }

  function setZoom(value) {
    zoom = Math.min(4, Math.max(0.25, value));
    image.style.width = `${zoom * 100}%`;
    image.style.maxWidth = zoom === 1 ? '100%' : 'none';
    zoomLabel.textContent = `${Math.round(zoom * 100)}%`;
  }

  async function copyContent() {
    try {
      await navigator.clipboard.writeText(content);
      toast('Preview text copied');
    } catch {
      toast('Clipboard unavailable; select the text and copy manually', 'error');
    }
  }

  function cleanup() {
    controller?.abort();
    controller = null;
    releaseObjectUrl();
    pdf.removeAttribute('src');
    image.removeAttribute('src');
  }
}