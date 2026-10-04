// Overlay primitives: dialogs, toasts, confirmation, popovers, and meters.
// Screens compose these instead of hand-rolling <dialog> lifecycle, so focus
// handling, Escape, backdrop dismissal, and stacking behave identically.

import { button, clear, el, fill, icon, on } from './core.js';

let region = null;

function toastRegion() {
  if (!region) {
    region = el('div', 'toast-region');
    region.setAttribute('aria-live', 'polite');
    document.body.append(region);
  }
  return region;
}

/** Show a transient message. Errors stay longer because they need reading. */
export function toast(message, tone = 'ok') {
  const node = el('div', 'toast');
  node.dataset.tone = tone;
  node.setAttribute('role', tone === 'error' ? 'alert' : 'status');
  const dismiss = el('button');
  dismiss.type = 'button';
  dismiss.setAttribute('aria-label', 'Dismiss notification');
  dismiss.append(icon('close'));
  node.append(el('span', undefined, message), dismiss);
  toastRegion().append(node);
  let timer = setTimeout(() => node.remove(), tone === 'error' ? 9000 : 4000);
  on(node, 'mouseenter', () => clearTimeout(timer));
  on(node, 'mouseleave', () => {
    timer = setTimeout(() => node.remove(), 2000);
  });
  on(dismiss, 'click', () => node.remove());
  return node;
}

/**
 * Open a native modal dialog around `content`.
 *
 * Returns a handle with close(). The opener is captured so focus returns to
 * the control that opened the dialog, and a click on the backdrop (the dialog
 * element itself) dismisses, matching what the pointer gesture implies.
 */
export function openOverlay(content, { label, wide = false } = {}) {
  const opener = document.activeElement;
  const frame = el('div', wide ? 'dialog dialog--wide' : 'dialog');
  frame.append(content);
  const dialog = el('dialog');
  dialog.append(frame);
  document.body.append(dialog);
  on(dialog, 'click', (event) => {
    if (event.target === dialog) close();
  });
  on(dialog, 'close', () => {
    dialog.remove();
    if (opener && opener.isConnected) opener.focus({ preventScroll: true });
  });
  dialog.showModal();
  const focusTarget = frame.querySelector('[autofocus]') || dialog;
  focusTarget.focus({ preventScroll: true });
  function close() {
    if (dialog.open) dialog.close();
  }
  return { dialog, frame, close };
}

/** Compose a standard dialog frame: head, optional toolbar, body, foot. */
export function dialogShell({ title, subtitle, toolbar, body, footer, wide, flush, onClose }) {
  const node = el('div');
  const head = el('div', 'dialog__head');
  const identity = el('div', 'dialog__identity');
  identity.append(el('h2', 'dialog__title', title));
  if (subtitle) identity.append(el('p', 'dialog__sub', subtitle));
  const close = button('Close', { size: 'sm', onClick: () => onClose() });
  head.append(identity, close);
  node.append(head);
  if (toolbar) {
    const bar = el('div', 'dialog__toolbar');
    fill(bar, toolbar);
    node.append(bar);
  }
  const bodyNode = el('div', flush ? 'dialog__body dialog__body--flush' : 'dialog__body');
  fill(bodyNode, body);
  node.append(bodyNode);
  if (footer) {
    const foot = el('div', 'dialog__foot');
    fill(foot, footer);
    node.append(foot);
  }
  return { node, body: bodyNode, wide };
}

/** Modal confirmation. Resolves false on Escape or backdrop dismissal. */
export function confirm({ title, message, confirmLabel = 'Confirm', tone = 'primary', detail }) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value, handle) => {
      if (settled) return;
      settled = true;
      handle.close();
      resolve(value);
    };
    const body = el('div');
    body.append(el('p', undefined, message));
    if (detail) body.append(el('p', 'field__hint', detail));
    const shell = dialogShell({
      title,
      body,
      onClose: () => finish(false, handle),
      footer: el('div', 'btn-row'),
    });
    const foot = shell.node.querySelector('.dialog__foot > div');
    foot.append(
      button('Cancel', { size: 'sm', onClick: () => finish(false, handle) }),
      button(confirmLabel, {
        size: 'sm',
        variant: tone,
        onClick: () => finish(true, handle),
      }),
    );
    const handle = openOverlay(shell.node);
    handle.dialog.addEventListener('close', () => finish(false, handle));
    const primary = foot.lastChild;
    primary.setAttribute('autofocus', '');
    primary.focus({ preventScroll: true });
  });
}

/**
 * A dismissible popover anchored below `anchor`. Used for the filter panel,
 * which is a popover on desktop and a bottom sheet under 640px (handled in
 * CSS). Returns a close function.
 */
export function openPopover(anchor, content, { align = 'start' } = {}) {
  const existing = document.querySelector('.popover');
  if (existing) existing.remove();
  const popover = el('div', 'popover');
  popover.setAttribute('role', 'dialog');
  popover.setAttribute('aria-label', anchor.getAttribute('aria-label') || 'Options');
  fill(popover, content);
  document.body.append(popover);
  const box = anchor.getBoundingClientRect();
  const size = popover.getBoundingClientRect();
  const left =
    align === 'end'
      ? Math.max(8, Math.min(window.innerWidth - size.width - 8, box.right - size.width))
      : Math.max(8, Math.min(window.innerWidth - size.width - 8, box.left));
  const below = box.bottom + 6;
  const top = below + size.height > window.innerHeight - 8 ? Math.max(8, box.top - size.height - 6) : below;
  popover.style.left = `${left}px`;
  popover.style.top = `${top}px`;
  const close = () => {
    popover.remove();
    document.removeEventListener('keydown', onKey, true);
    document.removeEventListener('pointerdown', onOutside, true);
    window.removeEventListener('resize', close);
  };
  const onKey = (event) => {
    if (event.key === 'Escape') {
      event.stopPropagation();
      close();
      anchor.focus({ preventScroll: true });
    }
  };
  const onOutside = (event) => {
    if (!popover.contains(event.target) && !anchor.contains(event.target)) close();
  };
  setTimeout(() => {
    document.addEventListener('keydown', onKey, true);
    document.addEventListener('pointerdown', onOutside, true);
    window.addEventListener('resize', close);
  });
  const focusable = popover.querySelector('input, select, button');
  if (focusable) focusable.focus({ preventScroll: true });
  return close;
}

/** A labelled progress meter. `fraction` of null renders as indeterminate. */
export function meter(fraction, { label } = {}) {
  const wrap = el('div');
  if (label) wrap.append(el('div', 'field__label', label));
  const track = el('div', 'meter');
  track.setAttribute('role', 'progressbar');
  const fill = el('div', 'meter__fill');
  if (fraction === null || fraction === undefined) {
    track.setAttribute('aria-label', label || 'Working');
    fill.style.width = '30%';
  } else {
    const clamped = Math.max(0, Math.min(1, fraction));
    track.setAttribute('aria-valuenow', String(Math.round(clamped * 100)));
    track.setAttribute('aria-valuemin', '0');
    track.setAttribute('aria-valuemax', '100');
    if (label) track.setAttribute('aria-label', label);
    fill.style.width = `${clamped * 100}%`;
  }
  track.append(fill);
  wrap.append(track);
  return {
    node: wrap,
    set(next, tone) {
      if (next === null || next === undefined) return;
      const clamped = Math.max(0, Math.min(1, next));
      fill.style.width = `${clamped * 100}%`;
      track.setAttribute('aria-valuenow', String(Math.round(clamped * 100)));
      if (tone) fill.dataset.tone = tone;
    },
  };
}

/** Inline error surface used by the Score screen panels. */
export function errorLine(node, message) {
  clear(node);
  node.hidden = !message;
  node.className = 'banner';
  if (message) node.append(icon('alert'), el('span', undefined, message));
  return node;
}

/**
 * Standard panel chrome, so both Score tabs read as one screen. The panel is
 * returned rather than mounted: callers decide whether to append it or to
 * replace the contents of a container they already own.
 */
export function panel(title, hint, body, { flush = false } = {}) {
  const head = el('div', 'panel__head', el('h2', 'panel__title', title), hint ? el('p', 'panel__hint', hint) : null);
  const content = el('div', flush ? 'panel__body panel__body--flush' : 'panel__body', body);
  return { node: el('section', 'panel', head, content), head, body: content };
}