'use strict';
/* Yoru Repeater - shared helpers. No dependencies, no CDN, no build step. */

const Y = {};

/* ------------------------------------------------------------------ format */

Y.fmtBytes = function (b) {
  if (b == null || !isFinite(b)) return '-';
  const abs = Math.abs(b);
  if (abs >= 1e12) return (b / 1e12).toFixed(abs >= 1e13 ? 0 : 1) + ' TB';
  if (abs >= 1e9) return (b / 1e9).toFixed(abs >= 1e10 ? 0 : 1) + ' GB';
  if (abs >= 1e6) return (b / 1e6).toFixed(abs >= 1e7 ? 0 : 1) + ' MB';
  if (abs >= 1e3) return (b / 1e3).toFixed(abs >= 1e4 ? 0 : 1) + ' kB';
  return Math.round(b) + ' B';
};
Y.fmtRate = function (b) { return b == null || !isFinite(b) ? '-' : Y.fmtBytes(b) + '/s'; };
Y.fmtNum = function (n) { return n == null || !isFinite(n) ? '-' : Math.round(n).toLocaleString(); };
Y.fmtPct = function (n) { return n == null || !isFinite(n) ? '-' : n.toFixed(n >= 10 ? 0 : 1) + '%'; };
Y.fmtMHz = function (m) {
  if (m == null || !isFinite(m)) return '-';
  return m >= 1000 ? (m / 1000).toFixed(2) + ' GHz' : Math.round(m) + ' MHz';
};
Y.fmtDur = function (sec) {
  if (sec == null || !isFinite(sec) || sec < 0) return '-';
  sec = Math.floor(sec);
  const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600),
    m = Math.floor(sec % 3600 / 60), s = sec % 60;
  if (d) return d + 'd ' + h + 'h';
  if (h) return h + 'h ' + m + 'm';
  if (m) return m + 'm ' + (s < 10 ? '' : s + 's');
  return s + 's';
};
Y.fmtTime = function (ms) {
  if (!ms) return '-';
  const d = new Date(ms);
  return d.toLocaleTimeString([], { hour12: false });
};
Y.fmtDateTime = function (ms) {
  if (!ms) return '-';
  return new Date(ms).toLocaleString([], { hour12: false });
};
Y.fmtAgo = function (ms) {
  if (!ms) return 'never';
  const d = Math.max(0, Date.now() - ms);
  if (d < 5000) return 'just now';
  if (d < 60000) return Math.floor(d / 1000) + 's ago';
  if (d < 3600000) return Math.floor(d / 60000) + 'm ago';
  return Math.floor(d / 3600000) + 'h ago';
};
Y.bandLabel = function (b) {
  return { '2g': '2.4 GHz', '5g': '5 GHz', '6g': '6 GHz' }[b] || b || '';
};
Y.freqToChannel = function (f) {
  if (!f) return '';
  if (f >= 2400 && f <= 2484) return Math.round((f - 2412) / 5) + 1;
  if (f >= 5170 && f <= 5895) return Math.round((f - 5180) / 5) + 36;
  if (f >= 5955 && f <= 7115) return Math.round((f - 5955) / 5) + 1;
  return '';
};

/* --------------------------------------------------------------------- DOM */

Y.el = function (tag, attrs, children) {
  const n = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === 'class') n.className = v;
      else if (k === 'html') n.innerHTML = v;
      else if (k.startsWith('on') && typeof v === 'function') n.addEventListener(k.slice(2), v);
      else if (k === 'dataset') Object.assign(n.dataset, v);
      else n.setAttribute(k, v === true ? '' : v);
    }
  }
  if (children != null) Y.append(n, children);
  return n;
};
Y.append = function (parent, children) {
  if (!Array.isArray(children)) children = [children];
  for (const c of children) {
    if (c == null || c === false) continue;
    if (Array.isArray(c)) { Y.append(parent, c); continue; }
    parent.appendChild(typeof c === 'object' ? c : document.createTextNode(String(c)));
  }
  return parent;
};
Y.icon = function (name, cls) {
  const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  s.setAttribute('class', cls || 'icon');
  s.setAttribute('aria-hidden', 'true');
  const u = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  u.setAttribute('href', '#i-' + name);
  s.appendChild(u);
  return s;
};
Y.iconBtn = function (name, label, fn, cls) {
  const b = Y.el('button', { class: (cls || 'icon-btn') + (name ? '' : ''), 'aria-label': label, title: label, type: 'button' });
  b.appendChild(Y.icon(name, 'icon'));
  if (fn) b.addEventListener('click', fn);
  return b;
};
Y.btn = function (kind, iconName, text, fn) {
  const b = Y.el('button', { class: 'btn btn-' + kind, type: 'button' });
  if (iconName) b.appendChild(Y.icon(iconName, 'icon-20'));
  b.appendChild(document.createTextNode(text));
  if (fn) b.addEventListener('click', fn);
  return b;
};
Y.clear = function (n) { while (n.firstChild) n.removeChild(n.firstChild); return n; };

/* ------------------------------------------------------------------- store */

Y.store = {
  get(k, def) {
    try {
      const v = localStorage.getItem('yoru.' + k);
      return v == null ? def : JSON.parse(v);
    } catch (e) { return def; }
  },
  set(k, v) {
    try { localStorage.setItem('yoru.' + k, JSON.stringify(v)); } catch (e) { /* private mode */ }
  },
};

/* ---------------------------------------------------------- M3 tonal colors
   An approximation of the Material 3 tonal palette in HSL: hues and chroma
   are preserved while lightness follows the M3 tone ladder. This is what
   powers Dynamic (seed color) and the preset accents, all offline. */

Y.hslToHex = function (h, s, l) {
  s /= 100; l /= 100;
  const k = n => (n + h / 30) % 12;
  const a = s * Math.min(l, 1 - l);
  const f = n => l - a * Math.max(-1, Math.min(k(n) - 3, Math.min(9 - k(n), 1)));
  const hex = x => Math.round(255 * x).toString(16).padStart(2, '0');
  return '#' + hex(f(0)) + hex(f(8)) + hex(f(4));
};

Y.tone = function (h, s, t) {
  const tt = Math.min(100, Math.max(0, t));
  const light = 100 - 100 * Math.pow(1 - tt / 100, 1.08);
  return Y.hslToHex(h, Math.max(8, Math.min(96, s)), light);
};

Y.rgba = function (hex, a) {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${n >> 16 & 255},${n >> 8 & 255},${n & 255},${a})`;
};

/* Build the full set of M3 color roles from one HSL seed. */
Y.palette = function (h, s) {
  const P = (t) => Y.tone(h, s, t);
  const N = (t) => Y.tone(h, Math.max(8, s * 0.16), t);       // neutral (tinted)
  const NV = (t) => Y.tone(h, Math.max(10, s * 0.34), t);     // neutral variant
  const S = (t) => Y.tone(h, Math.max(8, s * 0.42), t);       // secondary
  const T = (t) => Y.tone((h + 60) % 360, Math.max(12, s * 0.55), t); // tertiary
  const E = (t) => Y.tone(25, 88, t);
  return {
    light: {
      '--md-primary': P(40), '--md-on-primary': '#ffffff',
      '--md-primary-container': P(90), '--md-on-primary-container': P(12),
      '--md-secondary': S(40), '--md-on-secondary': '#ffffff',
      '--md-secondary-container': S(90), '--md-on-secondary-container': S(14),
      '--md-tertiary': T(40), '--md-on-tertiary': '#ffffff',
      '--md-tertiary-container': T(90), '--md-on-tertiary-container': T(14),
      '--md-error': E(40), '--md-on-error': '#ffffff',
      '--md-error-container': E(90), '--md-on-error-container': E(12),
      '--md-success': '#146c2e', '--md-on-success': '#ffffff', '--md-success-container': '#a7f7b4',
      '--md-warning': '#7a5900', '--md-on-warning-container': '#2c1e00', '--md-warning-container': '#ffdf9e',
      '--md-surface': N(98), '--md-surface-dim': N(87),
      '--md-surface-container-lowest': '#ffffff', '--md-surface-container-low': N(96.5),
      '--md-surface-container': N(94.5), '--md-surface-container-high': N(92.5),
      '--md-surface-container-highest': N(90.5),
      '--md-on-surface': N(10), '--md-on-surface-variant': NV(30),
      '--md-outline': NV(50), '--md-outline-variant': NV(80),
      '--md-inverse-surface': N(20), '--md-inverse-on-surface': N(95),
      '--md-chart-grid': 'rgba(60,58,72,.16)',
      '--md-scrim': '0 0 0',
    },
    dark: {
      '--md-primary': P(80), '--md-on-primary': P(20),
      '--md-primary-container': P(30), '--md-on-primary-container': P(90),
      '--md-secondary': S(80), '--md-on-secondary': S(20),
      '--md-secondary-container': S(32), '--md-on-secondary-container': S(90),
      '--md-tertiary': T(80), '--md-on-tertiary': T(20),
      '--md-tertiary-container': T(32), '--md-on-tertiary-container': T(90),
      '--md-error': E(80), '--md-on-error': E(20),
      '--md-error-container': E(32), '--md-on-error-container': E(90),
      '--md-success': '#6dd58c', '--md-on-success': '#0a3d1a', '--md-success-container': '#11552a',
      '--md-warning': '#f2c35b', '--md-on-warning-container': '#ffdf9e', '--md-warning-container': '#5c430a',
      '--md-surface': N(8), '--md-surface-dim': N(6),
      '--md-surface-container-lowest': N(4.5), '--md-surface-container-low': N(10),
      '--md-surface-container': N(12), '--md-surface-container-high': N(17),
      '--md-surface-container-highest': N(22),
      '--md-on-surface': N(90), '--md-on-surface-variant': NV(80),
      '--md-outline': NV(60), '--md-outline-variant': NV(30),
      '--md-inverse-surface': N(90), '--md-inverse-on-surface': N(20),
      '--md-chart-grid': 'rgba(200,196,214,.16)',
      '--md-scrim': '0 0 0',
    },
  };
};

Y.amoledify = function (roles) {
  const out = Object.assign({}, roles);
  const flat = {
    '--md-surface': '#000000',
    '--md-surface-dim': '#000000',
    '--md-surface-container-lowest': '#000000',
    '--md-surface-container-low': '#060609',
    '--md-surface-container': '#0c0c10',
    '--md-surface-container-high': '#121216',
    '--md-surface-container-highest': '#191920',
  };
  return Object.assign(out, flat);
};

/* ------------------------------------------------------------------ feedback */

Y.snack = function (msg, opts) {
  opts = opts || {};
  const host = document.getElementById('snackbars');
  const s = Y.el('div', { class: 'snackbar' + (opts.err ? ' err' : ''), role: 'status' });
  s.appendChild(Y.icon(opts.err ? 'error' : 'check', 'icon-20'));
  const span = Y.el('span', {}, msg);
  s.appendChild(span);
  if (opts.action) {
    s.appendChild(Y.btn('text', null, opts.action, () => { try { opts.fn && opts.fn(); } finally { close(); } }));
  }
  host.appendChild(s);
  let closed = false;
  function close() {
    if (closed) return; closed = true;
    s.classList.add('out');
    setTimeout(() => s.remove(), 250);
  }
  setTimeout(close, opts.ms || (opts.err ? 6500 : 3800));
  s.addEventListener('click', (e) => { if (e.target === s || e.target === span) close(); });
};

/* Modal confirm dialog. Returns a promise resolving true/false. */
Y.confirm = function (title, body, opts) {
  opts = opts || {};
  return new Promise((resolve) => {
    const host = document.getElementById('dialog-host');
    Y.clear(host);
    host.classList.remove('hidden');
    const dialog = Y.el('div', { class: 'dialog', role: 'alertdialog', 'aria-modal': 'true', 'aria-label': title });
    dialog.appendChild(Y.el('h3', {}, title));
    if (typeof body === 'string') dialog.appendChild(Y.el('p', {}, body));
    else Y.append(dialog, body);
    const actions = Y.el('div', { class: 'dialog-actions' });
    const cancel = Y.btn('text', null, opts.cancelText || 'Cancel', () => done(false));
    const ok = Y.btn(opts.danger ? 'danger' : 'filled', null, opts.okText || 'Apply', () => done(true));
    actions.append(cancel, ok);
    dialog.appendChild(actions);
    host.appendChild(dialog);
    function done(v) {
      host.classList.add('hidden');
      Y.clear(host);
      document.removeEventListener('keydown', onKey);
      resolve(v);
    }
    function onKey(e) { if (e.key === 'Escape') done(false); }
    document.addEventListener('keydown', onKey);
    host.addEventListener('click', (e) => { if (e.target === host) done(false); }, { once: true });
    cancel.focus();
  });
};

Y.copyText = async function (text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (e) {
    const ta = Y.el('textarea', { style: 'position:fixed;opacity:0' });
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (e2) { /* noop */ }
    ta.remove();
    return ok;
  }
};

Y.clone = function (o) { return JSON.parse(JSON.stringify(o)); };

Y.download = function (name, mime, content) {
  const blob = new Blob([content], { type: mime });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
};
