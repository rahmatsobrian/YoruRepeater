'use strict';
/* Yoru Repeater - application shell: theme, navigation, auth and boot. */

Y.ACCENTS = [
  { name: 'night', hue: 258, sat: 62, css: '#6c5ce6' },
  { name: 'ocean', hue: 210, sat: 65, css: '#2f7de8' },
  { name: 'teal', hue: 175, sat: 55, css: '#0d9488' },
  { name: 'forest', hue: 145, sat: 48, css: '#16a34a' },
  { name: 'amber', hue: 38, sat: 75, css: '#d97706' },
  { name: 'ember', hue: 18, sat: 78, css: '#e8672f' },
  { name: 'rose', hue: 340, sat: 62, css: '#db2777' },
  { name: 'graphite', hue: 260, sat: 8, css: '#64748b' },
];

Y.state = {
  mode: Y.store.get('mode', 'system'),
  accent: Y.store.get('accent', 'night'),
  seed: Y.store.get('seed', null),
  maskMacs: Y.store.get('maskMacs', true),
};

Y.NAV = [
  { id: 'dashboard', label: 'Home', icon: 'home', primary: true },
  { id: 'clients', label: 'Clients', icon: 'devices', primary: true },
  { id: 'performance', label: 'Stats', icon: 'performance', primary: true },
  { id: 'settings', label: 'Settings', icon: 'settings', primary: true },
  { id: 'repeater', label: 'Repeater', icon: 'repeater' },
  { id: 'wifi', label: 'Wi-Fi', icon: 'wifi' },
  { id: 'network', label: 'Network', icon: 'network' },
  { id: 'system', label: 'System', icon: 'system' },
  { id: 'battery', label: 'Battery', icon: 'battery' },
  { id: 'traffic', label: 'Traffic', icon: 'traffic' },
  { id: 'logs', label: 'Logs', icon: 'logs' },
  { id: 'diagnostics', label: 'Diagnostics', icon: 'diagnostics' },
  { id: 'about', label: 'About', icon: 'info' },
];

function hexToHsl(hex) {
  if (!hex || !/^#[0-9a-f]{6}$/i.test(hex)) return [258, 62];
  const n = parseInt(hex.slice(1), 16);
  const r = (n >> 16 & 255) / 255, g = (n >> 8 & 255) / 255, b = (n & 255) / 255;
  const max = Math.max(r, g, b), min = Math.min(r, g, b), d = max - min;
  let h = 0;
  if (d) {
    if (max === r) h = ((g - b) / d) % 6;
    else if (max === g) h = (b - r) / d + 2;
    else h = (r - g) / d + 4;
    h = (h * 60 + 360) % 360;
  }
  const l = (max + min) / 2;
  const s = d === 0 ? 0 : d / (1 - Math.abs(2 * l - 1));
  return [h, Math.min(96, Math.max(8, s * 100))];
}

Y.applyTheme = function () {
  const root = document.documentElement;
  let mode = Y.state.mode;
  if (mode === 'system') mode = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  let hue = 258, sat = 62;
  if (Y.state.accent === 'custom' && Y.state.seed) {
    [hue, sat] = hexToHsl(Y.state.seed);
  } else {
    const p = Y.ACCENTS.find(a => a.name === Y.state.accent) || Y.ACCENTS[0];
    hue = p.hue; sat = p.sat;
  }
  const pal = Y.palette(hue, sat);
  const roles = mode === 'amoled' ? Y.amoledify(pal.dark) : pal[mode === 'dark' ? 'dark' : 'light'];
  for (const [k, v] of Object.entries(roles)) root.style.setProperty(k, v);
  root.dataset.theme = mode;
  const mt = document.getElementById('meta-theme');
  if (mt) mt.setAttribute('content', roles['--md-surface'] || '#000000');
  const btn = document.getElementById('btn-theme');
  if (btn) {
    Y.clear(btn);
    btn.appendChild(Y.icon(mode === 'light' ? 'sun' : mode === 'dark' ? 'moon' : 'amoled', 'icon'));
  }
};

/* --------------------------------------------------------------- routing */

Y.router = {
  current: null,
  cleanup: null,
  go(force) {
    let id = (location.hash || '#/dashboard').replace(/^#\//, '').split('?')[0] || 'dashboard';
    if (!Y.pages[id]) id = 'dashboard';
    if (this.current === id && !force) return;
    if (this.cleanup) { try { this.cleanup(); } catch (e) { console.error(e); } this.cleanup = null; }
    this.current = id;
    const item = Y.NAV.find(n => n.id === id) || { label: id };
    document.getElementById('topbar-title').textContent = item.label;
    document.title = item.label + ' - Yoru Repeater';
    for (const a of document.querySelectorAll('[data-nav]')) {
      if (a.dataset.nav === id) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    }
    const main = Y.clear(document.getElementById('page'));
    main.classList.remove('page-in');
    void main.offsetWidth;
    main.classList.add('page-in');
    try {
      const r = Y.pages[id](main);
      if (typeof r === 'function') this.cleanup = r;
    } catch (e) {
      console.error(e);
      main.appendChild(banner('error', 'error', 'This page failed to render: ' + e.message));
    }
    window.scrollTo(0, 0);
    closeDrawer();
  },
};

/* --------------------------------------------------------------- navigation */

function buildNav() {
  const side = document.getElementById('sidenav-list');
  const bottom = document.getElementById('bottomnav');
  Y.clear(side); Y.clear(bottom);
  for (const n of Y.NAV) {
    const a = Y.el('a', { class: 'nav-item', href: '#/' + n.id, dataset: { nav: n.id } });
    const ni = Y.el('span', { class: 'ni' });
    ni.appendChild(Y.icon(n.icon, 'icon-20'));
    const lab = Y.el('span', { class: 'nlabel' }, n.label);
    a.append(ni, lab);
    side.appendChild(a);
  }
  const foot = document.getElementById('sidenav-foot');
  Y.clear(foot);
  foot.textContent = 'Yoru Repeater';
  const primary = Y.NAV.filter(n => n.primary);
  for (const n of primary) {
    const a = Y.el('a', { href: '#/' + n.id, dataset: { nav: n.id } });
    const ni = Y.el('span', { class: 'ni' });
    ni.appendChild(Y.icon(n.icon, 'icon-20'));
    a.append(ni, Y.el('span', {}, n.label));
    bottom.appendChild(a);
  }
}

function closeDrawer() {
  const sidenav = document.getElementById('sidenav');
  const menuBtn = document.getElementById('btn-menu');
  if (sidenav) sidenav.classList.remove('drawer-open');
  if (menuBtn) menuBtn.setAttribute('aria-expanded', 'false');
  document.body.style.overflow = '';
  scrim(false);
}

function scrim(on) {
  const s = document.getElementById('scrim');
  const dlgOpen = !document.getElementById('dialog-host').classList.contains('hidden');
  if (on) s.classList.remove('hidden');
  else if (!dlgOpen) s.classList.add('hidden');
}
document.getElementById('scrim').addEventListener('click', closeDrawer);

/* --------------------------------------------------------------- auth */

function updateAuthUI() {
  const st = Y.cache.status;
  const btn = document.getElementById('btn-auth');
  const show = !!(st && st.auth && st.auth.required && st.auth.authenticated);
  btn.classList.toggle('hidden', !show);
}

async function doLogin(pw, readonly) {
  const d = await Y.api.post('/login', { password: pw, readonly });
  Y.cache.config = null;
  await Y.pollStatus(true).catch(() => { });
  Y.stream.close(); Y.stream.open();
  Y.router.go(true);
  return d;
}

function showLogin(msg) {
  const ov = document.getElementById('login-overlay');
  ov.classList.remove('hidden');
  const err = document.getElementById('login-err');
  err.textContent = msg || '';
  document.getElementById('login-pass').focus();
}
function hideLogin() {
  document.getElementById('login-overlay').classList.add('hidden');
}

/* --------------------------------------------------------------- boot */

function setConn(kind, text) {
  const pill = document.getElementById('conn-pill');
  pill.classList.remove('ok', 'warn', 'err');
  if (kind) pill.classList.add(kind);
  document.getElementById('conn-text').textContent = text;
}

async function pingFirst() {
  try {
    const st = await Y.api.get('/status');
    Y.cache.status = st;
    hideSplash();
    updateAuthUI();
    Y.bus.emit('status', st);
    if (st.auth && st.auth.required && !st.auth.authenticated) showLogin();
    else Y.stream.open();
    return true;
  } catch (e) {
    if (e.status === 401) {
      hideSplash();
      showLogin();
      return false;
    }
    return false;
  }
}
function hideSplash() {
  document.getElementById('splash').classList.add('done');
}

async function boot() {
  buildNav();
  for (const el of document.querySelectorAll('[data-i]')) {
    if (!el.querySelector('svg')) el.appendChild(Y.icon(el.dataset.i, 'icon'));
  }
  Y.applyTheme();
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if (Y.state.mode === 'system') Y.applyTheme();
  });
  window.addEventListener('hashchange', () => Y.router.go());

  document.getElementById('btn-theme').addEventListener('click', () => {
    const order = ['system', 'light', 'dark', 'amoled'];
    Y.state.mode = order[(order.indexOf(Y.state.mode) + 1) % order.length];
    Y.store.set('mode', Y.state.mode);
    Y.applyTheme();
  });
  document.getElementById('btn-refresh').addEventListener('click', () => {
    Y.cache.status = null; Y.cache.capabilities = null; Y.cache.config = null;
    Y.pollStatus(true).catch(() => { });
    Y.router.go(true);
  });
  document.getElementById('btn-auth').addEventListener('click', async () => {
    if (!await Y.confirm('Sign out of the dashboard?', 'Monitoring keeps working; configuration changes will need a new sign-in.')) return;
    try { await Y.api.post('/logout'); } catch (e) { }
    Y.cache.status = null;
    await pingFirst();
  });

  document.getElementById('login-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const pw = document.getElementById('login-pass').value;
    const ro = document.getElementById('login-readonly').checked;
    const btn = document.getElementById('login-btn');
    btn.disabled = true;
    document.getElementById('login-err').textContent = '';
    try {
      await doLogin(pw, ro);
      hideLogin();
      Y.snack('Signed in' + (ro ? ' (read-only)' : ''));
    } catch (e) {
      document.getElementById('login-err').textContent = e.message;
      if (e.code === 'no_password') document.getElementById('login-first').classList.remove('hidden');
    }
    btn.disabled = false;
  });

  Y.bus.on('unauthorized', () => {
    Y.stream.close();
    showLogin('Your session expired. Sign in again.');
    Y.pollStatus().then(() => { Y.stream.open(); hideLogin(); }).catch(() => { });
  });
  Y.bus.on('stream', (s) => {
    if (s === 'online') setConn('ok', 'Live');
    else if (s === 'reconnecting') setConn('warn', 'Reconnecting…');
    else setConn('err', 'Connection lost');
  });

  const ok = await pingFirst();
  if (!ok) {
    setConn('err', 'Connecting…');
    Y.stream.open();
  }

  window.addEventListener('offline', () => setConn('err', 'Offline'));
  window.addEventListener('online', () => pingFirst());

  const topbar = document.getElementById('topbar');
  window.addEventListener('scroll', () => topbar.classList.toggle('scrolled', window.scrollY > 8), { passive: true });

  initMenuDrawer();
  Y.router.go(true);
}

function initMenuDrawer() {
  const menuBtn = document.getElementById('btn-menu');
  const sidenav = document.getElementById('sidenav');
  if (!menuBtn || !sidenav) return;
  menuBtn.classList.remove('hidden');
  menuBtn.addEventListener('click', () => {
    const open = sidenav.classList.toggle('drawer-open');
    menuBtn.setAttribute('aria-expanded', String(open));
    document.body.style.overflow = open ? 'hidden' : '';
    scrim(open);
  });
  sidenav.addEventListener('click', (e) => {
    if (e.target.closest('a.nav-item')) closeDrawer();
  });
}

document.addEventListener('DOMContentLoaded', boot);
