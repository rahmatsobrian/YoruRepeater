'use strict';
/* Yoru Repeater - page renderers. Each renderer builds DOM for its route,
   subscribes to realtime updates through Y.bus, and returns an unsubscribe
   function used when navigating away. Data is never fabricated: missing
   values render as "Unavailable on this device". */

/* ------------------------------------------------------------ shared parts */

function card(title, iconName, bodyNodes, cls) {
  const c = Y.el('section', { class: 'card' + (cls ? ' ' + cls : '') });
  if (title) {
    const h = Y.el('div', { class: 'card-head' });
    if (iconName) h.appendChild(Y.icon(iconName, 'icon-20'));
    h.appendChild(Y.el('h3', {}, title));
    const act = Y.el('div', { class: 'card-actions', style: 'display:flex;gap:4px;align-items:center' });
    h.appendChild(act);
    h._actions = act;
    c.appendChild(h);
    c._head = h;
  }
  Y.append(c, bodyNodes);
  return c;
}

function kvList(pairs) {
  const dl = Y.el('dl', { class: 'kv' });
  for (const [k, v, opts] of pairs) {
    if (v === undefined) continue;
    if (v === null || v === '') {
      if (opts && opts.hideMissing) continue;
      dl.appendChild(Y.el('dt', {}, k));
      dl.appendChild(Y.el('dd', { class: 'unavailable' }, 'Unavailable on this device'));
      continue;
    }
    dl.appendChild(Y.el('dt', {}, k));
    let node;
    if (v instanceof Node) node = v;
    else if (opts && opts.mono) node = Y.el('dd', { class: 'mono' }, String(v));
    else node = Y.el('dd', {}, String(v));
    if (opts && opts.id) node.id = opts.id;
    dl.appendChild(node);
  }
  return dl;
}

function banner(kind, icon, text, extra) {
  const b = Y.el('div', { class: 'banner ' + kind, role: kind === 'error' ? 'alert' : 'status' });
  b.appendChild(Y.icon(icon, 'icon-20'));
  const body = Y.el('div', { style: 'flex:1' });
  body.appendChild(Y.el('div', {}, text));
  if (extra) Y.append(body, extra);
  b.appendChild(body);
  return b;
}

function emptyState(icon, text, sub) {
  const e = Y.el('div', { class: 'empty' });
  e.appendChild(Y.icon(icon));
  e.appendChild(Y.el('div', {}, text));
  if (sub) e.appendChild(Y.el('div', { class: 'stat-sub' }, sub));
  return e;
}

function gaugeEl(size) {
  const g = Y.el('div', { class: 'gauge', style: size ? `width:${size}px;height:${size}px` : '' });
  g.innerHTML = '<svg viewBox="0 0 44 44"><circle class="track" cx="22" cy="22" r="17"></circle><circle class="val" cx="22" cy="22" r="17" stroke-dasharray="106.8" stroke-dashoffset="106.8"></circle></svg><div class="center"><b>-</b><span></span></div>';
  return g;
}
function gaugeSet(g, pct, label, cls) {
  const val = g.querySelector('.val'), b = g.querySelector('.center b'), s = g.querySelector('.center span');
  const circ = 106.8;
  const p = Math.max(0, Math.min(100, pct || 0));
  val.style.strokeDashoffset = (circ * (1 - p / 100)).toFixed(1);
  b.textContent = (pct == null || isNaN(pct)) ? '-' : Math.round(pct) + '%';
  if (label != null) s.textContent = label;
  val.parentElement.parentElement.classList.remove('err');
  if (cls === 'err') g.classList.add('err');
}

function chip(cls, text, iconName) {
  const c = Y.el('span', { class: 'chip state ' + cls });
  if (iconName) c.appendChild(Y.icon(iconName, 'icon-16'));
  c.appendChild(document.createTextNode(text));
  return c;
}
Y.stateChip = function (state) {
  switch (state) {
    case 'running': return chip('yes', 'Running', 'check');
    case 'degraded': return chip('warn', 'Degraded', 'warning');
    case 'starting': case 'stopping': case 'rolling-back': return chip('info', state[0].toUpperCase() + state.slice(1), 'refresh');
    case 'cooldown': return chip('warn', 'Cooling down', 'warning');
    case 'failed': return chip('no', 'Failed', 'error');
    default: return chip('muted', 'Stopped', 'stop');
  }
};
Y.internetChip = function (inet) {
  if (!inet) return chip('muted', 'Unknown');
  if (inet.reachable) return chip('yes', 'Internet connected' + (inet.latencyMs ? ' - ' + inet.latencyMs + ' ms' : ''), 'check');
  return chip('no', 'No internet', 'warning');
};
function chartCard(title, iconName, chartOpts, statsNodes) {
  const c = card(title, iconName, null, 'chart-card');
  const holder = Y.el('div', { class: 'chart-box' });
  const cv = Y.el('canvas', { 'aria-label': title + ' chart', role: 'img' });
  holder.appendChild(cv);
  c.appendChild(holder);
  const leg = Y.el('div', { class: 'legend' });
  c.appendChild(leg);
  if (statsNodes) { const st = Y.el('div', { class: 'chart-stats' }); c.appendChild(st); c._stats = st; Y.append(st, statsNodes); }
  const ch = new Y.Chart(cv, chartOpts);
  for (const s of chartOpts.series || []) {
    const se = ch.addSeries(s.key, s.label, s.color, s);
    leg.appendChild(Y.el('span', {}, [Y.el('i', { style: 'background:' + s.color }), s.label]));
  }
  c._chart = ch;
  return c;
}

function canControl() {
  const st = Y.cache.status;
  if (!st || !st.auth) return true;
  if (!st.auth.required) return true;
  return st.auth.authenticated && !st.auth.readonly;
}
function needsLoginErr(err) { return err && err.status === 401; }

/* ------------------------------------------------------------ dashboard */

Y.pages = {};

Y.pages.dashboard = function (root) {
  const unsubs = [];

  const hero = card(null, null, null, 'hero');
  const top = Y.el('div', {});
  const heroTitle = Y.el('h3', { style: 'font-size:1.5rem;font-weight:600' }, 'Yoru Repeater');
  const pillsRow = Y.el('div', { style: 'display:flex;flex-direction:column;align-items:flex-start;gap:6px;margin-top:10px' });
  const statePill = Y.el('div', {});
  const modeLine = Y.el('div', { class: 'stat-sub' }, '');
  top.append(heroTitle);
  const inetPill = Y.el('div', {});
  pillsRow.append(statePill, inetPill);
  const dashUrls = Y.el('div', { class: 'dash-urls', style: 'margin-top:8px' });
  Y.append(hero, [top, pillsRow, modeLine, dashUrls]);

  const controls = Y.el('div', { class: 'hero-controls' });
  const btnStart = Y.btn('filled', 'play', 'Start', () => control('start'));
  const btnStop = Y.btn('tonal', 'stop', 'Stop', () => control('stop'));
  const btnRestart = Y.btn('outlined', 'restart', 'Restart', () => control('restart'));
  controls.append(btnStart, btnStop, btnRestart);
  const authHint = Y.el('div', { class: 'stat-sub', style: 'margin-top:8px' });
  hero.appendChild(controls);
  hero.appendChild(authHint);

  async function control(action) {
    btnStart.disabled = btnStop.disabled = btnRestart.disabled = true;
    try {
      await Y.api.post('/repeater/' + action);
      Y.snack('Repeater ' + action + ' requested');
      await Y.pollStatus();
      await Y.pollCapabilities(true);
    } catch (e) {
      Y.snack(e.message, { err: true });
    }
    btnStart.disabled = btnStop.disabled = btnRestart.disabled = false;
    paintStatus();
  }

  const dlCard = card(null, 'download', null);
  const dlVal = Y.el('div', { class: 'stat-value big' }, '-');
  const dlSpark = Y.el('canvas', { class: 'spark', style: 'width:100%;height:38px', 'aria-hidden': 'true' });
  const ulVal = Y.el('div', { class: 'stat-value', style: 'font-size:1.3rem' }, '-');
  Y.append(dlCard, [
    Y.el('div', { class: 'stat-label' }, 'Download'), dlVal,
    Y.el('div', { class: 'stat-label', style: 'margin-top:8px' }, 'Upload'), ulVal,
    dlSpark,
  ]);

  const clientsCard = card('Clients', 'devices');
  const clientsBig = Y.el('div', { class: 'stat-value big' }, '-');
  const clientsSub = Y.el('div', { class: 'stat-sub' }, '');
  Y.append(clientsCard, [clientsBig, clientsSub]);
  const clientsLink = Y.el('a', { class: 'btn btn-text', href: '#/clients' }, 'View all');
  clientsCard._head._actions.appendChild(clientsLink);

  const cpuCard = card('CPU', 'cpu');
  const cpuG = gaugeEl();
  const cpuSpark = Y.el('canvas', { class: 'spark', style: 'width:100%;height:34px', 'aria-hidden': 'true' });
  const cpuSub = Y.el('div', { class: 'stat-sub' }, '');
  const cpuTempVal = Y.el('div', { class: 'stat-value', style: 'font-size:1.4rem;color:var(--chart-2)' }, '-');
  const cpuTempLabel = Y.el('div', { class: 'stat-sub' }, 'CPU temp');
  Y.append(cpuCard, [
    Y.el('div', { style: 'display:flex;gap:16px;align-items:center' }, [
      cpuG,
      Y.el('div', { style: 'flex:1;min-width:0' }, [cpuSub, cpuSpark]),
      Y.el('div', { style: 'text-align:center;flex:none;padding-left:12px;border-left:1px solid var(--md-outline-variant)' }, [cpuTempVal, cpuTempLabel]),
    ]),
  ]);

  const memCard = card('RAM', 'memory');
  const memG = gaugeEl();
  const memSpark = Y.el('canvas', { class: 'spark', style: 'width:100%;height:34px', 'aria-hidden': 'true' });
  const memSub = Y.el('div', { class: 'stat-sub' }, '');
  Y.append(memCard, [Y.el('div', { style: 'display:flex;gap:16px;align-items:center' }, [memG, Y.el('div', {}, [memSub, memSpark])])]);

  const battCard = card('Battery', 'battery');
  const battG = gaugeEl();
  const battSub = Y.el('div', { class: 'stat-sub' }, '');
  const battTempVal = Y.el('div', { class: 'stat-value', style: 'font-size:1.4rem;color:var(--chart-2)' }, '-');
  const battTempLabel = Y.el('div', { class: 'stat-sub' }, 'Battery temp');
  Y.append(battCard, [
    Y.el('div', { style: 'display:flex;gap:16px;align-items:center' }, [
      battG,
      Y.el('div', { style: 'flex:1;min-width:0' }, [battSub]),
      Y.el('div', { style: 'text-align:center;flex:none;padding-left:12px;border-left:1px solid var(--md-outline-variant)' }, [battTempVal, battTempLabel]),
    ]),
  ]);

  const wifiCard = card('Wi-Fi signal', 'wifi');
  const wifiVal = Y.el('div', { class: 'stat-value' }, '-');
  const wifiSub = Y.el('div', { class: 'stat-sub' }, '');
  Y.append(wifiCard, [wifiVal, wifiSub]);

  const trafficChart = chartCard('Traffic - last minutes', 'traffic', {
    height: 170, unit: 'bytes', maxPoints: 300,
    series: [
      { key: 'rx', label: 'Down', color: '#12a36c' },
      { key: 'tx', label: 'Up', color: '#2f7de8' },
    ],
  });
  for (const p of Y.live.histOf('trafficRate')) trafficChart._chart.push(p);
  trafficChart._chart.draw();
  unsubs.push(Y.bus.on('live:traffic', () => {
    const h = Y.live.histOf('trafficRate');
    const last = h[h.length - 1];
    if (last) { trafficChart._chart.push(last); trafficChart._chart.draw(); }
  }));

  const stCard = card('Storage', 'storage');
  stCard.appendChild(Y.el('div', { class: 'unavailable' }, 'Loading…'));
  Y.append(root, [
    hero,
    Y.el('div', { class: 'grid', style: 'margin-top:12px;grid-template-columns:repeat(3,1fr)' }, [dlCard, clientsCard, cpuCard]),
    Y.el('div', { class: 'grid', style: 'margin-top:12px;grid-template-columns:repeat(3,1fr)' }, [memCard, battCard, wifiCard]),
    Y.el('div', { class: 'grid', style: 'margin-top:12px;grid-template-columns:1fr' }, [stCard]),
    Y.el('div', { class: 'grid', style: 'margin-top:12px;grid-template-columns:1fr' }, [trafficChart]),
  ]);

  const errHost = Y.el('div', { style: 'order:-1' });
  root.prepend(errHost);

  function paintStatus() {
    const st = Y.cache.status;
    if (!st) return;
    const rep = st.repeater || {};
    Y.clear(statePill); statePill.appendChild(Y.stateChip(rep.state));
    modeLine.textContent = rep.modeLabel || '';
    Y.clear(inetPill); inetPill.appendChild(Y.internetChip(rep.internet));
    clientsBig.textContent = Y.fmtNum(st.clientsOnline);
    clientsSub.textContent = st.clientsTotal ? (st.clientsTotal - st.clientsOnline) + ' known but offline' : 'no devices seen yet';
    const urls = st.dashboardUrls || [];
    Y.clear(dashUrls);
    if (urls.length) {
      dashUrls.appendChild(Y.el('div', { class: 'stat-sub' }, 'Dashboard'));
      urls.forEach((u) => {
        const a = Y.el('a', { href: u, class: 'mono dash-url' }, u);
        dashUrls.appendChild(a);
      });
    }
    const busy = ['starting', 'stopping', 'rolling-back'].includes(rep.state);
    const running = ['running', 'degraded'].includes(rep.state);
    btnStart.disabled = !canControl() || busy || running || rep.state === 'cooldown';
    btnStop.disabled = !canControl() || busy || (!running && rep.state !== 'failed' && rep.state !== 'cooldown');
    btnRestart.disabled = !canControl() || busy || !running;
    Y.clear(authHint);
    if (!canControl()) {
      authHint.appendChild(Y.el('span', {}, st.auth && st.auth.readonly ? 'Read-only session - sign in without the read-only option to control the repeater.' : 'Sign in to control the repeater.'));
    } else if (rep.autoStartDisabled) {
      authHint.appendChild(Y.el('span', {}, 'Automatic start is disabled after repeated failures; starting manually resets the counter.'));
    }
    Y.clear(errHost);
    if (rep.lastError) errHost.appendChild(banner('error', 'error', 'Repeater: ' + rep.lastError));
  }

  function paintLive() {
    const tr = Y.live.get('traffic');
    if (tr && tr.rates) {
      const agg = tr.rates.__agg || Object.values(tr.rates)[0];
      if (agg) {
        dlVal.textContent = agg.valid ? Y.fmtRate(agg.rxBytesPerSec) : '-';
        ulVal.textContent = agg.valid ? Y.fmtRate(agg.txBytesPerSec) : '-';
        Y.spark(dlSpark, Y.live.histOf('trafficRate').slice(-90).map(p => p.v.rx), getComputedStyle(document.documentElement).getPropertyValue('--chart-2'), { zeroBase: true });
      }
    }
    const cpu = Y.live.get('cpu');
    if (cpu) {
      gaugeSet(cpuG, cpu.total, 'CPU');
      cpuSub.textContent = (cpu.load ? 'load ' + [cpu.load.l1, cpu.load.l5, cpu.load.l15].map(x => (x || 0).toFixed(1)).join(' ') : '') + (cpu.frequencies && cpu.frequencies.length ? ' - ' + Y.fmtMHz(Math.max(...cpu.frequencies.map(f => f.curKhz)) / 1000) : '');
      Y.spark(cpuSpark, Y.live.histOf('cpuNow').slice(-90).map(p => p.v.total), getComputedStyle(document.documentElement).getPropertyValue('--md-primary'), { zeroBase: true });
    }
    const mem = Y.live.get('memory');
    if (mem && mem.mem) {
      gaugeSet(memG, mem.mem.usedPct, 'RAM');
      memSub.textContent = Y.fmtBytes(mem.mem.usedKb * 1024) + ' of ' + Y.fmtBytes(mem.mem.totalKb * 1024);
      Y.spark(memSpark, Y.live.histOf('memNow').slice(-90).map(p => p.v.usedPct), getComputedStyle(document.documentElement).getPropertyValue('--chart-4'), { zeroBase: true });
    }
    const bat = Y.live.get('battery');
    if (bat && bat.battery) {
      const b = bat.battery;
      gaugeSet(battG, b.capacity, '%');
      let sub = b.status ? b.status.toLowerCase() : 'state unknown';
      if (b.powerMw) sub += ' \u00B7 ' + (Math.abs(b.powerMw) >= 1000 ? (b.powerMw / 1000).toFixed(1) + ' W' : b.powerMw + ' mW');
      battSub.textContent = sub;
      if (b.tempMilliC) {
        var t = b.tempMilliC / 100;
        battTempVal.textContent = t.toFixed(1) + '\u00B0C';
        battTempVal.style.color = t >= 45 ? 'var(--md-error)' : 'var(--chart-2)';
      }
    }
  }
  unsubs.push(Y.bus.on('status', () => { paintStatus(); }));
  unsubs.push(Y.bus.on('live', paintLive));
  Y.pollStatus().catch(e => { if (!needsLoginErr(e)) Y.snack(e.message, { err: true }); });
  paintStatus();
  paintLive();

  Y.api.get('/wifi').then(w => {
    const st = (w.stations || []).find(s => s.connected) || (w.stations || [])[0];
    if (st && st.rssi) {
      wifiVal.textContent = st.rssi + ' dBm';
      wifiSub.textContent = (st.ssid && st.ssid !== 'unknown' ? st.ssid + ' ' : '') + 'ch' + (st.channel || Y.freqToChannel(st.frequencyMHz)) + (st.band ? ' ' + Y.bandLabel(st.band) : '') + (st.linkSpeedMbps ? ' - ' + st.linkSpeedMbps + ' Mbps' : '');
    } else if (st && st.connected) {
      wifiVal.textContent = 'connected';
      wifiSub.textContent = (st.ssid && st.ssid !== 'unknown' ? st.ssid + ' ' : '') + 'on ' + (st.iface || 'Wi-Fi') + (w.note ? ' (' + w.note + ')' : '');
    } else if (w.note) {
      wifiVal.textContent = '-';
      wifiSub.textContent = w.note;
    } else {
      wifiVal.textContent = '-';
      wifiSub.textContent = 'connect Wi-Fi to monitor';
    }
    if (w.signalQuality != null) wifiVal.textContent += ' (' + w.signalQuality + '/100)';
  }).catch(() => { });

  Y.api.get('/storage').then(store => {
    Y.clear(stCard);
    const parts = store.partitions || [];
    const internal = parts.find(p => p.mount === '/data');
    const external = parts.find(p => p.mount.startsWith('/storage/') && p.mount !== '/storage/emulated' && !p.readOnly && p.totalBytes > 0);
    const shown = [internal, external].filter(Boolean);
    if (!shown.length) { stCard.appendChild(Y.el('div', { class: 'unavailable' }, 'No storage data')); return; }
    const grid = Y.el('div', { class: 'grid', style: 'grid-template-columns:1fr 1fr;gap:8px' });
    for (const p of shown) {
      const label = p.mount === '/data' ? 'Internal' : 'External';
      const g = gaugeEl();
      gaugeSet(g, p.usedPct, '%');
      const sub = Y.el('div', { class: 'stat-sub' }, Y.fmtBytes(p.availBytes || (p.totalBytes - p.usedBytes)) + ' free');
      grid.appendChild(Y.el('div', {}, [Y.el('div', { class: 'stat-label' }, label), g, sub]));
    }
    stCard.appendChild(grid);
  }).catch(() => { Y.clear(stCard); stCard.appendChild(Y.el('div', { class: 'unavailable' }, 'Storage info unavailable')); });

  function loadThermal() {
    Y.api.get('/temperature').then(function(temp) {
      if (!temp) { cpuTempVal.textContent = '-'; return; }
      var seen = {};
      var cpuSensors = [];
      var zones = temp.zones || [];
      var hw = temp.hwmon || [];
      for (var i = 0; i < zones.length; i++) {
        var z = zones[i];
        if (seen[z.name]) continue;
        seen[z.name] = true;
        if (z.tempMilliC && (z.kind === 'CPU' || (z.name && z.name.indexOf('cpu') >= 0))) {
          cpuSensors.push({ name: z.name, tempC: z.tempMilliC / 1000 });
        }
      }
      for (var j = 0; j < hw.length; j++) {
        var h = hw[j];
        if (seen[h.name]) continue;
        seen[h.name] = true;
        if (h.tempMilliC && (h.kind === 'CPU' || (h.name && h.name.indexOf('cpu') >= 0))) {
          cpuSensors.push({ name: h.name, tempC: h.tempMilliC / 1000 });
        }
      }
      if (cpuSensors.length) {
        cpuSensors.sort(function(a, b) { return b.tempC - a.tempC; });
        var max = cpuSensors[0];
        cpuTempVal.textContent = max.tempC.toFixed(1) + '\u00B0C';
        cpuTempVal.style.color = max.tempC >= 65 ? 'var(--md-error)' : 'var(--chart-2)';
      } else {
        cpuTempVal.textContent = '-';
      }
    }).catch(function() { cpuTempVal.textContent = '-'; });
  }
  loadThermal();
  var thPoll = setInterval(loadThermal, 10000);
  unsubs.push(function() { clearInterval(thPoll); });

  unsubs.push(Y.bus.on('live:status', (h) => {
    if (h && h.engine) {
      const rep = Y.cache.status;
      if (rep) { rep.repeater = h.engine; paintStatus(); }
    }
  }));

  const poll = setInterval(() => { Y.pollStatus().catch(() => { }); }, 12000);
  unsubs.push(() => clearInterval(poll));
  return () => unsubs.forEach(f => f());
};

/* ------------------------------------------------------------ repeater */

Y.pages.repeater = function (root) {
  const unsubs = [];
  const wrap = Y.el('div', {});
  root.appendChild(wrap);

  function render() {
    Y.clear(wrap);
    const st = Y.cache.status;
    if (!st) { wrap.appendChild(emptyState('refresh', 'Waiting for the daemon…')); return; }
    const rep = st.repeater || {};

    const stateCard = card('Repeater state', 'repeater');
    const headRow = Y.el('div', { style: 'display:flex;gap:12px;align-items:center;flex-wrap:wrap' });
    headRow.appendChild(Y.stateChip(rep.state));
    headRow.appendChild(Y.internetChip(rep.internet));
    if (rep.uptimeSec) headRow.appendChild(chip('info', 'up ' + Y.fmtDur(rep.uptimeSec)));
    Y.append(stateCard, [
      headRow,
      Y.el('div', { class: 'stat-sub', style: 'margin:8px 0' }, rep.modeLabel || 'not running'),
      kvList([
        ['Mode', rep.mode ? rep.mode : null],
        ['AP strategy', rep.apStrategy || null],
        ['Gateway', rep.gateway, { mono: true }],
        ['Firewall backend', rep.firewallBackend || null],
        ['DHCP', rep.dhcpRunning === undefined ? null : (rep.dhcpRunning ? 'running' : 'not running')],
        ['DNS', rep.dnsRunning === undefined ? null : (rep.dnsRunning ? 'running' : 'not running')],
        ['Consecutive failures', rep.consecutiveFailures || 0],
        ['Last failure', rep.lastFailureAt || null],
      ]),
    ]);
    if (rep.lastError) stateCard.appendChild(Y.el('div', { class: 'banner error', style: 'margin-top:10px' }, [Y.icon('error', 'icon-20'), Y.el('div', {}, rep.lastError)]));

    const ifaceCard = card('Path', 'network');
    const up = rep.upstream || {}, dn = rep.downstream || {};
    Y.append(ifaceCard, [
      Y.el('div', { class: 'card-title' }, 'Upstream (internet)'),
      kvList([
        ['Interface', up.name || 'not resolved', { mono: true }],
        ['Class', up.kind || null],
        ['Address', up.cidr || up.address, { mono: true }],
        ['MAC', up.mac, { mono: true }],
        ['Detail', up.detail || null],
      ]),
      Y.el('div', { class: 'card-title', style: 'margin-top:14px' }, 'Downstream (clients)'),
      kvList([
        ['Interface', dn.name || 'not resolved', { mono: true }],
        ['Class', dn.kind || null],
        ['Address', dn.cidr || dn.address, { mono: true }],
        ['MAC', dn.mac, { mono: true }],
      ]),
    ]);

    if (rep.internet && rep.internet.detail) {
      const ic = card('Internet probe', 'dns');
      Y.append(ic, [kvList([
        ['Verdict', rep.internet.reachable ? 'reachable' : 'not reachable'],
        ['Method', rep.internet.method || null],
        ['Latency', rep.internet.latencyMs ? rep.internet.latencyMs + ' ms' : null],
        ['DNS works', rep.internet.dnsWorks === undefined ? null : (rep.internet.dnsWorks ? 'yes' : 'no')],
        ['Checked', rep.internet.checkedAtMs ? Y.fmtAgo(rep.internet.checkedAtMs) : null],
        ['Detail', rep.internet.detail || null],
      ]), rep.internet.probes && rep.internet.probes.length ? Y.el('div', { class: 'mono field-help' }, 'probes: ' + rep.internet.probes.join(', ')) : null]);
      ic.style.marginTop = '12px';
      wrap.appendChild(ic);
    }

    const stepsCard = card('Bring-up steps', 'diagnostics');
    if ((rep.steps || []).length) {
      const sl = Y.el('div', { class: 'steps' });
      for (const s of rep.steps) {
        const row = Y.el('div', { class: 'step' + (s.ok ? '' : ' failed') });
        row.appendChild(Y.el('div', { class: 'step-rail' }, [Y.el('div', { class: 'step-dot' }), Y.el('div', { class: 'line' })]));
        const info = Y.el('div', {});
        info.appendChild(Y.el('div', { class: 'step-name' }, s.step + ' ' + (s.tookMs ? '(' + s.tookMs + ' ms)' : '')));
        if (s.detail) info.appendChild(Y.el('div', { class: 'step-detail' }, s.detail));
        row.appendChild(info);
        sl.appendChild(row);
      }
      stepsCard.appendChild(sl);
    } else {
      stepsCard.appendChild(Y.el('div', { class: 'unavailable' }, 'No startup attempt recorded yet.'));
    }
    if ((rep.rollbackLog || []).length) {
      stepsCard.appendChild(Y.el('div', { class: 'card-title', style: 'margin-top:10px' }, 'Rollback log'));
      stepsCard.appendChild(Y.el('ul', { style: 'margin:0;padding-left:20px' }, rep.rollbackLog.map(x => Y.el('li', {}, x))));
    }
    if ((rep.notes || []).length) {
      stepsCard.appendChild(Y.el('div', { class: 'card-title', style: 'margin-top:10px' }, 'Notes'));
      stepsCard.appendChild(Y.el('ul', { style: 'margin:0;padding-left:20px;font-size:.86rem' }, rep.notes.map(x => Y.el('li', {}, x))));
    }

    const ctl = card('Controls', 'power');
    const btnRow = Y.el('div', { style: 'display:flex;gap:8px;flex-wrap:wrap' });
    btnRow.append(
      Y.btn('filled', 'play', 'Start', () => ctl2('start', btnRow)),
      Y.btn('tonal', 'restart', 'Restart', () => ctl2('restart', btnRow)),
      Y.btn('danger', 'stop', 'Stop', async () => {
        if (await Y.confirm('Stop the repeater?', 'Connected clients will be disconnected and Yoru will remove its firewall rules, addresses and DHCP/DNS servers.', { danger: true, okText: 'Stop' })) ctl2('stop', btnRow);
      }),
    );
    ctl.appendChild(btnRow);
    if (!canControl()) ctl.appendChild(Y.el('p', { class: 'field-help' }, st.auth && st.auth.readonly ? 'Read-only session.' : 'Sign in with a full session to control the repeater.'));

    const capCard = card('Available modes', 'signal');
    renderModes(capCard, Y.cache.capabilities);

    Y.append(wrap, [
      Y.el('div', { class: 'grid', style: 'margin-top:12px' }, [stateCard, ifaceCard]),
      Y.el('div', { class: 'grid', style: 'margin-top:12px' }, [stepsCard, ctl]),
      Y.el('div', { style: 'margin-top:12px' }, [capCard]),
    ]);
    refreshStrategies();
  }
  async function refreshStrategies() {
    try {
      const cap = await Y.pollCapabilities();
      const modeCard = wrap.querySelector('.grid:nth-of-type(3) > .card');
      if (modeCard) renderModes(modeCard, cap);
    } catch (e) { /* login overlay will surface auth problems */ }
  }

  function renderModes(c, cap) {
    Y.clear(c);
    const head = Y.el('div', { class: 'card-head' });
    head.appendChild(Y.icon('signal', 'icon-20'));
    head.appendChild(Y.el('h3', {}, 'Available modes'));
    c.appendChild(head);
    const s = cap && cap.summary;
    if (!s) { c.appendChild(Y.el('div', { class: 'unavailable' }, 'Loading…')); return; }
    const rows = Y.el('div', { class: 'list' });
    const mk = (ok, title, sub) => {
      const li = Y.el('div', { class: 'list-item' });
      li.appendChild(Y.icon(ok ? 'check' : 'close', 'icon-20'));
      const b = Y.el('div', { class: 'li-body' });
      b.appendChild(Y.el('div', { class: 'li-title' }, title));
      if (sub) b.appendChild(Y.el('div', { class: 'li-sub' }, sub));
      li.appendChild(b);
      li.appendChild(chip(ok ? 'yes' : 'muted', ok ? 'supported' : 'unavailable'));
      return li;
    };
    Y.append(rows, [
      mk(s.trueRepeater, 'True Wi-Fi repeater (STA + AP concurrent)', s.trueRepeater ? '' : 'Hardware/driver dependent - see reasons below'),
      mk(s.hotspotRouter, 'Wi-Fi hotspot router (upstream -> NAT -> AP)', ''),
      mk(s.usbRouter, 'USB upstream router', ''),
      mk(s.ethernetRouter, 'Ethernet upstream router', ''),
    ]);
    c.appendChild(rows);
    if ((s.reasons || []).length) {
      c.appendChild(Y.el('div', { class: 'card-title', style: 'margin-top:10px' }, 'Why modes are unavailable'));
      c.appendChild(Y.el('ul', { style: 'margin:0;padding-left:20px;font-size:.84rem;color:var(--md-on-surface-variant)' }, s.reasons.map(r => Y.el('li', {}, r))));
    }
    if (cap && cap.strategies && cap.strategies.length) {
      c.appendChild(Y.el('div', { class: 'card-title', style: 'margin-top:10px' }, 'AP backends'));
      const list = Y.el('div', { class: 'list' });
      for (const st of cap.strategies) {
        const li = Y.el('div', { class: 'list-item' });
        li.appendChild(Y.icon(st.available ? 'check' : 'close', 'icon-20'));
        const b = Y.el('div', { class: 'li-body' });
        b.appendChild(Y.el('div', { class: 'li-title' }, st.name));
        if (st.reason) b.appendChild(Y.el('div', { class: 'li-sub' }, st.reason));
        li.appendChild(b);
        list.appendChild(li);
      }
      c.appendChild(list);
    }
  }

  async function ctl2(action, btnRow) {
    for (const b of btnRow.querySelectorAll('button')) b.disabled = true;
    try {
      await Y.api.post('/repeater/' + action);
      Y.snack('Repeater ' + action + ' requested');
      await Y.pollStatus();
      render();
    } catch (e) {
      Y.snack(e.message, { err: true });
      for (const b of btnRow.querySelectorAll('button')) b.disabled = false;
    }
  }

  unsubs.push(Y.bus.on('status', render));
  unsubs.push(Y.bus.on('live:status', () => render()));
  Y.pollStatus().catch(() => { });
  render();
  return () => unsubs.forEach(f => f());
};

/* ------------------------------------------------------------ clients */

Y.pages.clients = function (root) {
  let unsubs = [];
  const filters = { q: '', state: 'all', sort: '' };
  const wrap = Y.el('div', {});
  root.appendChild(wrap);

  const toolbar = Y.el('div', { style: 'display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:12px' });
  const search = Y.el('input', { type: 'search', placeholder: 'Search name, IP, MAC…', 'aria-label': 'Search clients', style: 'flex:1;min-width:180px;padding:12px 16px;border-radius:999px;border:1px solid var(--md-outline-variant);background:var(--md-surface-container);color:var(--md-on-surface);font:inherit' });
  search.addEventListener('input', () => { filters.q = search.value; load(); });
  const seg = Y.el('div', { class: 'segmented', role: 'group', 'aria-label': 'Filter clients' });
  for (const [k, label] of [['all', 'All'], ['online', 'Online'], ['offline', 'Offline']]) {
    const b = Y.el('button', { type: 'button', class: (k === 'all' ? 'sel' : '') }, label);
    b.addEventListener('click', () => {
      filters.state = k;
      for (const x of seg.children) x.classList.remove('sel');
      b.classList.add('sel');
      load();
    });
    seg.appendChild(b);
  }
  const sortSel = Y.el('select', { 'aria-label': 'Sort clients', style: 'padding:11px 14px;border-radius:999px;border:1px solid var(--md-outline-variant);background:var(--md-surface-container);color:var(--md-on-surface);font:inherit' });
  for (const [k, label] of [['', 'Online first'], ['name', 'Name'], ['traffic', 'Total traffic'], ['rx', 'Download'], ['tx', 'Upload'], ['newest', 'Newest']]) {
    sortSel.appendChild(Y.el('option', { value: k }, label));
  }
  sortSel.addEventListener('change', () => { filters.sort = sortSel.value; load(); });
  const maskBtn = Y.iconBtn('eye', 'Toggle MAC masking', () => {
    Y.state.maskMacs = !Y.state.maskMacs;
    Y.store.set('maskMacs', Y.state.maskMacs);
    load();
  });
  toolbar.append(search, seg, sortSel, maskBtn);

  const stats = Y.el('div', { class: 'chips', style: 'margin-bottom:12px' });
  const listHost = Y.el('div', { class: 'grid' });
  Y.append(wrap, [toolbar, stats, listHost]);

  const iconFor = (c) => {
    const g = (c.deviceClass || '') + ' ' + (c.hostname || '');
    if (/tv|bravia|roku|shield/i.test(g)) return 'tv';
    if (/laptop|notebook|macbook|thinkpad|xps|surface/i.test(g)) return 'laptop';
    if (/watch|band|gear/i.test(g)) return 'watch';
    if (/print|scanner/i.test(g)) return 'print';
    if (/game|playstation|xbox|nintendo/i.test(g)) return 'game';
    if (/phone|android|iphone|galaxy|pixel|xiaomi|redmi|oneplus/i.test(g)) return 'system';
    return 'devices';
  };
  const dispMac = (c) => {
    if (!c.mac) return null;
    if (Y.state.maskMacs) {
      const parts = c.mac.split(':');
      return parts[0] + ':' + parts[1] + ':••:••:••:' + parts[5];
    }
    return c.macDisplay && !Y.state.maskMacs ? c.mac : c.mac;
  };

  let lastErr = 0;
  let loading = false;
  async function load() {
    if (loading) return; loading = true;
    try {
      const q = new URLSearchParams();
      if (filters.q) q.set('q', filters.q);
      if (filters.state !== 'all') q.set('state', filters.state);
      if (filters.sort) q.set('sort', filters.sort);
      const d = await Y.api.get('/clients?' + q.toString());
      Y.clear(stats);
      const s = d.stats || {};
      stats.append(
        chip('yes', (s.online || 0) + ' online'),
        chip('muted', (s.total || 0) + ' known'),
        d.leaseSources && d.leaseSources.length ? chip('info', 'leases: ' + d.leaseSources.join(', ')) : chip('warn', 'no lease source readable'),
      );
      Y.clear(listHost);
      const cs = d.clients || [];
      if (!cs.length) {
        listHost.appendChild(emptyState('devices', 'No clients match', 'Devices appear here when they connect to the repeater network.'));
        return;
      }
      for (const c of cs) {
        const el = card(null, null, null, 'client-card');
        el.style.display = 'flex';
        const ic = Y.el('div', { class: 'client-icon' + (c.online ? '' : ' offline') });
        ic.appendChild(Y.icon(iconFor(c)));
        const main = Y.el('div', { class: 'client-main' });
        const name = Y.el('div', { class: 'client-name' }, c.hostname || c.ip || c.macDisplay || 'Unknown device');
        const meta = Y.el('div', { class: 'client-meta' });
        const bits = [];
        if (c.ip) bits.push(c.ip);
        if (c.ipv6 && c.ipv6.length) bits.push(c.ipv6[0]);
        const mac = dispMac(c);
        if (mac) bits.push(mac);
        if (c.ouiHint) bits.push(c.ouiHint);
        meta.textContent = bits.join(' - ');
        const dur = Y.el('div', { class: 'client-meta' }, c.online
          ? 'connected ' + Y.fmtDur(c.assocSec || Math.round((Date.now() - c.firstSeenMs) / 1000))
          : 'offline ' + Y.fmtDur(c.offlineSec));
        main.append(name, meta, dur);
        const tr = Y.el('div', { class: 'traffic-pair' });
        tr.append(
          Y.el('span', { class: 'dl' }, '↓ ' + Y.fmtBytes(c.rxBytes)),
          Y.el('span', { class: 'ul' }, '↑ ' + Y.fmtBytes(c.txBytes)),
        );
        main.appendChild(tr);
        if (c.rssi) main.appendChild(Y.el('div', { class: 'client-meta' }, c.rssi + ' dBm'));
        el.append(ic, main);
        el.appendChild(Y.el('div', { style: 'display:flex;flex-direction:column;align-items:flex-end;gap:6px' }, [
          chip(c.online ? 'yes' : 'muted', c.online ? 'online' : 'offline'),
          c.iface ? Y.el('span', { class: 'client-meta' }, c.iface) : null,
        ]));
        listHost.appendChild(el);
      }
    } catch (e) {
      if (!needsLoginErr(e) && Date.now() - lastErr > 10000) { Y.snack(e.message, { err: true }); lastErr = Date.now(); }
    } finally { loading = false; }
  }

  load();
  const t = setInterval(() => { if (!document.hidden) load(); }, 8000);
  return () => { clearInterval(t); unsubs.forEach(f => f()); };
};

/* ------------------------------------------------------------ wifi */

Y.pages.wifi = function (root) {
  const unsubs = [];
  const wrap = Y.el('div', {});
  root.appendChild(wrap);
  const rssiHist = [];

  const sigChart = chartCard('Signal (RSSI)', 'wifi', {
    height: 150, yFrom0: false, fmt: (v) => Math.round(v) + ' dBm', maxPoints: 240,
    series: [{ key: 'rssi', label: 'station RSSI', color: '#12a36c' }],
  });

  async function render() {
    try {
      const w = await Y.api.get('/wifi');
      Y.clear(wrap);

      const stCard = card('Station (upstream Wi-Fi)', 'wifi');
      const sts = w.stations || [];
      if (!sts.length) {
        stCard.appendChild(Y.el('div', { class: 'unavailable' }, w.note || 'No station interface is active.'));
      } else {
        for (const s of sts) {
          const body = kvList([
            ['Interface', s.iface, { mono: true }],
            ['Connected', s.connected ? 'yes' : 'no'],
            ['SSID', s.ssid || null],
            ['BSSID', s.bssid, { mono: true }],
            ['Band', s.band ? Y.bandLabel(s.band) : null],
            ['Channel', s.channel ? s.channel : (s.frequencyMHz ? 'ch' + Y.freqToChannel(s.frequencyMHz) : null)],
            ['Frequency', s.frequencyMHz ? s.frequencyMHz + ' MHz' : null],
            ['RSSI', s.rssi ? s.rssi + ' dBm' : null],
            ['Link speed', s.linkSpeedMbps ? s.linkSpeedMbps + ' Mbps' : null],
            ['Noise', s.noiseDbm ? s.noiseDbm + ' dBm' : null],
            ['Connected for', s.connectedSec ? Y.fmtDur(s.connectedSec) : null],
            ['Sources', (s.sources || []).join(', ') || null],
          ]);
          if (!s.connected) body.appendChild(Y.el('div', { class: 'unavailable' }, 'disconnected'));
          stCard.appendChild(body);
          if (s.rssi) {
            rssiHist.push({ t: Date.now(), v: { rssi: s.rssi } });
            if (rssiHist.length > 240) rssiHist.shift();
            sigChart._chart.setSamples(rssiHist);
          }
        }
      }

      const apCard = card('Access points (downstream)', 'repeater');
      const aps = w.accessPoints || [];
      if (!aps.length) apCard.appendChild(Y.el('div', { class: 'unavailable' }, 'No active access point. Start the repeater to bring one up.'));
      for (const a of aps) {
        Y.append(apCard, [
          Y.el('div', { style: 'display:flex;gap:10px;align-items:center;margin:8px 0 4px' }, [
            Y.el('b', {}, a.ssid || '(hidden network)'),
            chip(a.active ? 'yes' : 'muted', a.active ? 'active' : 'inactive'),
          ]),
          kvList([
            ['Interface', a.iface, { mono: true }],
            ['BSSID', a.bssid, { mono: true }],
            ['Band/ch', [a.band ? Y.bandLabel(a.band) : null, a.channel ? 'ch ' + a.channel : null].filter(Boolean).join(' ') || null],
            ['Frequency', a.frequencyMHz ? a.frequencyMHz + ' MHz' : null],
            ['PHY generation', [a.he && '802.11ax', a.vht && '802.11ac', a.ht && '802.11n'].filter(Boolean).join(', ') || null],
            ['Country', a.country || null],
            ['Clients', a.clients],
            ['Controller', a.controller || null],
          ]),
        ]);
      }

      const radCard = card('Radios & capabilities', 'signal');
      for (const r of (w.radios || [])) {
        const b = Y.el('div', { style: 'margin-bottom:12px' });
        b.appendChild(Y.el('div', { style: 'display:flex;gap:8px;align-items:center;flex-wrap:wrap' }, [
          Y.el('b', {}, r.phy + (r.driver ? ' - ' + r.driver : '')),
          r.supportsAp ? chip('yes', 'AP') : chip('no', 'no AP'),
          r.supportsSta ? chip('yes', 'STA') : chip('no', 'no STA'),
          r.he ? chip('info', 'Wi-Fi 6') : (r.vht ? chip('info', 'Wi-Fi 5') : (r.ht40 ? chip('info', 'Wi-Fi 4') : null)),
        ]));
        const chLines = [];
        if ((r.channels2ghz || []).length) chLines.push('2.4 GHz: ch ' + r.channels2ghz.join(','));
        if ((r.channels5ghz || []).length) chLines.push('5 GHz: ch ' + r.channels5ghz.join(','));
        if ((r.channels6ghz || []).length) chLines.push('6 GHz: ch ' + r.channels6ghz.join(','));
        b.appendChild(Y.el('div', { class: 'stat-sub' }, chLines.join(' | ') || 'no channel list'));
        if ((r.interfaceCombos || []).length) b.appendChild(Y.el('div', { class: 'field-help' }, 'concurrency: ' + r.interfaceCombos.join(' + ')));
        if (r.concurrencyHint) b.appendChild(Y.el('div', { class: 'field-help' }, r.concurrencyHint));
        radCard.appendChild(b);
      }
      const capList = card('Driver capabilities', 'diagnostics');
      const cw = Y.el('div', { class: 'chips' });
      for (const c of (w.capabilities || [])) {
        if (!/WIFI|AP|STA|CONCURREN|HOSTAPD|IW/.test(c.id)) continue;
        cw.appendChild(chip(c.state === 'yes' ? 'yes' : c.state === 'degraded' ? 'warn' : 'no', c.id.toLowerCase().replace(/_/g, ' ')));
      }
      capList.appendChild(cw);

      Y.append(wrap, [
        Y.el('div', { class: 'grid' }, [stCard, apCard]),
        Y.el('div', { style: 'margin-top:12px' }, [sigChart]),
        Y.el('div', { class: 'grid', style: 'margin-top:12px' }, [radCard, capList]),
      ]);
    } catch (e) {
      if (!needsLoginErr(e)) wrap.appendChild(banner('error', 'error', e.message));
    }
  }

  render();
  const t = setInterval(() => { if (!document.hidden) render(); }, 6000);
  return () => { clearInterval(t); unsubs.forEach(f => f()); };
};

/* ------------------------------------------------------------ network */

function flatTable(headers, rows, cls) {
  const wrapEl = Y.el('div', { class: 'table-wrap' });
  const tb = Y.el('table', { class: 'data' + (cls ? ' ' + cls : '') });
  tb.appendChild(Y.el('thead', {}, Y.el('tr', {}, headers.map(h => Y.el('th', {}, h)))));
  const tbody = Y.el('tbody');
  for (const r of rows) tbody.appendChild(Y.el('tr', {}, r.map(cell => cell instanceof Node ? Y.el('td', {}, cell) : Y.el('td', {}, cell == null ? '-' : String(cell)))));
  tb.appendChild(tbody);
  wrapEl.appendChild(tb);
  return wrapEl;
}

Y.pages.network = function (root) {
  const wrap = Y.el('div', {});
  root.appendChild(wrap);

  async function render() {
    try {
      const d = await Y.api.get('/network');
      Y.clear(wrap);
      const rep = d.repeater || {};

      const health = [];
      if (rep.dhcpRunning) health.push(chip('yes', 'DHCP running')); else health.push(chip('warn', 'DHCP off'));
      if (rep.dnsRunning) health.push(chip('yes', 'DNS running')); else health.push(chip('warn', 'DNS off'));
      health.push(chip('info', 'firewall: ' + (rep.firewallBackend || 'none')));
      if (d.snapshot && d.snapshot.ipv6Enabled) health.push(chip('yes', 'IPv6 enabled'));
      Y.append(wrap, [Y.el('div', { class: 'chips', style: 'margin-bottom:12px' }, health)]);

      if ((d.tunnel || []).length) {
        for (const t of d.tunnel) {
          wrap.appendChild(banner('warn', 'warning', 'VPN/tunnel interface ' + t.iface + (t.address ? ' (' + t.address + ')' : '') + ' is ' + (t.up ? 'up' : 'down') + '. ' + (t.warning || ''),
            Y.el('div', { class: 'field-help' }, 'Yoru never modifies VPN configuration.')));
        }
      }

      const routeCard = card('Routes (default)', 'route');
      const rs = ((d.snapshot || {}).routes || []).filter(r => r.isDefault || (r.dst && r.dst !== 'default' && r.table === 'main' && r.dst.split('/')[0].startsWith('192.168'))).slice(0, 20);
      routeCard.appendChild(flatTable(['family', 'destination', 'via', 'dev', 'table', 'metric'],
        rs.map(r => [r.family, r.dst, r.gateway || '-', r.dev, r.table, r.metric])));

      const dnsCard = card('DNS', 'dns');
      const ds = (d.snapshot || {}).dns || [];
      Y.append(dnsCard, [
        flatTable(['server', 'iface', 'source'], ds.map(x => [x.server, x.iface || '-', x.source])),
        d.dnsServer ? kvList([
          ['Yoru forwarder', d.dnsServer.running ? 'running' : 'stopped'],
          ['bind', d.dnsServer.bind, { mono: true }],
          ['upstream', d.dnsServer.upstream || null, { mono: true }],
          ['queries', d.dnsServer.quotes ?? d.dnsServer.queries],
          ['cache entries', d.dnsServer.cached],
        ]) : null,
      ]);

      const dhcpCard = card('DHCP', 'network');
      if (d.dhcpServer) {
        Y.append(dhcpCard, [kvList([
          ['Built-in server', d.dhcpServer.running ? 'running' : 'stopped'],
          ['Interface', d.dhcpServer.iface, { mono: true }],
          ['Pool', d.dhcpServer.pool, { mono: true }],
          ['Pool size', d.dhcpServer.poolSize],
          ['Lease', d.dhcpServer.leaseSeconds ? Y.fmtDur(d.dhcpServer.leaseSeconds) : null],
          ['Active', d.dhcpServer.active],
          ['Packets', d.dhcpServer.packets],
        ])]);
      } else dhcpCard.appendChild(Y.el('div', { class: 'unavailable' }, 'Built-in DHCP server not active (leases may come from the framework or dnsmasq).'));
      if ((d.leases || []).length) {
        dhcpCard.appendChild(Y.el('div', { class: 'card-title', style: 'margin-top:10px' }, 'Leases'));
        dhcpCard.appendChild(flatTable(['ip', 'mac', 'hostname', 'expires'],
          d.leases.map(l => [l.ip, l.mac, l.hostname || '-', Y.fmtAgo(l.expiryMs)]), 'compact'));
      }

      const fwCard = card('Firewall (Yoru objects only)', 'lock');
      const f = d.firewall || {};
      const fkv = [['backend', f.backend], ['binary', f.binary, { mono: true }], ['active', f.active === undefined ? null : (f.active ? 'yes' : 'no')]];
      if (f.chains) for (const [k, v] of Object.entries(f.chains)) fkv.push([k, v + ' rules', { mono: true }]);
      fwCard.appendChild(kvList(fkv));

      const ifCard = card('Interfaces', 'network');
      const links = (d.snapshot || {}).links || [];
      ifCard.appendChild(flatTable(['name', 'state', 'mac', 'mtu', 'type', 'speed'],
        links.map(l => [l.name, (l.up ? 'up' : 'down') + (l.operState ? '/' + l.operState : ''), l.mac || '-', l.mtu, l.kind || l.type, l.speedMbps ? l.speedMbps + ' Mb/s' : '-'])));

      Y.append(wrap, [
        Y.el('div', { class: 'grid' }, [routeCard, dnsCard]),
        Y.el('div', { class: 'grid', style: 'margin-top:12px' }, [dhcpCard, fwCard]),
        Y.el('div', { style: 'margin-top:12px' }, [ifCard]),
      ]);
    } catch (e) {
      if (!needsLoginErr(e)) wrap.appendChild(banner('error', 'error', e.message));
    }
  }
  render();
  const t = setInterval(() => { if (!document.hidden) render(); }, 8000);
  return () => clearInterval(t);
};

/* ------------------------------------------------------------ system */

Y.pages.system = function (root) {
  const wrap = Y.el('div', {});
  root.appendChild(wrap);

  async function render() {
    try {
      const [sys, store, info] = await Promise.all([
        Y.api.get('/system'), Y.api.get('/storage'), Y.pollInfo().catch(() => null),
      ]);
      Y.clear(wrap);
      const a = sys.android || {};
      const k = sys.kernel || {};
      const infoA = (info && info.android) || {};

      const osCard = card('Device', 'system');
      osCard.appendChild(kvList([
        ['Model', [a.manufacturer, a.model].filter(Boolean).join(' ') || null],
        ['Device', a.device || null, { mono: true }],
        ['Android', a.release ? a.release + ' (SDK ' + a.sdk + ')' : null],
        ['SoC', a.soc || infoA.securityPatch ? (a.soc || '') : null],
        ['Board', a.board || null, { mono: true }],
        ['ABI', [a.abi, a.abilist && a.abilist !== a.abi ? '(' + a.abilist + ')' : ''].filter(Boolean).join(' ') || null, { mono: true }],
        ['Build', infoA.incremental || a.display || null],
        ['Security patch', infoA.securityPatch || null],
        ['Kernel', [k.sysname, k.release, k.version].filter(Boolean).join(' ') || null, { mono: true }],
        ['Boot ID', sys.bootId || null, { mono: true }],
        ['Uptime', Y.fmtDur(sys.uptimeSec)],
      ]));

      const cpuCard = card('Processor', 'cpu');
      const c = sys.cpu || {};
      Y.append(cpuCard, [
        kvList([
          ['Model', c.model || null],
          ['Cores', c.cores ? c.onlineCores + ' online / ' + c.cores + ' total' : null],
          ['Governors', (c.governors || []).join(', ') || null],
          ['Load', c.load ? [c.load.l1, c.load.l5, c.load.l15].map(x => x == null ? '-' : x.toFixed(2)).join(' ') : null],
          ['Architecture', [c.arch, c.cpuPart].filter(Boolean).join(' / ') || null],
        ]),
      ]);

      const runCard = card('Runtime', 'performance');
      const r = sys.runtime || {};
      runCard.appendChild(kvList([
        ['Daemon pid', sys.pid],
        ['Go version', r.goVersion],
        ['Goroutines', r.goroutines],
        ['Heap in use', Y.fmtBytes(r.allocBytes)],
        ['Reserved (Go)', Y.fmtBytes(r.sysBytes)],
        ['Processes', (sys.procs || {}).running != null ? sys.procs.running + ' running / ' + sys.procs.total + ' total' : null],
      ]));

      const stCard = card('Storage', 'storage');
    const seen = new Set();
    const parts = (store.partitions || []).filter(p => {
      if (p.fsType === 'tmpfs' || p.totalBytes === 0) return false;
      const key = p.totalBytes + ':' + p.device;
      if (seen.has(key)) return false;
      seen.add(key);
      return p.important || p.mount === '/data' || p.mount === '/';
    });
      const list = Y.el('div', { class: 'list' });
      for (const p of parts) {
        const li = Y.el('div', { class: 'list-item' });
        const body = Y.el('div', { class: 'li-body' });
        body.appendChild(Y.el('div', { class: 'li-title mono' }, p.mount));
        body.appendChild(Y.el('div', { class: 'li-sub' }, Y.fmtBytes(p.usedBytes) + ' of ' + Y.fmtBytes(p.totalBytes) + ' - ' + p.fsType + (p.readOnly ? ' (read-only)' : '')));
        const bar = Y.el('div', { class: 'bar', style: 'margin-top:6px' });
        const fill = Y.el('i', { class: p.usedPct > 92 ? 'err' : p.usedPct > 80 ? 'warn' : 'ok' });
        fill.style.width = Math.min(100, p.usedPct || 0) + '%';
        bar.appendChild(fill);
        body.appendChild(bar);
        li.appendChild(body);
        li.appendChild(Y.el('div', { class: 'li-side' }, Math.round(p.usedPct) + '%'));
        list.appendChild(li);
      }
      stCard.appendChild(list.length || parts.length ? list : Y.el('div', { class: 'unavailable' }, 'Filesystem statistics are not readable on this device.'));
      if (store.log) {
        stCard.appendChild(Y.el('div', { class: 'field-help' }, 'Yoru logs: ' + Y.fmtBytes(store.log.bytes || 0) + ' in ' + (store.log.files || 1) + ' file(s)'));
      }

      Y.append(wrap, [
        Y.el('div', { class: 'grid' }, [osCard, cpuCard]),
        Y.el('div', { class: 'grid', style: 'margin-top:12px' }, [runCard, stCard]),
      ]);
    } catch (e) {
      if (!needsLoginErr(e)) wrap.appendChild(banner('error', 'error', e.message));
    }
  }
  render();
  const t = setInterval(() => { if (!document.hidden) render(); }, 10000);
  return () => clearInterval(t);
};

/* ------------------------------------------------------------ battery */

Y.pages.battery = function (root) {
  const wrap = Y.el('div', {});
  root.appendChild(wrap);
  const chart = chartCard('Capacity & power', 'battery', {
    height: 160, maxPoints: 300,
    fmt: (v) => Math.round(v) + (v > 2000 ? ' mW' : '%'),
    series: [
      { key: 'capacity', label: 'capacity %', color: '#12a36c' },
      { key: 'powerMw', label: 'power mW (signed)', color: '#e8672f' },
    ],
  });

  async function render() {
    try {
      const [b, hist] = await Promise.all([Y.api.get('/battery'), Y.api.get('/history?series=battery&points=300').catch(() => null)]);
      if (hist && hist.series && hist.series.battery) chart._chart.setSamples(hist.series.battery);
      const bb = b.battery || {};
      Y.clear(wrap);
      const gCard = card(null, null, null, 'hero');
      const g = gaugeEl(110);
      gaugeSet(g, bb.capacity, '%');
      const side = Y.el('div', {});
      side.appendChild(Y.el('div', { class: 'stat-value big' }, (bb.capacity ?? '-') + '%'));
      side.appendChild(Y.el('div', {}, chip(bb.status === 'Charging' ? 'yes' : bb.status === 'Discharging' ? 'warn' : 'muted', bb.status || 'state unknown')
      ));
      const sub = Y.el('div', { class: 'stat-sub', style: 'margin-top:6px' });
      if (bb.status === 'Charging' && bb.timeToFullS) sub.textContent = 'full in ' + Y.fmtDur(bb.timeToFullS);
      else if (bb.status === 'Discharging' && bb.timeToEmptyS) sub.textContent = 'empty in ' + Y.fmtDur(bb.timeToEmptyS);
      else if (bb.status === 'Full') sub.textContent = 'battery full';
      side.appendChild(sub);
      Y.append(gCard, [Y.el('div', { style: 'display:flex;gap:20px;align-items:center' }, [g, side])]);
      if (b.note) gCard.appendChild(Y.el('div', { class: 'field-help', style: 'margin-top:8px' }, b.note));

      const detCard = card('Details', 'battery');
      detCard.appendChild(kvList([
        ['Supply node', bb.name, { mono: true }],
        ['Source', bb.source || null],
        ['Health', bb.health || null],
        ['Technology', bb.technology || null],
        ['Temperature', bb.tempMilliC ? (bb.tempMilliC / 100).toFixed(1) + ' °C' : null],
        ['Voltage', bb.voltageUv ? (bb.voltageUv / 1e6).toFixed(2) + ' V' : null],
        ['Current', bb.currentUa ? (bb.currentUa / 1000).toFixed(0) + ' mA' : null],
        ['Power', bb.powerMw ? (Math.abs(bb.powerMw) >= 1000 ? (bb.powerMw / 1000).toFixed(2) + ' W' : bb.powerMw + ' mW') : null],
        ['Charge now', bb.chargeNowMah != null && bb.chargeNowMah !== 0 ? bb.chargeNowMah + ' mAh' : null],
        ['Charge full', bb.chargeFullMah || null],
        ['Design capacity', bb.fullDesignMah || null],
        ['Cycle count', bb.cycleCount || null],
        ['Charger', bb.chargerType || null],
        ['Plugged in', bb.online === undefined ? null : (bb.online ? 'yes' : 'no')],
        ['Present', bb.present === undefined ? null : (bb.present ? 'yes' : 'no')],
      ]));
      if ((bb.missing || []).length) {
        detCard.appendChild(Y.el('div', { class: 'field-help' }, 'Not exposed by this battery driver: ' + bb.missing.join(', ')));
      }
      Y.append(wrap, [Y.el('div', { class: 'grid' }, [gCard, detCard]), Y.el('div', { style: 'margin-top:12px' }, [chart])]);
    } catch (e) {
      if (!needsLoginErr(e)) wrap.appendChild(banner('error', 'error', e.message));
    }
  }
  const un = Y.bus.on('live:battery', render);
  render();
  return () => { un(); };
};

/* ------------------------------------------------------------ performance */

Y.pages.performance = function (root) {
  const wrap = Y.el('div', {});
  root.appendChild(wrap);
  let rangeMin = 5;

  const cs = getComputedStyle(document.documentElement);
  const c1 = cs.getPropertyValue('--md-primary').trim(), c2 = cs.getPropertyValue('--chart-2').trim(),
    c3 = cs.getPropertyValue('--chart-3').trim(), c4 = cs.getPropertyValue('--chart-4').trim(),
    c5 = cs.getPropertyValue('--chart-5').trim(), c6 = cs.getPropertyValue('--chart-6').trim();

  const cpuChart = chartCard('CPU usage', 'cpu', { height: 160, unit: 'pct', fmt: v => Math.round(v) + '%', maxPoints: 1200, series: [{ key: 'total', label: 'total', color: c1 }] });
  const perCoreChart = chartCard('Per-core usage', 'cpu', { height: 160, unit: 'pct', fmt: v => Math.round(v) + '%', maxPoints: 1200, series: [] });
  const memChart = chartCard('Memory', 'memory', { height: 160, fmt: v => Math.round(v) + ' MB', maxPoints: 1200, series: [{ key: 'usedMb', label: 'used', color: c4 }, { key: 'availableMb', label: 'available', color: c2 }] });
  const thChart = chartCard('Temperature', 'thermo', { height: 160, yFrom0: false, fmt: v => Math.round(v) + ' °C', maxPoints: 1200, series: [] });
  const trChart = chartCard('Throughput', 'traffic', { height: 160, unit: 'bytes', maxPoints: 1200, series: [{ key: 'rxBps', label: 'down', color: c2 }, { key: 'txBps', label: 'up', color: c4 }] });
  const batChart = chartCard('Battery', 'battery', { height: 160, fmt: v => Math.round(v) + '%', maxPoints: 1200, series: [{ key: 'capacity', label: 'capacity', color: c2 }] });

  const seg = Y.el('div', { class: 'segmented', role: 'group', 'aria-label': 'Time range' });
  for (const [m, label] of [[1, '1 min'], [5, '5 min'], [15, '15 min'], [60, '1 h']]) {
    const b = Y.el('button', { type: 'button', class: m === rangeMin ? 'sel' : '' }, label);
    b.addEventListener('click', () => {
      rangeMin = m;
      for (const x of seg.children) x.classList.remove('sel');
      b.classList.add('sel');
      load();
    });
    seg.appendChild(b);
  }

  async function load() {
    const pts = Math.min(1200, rangeMin * 60);
    try {
      const h = await Y.api.get('/history?points=' + pts);
      const s = h.series || {};
      cpuChart._chart.setSamples(s.cpu || []);
      memChart._chart.setSamples(s.memory || []);
      trChart._chart.setSamples(s.traffic || []);
      batChart._chart.setSamples(s.battery || []);

      const perc = s.cpuPerCore || [];
      const coreKeys = new Set();
      for (const sm of perc) for (const k of Object.keys(sm.v || {})) if (/^\d+$/.test(k)) coreKeys.add(k);
      const keys = [...coreKeys].sort((a, b) => +a - +b);
      const palette = [c1, c2, c3, c4, c5, c6, '#666'];
      perCoreChart._chart.series = [];
      Y.clear(perCoreChart.querySelector('.legend'));
      keys.forEach((k, i) => {
        perCoreChart._chart.addSeries(k, 'core ' + k, palette[i % palette.length]);
        perCoreChart.querySelector('.legend').appendChild(Y.el('span', {}, [Y.el('i', { style: 'background:' + palette[i % palette.length] }), 'core ' + k]));
      });
      perCoreChart._chart.setSamples(perc);
      perCoreChart._chart.draw();

      const th = s.thermal || [];
      const totals = {};
      for (const sm of th) for (const [k, v] of Object.entries(sm.v || {})) (totals[k] = totals[k] || []).push(v);
      const top = Object.entries(totals)
        .map(([k, vs]) => [k, vs.reduce((a, b) => a + b, 0) / vs.length])
        .sort((a, b) => b[1] - a[1]).slice(0, 5);
      thChart._chart.series = [];
      Y.clear(thChart.querySelector('.legend'));
      top.forEach(([k], i) => {
        thChart._chart.addSeries(k, k.replace(/\//g, ' '), palette[i % palette.length]);
        thChart.querySelector('.legend').appendChild(Y.el('span', {}, [Y.el('i', { style: 'background:' + palette[i % palette.length] }), k.replace(/\//g, ' ')]));
      });
      thChart._chart.setSamples(th);
      thChart._chart.draw();
    } catch (e) {
      if (!needsLoginErr(e)) Y.snack(e.message, { err: true });
    }
  }
  Y.append(wrap, [
    Y.el('div', { style: 'margin-bottom:12px' }, [seg]),
    Y.el('div', { class: 'grid-2' }, [cpuChart, perCoreChart, memChart, thChart, trChart, batChart]),
  ]);
  load();
  const t = setInterval(() => { if (!document.hidden) load(); }, 5000);
  return () => clearInterval(t);
};

/* ------------------------------------------------------------ traffic */

Y.pages.traffic = function (root) {
  const wrap = Y.el('div', {});
  root.appendChild(wrap);
  const cs = getComputedStyle(document.documentElement);
  const big = chartCard('Throughput', 'traffic', {
    height: 210, unit: 'bytes', maxPoints: 1200,
    series: [
      { key: 'rxBps', label: 'Download', color: cs.getPropertyValue('--chart-2').trim() },
      { key: 'txBps', label: 'Upload', color: cs.getPropertyValue('--chart-4').trim() },
    ],
  });
  const totalsBox = Y.el('div', { class: 'grid' });
  const tableBox = Y.el('div', { style: 'margin-top:12px' });
  Y.append(wrap, [totalsBox, Y.el('div', { style: 'margin-top:12px' }, [big]), tableBox]);

  function paintLive() {
    const tr = Y.live.get('traffic');
    if (!tr || !tr.rates) return;
    const h = Y.live.histOf('trafficRate');
    const last = h[h.length - 1];
    if (last) { big._chart.push({ t: last.t, v: { rxBps: last.v.rx, txBps: last.v.tx } }); big._chart.draw(); }
  }
  async function load() {
    try {
      const [tr, hist] = await Promise.all([Y.api.get('/traffic'), Y.api.get('/history?series=traffic&points=600').catch(() => null)]);
      if (hist && hist.series && hist.series.traffic) big._chart.setSamples(hist.series.traffic);
      Y.clear(totalsBox);
      const agg = (tr.rates || {}).__agg;
      if (agg) {
        const c1 = card(null, 'download'), c2 = card(null, 'upload');
        Y.append(c1, [Y.el('div', { class: 'stat-label' }, 'Current'), Y.el('div', { class: 'stat-value big' }, agg.valid ? Y.fmtRate(agg.rxBytesPerSec) : '-'), Y.el('div', { class: 'stat-sub' }, 'total ' + Y.fmtBytes(agg.rxBytesTotal) + ' - ' + Y.fmtNum(agg.rxPacketsTotal) + ' pkts')]);
        Y.append(c2, [Y.el('div', { class: 'stat-label' }, 'Current'), Y.el('div', { class: 'stat-value big' }, agg.valid ? Y.fmtRate(agg.txBytesPerSec) : '-'), Y.el('div', { class: 'stat-sub' }, 'total ' + Y.fmtBytes(agg.txBytesTotal) + ' - ' + Y.fmtNum(agg.txPacketsTotal) + ' pkts')]);
        totalsBox.append(c1, c2);
      }
      const rows = Object.values(tr.rates || {}).filter(r => r.iface !== 'aggregate').sort((a, b) => (b.rxBytesTotal + b.txBytesTotal) - (a.rxBytesTotal + a.txBytesTotal));
      Y.clear(tableBox);
      tableBox.appendChild(card('Per interface (/sys/class/net/.../statistics)', 'storage',
        flatTable(['interface', 'down now', 'up now', 'rx total', 'tx total', 'rx pkts', 'tx pkts', 'rx err/drop', 'tx err/drop'],
          rows.map(r => [
            r.iface, r.valid ? Y.fmtRate(r.rxBytesPerSec) : '-', r.valid ? Y.fmtRate(r.txBytesPerSec) : '-',
            Y.fmtBytes(r.rxBytesTotal), Y.fmtBytes(r.txBytesTotal),
            Y.fmtNum(r.rxPacketsTotal), Y.fmtNum(r.txPacketsTotal),
            r.rxErrors + ' / ' + r.rxDropped, r.txErrors + ' / ' + r.txDropped,
          ]))));
    } catch (e) {
      if (!needsLoginErr(e)) Y.snack(e.message, { err: true });
    }
  }
  load();
  const un = Y.bus.on('live:traffic', paintLive);
  const t = setInterval(() => { if (!document.hidden) load(); }, 8000);
  return () => { clearInterval(t); un(); };
};

/* ------------------------------------------------------------ logs */

Y.pages.logs = function (root) {
  let unsubs = [];
  const state = { level: '', q: '', live: true, follow: true, last: 0 };
  const wrap = Y.el('div', {});
  root.appendChild(wrap);

  const bar = Y.el('div', { style: 'display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:12px' });
  const search = Y.el('input', { type: 'search', placeholder: 'Filter logs…', 'aria-label': 'Filter logs', style: 'flex:1;min-width:160px;padding:12px 16px;border-radius:999px;border:1px solid var(--md-outline-variant);background:var(--md-surface-container);color:var(--md-on-surface);font:inherit' });
  search.addEventListener('input', () => { state.q = search.value; refresh(true); });
  const seg = Y.el('div', { class: 'segmented', role: 'group', 'aria-label': 'Minimum log level' });
  for (const lv of ['DEBUG', 'INFO', 'WARN', 'ERROR']) {
    const b = Y.el('button', { type: 'button', class: lv === 'INFO' ? '' : (lv === '' ? 'sel' : '') }, lv);
    b.addEventListener('click', () => {
      state.level = seg.querySelector('.sel') === b ? '' : lv;
      for (const x of seg.children) x.classList.remove('sel');
      if (state.level) b.classList.add('sel');
      refresh(true);
    });
    seg.appendChild(b);
  }
  const liveToggle = Y.el('label', { class: 'switch-row', style: 'padding:4px 0;gap:8px' });
  const sw = Y.el('span', { class: 'switch' });
  const chk = Y.el('input', { type: 'checkbox', checked: true });
  chk.setAttribute('aria-label', 'Live updates');
  sw.append(chk, Y.el('i'));
  liveToggle.append(sw, Y.el('span', {}, 'Live'));
  chk.addEventListener('change', () => { state.live = chk.checked; });
  bar.append(search, seg, liveToggle);

  const actions = Y.el('div', { style: 'display:flex;gap:4px;margin-left:auto' });
  actions.append(
    Y.iconBtn('copy', 'Copy visible logs', () => {
      Y.copyText([...box.querySelectorAll('.logline')].map(l => l.textContent.replace(/\s+/g, ' ').trim()).join('\n')).then(ok => Y.snack(ok ? 'Logs copied' : 'Copy failed', { err: !ok }));
    }),
    Y.iconBtn('download', 'Download logs', () => {
      fetch('/api/v1/logs?download=text&limit=5000&' + new URLSearchParams(state.q ? { q: state.q } : {}), { credentials: 'same-origin' })
        .then(r => r.ok ? r.text() : Promise.reject(new Error('download refused')))
        .then(txt => Y.download('yoru-logs.txt', 'text/plain', txt))
        .catch(e => Y.snack(e.message, { err: true }));
    }),
    Y.iconBtn('delete', 'Clear view (does not delete daemon logs)', () => { Y.clear(box); state.last = 0; refresh(true); }),
  );
  bar.appendChild(actions);

  const box = Y.el('div', { class: 'logbox', tabindex: '0', role: 'log', 'aria-label': 'Daemon log', 'aria-live': 'off' });
  const errHost = Y.el('div', {});
  Y.append(wrap, [errHost, bar, box]);

  async function refresh(reset) {
    try {
      const qs = new URLSearchParams({ limit: '300' });
      if (state.level) qs.set('level', state.level.toLowerCase());
      if (state.q) qs.set('q', state.q);
      const d = await Y.api.get('/logs?' + qs.toString());
      const es = d.entries || [];
      if (reset) {
        Y.clear(box);
        state.last = 0;
        for (const e of es) addLine(e);
      } else {
        for (const e of es) if (e.t > state.last) addLine(e);
      }
      if (es.length) state.last = es[es.length - 1].t;
    } catch (e) {
      if (!needsLoginErr(e)) Y.clear(errHost), errHost.appendChild(banner('error', 'error', e.message));
    }
  }
  function addLine(e) {
    const line = Y.el('div', { class: 'logline ' + (e.level || 'INFO') });
    line.append(
      Y.el('span', { class: 'lt' }, Y.fmtTime(e.t)),
      Y.el('span', { class: 'll' }, (e.level || '').slice(0, 5)),
      Y.el('span', { class: 'ls' }, e.src || ''),
      Y.el('span', { class: 'lm' }, e.msg || ''),
    );
    box.appendChild(line);
    while (box.children.length > 800) box.removeChild(box.firstChild);
    if (state.follow) box.scrollTop = box.scrollHeight;
  }
  box.addEventListener('scroll', () => {
    state.follow = box.scrollTop + box.clientHeight >= box.scrollHeight - 30;
  });
  refresh(true);
  const t = setInterval(() => { if (state.live && !document.hidden) refresh(false); }, 3000);
  return () => { clearInterval(t); unsubs.forEach(f => f()); };
};

/* ------------------------------------------------------------ diagnostics */

Y.pages.diagnostics = function (root) {
  const wrap = Y.el('div', {});
  root.appendChild(wrap);

  async function render() {
    Y.clear(wrap);
    const bar = Y.el('div', { style: 'display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px' });
    bar.append(
      Y.btn('tonal', 'refresh', 'Re-run', render),
      Y.btn('outlined', 'copy', 'Copy report', async () => {
        const ok = await Y.copyText(JSON.stringify(Y.diagRaw || {}, null, 2));
        Y.snack(ok ? 'Report copied' : 'Copy failed', { err: !ok });
      }),
      Y.btn('outlined', 'download', 'Download report', () => {
        Y.download('yoru-diagnostics.json', 'application/json', JSON.stringify(Y.diagRaw || {}, null, 2));
      }),
    );
    wrap.appendChild(bar);
    let d;
    try {
      d = await Y.api.get('/diagnostics');
    } catch (e) {
      wrap.appendChild(banner('error', 'error', 'Diagnostics failed: ' + e.message));
      return;
    }
    Y.diagRaw = d;
    const sec = (title, iconName, nodes) => {
      const c = card(title, iconName);
      Y.append(c, nodes);
      return c;
    };

    const sum = d.summary || {};
    wrap.appendChild(sec('Verdict', 'diagnostics', [
      Y.el('div', { class: 'chips', style: 'margin-bottom:10px' }, [
        chip(sum.trueRepeater ? 'yes' : 'no', 'true repeater'),
        chip(sum.hotspotRouter ? 'yes' : 'no', 'hotspot router'),
        chip(sum.usbRouter ? 'yes' : 'no', 'usb router'),
        chip(sum.ethernetRouter ? 'yes' : 'no', 'ethernet router'),
      ]),
      (sum.reasons || []).length ? Y.el('ul', { style: 'margin:0;padding-left:20px;font-size:.88rem' }, sum.reasons.map(r => Y.el('li', {}, r))) : null,
    ]));

    const a = d.android || {}, r = d.root || {}, k = d.kernel || {}, sel = d.selinux || {};
    wrap.appendChild(sec('Platform', 'system', kvList([
      ['Android', [a.release, a.apiLevelName].filter(Boolean).join(' - ')],
      ['SDK', a.sdk],
      ['Model', [a.manufacturer, a.model].filter(Boolean).join(' ')],
      ['Board/hardware', [a.board, a.hardware, a.bootHardware].filter(Boolean).join(' / ')],
      ['SoC', a.soc || null],
      ['ABI', a.abi],
      ['Kernel', [k.sysname, k.release, k.machine].filter(Boolean).join(' ')],
      ['Root', r.implementation || 'unknown (running uid ' + r.uid + ')'],
      ['Privileged', r.privileged === undefined ? null : (r.privileged ? 'yes' : 'no - network changes are refused')],
      ['SELinux', sel.mode || null],
      ['Identity', ((d.identity || {}).version) + ' built ' + ((d.runtime || {}).uptimeSec != null ? 'up ' + Y.fmtDur(d.runtime.uptimeSec) : '')],
    ])));

    const capsCard = sec('Capabilities', 'signal', null);
    const cw = Y.el('div', { class: 'table-wrap' });
    const tb = Y.el('table', { class: 'data' });
    tb.appendChild(Y.el('thead', {}, Y.el('tr', {}, ['capability', 'state', 'source', 'reason / detail'].map(h => Y.el('th', {}, h)))));
    const tbody = Y.el('tbody');
    for (const c of (d.capabilities || [])) {
      const tr = Y.el('tr');
      tr.append(
        Y.el('td', { class: 'mono' }, c.id),
        Y.el('td', {}, chip(c.state === 'yes' ? 'yes' : c.state === 'degraded' || c.state === 'unknown' ? 'warn' : 'no', c.state)),
        Y.el('td', {}, c.source || ''),
        Y.el('td', { class: 'wrap' }, [c.reason || '', c.detail ? ' ' + c.detail : '', c.fixHint ? ' Fix: ' + c.fixHint : ''].join('')),
      );
      tbody.appendChild(tr);
    }
    tb.appendChild(tbody);
    cw.appendChild(tb);
    capsCard.appendChild(cw);
    wrap.appendChild(capsCard);

    const engCard = sec('Engine', 'repeater', kvList([
      ['State', ((d.engine || {}).state) || 'stopped'],
      ['Mode', (d.engine || {}).modeLabel || null],
      ['Last error', (d.engine || {}).lastError || null],
      ['Firewall', (d.firewall || {}).backend, { mono: true }],
      ['Tools available', Object.entries(d.tools || {}).filter(([, v]) => v).map(([x]) => x).join(', ') || 'none'],
    ]));
    const radios = (d.radios || []).map(rr => rr.phy + ' (' + rr.driver + ': ' + [rr.supportsAp && 'AP', rr.supportsSta && 'STA', rr.supportsP2P && 'P2P'].filter(Boolean).join('/') + ')').join('; ');
    if (radios) engCard.appendChild(Y.el('div', { class: 'field-help' }, 'radios: ' + radios));
    wrap.appendChild(engCard);

    wrap.appendChild(sec('Raw report', 'logs', [
      Y.el('pre', { class: 'mono', style: 'max-height:420px;overflow:auto;background:var(--md-surface-container);padding:14px;border-radius:var(--shape-md);font-size:.74rem;white-space:pre-wrap;word-break:break-word', tabindex: '0' }, JSON.stringify(d, null, 2)),
    ]));
  }
  render();
  return () => { };
};

/* ------------------------------------------------------------ settings */

Y.pages.settings = function (root) {
  let unsubs = [];
  const wrap = Y.el('div', {});
  root.appendChild(wrap);
  let draft = null, avail = null;

  const tabsHost = Y.el('div', { class: 'tabs', role: 'tablist' });
  const body = Y.el('div', { class: 'stack' });
  Y.append(wrap, [tabsHost, body]);

  const TABS = [
    ['appearance', 'Appearance', 'palette'],
    ['repeater', 'Repeater', 'repeater'],
    ['network', 'Network', 'network'],
    ['monitoring', 'Monitoring', 'performance'],
    ['telegram', 'Telegram', 'notifications'],
    ['security', 'Security', 'lock'],
    ['advanced', 'Advanced', 'diagnostics'],
  ];
  let active = Y.store.get('settingsTab', 'appearance');

  function field(label, keyPath, input, help) {
    const f = Y.el('label', { class: 'field' });
    f.appendChild(input);
    f.appendChild(Y.el('span', { class: 'field-label' }, label));
    if (help) f.appendChild(Y.el('span', { class: 'field-help' }, help));
    return f;
  }
  function textInput(label, get, set, help, type) {
    const input = Y.el('input', { type: type || 'text', placeholder: ' ', value: get() == null ? '' : get() });
    input.addEventListener('change', () => set(input.value));
    return field(label, null, input, help);
  }
  function numberInput(label, get, set, help, min, max) {
    const attrs = { type: 'number', placeholder: ' ', value: get() };
    if (min != null) attrs.min = min;
    if (max != null) attrs.max = max;
    const input = Y.el('input', attrs);
    input.addEventListener('change', () => set(input.value === '' ? 0 : Number(input.value)));
    return field(label, null, input, help);
  }
  function selectInput(label, options, get, set, help) {
    const sel = Y.el('select', {});
    for (const [v, l] of options) sel.appendChild(Y.el('option', { value: v, selected: String(get()) === v }, l));
    sel.addEventListener('change', () => set(sel.value));
    const f = Y.el('label', { class: 'field' });
    f.append(sel, Y.el('span', { class: 'field-label' }, label));
    if (help) f.appendChild(Y.el('span', { class: 'field-help' }, help));
    return f;
  }
  function switchRow(label, sub, get, set) {
    const row = Y.el('label', { class: 'switch-row' });
    const sw = Y.el('span', { class: 'switch' });
    const inp = Y.el('input', { type: 'checkbox' });
    inp.checked = !!get();
    inp.addEventListener('change', () => set(inp.checked));
    sw.append(inp, Y.el('i'));
    const txt = Y.el('span', {});
    txt.appendChild(document.createTextNode(label));
    if (sub) txt.appendChild(Y.el('span', { class: 'field-help', style: 'display:block' }, sub));
    row.append(sw, txt);
    return row;
  }
  function sliderRow(label, min, max, step, get, set, fmtv) {
    const row = Y.el('div', { class: 'slider-row' });
    const inp = Y.el('input', { type: 'range', min, max, step });
    inp.value = get();
    const out = Y.el('output', {}, fmtv(Number(inp.value)));
    inp.addEventListener('input', () => { out.textContent = fmtv(Number(inp.value)); set(Number(inp.value)); });
    row.append(Y.el('label', {}, label), inp, out);
    return row;
  }

  function renderTabs() {
    Y.clear(tabsHost);
    for (const [id, label, ic] of TABS) {
      const b = Y.el('button', { type: 'button', role: 'tab', 'aria-selected': id === active, class: id === active ? 'sel' : '' });
      b.appendChild(Y.icon(ic, 'icon-20'));
      b.appendChild(document.createTextNode(' ' + label));
      b.addEventListener('click', () => { active = id; Y.store.set('settingsTab', id); renderTabs(); renderBody(); });
      tabsHost.appendChild(b);
    }
  }

  function renderBody() {
    Y.clear(body);
    if (!draft) { body.appendChild(emptyState('refresh', 'Loading configuration…')); return; }
    const R = draft.repeater, W = draft.web, M = draft.monitor, A = draft.advanced, TG = draft.telegram || {};
    if (active === 'appearance') renderAppearance();
    else if (active === 'repeater') renderRepeater(R);
    else if (active === 'network') renderNetwork(R);
    else if (active === 'monitoring') renderMonitoring(M);
    else if (active === 'telegram') renderTelegram(TG);
    else if (active === 'security') renderSecurity(W);
    else if (active === 'advanced') renderAdvanced(A);
    body.appendChild(saveBar());
  }

  const dirty = new Set();
  function mark(path) { dirty.add(path); }

  function saveBar() {
    const bar = Y.el('div', { style: 'display:flex;gap:10px;align-items:center;margin-top:20px;flex-wrap:wrap' });
    const btn = Y.btn('filled', 'check', 'Apply changes', saveAll);
    const note = Y.el('span', { class: 'stat-sub' });
    bar.append(btn, note);
    updateNote();
    function updateNote() { note.textContent = dirty.size ? dirty.size + ' change(s) pending' : 'Nothing to apply'; }
    btn.updateNote = updateNote;
    bar._update = updateNote;
    return bar;
  }

  async function saveAll() {
    if (!dirty.size) { Y.snack('No pending changes'); return; }
    const patch = {};
    const setP = (path, value) => {
      const keys = path.split('.');
      let o = patch;
      for (let i = 0; i < keys.length - 1; i++) o = o[keys[i]] = o[keys[i]] || {};
      o[keys[keys.length - 1]] = value;
    };
    for (const p of dirty) setP(p, getByPath(draft, p));
    try {
      const res = await Y.api.post('/config', patch);
      dirty.clear();
      Y.cache.config = null;
      const cfg = await Y.pollConfig(true);
      draft = Y.clone(cfg.config);
      if (res.rolledBack) {
        Y.snack('Changes were applied but the running repeater rejected them; settings were rolled back: ' + (res.error ? '' : ''), { err: true });
      }
      if ((res.warnings || []).length) Y.snack(res.warnings.join(' '), { err: true, ms: 9000 });
      else if (res.restarted) Y.snack('Saved - repeater restarted with the new settings');
      else if (res.note) Y.snack(res.note);
      else Y.snack('Saved');
      renderBody();
    } catch (e) {
      Y.snack('Apply failed: ' + e.message, { err: true, ms: 9000 });
    }
  }
  function getByPath(o, p) { for (const k of p.split('.')) o = o[k]; return o; }

  function renderAppearance() {
    const c = card('Theme', 'moon');
    const seg = Y.el('div', { class: 'segmented' });
    for (const m of ['system', 'light', 'dark', 'amoled']) {
      const b = Y.el('button', { type: 'button', class: Y.state.mode === m ? 'sel' : '' }, m);
      b.addEventListener('click', () => {
        Y.state.mode = m; Y.store.set('mode', m);
        for (const x of seg.children) x.classList.remove('sel');
        b.classList.add('sel');
        Y.applyTheme();
      });
      seg.appendChild(b);
    }
    c.appendChild(Y.el('div', { class: 'card-title' }, 'Mode'));
    c.appendChild(seg);

    const c2 = card('Color', 'palette');
    c2.appendChild(Y.el('div', { class: 'card-title' }, 'Accent palette'));
    const presets = Y.ACCENTS;
    const chips = Y.el('div', { class: 'chips' });
    for (const p of presets) {
      const b = Y.el('button', { class: 'chip' + (Y.state.accent === p.name ? ' sel' : ''), type: 'button' });
      b.appendChild(Y.el('i', { style: `width:18px;height:18px;border-radius:50%;background:${p.css};display:inline-block` }));
      b.appendChild(document.createTextNode(p.name));
      b.addEventListener('click', () => { Y.state.accent = p.name; Y.store.set('accent', p.name); Y.applyTheme(); renderBody(); });
      chips.appendChild(b);
    }
    c2.appendChild(chips);
    const dyn = Y.el('div', { style: 'margin-top:10px' });
    const inp = Y.el('input', { type: 'color', value: Y.state.seed || '#6c5ce6', 'aria-label': 'Custom accent color' });
    inp.addEventListener('input', () => { Y.state.seed = inp.value; Y.state.accent = 'custom'; Y.store.set('accent', 'custom'); Y.store.set('seed', inp.value); Y.applyTheme(); });
    dyn.append(Y.el('span', { class: 'stat-sub' }, 'Dynamic - pick any seed color (generated locally, M3 tonal ladder): '), inp);
    c2.appendChild(dyn);

    const c3 = card('Interface', 'settings');
    c3.appendChild(switchRow('Mask MAC addresses', 'Privacy-friendly display on the Clients page (local preference)', () => Y.state.maskMacs, (v) => { Y.state.maskMacs = v; Y.store.set('maskMacs', v); }));
    const rp = Y.store.get('refresh', 1);
    c3.appendChild(sliderRow('Dashboard refresh aggressiveness', 1, 5, 1, () => rp, (v) => { Y.store.set('refresh', v); Y.snack('Refresh settings take effect on the next page visit'); }, (v) => ['', 'very slow', 'slow', 'balanced', 'fast', 'very fast'][v]));
    Y.append(body, [Y.el('div', { class: 'grid-2' }, [c, c2]), c3]);
  }

  function renderRepeater(R) {
    const c = card('Access point', 'wifi');
    c.appendChild(textInput('SSID', () => R.ap.ssid, (v) => { R.ap.ssid = v; mark('repeater.ap.ssid'); }, 'Max 32 bytes (802.11 limit)'));
    if (R.ap.passphrase === '__YORU_SECRET_SET__') {
      const pw = Y.el('input', { type: 'password', placeholder: 'unchanged', autocomplete: 'new-password' });
      pw.addEventListener('change', () => {
        if (pw.value) { R.ap.passphrase = pw.value; mark('repeater.ap.passphrase'); }
      });
      c.appendChild(field('Wi-Fi passphrase (8-63 bytes)', null, pw, 'A passphrase is already stored. Leave empty to keep it. Required unless security is open.'));
    } else {
      const pw = Y.el('input', { type: 'text', placeholder: ' ', autocomplete: 'new-password' });
      pw.addEventListener('change', () => { R.ap.passphrase = pw.value; mark('repeater.ap.passphrase'); });
      c.appendChild(field('Wi-Fi passphrase (8-63 bytes)', null, pw, 'Never displayed again after saving and never sent to logs.'));
    }
    const secs = (avail && avail.securities) || ['open', 'wpa2-psk'];
    c.appendChild(selectInput('Security', secs.map(s => [s, s]), () => R.ap.security, (v) => { R.ap.security = v; mark('repeater.ap.security'); }, 'Only what this Wi-Fi driver can do is offered.'));
    const bands = (avail && avail.bands) || ['2g'];
    const bandSel = selectInput('Band', [['auto', 'auto']].concat(bands.map(b => [b, Y.bandLabel(b)])).filter(([v]) => v === 'auto' || bands.includes(v)), () => R.ap.band, (v) => { R.ap.band = v; mark('repeater.ap.band'); });
    c.appendChild(bandSel);
    const chans = (avail && avail.channels) || {};
    const chanSel = Y.el('select', {});
    function fillChannels() {
      Y.clear(chanSel);
      chanSel.appendChild(Y.el('option', { value: '0', selected: String(R.ap.channel) === '0' }, 'auto'));
      const list = chans[R.ap.band] || chans['2g'] || [];
      for (const ch of list) chanSel.appendChild(Y.el('option', { value: String(ch), selected: String(R.ap.channel) === String(ch) }, 'ch ' + ch));
    }
    fillChannels();
    bandSel.querySelector('select').addEventListener('change', () => setTimeout(fillChannels, 0));
    chanSel.addEventListener('change', () => { R.ap.channel = Number(chanSel.value); mark('repeater.ap.channel'); });
    const chanField = Y.el('label', { class: 'field' });
    chanField.append(chanSel, Y.el('span', { class: 'field-label' }, 'Channel'));
    c.appendChild(chanField);
    c.appendChild(switchRow('Hidden SSID', null, () => R.ap.hidden, (v) => { R.ap.hidden = v; mark('repeater.ap.hidden'); }));
    c.appendChild(numberInput('Maximum clients', () => R.ap.maxClients, (v) => { R.ap.maxClients = v; mark('repeater.ap.maxClients'); }, null, 1, 255));
    c.appendChild(textInput('Country code', () => R.ap.countryCode, (v) => { R.ap.countryCode = v; mark('repeater.ap.countryCode'); }, '2-letter ISO code; empty keeps driver default (legal requirement in many regions)'));
    const strat = (avail && avail.apStrategies) || ['auto', 'hostapd', 'android'];
    c.appendChild(selectInput('AP backend', [['auto', 'auto (recommended)'], ['hostapd', 'hostapd (direct driver control)'], ['android', 'android framework hotspot']].filter(o => strat.includes(o[0])), () => R.ap.strategy, (v) => { R.ap.strategy = v; mark('repeater.ap.strategy'); }));

    const m = card('Operation', 'repeater');
    m.appendChild(selectInput('Mode', [['auto', 'auto - pick the best supported'], ['repeater', 'Wi-Fi repeater (STA + AP)'], ['hotspot', 'hotspot router'], ['usb', 'USB upstream router'], ['ethernet', 'Ethernet upstream router'], ['disabled', 'disabled']], () => R.mode, (v) => { R.mode = v; mark('repeater.mode'); }));
    const ifaces = [['auto', 'auto']].concat(((avail && avail.interfaces) || []).map(i => [i, i]));
    m.appendChild(selectInput('Upstream interface', ifaces, () => R.upstream, (v) => { R.upstream = v; mark('repeater.upstream'); }, 'Where internet comes from'));
    m.appendChild(selectInput('Downstream interface', ifaces, () => R.downstream, (v) => { R.downstream = v; mark('repeater.downstream'); }, 'What clients connect to'));
    m.appendChild(switchRow('Start automatically at boot', null, () => R.autoStart, (v) => { R.autoStart = v; mark('repeater.autoStart'); }));
    Y.append(body, [m, c]);
  }

  function renderNetwork(R) {
    const lan = card('LAN / DHCP / DNS', 'network');
    lan.appendChild(textInput('Gateway', () => R.lan.gateway, (v) => { R.lan.gateway = v; mark('repeater.lan.gateway'); }, 'Address of the phone on the repeater network', 'text'));
    lan.appendChild(numberInput('Prefix length', () => R.lan.prefix, (v) => { R.lan.prefix = v; mark('repeater.lan.prefix'); }, '16-30', 16, 30));
    const r1 = Y.el('div', { class: 'form-row cols-2' });
    r1.append(
      textInput('DHCP start', () => R.lan.dhcpStart, (v) => { R.lan.dhcpStart = v; mark('repeater.lan.dhcpStart'); }),
      textInput('DHCP end', () => R.lan.dhcPEnd, (v) => { R.lan.dhcPEnd = v; mark('repeater.lan.dhcPEnd'); }),
    );
    lan.appendChild(r1);
    lan.appendChild(numberInput('Lease time (minutes)', () => R.lan.leaseMinutes, (v) => { R.lan.leaseMinutes = v; mark('repeater.lan.leaseMinutes'); }, null, 1, 10080));
    const dnsModes = (avail && avail.dnsModes) || ['auto', 'builtin', 'off'];
    const dhcpModes = (avail && avail.dhcpModes) || ['auto', 'builtin', 'off'];
    lan.appendChild(selectInput('DHCP mode', dhcpModes.map(x => [x, x]), () => R.lan.dhcpMode, (v) => { R.lan.dhcpMode = v; mark('repeater.lan.dhcpMode'); }, 'built-in = no extra binary needed'));
    lan.appendChild(selectInput('DNS mode', dnsModes.map(x => [x, x]), () => R.lan.dnsMode, (v) => { R.lan.dnsMode = v; mark('repeater.lan.dnsMode'); }));
    const r2 = Y.el('div', { class: 'form-row cols-2' });
    r2.append(
      textInput('Upstream DNS 1', () => R.lan.dns1, (v) => { R.lan.dns1 = v; mark('repeater.lan.dns1'); }, 'empty = detected from the system', 'text'),
      textInput('Upstream DNS 2', () => R.lan.dns2, (v) => { R.lan.dns2 = v; mark('repeater.lan.dns2'); }, null, 'text'),
    );
    lan.appendChild(r2);
    lan.appendChild(selectInput('IPv6', [['auto', 'auto (forward only)'], ['forward', 'forward'], ['ula', 'unique local addresses'], ['off', 'off - v6 disabled for clients']], () => R.lan.ipv6, (v) => { R.lan.ipv6 = v; mark('repeater.lan.ipv6'); }));
    lan.appendChild(textInput('LAN domain', () => R.lan.domain, (v) => { R.lan.domain = v; mark('repeater.lan.domain'); }, 'clients resolve as name.<domain>'));

    const rt = card('Routing / NAT / firewall', 'route');
    rt.appendChild(switchRow('IPv4 forwarding', null, () => R.routing.ipForward, (v) => { R.routing.ipForward = v; mark('repeater.routing.ipForward'); }));
    rt.appendChild(switchRow('IPv6 forwarding', 'Yoru restores the previous sysctl values when the repeater stops', () => R.routing.ipv6Forward, (v) => { R.routing.ipv6Forward = v; mark('repeater.routing.ipv6Forward'); }));
    rt.appendChild(switchRow('Source NAT (masquerade)', 'off = clients need a routable upstream and manual routing', () => R.routing.nat, (v) => { R.routing.nat = v; mark('repeater.routing.nat'); }));
    rt.appendChild(switchRow('Isolate clients', 'block client-to-client traffic', () => R.routing.isolateClients, (v) => { R.routing.isolateClients = v; mark('repeater.routing.isolateClients'); }));
    rt.appendChild(selectInput('Firewall backend', [['auto', 'auto (prefer least invasive)'], ['iptables', 'iptables'], ['nftables', 'nftables']], () => R.routing.firewallBackend, (v) => { R.routing.firewallBackend = v; mark('repeater.routing.firewallBackend'); }, 'Yoru only ever writes its own YORU_* chains; the rest of the ruleset is never touched.'));
    Y.append(body, [lan, rt]);
  }

  function renderMonitoring(M) {
    const c = card('Sampling intervals', 'performance', null, '');
    const sl = (label, key, min, max, step, unit) => sliderRow(label, min, max, step,
      () => M[key], (v) => { M[key] = v; mark('monitor.' + key); }, (v) => v >= 1000 ? (v / 1000).toFixed(1) + ' s' : v + ' ms');
    c.append(
      sl('CPU', 'cpuIntervalMs', 250, 30000, 250),
      sl('Memory', 'memIntervalMs', 500, 30000, 250),
      sl('Battery', 'batteryIntervalMs', 1000, 60000, 1000),
      sl('Temperature', 'thermalIntervalMs', 500, 60000, 500),
      sl('Traffic', 'trafficIntervalMs', 250, 30000, 250),
      sl('Clients', 'clientsIntervalMs', 500, 60000, 500),
      sliderRow('Chart history depth', 60, 2000, 60, () => M.historyPoints, (v) => { M.historyPoints = v; mark('monitor.historyPoints'); }, (v) => v + ' samples'),
    );
    const c2 = card('Logs & privacy', 'logs');
    c2.append(
      numberInput('Log file size (bytes)', () => M.logMaxBytes, (v) => { M.logMaxBytes = v; mark('monitor.logMaxBytes'); }, '64 KiB - 64 MiB', 65536, 67108864),
      numberInput('Log rotation files', () => M.logMaxFiles, (v) => { M.logMaxFiles = v; mark('monitor.logMaxFiles'); }, null, 1, 20),
      switchRow('Mask MAC addresses server-side', 'affects API payloads, not just this browser', () => M.maskMacs, (v) => { M.maskMacs = v; mark('monitor.maskMacs'); }),
    );
    c2.appendChild(Y.el('div', { class: 'field-help' }, 'Yoru strips passphrases and tokens from logs automatically; nothing here disables that.'));
    Y.append(body, [c, c2]);
  }

  function renderSecurity(W) {
    const c = card('Dashboard authentication', 'lock');
    c.appendChild(switchRow('Require sign-in for privileged actions', 'start/stop/config changes always require a session when enabled', () => W.auth.enabled, (v) => { W.auth.enabled = v; mark('web.auth.enabled'); }));
    c.appendChild(numberInput('Session lifetime (hours)', () => W.sessionHours, (v) => { W.sessionHours = v; mark('web.sessionHours'); }, null, 1, 720));
    c.appendChild(numberInput('Rate limit (requests/min/client)', () => W.rateLimitPerMin, (v) => { W.rateLimitPerMin = v; mark('web.rateLimitPerMin'); }, null, 10, 100000));
    const pwCard = card('Password', 'key');
    const p1 = Y.el('input', { type: 'password', placeholder: ' ', autocomplete: 'new-password', minlength: 8 });
    const p2 = Y.el('input', { type: 'password', placeholder: ' ', autocomplete: 'new-password', minlength: 8 });
    const cur = Y.el('input', { type: 'password', placeholder: ' ', autocomplete: 'current-password' });
    pwCard.appendChild(field(W.auth.passwordSet ? 'Current password' : 'New password', null, cur, W.auth.passwordSet ? '' : 'No password set yet - first one created here (and until then the dashboard is open on the LAN).'));
    pwCard.appendChild(field('New password', null, p1, 'min 8 characters'));
    pwCard.appendChild(field('Repeat new password', null, p2));
    pwCard.appendChild(Y.btn('filled', 'key', 'Set password', async () => {
      if (p1.value.length < 8) { Y.snack('Password is too short', { err: true }); return; }
      if (p1.value !== p2.value) { Y.snack('The two entries do not match', { err: true }); return; }
      try {
        await Y.api.post('/password', { password: p1.value, current: cur.value || '' });
        Y.snack('Password updated - re-sign in required');
        p1.value = p2.value = cur.value = '';
        Y.cache.config = null; Y.cache.status = null;
        await Y.pollStatus().catch(() => { });
      } catch (e) { Y.snack(e.message, { err: true }); }
    }));
    if (W.auth.passwordSet) {
      pwCard.appendChild(Y.el('div', { style: 'height:10px' }));
      pwCard.appendChild(Y.btn('outlined', 'close', 'Disable password', async () => {
        if (!await Y.confirm('Disable dashboard authentication?', 'Anyone on the repeater network will be able to reconfigure Yoru.', { danger: true, okText: 'Disable' })) return;
        try { await Y.api.post('/password', { password: '', current: '', disable: true }); Y.snack('Authentication disabled'); Y.cache.config = null; Y.pollConfig(true); }
        catch (e) { Y.snack(e.message, { err: true }); }
      }));
    }
    const bind = card('Exposure', 'network');
    bind.appendChild(selectInput('Bind', [['lan', 'LAN interfaces only (recommended)'], ['loopback', 'loopback only (phone-local)'], ['all', 'all interfaces']], () => W.bind, (v) => { W.bind = v; mark('web.bind'); }, 'Which interfaces the dashboard listens on'));
    bind.appendChild(numberInput('Port', () => W.port, (v) => { W.port = v; mark('web.port'); }, '1-65535', 1, 65535));
    bind.appendChild(switchRow('Anonymous read-only monitoring', 'unauthenticated LAN clients can watch charts but never control anything', () => W.readonlyEnabled, (v) => { W.readonlyEnabled = v; mark('web.readonlyEnabled'); }));
    Y.append(body, [c, pwCard, bind]);
  }

  function renderTelegram(TG) {
    if (!draft.telegram) draft.telegram = {};
    const T = draft.telegram;

    const main = card('Telegram Notifications', 'notifications');
    main.appendChild(switchRow('Enable Telegram notifications', 'receive battery alerts on Telegram', () => T.enabled, (v) => { T.enabled = v; mark('telegram.enabled'); }));
    main.appendChild(textInput('Bot Token', () => T.botToken || '', (v) => { T.botToken = v; mark('telegram.botToken'); }, 'from @BotFather on Telegram'));
    main.appendChild(textInput('Chat ID', () => T.chatId || '', (v) => { T.chatId = v; mark('telegram.chatId'); }, 'your Telegram user or group ID'));

    const testBtn = Y.el('button', { class: 'btn btn-tonal', style: 'margin-top:8px' }, 'Send test notification');
    testBtn.addEventListener('click', async () => {
      testBtn.disabled = true;
      testBtn.textContent = 'Sending\u2026';
      try {
        const patch = { telegram: { botToken: T.botToken || '', chatId: T.chatId || '' } };
        await Y.api.post('/config', patch);
        dirty.clear();
        Y.cache.config = null;
        await Y.api.post('/telegram/test', { botToken: T.botToken || '', chatId: T.chatId || '' });
        testBtn.textContent = 'Sent!';
        Y.snack('Saved & test notification sent to Telegram');
      } catch (e) {
        testBtn.textContent = 'Failed';
        Y.snack('Telegram error: ' + e.message, { err: true });
      }
      setTimeout(() => { testBtn.disabled = false; testBtn.textContent = 'Send test notification'; }, 2000);
    });
    main.appendChild(testBtn);

    const lowBat = card('Low Battery Alert', 'battery');
    lowBat.appendChild(switchRow('Notify on low battery', 'send alert when battery drops below threshold', () => T.notifyLowBat, (v) => { T.notifyLowBat = v; mark('telegram.notifyLowBat'); }));
    lowBat.appendChild(numberInput('Low battery threshold (%)', () => T.lowBatPercent || 20, (v) => { T.lowBatPercent = v; mark('telegram.lowBatPercent'); }, 'alert when battery is at or below this level', 5, 50));

    const charge = card('Charge Milestones', 'battery');
    charge.appendChild(switchRow('Notify on charge milestones', 'send alerts while charging', () => T.notifyCharge, (v) => { T.notifyCharge = v; mark('telegram.notifyCharge'); }));
    charge.appendChild(switchRow('80%', 'notify when reaching 80%', () => T.charge80, (v) => { T.charge80 = v; mark('telegram.charge80'); }));
    charge.appendChild(switchRow('90%', 'notify when reaching 90%', () => T.charge90, (v) => { T.charge90 = v; mark('telegram.charge90'); }));
    charge.appendChild(switchRow('100%', 'notify when fully charged', () => T.charge100, (v) => { T.charge100 = v; mark('telegram.charge100'); }));

    Y.append(body, [main, lowBat, charge]);
  }

  function renderAdvanced(A) {
    const c = card('Watchdog / crash recovery', 'diagnostics');
    c.append(
      switchRow('Supervisor restart policy', 'bounded backoff; after the budget is spent Yoru halts and records the error instead of looping', () => A.watchdog.enabled, (v) => { A.watchdog.enabled = v; mark('advanced.watchdog.enabled'); }),
      numberInput('Maximum restarts in window', () => A.watchdog.maxRestarts, (v) => { A.watchdog.maxRestarts = v; mark('advanced.watchdog.maxRestarts'); }, null, 1, 100),
      numberInput('Window (seconds)', () => A.watchdog.windowSec, (v) => { A.watchdog.windowSec = v; mark('advanced.watchdog.windowSec'); }, null, 30, 86400),
      numberInput('Backoff step (ms)', () => A.watchdog.backoffStepMs, (v) => { A.watchdog.backoffStepMs = v; mark('advanced.watchdog.backoffStepMs'); }, null, 100, 60000),
    );
    const d = card('Debug', 'logs');
    d.appendChild(switchRow('Debug logging', 'verbose structured logs; still secret-free', () => A.debug, (v) => { A.debug = v; mark('advanced.debug'); }));
    d.appendChild(switchRow('Force interface even on subnet conflict', 'dangerous: overlapping networks become unreachable for clients', () => A.forceInterface, (v) => { A.forceInterface = v; mark('advanced.forceInterface'); }));
    d.appendChild(textInput('Upstream hint', () => A.upstreamHint || '', (v) => { A.upstreamHint = v; mark('advanced.upstreamHint'); }, 'free-form hint used by diagnostics only'));
    Y.append(body, [c, d]);
  }

  async function boot() {
    try {
      const cfg = await Y.pollConfig(true);
      draft = Y.clone(cfg.config);
      avail = cfg.available;
      renderTabs();
      renderBody();
      if (cfg.password && cfg.password.required) {
        body.prepend(banner('warn', 'key', 'No dashboard password is set. Anyone on the network can control Yoru until you create one (Security tab).'));
      }
      if ((cfg.warnings || []).length) {
        body.prepend(banner('warn', 'warning', 'Configuration notes: ' + cfg.warnings.join(' | ')));
      }
    } catch (e) {
      if (!needsLoginErr(e)) body.appendChild(banner('error', 'error', e.message));
    }
  }
  boot();
  return () => unsubs.forEach(f => f());
};

/* ------------------------------------------------------------ about */

Y.pages.about = function (root) {
  const wrap = Y.el('div', {});
  root.appendChild(wrap);
  async function render() {
    try {
      const info = await Y.pollInfo(true);
      const st = Y.cache.status || {};
      Y.clear(wrap);
      const brand = card(null, null, null, 'hero');
      const row = Y.el('div', { style: 'display:flex;gap:16px;align-items:center' });
      const logo = Y.el('span', { style: 'color:var(--md-on-primary-container)' });
      logo.appendChild(Y.icon('yoru'));
      logo.querySelector('svg').setAttribute('width', '58');
      logo.querySelector('svg').setAttribute('height', '58');
      const t = Y.el('div', {});
      t.appendChild(Y.el('div', { class: 'stat-value', style: 'font-size:1.7rem' }, 'Yoru Repeater'));
      t.appendChild(Y.el('div', {}, (info.version || '') + ' (' + (info.hash || 'dev') + ')'));
      row.append(logo, t);
      Y.append(brand, [row, Y.el('div', { class: 'stat-sub', style: 'margin-top:8px' }, 'Built ' + (info.built || 'unknown') + ' - API v' + (info.api || '?') + ' - config schema ' + (info.schema ?? '?'))]);
      wrap.appendChild(brand);

      const det = card('Build & platform', 'info');
      const a = info.android || {};
      det.appendChild(kvList([
        ['Version', info.version],
        ['Commit', info.hash, { mono: true }],
        ['Built', info.built],
        ['API version', info.api],
        ['Schema', info.schema],
        ['Product', info.product],
        ['Android', [a.release, a.sdk ? 'SDK ' + a.sdk : ''].filter(Boolean).join(' ') || null],
        ['Model', [a.manufacturer, a.model].filter(Boolean).join(' ') || null],
        ['Fingerprint', a.fingerprint || null, { mono: true }],
        ['Kernel', (info.kernel || {}).release || null],
        ['Architecture', info.arch || null],
        ['Daemon pid', (info.root || {}).pid],
        ['Dashboard URLs', (st.dashboardUrls || []).join(' , ') || null],
      ]));
      det.style.marginTop = '12px';
      wrap.appendChild(det);

      const ep = card('API endpoints', 'dns');
      ep.style.marginTop = '12px';
      ep.appendChild(Y.el('div', { class: 'mono field-help', style: 'line-height:1.8' }, (info.endpoints || []).join('\n').split('\n').map(x => Y.el('div', {}, x))));
      wrap.appendChild(ep);

      const legal = card('Licenses & notices', 'warning');
      legal.style.marginTop = '12px';
      Y.append(legal, [
        Y.el('p', {}, 'This dashboard ships inside the Yoru daemon binary. It loads nothing from the internet: no CDN, no web fonts, no analytics. All charts are drawn with a small local canvas renderer.'),
        Y.el('p', {}, 'Icons are original inline SVG artwork distributed with the module.'),
        Y.el('p', {}, 'Wi-Fi repeating depends on your chipset, driver and regulatory domain. Yoru detects what is possible and explains - honestly - what is not. Repeater operation may violate your carrier terms or local regulations depending on jurisdiction; you are responsible for lawful use.'),
      ]);
      wrap.appendChild(legal);
    } catch (e) {
      if (!needsLoginErr(e)) wrap.appendChild(banner('error', 'error', e.message));
    }
  }
  render();
  return () => { };
};
