'use strict';
/* Yoru Repeater - API client, SSE transport and the live data store.
   The dashboard never fakes anything: a value is either real data from the
   daemon or an explicit "unavailable" note. */

Y.api = {
  base: '/api/v1',

  async call(method, path, body) {
    const opt = { method, headers: {}, credentials: 'same-origin' };
    if (body !== undefined) {
      opt.headers['Content-Type'] = 'application/json';
      opt.body = JSON.stringify(body);
    }
    let res;
    try {
      res = await fetch(this.base + path, opt);
    } catch (e) {
      const err = new Error('Connection lost');
      err.offline = true;
      throw err;
    }
    this.lastOkAt = Date.now();
    let data = null;
    try { data = await res.json(); } catch (e) { /* non-JSON (text download) */ }
    if (res.status === 401) {
      Y.bus.emit('unauthorized');
      const err = new Error(data && data.error ? data.error.message : 'Sign in required');
      err.code = data && data.error ? data.error.code : 'unauthenticated';
      err.status = 401;
      throw err;
    }
    if (!res.ok) {
      const e2 = data && data.error;
      const err = new Error(e2 ? (e2.message + (e2.hint ? ' - ' + e2.hint : '')) : 'HTTP ' + res.status);
      err.code = e2 ? e2.code : 'http';
      err.status = res.status;
      err.field = e2 ? e2.path : undefined;
      throw err;
    }
    return data ? data.data : null;
  },

  get(path) { return this.call('GET', path); },
  post(path, body) { return this.call('POST', path, body === undefined ? {} : body); },
};

Y.bus = {
  map: {},
  on(k, fn) { (this.map[k] = this.map[k] || []).push(fn); return () => this.off(k, fn); },
  off(k, fn) { this.map[k] = (this.map[k] || []).filter(f => f !== fn); },
  emit(k, v) { for (const f of (this.map[k] || []).slice()) { try { f(v); } catch (e) { console.error(e); } } },
};

/* Live store: latest frame per topic + bounded history for the sparklines. */
Y.live = {
  ringMax: 300,
  data: {},
  hist: {},
  put(topic, frame) {
    this.data[topic] = { at: Date.now(), frame };
    Y.bus.emit('live:' + topic, frame);
    Y.bus.emit('live', topic);
  },
  get(topic) { return this.data[topic] ? this.data[topic].frame : null; },
  age(topic) { return this.data[topic] ? Date.now() - this.data[topic].at : Infinity; },
  pushHist(topic, point) {
    const h = this.hist[topic] = this.hist[topic] || [];
    h.push(point);
    if (h.length > this.ringMax) h.splice(0, h.length - this.ringMax);
    return h;
  },
  histOf(topic) { return this.hist[topic] || []; },
};

/* SSE manager with reconnect visibility and a "connection lost" state. */
Y.stream = {
  es: null,
  retries: 0,
  open() {
    if (this.es) return;
    const es = new EventSource(Y.api.base + '/stream');
    this.es = es;
    es.addEventListener('hello', () => {
      this.retries = 0;
      Y.bus.emit('stream', 'online');
    });
    const relay = (name) => (e) => {
      let obj;
      try { obj = JSON.parse(e.data); } catch (err) { return; }
      this.route(name, obj);
    };
    for (const n of ['traffic', 'cpu', 'memory', 'battery', 'thermal', 'status']) {
      es.addEventListener(n, relay(n));
    }
    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) {
        this.es = null;
        Y.bus.emit('stream', 'offline');
        setTimeout(() => this.open(), 3000);
      } else {
        this.retries++;
        Y.bus.emit('stream', 'reconnecting');
      }
    };
  },
  close() {
    if (this.es) { this.es.close(); this.es = null; }
  },
  route(topic, frame) {
    if (topic === 'traffic' && frame.rates) {
      const agg = frame.rates.__agg || frame.rates[Object.keys(frame.rates)[0]];
      if (agg) {
        Y.live.pushHist('trafficRate', { t: Date.now(), v: { rx: agg.rxBytesPerSec || 0, tx: agg.txBytesPerSec || 0 } });
        Y.live.rxTotal = agg.rxBytesTotal; Y.live.txTotal = agg.txBytesTotal;
      }
    }
    if (topic === 'cpu' && frame) {
      Y.live.pushHist('cpuNow', { t: Date.now(), v: { total: frame.total || 0 } });
      if (Array.isArray(frame.perCore)) {
        const v = { total: frame.total || 0 };
        frame.perCore.forEach((p, i) => { v['c' + i] = p; });
        Y.live.pushHist('cpuAll', { t: Date.now(), v });
      }
    }
    if (topic === 'memory' && frame.mem) {
      Y.live.pushHist('memNow', { t: Date.now(), v: { usedPct: frame.mem.usedPct || 0 } });
    }
    if (topic === 'battery' && frame.battery) {
      Y.live.pushHist('battNow', { t: Date.now(), v: { capacity: frame.battery.capacity || 0, powerMw: frame.battery.powerMw || 0 } });
    }
    Y.live.put(topic, frame);
  },
};

/* Polling scheduler: every page declares the endpoints it needs and they are
   fetched on a shared cadence; SSE covers the 1s stuff. */
Y.poller = {
  timers: {},
  need(set) {
    for (const [name, fn] of Object.entries(set)) {
      if (this.timers[name]) continue;
      fn();
      this.timers[name] = setInterval(() => {
        if (document.hidden) return;
        fn().catch(() => { /* handled by bus events */ });
      }, 10000 + Object.keys(this.timers).length * 900);
    }
  },
  idle() {
    for (const t of Object.values(this.timers)) clearInterval(t);
    this.timers = {};
  },
};

/* Cache of expensive shared reads. */
Y.cache = { status: null, capabilities: null, config: null, info: null };

Y.pollStatus = async function () {
  const s = await Y.api.get('/status');
  Y.cache.status = s;
  Y.bus.emit('status', s);
  return s;
};
Y.pollCapabilities = async function (force) {
  if (Y.cache.capabilities && !force) return Y.cache.capabilities;
  const c = await Y.api.get('/capabilities');
  Y.cache.capabilities = c;
  Y.bus.emit('capabilities', c);
  return c;
};
Y.pollConfig = async function (force) {
  if (Y.cache.config && !force) return Y.cache.config;
  const c = await Y.api.get('/config');
  Y.cache.config = c;
  Y.bus.emit('config', c);
  return c;
};
Y.pollInfo = async function (force) {
  if (Y.cache.info && !force) return Y.cache.info;
  const i = await Y.api.get('/info');
  Y.cache.info = i;
  return i;
};
