'use strict';
/* Yoru Repeater - lightweight canvas charts. No libraries: a phone tethering
   for a week should not pay for a megabyte of chart framework. Supports
   multi-series line/area with honest gaps (null breaks the line). */

Y.Chart = class {
  constructor(canvas, opts) {
    opts = opts || {};
    this.cv = canvas;
    this.ctx = canvas.getContext('2d');
    this.opts = Object.assign({
      height: 150,
      area: true,
      smooth: true,
      yFrom0: true,
      maxPoints: 240,
      unit: '',
      fmt: null,
      grid: true,
      labels: true,
      windowSec: 0,
    }, opts);
    this.series = [];
    this.resize();
    // A chart whose canvas left the DOM (navigation) detaches itself, so
    // repeatedly opening pages never accumulates resize listeners.
    this._ro = () => {
      if (!this.cv.isConnected) { window.removeEventListener('resize', this._ro); return; }
      this.resize();
    };
    window.addEventListener('resize', this._ro);
  }

  destroy() { window.removeEventListener('resize', this._ro); }

  addSeries(key, label, color, opts) {
    opts = opts || {};
    this.series.push({ key, label, color, data: [], dashed: !!opts.dashed, hidden: false, scale: opts.scale || 1 });
    return this.series[this.series.length - 1];
  }

  seriesByKey(k) { return this.series.find(s => s.key === k); }

  /* push one sample: {t, v:{key:val,...}} */
  push(sample) {
    const max = this.opts.maxPoints;
    for (const s of this.series) {
      const raw = sample.v == null ? null : sample.v[s.key];
      s.data.push(raw == null || !isFinite(raw) ? null : raw * s.scale);
      if (s.data.length > max) s.data.splice(0, s.data.length - max);
    }
    this.t0 = sample.t;
    this.tn = sample.t;
  }

  setSamples(samples) {
    for (const s of this.series) s.data = [];
    if (!samples || !samples.length) { this.draw(); return; }
    for (const sm of samples) {
      for (const s of this.series) {
        const raw = sm.v == null ? null : sm.v[s.key];
        s.data.push(raw == null || !isFinite(raw) ? null : raw * s.scale);
      }
    }
    this.t0 = samples[0].t;
    this.tn = samples[samples.length - 1].t;
    this.draw();
  }

  resize() {
    const dpr = Math.min(2.5, window.devicePixelRatio || 1);
    const w = this.cv.clientWidth || this.cv.parentElement.clientWidth || 300;
    const h = this.opts.height;
    this.cv.width = Math.max(1, Math.round(w * dpr));
    this.cv.height = Math.round(h * dpr);
    this.cv.style.height = h + 'px';
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    this.w = w; this.h = h;
    this.draw();
  }

  visible() { return this.series.filter(s => !s.hidden); }

  draw() {
    const { ctx, w, h } = this;
    if (!w || !h) return;
    const css = getComputedStyle(document.documentElement);
    const gridC = css.getPropertyValue('--md-chart-grid').trim() || 'rgba(128,128,128,.2)';
    const textC = css.getPropertyValue('--md-on-surface-variant').trim() || '#888';
    ctx.clearRect(0, 0, w, h);
    const padL = this.opts.labels ? 46 : 6, padR = 8, padT = 8, padB = this.opts.labels ? 18 : 6;
    const iw = w - padL - padR, ih = h - padT - padB;
    const vis = this.visible();
    let n = 0;
    for (const s of vis) n = Math.max(n, s.data.length);
    if (!n) {
      ctx.fillStyle = textC;
      ctx.font = '12px system-ui';
      ctx.textAlign = 'center';
      ctx.fillText('collecting data…', w / 2, h / 2);
      return;
    }
    let lo = Infinity, hi = -Infinity;
    for (const s of vis) {
      for (const v of s.data) {
        if (v == null) continue;
        if (v < lo) lo = v;
        if (v > hi) hi = v;
      }
    }
    if (lo === Infinity) { lo = 0; hi = 1; }
    if (this.opts.yFrom0) lo = Math.min(0, lo);
    if (hi === lo) hi = lo + 1;
    const span = hi - lo;
    hi += span * 0.08;
    if (this.opts.yFrom0) lo = Math.max(0, lo);
    const fmt = this.opts.fmt || (v => this.opts.unit === 'bytes' ? Y.fmtRate(v) : this.opts.unit === 'pct' ? Math.round(v) + '%' : Math.round(v * 10) / 10);

    /* grid + y labels */
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    ctx.font = '10.5px system-ui';
    const rows = 4;
    for (let i = 0; i <= rows; i++) {
      const y = padT + ih - ih * i / rows;
      ctx.strokeStyle = gridC;
      ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(w - padR, y); ctx.stroke();
      if (this.opts.labels) {
        ctx.fillStyle = textC;
        ctx.fillText(fmt(lo + (hi - lo) * i / rows), padL - 6, y);
      }
    }

    const xAt = (i) => padL + (n < 2 ? iw / 2 : iw * i / (n - 1));
    const yAt = (v) => padT + ih - ih * (v - lo) / (hi - lo);

    for (const s of vis) {
      const off = n - s.data.length;
      ctx.strokeStyle = s.color;
      ctx.lineWidth = 2;
      ctx.lineJoin = 'round';
      ctx.setLineDash(s.dashed ? [5, 4] : []);
      ctx.beginPath();
      let started = false;
      const pts = [];
      for (let i = 0; i < s.data.length; i++) {
        const v = s.data[i];
        if (v == null) { started = false; continue; }
        const x = xAt(i + off), y = yAt(v);
        pts.push([x, y]);
        if (!started) { ctx.moveTo(x, y); started = true; }
        else ctx.lineTo(x, y);
      }
      ctx.stroke();
      ctx.setLineDash([]);
      if (this.opts.area && pts.length > 1) {
        const g = ctx.createLinearGradient(0, padT, 0, padT + ih);
        g.addColorStop(0, Y.rgba(s.color, .22));
        g.addColorStop(1, Y.rgba(s.color, .02));
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.moveTo(pts[0][0], padT + ih);
        for (const p of pts) ctx.lineTo(p[0], p[1]);
        ctx.lineTo(pts[pts.length - 1][0], padT + ih);
        ctx.closePath();
        ctx.fill();
      }
    }

    /* x time labels */
    if (this.opts.labels && this.t0 && this.tn > this.t0) {
      ctx.fillStyle = textC;
      ctx.textAlign = 'left';
      ctx.fillText('-' + Y.fmtDur((this.tn - this.t0) / 1000), padL, h - 8);
      ctx.textAlign = 'right';
      ctx.fillText('now', w - padR, h - 8);
    }
  }
};

/* Tiny inline sparkline used inside cards. */
Y.spark = function (canvas, values, color, opts) {
  opts = opts || {};
  const ctx = canvas.getContext('2d');
  const dpr = Math.min(2.5, window.devicePixelRatio || 1);
  const w = canvas.clientWidth || 120, h = canvas.clientHeight || 34;
  canvas.width = w * dpr; canvas.height = h * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  const vals = values.filter(v => v != null && isFinite(v));
  if (vals.length < 2) return;
  let lo = Math.min(...vals), hi = Math.max(...vals);
  if (opts.zeroBase) lo = Math.min(0, lo);
  if (hi === lo) hi = lo + 1;
  const step = w / (values.length - 1);
  ctx.strokeStyle = color;
  ctx.lineWidth = 1.8;
  ctx.lineJoin = 'round';
  ctx.beginPath();
  let started = false;
  values.forEach((v, i) => {
    if (v == null || !isFinite(v)) { started = false; return; }
    const x = i * step, y = h - 2 - (h - 4) * (v - lo) / (hi - lo);
    if (!started) { ctx.moveTo(x, y); started = true; } else ctx.lineTo(x, y);
  });
  ctx.stroke();
};
