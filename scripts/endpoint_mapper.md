<img width="2560" height="1440" alt="image" src="https://github.com/user-attachments/assets/0794e668-eebe-4a02-80ca-307a887c9d68" />

```js
(() => {
  if (window.__plAuto) { console.warn('[pl-auto] already running'); return; }

  const ORIGIN = location.origin;
  const QUIET_MS = 1500;   // dump after this much silence following activity
  const MAX_WAIT = 4000;   // or force dump at this interval during activity

  const state = {
    hits: new Map(),
    samples: new Map(),
    entities: new Map(),
    started: Date.now(),
    lastActivity: 0,
    dirty: false,
    dumped: false,
    quietTimer: null,
    forceTimer: null,
  };

  const norm = (raw) => {
    try {
      const u = new URL(raw, location.href);
      if (u.origin !== ORIGIN) return null;
      return u.pathname
        .replace(/\/\d+/g, '/:id')
        .replace(/\/[0-9a-f]{8}-[0-9a-f-]{27,}/gi, '/:uuid')
        .replace(/\/[0-9a-f]{24,}/gi, '/:hash');
    } catch { return null; }
  };

  const bump = () => {
    state.lastActivity = Date.now();
    state.dirty = true;
    scheduleDump();
  };

  const record = (method, url) => {
    const p = norm(url);
    if (!p) return;
    const key = method + ' ' + p;
    state.hits.set(key, (state.hits.get(key) || 0) + 1);
    bump();
  };

  const noteEntity = (path, json) => {
    if (!path) return;
    let keys;
    if (Array.isArray(json)) keys = ['[array]'];
    else if (json && typeof json === 'object') keys = Object.keys(json);
    else return;
    if (!state.entities.has(path)) state.entities.set(path, new Set());
    keys.forEach(k => state.entities.get(path).add(k));
    bump();
  };

  // ---------- interceptors ----------
  const _fetch = window.fetch;
  window.fetch = async function (input, init) {
    const url  = typeof input === 'string' ? input : (input && input.url);
    const meth = (init && init.method || (typeof input !== 'string' && input && input.method) || 'GET').toUpperCase();
    record(meth, url);
    const res = await _fetch.apply(this, arguments);
    const p = norm(url);
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('json') && p) {
      state.samples.set(meth + ' ' + p, { url, status: res.status });
      res.clone().json().then(j => noteEntity(p, j)).catch(() => {});
    }
    return res;
  };

  const _open = XMLHttpRequest.prototype.open;
  const _send = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (m, u) {
    this.__plMethod = (m || 'GET').toUpperCase();
    this.__plUrl = u;
    record(this.__plMethod, u);
    return _open.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function () {
    this.addEventListener('load', () => {
      try {
        const ct = this.getResponseHeader('content-type') || '';
        if (!ct.includes('json')) return;
        const p = norm(this.__plUrl);
        state.samples.set(this.__plMethod + ' ' + p, { url: this.__plUrl, status: this.status });
        noteEntity(p, JSON.parse(this.responseText));
      } catch {}
    });
    return _send.apply(this, arguments);
  };

  if (navigator.sendBeacon) {
    const _sb = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (u, d) { record('BEACON', u); return _sb(u, d); };
  }

  // ---------- bundle harvest ----------
  const harvestBundles = async () => {
    const scripts = [...document.querySelectorAll('script[src]')]
      .map(s => s.src).filter(s => s.startsWith(ORIGIN));
    const pat = /["'`](\/(?:api|v\d+|graphql|rest|internal|auth|users?|labs?|challenges?|admin|config|me|sessions?|tokens?)[^"'`\s]{0,120})["'`]/g;
    const found = new Map();
    for (const src of scripts) {
      try {
        const text = await (await _fetch(src)).text();
        let m;
        while ((m = pat.exec(text))) {
          const p = m[1].replace(/\/\d+/g, '/:id').replace(/\$\{[^}]+\}/g, ':param');
          found.set(p, (found.get(p) || 0) + 1);
        }
      } catch {}
    }
    return [...found.entries()].sort((a, b) => b[1] - a[1]).map(([path, occurrences]) => ({ path, occurrences }));
  };

  // ---------- dump ----------
  const dump = (reason) => {
    clearTimeout(state.quietTimer);
    clearTimeout(state.forceTimer);
    if (!state.dirty && state.dumped) return;

    const api = [...state.hits.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([key, n]) => {
        const [method, path] = key.split(' ');
        const s = state.samples.get(key) || {};
        return { method, path, hits: n, status: s.status ?? '', url: s.url ?? '' };
      });

    const entities = [...state.entities.entries()]
      .map(([path, set]) => ({ path, keys: [...set].join(', ') }))
      .sort((a, b) => a.path.localeCompare(b.path));

    console.group(`%c[pl-auto] dump @ ${new Date().toLocaleTimeString()} — ${reason}`,
                  'color:#0a0;font-weight:bold');
    console.log(`%cENDPOINTS (${api.length})`, 'color:#08f;font-weight:bold');
    console.table(api);
    console.log(`%cENTITIES / inferred tables (${entities.length})`, 'color:#08f;font-weight:bold');
    console.table(entities);
    console.groupEnd();

    state.dumped = true;
    state.dirty = false;
    return { api, entities };
  };

  const scheduleDump = () => {
    clearTimeout(state.quietTimer);
    clearTimeout(state.forceTimer);
    state.quietTimer = setTimeout(() => dump('idle'), QUIET_MS);
    if (!state.dumped) {
      state.forceTimer = setTimeout(() => dump('initial-window'), MAX_WAIT);
    }
  };

  // ---------- first pass: harvest immediately ----------
  (async () => {
    const bundles = await harvestBundles();
    if (bundles.length) {
      console.group(`%c[pl-auto] bundle routes (${bundles.length})`, 'color:#08f;font-weight:bold');
      console.table(bundles);
      console.groupEnd();
    }
    // ensure a dump even if the app makes zero XHRs
    setTimeout(() => { if (!state.dumped) dump('startup'); }, MAX_WAIT);
  })();

  // ---------- lifecycle hooks ----------
  window.addEventListener('pagehide', () => dump('pagehide'));
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') dump('hidden'); });

  // ---------- manual override ----------
  window.__plAuto = {
    state,
    dump,
    harvestBundles,
    reset: () => {
      state.hits.clear(); state.samples.clear(); state.entities.clear();
      state.dirty = false; state.dumped = false; state.started = Date.now();
    },
  };

  console.info('%c[pl-auto] installed — auto-dumping after %dms idle (max %dms), plus on hide/leave',
               'color:#0a0;font-weight:bold', QUIET_MS, MAX_WAIT);
})();

```
