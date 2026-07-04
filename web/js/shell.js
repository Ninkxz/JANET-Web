/* ============================================================================
   J.A.N.E.T. TWO  -  shell.js
   AppShell + router + view-registry + ctx + RunController.

   This is the ONLY code that fetches/polls the server. Per-tool views never
   call fetch: they go through ctx.run() -> RunController, which preserves the
   JANET ONE streaming guarantees verbatim:
     - POST the action, then ONE pollRun(key,gen) ~400ms loop
     - generation guard supersedes a stale poller when an action is re-run
     - status snapshot is taken BEFORE the events snapshot (server-side), so a
       terminal status never arrives without its final event
     - rows upsert keyed by  _rk || host || id  (multi-row-per-host safe)
     - graceful cancel + navigator.sendBeacon on unload
     - runs survive tab/tool switches (run-state lives here, not in the view)
   Vanilla JS, no build step.
   ========================================================================== */
(function () {
  'use strict';

  var Janet = window.Janet = window.Janet || {};
  Janet.components = Janet.components || {};
  var BOOT_NONCE = Date.now();   // per-session cache-bust for lazy-loaded view scripts

  /* --- session token (minted by JanetTwo.Internal.ps1, passed as ?t=) ------- */
  var _qsTok = new URLSearchParams(location.search).get('t');
  var TOKEN = '';
  if (_qsTok) {
    TOKEN = _qsTok;
    try { sessionStorage.setItem('janet2_token', TOKEN); } catch (e) {}
    try { history.replaceState(null, '', location.pathname); } catch (e) {}
  } else {
    try { TOKEN = sessionStorage.getItem('janet2_token') || ''; } catch (e) { TOKEN = ''; }
  }

  /* ========================================================================
     util
     ===================================================================== */
  function el(tag, cls, txt) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (txt != null) e.textContent = txt;
    return e;
  }
  function qs(sel, root) { return (root || document).querySelector(sel); }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
  function pad2(n) { return String(n).padStart(2, '0'); }
  function fileStamp() {
    var d = new Date();
    return '' + d.getFullYear() + pad2(d.getMonth() + 1) + pad2(d.getDate()) + '-' + pad2(d.getHours()) + pad2(d.getMinutes()) + pad2(d.getSeconds());
  }
  function clockStr() {
    var d = new Date();
    return pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
  }
  // Parse a free-text host list: split on comma/space/newline, trim, case-insensitive dedup.
  function parseHosts(text) {
    var seen = {}, out = [];
    String(text || '').split(/[\s,]+/).forEach(function (h) {
      h = h.trim(); if (!h) return;
      var k = h.toLowerCase();
      if (!seen[k]) { seen[k] = 1; out.push(h); }
    });
    return out;
  }
  // A decoupled, DOM-free target list model (TargetManager binds to one of these).
  function targetModel(initial) {
    var raw = initial || '', listeners = [];
    return {
      get raw() { return raw; },
      set: function (text) { raw = String(text == null ? '' : text); listeners.forEach(function (f) { try { f(); } catch (e) {} }); },
      hosts: function () { return parseHosts(raw); },
      count: function () { return parseHosts(raw).length; },
      onChange: function (fn) { listeners.push(fn); return function () { var i = listeners.indexOf(fn); if (i >= 0) listeners.splice(i, 1); }; }
    };
  }
  function downloadBlob(name, mime, content) {
    var url = URL.createObjectURL(new Blob([content], { type: mime }));
    var a = el('a'); a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
  }
  // RFC-4180 CSV parse -> { headers, rows[][] }: quoted fields, "" escapes,
  // embedded commas/newlines. Comma-delimited (the universal export format).
  function parseCsv(text) {
    var rows = [], cur = [], field = '', i = 0, inQ = false; text = String(text == null ? '' : text);
    while (i < text.length) {
      var ch = text[i];
      if (inQ) { if (ch === '"') { if (text[i + 1] === '"') { field += '"'; i += 2; continue; } inQ = false; i++; continue; } field += ch; i++; continue; }
      if (ch === '"') { inQ = true; i++; continue; }
      if (ch === ',') { cur.push(field); field = ''; i++; continue; }
      if (ch === '\r') { i++; continue; }
      if (ch === '\n') { cur.push(field); rows.push(cur); cur = []; field = ''; i++; continue; }
      field += ch; i++;
    }
    if (field !== '' || cur.length) { cur.push(field); rows.push(cur); }
    while (rows.length && rows[rows.length - 1].length === 1 && rows[rows.length - 1][0] === '') rows.pop();
    return { headers: rows.length ? rows.shift() : [], rows: rows };
  }
  // Serialize to CSV text (CRLF rows, trailing CRLF). rows = array of value-arrays,
  // OR array of objects (keys defaults to headers; pass keys to pull other columns).
  function toCsv(headers, rows, keys) {
    function q(v) { v = v == null ? '' : String(v); return /[",\r\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }
    keys = keys || headers || [];
    var body = (rows || []).map(function (r) {
      return (Array.isArray(r) ? r : keys.map(function (k) { return r[k]; })).map(q).join(',');
    });
    return [(headers || []).map(q).join(',')].concat(body).join('\r\n') + '\r\n';
  }
  // MERGE (do not replace): component files (e.g. xlsx.js) may have already
  // attached helpers to Janet.util before shell.js loaded.
  Janet.util = Object.assign(Janet.util || {}, {
    el: el, qs: qs, sleep: sleep, esc: esc, fileStamp: fileStamp,
    clockStr: clockStr, parseHosts: parseHosts, targetModel: targetModel, downloadBlob: downloadBlob,
    parseCsv: parseCsv, toCsv: toCsv
  });
  /* ========================================================================
     api  (the ONLY fetch in the app, besides RunController which calls it)
     ===================================================================== */
  async function api(method, path, body) {
    var opt = { method: method, headers: { 'X-Janet-Token': TOKEN } };
    if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    var r;
    try { r = await fetch('/api' + path, opt); }
    catch (netErr) { var e = new Error('network error'); e.status = 0; throw e; }
    if (!r.ok) { var e2 = new Error('HTTP ' + r.status + ' ' + path); e2.status = r.status; throw e2; }
    return r.json();
  }
  // Upload a file via the binary-safe /api/upload; returns the server-side temp path.
  async function uploadFile(file, subdir) {
    var headers = { 'X-Janet-Token': TOKEN, 'X-Janet-Filename': encodeURIComponent(file.name) };
    if (subdir) headers['X-Janet-Subdir'] = String(subdir);   // co-locate related files in one host folder
    var r = await fetch('/api/upload', {
      method: 'POST',
      headers: headers,
      body: file
    });
    if (!r.ok) throw new Error('upload failed: HTTP ' + r.status);
    var j = await r.json();
    if (!j.ok) throw new Error(j.error || 'upload failed');
    return j.path;
  }
  function pollLossMsg(e) {
    var s = e && e.status;
    if (s === 401 || s === 403) return 'server was restarted - reload the page to reconnect';
    if (s === 404) return 'run is no longer on the server (it finished, was evicted, or the server restarted)';
    return 'server not responding - check the JANET TWO console window';
  }

  /* ========================================================================
     RunController  -  the keep-verbatim JANET ONE streaming client, wrapped
     ===================================================================== */
  var RunController = (function () {
    var runs = {};   // key -> run-state (persists across view mounts -> keep-alive)
    var gen = {};    // key -> generation (supersede a stale poller on re-run)
    var subs = {};   // key -> [handlerObj]

    function defaultKeyOf(ev) {
      if (ev._rk != null) return String(ev._rk);
      var hostCols = ['Host', 'host', 'Hostname', 'HostName', 'Computer', 'ComputerName', 'Server', 'Name'];
      for (var i = 0; i < hostCols.length; i++) { if (ev[hostCols[i]] != null && ev[hostCols[i]] !== '') return String(ev[hostCols[i]]); }
      if (ev.id != null) return '_row' + String(ev.id);
      return null;   // caller assigns a sequence key
    }
    function freshRun(key, toolId, actionId, opts) {
      var rs = runs[key] || (runs[key] = {});
      rs.key = key; rs.toolId = toolId; rs.actionId = actionId;
      rs.rows = {}; rs.order = []; rs.log = [];
      rs.status = 'starting...'; rs.progress = 0; rs.done = 0; rs.total = 0;
      rs.jobId = null; rs.since = 0; rs.active = true; rs.terminal = false; rs._rowSeq = 0;
      rs.summary = null; rs.result = null; rs.error = null;
      rs.destructive = !!(opts && opts.destructive);
      rs.keyOf = (opts && opts.keyOf) || defaultKeyOf;
      return rs;
    }
    function listFor(key) { return subs[key] || (subs[key] = []); }
    function dispatch(key, type, payload) {
      (subs[key] || []).forEach(function (h) { if (typeof h[type] === 'function') { try { h[type](payload); } catch (e) {} } });
    }
    function upsert(rs, ev) {
      var k = rs.keyOf(ev);
      if (k == null) k = '_row' + (rs._rowSeq++);
      if (!Object.prototype.hasOwnProperty.call(rs.rows, k)) { rs.rows[k] = {}; rs.order.push(k); }
      Object.assign(rs.rows[k], ev);
      return rs.rows[k];
    }
    function reduce(key, ev) {
      var rs = runs[key]; if (!rs) return;
      if (!ev || typeof ev !== 'object') return;   // a malformed event must never wedge the poller
      switch (ev.type) {
        case 'status': rs.status = ev.text; dispatch(key, 'status', rs.status); break;
        case 'progress':
          rs.done = ev.done || 0; rs.total = ev.total || 0;
          rs.progress = ev.total ? Math.round(100 * ev.done / ev.total) : 0;
          dispatch(key, 'progress', { done: rs.done, total: rs.total, pct: rs.progress }); break;
        case 'row': { var row = upsert(rs, ev); dispatch(key, 'row', row); } break;
        case 'log': { var l = { text: ev.text, level: ev.level }; rs.log.push(l); dispatch(key, 'log', l); } break;
        case 'error': rs.error = ev.text; rs.log.push({ text: ev.text, level: 'err' }); rs.status = 'error'; dispatch(key, 'error', { text: ev.text }); dispatch(key, 'log', { text: ev.text, level: 'err' }); dispatch(key, 'status', rs.status); break;
        case 'final': rs.result = ev.result; rs.summary = (ev.result && ev.result.summary) || null; dispatch(key, 'final', ev.result); break;
      }
    }
    async function poll(key, g) {
      var rs = runs[key]; if (!rs) return;
      var fails = 0;
      while (rs.active && gen[key] === g) {
        var data;
        try { data = await api('GET', '/job/' + rs.jobId + '/events?since=' + rs.since); fails = 0; }
        catch (e) { if (++fails >= 6) { rs.status = pollLossMsg(e); dispatch(key, 'status', rs.status); break; } await sleep(800); continue; }
        if (gen[key] !== g) return;   // a re-run superseded us mid-await
        if (typeof data.nextSince === 'number') rs.since = data.nextSince;
        (data.events || []).forEach(function (ev) { reduce(key, ev); });
        if (data.status === 'running' || data.status === 'cancelling') {
          if (data.status === 'cancelling') { rs.status = 'cancelling... (draining in-flight hosts)'; dispatch(key, 'status', rs.status); }
          await sleep(400);
        } else {
          if (data.status === 'cancelled') { rs.status = 'cancelled'; dispatch(key, 'status', rs.status); }
          rs.progress = 100; dispatch(key, 'progress', { done: rs.done, total: rs.total, pct: 100 });
          break;
        }
      }
      rs.active = false; rs.terminal = true;
      dispatch(key, 'active', false);
    }
    function replay(rs, h) {
      if (!rs) return;
      if (h.reset) h.reset(rs);
      if (h.status) h.status(rs.status);
      if (h.progress) h.progress({ done: rs.done, total: rs.total, pct: rs.progress });
      if (h.row) rs.order.forEach(function (k) { h.row(rs.rows[k]); });
      if (h.log) rs.log.forEach(function (l) { h.log(l); });
      if (rs.terminal) {
        if (rs.error && h.error) h.error({ text: rs.error });
        if (rs.result != null && h.final) h.final(rs.result);
      }
      if (h.active) h.active(!!rs.active);
    }
    function makeHandle(key) {
      return {
        key: key,
        get state() { return runs[key]; },
        subscribe: function (handlers) {
          var list = listFor(key); list.push(handlers);
          replay(runs[key], handlers);   // late binder still paints the run so far
          return function () { var i = list.indexOf(handlers); if (i >= 0) list.splice(i, 1); };
        },
        cancel: function () { var rs = runs[key]; if (rs && rs.jobId) api('POST', '/job/' + rs.jobId + '/cancel').catch(function () {}); }
      };
    }
    function start(toolId, actionId, params, opts) {
      opts = opts || {};
      // opts.key lets a caller run a side-fetch (e.g. a Host Info peek) under its
      // own client-side state bucket so it never supersedes the tool's main run.
      // The POST below still routes by toolId/actionId, so the server is unaffected.
      var key = opts.key || (toolId + '/' + actionId);
      var rs = freshRun(key, toolId, actionId, opts);
      var g = gen[key] = (gen[key] || 0) + 1;
      dispatch(key, 'reset', rs);
      (async function () {
        try {
          var r = await api('POST', '/tool/' + toolId + '/action/' + actionId, params || {});
          rs.jobId = r.jobId;
          poll(key, g);
        } catch (e) {
          rs.active = false; rs.terminal = true;
          rs.status = (e.status === 403)
            ? 'Admin session required - Set Credentials and accept responsibility (Start Admin Session) before running actions that change machines.'
            : ('failed to start: ' + e.message);
          rs.error = rs.status;
          dispatch(key, 'status', rs.status);
          dispatch(key, 'error', { text: rs.status });
          dispatch(key, 'active', false);
        }
      })();
      return makeHandle(key);
    }
    function beaconCancel(jobId) {
      if (!jobId) return;
      var url = '/api/job/' + encodeURIComponent(jobId) + '/cancel' + (TOKEN ? ('?t=' + encodeURIComponent(TOKEN)) : '');
      try { if (navigator.sendBeacon && navigator.sendBeacon(url)) return; } catch (e) {}
      try { api('POST', '/job/' + jobId + '/cancel').catch(function () {}); } catch (e) {}
    }
    // On unload, beacon-cancel every active DESTRUCTIVE run (mirrors JANET ONE).
    window.addEventListener('pagehide', function () {
      Object.keys(runs).forEach(function (k) { var rs = runs[k]; if (rs.active && rs.destructive && rs.jobId) beaconCancel(rs.jobId); });
    });
    // Guard a stray refresh/close while ANY run is in flight: a destructive run is
    // cancelled on unload (above), so confirm before losing it. Browsers show their
    // own generic text; returnValue just has to be set.
    window.addEventListener('beforeunload', function (e) {
      if (Object.keys(runs).some(function (k) { return runs[k] && runs[k].active; })) { e.preventDefault(); e.returnValue = ''; }
    });
    return {
      start: start,
      dispose: function (key) { delete runs[key]; delete gen[key]; delete subs[key]; },
      cancelDestructive: function (toolId) {
        var hit = [];
        Object.keys(runs).forEach(function (k) {
          var rs = runs[k];
          if (!rs.active || !rs.destructive || !rs.jobId) return;
          if (toolId && rs.toolId !== toolId) return;
          api('POST', '/job/' + rs.jobId + '/cancel').catch(function () {});
          rs.status = 'cancelling...'; dispatch(k, 'status', rs.status);
          hit.push(rs.actionId);
        });
        return hit;
      }
    };
  })();

  /* ========================================================================
     Universal Host Info  ->  Janet.hostInfo / Janet.hostInfoPanel
     A read-only snapshot of one workstation, reusing WPT's host-info action
     (the only engine that owns it) cross-tool via RunController -- exactly how
     the hub calls wpt/bulk-scan. Surfaced two ways: the shared grid's
     double-click drill-down (resultsgrid.js) and the TargetManager Get Info
     button. Each peek gets its OWN run key so it never clobbers the WPT Host
     Info tab or another peek.
     ===================================================================== */
  var _peekSeq = 0;
  function runHostInfo(host, handlers) {
    host = String(host || '').trim();
    handlers = handlers || {};
    if (!host) { if (handlers.error) handlers.error({ text: 'No host.' }); if (handlers.done) handlers.done(); return null; }
    var h = RunController.start('wpt', 'host-info', { host: host }, {
      key: 'wpt/host-info#peek:' + (++_peekSeq) + ':' + host.toUpperCase(),
      keyOf: function (r) { return r._rk || (r.Host + '|' + r.Property); }
    });
    var unsub = h.subscribe({
      status: function (t) { if (handlers.status) handlers.status(t); },
      row: function (r) { if (handlers.row) handlers.row(r); },
      log: function (l) { if (handlers.log) handlers.log(l); },
      error: function (e) { if (handlers.error) handlers.error(e); },
      final: function (res) { if (handlers.final) handlers.final(res); },
      active: function (a) { if (!a) { if (handlers.done) handlers.done(); if (unsub) unsub(); RunController.dispose(h.key); } }
    });
    return h;
  }

  // Get Info button target: a modal with a host picker (when >1) + Property/Value grid.
  function hostInfoPanel(hosts) {
    hosts = (hosts || []).map(function (h) { return String(h || '').trim(); }).filter(Boolean);
    if (!hosts.length) {
      Janet.components.ConfirmDialog({ title: 'Get Info', body: 'Add at least one target host first.', okText: 'OK', cancelText: null });
      return;
    }
    var body = el('div'); body.style.cssText = 'display:flex;flex-direction:column;gap:8px;min-width:380px';
    var row1 = el('div'); row1.style.cssText = 'display:flex;gap:8px;align-items:center;flex-wrap:wrap';
    row1.appendChild(el('span', 'j-kv-k', 'Host'));
    var sel = null;
    if (hosts.length > 1) {
      sel = el('select', 'j-select');
      hosts.forEach(function (hn) { sel.appendChild(new Option(hn, hn)); });
      row1.appendChild(sel);
    } else {
      row1.appendChild(el('span', 'j-kv-v', hosts[0]));
    }
    body.appendChild(row1);
    var status = el('div', 'muted'); status.style.fontSize = '11.5px'; body.appendChild(status);
    var grid = Janet.components.ResultsGrid({ title: 'Host info', keyMode: { rk: true }, popOut: false, columns: [{ key: 'Property', label: 'PROPERTY', width: 190 }, { key: 'Value', label: 'VALUE' }] });
    var gh = el('div'); gh.style.cssText = 'height:340px;display:flex'; gh.appendChild(grid.el); body.appendChild(gh);
    function load(hn) {
      grid.clear(); status.textContent = 'Querying ' + hn + '...';
      runHostInfo(hn, {
        status: function (t) { if (!grid.rows().length) status.textContent = t; },
        row: function (r) { grid.upsert(r); },
        error: function (e) { status.textContent = (e && e.text) || 'host info failed'; },
        done: function () { status.textContent = grid.rows().length ? (hn + ' - ' + grid.rows().length + ' field(s)') : 'No host info (set credentials and start an admin session?).'; }
      });
    }
    if (sel) sel.onchange = function () { load(sel.value); };
    Janet.components.ConfirmDialog({ title: 'Host Info', body: body, okText: 'Close', cancelText: null });
    load(hosts[0]);
  }

  Janet.hostInfo = runHostInfo;
  Janet.hostInfoPanel = hostInfoPanel;

  /* ========================================================================
     view registry + lazy loader
     ===================================================================== */
  var views = {};
  window.JanetViews = {
    register: function (id, def) { views[id] = def; }
  };
  function loadView(id) {
    return new Promise(function (resolve, reject) {
      if (views[id]) return resolve(views[id]);
      var s = document.createElement('script');
      // cache-bust per page-load: view files live on a shared drive and get updated,
      // and the static server sends no cache validators - without this the browser can
      // serve a stale view after an update. (One nonce per session; views load once each.)
      s.src = '/js/views/' + id + '.view.js?v=' + BOOT_NONCE;
      s.onload = function () { views[id] ? resolve(views[id]) : reject(new Error('view "' + id + '" loaded but did not register')); };
      s.onerror = function () { reject(new Error('could not load view script for "' + id + '"')); };
      document.head.appendChild(s);
    });
  }

  /* ========================================================================
     Session state (cred + responsibility ack), authoritative-server-mirrored
     ===================================================================== */
  var Session = {
    ack: false, credSet: false, active: false, adOnly: false,
    user: '', mode: 'current Kerberos (CAC)', logRoot: '', onShare: false, localOnly: false,
    _listeners: []
  };
  try { Session.ack = (sessionStorage.getItem('janet2_ack') === 'yes'); } catch (e) {}
  try { Session.active = (sessionStorage.getItem('janet2_session') === '1'); } catch (e) {}
  function sessionChanged() { Session._listeners.forEach(function (f) { try { f(Session); } catch (e) {} }); updateStrip(); }
  var SessionApi = {
    get state() { return Session; },
    onChange: function (fn) { Session._listeners.push(fn); return function () { var i = Session._listeners.indexOf(fn); if (i >= 0) Session._listeners.splice(i, 1); }; },
    refreshCred: refreshCred, setCred: setCred, clearCred: clearCred, startSession: startSession
  };
  async function refreshCred() {
    try {
      var st = await api('GET', '/cred');
      Session.credSet = !!st.set; Session.user = st.user || ''; Session.mode = st.mode || Session.mode;
      sessionChanged();
    } catch (e) {}
    return Session;
  }
  async function setCred() {
    var r = await api('POST', '/cred');
    if (r && r.status) { Session.credSet = !!r.status.set; Session.user = r.status.user || ''; Session.mode = r.status.mode || Session.mode; }
    sessionChanged();
    return r;
  }
  async function clearCred() {
    var r = await api('DELETE', '/cred');
    if (r && r.status) { Session.credSet = !!r.status.set; Session.user = r.status.user || ''; Session.mode = r.status.mode || Session.mode; }
    sessionChanged();
    return r;
  }
  async function startSession(ack) {
    var r = await api('POST', '/session/start', { ack: !!ack });
    Session.ack = !!r.ack; Session.credSet = !!r.credSet; Session.active = !!r.active;
    try { if (Session.ack) sessionStorage.setItem('janet2_ack', 'yes'); if (Session.active) sessionStorage.setItem('janet2_session', '1'); } catch (e) {}
    sessionChanged();
    return r;
  }
  async function refreshStatus() {
    try {
      var st = await api('GET', '/status');
      Session.logRoot = st.logRoot || ''; Session.onShare = !!st.onShare; Session.localOnly = !!st.localOnly;
      updateStrip();
    } catch (e) {}
  }

  /* ========================================================================
     AppShell  -  builds the whole frame in JS (index.html stays minimal)
     ===================================================================== */
  var TOOLS = [], SUITE = 'J.A.N.E.T. TWO';
  var dom = {};   // cached element refs

  function buildShell(root) {
    var app = el('div'); app.id = 'j-app';

    // --- shell row: persistent tool sidebar + main column ---
    var shell = el('div'); shell.id = 'j-shell';

    // sidebar: brand (-> home) + tool filter + grouped nav + session foot
    var side = el('nav'); side.id = 'j-sidebar'; side.setAttribute('aria-label', 'Tool navigation');
    var brand = el('button', 'j-side-brand'); brand.type = 'button'; brand.title = 'Home - all tools';
    var mark = el('div', 'j-brand-mark'); mark.innerHTML = 'J<span>2</span>'; brand.appendChild(mark);
    var btitles = el('div', 'j-side-brand-t');
    var t = el('div', 'j-brand-title'); t.innerHTML = 'J.A.N.E.T. <b>TWO</b>'; btitles.appendChild(t);
    btitles.appendChild(el('div', 'j-brand-sub', 'Admin console')); brand.appendChild(btitles);
    brand.onclick = backToHub;
    side.appendChild(brand);

    var fw = el('div', 'j-filter-wrap');
    var fico = el('span', 'j-filter-ico'); fico.textContent = iconGlyph('E721'); fw.appendChild(fico);   // search glyph
    dom.toolFilter = el('input'); dom.toolFilter.type = 'text'; dom.toolFilter.placeholder = 'Filter tools...';
    dom.toolFilter.setAttribute('aria-label', 'Filter tools'); dom.toolFilter.spellcheck = false; dom.toolFilter.autocomplete = 'off';
    dom.toolFilter.oninput = function () { renderNav(dom.toolFilter.value); };
    fw.appendChild(dom.toolFilter); side.appendChild(fw);

    dom.navList = el('div'); dom.navList.id = 'j-navlist';
    dom.navList.setAttribute('role', 'listbox'); dom.navList.setAttribute('aria-label', 'Tools');
    side.appendChild(dom.navList);

    var sfoot = el('div', 'j-side-foot');
    dom.sideWho = el('div', 'j-side-who'); sfoot.appendChild(dom.sideWho);
    dom.sideLog = el('div', 'j-side-log'); sfoot.appendChild(dom.sideLog);
    side.appendChild(sfoot);
    shell.appendChild(side);

    // main column: top bar (breadcrumb + universal cred + clock) + body (hub OR tool host)
    var main = el('div'); main.id = 'j-main';
    var top = el('div'); top.id = 'j-topbar';
    var crumb = el('div', 'j-crumb');
    dom.crumbCat = el('span', 'j-crumb-cat', 'Home');
    dom.crumbSep = el('span', 'j-crumb-sep'); dom.crumbSep.textContent = iconGlyph('E76C'); dom.crumbSep.style.display = 'none';
    dom.crumbTool = el('span', 'j-crumb-tool', '');
    crumb.appendChild(dom.crumbCat); crumb.appendChild(dom.crumbSep); crumb.appendChild(dom.crumbTool);
    top.appendChild(crumb);
    top.appendChild(el('div', 'j-top-spacer'));
    dom.credbar = el('div', 'j-credbar'); top.appendChild(dom.credbar);
    top.appendChild(makeThemeToggle());
    dom.clock = el('div'); dom.clock.id = 'j-clock'; top.appendChild(dom.clock);
    main.appendChild(top);

    var body = el('div'); body.id = 'j-mainbody';
    dom.hub = el('div'); dom.hub.id = 'j-hub'; body.appendChild(dom.hub);
    dom.tool = el('div', 'hidden'); dom.tool.id = 'j-tool';
    var th = el('div'); th.id = 'j-tool-head';
    dom.thIcon = el('span', 'j-th-icon'); th.appendChild(dom.thIcon);
    var thtext = el('div');
    dom.thName = el('div', 'j-th-name'); dom.thSum = el('div', 'j-th-sum');
    thtext.appendChild(dom.thName); thtext.appendChild(dom.thSum); th.appendChild(thtext);
    dom.tool.appendChild(th);
    // "How to use" callout - one per tool, populated by openTool from JANET2_HELP.
    dom.howto = el('div', 'j-howto'); dom.howto.style.display = 'none'; dom.tool.appendChild(dom.howto);
    dom.viewHost = el('div'); dom.viewHost.id = 'j-view-host'; dom.tool.appendChild(dom.viewHost);
    body.appendChild(dom.tool);
    main.appendChild(body);
    shell.appendChild(main);
    app.appendChild(shell);

    // --- status strip ---
    var strip = el('div'); strip.id = 'j-strip';
    dom.stripSession = el('div', 'j-strip-seg'); strip.appendChild(dom.stripSession);
    dom.stripTargets = el('div', 'j-strip-seg'); strip.appendChild(dom.stripTargets);
    var ss = el('div'); ss.id = 'j-strip-spacer'; strip.appendChild(ss);
    dom.stripLog = el('div', 'j-strip-seg'); strip.appendChild(dom.stripLog);
    dom.stripBeat = el('div', 'j-strip-seg');
    dom.beatDot = el('span', 'j-dot j-dot-ok j-dot-pulse'); dom.beatDot.style.color = 'var(--ok)';
    dom.stripBeat.appendChild(dom.beatDot); dom.stripBeat.appendChild(el('span', null, 'live'));
    strip.appendChild(dom.stripBeat);
    app.appendChild(strip);

    root.appendChild(app);
    setInterval(function () { dom.clock.textContent = clockStr(); }, 1000);
    dom.clock.textContent = clockStr();
    renderCredbar();
    SessionApi.onChange(renderCredbar);   // keep the header cred pill in sync when any strip sets/clears creds
  }

  // The SINGLE, universal credential control for the whole app (top-right of the
  // brand band). No per-tool view renders its own Set Credentials - they all share
  // this one and read the resulting Session.credSet via ctx.session.
  function renderCredbar() {
    var c = dom.credbar; c.innerHTML = '';
    var dot = el('span', 'j-dot ' + (Session.credSet ? 'j-dot-ok' : 'j-dot-warn'));
    var label = el('span', 'j-cred-status ' + (Session.credSet ? 'st-ok' : 'st-warn'),
      Session.credSet ? (Session.user + ' (ADW)') : 'Kerberos (CAC)');
    c.appendChild(dot); c.appendChild(label);
    var setb = Janet.ui.button(Session.credSet ? 'Change' : 'Set Credentials', { size: 'sm', title: 'Open the Windows smartcard picker on your desktop; held in this app memory only.' });
    setb.onclick = function () { setb.disabled = true; setCred().catch(function () {}).then(function () { setb.disabled = false; }); };
    c.appendChild(setb);
    if (Session.credSet) {
      var clr = Janet.ui.ghostButton('Clear', { size: 'sm', title: 'Forget the selected credential; fall back to your current Kerberos (CAC) login.' });
      clr.onclick = function () { clearCred().catch(function () {}); };
      c.appendChild(clr);
    }
  }

  function updateStrip() {
    if (!dom.stripSession) return;
    dom.stripSession.innerHTML = '';
    var sdot = el('span', 'j-dot ' + (Session.active ? 'j-dot-ok' : (Session.adOnly ? 'j-dot-warn' : 'j-dot-bad')));
    dom.stripSession.appendChild(sdot);
    var sval = Session.active ? ('ADMIN ' + (Session.user || '')) : (Session.adOnly ? 'READ-ONLY' : 'LOCKED');
    dom.stripSession.appendChild(html('SESSION <b>' + esc(sval) + '</b>'));
    dom.stripTargets.innerHTML = '';
    dom.stripTargets.appendChild(html('TARGETS <b>' + sharedTargets.count() + '</b>'));
    dom.stripLog.innerHTML = '';
    var logTxt = Session.logRoot ? (Session.localOnly ? 'LOG (local) ' : 'LOG ') : 'LOG ';
    var seg = html(logTxt + '<b class="j-strip-path">' + esc(Session.logRoot || '-') + '</b>');
    seg.style.cursor = 'pointer'; seg.title = 'Open the audit log viewer'; seg.onclick = openAuditViewer;
    dom.stripLog.appendChild(seg);
    // mirror session + log into the sidebar foot
    if (dom.sideWho) {
      var st = Session.active ? 'ok' : (Session.adOnly ? 'warn' : 'bad');
      var who = Session.active ? ('ADMIN - ' + (Session.user || '')) : (Session.adOnly ? 'READ-ONLY' : 'LOCKED');
      dom.sideWho.innerHTML = '';
      dom.sideWho.appendChild(el('span', 'j-dot j-dot-' + st));
      dom.sideWho.appendChild(el('span', null, who));
    }
    if (dom.sideLog) {
      dom.sideLog.textContent = Session.logRoot ? ((Session.localOnly ? 'log (local) -> ' : 'log -> ') + Session.logRoot) : 'log -> -';
    }
  }
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function html(markup) { var span = el('span'); span.innerHTML = markup; return span; }

  // Audit log viewer: two read-only views of THIS operator's logs for a chosen tool -
  //   "Audit rows"  = the structured current-month detail CSV (via /api/logs/tail), table.
  //   "Transcript"  = this session's human-readable .log narrative (via /api/logs/transcript).
  function openAuditViewer() {
    var overlay = el('div', 'j-modal j-audit-modal');
    var card = el('div', 'j-audit-card');
    var head = el('div', 'j-audit-head');
    head.appendChild(el('span', 'j-modal-title', 'Audit log'));

    // view-mode toggle: structured rows vs the .log transcript narrative
    var mode = 'rows';
    var modeWrap = el('div'); modeWrap.style.cssText = 'display:inline-flex;gap:4px';
    var rowsBtn = Janet.ui.ghostButton('Audit rows', { size: 'sm', title: 'The structured per-action audit CSV (this month).' });
    var tranBtn = Janet.ui.ghostButton('Transcript', { size: 'sm', title: 'This session’s human-readable .log narrative.' });
    function paintModes() {
      [[rowsBtn, 'rows'], [tranBtn, 'transcript']].forEach(function (p) {
        var on = mode === p[1]; p[0].style.opacity = on ? '1' : '0.55'; p[0].style.fontWeight = on ? '700' : '';
      });
    }
    modeWrap.appendChild(rowsBtn); modeWrap.appendChild(tranBtn);

    var toolSel = el('select', 'j-select');
    (TOOLS || []).forEach(function (t) { toolSel.appendChild(new Option(t.name, t.id)); });
    if (current && current.tool) toolSel.value = current.tool.id;
    var filter = el('input', 'j-audit-filter'); filter.type = 'text'; filter.placeholder = 'Filter...';
    var closeB = Janet.ui.ghostButton('Close', { size: 'sm' });
    head.appendChild(modeWrap); head.appendChild(toolSel); head.appendChild(filter); head.appendChild(closeB);
    var meta = el('div', 'j-audit-meta muted', 'Loading...');
    var bodyWrap = el('div', 'j-audit-table');
    card.appendChild(head); card.appendChild(meta); card.appendChild(bodyWrap);
    overlay.appendChild(card); document.body.appendChild(overlay);

    var data = { headers: [], rows: [], _path: '' };   // rows-mode
    var tlines = [], tpath = '';                        // transcript-mode

    function renderRows() {
      var q = filter.value.trim().toLowerCase();
      var rows = !q ? data.rows : data.rows.filter(function (r) { return r.join(' ').toLowerCase().indexOf(q) >= 0; });
      bodyWrap.innerHTML = '';
      if (!data.headers.length) { bodyWrap.appendChild(el('div', 'muted', 'No audit rows for this tool yet.')); return; }
      var tbl = el('table', 'j-audit-tbl');
      var thr = el('tr'); data.headers.forEach(function (h) { thr.appendChild(el('th', null, h)); }); tbl.appendChild(thr);
      rows.slice(-500).reverse().forEach(function (r) {
        var tr = el('tr'); data.headers.forEach(function (_, i) { tr.appendChild(el('td', null, r[i] == null ? '' : r[i])); }); tbl.appendChild(tr);
      });
      bodyWrap.appendChild(tbl);
      if (meta.className.indexOf('st-bad') < 0) meta.textContent = rows.length + ' row(s)' + (q ? ' (filtered)' : '') + (data._path ? '  -  ' + data._path : '');
    }
    function renderTranscript() {
      var q = filter.value.trim().toLowerCase();
      var lines = !q ? tlines : tlines.filter(function (l) { return String(l).toLowerCase().indexOf(q) >= 0; });
      bodyWrap.innerHTML = '';
      if (!tlines.length) { bodyWrap.appendChild(el('div', 'muted', 'No transcript for this tool yet this session.')); return; }
      var pre = el('pre');
      pre.style.cssText = 'font-family:var(--mono);white-space:pre-wrap;word-break:break-word;font-size:12px;line-height:1.5;margin:0';
      pre.textContent = lines.join('\n');
      bodyWrap.appendChild(pre);
      if (meta.className.indexOf('st-bad') < 0) meta.textContent = lines.length + ' line(s)' + (q ? ' (filtered)' : '') + (tpath ? '  -  ' + tpath : '');
    }
    function render() { (mode === 'rows') ? renderRows() : renderTranscript(); }

    function loadRows() {
      meta.className = 'j-audit-meta muted'; meta.textContent = 'Loading...'; data = { headers: [], rows: [], _path: '' }; bodyWrap.innerHTML = '';
      api('GET', '/logs/tail?tool=' + encodeURIComponent(toolSel.value) + '&n=500').then(function (res) {
        if (!res || !res.exists) { meta.textContent = 'No audit log yet for this tool' + (res && res.path ? ' (' + res.path + ')' : '') + '.'; render(); return; }
        var parsed = parseCsv((res.header || '') + '\n' + (res.rows || []).join('\n'));
        data = { headers: parsed.headers, rows: parsed.rows, _path: (res.onShare ? 'share' : 'local') + ': ' + res.path };
        render();
      }).catch(function (e) { meta.className = 'j-audit-meta st-bad'; meta.textContent = 'Could not read audit log: ' + (e && e.message); });
    }
    function loadTranscript() {
      meta.className = 'j-audit-meta muted'; meta.textContent = 'Loading...'; tlines = []; tpath = ''; bodyWrap.innerHTML = '';
      api('GET', '/logs/transcript?tool=' + encodeURIComponent(toolSel.value) + '&n=2000').then(function (res) {
        if (!res || !res.exists) { meta.textContent = 'No transcript yet for this tool this session' + (res && res.path ? ' (' + res.path + ')' : '') + '.'; render(); return; }
        tlines = res.lines || []; tpath = (res.onShare ? 'share' : 'local') + ': ' + res.path;
        render();
      }).catch(function (e) { meta.className = 'j-audit-meta st-bad'; meta.textContent = 'Could not read transcript: ' + (e && e.message); });
    }
    function load() { (mode === 'rows') ? loadRows() : loadTranscript(); }
    function setMode(m) { if (mode === m) return; mode = m; paintModes(); filter.value = ''; load(); }

    function close() { overlay.remove(); document.removeEventListener('keydown', onKey, true); }
    function onKey(e) { if (e.key === 'Escape') { e.preventDefault(); close(); } }
    rowsBtn.onclick = function () { setMode('rows'); };
    tranBtn.onclick = function () { setMode('transcript'); };
    toolSel.onchange = load; filter.addEventListener('input', render); closeB.onclick = close;
    overlay.addEventListener('mousedown', function (e) { if (e.target === overlay) close(); });
    document.addEventListener('keydown', onKey, true);
    paintModes();
    load();
  }

  /* --- launcher hub: a launchpad of icon tiles (flat grid, no category tabs) --- */
  // tool.icon is a Segoe MDL2 Assets codepoint (hex, e.g. "E895" - the original WPT
  // icon set); convert to the glyph char. Anything non-hex (emoji/text) renders verbatim.
  function iconGlyph(icon) {
    var s = String(icon == null ? '' : icon);
    return /^[0-9a-fA-F]{4,5}$/.test(s) ? String.fromCodePoint(parseInt(s, 16)) : s;
  }
  // --- light/dark theme: <html data-theme="light"> + localStorage. Dark is default.
  // A no-flash inline script in index.html sets the attribute before first paint.
  function currentTheme() {
    return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  }
  function applyTheme(t, btn) {
    var light = (t === 'light');
    if (light) document.documentElement.setAttribute('data-theme', 'light');
    else document.documentElement.removeAttribute('data-theme');
    try { localStorage.setItem('janet-theme', light ? 'light' : 'dark'); } catch (e) {}
    if (btn) {
      // glyph shows the mode you switch TO: sun in dark, moon in light
      btn.textContent = iconGlyph(light ? 'E708' : 'E706');
      btn.title = light ? 'Switch to dark theme' : 'Switch to light theme';
      btn.setAttribute('aria-label', btn.title);
    }
  }
  function makeThemeToggle() {
    var b = el('button', 'j-icon-btn'); b.type = 'button';
    applyTheme(currentTheme(), b);
    b.onclick = function () { applyTheme(currentTheme() === 'light' ? 'dark' : 'light', b); };
    return b;
  }
  function makeToolCard(tool) {
    var card = el('button', 'j-toolcard'); card.type = 'button';
    card.title = tool.name + (tool.summary ? ' - ' + tool.summary : '');
    card.appendChild(el('div', 'j-tc-icon', iconGlyph(tool.icon)));
    card.appendChild(el('div', 'j-tc-cat', tool.category || ''));
    var name = el('div', 'j-tc-name'); name.textContent = tool.name;
    if (tool.beta) name.appendChild(el('span', 'j-tc-tag beta', 'BETA'));
    card.appendChild(name);
    card.appendChild(el('div', 'j-tc-sum', tool.summary || ''));
    card.onclick = function () { openTool(tool); };
    return card;
  }
  // Fleet snapshot: a read-only bulk-scan over a chosen host set, aggregated to
  // online / offline / reboot-pending / needs-updates. Reuses the WPT bulk-scan
  // action + RunController, so no new plumbing. Hidden if WPT isn't in the registry.
  function buildSnapshot() {
    if (!(TOOLS || []).some(function (t) { return t.id === 'wpt'; })) return null;
    var wrap = el('div', 'j-snapshot');
    var bar = el('div', 'j-snap-bar');
    bar.appendChild(el('span', 'j-snap-title', 'FLEET SNAPSHOT'));
    var sel = el('select', 'j-select j-snap-group');
    function fillGroups() {
      sel.innerHTML = '';
      sel.appendChild(new Option('Current targets (' + sharedTargets.count() + ')', '__shared__'));
      (Janet.store ? Janet.store.names() : []).forEach(function (n) { sel.appendChild(new Option(n, n)); });
    }
    fillGroups();
    var scanBtn = Janet.ui.button('Scan fleet', { variant: 'cyan', size: 'sm', title: 'Read-only bulk scan: online, reboot-pending, pending updates.' });
    var openBtn = Janet.ui.ghostButton('Open in WPT', { size: 'sm', title: 'Load these hosts into Workstation Patching.' });
    var out = el('div', 'j-snap-out muted', 'Pick a host set, then Scan fleet.');
    bar.appendChild(sel); bar.appendChild(scanBtn); bar.appendChild(openBtn); bar.appendChild(out);
    wrap.appendChild(bar);

    function hostsFor() {
      var v = sel.value, raw = (v === '__shared__') ? sharedTargets.raw : (Janet.store ? Janet.store.get(v) : '');
      return parseHosts(raw);
    }
    openBtn.onclick = function () {
      var hosts = hostsFor(); if (!hosts.length) { out.className = 'j-snap-out st-warn'; out.textContent = 'No hosts in that set.'; return; }
      if (Janet.handoff) Janet.handoff.send(hosts, 'Fleet Snapshot');
      var wpt = (TOOLS || []).filter(function (t) { return t.id === 'wpt'; })[0]; if (wpt) openTool(wpt, 'bulk');
    };
    scanBtn.onclick = function () {
      var hosts = hostsFor(); if (!hosts.length) { out.className = 'j-snap-out st-warn'; out.textContent = 'No hosts in that set.'; return; }
      scanBtn.disabled = true;
      var agg = { on: 0, off: 0, reboot: 0, upd: 0, done: 0 };
      function paint(done) {
        out.className = 'j-snap-out';
        out.innerHTML = '<b class="st-ok">' + agg.on + '</b> online &middot; <b class="st-bad">' + agg.off + '</b> offline &middot; <b class="st-warn">' + agg.reboot + '</b> reboot-pending &middot; <b>' + agg.upd + '</b> need updates' + (done ? '' : ' <span class="muted">(' + agg.done + '/' + hosts.length + ')</span>');
      }
      out.className = 'j-snap-out'; out.textContent = 'Scanning ' + hosts.length + ' host(s)...';
      // Own run-key so the hub snapshot never collides with the WPT Bulk Scan
      // tab (both call wpt/bulk-scan); unsubscribe + dispose on terminal so the
      // hidden hub subscriber isn't left live after the operator opens a tool.
      var snapKey = 'wpt/bulk-scan#snapshot';
      var run = RunController.start('wpt', 'bulk-scan', { targets: hosts.join('\n'), threads: 24 }, { destructive: false, key: snapKey });
      var unsub = run.subscribe({
        // bail if the operator already left the hub (DOM detached)
        row: function (r) {
          if (!out.isConnected) return;
          agg.done++;
          if (r.Online === false) agg.off++; else agg.on++;
          if (r.RebootPending === true || r.RebootPending === 'true' || r.RebootPending === 'YES') agg.reboot++;
          if (((+r.MECMUpdateCount || 0) + (+r.WindowsUpdateCount || 0) + (+r.AppCount || 0)) > 0) agg.upd++;
          paint(false);
        },
        final: function () { if (unsub) unsub(); RunController.dispose(snapKey); if (!out.isConnected) return; scanBtn.disabled = false; paint(true); },
        error: function (e) { if (unsub) unsub(); RunController.dispose(snapKey); if (!out.isConnected) return; scanBtn.disabled = false; out.className = 'j-snap-out st-bad'; out.textContent = 'Scan failed: ' + ((e && e.text) || ''); }
      });
    };
    return wrap;
  }

  // Mission board: a read-only status strip above the launchpad. GETs /api/dashboard
  // (FLAT FILES only - no hosts touched) and renders neutral tiles for the newest WPT
  // bulk-scan snapshot, the SLA firstSeen ledger, and the KEV catalog. Each tile is a
  // click-through via openTool(tool, tab) using the same deep-link routing as the
  // command palette; a tile whose file is absent stays neutral (value '--'). Reuses the
  // j-snapshot card shell + j-stats/j-stat tiles so no new CSS is needed.
  function buildMissionBoard() {
    function toolById(id) { return (TOOLS || []).filter(function (t) { return t.id === id; })[0]; }
    function fmtAge(h) {
      if (h == null) return '--';
      if (h < 1) return '<1h';
      if (h < 48) return Math.round(h) + 'h';
      return Math.round(h / 24) + 'd';
    }
    var wrap = el('div', 'j-snapshot');
    var title = el('div', 'j-snap-title', 'MISSION BOARD'); title.style.marginBottom = '8px';
    wrap.appendChild(title);
    var row = el('div', 'j-stats'); row.style.flexWrap = 'wrap';
    wrap.appendChild(row);
    row.appendChild(el('div', 'muted', 'Reading local status files...'));

    // opts: { label, value, sub, state ('ok'|'gold'|'bad'|'cyan'), toolId, tab }
    function tile(opts) {
      var tool = opts.toolId ? toolById(opts.toolId) : null;
      var node = el(tool ? 'button' : 'div', 'j-stat' + (opts.state ? ' ' + opts.state : ''));
      node.style.minWidth = '128px';
      node.appendChild(el('div', 'j-stat-num', String(opts.value)));
      node.appendChild(el('div', 'j-stat-cap', opts.label));
      var sub = el('div', 'muted', opts.sub || ''); sub.style.fontSize = '10.5px'; sub.style.marginTop = '2px';
      node.appendChild(sub);
      if (tool) {
        node.type = 'button'; node.style.cursor = 'pointer'; node.style.textAlign = 'left';
        node.title = 'Open ' + tool.name;
        node.onclick = function () { openTool(tool, opts.tab || null); };
      }
      return node;
    }

    api('GET', '/dashboard').then(function (d) {
      row.innerHTML = ''; d = d || {};
      var snap = d.snapshot || {}, sla = d.sla || {}, kev = d.kev || {};
      // fleet pending + stuck (WPT Compliance Trend, read-only)
      if (snap.present) {
        row.appendChild(tile({ label: 'FLEET PENDING', value: snap.pending, sub: snap.online + '/' + snap.total + ' online - ' + fmtAge(snap.ageHours) + ' old', state: (snap.pending > 0 ? 'gold' : 'ok'), toolId: 'wpt', tab: 'trend' }));
        row.appendChild(tile({ label: 'STUCK HOSTS', value: snap.stuck, sub: 'pending 3+ consecutive scans', state: (snap.stuck > 0 ? 'bad' : 'ok'), toolId: 'wpt', tab: 'trend' }));
      } else {
        row.appendChild(tile({ label: 'FLEET PENDING', value: '--', sub: 'no bulk-scan snapshots yet', state: 'cyan', toolId: 'wpt', tab: 'trend' }));
      }
      // SLA firstSeen ledger (Reports SLA / Aging tab)
      if (sla.present) {
        var oldTxt = (sla.oldestAgeDays != null) ? (sla.oldestAgeDays + 'd oldest') : 'tracked';
        row.appendChild(tile({ label: 'SLA LEDGER', value: sla.count, sub: oldTxt + (sla.kev ? ' - ' + sla.kev + ' KEV' : ''), state: (sla.count > 0 ? 'gold' : 'ok'), toolId: 'reports', tab: 'sla' }));
      } else {
        row.appendChild(tile({ label: 'SLA LEDGER', value: '--', sub: 'no findings tracked yet', state: 'cyan', toolId: 'reports', tab: 'sla' }));
      }
      // KEV catalog size + mtime (KEV Cross-Check)
      if (kev.present) {
        row.appendChild(tile({ label: 'KEV CATALOG', value: kev.count, sub: 'updated ' + (kev.modified || ''), state: 'cyan', toolId: 'kev' }));
      } else {
        row.appendChild(tile({ label: 'KEV CATALOG', value: '--', sub: 'catalog file absent', state: 'cyan', toolId: 'kev' }));
      }
      // last-scan age / stale indicator (History)
      if (snap.present) {
        var stale = (snap.ageHours != null && snap.ageHours > 24);
        row.appendChild(tile({ label: 'LAST SCAN', value: fmtAge(snap.ageHours), sub: snap.snapshots + ' snapshot(s) on file', state: (stale ? 'gold' : 'ok'), toolId: 'history' }));
      } else {
        row.appendChild(tile({ label: 'LAST SCAN', value: '--', sub: 'no history yet', state: 'cyan', toolId: 'history' }));
      }
    }).catch(function () {
      row.innerHTML = '';
      row.appendChild(el('div', 'muted', 'Mission board unavailable (server not responding).'));
    });

    return wrap;
  }

  function renderHub() {
    var hub = dom.hub; hub.innerHTML = '';
    var inner = el('div', 'j-hub-inner');
    var lede = el('p', 'j-hub-lede');
    lede.innerHTML = 'Select a tool. Each tool is a faithful re-front of its desktop counterpart; the originals in <code>Tools\\</code> are untouched.';
    inner.appendChild(lede);
    var board = buildMissionBoard(); if (board) inner.appendChild(board);
    var snap = buildSnapshot(); if (snap) inner.appendChild(snap);
    // one launchpad tile per tool, in catalog order (no scroll until it overflows)
    var scroll = el('div', 'j-hub-scroll');
    var grid = el('div', 'j-launchpad');
    TOOLS.forEach(function (t) { grid.appendChild(makeToolCard(t)); });
    scroll.appendChild(grid);
    inner.appendChild(scroll);
    hub.appendChild(inner);
  }

  /* --- persistent sidebar nav: tools grouped by category, live filter, collapsible groups --- */
  var navActiveId = null;     // currently-open tool id (null = home/hub)
  var navCollapsed = {};      // category -> true if collapsed
  function navCatOrder() {    // categories in registry order of first appearance
    var seen = [], s = {};
    TOOLS.forEach(function (t) { var c = t.category || 'Other'; if (!s[c]) { s[c] = 1; seen.push(c); } });
    return seen;
  }
  function renderNav(filterStr) {
    if (!dom.navList) return;
    var q = (filterStr || '').trim().toLowerCase();
    dom.navList.innerHTML = '';
    navCatOrder().forEach(function (cat) {
      var items = TOOLS.filter(function (t) {
        if ((t.category || 'Other') !== cat) return false;
        if (!q) return true;
        return ((t.name || '').toLowerCase().indexOf(q) >= 0) || (cat.toLowerCase().indexOf(q) >= 0);
      });
      if (!items.length) return;
      var group = el('div', 'j-cat-group' + (navCollapsed[cat] ? ' collapsed' : ''));
      var head = el('button', 'j-cat-head'); head.type = 'button';
      head.setAttribute('aria-expanded', navCollapsed[cat] ? 'false' : 'true');
      head.appendChild(el('span', null, cat));
      head.appendChild(el('span', 'j-cat-count', String(items.length)));
      var chev = el('span', 'j-chev'); chev.textContent = iconGlyph('E70D'); head.appendChild(chev);
      head.onclick = function () { navCollapsed[cat] = !navCollapsed[cat]; renderNav(dom.toolFilter ? dom.toolFilter.value : ''); };
      group.appendChild(head);
      var box = el('div', 'j-cat-items');
      items.forEach(function (t) {
        var row = el('button', 'j-tool-row' + (t.id === navActiveId ? ' active' : '')); row.type = 'button';
        row.setAttribute('role', 'option'); row.setAttribute('aria-selected', t.id === navActiveId ? 'true' : 'false');
        row.dataset.id = t.id;
        var ic = el('span', 'j-tr-ico'); ic.textContent = iconGlyph(t.icon); row.appendChild(ic);
        row.appendChild(el('span', 'j-tr-name', t.name));
        if (t.beta) row.appendChild(el('span', 'j-tr-beta', 'BETA'));
        row.onclick = function () { openTool(t); };
        box.appendChild(row);
      });
      group.appendChild(box); dom.navList.appendChild(group);
    });
  }
  function setNavActive(id) {
    navActiveId = id;
    if (!dom.navList) return;
    Array.prototype.forEach.call(dom.navList.querySelectorAll('.j-tool-row'), function (r) {
      var on = r.dataset.id === id;
      r.classList.toggle('active', on);
      r.setAttribute('aria-selected', on ? 'true' : 'false');
    });
  }

  /* --- "How to use" box + full guide modal ------------------------------------
     The box shows a one-line blurb (JANET2_HELP); the "How to" button opens the
     full per-tab guide (JANET2_GUIDE: what it does / how to run / how to patch /
     notes + safety flag) in a modal. Box updates per tab via Janet.howtoTab,
     called by TabHost on each tab switch. */
  var howtoCtx = { toolId: null, tabId: null, label: '' };
  var currentToolName = '';

  function guideFor(c) {
    var G = (window.JANET2_GUIDE || {})[c.toolId];
    if (!G) return null;
    if (c.tabId && G.tabs && G.tabs[c.tabId]) {
      var lbl = String(c.label || c.tabId).replace(/^\d+\s+/, '');
      return { title: (currentToolName ? currentToolName + ' — ' : '') + lbl, guide: G.tabs[c.tabId] };
    }
    if (G.overview) return { title: currentToolName || c.toolId, guide: G.overview };
    return null;
  }

  function openHowtoModal() {
    var g = guideFor(howtoCtx);
    if (!g || !Janet.components || !Janet.components.ConfirmDialog) return;
    var gd = g.guide;
    var box = el('div', 'j-guide');
    function section(label, node) { box.appendChild(el('div', 'j-guide-h', label)); box.appendChild(node); }
    var isBad = gd.flag === 'destructive';
    box.appendChild(el('div', 'j-guide-flag ' + (isBad ? 'is-bad' : 'is-ok'), isBad ? 'DESTRUCTIVE — changes hosts' : 'READ-ONLY — changes nothing'));
    if (gd.what) { var w = el('div', 'j-guide-what'); w.innerHTML = gd.what; section('What it does', w); }
    if (gd.steps && gd.steps.length) {
      var ol = el('ol', 'j-guide-steps');
      gd.steps.forEach(function (s) { var li = el('li'); li.innerHTML = s; ol.appendChild(li); });
      section('How to run it', ol);
    }
    if (gd.patch) { var p = el('div', 'j-guide-patch'); p.innerHTML = gd.patch; section('How to patch', p); }
    if (gd.notes && gd.notes.length) {
      var ul = el('ul', 'j-guide-notes');
      gd.notes.forEach(function (n) { var li = el('li'); li.innerHTML = n; ul.appendChild(li); });
      section('Notes', ul);
    }
    Janet.components.ConfirmDialog({ title: 'How to: ' + g.title, body: box, okText: 'Got it', cancelText: null });
  }

  function renderHowto(html) {
    if (!dom.howto) return;
    // reset any clickable state from a previous tab
    dom.howto.onclick = null; dom.howto.onkeydown = null;
    dom.howto.classList.remove('is-clickable');
    dom.howto.removeAttribute('role'); dom.howto.removeAttribute('tabindex'); dom.howto.removeAttribute('title');
    if (!html) { dom.howto.innerHTML = ''; dom.howto.style.display = 'none'; return; }
    dom.howto.innerHTML = '';
    dom.howto.appendChild(el('span', 'j-howto-tag', 'HOW TO USE'));
    var txt = el('span', 'j-howto-text'); txt.innerHTML = html; dom.howto.appendChild(txt);
    if (guideFor(howtoCtx)) {
      // the WHOLE box is the click target (left chip + text) -> opens the full guide.
      dom.howto.classList.add('is-clickable');
      dom.howto.setAttribute('role', 'button');
      dom.howto.setAttribute('tabindex', '0');
      dom.howto.title = 'Click for the full guide: what it does, how to run it, how to patch';
      dom.howto.onclick = openHowtoModal;
      dom.howto.onkeydown = function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openHowtoModal(); } };
    }
    dom.howto.style.display = '';
  }

  // Called by TabHost on each tab switch (toolId from opts.helpId, tab id + label).
  Janet.howtoTab = function (toolId, tabId, label) {
    howtoCtx = { toolId: toolId, tabId: tabId, label: label || '' };
    var h = (window.JANET2_HELP || {})[toolId];
    renderHowto((h && typeof h === 'object') ? (h[tabId] || h._overview) : (typeof h === 'string' ? h : ''));
  };

  /* --- tool routing --- */
  var current = null;   // { tool, view, ctx }
  var openGen = 0;      // bumped per openTool call; guards against out-of-order async mounts
  async function openTool(tool, pendingTab) {
    // Re-clicking the tool that is already open (sidebar row / command palette) must
    // NOT tear down its in-flight destructive run. No-op unless a deep-link tab was
    // requested (that still needs to route the TabHost).
    if (current && current.tool.id === tool.id && !pendingTab) { return; }
    var gen = ++openGen;
    // Tear down the outgoing view first (mirrors backToHub egress): cancel any
    // running destructive op and unmount so its listeners / detached DOM do not leak.
    if (current) {
      RunController.cancelDestructive(current.tool.id);
      try { if (current.view && current.view.unmount) current.view.unmount(); } catch (e) {}
      current = null;
    }
    Janet._pendingTab = pendingTab || null;   // consumed by the view's TabHost on mount (command palette deep-link)
    dom.thIcon.textContent = iconGlyph(tool.icon);
    dom.thName.textContent = tool.name;
    dom.thSum.textContent = tool.summary || '';
    if (dom.crumbCat) {
      dom.crumbCat.textContent = tool.category || 'Tool';
      dom.crumbTool.textContent = tool.name;
      dom.crumbSep.style.display = '';
    }
    setNavActive(tool.id);
    // "How to use" box: tool overview now; tab tools refine it via Janet.howtoTab
    // (TabHost fires it on tab select). Brief copy in help-content.js (JANET2_HELP),
    // the full "How to" modal in JANET2_GUIDE.
    currentToolName = tool.name;
    howtoCtx = { toolId: tool.id, tabId: null, label: tool.name };
    var help = (window.JANET2_HELP || {})[tool.id];
    renderHowto(typeof help === 'string' ? help : (help && help._overview));
    dom.hub.classList.add('hidden');
    dom.tool.classList.remove('hidden');
    dom.viewHost.innerHTML = '';
    var loading = el('div'); loading.style.padding = '24px'; loading.className = 'muted'; loading.textContent = 'Loading ' + tool.name + '...';
    dom.viewHost.appendChild(loading);
    var view, manifest = null;
    try {
      var pair = await Promise.all([loadView(tool.id), api('GET', '/tool/' + tool.id + '/manifest').catch(function () { return null; })]);
      view = pair[0]; manifest = pair[1];
    } catch (e) {
      dom.viewHost.innerHTML = '';
      var err = el('div'); err.style.padding = '24px'; err.className = 'st-bad';
      err.textContent = 'Could not open ' + tool.name + ': ' + e.message;
      dom.viewHost.appendChild(err);
      return;
    }
    // A newer openTool() superseded this one while we awaited the view/manifest
    // fetch; bail so we do not wipe the newer view's DOM or clobber `current`.
    if (gen !== openGen) { return; }
    // Unmount whatever is mounted right now (not just what we tore down at entry)
    // before replacing it, so an interleaved mount cannot leak its listeners.
    if (current) {
      try { if (current.view && current.view.unmount) current.view.unmount(); } catch (e) {}
      current = null;
    }
    dom.viewHost.innerHTML = '';
    var ctx = buildCtx(tool, manifest);
    current = { tool: tool, view: view, ctx: ctx };
    try { view.mount(dom.viewHost, ctx); }
    catch (e) {
      var err2 = el('div'); err2.style.padding = '24px'; err2.className = 'st-bad';
      err2.textContent = 'View "' + tool.id + '" failed to mount: ' + (e && e.message);
      dom.viewHost.appendChild(err2);
      if (window.console) console.error(e);
    }
  }
  function backToHub() {
    if (current) {
      // a running destructive op in this tool is cancelled on egress (mirrors JANET ONE),
      // read-only/streaming runs keep going in the background.
      RunController.cancelDestructive(current.tool.id);
      try { if (current.view && current.view.unmount) current.view.unmount(); } catch (e) {}
      current = null;
    }
    dom.tool.classList.add('hidden');
    dom.hub.classList.remove('hidden');
    dom.viewHost.innerHTML = '';
    setNavActive(null);
    if (dom.crumbCat) { dom.crumbCat.textContent = 'Home'; dom.crumbTool.textContent = ''; dom.crumbSep.style.display = 'none'; }
  }

  function findAction(manifest, actionId) {
    if (!manifest || !manifest.actions) return null;
    return manifest.actions.find(function (a) { return a.id === actionId; }) || null;
  }
  var sharedTargets = targetModel('');
  sharedTargets.onChange(function () { updateStrip(); });

  function buildCtx(tool, manifest) {
    return {
      toolId: tool.id,
      toolName: tool.name,
      tool: tool,
      manifest: manifest,
      session: SessionApi,
      targets: sharedTargets,
      components: Janet.components,
      ui: Janet.ui,
      util: Janet.util,
      api: api,
      uploadFile: uploadFile,
      run: function (actionId, params, opts) {
        opts = opts || {};
        var act = findAction(manifest, actionId);
        var o = { destructive: (opts.destructive != null) ? opts.destructive : !!(act && act.destructive), keyOf: opts.keyOf };
        return RunController.start(tool.id, actionId, params || {}, o);
      },
      confirm: function (opts) { return Janet.components.ConfirmDialog(opts); },
      arm: function (opts) { return Janet.components.ArmingDialog(opts); },
      // Cross-tool handoff: a view hands its work to another tool by id (e.g. the
      // Reports Remediation Router loads a route's hosts into shared targets then
      // opens the mapped acas/upr tool). Same registry lookup the palette uses; an
      // unknown id is a safe no-op.
      openTool: function (toolId) {
        var t = (TOOLS || []).filter(function (x) { return x.id === toolId; })[0];
        if (t) openTool(t);
      }
    };
  }

  /* ========================================================================
     session gate (launch overlay)
     ===================================================================== */
  function buildGate() {
    var gate = el('div'); gate.id = 'j-gate';
    var card = el('div', 'j-gate-card');
    var brand = el('div', 'j-gate-brand');
    var mark = el('div', 'j-brand-mark'); mark.innerHTML = 'J<span>2</span>'; brand.appendChild(mark);
    var bt = el('div');
    var ti = el('div', 'j-gate-title'); ti.innerHTML = 'J.A.N.E.T. <b>TWO</b>'; bt.appendChild(ti);
    bt.appendChild(el('div', 'j-gate-sub', 'Joint Administration and Network Execution Toolkit')); brand.appendChild(bt);
    card.appendChild(brand);

    // credentials
    var s1 = el('div', 'j-gate-sec');
    var h1 = el('div', 'j-gate-h'); h1.innerHTML = 'Credentials <span class="j-gate-req">(required for an admin session)</span>'; s1.appendChild(h1);
    s1.appendChild(el('p', 'j-gate-p', 'Set your ADW admin credential before starting an admin session - the Windows smartcard picker opens on your desktop. Held in this app memory only: never written to disk, never sent to the browser.'));
    var row = el('div', 'j-gate-row');
    var setb = Janet.ui.button('Set Credentials', { variant: 'gold' });
    var clrb = Janet.ui.ghostButton('Clear');
    var cdot = el('span', 'j-dot j-dot-warn');
    var ctext = el('span', 'muted', 'checking credential...');
    row.appendChild(setb); row.appendChild(clrb); row.appendChild(cdot); row.appendChild(ctext); s1.appendChild(row);
    card.appendChild(s1);

    // responsibility
    var s2 = el('div', 'j-gate-sec');
    var h2 = el('div', 'j-gate-h warn'); h2.innerHTML = 'Responsibility acknowledgment <span class="j-gate-req">(required)</span>'; s2.appendChild(h2);
    s2.appendChild(el('p', 'j-gate-p', 'This toolkit performs remote patching, application management, reboots, message broadcasts, and package deployment across workstations. Incorrect use can disrupt end-user systems. Do you accept responsibility and confirm you understand the impact?'));
    var yes = el('label', 'j-gate-radio'); var yesr = el('input'); yesr.type = 'radio'; yesr.name = 'j-gate-ack'; yesr.value = 'yes';
    yes.appendChild(yesr); yes.appendChild(el('span', null, 'Yes, I understand and accept responsibility.'));
    var no = el('label', 'j-gate-radio'); var nor = el('input'); nor.type = 'radio'; nor.name = 'j-gate-ack'; nor.value = 'no';
    no.appendChild(nor); no.appendChild(el('span', null, 'No.'));
    s2.appendChild(yes); s2.appendChild(no);
    var ackStatus = el('div', 'muted j-gate-status', 'Select Yes or No before starting.'); s2.appendChild(ackStatus);
    card.appendChild(s2);

    // actions
    var acts = el('div', 'j-gate-actions');
    var startAdmin = Janet.ui.button('Start Admin Session', { variant: 'go' }); startAdmin.disabled = true;
    startAdmin.title = 'Requires an ADW credential and the responsibility acknowledgment. Unlocks the full toolkit.';
    var startAd = Janet.ui.ghostButton('Browse tools (read-only)');
    startAd.title = 'Open the launcher without an admin session. Read-only tools work; actions that change machines stay blocked until you start an admin session.';
    var startAdsearch = Janet.ui.ghostButton('AD Search (read-only)');
    startAdsearch.title = 'Jump straight to the read-only Active Directory search - no admin session or credential needed. Other tools stay read-only until you start an admin session.';
    acts.appendChild(startAdmin); acts.appendChild(startAd); acts.appendChild(startAdsearch);
    card.appendChild(acts);

    var foot = el('div', 'j-gate-sec'); var sessInfo = el('span', 'muted'); foot.appendChild(sessInfo); card.appendChild(foot);

    gate.appendChild(card);
    document.body.appendChild(gate);

    // wire
    if (yesr.checked || Session.ack) yesr.checked = true;
    function refreshGate() {
      cdot.className = 'j-dot ' + (Session.credSet ? 'j-dot-ok' : 'j-dot-warn');
      ctext.className = Session.credSet ? 'st-ok' : 'muted';
      ctext.textContent = Session.credSet ? ('Active: ' + Session.user + ' (ADW)') : 'No credential set (read-only runs as your current login).';
      var ackYes = yesr.checked;
      ackStatus.textContent = ackYes ? 'Responsibility accepted.' : (nor.checked ? 'You selected No - admin session unavailable.' : 'Select Yes or No before starting.');
      startAdmin.disabled = !(Session.credSet && ackYes);
    }
    setb.onclick = function () { setb.disabled = true; ctext.textContent = 'opening smartcard picker...'; setCred().catch(function () {}).then(function () { setb.disabled = false; refreshGate(); }); };
    clrb.onclick = function () { clearCred().catch(function () {}).then(refreshGate); };
    yesr.onchange = refreshGate; nor.onchange = refreshGate;
    startAdmin.onclick = function () {
      startAdmin.disabled = true;
      startSession(true).then(function () {
        if (Session.active) { gate.remove(); refreshStatus(); }
        else { startAdmin.disabled = false; ackStatus.textContent = 'Server did not accept the session - check credential + ack.'; }
      }).catch(function () { startAdmin.disabled = false; });
    };
    startAd.onclick = function () {
      Session.adOnly = true;
      try { sessionStorage.setItem('janet2_adonly', '1'); } catch (e) {}
      gate.remove(); refreshStatus(); updateStrip();
    };
    // read-only bypass straight into AD Search (no credential / admin session needed),
    // mirroring JANET ONE's gate. Other tools stay read-only until an admin session.
    startAdsearch.onclick = function () {
      Session.adOnly = true;
      try { sessionStorage.setItem('janet2_adonly', '1'); } catch (e) {}
      gate.remove(); refreshStatus(); updateStrip();
      var adTool = (TOOLS || []).filter(function (t) { return t.id === 'adsearch'; })[0];
      if (adTool) openTool(adTool);
    };
    Session.onChange(refreshGate);
    refreshCred().then(refreshGate);
    // if a prior admin session was already established this browser session, skip the gate
    if (Session.active) { gate.remove(); refreshStatus(); }
  }

  /* ========================================================================
     boot
     ===================================================================== */
  async function boot() {
    var root = qs('#j-root') || document.body;
    buildShell(root);
    updateStrip();
    try {
      var cat = await api('GET', '/tools');
      SUITE = cat.suite || SUITE; TOOLS = cat.tools || [];
    } catch (e) {
      TOOLS = [];
      var warn = el('div'); warn.style.padding = '24px'; warn.className = 'st-bad';
      warn.textContent = 'Could not reach the JANET TWO server (' + e.message + '). Is the console window still open?';
      dom.hub.appendChild(warn);
    }
    renderHub();
    renderNav('');
    if (Janet.palette) Janet.palette.setProvider(paletteItems);
    buildGate();
  }

  // Command-palette items: every tool, plus a deep-link per tab (from JANET2_HELP).
  var TAB_LABEL = { kb: 'KB', sccm: 'Software Center', dhcp: 'DHCP', os: 'OS', acas: 'ACAS', cora: 'CORA',
    appupd: 'App Updater', regkey: 'Reg Keys', winrm: 'WinRM', log4j: 'Log4j', dirty30: 'Dirty 30',
    future: 'Future IPs', bulk: 'Bulk Scan & Patch', wpt: 'WPT' };
  function humanizeTab(id) { return TAB_LABEL[id] || (id.charAt(0).toUpperCase() + id.slice(1)); }
  function paletteItems() {
    var items = [{ label: 'Audit log', sub: 'view', run: openAuditViewer }];
    (TOOLS || []).forEach(function (t) {
      items.push({ label: t.name, sub: t.category || 'Tool', run: function () { openTool(t); } });
      var help = (window.JANET2_HELP || {})[t.id];
      if (help && typeof help === 'object') {
        Object.keys(help).forEach(function (tab) {
          if (tab === '_overview') return;
          items.push({ label: t.name + ' → ' + humanizeTab(tab), sub: 'tab', run: function () { openTool(t, tab); } });
        });
      }
    });
    return items;
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
