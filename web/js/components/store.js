/* ============================================================================
   Store + Handoff  ->  Janet.store / Janet.handoff
   - Janet.store: named host GROUPS persisted on the SERVER (JanetLocal\
     target-groups.json) so you don't re-paste hostnames into every tool. The
     target library (TargetManager) and the hub snapshot read/write these.
   - Janet.handoff: a transient, this-page-session host set passed BETWEEN tools
     (e.g. WPT scan -> Restart). In-memory only; cleared once taken.

   Groups used to live in localStorage (keyed by origin INCLUDING port), so they
   didn't carry across a browser wipe or a different launch port. They now live in
   a JanetLocal JSON via GET/POST /api/target-groups, so they survive both AND ship
   in take-to-work. The Janet.store API stays SYNCHRONOUS (TargetManager reads it
   inline): an in-memory CACHE backs every read; it's seeded from localStorage for
   an instant first paint, then hydrated from the server (Janet.store.ready). Writes
   update the cache + a localStorage mirror synchronously and push the whole map to
   the server async - if the fetch ever fails the mirror keeps the UI working.
   ========================================================================== */
(function () {
  'use strict';
  var Janet = window.Janet = window.Janet || {};
  var KEY = 'janet2_target_groups';
  var EP = '/api/target-groups';

  function lsLoad() { try { return JSON.parse(localStorage.getItem(KEY) || '{}') || {}; } catch (e) { return {}; } }
  function lsSave(obj) { try { localStorage.setItem(KEY, JSON.stringify(obj)); } catch (e) {} }

  // Same token resolution as shell.js (sessionStorage; ?t= only on first paint).
  function token() {
    try { var q = new URLSearchParams(location.search).get('t'); if (q) return q; } catch (e) {}
    try { return sessionStorage.getItem('janet2_token') || ''; } catch (e) { return ''; }
  }

  // In-memory source of truth for the synchronous API. Seed from the localStorage
  // mirror so groups render immediately on the pinned port; the server hydrate
  // (below) then supersedes it (a fresh browser / new port has an empty mirror).
  var CACHE = lsLoad();

  function serverPush(obj) {
    var body = JSON.stringify(obj);
    return fetch(EP, {
      method: 'POST',
      headers: { 'X-Janet-Token': token(), 'Content-Type': 'application/json' },
      body: body
    }).then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); });
  }

  Janet.store = {
    names: function () { return Object.keys(CACHE).sort(function (a, b) { return a.toLowerCase() < b.toLowerCase() ? -1 : 1; }); },
    get: function (name) { return CACHE[name] || ''; },
    set: function (name, text) { CACHE[String(name)] = String(text == null ? '' : text); lsSave(CACHE); serverPush(CACHE)['catch'](function () {}); },
    remove: function (name) { delete CACHE[name]; lsSave(CACHE); serverPush(CACHE)['catch'](function () {}); },
    has: function (name) { return Object.prototype.hasOwnProperty.call(CACHE, name); }
  };

  // Hydrate from the server once, after the sync scripts (incl. shell.js -> token)
  // have run. Resolves Janet.store.ready so a mounted TargetManager can re-render
  // its group list with the authoritative set. On any failure keep the localStorage
  // cache so the UI never hard-breaks (offline seed / first launch).
  Janet.store.ready = fetch(EP, { headers: { 'X-Janet-Token': token() } })
    .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
    .then(function (obj) { if (obj && typeof obj === 'object') { CACHE = obj; lsSave(CACHE); } })
    ['catch'](function () {});

  // transient cross-tool handoff (in-memory, this page session only)
  var pending = null;
  Janet.handoff = {
    send: function (hosts, label) { pending = { hosts: (hosts || []).filter(Boolean), label: label || '', stamp: (Janet.util && Janet.util.clockStr ? Janet.util.clockStr() : '') }; },
    peek: function () { return pending; },
    take: function () { var p = pending; pending = null; return p; },
    clear: function () { pending = null; }
  };
})();
