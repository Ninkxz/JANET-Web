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
  var KEY = 'janetweb_target_groups';
  var EP = '/api/target-groups';

  function lsLoad() { try { return JSON.parse(localStorage.getItem(KEY) || '{}') || {}; } catch (e) { return {}; } }
  function lsSave(obj) { try { localStorage.setItem(KEY, JSON.stringify(obj)); } catch (e) {} }

  // Same token resolution as shell.js (sessionStorage; ?t= only on first paint).
  function token() {
    try { var q = new URLSearchParams(location.search).get('t'); if (q) return q; } catch (e) {}
    try { return sessionStorage.getItem('janetweb_token') || ''; } catch (e) { return ''; }
  }

  // In-memory source of truth for the synchronous API. Seed from the localStorage
  // mirror so groups render immediately on the pinned port; the server hydrate
  // (below) then supersedes it (a fresh browser / new port has an empty mirror).
  var CACHE = lsLoad();

  // audit#27: keys written locally BEFORE the boot hydrate resolves. The hydrate
  // must not wholesale-replace CACHE and drop a group saved during that window (and
  // then push the group-less map back, deleting it server-side too). We record such
  // writes and re-apply them on top of the hydrated map. Cleared once ready settles.
  var dirty = {}, hydrated = false;
  function markDirty(name, removed) { if (!hydrated) dirty[name] = { removed: !!removed }; }

  function serverPush(obj) {
    var body = JSON.stringify(obj);
    return fetch(EP, {
      method: 'POST',
      headers: { 'X-Janet-Token': token(), 'Content-Type': 'application/json' },
      body: body
    }).then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); });
  }

  Janet.store = {
    // audit#26: localeCompare returns 0 on equal-lowercased names (the old ?-1:1
    // never returned 0, an inconsistent comparator -> unstable dropdown order).
    names: function () { return Object.keys(CACHE).sort(function (a, b) { return a.toLowerCase().localeCompare(b.toLowerCase()); }); },
    get: function (name) { return CACHE[name] || ''; },
    set: function (name, text) { CACHE[String(name)] = String(text == null ? '' : text); markDirty(String(name), false); lsSave(CACHE); serverPush(CACHE)['catch'](function () {}); },
    remove: function (name) { delete CACHE[name]; markDirty(String(name), true); lsSave(CACHE); serverPush(CACHE)['catch'](function () {}); },
    has: function (name) { return Object.prototype.hasOwnProperty.call(CACHE, name); }
  };

  // Hydrate from the server once, after the sync scripts (incl. shell.js -> token)
  // have run. Resolves Janet.store.ready so a mounted TargetManager can re-render
  // its group list with the authoritative set. On any failure keep the localStorage
  // cache so the UI never hard-breaks (offline seed / first launch).
  Janet.store.ready = fetch(EP, { headers: { 'X-Janet-Token': token() } })
    .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
    .then(function (obj) {
      if (obj && typeof obj === 'object') {
        // Re-apply any writes made during the fetch window on top of the server map,
        // then push if we changed anything so the merged set is durable (audit#27).
        var pushBack = false;
        Object.keys(dirty).forEach(function (k) {
          if (dirty[k].removed) { if (k in obj) { delete obj[k]; pushBack = true; } }
          else { obj[k] = CACHE[k]; pushBack = true; }
        });
        CACHE = obj; lsSave(CACHE);
        if (pushBack) serverPush(CACHE)['catch'](function () {});
      }
    })
    ['catch'](function () {})
    .then(function () { hydrated = true; dirty = {}; });

  // transient cross-tool handoff (in-memory, this page session only)
  var pending = null;
  Janet.handoff = {
    send: function (hosts, label, extra) { pending = { hosts: (hosts || []).filter(Boolean), label: label || '', stamp: (Janet.util && Janet.util.clockStr ? Janet.util.clockStr() : ''), extra: extra || null }; },
    peek: function () { return pending; },
    take: function () { var p = pending; pending = null; return p; },
    clear: function () { pending = null; }
  };
})();
