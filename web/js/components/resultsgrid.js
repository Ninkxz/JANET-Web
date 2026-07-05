/* ============================================================================
   ResultsGrid  ->  Janet.components.ResultsGrid
   Colour-coded per-entity grid driven by a per-tool ColumnSpec. One row per
   entity, upserted by an EXPLICIT key (keyMode) so multi-row-per-host scans do
   not collapse onto a shared Host value. Colour is type-aware and HAND-WRITTEN
   per column (colorRule / render), never regex-on-name. Supports per-cell and
   whole-row colouring, checkbox select (+ Select All / None / a predicate),
   clickable-header sort, drag-resize columns, double-click RowDetail, a row.Tag
   full-result cache, and a Pop-Out window that keeps streaming the same DOM.

   ColumnSpec column: {
     key, label, width?, type?('text'|'bool'|'status'|'count'|'sev'),
     render?(row)->cell, colorRule?(value,row)->cssClass, sortVal?(row), title?
   }   cell = { text, cls?, title?, bar?:{pct,cls} }

   instance = ResultsGrid({
     columns, keyMode, selectable, rowClass(row), title, onRowClick(row), popOut
   })
   keyMode: { rk:true } uses _rk; { hostCol:'Host' } keys by a column; or a fn(row).
     .el  .upsert(row)  .clear()  .rows()  .order()
     .getChecked()  .selectAll(on)  .selectWhere(fn)
   ========================================================================== */
(function () {
  'use strict';
  var Janet = window.Janet = window.Janet || {};
  Janet.components = Janet.components || {};
  var el = Janet.ui.el;

  function defaultCell(col, row) {
    var v = row[col.key];
    var text = (v === true) ? 'yes' : (v === false) ? 'no' : (v == null ? '' : String(v));
    var cls = '';
    if (typeof col.colorRule === 'function') { try { cls = col.colorRule(v, row) || ''; } catch (e) { cls = ''; } }
    else if (col.type === 'bool') { cls = (v === true) ? 'st-ok' : (v === false ? 'st-bad' : ''); }
    return { text: text, cls: cls, title: col.title };
  }

  function ResultsGrid(opts) {
    opts = opts || {};
    var columns = opts.columns || [];
    var selectable = !!opts.selectable;
    var rows = {};          // key -> row data (full result cache = row.Tag)
    var order = [];         // key order (insertion)
    var trIndex = {};       // key -> <tr>
    var checked = new Set();
    var sort = opts.sort || { key: null, dir: 0 };   // dir 1 asc, -1 desc
    var filterFn = null;     // optional row predicate; non-matching rows are hidden (display:none), data/keys/selection untouched

    function keyOf(row) {
      if (typeof opts.keyMode === 'function') return opts.keyMode(row);
      var km = opts.keyMode || {};
      if (km.rk && row._rk != null) return String(row._rk);
      if (km.hostCol && row[km.hostCol] != null) return String(row[km.hostCol]);
      if (row._rk != null) return String(row._rk);
      if (row.id != null) return '_row' + row.id;
      return null;
    }

    var root = el('div', 'j-grid-wrap');

    // toolbar
    var toolbar = el('div', 'j-grid-toolbar');
    var selInfo = el('span', 'j-grid-sel');
    if (selectable) {
      toolbar.appendChild(selInfo);
      toolbar.appendChild(Janet.ui.ghostButton('Select all', { size: 'sm', onClick: function () { selectAll(true); } }));
      toolbar.appendChild(Janet.ui.ghostButton('None', { size: 'sm', onClick: function () { selectAll(false); } }));
    } else { toolbar.appendChild(selInfo); }
    (opts.toolbarButtons || []).forEach(function (b) { toolbar.appendChild(b); });
    if (opts.popOut !== false) toolbar.appendChild(Janet.ui.ghostButton('Pop-Out', { size: 'sm', onClick: popOut, title: 'Open this grid in a floating window; it keeps streaming.' }));
    root.appendChild(toolbar);

    var scroll = el('div', 'j-grid-scroll');
    var table = el('table', 'j-grid');
    var thead = el('thead'); var headRow = el('tr');
    var tbody = el('tbody');
    table.appendChild(thead); thead.appendChild(headRow); table.appendChild(tbody);
    scroll.appendChild(table);
    // Empty / loading placeholder shown over the (blank) tbody when no rows exist,
    // so an empty grid is never ambiguous ("did the scan return zero, is it still
    // running, or did nothing happen?"). Toggled by updateEmpty().
    var emptyText = opts.emptyText || 'No results yet.';
    var placeholder = el('div', 'j-grid-empty');
    var phSpin = el('span', 'j-grid-spinner');
    var phMsg = el('span', 'j-grid-empty-msg', emptyText);
    placeholder.appendChild(phSpin); placeholder.appendChild(phMsg);
    scroll.appendChild(placeholder);
    root.appendChild(scroll);
    var loading = false;

    buildHeader();
    // Show the empty placeholder immediately (before the first row streams in).
    setTimeout(function () { if (order.length === 0) updateEmpty(); }, 0);

    function buildHeader() {
      headRow.innerHTML = '';
      if (selectable) {
        var cbh = el('th', 'j-cb-col');
        var all = el('input'); all.type = 'checkbox'; all.title = 'Select all';
        all.onclick = function () { selectAll(all.checked); };
        cbh.appendChild(all); headRow.appendChild(cbh);
      }
      columns.forEach(function (col) {
        var th = el('th', 'j-col-resize'); th.textContent = col.label;
        if (col.width) th.style.width = col.width + 'px';
        if (sort.key === col.key && sort.dir) { var s = el('span', 'j-sort', sort.dir > 0 ? '▲' : '▼'); th.appendChild(s); }
        th.addEventListener('click', function (e) { if (e.target.classList.contains('j-rsz')) return; toggleSort(col); });
        var rsz = el('span', 'j-rsz'); rsz.addEventListener('mousedown', function (e) { startResize(e, th); }); th.appendChild(rsz);
        headRow.appendChild(th);
      });
    }
    function startResize(e, th) {
      e.preventDefault(); e.stopPropagation();
      var startX = e.clientX, startW = th.offsetWidth;
      function move(ev) { th.style.width = Math.max(40, startW + (ev.clientX - startX)) + 'px'; }
      function up() { document.removeEventListener('mousemove', move); document.removeEventListener('mouseup', up); }
      document.addEventListener('mousemove', move); document.addEventListener('mouseup', up);
    }
    function toggleSort(col) {
      if (sort.key === col.key) sort.dir = (sort.dir === 1) ? -1 : (sort.dir === -1 ? 0 : 1);
      else { sort.key = col.key; sort.dir = 1; }
      if (sort.dir === 0) sort.key = null;
      buildHeader(); repaint();
    }

    function cmp(a, b) {
      var sa = (a == null ? '' : String(a)).trim(), sb = (b == null ? '' : String(b)).trim();
      if (sa === sb) return 0; if (sa === '') return 1; if (sb === '') return -1;
      return sa.localeCompare(sb, undefined, { numeric: true, sensitivity: 'base' });
    }
    function sortedKeys() {
      if (!sort.key || !sort.dir) return order.slice();
      var col = columns.find(function (c) { return c.key === sort.key; }) || null;
      var val = function (k) { var r = rows[k]; return (col && typeof col.sortVal === 'function') ? col.sortVal(r) : r[sort.key]; };
      return order.slice().sort(function (ka, kb) { return sort.dir * cmp(val(ka), val(kb)); });
    }

    function fillCell(td, cell) {
      td.className = cell.cls || '';
      td.textContent = cell.text == null ? '' : cell.text;
      if (cell.title) td.title = cell.title;
      if (cell.bar) { var bar = el('span', 'j-cell-bar ' + (cell.bar.cls || '')); bar.style.width = Math.max(0, Math.min(100, cell.bar.pct)) + '%'; bar.style.maxWidth = '100%'; td.appendChild(bar); }
    }
    function makeRow(key) {
      var row = rows[key];
      var tr = el('tr'); tr.dataset.key = key;
      if (selectable) {
        var cbtd = el('td', 'j-cb-col');
        var cb = el('input'); cb.type = 'checkbox'; cb.className = 'j-rowcb'; cb.checked = checked.has(key);
        cb.addEventListener('click', function (e) { e.stopPropagation(); if (cb.checked) checked.add(key); else checked.delete(key); tr.classList.toggle('sel', cb.checked); updateSel(); });
        cbtd.appendChild(cb); tr.appendChild(cbtd);
      }
      columns.forEach(function (col) {
        var td = el('td');
        var cell = (typeof col.render === 'function') ? col.render(row) : defaultCell(col, row);
        fillCell(td, cell);
        tr.appendChild(td);
      });
      tr.classList.toggle('sel', checked.has(key));
      applyRowClass(tr, row);
      if (filterFn && !filterFn(row)) tr.style.display = 'none';
      tr.addEventListener('dblclick', function () { if (opts.onRowClick) opts.onRowClick(row); else openRowDetail(row); });
      return tr;
    }
    function applyRowClass(tr, row) {
      tr.classList.remove('row-ok', 'row-bad', 'row-warn');
      if (typeof opts.rowClass === 'function') { var c = opts.rowClass(row); if (c) tr.classList.add(c); }
    }
    function repaint() {
      tbody.innerHTML = ''; trIndex = {};
      sortedKeys().forEach(function (k) { var tr = makeRow(k); trIndex[k] = tr; tbody.appendChild(tr); });
      updateSel();
    }
    var repaintRaf = 0;
    function scheduleRepaint() {
      // Coalesce sorted-view repaints: during a live fleet scan many rows stream in
      // per frame; repaint once per animation frame instead of once per row (O(n) not O(n^2)).
      if (repaintRaf) return;
      var raf = window.requestAnimationFrame || function (cb) { return setTimeout(cb, 16); };
      repaintRaf = raf(function () { repaintRaf = 0; repaint(); });
    }
    function paintRow(key) {
      var tr = trIndex[key];
      if (!tr) { tr = makeRow(key); trIndex[key] = tr; tbody.appendChild(tr); return; }
      var row = rows[key];
      var off = selectable ? 1 : 0;
      columns.forEach(function (col, i) { var cell = (typeof col.render === 'function') ? col.render(row) : defaultCell(col, row); fillCell(tr.children[i + off], cell); });
      applyRowClass(tr, row);
      if (filterFn) tr.style.display = filterFn(row) ? '' : 'none';
    }
    function visibleCount() { if (!filterFn) return order.length; var n = 0; order.forEach(function (k) { if (filterFn(rows[k])) n++; }); return n; }
    function updateSel() {
      var shown = filterFn ? (visibleCount() + ' shown / ') : '';
      if (!selectable) { selInfo.textContent = order.length ? (shown + order.length + ' row(s)') : ''; return; }
      selInfo.textContent = checked.size + ' selected / ' + shown + order.length + ' row(s)';
    }
    function updateEmpty() {
      // Show the placeholder only when there are no rows at all (loading spinner +
      // "loading" text) OR when a filter hid everything ("no rows matched").
      var hasRows = order.length > 0;
      var filteredToNothing = hasRows && filterFn && visibleCount() === 0;
      if (loading) {
        placeholder.style.display = ''; placeholder.classList.add('loading');
        phMsg.textContent = 'Loading…';
        return;
      }
      placeholder.classList.remove('loading');
      if (!hasRows) { placeholder.style.display = ''; phMsg.textContent = emptyText; }
      else if (filteredToNothing) { placeholder.style.display = ''; phMsg.textContent = 'No rows match the current filter.'; }
      else { placeholder.style.display = 'none'; }
    }
    function setLoading(on) { loading = !!on; updateEmpty(); }

    function upsert(row) {
      var k = keyOf(row);
      if (k == null) k = '_row' + order.length;
      if (!Object.prototype.hasOwnProperty.call(rows, k)) { rows[k] = {}; order.push(k); }
      Object.assign(rows[k], row);
      // sorted view => full repaint keeps order correct (coalesced to once/frame); unsorted => in-place upsert
      if (sort.key && sort.dir) scheduleRepaint(); else paintRow(k);
      if (loading) loading = false;   // first row cancels the loading state
      updateSel(); updateEmpty();
    }
    function clear() { rows = {}; order = []; trIndex = {}; checked.clear(); tbody.innerHTML = ''; updateSel(); updateEmpty(); }
    function selectAll(on) {
      // Respect the active filter: a hidden (filtered-out) row must never be
      // selected - otherwise "Select all" + a destructive action (e.g. WPT
      // Uninstall Checked while filtered to one app) would hit rows the operator
      // can't see. No filter set => selects every row, as before.
      checked.clear();
      if (on) order.forEach(function (k) { if (!filterFn || filterFn(rows[k])) checked.add(k); });
      tbody.querySelectorAll('tr').forEach(function (tr) { var sel = checked.has(tr.dataset.key); var cb = tr.querySelector('.j-rowcb'); if (cb) cb.checked = sel; tr.classList.toggle('sel', sel); });
      updateSel();
    }
    function selectWhere(fn) {
      // Same filter-safety as selectAll: only select rows that BOTH match fn and
      // pass the active filter (no-op vs the old behavior when no filter is set).
      checked.clear();
      order.forEach(function (k) { if ((!filterFn || filterFn(rows[k])) && fn(rows[k])) checked.add(k); });
      tbody.querySelectorAll('tr').forEach(function (tr) { var on = checked.has(tr.dataset.key); var cb = tr.querySelector('.j-rowcb'); if (cb) cb.checked = on; tr.classList.toggle('sel', on); });
      updateSel();
    }
    function getChecked(options) {
      // Filter-safe by DEFAULT (audit#19): drop rows the active quick-filter is
      // hiding so a destructive action can't hit rows the operator can't see -
      // matching selectAll/selectWhere. Pass { visibleOnly:false } to opt out and
      // get every checked row regardless of the filter (e.g. a bulk export).
      var visibleOnly = (!options || options.visibleOnly !== false) && !!filterFn;
      return Array.from(checked).filter(function (k) { return !visibleOnly || filterFn(rows[k]); }).map(function (k) { return rows[k]; });
    }

    function rowHost(row) {
      // A host-info Property/Value row is itself stamped with Host -> do NOT let it
      // re-trigger a host-info fetch (would re-query the WPT Host Info tab grid too).
      if ('Property' in row && 'Value' in row) return null;
      var km = opts.keyMode || {};
      if (km.hostCol && row[km.hostCol] != null && row[km.hostCol] !== '') return String(row[km.hostCol]);
      var cols = ['Host', 'Hostname', 'HostName', 'Computer', 'ComputerName'];
      for (var i = 0; i < cols.length; i++) { if (row[cols[i]] != null && row[cols[i]] !== '') return String(row[cols[i]]); }
      return null;
    }

    function openRowDetail(row) {
      var body = el('div');
      Object.keys(row).forEach(function (key) {
        if (key === 'type' || key === 'Tag' || key.charAt(0) === '_') return;
        var v = row[key]; v = (v === true) ? 'yes' : (v === false) ? 'no' : (v == null ? '' : String(v));
        var kv = el('div', 'j-kv'); kv.appendChild(el('div', 'j-kv-k', key)); kv.appendChild(el('div', 'j-kv-v', v)); body.appendChild(kv);
      });
      // Live Host Info enrichment: any grid row that resolves to a host streams a
      // read-only snapshot into the same panel (reuses Janet.hostInfo -> WPT host-info).
      var host = rowHost(row);
      if (host && window.Janet && typeof Janet.hostInfo === 'function') {
        var hd = el('div'); hd.style.cssText = 'margin-top:8px;border-top:1px solid var(--line);padding-top:6px';
        hd.appendChild(el('div', 'j-section-h', 'HOST INFO - ' + host)); body.appendChild(hd);
        var stat = el('div', 'muted', 'Loading live host info...'); stat.style.fontSize = '11.5px'; body.appendChild(stat);
        var got = 0;
        Janet.hostInfo(host, {
          status: function (t) { if (!got) stat.textContent = t; },
          row: function (r) {
            if (stat.parentNode) stat.remove();
            got++;
            var kv = el('div', 'j-kv'); kv.appendChild(el('div', 'j-kv-k', r.Property == null ? '' : String(r.Property))); kv.appendChild(el('div', 'j-kv-v', r.Value == null ? '' : String(r.Value))); body.appendChild(kv);
          },
          error: function (e) { stat.textContent = (e && e.text) || 'host info failed'; },
          done: function () { if (stat.parentNode && !got) stat.textContent = 'No host info (set credentials and start an admin session?).'; }
        });
      }
      var km = opts.keyMode || {};
      var title = (km.hostCol && row[km.hostCol]) ? String(row[km.hostCol]) : (host || opts.title || 'Detail');
      Janet.components.ConfirmDialog({ title: title, body: body, okText: 'Close', cancelText: null });
    }

    function popOut() {
      var w = window.open('', '_blank', 'width=900,height=600');
      if (!w) return;
      var d = w.document; d.title = (opts.title || 'JANET Web') + ' - results';
      // copy our stylesheet link so the grid keeps its look
      var link = d.createElement('link'); link.rel = 'stylesheet'; link.href = '/css/janet.css'; d.head.appendChild(link);
      d.body.style.cssText = 'margin:0;background:var(--bg);height:100vh;display:flex';
      var holder = d.createElement('div'); holder.style.cssText = 'flex:1;display:flex;flex-direction:column;padding:12px;min-height:0';
      d.body.appendChild(holder);
      holder.appendChild(scroll);   // re-parent the SAME node -> it keeps streaming
      w.addEventListener('beforeunload', function () { root.appendChild(scroll); });
    }

    return {
      el: root, upsert: upsert, clear: clear, setLoading: setLoading,
      rows: function () { return order.map(function (k) { return rows[k]; }); },
      order: function () { return order.slice(); },
      getChecked: getChecked, selectAll: selectAll, selectWhere: selectWhere,
      setFilter: function (fn) { filterFn = fn || null; order.forEach(function (k) { var tr = trIndex[k]; if (tr) tr.style.display = (filterFn && !filterFn(rows[k])) ? 'none' : ''; }); updateSel(); updateEmpty(); }
    };
  }
  Janet.components.ResultsGrid = ResultsGrid;
})();
