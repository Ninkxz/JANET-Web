/* ============================================================================
   CommandPalette  ->  Janet.palette
   Ctrl+K / Cmd+K: a fuzzy jump-to overlay across every tool (and tab) so you
   don't hunt the sidebar. The shell registers the item provider in boot:
     Janet.palette.setProvider(function(){ return [{ label, sub, run }, ...]; });
   Arrow keys move, Enter runs, Esc/click-out closes.
   ========================================================================== */
(function () {
  'use strict';
  var Janet = window.Janet = window.Janet || {};
  var el = Janet.ui.el;

  var provider = function () { return []; };
  var openEl = null;

  function open() {
    if (openEl) return;
    var items = provider() || [];
    var overlay = el('div', 'j-modal j-palette-modal');
    var box = el('div', 'j-palette');
    var input = el('input', 'j-palette-input'); input.type = 'text';
    input.placeholder = 'Jump to a tool or tab…  (type to filter)';
    var list = el('div', 'j-palette-list');
    box.appendChild(input); box.appendChild(list); overlay.appendChild(box);
    document.body.appendChild(overlay); openEl = overlay;

    var filtered = items, sel = 0;
    function paintSel() {
      Array.prototype.forEach.call(list.children, function (c, i) { if (c.classList) c.classList.toggle('active', i === sel); });
      var act = list.children[sel]; if (act && act.scrollIntoView) act.scrollIntoView({ block: 'nearest' });
    }
    function render() {
      list.innerHTML = '';
      filtered.forEach(function (it, i) {
        var row = el('div', 'j-palette-row' + (i === sel ? ' active' : ''));
        row.appendChild(el('span', 'j-palette-l', it.label));
        if (it.sub) row.appendChild(el('span', 'j-palette-sub', it.sub));
        row.onmousedown = function (e) { e.preventDefault(); pick(i); };
        row.onmouseover = function () { sel = i; paintSel(); };
        list.appendChild(row);
      });
      if (!filtered.length) list.appendChild(el('div', 'j-palette-empty', 'No match'));
    }
    function applyFilter() {
      var q = input.value.trim().toLowerCase();
      filtered = !q ? items : items.filter(function (it) { return ((it.label || '') + ' ' + (it.sub || '')).toLowerCase().indexOf(q) >= 0; });
      sel = 0; render();
    }
    function pick(i) { var it = filtered[i]; close(); if (it && it.run) { try { it.run(); } catch (e) {} } }

    input.addEventListener('input', applyFilter);
    overlay.addEventListener('mousedown', function (e) { if (e.target === overlay) close(); });
    function onKey(e) {
      if (!openEl) return;
      if (e.key === 'Escape') { e.preventDefault(); close(); }
      else if (e.key === 'ArrowDown') { e.preventDefault(); if (filtered.length) { sel = (sel + 1) % filtered.length; paintSel(); } }
      else if (e.key === 'ArrowUp') { e.preventDefault(); if (filtered.length) { sel = (sel - 1 + filtered.length) % filtered.length; paintSel(); } }
      else if (e.key === 'Enter') { e.preventDefault(); pick(sel); }
    }
    document.addEventListener('keydown', onKey, true);
    openEl._onKey = onKey;
    render();
    setTimeout(function () { input.focus(); }, 0);
  }
  function close() { if (!openEl) return; document.removeEventListener('keydown', openEl._onKey, true); openEl.remove(); openEl = null; }

  Janet.palette = { setProvider: function (fn) { provider = fn || function () { return []; }; }, open: open, close: close };

  // ---- Keyboard shortcut cheatsheet (press ?) --------------------------------
  // The app is keyboard-driven but the shortcuts were invisible; ? makes them
  // discoverable. Lists the REAL shortcuts only (no phantom keys). Esc/click-out closes.
  var SHORTCUTS = [
    { keys: ['Ctrl', 'K'], desc: 'Open the command palette — jump to any tool or tab' },
    { keys: ['?'], desc: 'Show this shortcut cheatsheet' },
    { keys: ['Esc'], desc: 'Close the palette, a dialog, or this cheatsheet' },
    { keys: ['↑', '↓'], desc: 'Move the selection (in the command palette)' },
    { keys: ['Enter'], desc: 'Open the selected item / confirm a dialog' }
  ];
  var cheatEl = null;
  function closeCheat() { if (!cheatEl) return; document.removeEventListener('keydown', cheatEl._onKey, true); cheatEl.remove(); cheatEl = null; }
  function openCheat() {
    if (cheatEl) { closeCheat(); return; }
    if (openEl) close();
    var overlay = el('div', 'j-modal');
    var box = el('div', 'j-modal-card'); box.style.cssText = 'min-width:340px;max-width:440px';
    box.appendChild(el('div', 'j-modal-title', 'Keyboard Shortcuts'));
    var body = el('div', 'j-modal-body');
    var tbl = el('div'); tbl.style.cssText = 'display:flex;flex-direction:column;gap:6px;margin:4px 0';
    SHORTCUTS.forEach(function (s) {
      var rowEl = el('div'); rowEl.style.cssText = 'display:flex;align-items:center;gap:10px';
      var keyWrap = el('div'); keyWrap.style.cssText = 'display:flex;gap:4px;flex:none;min-width:96px';
      s.keys.forEach(function (k) { var kbd = el('kbd', 'j-kbd', k); keyWrap.appendChild(kbd); });
      rowEl.appendChild(keyWrap);
      var d = el('span', null, s.desc); d.style.cssText = 'font-size:12px;color:var(--text-dim,#c8c8d0)';
      rowEl.appendChild(d);
      tbl.appendChild(rowEl);
    });
    body.appendChild(tbl);
    box.appendChild(body);
    overlay.appendChild(box);
    overlay.addEventListener('mousedown', function (e) { if (e.target === overlay) closeCheat(); });
    document.body.appendChild(overlay); cheatEl = overlay;
    function onKey(e) { if (e.key === 'Escape' || e.key === '?') { e.preventDefault(); closeCheat(); } }
    document.addEventListener('keydown', onKey, true); cheatEl._onKey = onKey;
  }
  Janet.cheatsheet = { open: openCheat, close: closeCheat };

  // global hotkeys
  function isTyping(e) {
    var t = e.target; if (!t) return false;
    var tag = (t.tagName || '').toUpperCase();
    return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || t.isContentEditable;
  }
  document.addEventListener('keydown', function (e) {
    // Confirm/arming dialogs own focus until the operator answers.
    if (document.querySelector('.j-modal [aria-modal="true"]')) return;
    if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) { e.preventDefault(); if (openEl) close(); else open(); return; }
    // ? opens the cheatsheet, but never while typing into a field.
    if (e.key === '?' && !e.ctrlKey && !e.metaKey && !e.altKey && !isTyping(e)) { e.preventDefault(); openCheat(); }
  });
})();
