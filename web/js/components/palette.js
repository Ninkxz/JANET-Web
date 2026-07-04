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

  // global hotkey
  document.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) { e.preventDefault(); if (openEl) close(); else open(); }
  });
})();
