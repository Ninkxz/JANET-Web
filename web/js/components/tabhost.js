/* ============================================================================
   TabHost  ->  Janet.components.TabHost
   Panel-swap navigation host covering every desktop nav style (hidden-header
   TabControl -> tab rail, sidebar panel-swap, mode-radio field-swap, single-
   card-stack). Each panel is BUILT LAZILY on first activation and then KEPT
   ALIVE: its DOM (grid / log / live run) survives switching away.

   instance = TabHost({
     rail:'left'|'top',
     tabs:[ { id, label, build(panelEl) } ]
   })
     .el  .select(id)
   ========================================================================== */
(function () {
  'use strict';
  var Janet = window.Janet = window.Janet || {};
  Janet.components = Janet.components || {};
  var el = Janet.ui.el;
  var hostSeq = 0;   // ids must be unique across every TabHost on the page

  function TabHost(opts) {
    opts = opts || {};
    var tabs = opts.tabs || [];
    var rail = opts.rail || 'left';
    var uid = 'j-th' + (++hostSeq);
    var root = el('div', 'j-tabhost rail-' + rail);
    var railEl = el('div', 'j-tabrail');
    var panelsEl = el('div', 'j-tabpanels');
    // ARIA tab pattern. The rail LOOKS like tabs and behaves like tabs, but was a bare
    // row of buttons: assistive tech announced "button 7 of 25" with no notion of a
    // selected tab or of which panel it drives, and Tab walked through all 25 before
    // reaching the panel content. Roles + roving tabindex + arrow keys below fix that
    // without changing a single class or the mouse behaviour. (audit 2026-07-24 P4)
    railEl.setAttribute('role', 'tablist');
    railEl.setAttribute('aria-orientation', rail === 'top' ? 'horizontal' : 'vertical');
    if (opts.ariaLabel) railEl.setAttribute('aria-label', opts.ariaLabel);
    if (!opts.external) root.appendChild(railEl);
    root.appendChild(panelsEl);

    var state = {};   // id -> { tab, btn, panel, built }
    var order = [];   // tab ids in rail order (arrow-key navigation)

    tabs.forEach(function (tab) {
      var btn = el('button', 'j-tab', tab.label);
      btn.type = 'button';
      btn.id = uid + '-tab-' + tab.id;
      btn.setAttribute('role', 'tab');
      btn.setAttribute('aria-selected', 'false');
      btn.setAttribute('aria-controls', uid + '-panel-' + tab.id);
      btn.tabIndex = -1;   // roving: only the active tab is in the Tab order
      btn.onclick = function () { select(tab.id); };
      btn.onkeydown = function (e) { onRailKey(e, tab.id); };
      railEl.appendChild(btn);
      var panel = el('div', 'j-tabpanel hidden');
      panel.id = uid + '-panel-' + tab.id;
      panel.setAttribute('role', opts.external ? 'region' : 'tabpanel');
      if (opts.external) panel.setAttribute('aria-label', tab.label);
      else panel.setAttribute('aria-labelledby', btn.id);
      panel.tabIndex = 0;   // the panel itself is the next Tab stop after its tab
      panelsEl.appendChild(panel);
      state[tab.id] = { tab: tab, btn: btn, panel: panel, built: false };
      order.push(tab.id);
    });

    // Arrow/Home/End move between tabs, as the tab pattern requires (the rail is ONE
    // Tab stop, not N). Selection follows focus, matching the click behaviour.
    function onRailKey(e, id) {
      var i = order.indexOf(id), n = order.length, j = -1;
      if (n < 2) return;
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') j = (i + 1) % n;
      else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') j = (i - 1 + n) % n;
      else if (e.key === 'Home') j = 0;
      else if (e.key === 'End') j = n - 1;
      if (j < 0) return;
      e.preventDefault();
      select(order[j]);
      try { state[order[j]].btn.focus(); } catch (err) {}
    }

    function select(id) {
      var s = state[id]; if (!s) return;
      if (!s.built) { try { if (s.tab.build) s.tab.build(s.panel); } catch (e) { s.panel.appendChild(el('div', 'st-bad', 'panel "' + id + '" failed: ' + (e && e.message))); } s.built = true; }
      // refresh the shell's "How to use" box for this tab (no-op for tools without per-tab help)
      if (!opts.external && opts.helpId && Janet.howtoTab) Janet.howtoTab(opts.helpId, id, s.tab.label);
      Object.keys(state).forEach(function (k) {
        var on = (k === id);
        state[k].panel.classList.toggle('hidden', !on);
        state[k].btn.classList.toggle('active', on);
        state[k].btn.setAttribute('aria-selected', on ? 'true' : 'false');
        state[k].btn.tabIndex = on ? 0 : -1;
      });
      if (opts.onSelect) opts.onSelect(id);
    }

    // open the command-palette's requested tab if it belongs to this host, else the first
    var requested = opts.external ? opts.initialTab : Janet._pendingTab;
    var initial = (requested && state[requested]) ? requested : (tabs[0] && tabs[0].id);
    if (!opts.external) Janet._pendingTab = null;
    if (initial) select(initial);

    return { el: root, select: select };
  }
  Janet.components.TabHost = TabHost;
})();
