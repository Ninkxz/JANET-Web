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

  function TabHost(opts) {
    opts = opts || {};
    var tabs = opts.tabs || [];
    var rail = opts.rail || 'left';
    var root = el('div', 'j-tabhost rail-' + rail);
    var railEl = el('div', 'j-tabrail');
    var panelsEl = el('div', 'j-tabpanels');
    root.appendChild(railEl); root.appendChild(panelsEl);

    var state = {};   // id -> { tab, btn, panel, built }

    tabs.forEach(function (tab) {
      var btn = el('button', 'j-tab', tab.label);
      btn.onclick = function () { select(tab.id); };
      railEl.appendChild(btn);
      var panel = el('div', 'j-tabpanel hidden');
      panelsEl.appendChild(panel);
      state[tab.id] = { tab: tab, btn: btn, panel: panel, built: false };
    });

    function select(id) {
      var s = state[id]; if (!s) return;
      if (!s.built) { try { if (s.tab.build) s.tab.build(s.panel); } catch (e) { s.panel.appendChild(el('div', 'st-bad', 'panel "' + id + '" failed: ' + (e && e.message))); } s.built = true; }
      // refresh the shell's "How to use" box for this tab (no-op for tools without per-tab help)
      if (opts.helpId && Janet.howtoTab) Janet.howtoTab(opts.helpId, id, s.tab.label);
      Object.keys(state).forEach(function (k) {
        var on = (k === id);
        state[k].panel.classList.toggle('hidden', !on);
        state[k].btn.classList.toggle('active', on);
      });
    }

    // open the command-palette's requested tab if it belongs to this host, else the first
    var initial = (Janet._pendingTab && state[Janet._pendingTab]) ? Janet._pendingTab : (tabs[0] && tabs[0].id);
    Janet._pendingTab = null;
    if (initial) select(initial);

    return { el: root, select: select };
  }
  Janet.components.TabHost = TabHost;
})();
