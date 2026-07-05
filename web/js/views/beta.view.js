/* ============================================================================
   beta.view.js  -  Beta Lab (tool id: 'beta')
   Staging ground for experimental JANET Web features (one tab per section).
   No sections are active right now: App Versions / Software Inventory graduated
   into Workstation Patching, and logged-on user / last boot / pending-reboot
   moved into the WPT Bulk Scan grid. When a new beta feature lands, restore the
   buildScanSection + TabHost pattern (in git history) and add its cfg + tab.
   ========================================================================== */
(function () {
  'use strict';

  JanetViews.register('beta', {
    mount: function (host, ctx) {
      var el = ctx.util.el;

      var wrap = el('div');
      wrap.style.cssText = 'height:100%;min-height:0;display:flex;align-items:center;justify-content:center;padding:32px;box-sizing:border-box';

      var card = el('div', 'j-card');
      card.style.cssText = 'max-width:580px;text-align:center;padding:28px 34px';

      var h = el('div'); h.textContent = 'Beta Lab';
      h.style.cssText = 'font-size:18px;font-weight:600;margin-bottom:12px';

      var p1 = el('div', 'muted'); p1.style.cssText = 'line-height:1.6;margin-bottom:12px';
      p1.innerHTML = 'No experimental features are active right now. Beta is the staging ground where new <b>read-only</b> fleet features bake before graduating into their own tool.';

      var p2 = el('div', 'muted'); p2.style.cssText = 'line-height:1.6;font-size:12.5px';
      p2.innerHTML = 'Recently graduated &rarr; <b>App Versions</b> + <b>Software Inventory</b> now live in Workstation Patching (Software Manager / App Updater); <b>logged-on user</b>, <b>last boot</b> and <b>pending-reboot</b> are in the WPT Bulk Scan grid.';

      card.appendChild(h); card.appendChild(p1); card.appendChild(p2);
      wrap.appendChild(card);
      host.appendChild(wrap);
      this._root = wrap;
    },
    unmount: function () { if (this._root) this._root.remove(); }
  });
})();
