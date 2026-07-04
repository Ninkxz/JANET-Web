/* ============================================================================
   RunBar  ->  Janet.components.RunBar
   The per-tool command bar: a primary CTA (disable-on-launch, re-enable-on-
   final, optional morph-to-Cancel) and pre-flight guards (no targets / no creds
   / nothing selected) run before the action fires.

   instance = RunBar({
       label:'SEND', cancelLabel:'CANCEL', morphToCancel:true,
       guards:[ ()=> hosts.length ? null : 'No targets' , ... ],   // return msg to block
       onRun(), onCancel(), onGuardFail(msg)
   })
     .el  .cta  .setActive(bool)  .setStatus(txt[,cls])
   ========================================================================== */
(function () {
  'use strict';
  var Janet = window.Janet = window.Janet || {};
  Janet.components = Janet.components || {};
  var el = Janet.ui.el;

  function RunBar(opts) {
    opts = opts || {};
    var root = el('div', 'j-runbar');
    var active = false;
    var label = opts.label || 'Run';
    var cancelLabel = opts.cancelLabel || 'Cancel';

    var cta = Janet.ui.ctaButton(label, { title: opts.title });

    function runGuards() {
      var guards = opts.guards || [];
      for (var i = 0; i < guards.length; i++) {
        var msg = null; try { msg = guards[i](); } catch (e) { msg = null; }
        if (msg) return msg;
      }
      return null;
    }
    cta.addEventListener('click', function () {
      if (active) { if (opts.onCancel) opts.onCancel(); return; }
      var block = runGuards();
      if (block) { if (opts.onGuardFail) opts.onGuardFail(block); return; }
      if (opts.onRun) opts.onRun();
    });

    var status = el('span', 'muted');
    status.style.marginLeft = '2px';

    var topRow = el('div'); topRow.style.display = 'flex'; topRow.style.flexDirection = 'column'; topRow.style.gap = 'var(--s2)';
    topRow.appendChild(cta);
    topRow.appendChild(status);
    root.appendChild(topRow);

    function setActive(on) {
      active = !!on;
      if (opts.morphToCancel) {
        cta.classList.toggle('is-cancel', active);
        cta.textContent = active ? cancelLabel : label;
        cta.disabled = false;   // stays clickable to cancel
      } else {
        cta.textContent = label;
        cta.disabled = active;
      }
    }
    function setStatus(txt, cls) { status.textContent = txt == null ? '' : String(txt); status.className = cls || 'muted'; }
    return { el: root, cta: cta, setActive: setActive, setStatus: setStatus };
  }
  Janet.components.RunBar = RunBar;
})();
