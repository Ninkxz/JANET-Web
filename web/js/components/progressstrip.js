/* ============================================================================
   ProgressStatusStrip  ->  Janet.components.ProgressStatusStrip
   The progress signal: an "X / N" count label that turns green on completion
   (the canonical JANET indicator) + a thin custom-fill bar (Value/Maximum) +
   an optional phase label. Drive it straight from the run stream:
     run.subscribe({ progress: p => strip.setProgress(p.done, p.total),
                     status:   t => strip.setPhase(t) })

   instance = ProgressStatusStrip({ showBar:true, showCount:true })
     .el
     .setProgress(done, total)    update count + bar; greens out when done>=total>0
     .setPhase(text)              phase / status line
     .reset()
   ========================================================================== */
(function () {
  'use strict';
  var Janet = window.Janet = window.Janet || {};
  Janet.components = Janet.components || {};
  var el = Janet.ui.el;

  function ProgressStatusStrip(opts) {
    opts = opts || {};
    var root = el('div', 'j-prog');
    var count = (opts.showCount !== false) ? el('span', 'j-prog-count', '0 / 0') : null;
    var track = null, fill = null;
    if (opts.showBar !== false) {
      track = el('div', 'j-prog-track'); fill = el('div', 'j-prog-fill'); track.appendChild(fill);
    }
    var phase = el('span', 'j-prog-phase', opts.phase || '');
    if (count) root.appendChild(count);
    if (track) root.appendChild(track);
    root.appendChild(phase);

    function setProgress(done, total) {
      done = done || 0; total = total || 0;
      var pct = total ? Math.round(100 * done / total) : 0;
      var complete = (total > 0 && done >= total);
      if (count) { count.textContent = done + ' / ' + total; count.classList.toggle('done', complete); }
      if (fill) { fill.style.width = pct + '%'; fill.classList.toggle('done', complete); }
    }
    function setPhase(text) { phase.textContent = text == null ? '' : String(text); }
    function reset() { setProgress(0, 0); if (fill) fill.classList.remove('done'); if (count) count.classList.remove('done'); setPhase(opts.phase || ''); }
    return { el: root, setProgress: setProgress, setPhase: setPhase, reset: reset };
  }
  Janet.components.ProgressStatusStrip = ProgressStatusStrip;
})();
