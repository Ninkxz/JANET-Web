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

  // Compact duration: 45s, 2m14s, 1h03m.
  function fmtDur(sec) {
    sec = Math.max(0, Math.round(sec));
    if (sec < 60) return sec + 's';
    if (sec < 3600) { var m = Math.floor(sec / 60), s = sec % 60; return m + 'm' + (s < 10 ? '0' : '') + s + 's'; }
    var h = Math.floor(sec / 3600), mm = Math.floor((sec % 3600) / 60); return h + 'h' + (mm < 10 ? '0' : '') + mm + 'm';
  }

  function ProgressStatusStrip(opts) {
    opts = opts || {};
    var root = el('div', 'j-prog');
    var count = (opts.showCount !== false) ? el('span', 'j-prog-count', '0 / 0') : null;
    var track = null, fill = null;
    if (opts.showBar !== false) {
      track = el('div', 'j-prog-track'); fill = el('div', 'j-prog-fill'); track.appendChild(fill);
    }
    // Live elapsed / throughput / ETA readout (audit improvement: a 1,900-host scan
    // otherwise shows only "X / N" with no sense of pace). Shown once the run starts.
    var eta = (opts.showEta !== false) ? el('span', 'j-prog-eta', '') : null;
    var phase = el('span', 'j-prog-phase', opts.phase || '');
    if (count) root.appendChild(count);
    if (track) root.appendChild(track);
    if (eta) root.appendChild(eta);
    root.appendChild(phase);

    var startMs = 0;   // set on the first progress tick with done>0

    function setProgress(done, total) {
      done = done || 0; total = total || 0;
      var pct = total ? Math.round(100 * done / total) : 0;
      var complete = (total > 0 && done >= total);
      if (count) { count.textContent = done + ' / ' + total; count.classList.toggle('done', complete); }
      if (fill) { fill.style.width = pct + '%'; fill.classList.toggle('done', complete); }
      if (eta) {
        var now = (window.performance && performance.now) ? performance.now() : Date.now();
        if (done > 0 && startMs === 0) startMs = now;   // clock starts at first real progress
        if (startMs === 0) { eta.textContent = ''; }
        else {
          var elapsedS = (now - startMs) / 1000;
          if (complete) {
            eta.textContent = 'done in ' + fmtDur(elapsedS);
            eta.classList.add('done');
          } else {
            var rate = elapsedS > 0 ? (done / elapsedS) : 0;   // items/sec
            var parts = [fmtDur(elapsedS)];
            if (rate > 0) parts.push((rate >= 10 ? Math.round(rate) : rate.toFixed(1)) + '/s');
            if (rate > 0 && total > done) parts.push('~' + fmtDur((total - done) / rate) + ' left');
            eta.textContent = parts.join(' · ');
            eta.classList.remove('done');
          }
        }
      }
    }
    function setPhase(text) { phase.textContent = text == null ? '' : String(text); }
    function reset() {
      startMs = 0;
      setProgress(0, 0);
      if (fill) fill.classList.remove('done');
      if (count) count.classList.remove('done');
      if (eta) { eta.textContent = ''; eta.classList.remove('done'); }
      setPhase(opts.phase || '');
    }
    return { el: root, setProgress: setProgress, setPhase: setPhase, reset: reset };
  }
  Janet.components.ProgressStatusStrip = ProgressStatusStrip;
})();
