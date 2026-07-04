/* ============================================================================
   _stub.view.js  -  Phase 0b kit verification view (NOT a shipped tool).
   Composes every shared component against a run driven entirely by ctx.run()
   (-> RunController). Used with web/_devtest.html, which mocks window.fetch to
   script a status/row/log/progress/final job stream so the whole client
   pipeline renders a live run with no real engine.
   ========================================================================== */
(function () {
  'use strict';
  JanetViews.register('_stub', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;

      var wrap = el('div'); wrap.style.cssText = 'display:flex;gap:16px;height:100%;min-height:0;padding:16px;box-sizing:border-box';
      var left = ui.card({}); left.style.cssText += ';flex:0 0 340px;display:flex;flex-direction:column;gap:12px;min-height:0';
      var right = el('div'); right.style.cssText = 'flex:1;display:flex;flex-direction:column;gap:12px;min-height:0';
      wrap.appendChild(left); wrap.appendChild(right);

      // (credentials are universal - the shell header owns the single Set Credentials control)

      // targets (tool-owned model)
      left.appendChild(ui.sectionHeader('TARGETS'));
      var targets = C.TargetManager({
        model: ctx.util.targetModel('alpha01\nbravo02\ncharlie03\ndelta04'),
        pingAll: true,
        onPingAll: function () { log.banner('Ping All'); targets.hosts().forEach(function (h, i) { log.append({ text: '[' + h + '] ' + (i % 3 ? 'ONLINE' : 'OFFLINE / not pingable'), level: i % 3 ? 'ok' : 'err' }); }); log.banner('Ping complete'); },
        onImport: function (n, name) { log.append({ text: 'Imported ' + n + ' host(s) from ' + name, level: 'info' }); }
      });
      var tgWrap = el('div'); tgWrap.style.cssText = 'flex:1;min-height:120px;display:flex'; tgWrap.appendChild(targets.el);
      left.appendChild(tgWrap);

      // stats
      var stats = C.StatCards({ cards: [
        { key: 'ok', label: 'OK', color: 'ok' }, { key: 'fail', label: 'FAILED', color: 'bad' }, { key: 'total', label: 'TOTAL', color: 'accent' }
      ] });
      left.appendChild(stats.el);

      // progress + runbar
      var prog = C.ProgressStatusStrip({});
      left.appendChild(prog.el);

      var current = null;
      var runbar = C.RunBar({
        label: 'RUN DEMO', cancelLabel: 'CANCEL RUN', morphToCancel: true,
        guards: [function () { return targets.count() ? null : 'No targets - add hosts first.'; }],
        onGuardFail: function (m) { runbar.setStatus(m, 'st-warn'); },
        onRun: doRun, onCancel: function () { if (current) current.cancel(); }
      });
      left.appendChild(runbar.el);

      // grid + log
      var grid = C.ResultsGrid({
        title: 'Results', selectable: true, keyMode: { hostCol: 'Host' },
        columns: [
          { key: 'Host', label: 'Host' },
          { key: 'Status', label: 'Status', colorRule: function (v) { return v === 'OK' ? 'st-ok' : v === 'FAIL' ? 'st-bad' : 'st-warn'; } },
          { key: 'Detail', label: 'Detail' }
        ],
        rowClass: function (r) { return r.Status === 'OK' ? 'row-ok' : r.Status === 'FAIL' ? 'row-bad' : ''; }
      });
      var gridWrap = el('div'); gridWrap.style.cssText = 'flex:1;min-height:0;display:flex'; gridWrap.appendChild(grid.el);
      right.appendChild(gridWrap);

      var logCard = ui.card({}); logCard.style.cssText += ';flex:1;min-height:0;display:flex';
      var log = C.ActivityLog({ title: 'Activity Log', defaultName: 'KitTest_Log' });
      logCard.appendChild(log.el);
      right.appendChild(logCard);

      function recompute() {
        var rows = grid.rows(), ok = 0, fail = 0;
        rows.forEach(function (r) { if (r.Status === 'OK') ok++; else if (r.Status === 'FAIL') fail++; });
        stats.setAll({ ok: ok, fail: fail, total: rows.length });
      }

      async function doRun() {
        var hosts = targets.hosts();
        var ok = await ctx.confirm({
          title: 'Run demo on ' + hosts.length + ' host(s)?', danger: true,
          body: 'This is the kit verification run (mocked stream). Proceed?',
          list: hosts.slice(0, 5), okText: 'Run', cancelText: 'Cancel'
        });
        if (!ok) return;
        grid.clear(); log.clear(); stats.reset(); prog.reset();
        log.banner('Demo run on ' + hosts.length + ' target(s)');
        current = ctx.run('demo-run', { targets: hosts.join('\n'), count: hosts.length });
        current.subscribe({
          active: function (a) { runbar.setActive(a); if (!a) runbar.setStatus('Run complete.', 'st-ok'); },
          status: function (t) { prog.setPhase(t); },
          progress: function (p) { prog.setProgress(p.done, p.total); },
          row: function (r) { grid.upsert(r); recompute(); },
          log: function (l) { log.append(l); },
          final: function (res) { var s = (res && res.summary) || {}; log.banner('Done - ' + Object.keys(s).map(function (k) { return k + ': ' + s[k]; }).join(', ')); }
        });
      }

      host.appendChild(wrap);
      this._wrap = wrap;
    },
    unmount: function () { if (this._wrap) this._wrap.remove(); }
  });
})();
