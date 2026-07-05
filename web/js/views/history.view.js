/* ============================================================================
   history.view.js  -  Patch History / Audit Explorer (tool id: 'history')
   Read-only explorer over the audit trail JANET already writes (per-tool monthly
   detail CSVs, TouchedHosts attribution, and the fleet usage rollup on the central
   log share, with local-spool fallback when the share is down). Four tabs, each a
   compact controls row + StatCards + a ResultsGrid, all logging to one shared
   ActivityLog dock along the bottom (kev.view.js structure):
     1. Timeline   - every audit row mentioning one host, newest first.
     2. Activity   - all audit rows across tools within N days.
     3. Operators  - per-operator actions / successes / failures / sessions.
     4. Staleness  - pasted host list (TargetManager) -> FRESH / STALE / NEVER.
   Touches no hosts, needs no credentials. All server I/O via ctx.run.
   ========================================================================== */
(function () {
  'use strict';

  function resultCls(v) {
    var s = String(v == null ? '' : v).toLowerCase();
    if (s === 'success') return 'st-ok';
    if (s === 'failure') return 'st-bad';
    if (s === 'skipped') return 'st-warn';
    return '';
  }
  function verdictCls(v) {
    switch (String(v)) {
      case 'FRESH': return 'st-ok';
      case 'STALE': return 'st-warn';
      case 'NEVER TOUCHED': return 'st-bad';
      default: return '';
    }
  }
  function verdictRow(v) {
    switch (String(v)) {
      case 'FRESH': return 'row-ok';
      case 'STALE': return 'row-warn';
      case 'NEVER TOUCHED': return 'row-bad';
      default: return '';
    }
  }
  function intOr(node, dflt) {
    var n = parseInt(node && node.value, 10);
    if (isNaN(n) || n <= 0) return dflt;
    var max = node && parseInt(node.max, 10);       // honor the input's declared max (keyboard entry bypasses it)
    if (!isNaN(max) && max > 0 && n > max) n = max;
    return n;
  }
  // CSV formula-injection guard: desktop tools write unguarded Detail into shared CSVs
  // (Logging.ps1 diverges from Protect-JanetWebCsvField), so guard on export here.
  function csvGuard(v) {
    var s = String(v == null ? '' : v);
    return /^[=+\-@\t]/.test(s) ? ("'" + s) : s;
  }

  JanetViews.register('history', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;
      var subs = [];                 // every run-handle unsubscriber, torn down on unmount
      function track(u) { if (u) subs.push(u); }
      function ts() { return ctx.util.clockStr(); }

      // one shared activity dock; every tab logs here
      var actlog = C.ActivityLog({ title: 'ACTIVITY LOG', defaultName: 'PatchHistory_ActivityLog' });

      // Generic streaming binder. cfg: { action, params, grid, statusEl, label,
      // runbar, onReset(), onRow(row), onFinal(summary), track:bool }.
      function startRun(cfg) {
        cfg.grid.clear();
        if (cfg.onReset) cfg.onReset();
        setLine(cfg.statusEl, 'Working...', 'st-info');
        var run = ctx.run(cfg.action, cfg.params, { keyOf: function (ev) { return ev._rk; }, destructive: false });
        var unsub = run.subscribe({
          status: function (t) { setLine(cfg.statusEl, t, 'st-info'); },
          row: function (r) { cfg.grid.upsert(r); if (cfg.onRow) cfg.onRow(r); },
          log: function (l) { actlog.append(l); },
          error: function (e) { setLine(cfg.statusEl, (e && e.text) || 'Error', 'st-bad'); actlog.append({ text: (e && e.text) || 'error', level: 'err' }); },
          active: function (a) { if (cfg.runbar) { cfg.runbar.setActive(a); cfg.runbar.cta.textContent = a ? 'WORKING...' : cfg.label; } if (cfg.onActive) cfg.onActive(a); },
          final: function (res) { if (cfg.onFinal) cfg.onFinal((res && res.summary) || {}); }
        });
        track(unsub);
        return run;
      }
      function setLine(node, txt, cls) { if (!node) return; node.textContent = txt == null ? '' : String(txt); node.className = cls || 'muted'; }

      function exportGrid(grid, cols, fileBase) {
        var rows = grid.rows();
        if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Run a query first - there are no result rows yet.', okText: 'OK', cancelText: null }); return; }
        var keys = cols.map(function (c) { return c[0]; });
        var safeRows = rows.map(function (row) {
          var o = {};
          for (var i = 0; i < keys.length; i++) { o[keys[i]] = csvGuard(row[keys[i]]); }
          return o;
        });
        var csv = ctx.util.toCsv(cols.map(function (c) { return c[1]; }), safeRows, keys);
        ctx.util.downloadBlob(fileBase + '_' + ctx.util.fileStamp() + '.csv', 'text/csv', csv);
        actlog.append({ text: '[' + ts() + '] Exported ' + rows.length + ' row(s) to CSV.', level: 'info' });
      }

      // small labelled control on one row
      function ctrlRow(labelText, control) {
        var w = el('div'); w.style.cssText = 'display:flex;align-items:center;gap:8px';
        w.appendChild(ui.label(labelText)); w.appendChild(control); return w;
      }

      // =====================================================================
      //  TAB 1 - Timeline
      // =====================================================================
      function buildTimelineTab(panel) {
        panel.style.cssText = 'display:flex;flex-direction:column;gap:12px;height:100%;min-height:0;box-sizing:border-box;padding:12px';

        var ctrl = ui.card({}); ctrl.style.cssText += ';display:flex;align-items:center;gap:14px;flex-wrap:wrap';
        var hostIn = ui.input({ placeholder: 'host name (e.g. WS-0001)', title: 'The host whose audit history to build.' }); hostIn.style.width = '220px';
        var monthsIn = ui.number({ value: 6, min: 1, max: 24, title: 'How many months back to scan (1-24).' }); monthsIn.style.width = '70px';
        var statusLine = el('span', 'muted', 'Ready'); statusLine.style.cssText = 'min-width:160px;flex:1';
        var exportBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the timeline rows to CSV.' });
        var clearBtn = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the results grid.' });
        var ctaHolder = el('div'); ctaHolder.style.width = '210px';
        var runbar = C.RunBar({
          label: 'BUILD TIMELINE', morphToCancel: false, title: 'Every audit row that mentions this host, newest first.',
          guards: [ function () { return hostIn.value && hostIn.value.trim() ? null : 'Host Required|Enter a host name first.'; } ],
          onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
          onRun: doTimeline
        });
        ctaHolder.appendChild(runbar.el);
        ctrl.appendChild(ctrlRow('Host', hostIn));
        ctrl.appendChild(ctrlRow('Months', monthsIn));
        ctrl.appendChild(statusLine);
        ctrl.appendChild(exportBtn); ctrl.appendChild(clearBtn); ctrl.appendChild(ctaHolder);
        panel.appendChild(ctrl);

        var stats = C.StatCards({ cards: [
          { key: 'total', label: 'AUDIT ROWS', color: 'cyan' },
          { key: 'tools', label: 'TOOLS INVOLVED', color: 'accent' },
          { key: 'fails', label: 'FAILURES', color: 'bad' }
        ] });
        panel.appendChild(stats.el);

        var results = ui.namedCard('HOST TIMELINE', 'Every audit row (detail + TouchedHosts) mentioning the host, newest first.');
        results.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
        var grid = C.ResultsGrid({
          title: 'Host timeline', keyMode: { rk: true }, popOut: true, selectable: false,
          columns: [
            { key: 'Timestamp', label: 'TIMESTAMP', width: 150 },
            { key: 'Tool', label: 'TOOL', width: 130 },
            { key: 'Action', label: 'ACTION', width: 120 },
            { key: 'Result', label: 'RESULT', width: 90, render: function (r) { return { text: String(r.Result || ''), cls: resultCls(r.Result) }; } },
            { key: 'Operator', label: 'OPERATOR', width: 180 },
            { key: 'Detail', label: 'DETAIL', render: function (r) { var t = String(r.Detail == null ? '' : r.Detail); return { text: t, title: t }; } },
            { key: 'Source', label: 'SOURCE', width: 110, render: function (r) { return { text: String(r.Source || ''), cls: 'cell-dim' }; } }
          ]
        });
        var gh = el('div'); gh.style.cssText = 'flex:1;min-height:0;display:flex'; gh.appendChild(grid.el);
        results.appendChild(gh); panel.appendChild(results);

        var EXPORT = [['Timestamp', 'Timestamp'], ['Tool', 'Tool'], ['Action', 'Action'], ['Result', 'Result'], ['Operator', 'Operator'], ['Detail', 'Detail'], ['Source', 'Source']];
        exportBtn.onclick = function () { exportGrid(grid, EXPORT, 'PatchHistory_Timeline'); };
        clearBtn.onclick = function () { grid.clear(); stats.reset(); setLine(statusLine, 'Ready'); };

        var cTotal = 0, cFail = 0, cTools = {};
        function doTimeline() {
          startRun({
            action: 'host-timeline', label: 'BUILD TIMELINE', runbar: runbar, grid: grid, statusEl: statusLine,
            params: { host: hostIn.value.trim(), months: intOr(monthsIn, 6) },
            onReset: function () { stats.reset(); cTotal = 0; cFail = 0; cTools = {}; },
            onRow: function (r) {
              cTotal++; if (String(r.Result) === 'Failure') cFail++;
              if (r.Tool) cTools[String(r.Tool)] = 1;
              stats.setAll({ total: cTotal, tools: Object.keys(cTools).length, fails: cFail });
            },
            onFinal: function (s) {
              stats.setAll({ total: s.total || cTotal, tools: s.tools != null ? s.tools : Object.keys(cTools).length, fails: s.failures != null ? s.failures : cFail });
              var cap = s.capped ? ' (row cap hit)' : '';
              setLine(statusLine, 'Done - ' + (s.total || 0) + ' row(s) for ' + (s.host || '') + cap, (s.total ? 'st-ok' : 'st-warn'));
            }
          });
        }
      }

      // =====================================================================
      //  TAB 2 - Activity
      // =====================================================================
      function buildActivityTab(panel) {
        panel.style.cssText = 'display:flex;flex-direction:column;gap:12px;height:100%;min-height:0;box-sizing:border-box;padding:12px';

        var ctrl = ui.card({}); ctrl.style.cssText += ';display:flex;align-items:center;gap:14px;flex-wrap:wrap';
        var daysIn = ui.number({ value: 7, min: 1, max: 180, title: 'How many days back to include (1-180).' }); daysIn.style.width = '70px';
        var statusLine = el('span', 'muted', 'Ready'); statusLine.style.cssText = 'min-width:160px;flex:1';
        var exportBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the activity rows to CSV.' });
        var clearBtn = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the results grid.' });
        var ctaHolder = el('div'); ctaHolder.style.width = '210px';
        var runbar = C.RunBar({
          label: 'LOAD ACTIVITY', morphToCancel: false, title: 'All audit rows across every tool within the window.',
          guards: [], onRun: doActivity
        });
        ctaHolder.appendChild(runbar.el);
        ctrl.appendChild(ctrlRow('Days back', daysIn));
        ctrl.appendChild(statusLine);
        ctrl.appendChild(exportBtn); ctrl.appendChild(clearBtn); ctrl.appendChild(ctaHolder);
        panel.appendChild(ctrl);

        var stats = C.StatCards({ cards: [
          { key: 'total', label: 'AUDIT ROWS', color: 'cyan' },
          { key: 'fails', label: 'FAILURES', color: 'bad' },
          { key: 'ops', label: 'OPERATORS', color: 'accent' }
        ] });
        panel.appendChild(stats.el);

        var results = ui.namedCard('RECENT ACTIVITY', 'Every audit row across all tools inside the window, newest first.');
        results.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
        var grid = C.ResultsGrid({
          title: 'Recent activity', keyMode: { rk: true }, popOut: true, selectable: false,
          columns: [
            { key: 'Timestamp', label: 'TIMESTAMP', width: 150 },
            { key: 'Tool', label: 'TOOL', width: 130 },
            { key: 'Action', label: 'ACTION', width: 120 },
            { key: 'Target', label: 'TARGET', width: 150 },
            { key: 'Result', label: 'RESULT', width: 90, render: function (r) { return { text: String(r.Result || ''), cls: resultCls(r.Result) }; } },
            { key: 'Operator', label: 'OPERATOR', width: 180 },
            { key: 'Detail', label: 'DETAIL', render: function (r) { var t = String(r.Detail == null ? '' : r.Detail); return { text: t, title: t }; } }
          ]
        });
        var gh = el('div'); gh.style.cssText = 'flex:1;min-height:0;display:flex'; gh.appendChild(grid.el);
        results.appendChild(gh); panel.appendChild(results);

        var EXPORT = [['Timestamp', 'Timestamp'], ['Tool', 'Tool'], ['Action', 'Action'], ['Target', 'Target'], ['Result', 'Result'], ['Operator', 'Operator'], ['Detail', 'Detail']];
        exportBtn.onclick = function () { exportGrid(grid, EXPORT, 'PatchHistory_Activity'); };
        clearBtn.onclick = function () { grid.clear(); stats.reset(); setLine(statusLine, 'Ready'); };

        var cTotal = 0, cFail = 0, cOps = {};
        function doActivity() {
          startRun({
            action: 'recent-activity', label: 'LOAD ACTIVITY', runbar: runbar, grid: grid, statusEl: statusLine,
            params: { days: intOr(daysIn, 7) },
            onReset: function () { stats.reset(); cTotal = 0; cFail = 0; cOps = {}; },
            onRow: function (r) {
              cTotal++; if (String(r.Result) === 'Failure') cFail++;
              if (r.Operator) cOps[String(r.Operator)] = 1;
              stats.setAll({ total: cTotal, fails: cFail, ops: Object.keys(cOps).length });
            },
            onFinal: function (s) {
              stats.setAll({ total: s.total != null ? s.total : cTotal, fails: s.failures != null ? s.failures : cFail, ops: s.operators != null ? s.operators : Object.keys(cOps).length });
              var cap = s.capped ? ' (row cap hit)' : '';
              setLine(statusLine, 'Done - ' + (s.total || 0) + ' row(s), ' + (s.failPct || 0) + '% fail' + cap, (s.failures ? 'st-warn' : 'st-ok'));
            }
          });
        }
      }

      // =====================================================================
      //  TAB 3 - Operators
      // =====================================================================
      function buildOperatorTab(panel) {
        panel.style.cssText = 'display:flex;flex-direction:column;gap:12px;height:100%;min-height:0;box-sizing:border-box;padding:12px';

        var ctrl = ui.card({}); ctrl.style.cssText += ';display:flex;align-items:center;gap:14px;flex-wrap:wrap';
        var monthsIn = ui.number({ value: 3, min: 1, max: 24, title: 'How many months back to summarize (1-24).' }); monthsIn.style.width = '70px';
        var statusLine = el('span', 'muted', 'Ready'); statusLine.style.cssText = 'min-width:160px;flex:1';
        var exportBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the operator summary to CSV.' });
        var clearBtn = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the results grid.' });
        var ctaHolder = el('div'); ctaHolder.style.width = '210px';
        var runbar = C.RunBar({
          label: 'SUMMARIZE', morphToCancel: false, title: 'One row per operator over the window.',
          guards: [], onRun: doOps
        });
        ctaHolder.appendChild(runbar.el);
        ctrl.appendChild(ctrlRow('Months', monthsIn));
        ctrl.appendChild(statusLine);
        ctrl.appendChild(exportBtn); ctrl.appendChild(clearBtn); ctrl.appendChild(ctaHolder);
        panel.appendChild(ctrl);

        var stats = C.StatCards({ cards: [
          { key: 'ops', label: 'OPERATORS', color: 'cyan' },
          { key: 'actions', label: 'TOTAL ACTIONS', color: 'accent' },
          { key: 'fails', label: 'TOTAL FAILURES', color: 'bad' }
        ] });
        panel.appendChild(stats.el);

        var results = ui.namedCard('OPERATOR SUMMARY', 'Actions/successes/failures from detail rows; sessions + hosts touched from the usage rollup.');
        results.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
        var grid = C.ResultsGrid({
          title: 'Operator summary', keyMode: { rk: true }, popOut: true, selectable: false,
          columns: [
            { key: 'Operator', label: 'OPERATOR', width: 220 },
            { key: 'Sessions', label: 'SESSIONS', width: 90, type: 'text' },
            { key: 'Actions', label: 'ACTIONS', width: 90, type: 'text' },
            { key: 'Successes', label: 'SUCCESS', width: 90, render: function (r) { return { text: String(r.Successes == null ? '' : r.Successes), cls: 'st-ok' }; } },
            { key: 'Failures', label: 'FAILURES', width: 90, render: function (r) { var n = parseInt(r.Failures, 10) || 0; return { text: String(r.Failures == null ? '' : r.Failures), cls: n > 0 ? 'st-bad' : 'cell-dim' }; } },
            { key: 'HostsTouched', label: 'HOSTS', width: 90, type: 'text' },
            { key: 'LastActive', label: 'LAST ACTIVE', width: 150 }
          ]
        });
        var gh = el('div'); gh.style.cssText = 'flex:1;min-height:0;display:flex'; gh.appendChild(grid.el);
        results.appendChild(gh); panel.appendChild(results);

        var EXPORT = [['Operator', 'Operator'], ['Sessions', 'Sessions'], ['Actions', 'Actions'], ['Successes', 'Successes'], ['Failures', 'Failures'], ['HostsTouched', 'HostsTouched'], ['LastActive', 'LastActive']];
        exportBtn.onclick = function () { exportGrid(grid, EXPORT, 'PatchHistory_Operators'); };
        clearBtn.onclick = function () { grid.clear(); stats.reset(); setLine(statusLine, 'Ready'); };

        function doOps() {
          startRun({
            action: 'operator-summary', label: 'SUMMARIZE', runbar: runbar, grid: grid, statusEl: statusLine,
            params: { months: intOr(monthsIn, 3) },
            onReset: function () { stats.reset(); },
            onFinal: function (s) {
              stats.setAll({ ops: s.operators || 0, actions: s.actions || 0, fails: s.failures || 0 });
              setLine(statusLine, 'Done - ' + (s.operators || 0) + ' operator(s), ' + (s.actions || 0) + ' action(s)', (s.operators ? 'st-ok' : 'st-warn'));
            }
          });
        }
      }

      // =====================================================================
      //  TAB 4 - Staleness (TargetManager)
      // =====================================================================
      function buildStaleTab(panel) {
        panel.style.cssText = 'display:flex;gap:14px;height:100%;min-height:0;box-sizing:border-box;padding:12px';

        // LEFT: hosts + thresholds + run
        var left = el('div'); left.style.cssText = 'flex:0 0 380px;display:flex;flex-direction:column;gap:12px;min-height:0';
        var compCard = ui.namedCard('HOSTS', 'One host per line - comma/space/semicolon ok; # starts a comment.');
        compCard.style.cssText += ';flex:0 0 auto;min-height:160px;max-height:320px;display:flex;flex-direction:column;overflow:hidden';
        var targets = C.TargetManager({
          model: ctx.util.targetModel(''),
          hint: 'One host per line - comma/space/semicolon ok; # starts a comment.',
          placeholder: 'WS-0001\nWS-0002\n# lab row\nWS-0003',
          importLabel: 'Import TXT', importAccept: '.txt', countNoun: 'host',
          onImport: function (n, name) { actlog.append({ text: '[' + ts() + '] Added ' + n + ' host(s) from ' + name, level: 'info' }); }
        });
        var tgHolder = el('div'); tgHolder.style.cssText = 'flex:1;min-height:0;display:flex'; tgHolder.appendChild(targets.el);
        compCard.appendChild(tgHolder);
        left.appendChild(compCard);

        var optCard = ui.card({}); optCard.style.cssText += ';display:flex;flex-direction:column;gap:10px';
        var thrIn = ui.number({ value: 30, min: 1, max: 3650, title: 'A host not touched within this many days is STALE.' }); thrIn.style.width = '90px';
        var lookIn = ui.number({ value: 12, min: 1, max: 24, title: 'How far back to search for the last touch (months).' }); lookIn.style.width = '90px';
        optCard.appendChild(ctrlRow('Stale threshold (days)', thrIn));
        optCard.appendChild(ctrlRow('Lookback (months)', lookIn));
        var statusLine = el('div', 'muted', 'Ready'); statusLine.style.fontSize = '12px';
        optCard.appendChild(statusLine);
        left.appendChild(optCard);

        var actCard = ui.card({}); actCard.style.cssText += ';display:flex;flex-direction:column;gap:8px';
        var runbar = C.RunBar({
          label: 'CHECK STALENESS', morphToCancel: false, title: 'Last-touched date + FRESH/STALE/NEVER verdict per host.',
          guards: [ function () { return targets.count() ? null : 'No Hosts|Add at least one host to the list first.'; } ],
          onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
          onRun: doStale
        });
        var rbWrap = el('div'); rbWrap.appendChild(runbar.el); actCard.appendChild(rbWrap);
        left.appendChild(actCard);
        panel.appendChild(left);

        // RIGHT: stats + grid
        var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:12px;min-height:0';
        var stats = C.StatCards({ cards: [
          { key: 'total', label: 'HOSTS', color: 'cyan' },
          { key: 'fresh', label: 'FRESH', color: 'ok' },
          { key: 'stale', label: 'STALE', color: 'gold' },
          { key: 'never', label: 'NEVER TOUCHED', color: 'bad' }
        ] });
        right.appendChild(stats.el);

        var head = ui.card({}); head.style.cssText += ';display:flex;align-items:center;gap:12px;flex-wrap:wrap';
        var exportBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the staleness rows to CSV.' });
        var clearBtn = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the results grid.' });
        var spacer = el('div'); spacer.style.flex = '1'; head.appendChild(spacer);
        head.appendChild(exportBtn); head.appendChild(clearBtn);
        right.appendChild(head);

        var results = ui.namedCard('STALENESS BOARD', 'FRESH within threshold; STALE if the last touch is older; NEVER TOUCHED if no audit row inside the lookback window.');
        results.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
        var grid = C.ResultsGrid({
          title: 'Staleness board', keyMode: { rk: true }, popOut: true, selectable: false,
          columns: [
            { key: 'Host', label: 'HOST', width: 160 },
            { key: 'LastTouched', label: 'LAST TOUCHED', width: 150 },
            { key: 'DaysAgo', label: 'DAYS AGO', width: 90, type: 'text' },
            { key: 'LastTool', label: 'LAST TOOL', width: 130 },
            { key: 'LastOperator', label: 'LAST OPERATOR', width: 180 },
            { key: 'Verdict', label: 'VERDICT', width: 140, render: function (r) { return { text: String(r.Verdict || ''), cls: verdictCls(r.Verdict) }; } }
          ],
          rowClass: function (r) { return verdictRow(r.Verdict); }
        });
        var gh = el('div'); gh.style.cssText = 'flex:1;min-height:0;display:flex'; gh.appendChild(grid.el);
        results.appendChild(gh); right.appendChild(results);
        panel.appendChild(right);

        var EXPORT = [['Host', 'Host'], ['LastTouched', 'LastTouched'], ['DaysAgo', 'DaysAgo'], ['LastTool', 'LastTool'], ['LastOperator', 'LastOperator'], ['Verdict', 'Verdict']];
        exportBtn.onclick = function () { exportGrid(grid, EXPORT, 'PatchHistory_Staleness'); };
        clearBtn.onclick = function () { grid.clear(); stats.reset(); setLine(statusLine, 'Ready'); };

        var cFresh = 0, cStale = 0, cNever = 0, cTotal = 0;
        function doStale() {
          startRun({
            action: 'stale-hosts', label: 'CHECK STALENESS', runbar: runbar, grid: grid, statusEl: statusLine,
            params: { targets: targets.hosts().join('\n'), thresholdDays: intOr(thrIn, 30), lookbackMonths: intOr(lookIn, 12) },
            onReset: function () { stats.reset(); cFresh = 0; cStale = 0; cNever = 0; cTotal = 0; },
            onRow: function (r) {
              cTotal++;
              if (r.Verdict === 'FRESH') cFresh++;
              else if (r.Verdict === 'STALE') cStale++;
              else if (r.Verdict === 'NEVER TOUCHED') cNever++;
              stats.setAll({ total: cTotal, fresh: cFresh, stale: cStale, never: cNever });
            },
            onFinal: function (s) {
              stats.setAll({ total: s.total != null ? s.total : cTotal, fresh: s.fresh != null ? s.fresh : cFresh, stale: s.stale != null ? s.stale : cStale, never: s.never != null ? s.never : cNever });
              var bad = (s.stale || 0) + (s.never || 0);
              setLine(statusLine, 'Done - Fresh ' + (s.fresh || 0) + ' / Stale ' + (s.stale || 0) + ' / Never ' + (s.never || 0), bad ? 'st-warn' : 'st-ok');
            }
          });
        }
      }

      // ---- assemble: TabHost + bottom activity dock ----------------------------
      var root = el('div'); root.style.cssText = 'display:flex;flex-direction:column;gap:12px;height:100%;min-height:0;padding:14px;box-sizing:border-box';
      var tabHolder = el('div'); tabHolder.style.cssText = 'flex:1;min-height:0;display:flex';
      var tabs = C.TabHost({
        rail: 'top',
        helpId: 'history',
        tabs: [
          { id: 'timeline', label: 'Timeline', build: buildTimelineTab },
          { id: 'activity', label: 'Activity', build: buildActivityTab },
          { id: 'operators', label: 'Operators', build: buildOperatorTab },
          { id: 'stale', label: 'Staleness', build: buildStaleTab }
        ]
      });
      tabHolder.appendChild(tabs.el);
      root.appendChild(tabHolder);

      var logCard = ui.card({}); logCard.classList.add('j-logdock');
      logCard.appendChild(actlog.el);
      root.appendChild(logCard);

      actlog.append({ text: 'Patch History ready. Read-only explorer over the audit trail JANET already writes - no hosts touched, no credentials needed.', level: 'accent' });

      host.appendChild(root);
      this._root = root;
      this._unsub = function () { subs.forEach(function (u) { try { u(); } catch (e) {} }); };
    },
    unmount: function () { try { if (this._unsub) this._unsub(); } catch (e) {} if (this._root) this._root.remove(); }
  });
})();
