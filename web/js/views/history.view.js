/* ============================================================================
   history.view.js  -  Patch History / Audit Explorer (tool id: 'history')
   Read-only explorer over the audit trail JANET already writes (per-tool monthly
   detail CSVs, TouchedHosts attribution, and the fleet usage rollup on the central
   log share, with local-spool fallback when the share is down). Six tabs, each a
   compact controls row + StatCards + a ResultsGrid, all logging to one shared
   ActivityLog dock along the bottom (kev.view.js structure):
     1. Timeline     - every audit row mentioning one host, newest first.
     2. Activity     - all audit rows across tools within N days.
     3. Operators    - per-operator actions / successes / failures / sessions.
     4. Staleness    - pasted host list (TargetManager) -> FRESH / STALE / NEVER.
     5. Run Outcomes - the daily per-run cards grouped by action/profile/mode
                       (audit 2026-07-25 #7; group cards are counted ONCE server-side).
     6. Coverage     - the AD computer population x the audit trail -> COVERED /
                       STALE (live) / NEVER TOUCHED (live) / GHOST / DEAD OBJECT
                       (audit 2026-07-25 #8; UNKNOWN is never a pass).
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
  // audit 2026-07-24: the server also emits UNKNOWN verdicts ('UNKNOWN (capped)' when
  // the read ceiling tripped, 'UNKNOWN (read error)' when the audit source could not be
  // read). Both fell through to the default here - no colour at all - so the cell that
  // means "we could not tell" rendered exactly like plain text and read as benign.
  // Match on the prefix so any future UNKNOWN variant is still coloured.
  function isUnknownVerdict(v) { return String(v == null ? '' : v).indexOf('UNKNOWN') === 0; }
  function verdictCls(v) {
    if (isUnknownVerdict(v)) return 'st-warn';
    switch (String(v)) {
      case 'FRESH': return 'st-ok';
      case 'STALE': return 'st-warn';
      case 'NEVER TOUCHED': return 'st-bad';
      default: return '';
    }
  }
  function verdictRow(v) {
    if (isUnknownVerdict(v)) return 'row-warn';
    switch (String(v)) {
      case 'FRESH': return 'row-ok';
      case 'STALE': return 'row-warn';
      case 'NEVER TOUCHED': return 'row-bad';
      default: return '';
    }
  }
  // Coverage board verdicts (audit 2026-07-25 #8). Same rule as the staleness board:
  // an UNKNOWN prefix is coloured as a warning, never left as plain text - the cell
  // that means "we could not tell" must not render like a benign result. COVERED is
  // the ONLY green here; DEAD OBJECT is dimmed rather than red because it is expected
  // housekeeping, while GHOST (JANET touched a machine AD says is dead) is not.
  function covVerdictCls(v) {
    if (isUnknownVerdict(v)) return 'st-warn';
    switch (String(v)) {
      case 'COVERED': return 'st-ok';
      case 'STALE (live)': return 'st-warn';
      case 'NEVER TOUCHED (live)': return 'st-bad';
      case 'GHOST': return 'st-bad';
      case 'DEAD OBJECT': return 'cell-dim';
      default: return '';
    }
  }
  function covVerdictRow(v) {
    if (isUnknownVerdict(v)) return 'row-warn';
    switch (String(v)) {
      case 'COVERED': return 'row-ok';
      case 'STALE (live)': return 'row-warn';
      case 'NEVER TOUCHED (live)': return 'row-bad';
      case 'GHOST': return 'row-bad';
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
      var runUnsubs = {};   // action -> live unsub; a re-run must replace, not stack, its handler (audit 2026-07-23 deferred pass)
      function startRun(cfg) {
        cfg.grid.clear();
        if (cfg.onReset) cfg.onReset();
        setLine(cfg.statusEl, 'Working...', 'st-info');
        var run = ctx.run(cfg.action, cfg.params, { keyOf: function (ev) { return ev._rk; }, destructive: false });
        var prev = runUnsubs[cfg.action];
        if (prev) { var pi = subs.indexOf(prev); if (pi >= 0) subs.splice(pi, 1); prev(); }
        var unsub = run.subscribe({
          status: function (t) { setLine(cfg.statusEl, t, 'st-info'); },
          row: function (r) { cfg.grid.upsert(r); if (cfg.onRow) cfg.onRow(r); },
          log: function (l) { actlog.append(l); },
          error: function (e) { setLine(cfg.statusEl, (e && e.text) || 'Error', 'st-bad'); actlog.append({ text: (e && e.text) || 'error', level: 'err' }); },
          // A morph-to-Cancel RunBar owns its own label (setActive swaps it to the
          // cancel text); overwriting it with 'WORKING...' would hide the Cancel
          // affordance on the one long read here that can actually be cancelled.
          active: function (a) { if (cfg.runbar) { cfg.runbar.setActive(a); if (!cfg.morphToCancel) { cfg.runbar.cta.textContent = a ? 'WORKING...' : cfg.label; } } if (cfg.onActive) cfg.onActive(a); },
          final: function (res) { if (cfg.onFinal) cfg.onFinal((res && res.summary) || {}); }
        });
        runUnsubs[cfg.action] = unsub;
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
        ctx.util.exportCsv(fileBase, cols, safeRows);
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
              // audit 2026-07-24: a zero-row timeline over a source that failed to read is
              // UNKNOWN, not a clean "this host has no history" - never let it read as ok.
              var cap = (s.capped ? ' (row cap hit)' : '') + (s.readFailed ? ' (READ ERRORS - incomplete)' : '');
              setLine(statusLine, 'Done - ' + (s.total || 0) + ' row(s) for ' + (s.host || '') + cap, s.readFailed ? 'st-bad' : (s.total ? 'st-ok' : 'st-warn'));
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
              var cap = (s.capped ? ' (row cap hit)' : '') + (s.readFailed ? ' (READ ERRORS - incomplete)' : '');   // audit 2026-07-24
              setLine(statusLine, 'Done - ' + (s.total || 0) + ' row(s), ' + (s.failPct || 0) + '% fail' + cap, s.readFailed ? 'st-bad' : (s.failures ? 'st-warn' : 'st-ok'));
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
              setLine(statusLine, 'Done - ' + (s.operators || 0) + ' operator(s), ' + (s.actions || 0) + ' action(s)' + (s.readFailed ? ' (READ ERRORS - incomplete)' : ''), s.readFailed ? 'st-bad' : (s.operators ? 'st-ok' : 'st-warn'));   // audit 2026-07-24
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
        var left = el('div'); left.style.cssText = 'flex:0 0 380px;display:flex;flex-direction:column;gap:12px;min-height:0;overflow:auto';
        var compCard = ui.namedCard('HOSTS');   // hint comes from the TargetManager below
        compCard.style.cssText += ';flex:0 0 auto;display:flex;flex-direction:column';
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
          { key: 'never', label: 'NEVER TOUCHED', color: 'bad' },
          // audit 2026-07-24: UNKNOWN had no tile, so a run where EVERY host came back
          // UNKNOWN showed four zero/near-zero tiles and looked like a clean sweep.
          { key: 'unknown', label: 'UNKNOWN', color: 'accent' }
        ] });
        right.appendChild(stats.el);

        var head = ui.card({}); head.style.cssText += ';display:flex;align-items:center;gap:12px;flex-wrap:wrap';
        var exportBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the staleness rows to CSV.' });
        var clearBtn = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the results grid.' });
        var spacer = el('div'); spacer.style.flex = '1'; head.appendChild(spacer);
        head.appendChild(exportBtn); head.appendChild(clearBtn);
        right.appendChild(head);

        var results = ui.namedCard('STALENESS BOARD', 'FRESH within threshold; STALE if the last touch is older; NEVER TOUCHED if no audit row inside the lookback window; UNKNOWN when the read was capped or the audit source could not be read - UNKNOWN is not a pass.');
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

        var cFresh = 0, cStale = 0, cNever = 0, cUnknown = 0, cTotal = 0;
        function doStale() {
          startRun({
            action: 'stale-hosts', label: 'CHECK STALENESS', runbar: runbar, grid: grid, statusEl: statusLine,
            params: { targets: targets.hosts().join('\n'), thresholdDays: intOr(thrIn, 30), lookbackMonths: intOr(lookIn, 12) },
            onReset: function () { stats.reset(); cFresh = 0; cStale = 0; cNever = 0; cUnknown = 0; cTotal = 0; },
            onRow: function (r) {
              cTotal++;
              if (r.Verdict === 'FRESH') cFresh++;
              else if (r.Verdict === 'STALE') cStale++;
              else if (r.Verdict === 'NEVER TOUCHED') cNever++;
              else if (isUnknownVerdict(r.Verdict)) cUnknown++;
              stats.setAll({ total: cTotal, fresh: cFresh, stale: cStale, never: cNever, unknown: cUnknown });
            },
            onFinal: function (s) {
              var unk = s.unknown != null ? s.unknown : cUnknown;
              stats.setAll({ total: s.total != null ? s.total : cTotal, fresh: s.fresh != null ? s.fresh : cFresh, stale: s.stale != null ? s.stale : cStale, never: s.never != null ? s.never : cNever, unknown: unk });
              // audit 2026-07-24: a fully-capped (or unreadable-source) run has stale=0
              // and never=0, so the old bad-count made the line GREEN on a run that
              // established nothing at all. UNKNOWN is not a pass - show it, and never
              // go green while any host is unresolved or the source failed to read.
              var bad = (s.stale || 0) + (s.never || 0);
              var txt = 'Done - Fresh ' + (s.fresh || 0) + ' / Stale ' + (s.stale || 0) + ' / Never ' + (s.never || 0) + ' / Unknown ' + unk;
              if (s.readErrors) txt += ' (' + s.readErrors + ' read error(s))';
              setLine(statusLine, txt, s.readFailed ? 'st-bad' : ((bad || unk) ? 'st-warn' : 'st-ok'));
            }
          });
        }
      }

      // =====================================================================
      //  TAB 5 - Run Outcomes (audit 2026-07-25 #7)
      //  Reads the daily per-run cards the logging bridge has always written and
      //  nothing has ever read. The server de-dupes rolled-up group cards (one row
      //  per member, shared counters) before aggregating, so the numbers here are
      //  per CARD, not per member row.
      // =====================================================================
      function buildRunsTab(panel) {
        panel.style.cssText = 'display:flex;flex-direction:column;gap:12px;height:100%;min-height:0;box-sizing:border-box;padding:12px';

        var ctrl = ui.card({}); ctrl.style.cssText += ';display:flex;align-items:center;gap:14px;flex-wrap:wrap';
        var daysIn = ui.number({ value: 30, min: 1, max: 365, title: 'How many days of run cards to include (1-365).' }); daysIn.style.width = '80px';
        var statusLine = el('span', 'muted', 'Ready'); statusLine.style.cssText = 'min-width:160px;flex:1';
        var exportBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the run-outcome rows to CSV.' });
        var clearBtn = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the results grid.' });
        var ctaHolder = el('div'); ctaHolder.style.width = '210px';
        var runbar = C.RunBar({
          label: 'LOAD OUTCOMES', morphToCancel: false, title: 'Per-run outcome cards grouped by action / profile / mode.',
          guards: [], onRun: doRuns
        });
        ctaHolder.appendChild(runbar.el);
        ctrl.appendChild(ctrlRow('Days back', daysIn));
        ctrl.appendChild(statusLine);
        ctrl.appendChild(exportBtn); ctrl.appendChild(clearBtn); ctrl.appendChild(ctaHolder);
        panel.appendChild(ctrl);

        var stats = C.StatCards({ cards: [
          { key: 'groups', label: 'GROUPS', color: 'cyan' },
          { key: 'runs', label: 'RUNS', color: 'accent' },
          { key: 'ok', label: 'SUCCESS', color: 'ok' },
          { key: 'fail', label: 'FAILED', color: 'bad' }
        ] });
        panel.appendChild(stats.el);

        var results = ui.namedCard('RUN OUTCOMES', 'One row per (action, profile, mode) over the window. A rolled-up group card is counted ONCE, not once per member.');
        results.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
        var grid = C.ResultsGrid({
          title: 'Run outcomes', keyMode: { rk: true }, popOut: true, selectable: false,
          columns: [
            { key: 'Action', label: 'ACTION', width: 130 },
            { key: 'Profile', label: 'PROFILE', width: 150 },
            { key: 'Mode', label: 'MODE', width: 110 },
            { key: 'Runs', label: 'RUNS', width: 80, type: 'text' },
            { key: 'HostsTotal', label: 'HOSTS', width: 80, type: 'text' },
            { key: 'Success', label: 'SUCCESS', width: 90, render: function (r) { return { text: String(r.Success == null ? '' : r.Success), cls: 'st-ok' }; } },
            { key: 'Failed', label: 'FAILED', width: 90, render: function (r) { var n = parseInt(r.Failed, 10) || 0; return { text: String(r.Failed == null ? '' : r.Failed), cls: n > 0 ? 'st-bad' : 'cell-dim' }; } },
            { key: 'SuccessPct', label: 'SUCCESS %', width: 100, render: function (r) { var n = parseFloat(r.SuccessPct); if (isNaN(n)) return { text: '' }; return { text: String(n), cls: n >= 95 ? 'st-ok' : (n >= 80 ? 'st-warn' : 'st-bad') }; } },
            { key: 'AvgDurationSec', label: 'AVG SEC', width: 90, type: 'text' },
            { key: 'LastRun', label: 'LAST RUN', width: 150 },
            { key: 'Operators', label: 'OPERATORS', width: 100, type: 'text' }
          ]
        });
        var gh = el('div'); gh.style.cssText = 'flex:1;min-height:0;display:flex'; gh.appendChild(grid.el);
        results.appendChild(gh); panel.appendChild(results);

        var EXPORT = [['Action', 'Action'], ['Profile', 'Profile'], ['Mode', 'Mode'], ['Runs', 'Runs'], ['HostsTotal', 'HostsTotal'], ['Success', 'Success'], ['Failed', 'Failed'], ['SuccessPct', 'SuccessPct'], ['AvgDurationSec', 'AvgDurationSec'], ['LastRun', 'LastRun'], ['Operators', 'Operators']];
        exportBtn.onclick = function () { exportGrid(grid, EXPORT, 'PatchHistory_RunOutcomes'); };
        clearBtn.onclick = function () { grid.clear(); stats.reset(); setLine(statusLine, 'Ready'); };

        function doRuns() {
          startRun({
            action: 'run-outcomes', label: 'LOAD OUTCOMES', runbar: runbar, grid: grid, statusEl: statusLine,
            params: { days: intOr(daysIn, 30) },
            onReset: function () { stats.reset(); },
            onFinal: function (s) {
              stats.setAll({ groups: s.total || 0, runs: s.runs || 0, ok: s.success || 0, fail: s.failed || 0 });
              // A zero-row board over a source that failed to read is UNKNOWN, not
              // "nobody ran anything" - never let that go green.
              var cap = (s.capped ? ' (row cap hit)' : '') + (s.readFailed ? ' (READ ERRORS - incomplete)' : '');
              var txt = 'Done - ' + (s.total || 0) + ' group(s), ' + (s.runs || 0) + ' run(s), ' + (s.successPct || 0) + '% success' + cap;
              if (s.deduped) txt += ' [' + s.deduped + ' group-member row(s) de-duped]';
              setLine(statusLine, txt, s.readFailed ? 'st-bad' : ((s.total && !s.failed) ? 'st-ok' : (s.total ? 'st-warn' : 'st-warn')));
            }
          });
        }
      }

      // =====================================================================
      //  TAB 6 - Coverage (audit 2026-07-25 #8)
      //  The AD computer population x the audit trail. Fail-closed: UNKNOWN is
      //  never a pass, so it gets its own tile and never renders green.
      // =====================================================================
      function buildCoverageTab(panel) {
        panel.style.cssText = 'display:flex;gap:14px;height:100%;min-height:0;box-sizing:border-box;padding:12px';

        // LEFT: scope + thresholds + optional paste + run
        var left = el('div'); left.style.cssText = 'flex:0 0 380px;display:flex;flex-direction:column;gap:12px;min-height:0;overflow:auto';

        var scopeCard = ui.card({}); scopeCard.style.cssText += ';display:flex;flex-direction:column;gap:10px';
        var baseIn = ui.input({ placeholder: 'OU=Squadron,DC=example,DC=mil', title: 'Limit the AD enumeration to this OU. Blank = the whole domain (a big read). Must be a plain DN inside THIS host domain.' });
        baseIn.style.width = '100%';
        var baseWrap = el('div'); baseWrap.style.cssText = 'display:flex;flex-direction:column;gap:4px';
        baseWrap.appendChild(ui.label('Search base DN (blank = whole domain)'));
        baseWrap.appendChild(baseIn);
        scopeCard.appendChild(baseWrap);
        var thrIn = ui.number({ value: 30, min: 1, max: 3650, title: 'A live host not touched within this many days is not COVERED.' }); thrIn.style.width = '90px';
        var adStaleIn = ui.number({ value: 90, min: 1, max: 3650, title: 'An AD computer object with no logon in this many days counts as dead.' }); adStaleIn.style.width = '90px';
        var lookIn = ui.number({ value: 12, min: 1, max: 24, title: 'How far back to search the audit trail for the last touch (months).' }); lookIn.style.width = '90px';
        scopeCard.appendChild(ctrlRow('Coverage threshold (days)', thrIn));
        scopeCard.appendChild(ctrlRow('AD stale threshold (days)', adStaleIn));
        scopeCard.appendChild(ctrlRow('Audit lookback (months)', lookIn));
        var statusLine = el('div', 'muted', 'Ready'); statusLine.style.fontSize = '12px';
        scopeCard.appendChild(statusLine);
        left.appendChild(scopeCard);

        var compCard = ui.namedCard('ALSO RECONCILE THESE HOSTS (OPTIONAL)');
        compCard.style.cssText += ';flex:0 0 auto;display:flex;flex-direction:column';
        var targets = C.TargetManager({
          model: ctx.util.targetModel(''),
          hint: 'Optional - hosts to reconcile the OTHER direction (JANET touched them; does AD still have a live object?).',
          placeholder: 'WS-0001\nWS-0002',
          importLabel: 'Import TXT', importAccept: '.txt', countNoun: 'host',
          onImport: function (n, name) { actlog.append({ text: '[' + ts() + '] Added ' + n + ' host(s) from ' + name, level: 'info' }); }
        });
        var tgHolder = el('div'); tgHolder.style.cssText = 'flex:1;min-height:0;display:flex'; tgHolder.appendChild(targets.el);
        compCard.appendChild(tgHolder);
        left.appendChild(compCard);

        // A whole-domain enumeration is the one genuinely long read in this tool, so
        // this is the one tab whose CTA morphs to Cancel - the engine honours the
        // injected __job cancel between LDAP pages.
        var curRun = null;
        var actCard = ui.card({}); actCard.style.cssText += ';display:flex;flex-direction:column;gap:8px';
        var runbar = C.RunBar({
          label: 'RECONCILE', cancelLabel: 'CANCEL RECONCILE', morphToCancel: true,
          title: 'Enumerate the AD computer population and join it against the audit trail.',
          guards: [], onRun: doCoverage,
          onCancel: function () {
            if (curRun && curRun.cancel) { curRun.cancel(); actlog.append({ text: '[' + ts() + '] Cancel requested - the AD enumeration stops at the next page; the board will be PARTIAL.', level: 'warn' }); }
          }
        });
        var rbWrap = el('div'); rbWrap.appendChild(runbar.el); actCard.appendChild(rbWrap);
        left.appendChild(actCard);
        panel.appendChild(left);

        // RIGHT: stats + grid
        var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:12px;min-height:0';
        var stats = C.StatCards({ cards: [
          { key: 'total', label: 'HOSTS', color: 'cyan' },
          { key: 'covered', label: 'COVERED', color: 'ok' },
          { key: 'stale', label: 'STALE (LIVE)', color: 'gold' },
          { key: 'never', label: 'NEVER TOUCHED', color: 'bad' },
          { key: 'ghost', label: 'GHOST', color: 'bad' },
          { key: 'dead', label: 'DEAD OBJECT', color: 'accent' },
          // UNKNOWN gets its own tile for the same reason the staleness board's does:
          // a run where everything came back UNKNOWN must not look like a clean sweep.
          { key: 'unknown', label: 'UNKNOWN', color: 'accent' }
        ] });
        right.appendChild(stats.el);

        var head = ui.card({}); head.style.cssText += ';display:flex;align-items:center;gap:12px;flex-wrap:wrap';
        var exportBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the coverage rows to CSV.' });
        var clearBtn = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the results grid.' });
        var spacer = el('div'); spacer.style.flex = '1'; head.appendChild(spacer);
        head.appendChild(exportBtn); head.appendChild(clearBtn);
        right.appendChild(head);

        var results = ui.namedCard('FLEET COVERAGE', 'COVERED = a live AD object touched inside the threshold. STALE (live) = touched, but longer ago. NEVER TOUCHED (live) = a live object with no audit row. GHOST = JANET touched a host AD says is disabled, stale or absent. DEAD OBJECT = AD says dead and JANET never touched it. UNKNOWN = a capped or failed read - it is not a pass.');
        results.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
        var grid = C.ResultsGrid({
          title: 'Fleet coverage', keyMode: { rk: true }, popOut: true, selectable: false,
          columns: [
            { key: 'Host', label: 'HOST', width: 160 },
            { key: 'AdStatus', label: 'AD STATUS', width: 120, render: function (r) { var s = String(r.AdStatus || ''); return { text: s, cls: s === 'Enabled' ? 'st-ok' : (s === 'UNKNOWN' ? 'st-warn' : 'st-bad') }; } },
            { key: 'LastAdLogon', label: 'LAST AD LOGON', width: 150 },
            { key: 'LastTouched', label: 'LAST TOUCHED', width: 150 },
            { key: 'DaysAgo', label: 'DAYS AGO', width: 90, type: 'text' },
            { key: 'LastTool', label: 'LAST TOOL', width: 120 },
            { key: 'Verdict', label: 'VERDICT', width: 180, render: function (r) { return { text: String(r.Verdict || ''), cls: covVerdictCls(r.Verdict) }; } }
          ],
          rowClass: function (r) { return covVerdictRow(r.Verdict); }
        });
        var gh = el('div'); gh.style.cssText = 'flex:1;min-height:0;display:flex'; gh.appendChild(grid.el);
        results.appendChild(gh); right.appendChild(results);
        panel.appendChild(right);

        var EXPORT = [['Host', 'Host'], ['AdStatus', 'AdStatus'], ['LastAdLogon', 'LastAdLogon'], ['LastTouched', 'LastTouched'], ['DaysAgo', 'DaysAgo'], ['LastTool', 'LastTool'], ['Verdict', 'Verdict']];
        exportBtn.onclick = function () { exportGrid(grid, EXPORT, 'PatchHistory_Coverage'); };
        clearBtn.onclick = function () { grid.clear(); stats.reset(); setLine(statusLine, 'Ready'); };

        var cTotal = 0, cCov = 0, cStale = 0, cNever = 0, cGhost = 0, cDead = 0, cUnk = 0;
        function doCoverage() {
          curRun = startRun({
            action: 'coverage-reconcile', label: 'RECONCILE', runbar: runbar, grid: grid, statusEl: statusLine,
            morphToCancel: true,
            params: {
              searchBase: baseIn.value.trim(),
              thresholdDays: intOr(thrIn, 30),
              adStaleDays: intOr(adStaleIn, 90),
              lookbackMonths: intOr(lookIn, 12),
              targets: targets.hosts().join('\n')
            },
            onReset: function () { stats.reset(); cTotal = 0; cCov = 0; cStale = 0; cNever = 0; cGhost = 0; cDead = 0; cUnk = 0; },
            onRow: function (r) {
              cTotal++;
              var v = String(r.Verdict);
              if (v === 'COVERED') cCov++;
              else if (v === 'STALE (live)') cStale++;
              else if (v === 'NEVER TOUCHED (live)') cNever++;
              else if (v === 'GHOST') cGhost++;
              else if (v === 'DEAD OBJECT') cDead++;
              else if (isUnknownVerdict(v)) cUnk++;
              stats.setAll({ total: cTotal, covered: cCov, stale: cStale, never: cNever, ghost: cGhost, dead: cDead, unknown: cUnk });
            },
            onFinal: function (s) {
              var unk = s.unknown != null ? s.unknown : cUnk;
              stats.setAll({
                total: s.total != null ? s.total : cTotal,
                covered: s.covered != null ? s.covered : cCov,
                stale: s.staleLive != null ? s.staleLive : cStale,
                never: s.never != null ? s.never : cNever,
                ghost: s.ghost != null ? s.ghost : cGhost,
                dead: s.dead != null ? s.dead : cDead,
                unknown: unk
              });
              // UNKNOWN is not a pass, and neither is a ghost: never go green while
              // either is non-zero or a read failed.
              var bad = (s.ghost || 0) + (s.never || 0);
              var txt = 'Done - Covered ' + (s.covered || 0) + ' / Stale ' + (s.staleLive || 0) + ' / Never ' + (s.never || 0) + ' / Ghost ' + (s.ghost || 0) + ' / Dead ' + (s.dead || 0) + ' / Unknown ' + unk;
              if (s.rejected) txt = 'Rejected - invalid search base DN';
              if (s.adCapped) txt += ' (AD read capped)';
              if (s.cancelled) txt += ' (cancelled - PARTIAL)';
              if (s.readErrors) txt += ' (' + s.readErrors + ' read error(s))';
              setLine(statusLine, txt, (s.readFailed || s.rejected) ? 'st-bad' : ((bad || unk) ? 'st-warn' : 'st-ok'));
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
          { id: 'stale', label: 'Staleness', build: buildStaleTab },
          { id: 'runs', label: 'Run Outcomes', build: buildRunsTab },
          { id: 'coverage', label: 'Coverage', build: buildCoverageTab }
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
    }
  });
})();
