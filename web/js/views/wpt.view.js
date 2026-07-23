/* ============================================================================
   wpt.view.js  -  Workstation Patching Tool (tool id: 'wpt')  THE BIG ONE
   Faithful web-local re-build of the desktop J.A.N.E.T. Workstation Patching
   Tool v6.5.22 per docs/ui-specs/wpt.md: a single window whose left tab-rail
   mirrors the desktop's numbered sidebar nav, every operational tab fed by ONE
   shared global host list (ctx.targets), and the signature "activity run" - a
   toolbar action fans hosts across a runspace pool and per-host results stream
   back into a colour-coded ResultsGrid + an ActivityLog, with the X/N progress
   strip as the indicator.

   Architecture
   ------------
   - ONE shared TargetManager model (ctx.targets) is reused by every tab via a
     small "targets card" factory; the TabHost keeps each panel alive so a tab's
     grid + in-flight run survive switching away (desktop parity).
   - Each operational tab is built by makeRunTab(): a targets card (shared model)
     + a RunBar (with manifest-derived guards) + a ResultsGrid (manifest columns,
     hand-written colour rules) + an ActivityLog. Destructive actions guard on
     ctx.session.state.credSet and confirm via ctx.confirm / ctx.arm.
   - Multi-row-per-host grids (bulk-scan keeps 1/host; but scan-detail, app-list,
     software-scan, unsupported-scan, kb-scan, log4j) MUST pass keyOf to ctx.run
     AND a matching keyMode to ResultsGrid so rows do not collapse on Host.

   All server I/O goes through ctx.run -> RunController. No fetch/poll. No
   per-tool credential control (the shell header owns Set Credentials).

   Action ids / params / columns are taken verbatim from
   modules/JanetWeb.wpt.psm1 -> Get-JanetToolManifest (29 actions).
   ========================================================================== */
(function () {
  'use strict';

  var esc = Janet.util.esc;
  function asBool(v) { return v === true || v === 'true' || v === 'True' || v === 1 || v === '1'; }

  JanetViews.register('wpt', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;

      // -- per-view bookkeeping: every run unsubscribe so unmount() cleans up --
      var unsubs = [];                  // list of unsubscribe fns
      function track(unsub) { if (typeof unsub === 'function') unsubs.push(unsub); return unsub; }
      // audit 2026-07-23 deferred pass: RunController keys runs by toolId/actionId
      // and KEEPS every subscribed handler on that key, so a re-clicked one-shot
      // that bare-subscribes stacks one live handler per click - and any other
      // button sharing the actionId (e.g. Reg Keys "Verify Selected" vs its main
      // SCAN, or the two app-update-apply bars) feeds them all. resub() releases
      // the key's previous handler first (the kbUnsubs/healerUnsubs idiom, made
      // per-key). Optional onReplace lets a superseded site unfreeze its own
      // controls, since its released handler never sees the active:false that
      // normally re-enables them.
      var keyUnsubs = {};   // run key (actionId) -> { unsub, onReplace }
      function resub(actionId, run, handlers, onReplace) {
        var prev = keyUnsubs[actionId];
        if (prev) {
          var i = unsubs.indexOf(prev.unsub); if (i >= 0) unsubs.splice(i, 1);
          prev.unsub();
          if (prev.onReplace) { try { prev.onReplace(); } catch (e) {} }
        }
        // release BEFORE subscribing: subscribe() replays the fresh run's state
        // (incl. active:true) into the new handler, so the previous entry's
        // onReplace must not fire after that and un-arm the just-armed controls.
        keyUnsubs[actionId] = { unsub: track(run.subscribe(handlers)), onReplace: onReplace };
        return keyUnsubs[actionId].unsub;
      }
      var rebootMonitorFn = null;       // set by the Reboot Countdown tab; called by Bulk "Reboot Selected" to monitor a host subset

      // ----------------------------------------------------------------------
      //  SESSION TELEMETRY  (desktop Track-Action -> $global:Stats /
      //  $global:ActionHistory + the global activity sink). Fed by a wrapper
      //  around ctx.run, so EVERY action on EVERY tab is recorded regardless of
      //  which tab launched it. The Reports / Usage / Logs tabs render from this.
      // ----------------------------------------------------------------------
      var Telemetry = (function () {
        function zero() { return { scanned: 0, updates: 0, installed: 0, uninstalled: 0, reinstalled: 0, repaired: 0, reboots: 0 }; }
        var stats = zero(), history = [], logBuf = [], runs = 0, hostSet = {}, startedAt = null, seq = 0;
        var changeFns = [], logFns = [];
        function fireChange() { changeFns.forEach(function (f) { try { f(); } catch (e) {} }); }
        function pushLog(l) { logBuf.push(l); if (logBuf.length > 5000) logBuf.shift(); logFns.forEach(function (f) { try { f(l); } catch (e) {} }); }
        function bump(k, n) { stats[k] = (stats[k] || 0) + (n || 1); }
        var LABELS = {
          'bulk-scan': 'Scan', 'trend': 'Compliance Trend', 'bulk-patch': 'Patch', 'reboot': 'Reboot', 'reboot-schedule': 'Reboot Countdown',
          'reboot-abort': 'Cancel Reboot', 'ping-sweep': 'Ping Sweep', 'winrm-bootstrap': 'Repair WinRM',
          'health-scan': 'Health Scan', 'healer-restart-ccm': 'Restart MECM', 'healer-ccm-repair': 'Repair MECM', 'healer-wmi-repair': 'Repair WMI',
          'healer-wu-reset': 'Reset WU', 'healer-trigger-checkin': 'MECM Check-In', 'healer-gpupdate': 'gpupdate', 'healer-rdp-rebind': 'Repair RDP',
          'host-info': 'Host Info', 'eventlog-scan': 'Event Log Scan', 'maintenance-lock': 'Maint Lock', 'maintenance-unlock': 'Maint Unlock', 'ad-computers': 'AD Query', 'sccm-available': 'Available', 'sccm-install-available': 'Install Avail', 'clean-user-apps': 'Clean Apps',
          'software-scan': 'Software Scan', 'scan-detail': 'Scan Detail', 'software-uninstall': 'Uninstall',
          'app-list': 'Query Apps', 'app-action': 'App Action', 'unsupported-scan': 'Unsupported Scan',
          'unsupported-uninstall': 'Unsupported Uninstall', 'kb-scan': 'KB Scan', 'kb-trigger-mecm': 'MECM Cycles',
          'kb-push-download': 'KB Push', 'kb-install': 'KB Install', 'verify-patch': 'Verify Patch', 'remote-message': 'Remote Message',
          'cleanup-disk': 'Cleanup', 'registry-key-scan': 'Reg Scan', 'registry-key-apply': 'Reg Apply',
          'app-update-verify': 'App Update Verify', 'app-update-apply': 'App Update', 'log4j-scanner': 'Log4j Scan'
        };
        function label(id) { return LABELS[id] || id; }
        // classify one result row -> { add:{stat:n}, result, detail }. Multi-row-per-host
        // scans add nothing here; recordRun adds their distinct-host count once.
        function classify(actionId, r) {
          var add = {}, result = '', detail = r.Detail || r.Error || '';
          switch (actionId) {
            case 'bulk-scan': if (r.Online === false) { result = 'Offline'; } else { add.scanned = 1; result = 'Scanned'; detail = r.Error || ''; } break;
            case 'health-scan': add.scanned = 1; result = r.OverallHealth || 'Scanned'; detail = ''; break;
            case 'kb-scan': result = 'KB ' + (r.HotFixID || ''); detail = r.Description || ''; break;
            case 'software-scan': result = 'App'; detail = r.Name || ''; break;
            case 'unsupported-scan': result = r.Status || 'Scanned'; detail = r.DisplayName || r.Name || ''; break;
            case 'bulk-patch': {
              var u = parseInt(r.UpdatesTriggered, 10) || 0, a = parseInt(r.AppsTriggered, 10) || 0;
              if (r.Error) { result = 'Error'; } else { if (u) add.updates = u; if (a) add.installed = a; result = asBool(r.Reachable) ? 'Patched' : 'Unreachable'; detail = 'upd ' + u + ', app ' + a; }
              break;
            }
            case 'kb-install': { var kr = String(r.Result || (asBool(r.Success) ? 'Installed' : 'Failed')); if (/^installed$/i.test(kr)) add.installed = 1; result = kr; break; }
            case 'software-uninstall': { var ok = /^(uninstalled|removed|success|ok)$/i.test(String(r.Result || '')); if (ok) add.uninstalled = 1; result = r.Result || (ok ? 'Uninstalled' : 'Failed'); detail = (r.App || '') + (detail ? ' - ' + detail : ''); break; }
            case 'unsupported-uninstall': { var ok2 = /^(uninstalled|removed|success|ok)$/i.test(String(r.Result || r.Status || '')); if (ok2) add.uninstalled = 1; result = r.Result || r.Status || ''; break; }
            case 'app-action': {
              var m = String(r.Method || '').toLowerCase(), ok3 = /^(triggered|success|ok|installed|uninstalled|repaired)$/i.test(String(r.Result || ''));
              if (ok3) { if (m === 'install') add.installed = 1; else if (m === 'uninstall') add.uninstalled = 1; else if (m === 'reinstall') add.reinstalled = 1; else if (m === 'repair') add.repaired = 1; }
              result = r.Result || ''; detail = ((r.App || '') + ' ' + (r.Method || '')).trim(); break;
            }
            case 'app-update-apply': if (asBool(r.Success)) add.updates = 1; result = asBool(r.Success) ? 'Updated' : 'Failed'; break;
            case 'healer-restart-ccm': case 'healer-ccm-repair': case 'healer-wmi-repair': case 'healer-wu-reset': case 'healer-gpupdate': case 'healer-trigger-checkin': case 'healer-rdp-rebind':
              if (asBool(r.Success)) add.repaired = 1; result = asBool(r.Success) ? 'Repaired' : 'Failed'; break;
            case 'reboot': if (asBool(r.Success)) add.reboots = 1; result = asBool(r.Success) ? 'Reboot sent' : 'Failed'; break;
            case 'reboot-schedule': if (asBool(r.Success)) add.reboots = 1; result = asBool(r.Success) ? 'Armed' : 'Failed'; detail = r.RebootAt ? ('~' + r.RebootAt) : detail; break;
            case 'reboot-abort': result = asBool(r.Success) ? 'Cancelled' : 'Failed'; break;
            default:
              var g = (r.Success != null) ? asBool(r.Success) : (r.Reachable != null) ? asBool(r.Reachable) : null;
              result = (g == null) ? (r.Status || r.Result || '') : (g ? 'OK' : 'Failed');
          }
          return { add: add, result: result, detail: detail };
        }
        function recordRun(actionId, rs) {
          if (!rs || !rs.order) return;
          var t = ctx.util.clockStr(), distinct = {};
          rs.order.forEach(function (k) {
            var r = rs.rows[k]; if (!r) return;
            var hn = r.Host || r.host || ''; if (hn) { distinct[hn] = 1; hostSet[hn] = 1; }
            var c = classify(actionId, r);
            for (var s in c.add) { if (Object.prototype.hasOwnProperty.call(c.add, s)) bump(s, c.add[s]); }
            history.push({ seq: ++seq, time: t, action: label(actionId), target: hn, result: c.result, detail: c.detail });
          });
          if (actionId === 'kb-scan' || actionId === 'software-scan' || actionId === 'unsupported-scan') bump('scanned', Object.keys(distinct).length);
          runs++;
          pushLog({ text: label(actionId) + ' complete (' + rs.order.length + ' row(s))', level: 'banner' });
          fireChange();
        }
        function attach(actionId, params, handle) {
          if (!startedAt) startedAt = ctx.util.clockStr();
          var n = (ctx.util.parseHosts((params && params.targets) || '') || []).length;
          pushLog({ text: label(actionId) + ' started' + (n ? ' (' + n + ' host(s))' : ''), level: 'accent' });
          var done = false, unsub = null;
          function flush() { if (done) return; done = true; try { recordRun(actionId, handle.state); } catch (e) {} if (unsub) setTimeout(unsub, 0); }
          unsub = handle.subscribe({
            log: function (l) { pushLog(l); },
            error: function (e) { pushLog({ text: e.text, level: 'err' }); },
            final: function () { flush(); },
            active: function (a) { if (!a) flush(); }
          });
          track(unsub);
        }
        return {
          attach: attach,
          stats: function () { return stats; }, history: function () { return history; }, logBuf: function () { return logBuf; },
          metrics: function () { return { runs: runs, hosts: Object.keys(hostSet).length, started: startedAt, entries: history.length }; },
          onChange: function (f) { changeFns.push(f); return function () { var i = changeFns.indexOf(f); if (i >= 0) changeFns.splice(i, 1); }; },
          onLog: function (f) { logFns.push(f); return function () { var i = logFns.indexOf(f); if (i >= 0) logFns.splice(i, 1); }; },
          clear: function () { stats = zero(); history = []; runs = 0; hostSet = {}; seq = 0; fireChange(); }
        };
      })();
      // wrap ctx.run ONCE so every action (every tab) feeds Telemetry. Views still
      // get the same handle + subscribe as before; this only taps it in parallel.
      var _origRun = ctx.run;
      ctx.run = function (actionId, params, opts) { var h = _origRun(actionId, params, opts); try { Telemetry.attach(actionId, params, h); } catch (e) {} return h; };

      var root = el('div'); root.style.cssText = 'display:flex;flex-direction:column;height:100%;min-height:0;background:var(--bg)';

      // ----- small shared helpers -----
      function notice(title, body) { return ctx.confirm({ title: title, body: body, okText: 'OK', cancelText: null }); }
      function needCred() {
        if (ctx.session.state.credSet) return false;
        notice('Admin session required', 'Set your ADW credential (Set Credentials, top-right) and start an admin session before running this - it changes machines.');
        return true;
      }
      // standard guards for an action that fans out over the shared target list
      function fleetGuards() {
        return [
          function () { return ctx.targets.count() ? null : 'No Targets|Build the shared host list on the Targets tab first.'; },
          function () { return ctx.session.state.credSet ? null : 'No Credentials|Set your ADW credential (top-right) before running remote operations.'; }
        ];
      }
      function guardFail(m) { var p = m.split('|'); notice(p[0], p[1] || p[0]); }

      // a per-tab "TARGET WORKSTATIONS" card bound to the SHARED model (ctx.targets).
      // Every operational tab shows the same live list; editing it anywhere updates
      // every tab + the status strip (the desktop's $global:ComputerList).
      function sharedTargetsCard(opts) {
        opts = opts || {};
        var box = ui.card({});
        box.style.cssText += ';flex:0 0 300px;display:flex;flex-direction:column;min-height:0';
        var h = el('div', 'j-section-h', 'TARGET WORKSTATIONS'); h.style.marginBottom = '6px';
        box.insertBefore(h, box.firstChild);
        var note = el('div', 'muted', 'Shared host list - edit on any tab.'); note.style.cssText = 'font-size:11px;margin-bottom:6px';
        box.appendChild(note);
        var tm = C.TargetManager({
          model: ctx.targets, countNoun: 'host', importLabel: 'Import TXT',
          importAccept: '.txt,.csv,.tsv',
          hint: opts.hint || 'Paste hostnames (line / comma / space separated)'
        });
        track(tm.dispose);   // release TargetManager's listener on the shared ctx.targets model (avoid per-mount leak)
        var holder = el('div'); holder.style.cssText = 'flex:1;min-height:120px;display:flex'; holder.appendChild(tm.el);
        box.appendChild(holder);
        return { box: box, tm: tm };
      }

      // a single-host picker bound to a small select that re-syncs from the shared list.
      // Used by the single-host tabs (Software Manager scan/detail/app-list).
      function hostPickerRow(label) {
        var wrap = el('div'); wrap.style.cssText = 'display:flex;align-items:flex-end;gap:10px;flex-wrap:wrap';
        var sel = ui.select({ options: [{ value: '', label: '(no hosts - add on Targets)' }] });
        sel.style.minWidth = '220px';
        var manual = ui.input({ placeholder: 'or type a hostname', title: 'Type a host if it is not in the shared list.' });
        manual.style.width = '200px';
        function sync() {
          var cur = sel.value;
          var hosts = ctx.targets.hosts();
          sel.innerHTML = '';
          if (!hosts.length) { var o = el('option', null, '(no hosts - add on Targets)'); o.value = ''; sel.appendChild(o); }
          hosts.forEach(function (hn) { var o = el('option', null, hn); o.value = hn; sel.appendChild(o); });
          if (hosts.indexOf(cur) >= 0) sel.value = cur;
        }
        track(ctx.targets.onChange(sync)); sync();
        wrap.appendChild(ui.field(label || 'Host', sel));
        wrap.appendChild(manual);
        return {
          el: wrap, sync: sync,
          host: function () { return (manual.value || '').trim() || sel.value || ''; }
        };
      }

      // ----------------------------------------------------------------------
      //  Generic fleet "scan/run" tab factory.
      //  spec = {
      //    actionId, runLabel, cancelLabel?, morphToCancel?, destructive?,
      //    columns:[ResultsGrid cols], keyOf?, keyMode?, rowClass?,
      //    selectable?, logName,
      //    params(grid, opts)->extra params for ctx.run (besides targets),
      //    settings(panel)->build extra inputs (returns getter fns stashed on closure),
      //    confirmBeforeRun(grid)->Promise<bool>|null  (destructive confirm),
      //    onRow(row, log, counters), onFinal(log, grid, counters),
      //    toolbarButtons(grid, runTab)->[btn],   // follow-on actions etc.
      //    intro:[{text,level}]
      //  }
      // ----------------------------------------------------------------------
      function makeRunTab(panel, spec) {
        var run = null;
        var counters = {};

        var lay = el('div'); lay.style.cssText = 'display:flex;flex-direction:column;gap:12px;height:100%;min-height:0;padding:12px;box-sizing:border-box';
        panel.appendChild(lay);

        // top work area: shared targets (left) + controls/results (right)
        var workRow = el('div'); workRow.style.cssText = 'display:flex;gap:12px;flex:1;min-height:0';
        lay.appendChild(workRow);

        // LEFT: shared targets
        var tg = sharedTargetsCard({ hint: spec.targetHint });
        workRow.appendChild(tg.box);

        // RIGHT column
        var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:10px;min-height:0';
        workRow.appendChild(right);

        // settings + run bar card
        var ctlCard = ui.card({}); ctlCard.style.cssText += ';display:flex;flex-direction:column;gap:10px';
        var hdr = el('div', 'j-section-h', spec.title || spec.runLabel); ctlCard.appendChild(hdr);
        if (spec.description) { var d = el('div', 'muted', spec.description); d.style.cssText = 'font-size:11.5px'; ctlCard.appendChild(d); }
        var settingsHolder = el('div'); settingsHolder.style.cssText = 'display:flex;flex-wrap:wrap;gap:14px;align-items:flex-end';
        ctlCard.appendChild(settingsHolder);
        var getSettings = spec.settings ? spec.settings(settingsHolder) : function () { return {}; };

        // RunBar
        var grid;     // defined below, referenced by guards/params via closure
        var runbar = C.RunBar({
          label: spec.runLabel, cancelLabel: spec.cancelLabel || ('CANCEL ' + spec.runLabel),
          morphToCancel: spec.morphToCancel !== false,
          title: spec.runTitle || spec.description,
          guards: spec.guards || fleetGuards(),
          onGuardFail: guardFail,
          onRun: doRun,
          onCancel: function () { if (run) { run.cancel(); log.append({ text: 'CANCEL requested - draining in-flight hosts...', level: 'warn' }); } }
        });
        var runRow = el('div'); runRow.style.cssText = 'display:flex;align-items:center;gap:12px;flex-wrap:wrap';
        var ctaHold = el('div'); ctaHold.style.minWidth = '240px'; ctaHold.appendChild(runbar.el);
        runRow.appendChild(ctaHold);
        ctlCard.appendChild(runRow);
        right.appendChild(ctlCard);

        // RESULTS grid + progress
        var resCard = ui.card({}); resCard.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
        grid = C.ResultsGrid({
          title: spec.runLabel + ' results',
          columns: spec.columns,
          keyMode: spec.keyMode || { hostCol: 'Host' },
          selectable: !!spec.selectable,
          rowClass: spec.rowClass,
          onRowClick: spec.onRowClick,
          popOut: true,
          toolbarButtons: spec.toolbarButtons ? spec.toolbarButtons(function () { return grid; }, { getRun: function () { return run; } }) : null
        });
        var gridHolder = el('div'); gridHolder.style.cssText = 'flex:1;min-height:0;display:flex'; gridHolder.appendChild(grid.el);
        resCard.appendChild(gridHolder);
        var prog = C.ProgressStatusStrip({ showCount: true });
        prog.el.style.marginTop = '8px'; resCard.appendChild(prog.el);
        right.appendChild(resCard);

        // ACTIVITY log: full-width dock across the bottom of the tool (more visible lines)
        var logCard = ui.card({}); logCard.classList.add('j-logdock');
        var log = C.ActivityLog({ title: 'ACTIVITY LOG', defaultName: spec.logName || ('WPT_' + spec.actionId) });
        logCard.appendChild(log.el);
        lay.appendChild(logCard);

        (spec.intro || []).forEach(function (l) { log.append(l); });

        // expose so toolbar follow-on buttons can read selection
        var api = {
          grid: grid, log: log, prog: prog, runbar: runbar,
          counters: counters, getSettings: getSettings,
          targetText: function () { return ctx.targets.raw; }
        };

        async function doRun() {
          // destructive guard (credSet already checked by guards, but confirm here)
          if (spec.confirmBeforeRun) {
            var ok = await spec.confirmBeforeRun(api);
            if (!ok) { log.append({ text: spec.runLabel + ' cancelled by operator.', level: 'warn' }); return; }
          }
          grid.clear(); prog.reset();
          for (var k in counters) if (Object.prototype.hasOwnProperty.call(counters, k)) delete counters[k];
          var hosts = ctx.targets.hosts();
          log.banner(spec.runLabel + ' - ' + hosts.length + ' host(s)');
          var params = Object.assign({ targets: ctx.targets.raw }, spec.params ? spec.params(api) : {});
          var opts = {};
          if (spec.keyOf) opts.keyOf = spec.keyOf;
          run = ctx.run(spec.actionId, params, opts);
          // per-key resub: a re-run (or another button sharing this actionId)
          // replaces this handler; onReplace un-morphs the runbar in that case.
          resub(spec.actionId, run, {
            status: function (t) { prog.setPhase(t); },
            progress: function (p) { prog.setProgress(p.done, p.total); },
            row: function (r) { grid.upsert(r); if (spec.onRow) spec.onRow(r, log, counters); },
            log: function (l) { log.append(l); },
            error: function (e) { log.append({ text: e.text, level: 'err' }); },
            final: function (res) { if (spec.onFinal) spec.onFinal(log, grid, counters, res); else log.banner(spec.runLabel + ' complete - ' + grid.rows().length + ' row(s)'); },
            active: function (a) { runbar.setActive(a); }
          }, function () { runbar.setActive(false); });
        }

        return api;
      }

      // a tiny "threads" number input usable from a spec.settings builder
      function threadsInput(holder, def, max) {
        var n = ui.number({ value: def, min: 1, max: max || 64, title: 'Parallel hosts (1-' + (max || 64) + ').' });
        n.style.width = '90px';
        holder.appendChild(ui.field('Parallel hosts', n));
        return function () { return Math.max(1, Math.min(max || 64, parseInt(n.value, 10) || def)); };
      }

      /* ======================================================================
         COLUMN + COLOUR SPECS  (hand-written per the desktop semantics)
         ==================================================================== */
      // bulk-scan: the canonical compact colour-coded fleet grid.
      function bulkScanColumns() {
        function driveFreeCell(r) {
          var pct = r.DriveFreePercent, sz = r.DriveSize;
          if (r.Online === false) return { text: '', cls: 'cell-dim' };
          if (pct === 'Error' || sz === 'Error') return { text: 'Error', cls: 'st-bad' };
          if (sz == null || sz === '') return { text: '', cls: 'cell-dim' };
          var n = parseInt(pct, 10);
          var txt = sz + 'GB (' + (isNaN(n) ? '?' : n) + '%)';
          return { text: txt, cls: (isNaN(n) ? '' : (n > 20 ? 'st-ok' : 'st-warn')) };
        }
        function countCell(v, dimWhenZeroOk) {
          if (v === 'Error') return { text: 'Error', cls: 'st-bad' };
          if (v == null || v === '') return { text: '', cls: 'cell-dim' };
          var n = parseInt(v, 10);
          if (isNaN(n)) return { text: String(v), cls: '' };
          if (n === 0) return { text: 'Current', cls: 'st-ok' };
          return { text: n + (dimWhenZeroOk || ''), cls: 'st-warn' };
        }
        return [
          { key: 'Host', label: 'HOST', width: 130 },
          { key: 'LoggedOnUser', label: 'USER', width: 150, render: function (r) {
              if (r.Online === false) return { text: '', cls: 'cell-dim' };
              var u = r.LoggedOnUser;
              if (u == null || u === '') return { text: '(none)', cls: 'cell-dim' };
              return { text: String(u), cls: 'st-warn' };   // highlight: someone is signed in (matters before patch/reboot)
          } },
          { key: 'Online', label: 'UP', width: 64, render: function (r) { return r.Online === true ? { text: 'Online', cls: 'st-ok' } : { text: 'Offline', cls: 'st-bad' }; } },
          { key: 'OsName', label: 'OS', width: 155, render: function (r) {
              if (r.Online === false) return { text: '', cls: 'cell-dim' };
              return (r.OsName == null || r.OsName === '') ? { text: '', cls: 'cell-dim' } : { text: String(r.OsName), cls: '' };
          } },
          { key: 'OsBuild', label: 'BUILD', width: 130, render: function (r) {
              if (r.Online === false) return { text: '', cls: 'cell-dim' };
              return (r.OsBuild == null || r.OsBuild === '') ? { text: '', cls: 'cell-dim' } : { text: String(r.OsBuild), cls: '' };
          } },
          { key: 'DriveFree', label: 'C:', width: 110, render: driveFreeCell, sortVal: function (r) { return parseInt(r.DriveFreePercent, 10) || 0; } },
          { key: 'RebootPending', label: 'REB', width: 60, render: function (r) {
              if (r.Online === false) return { text: '', cls: 'cell-dim' };
              if (r.RebootPending === 'Error') return { text: 'Error', cls: 'st-bad' };
              if (r.RebootPending == null || r.RebootPending === '') return { text: '', cls: 'cell-dim' };
              return asBool(r.RebootPending) ? { text: 'YES', cls: 'st-warn' } : { text: 'No', cls: 'st-ok' };
          } },
          { key: 'MECMUpdateCount', label: 'MECM', width: 78, render: function (r) { return countCell(r.MECMUpdateCount, ' upd'); } },
          { key: 'WindowsUpdateCount', label: 'WU', width: 70, render: function (r) { return countCell(r.WindowsUpdateCount, ' upd'); } },
          { key: 'AppCount', label: 'APP', width: 70, render: function (r) { return countCell(r.AppCount, ' app'); } },
          { key: 'Error', label: 'NOTES / ERROR', render: function (r) { return { text: r.Error == null ? '' : String(r.Error), cls: r.Error ? 'st-warn' : '' }; } }
        ];
      }

      // a health-state cell: colour OK/Healthy green, Error/Critical red, else amber.
      // (render is called UNBOUND by ResultsGrid, so the column key is captured here.)
      function healthStateCell(key) {
        return function (r) {
          var s = String(r[key] == null ? '' : r[key]);
          if (!s) return { text: '', cls: 'cell-dim' };
          var cls = /(healthy|ok|good|running|up|enabled|current)/i.test(s) ? 'st-ok'
            : /(error|fail|critical|stopped|down|bad|missing|disabled)/i.test(s) ? 'st-bad'
            : 'st-warn';
          return { text: s, cls: cls };
        };
      }

      /* ======================================================================
         TAB BUILDERS
         Each returns void; builds into the given panel. Built lazily by TabHost.
         ==================================================================== */

      // ---- TAB: Targets ----
      function buildTargets(panel) {
        var lay = el('div'); lay.style.cssText = 'display:flex;gap:12px;height:100%;min-height:0;padding:14px;box-sizing:border-box';
        var card = ui.card({}); card.style.cssText += ';flex:0 0 420px;display:flex;flex-direction:column;min-height:0';
        var h = el('div', 'j-section-h', 'TARGET WORKSTATIONS'); h.style.marginBottom = '6px'; card.appendChild(h);
        card.appendChild((function () { var d = el('div', 'muted', 'This shared list feeds EVERY operational tab (the desktop $global:ComputerList). Paste one host per line, or import a TXT/CSV.'); d.style.cssText = 'font-size:11.5px;margin-bottom:8px'; return d; })());
        var tm = C.TargetManager({
          model: ctx.targets, countNoun: 'host', importLabel: 'Import TXT', importAccept: '.txt,.csv,.tsv',
          hint: 'Paste hostnames (line / comma / space separated)',
          onImport: function (n, name) { /* count shown live */ }
        });
        track(tm.dispose);   // release TargetManager's listener on the shared ctx.targets model (avoid per-mount leak)
        var holder = el('div'); holder.style.cssText = 'flex:1;min-height:160px;display:flex'; holder.appendChild(tm.el);
        card.appendChild(holder);

        // Import ACAS CSV: the desktop auto-detected the hostname column from a
        // Tenable/ACAS export (plain "Import TXT" feeds every cell through parseHosts
        // = garbage on a real multi-column CSV). Detect the best host column, extract
        // + normalize to short names, append to the shared list.
        var acasRow = el('div'); acasRow.style.cssText = 'display:flex;align-items:center;gap:8px;margin-top:8px;flex-wrap:wrap';
        var acasBtn = ui.ghostButton('Import ACAS CSV...', { size: 'sm', title: 'Import a Tenable/ACAS CSV export - auto-detects the DNS/NetBIOS/Host/IP column.' });
        var acasNote = el('span', 'muted'); acasNote.style.fontSize = '11px';
        acasRow.appendChild(acasBtn); acasRow.appendChild(acasNote);
        card.appendChild(acasRow);
        acasBtn.onclick = function () {
          var fi = el('input'); fi.type = 'file'; fi.accept = '.csv,.txt'; fi.style.display = 'none';
          document.body.appendChild(fi);
          fi.addEventListener('change', function () {
            var f = fi.files && fi.files[0]; document.body.removeChild(fi);
            if (!f) return;
            var rd = new FileReader();
            rd.onload = function () {
              var res = importAcasHosts(String(rd.result || ''));
              if (!res) { acasNote.textContent = 'No host column found.'; acasNote.className = 'st-warn'; return; }
              acasNote.textContent = 'Imported ' + res.added + ' new host(s) from column "' + res.col + '".';
              acasNote.className = res.added ? 'st-ok' : 'muted';
            };
            rd.readAsText(f);
          });
          fi.click();
        };
        // extract the host column from an ACAS/Nessus CSV, normalize, append (dedup) to ctx.targets
        function importAcasHosts(text) {
          var p = ctx.util.parseCsv(text);
          if (!p.headers.length) return null;
          var prefs = [/netbios/i, /dns\s*name/i, /^host$/i, /hostname/i, /ip\s*address/i, /^ip$/i];
          var idx = -1;
          for (var pi = 0; pi < prefs.length && idx < 0; pi++) { for (var hi = 0; hi < p.headers.length; hi++) { if (prefs[pi].test((p.headers[hi] || '').trim())) { idx = hi; break; } } }
          if (idx < 0) idx = 0;
          var hosts = p.rows.map(function (r) {
            var v = (r[idx] || '').trim(); if (!v) return '';
            v = v.split('\\').pop().replace(/:\d+$/, '');
            if (!/^\d+\.\d+\.\d+\.\d+$/.test(v) && v.indexOf('.') >= 0) v = v.split('.')[0];   // FQDN -> short, keep IPs
            return v;
          }).filter(Boolean);
          var before = ctx.targets.hosts().length;
          tm.setText(ctx.util.parseHosts(tm.getText() + '\n' + hosts.join('\n')).join('\n'));
          return { added: ctx.targets.hosts().length - before, col: (p.headers[idx] || 'col 1') };
        }
        // ---- Import from Active Directory (OU-exclusion picker) ----
        var adRow = el('div'); adRow.style.cssText = 'display:flex;align-items:center;gap:8px;margin-top:8px;flex-wrap:wrap';
        var adBtn = ui.ghostButton('Import from AD (OU)...', { size: 'sm', title: 'Query AD for computers, then pick/exclude OUs to add to the shared target list.' });
        var adNote = el('span', 'muted'); adNote.style.fontSize = '11px';
        adRow.appendChild(adBtn); adRow.appendChild(adNote);
        card.appendChild(adRow);
        var AD_EXCL_KEY = 'wpt_ad_excluded_ous';
        function ouFriendly(dn) {
          var parts = String(dn || '').split(',').filter(function (p) { return /^(OU|CN)=/i.test(p); }).map(function (p) { return p.replace(/^(OU|CN)=/i, ''); });
          return parts.length ? parts.join(' \\ ') : (dn || '(no OU)');
        }
        adBtn.onclick = function () {
          adBtn.disabled = true; var orig = adBtn.textContent; adBtn.textContent = 'Querying AD...'; adNote.textContent = '';
          var comps = [], done = false;
          function finish() { if (done) return; done = true; adBtn.disabled = false; adBtn.textContent = orig; showOuPicker(comps); }
          var run = ctx.run('ad-computers', { workstationsonly: true });
          // audit 2026-07-23 deferred pass: per-key resub (re-click stacked handlers)
          resub('ad-computers', run, {
            row: function (r) { comps.push(r); },
            error: function (e) { adNote.textContent = e.text || 'AD query error'; adNote.className = 'st-warn'; },
            final: function () { finish(); },
            active: function (a) { if (!a) finish(); }
          });
        };
        function showOuPicker(comps) {
          if (!comps.length) { notice('No computers', 'Active Directory returned no computer objects (or the query failed / was cancelled).'); return; }
          var ouMap = {};
          comps.forEach(function (c) { var ou = c.OU || '(no OU)'; if (!ouMap[ou]) ouMap[ou] = []; ouMap[ou].push(c.Name); });
          var ous = Object.keys(ouMap).sort();
          var excluded = {};
          try { (JSON.parse(localStorage.getItem(AD_EXCL_KEY) || '[]') || []).forEach(function (o) { excluded[o] = 1; }); } catch (e) {}
          var body = el('div'); body.style.cssText = 'display:flex;flex-direction:column;gap:8px;min-width:520px;max-width:700px';
          var hdr = el('div', 'muted'); hdr.style.fontSize = '11.5px';
          hdr.innerHTML = 'Found <b>' + comps.length + '</b> computer(s) in <b>' + ous.length + '</b> OU(s). <b>Uncheck</b> the OUs to EXCLUDE, then Add Selected. Exclusions are remembered on this browser.';
          body.appendChild(hdr);
          var search = ui.input({ placeholder: 'Filter OUs...' }); body.appendChild(search);
          var ctlRow = el('div'); ctlRow.style.cssText = 'display:flex;gap:8px';
          var allBtn = ui.ghostButton('Check all', { size: 'sm' }); var noneBtn = ui.ghostButton('Uncheck all', { size: 'sm' });
          ctlRow.appendChild(allBtn); ctlRow.appendChild(noneBtn); body.appendChild(ctlRow);
          var listWrap = el('div'); listWrap.style.cssText = 'max-height:340px;overflow:auto;border:1px solid var(--border);border-radius:4px;padding:6px;display:flex;flex-direction:column;gap:1px';
          body.appendChild(listWrap);
          var rowEls = [];
          ous.forEach(function (ou) {
            var row = el('div'); row.style.cssText = 'display:flex;align-items:center;gap:8px;padding:1px 0';
            var cb = document.createElement('input'); cb.type = 'checkbox'; cb.checked = !excluded[ou];
            var lbl = el('span'); lbl.style.cssText = 'font-size:12px;font-family:var(--ui)'; lbl.textContent = ouFriendly(ou) + '  (' + ouMap[ou].length + ')'; lbl.title = ou;
            row.appendChild(cb); row.appendChild(lbl); listWrap.appendChild(row);
            rowEls.push({ ou: ou, cb: cb, row: row, text: (ouFriendly(ou) + ' ' + ou).toLowerCase() });
          });
          search.addEventListener('input', function () { var q = search.value.toLowerCase(); rowEls.forEach(function (re) { re.row.style.display = (!q || re.text.indexOf(q) >= 0) ? '' : 'none'; }); });
          allBtn.onclick = function () { rowEls.forEach(function (re) { if (re.row.style.display !== 'none') re.cb.checked = true; }); };
          noneBtn.onclick = function () { rowEls.forEach(function (re) { if (re.row.style.display !== 'none') re.cb.checked = false; }); };
          ctx.confirm({ title: 'Import from Active Directory', body: body, okText: 'Add Selected', cancelText: 'Cancel' }).then(function (ok) {
            if (!ok) return;
            var add = [], newExcluded = [];
            rowEls.forEach(function (re) { if (re.cb.checked) { add = add.concat(ouMap[re.ou]); } else { newExcluded.push(re.ou); } });
            try { localStorage.setItem(AD_EXCL_KEY, JSON.stringify(newExcluded)); } catch (e) {}
            if (!add.length) { adNote.textContent = 'All OUs excluded - nothing added.'; adNote.className = 'st-warn'; return; }
            var before = ctx.targets.hosts().length;
            tm.setText(ctx.util.parseHosts(tm.getText() + '\n' + add.join('\n')).join('\n'));
            var added = ctx.targets.hosts().length - before;
            adNote.textContent = 'Added ' + added + ' new host(s) from ' + (rowEls.length - newExcluded.length) + ' OU(s).';
            adNote.className = added ? 'st-ok' : 'muted';
          });
        }

        lay.appendChild(card);

        var info = ui.card({}); info.style.cssText += ';flex:1;min-width:0';
        var ih = el('div', 'j-section-h', 'HOW THE LIST IS USED'); info.appendChild(ih);
        var p = el('div', 'muted'); p.style.cssText = 'font-size:12px;line-height:1.6;margin-top:8px';
        p.innerHTML =
          'The host list is <b>case-insensitively de-duplicated</b> and shared across all tabs.<br><br>' +
          '&bull; Bulk Scan &amp; Patch fans the whole list out in parallel.<br>' +
          '&bull; Software Manager / Software Center pick a single host from the list.<br>' +
          '&bull; All destructive actions still require an admin session (Set Credentials, top-right).<br><br>' +
          'ACAS / XLSX import: paste the hostnames column, or Import a TXT/CSV export.';
        info.appendChild(p);
        lay.appendChild(info);
        panel.appendChild(lay);
      }

      // ---- TAB: Bulk Scan & Patch (centerpiece) ----
      function buildBulk(panel) {
        var tab = makeRunTab(panel, {
          actionId: 'bulk-scan', runLabel: 'SCAN ALL', cancelLabel: 'CANCEL SCAN',
          title: 'BULK SCAN & PATCH', logName: 'WPT_BulkScan',
          description: 'Parallel scan: online (TCP 5985/5986/445), logged-on user, C: free space, reboot-pending, MECM / Windows Update / app pending counts. Double-click a row for Host Details. Select rows then Patch / Reboot.',
          columns: bulkScanColumns(),
          keyMode: { hostCol: 'Host' },   // 1 row per host (default Host key)
          selectable: true,
          settings: function (h) {
            var t = threadsInput(h, 24);
            // saveSnapshot checkbox: the manifest input does not auto-render here (this
            // view builds bulk controls by hand), so wire it explicitly into the params.
            var snapCb = ui.checkbox('Save snapshot for trending', { title: 'After the scan, persist a per-host CSV snapshot to JanetLocal\\snapshots. The Trend tab charts these over time (newest 60).' });
            var snapWrap = el('div'); snapWrap.style.cssText = 'display:flex;align-items:flex-end;padding-bottom:6px';
            snapWrap.appendChild(snapCb); h.appendChild(snapWrap);
            return function () { return { threads: t(), saveSnapshot: snapCb._cb.checked }; };
          },
          params: function (api) { var s = api.getSettings(); return { threads: s.threads, saveSnapshot: !!s.saveSnapshot }; },
          rowClass: function (r) { if (r.Online === false) return 'row-bad'; return ''; },
          onRowClick: function (r) { showHostDetails(r); },
          onRow: function (r, log, c) {
            if (r.Online === false) { c.off = (c.off || 0) + 1; }
            else { c.on = (c.on || 0) + 1; }
          },
          onFinal: function (log, grid, c) {
            var needWork = grid.rows().filter(rowNeedsWork).length;
            log.banner('Scan complete: ' + (c.on || 0) + ' online, ' + (c.off || 0) + ' offline, ' + needWork + ' need work');
            // Dual compliance denominators so offline boxes don't distort the number:
            // Fleet% over ALL targets, Measured% over hosts that actually answered.
            var total = grid.rows().length, online = (c.on || 0), compliant = Math.max(0, online - needWork);
            var fleetPct = total > 0 ? Math.round(compliant / total * 100) : null;
            var measuredPct = online > 0 ? Math.round(compliant / online * 100) : null;
            log.append({ text: 'Compliance - Fleet: ' + (fleetPct == null ? 'n/a' : fleetPct + '% (' + compliant + '/' + total + ')') +
              '  |  Measured: ' + (measuredPct == null ? 'n/a' : measuredPct + '% (' + compliant + '/' + online + ' online)'), level: 'accent' });
            api.runbar.setStatus('Scan done. Use "Select With Updates" then Patch / Reboot.', 'st-ok');
          },
          intro: [
            { text: 'Bulk Scan & Patch ready. Add hosts on Targets, set credentials, then SCAN ALL.', level: 'accent' },
            { text: 'Selection buttons feed Patch Selected / Reboot Selected (below the grid).', level: 'dim' }
          ],
          // follow-on selection + action buttons live in the grid toolbar
          toolbarButtons: function (getGrid) {
            var btns = [];
            var selWith = ui.ghostButton('Select With Updates', { size: 'sm', title: 'Check every host that has pending MECM/WU/app updates or a reboot pending.' });
            selWith.onclick = function () { getGrid().selectWhere(rowNeedsWork); };
            btns.push(selWith);
            var details = ui.ghostButton('Host Details', { size: 'sm', title: 'Show the full scan result for the first checked (or clicked) host.' });
            details.onclick = function () { var ch = getGrid().getChecked(); if (ch.length) showHostDetails(ch[0]); else notice('Nothing selected', 'Check a host (or double-click a row) to see its details.'); };
            btns.push(details);
            var exp = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the scan grid to CSV.' });
            exp.onclick = function () { exportGridCsv(getGrid(), 'WPT_BulkScan'); };
            btns.push(exp);
            return btns;
          }
        });
        var api = tab;

        // -------- Patch Selected / Reboot Selected action bar (below grid) --------
        // These run their OWN actions on the CHECKED hosts of the scan grid.
        var actBar = el('div'); actBar.style.cssText = 'display:flex;gap:10px;align-items:center;margin-top:10px;flex-wrap:wrap';
        // Patch posture: non-invasive (default; reboots suppressed, patch while users
        // work) vs forced (reboot-if-needed, customer-affecting; for quarantined hosts).
        var patchModeSel = ui.select({ options: [
          { value: 'noninvasive', label: 'Non-invasive (reboots suppressed)' },
          { value: 'forced', label: 'FORCED (reboot if needed)' }
        ], title: 'Non-invasive patches while users work and suppresses reboots. FORCED reboots the box when an install needs it — customer-affecting, for quarantined / no-user hosts.' });
        var patchBtn = ui.button('Patch Selected', { variant: 'gold', title: 'Trigger MECM updates + pending apps on the checked hosts, using the selected posture.' });
        var patchAllBtn = ui.button('Patch All Needing', { variant: 'gold', title: 'Select hosts with work, then patch them in one click (selected posture).' });
        var rebootBtn = ui.button('Reboot Selected', { variant: 'danger', title: 'Force an immediate reboot on the checked hosts.' });
        var pingBtn = ui.button('Ping Sweep', { variant: 'cyan', title: 'TCP reachability test (5985/5986/445) across the target list.' });
        var winrmBtn = ui.button('Repair WinRM', { variant: 'cyan', title: 'Bootstrap WinRM over DCOM on the checked (offline) hosts.' });
        actBar.appendChild(ui.eyebrow('POSTURE')); actBar.appendChild(patchModeSel);
        [patchBtn, patchAllBtn, rebootBtn, pingBtn, winrmBtn].forEach(function (b) { actBar.appendChild(b); });
        // place the action bar right after the results card's progress strip
        api.prog.el.parentNode.appendChild(actBar);

        function checkedHosts() { return api.grid.getChecked().map(function (r) { return r.Host; }).filter(Boolean); }

        patchBtn.onclick = function () { followOnFleet('bulk-patch', checkedHosts(), 'Patch Selected'); };
        patchAllBtn.onclick = function () {
          api.grid.selectWhere(rowNeedsWork);
          var hs = checkedHosts();
          if (!hs.length) { notice('Nothing to patch', 'No scanned host currently needs updates/apps. Run a scan first.'); return; }
          followOnFleet('bulk-patch', hs, 'Patch All Needing');
        };
        rebootBtn.onclick = function () { followOnFleet('reboot', checkedHosts(), 'Reboot Selected'); };
        pingBtn.onclick = function () { followOnFleet('ping-sweep', ctx.targets.hosts(), 'Ping Sweep'); };
        winrmBtn.onclick = function () {
          var hs = checkedHosts();
          if (!hs.length) hs = api.grid.rows().filter(function (r) { return r.Online === false; }).map(function (r) { return r.Host; });
          followOnFleet('winrm-bootstrap', hs, 'Repair WinRM');
        };

        // Run a follow-on fleet action against an explicit host set, streaming into
        // the SAME activity log. Results land in a transient modal-less popout grid
        // would be overkill; we stream into the log + flip per-host scan rows where
        // we can (patch/reboot annotate the matching Host row's NOTES).
        var sideRun = null;
        async function followOnFleet(actionId, hosts, label) {
          if (!hosts || !hosts.length) { notice('Nothing Selected', 'Check at least one host in the grid first.'); return; }
          var act = findManifestAction(actionId);
          var destructive = act && act.destructive;
          if (destructive && needCred()) return;
          var patchMode = (actionId === 'bulk-patch') ? (patchModeSel.value || 'noninvasive') : null;
          var patchForced = (patchMode === 'forced');
          if (destructive) {
            var danger = (actionId === 'reboot') || patchForced;   // forced patching is customer-affecting -> danger confirm
            var body = (actionId === 'reboot')
              ? 'REBOOT <b>' + hosts.length + '</b> workstation(s)? This is immediate and forced (Restart-Computer -Force).'
              : (actionId === 'winrm-bootstrap')
                ? 'Repair WinRM on <b>' + hosts.length + '</b> host(s)? Sets the service Automatic, starts it, runs winrm quickconfig over DCOM, re-probes 5985.'
                : patchForced
                  ? 'Patch <b>' + hosts.length + '</b> workstation(s) — <b>FORCED</b> posture. App installs will <b>REBOOT the box when an install needs it</b> (customer-affecting). Use for quarantined / no-user hosts only.'
                  : 'Patch <b>' + hosts.length + '</b> workstation(s) — <b>non-invasive</b> posture. Triggers MECM updates + pending app installs; <b>reboots are suppressed</b> so patching runs while users work.';
            var ok = await ctx.confirm({ title: 'Confirm ' + label + (patchMode ? (' · ' + (patchForced ? 'FORCED' : 'non-invasive')) : ''), danger: danger, body: body, list: hosts.slice(0, 6), preflight: { targets: hosts, actionLabel: label }, okText: danger ? (patchForced ? 'Force patch' : 'Reboot') : 'Proceed', cancelText: 'Cancel' });
            if (!ok) { api.log.append({ text: label + ' cancelled by operator.', level: 'warn' }); return; }
          }
          api.log.banner(label + ' - ' + hosts.length + ' host(s)' + (patchMode ? (' [' + (patchForced ? 'FORCED' : 'non-invasive') + ']') : ''));
          [patchBtn, patchAllBtn, rebootBtn, pingBtn, winrmBtn].forEach(function (b) { b.disabled = true; });
          var runParams = { targets: hosts.join('\n') };
          if (patchMode) runParams.mode = patchMode;
          sideRun = ctx.run(actionId, runParams);
          // audit 2026-07-23 deferred pass: per-key resub (ping-sweep is shared
          // with the Reboot Countdown monitor); onReplace unfreezes the action bar.
          resub(actionId, sideRun, {
            status: function (t) { api.prog.setPhase(t); },
            progress: function (p) { api.prog.setProgress(p.done, p.total); },
            row: function (r) { annotateBulkRow(actionId, r); },
            log: function (l) { api.log.append(l); },
            error: function (e) { api.log.append({ text: e.text, level: 'err' }); },
            final: function () {
              api.log.banner(label + ' complete');
              // desktop parity: after a Bulk "Reboot Selected" wave, offer to watch the
              // rebooted hosts ping back online (reuses the Reboot Countdown monitor).
              if (actionId === 'reboot') {
                var rebooted = hosts.slice();
                ctx.confirm({ title: 'Monitor reboots?', body: 'Watch <b>' + rebooted.length + '</b> rebooted host(s) drop and ping back online?', okText: 'Monitor', cancelText: 'No' }).then(function (yes) {
                  if (!yes) return;
                  tabHost.select('reboot');                  // build + show the Reboot Countdown tab
                  if (rebootMonitorFn) { rebootMonitorFn(rebooted); api.log.append({ text: 'Post-reboot monitor started on the Reboot Countdown tab.', level: 'accent' }); }
                  else api.log.append({ text: 'Reboot monitor unavailable.', level: 'warn' });
                });
              }
            },
            active: function (a) { if (!a) [patchBtn, patchAllBtn, rebootBtn, pingBtn, winrmBtn].forEach(function (b) { b.disabled = false; }); }
          }, function () { [patchBtn, patchAllBtn, rebootBtn, pingBtn, winrmBtn].forEach(function (b) { b.disabled = false; }); });
        }

        function annotateBulkRow(actionId, r) {
          var grid = api.grid;
          // merge a NOTES annotation into the Error col of the matching scan row
          var note = '';
          if (actionId === 'bulk-patch') {
            if (r.Error) note = 'Patch error: ' + r.Error;
            else if (asBool(r.Reachable)) note = 'Triggered: ' + (r.UpdatesTriggered || 0) + ' upd, ' + (r.AppsTriggered || 0) + ' app';
            else note = 'Unreachable - nothing patched';
          } else if (actionId === 'reboot') {
            note = asBool(r.Success) ? 'Reboot sent' : ('Reboot failed: ' + (r.Detail || ''));
          } else if (actionId === 'ping-sweep') {
            note = asBool(r.Reachable) ? 'Online' : 'Offline';
            grid.upsert({ Host: r.Host, Online: asBool(r.Reachable) });
            return;
          } else if (actionId === 'winrm-bootstrap') {
            note = asBool(r.Success) ? ('WinRM repaired' + (asBool(r.PostProbeOk) ? ' (5985 up)' : '')) : ('WinRM repair failed');
          }
          grid.upsert({ Host: r.Host, Error: note });
        }
      }

      function rowNeedsWork(r) {
        if (r.Online === false) return false;
        var c = function (v) { var n = parseInt(v, 10); return !isNaN(n) && n > 0; };
        return c(r.MECMUpdateCount) || c(r.WindowsUpdateCount) || c(r.AppCount) || asBool(r.RebootPending);
      }

      function showHostDetails(r) {
        if (!r) return;
        var body = el('div');
        function kv(k, v) { var d = el('div', 'j-kv'); d.appendChild(el('div', 'j-kv-k', k)); d.appendChild(el('div', 'j-kv-v', v == null ? '' : String(v))); body.appendChild(d); }
        kv('Host', r.Host);
        kv('Online', r.Online === true ? 'Online' : 'Offline');
        kv('OS', (r.OsName == null || r.OsName === '') ? '(unknown)' : r.OsName);
        kv('Build', (r.OsBuild == null || r.OsBuild === '') ? '(unknown)' : r.OsBuild);
        kv('Logged-on user', (r.LoggedOnUser == null || r.LoggedOnUser === '') ? '(none)' : r.LoggedOnUser);
        kv('C: free', (r.DriveFree != null ? (r.DriveFree + 'GB') : '') + (r.DriveFreePercent != null ? (' (' + r.DriveFreePercent + '%)') : '') + (r.DriveSize != null ? (' of ' + r.DriveSize + 'GB') : ''));
        kv('Reboot pending', asBool(r.RebootPending) ? 'YES' : 'No');
        kv('Last boot', r.LastBootTime);
        kv('MECM updates (' + (r.MECMUpdateCount || 0) + ')', r.MECMUpdates || '(none)');
        kv('Windows Update (' + (r.WindowsUpdateCount || 0) + ')', r.WindowsUpdates || '(none)');
        kv('Pending apps (' + (r.AppCount || 0) + ')', r.PendingApps || '(none)');
        if (r.Error) kv('Scan error', r.Error);
        ctx.confirm({ title: 'Host Details - ' + r.Host, body: body, okText: 'Close', cancelText: null });
      }

      function findManifestAction(id) {
        return (ctx.manifest && ctx.manifest.actions || []).find(function (a) { return a.id === id; }) || null;
      }

      function exportGridCsv(grid, prefix) {
        var rows = grid.rows();
        if (!rows.length) { notice('Nothing to export', 'Run a scan first - there are no rows yet.'); return; }
        // Column set = UNION of keys across ALL rows (first-seen order). Keying off
        // rows[0] alone drops columns whenever the first row is a sparse offline host.
        var cols = [], seenCol = {};
        rows.forEach(function (r) {
          Object.keys(r).forEach(function (k) {
            if (k.charAt(0) === '_' || k === 'type') return;
            if (!Object.prototype.hasOwnProperty.call(seenCol, k)) { seenCol[k] = 1; cols.push(k); }
          });
        });
        var csv = ctx.util.toCsv(cols, rows, cols);
        ctx.util.downloadBlob(prefix + '_' + ctx.util.fileStamp() + '.csv', 'text/csv', csv);
      }

      // ---- TAB: Software Manager (single-host scan + uninstall + scan-detail) ----
      function buildSoftwareManager(panel) {
        var lay = el('div'); lay.style.cssText = 'display:flex;flex-direction:column;gap:12px;min-height:100%;padding:12px;box-sizing:border-box';
        panel.appendChild(lay);

        var ctlCard = ui.card({}); ctlCard.style.cssText += ';display:flex;flex-direction:column;gap:10px';
        ctlCard.appendChild(el('div', 'j-section-h', 'SOFTWARE MANAGER (single host)'));
        ctlCard.appendChild((function () { var d = el('div', 'muted', 'Registry software scan (Win32 + Store apps) on one host, then native uninstall by display name or {GUID}. "Scan Detail" lists the NAMED pending items behind the bulk-scan counts.'); d.style.cssText = 'font-size:11.5px'; return d; })());
        var picker = hostPickerRow('Host');
        ctlCard.appendChild(picker.el);
        var filterRow = el('div'); filterRow.style.cssText = 'display:flex;align-items:flex-end;gap:10px;flex-wrap:wrap';
        var filterInput = ui.input({ placeholder: 'Name / Publisher filter (optional)', title: 'Only list apps matching this substring.' });
        filterInput.style.width = '240px';
        var scanBtn = ui.button('Software Scan', { variant: 'cyan' });
        var detailBtn = ui.button('Scan Detail', { variant: 'cyan', title: 'List named pending MECM / Windows Update / Software Center items on this host.' });
        var uninstallBtn = ui.button('Uninstall Checked', { variant: 'danger', title: 'Uninstall the checked apps on this host with their native uninstaller.' });
        filterRow.appendChild(ui.field('Filter', filterInput));
        var quickSel = ui.select({ options: ['All software', 'Chrome', 'Edge', 'Microsoft 365 / Office', 'Teams', 'Tanium', 'Adobe', 'MSXML', 'Java'], title: 'Quick-filter the loaded list client-side (no re-scan).' });
        filterRow.appendChild(ui.field('Quick filter', quickSel));
        filterRow.appendChild(scanBtn); filterRow.appendChild(detailBtn); filterRow.appendChild(uninstallBtn);
        ctlCard.appendChild(filterRow);
        lay.appendChild(ctlCard);

        // results split: software grid (left) + detail grid (right)
        var split = el('div'); split.style.cssText = 'flex:1;min-height:300px;display:flex;gap:12px';
        lay.appendChild(split);

        var swCard = ui.card({}); swCard.style.cssText += ';flex:1;min-width:0;display:flex;flex-direction:column;min-height:0';
        swCard.appendChild(el('div', 'j-section-h', 'INSTALLED SOFTWARE'));
        var swGrid = C.ResultsGrid({
          title: 'Installed software', selectable: true,
          // software-scan emits _rk = host|name|ver|child -> key by _rk so duplicate
          // display names don't collapse. (manifest cols: Name/Version/Publisher/InstallDate/Install Type/Size)
          keyMode: { rk: true },
          columns: [
            { key: 'Name', label: 'NAME', width: 220 },
            { key: 'Version', label: 'VERSION', width: 110 },
            { key: 'Publisher', label: 'PUBLISHER', width: 160 },
            { key: 'InstallDate', label: 'INSTALLED', width: 100 },
            { key: 'Install Type', label: 'TYPE', width: 80 },
            { key: 'Size', label: 'SIZE', width: 80 }
          ]
        });
        var swHolder = el('div'); swHolder.style.cssText = 'flex:1;min-height:0;display:flex'; swHolder.appendChild(swGrid.el);
        swCard.appendChild(swHolder);
        split.appendChild(swCard);

        // client quick-filter of the loaded software list (desktop ddlSwQuickFilter), via grid.setFilter
        var SW_QUICK = { 'Chrome': /chrome/i, 'Edge': /edge/i, 'Microsoft 365 / Office': /microsoft 365|office|m365/i, 'Teams': /teams/i, 'Tanium': /tanium/i, 'Adobe': /adobe/i, 'MSXML': /msxml/i, 'Java': /\bjava\b|jre|jdk/i };
        quickSel.addEventListener('change', function () {
          var re = SW_QUICK[quickSel.value];
          swGrid.setFilter(re ? function (r) { return re.test(String(r.Name || '') + ' ' + String(r.Publisher || '')); } : null);
        });

        var dtCard = ui.card({}); dtCard.style.cssText += ';flex:0 0 360px;display:flex;flex-direction:column;min-height:0';
        dtCard.appendChild(el('div', 'j-section-h', 'PENDING ITEMS (Scan Detail)'));
        var dtGrid = C.ResultsGrid({
          title: 'Pending items',
          // scan-detail emits _rk = host|channel|name
          keyMode: { rk: true },
          columns: [
            { key: 'Channel', label: 'CHANNEL', width: 90, render: function (r) {
                var ch = String(r.Channel || '');
                var cls = /mecm/i.test(ch) ? 'st-info' : /windows/i.test(ch) ? 'st-warn' : 'st-accent';
                return { text: ch, cls: cls };
            } },
            { key: 'Name', label: 'ITEM' }
          ]
        });
        var dtHolder = el('div'); dtHolder.style.cssText = 'flex:1;min-height:0;display:flex'; dtHolder.appendChild(dtGrid.el);
        dtCard.appendChild(dtHolder);
        split.appendChild(dtCard);

        var logCard = ui.card({}); logCard.classList.add('j-logdock');
        var log = C.ActivityLog({ title: 'SOFTWARE ACTIVITY', defaultName: 'WPT_Software' });
        logCard.appendChild(log.el); lay.appendChild(logCard);
        log.append({ text: 'Pick a host, then Software Scan / Scan Detail. Check rows + Uninstall Checked.', level: 'accent' });

        function curHost() { var h = picker.host(); if (!h) { notice('Host required', 'Pick or type a host first.'); } return h; }

        scanBtn.onclick = function () {
          var h = curHost(); if (!h) return;
          swGrid.clear(); log.banner('Software scan - ' + h);
          var run = ctx.run('software-scan', { host: h, filter: filterInput.value || '' }, { keyOf: function (ev) { return ev._rk || (ev.Host + '|' + ev.Name); } });
          // audit 2026-07-23 deferred pass: per-key resub (re-click stacked handlers)
          resub('software-scan', run, {
            row: function (r) { swGrid.upsert(r); },
            log: function (l) { log.append(l); },
            status: function (t) { log.append({ text: t, level: 'dim' }); },
            final: function () { log.append({ text: h + ': ' + swGrid.rows().length + ' app(s) listed.', level: 'ok' }); }
          });
        };
        detailBtn.onclick = function () {
          var h = curHost(); if (!h) return;
          dtGrid.clear(); log.banner('Scan detail - ' + h);
          var run = ctx.run('scan-detail', { host: h }, { keyOf: function (ev) { return ev._rk || (ev.Host + '|' + ev.Channel + '|' + ev.Name); } });
          // audit 2026-07-23 deferred pass: per-key resub (re-click stacked handlers)
          resub('scan-detail', run, {
            row: function (r) { dtGrid.upsert(r); },
            log: function (l) { log.append(l); },
            status: function (t) { log.append({ text: t, level: 'dim' }); },
            final: function () { log.append({ text: h + ': ' + dtGrid.rows().length + ' pending item(s).', level: 'ok' }); }
          });
        };
        uninstallBtn.onclick = async function () {
          var h = curHost(); if (!h) return;
          if (needCred()) return;
          // visibleOnly: never uninstall rows the active quick-filter is hiding.
          var checked = swGrid.getChecked({ visibleOnly: true });
          if (!checked.length) { notice('Nothing checked', 'Check the app(s) to uninstall in the Installed Software grid.'); return; }
          var names = checked.map(function (r) { return r.Name; }).filter(Boolean);
          var ok = await ctx.confirm({
            title: 'Uninstall on ' + h, danger: true,
            body: 'Uninstall <b>' + names.length + '</b> app(s) on <b>' + esc(h) + '</b> with their native uninstaller (MSI /x /qn, EXE silent, or Remove-AppxPackage)? This cannot be undone.',
            list: names.slice(0, 8), okText: 'Uninstall', cancelText: 'Cancel'
          });
          if (!ok) { log.append({ text: 'Uninstall cancelled by operator.', level: 'warn' }); return; }
          log.banner('Uninstall on ' + h + ' - ' + names.length + ' app(s)');
          // software-uninstall emits _rk = host|app -> key by _rk
          var run = ctx.run('software-uninstall', { host: h, apps: names.join('\n') }, { keyOf: function (ev) { return ev._rk || (ev.Host + '|' + ev.App); } });
          // audit 2026-07-23 deferred pass: per-key resub (re-click stacked handlers)
          resub('software-uninstall', run, {
            row: function (r) {
              var okR = /^(uninstalled|success|removed|ok)$/i.test(String(r.Result || ''));
              log.append({ text: '[' + r.Host + '] ' + r.App + ' (' + (r['Install Type'] || '?') + '): ' + (r.Result || '') + (r.Detail ? ' - ' + r.Detail : ''), level: okR ? 'ok' : 'err' });
            },
            log: function (l) { log.append(l); },
            error: function (e) { log.append({ text: e.text, level: 'err' }); },
            final: function () { log.banner('Uninstall complete on ' + h); }
          });
        };
      }

      // ---- TAB: Software Center Apps (CCM_Application list + app-action) ----
      function buildSoftwareCenter(panel) {
        var lay = el('div'); lay.style.cssText = 'display:flex;flex-direction:column;gap:12px;min-height:100%;padding:12px;box-sizing:border-box';
        panel.appendChild(lay);

        var ctlCard = ui.card({}); ctlCard.style.cssText += ';display:flex;flex-direction:column;gap:10px';
        ctlCard.appendChild(el('div', 'j-section-h', 'SOFTWARE CENTER APPS (CCM_Application)'));
        ctlCard.appendChild((function () { var d = el('div', 'muted', 'Query one host\'s Software Center catalog, check app(s), then Install / Uninstall / Reinstall / Repair. The chosen app Id(s) + host are sent to App Action across the whole target list.'); d.style.cssText = 'font-size:11.5px'; return d; })());
        var picker = hostPickerRow('Query host');
        ctlCard.appendChild(picker.el);
        var actRow = el('div'); actRow.style.cssText = 'display:flex;align-items:center;gap:8px;flex-wrap:wrap';
        var queryBtn = ui.button('Query Apps', { variant: 'cyan' });
        var installBtn = ui.button('Install', { variant: 'go' });
        var uninstallBtn = ui.button('Uninstall', { variant: 'danger' });
        var reinstallBtn = ui.button('Reinstall', { variant: 'gold' });
        var repairBtn = ui.button('Repair', { variant: 'gold' });
        var allTargetsCb = ui.checkbox('Run on ALL targets (not just the query host)', { color: 'var(--warn)', title: 'App Action runs across the whole shared target list; unchecked = only the query host.' });
        [queryBtn, installBtn, uninstallBtn, reinstallBtn, repairBtn].forEach(function (b) { actRow.appendChild(b); });
        actRow.appendChild(allTargetsCb);
        ctlCard.appendChild(actRow);
        // client quick-filter of the loaded catalog (desktop ddlAmFilter), via grid.setFilter
        var qfRow = el('div'); qfRow.style.cssText = 'display:flex;align-items:flex-end;gap:10px;flex-wrap:wrap';
        var quickSel = ui.select({ options: ['All Applications', 'Chrome', 'Edge', 'Microsoft 365', 'Microsoft Teams', 'Tanium'], title: 'Quick-filter the loaded catalog client-side (no re-query).' });
        qfRow.appendChild(ui.field('Quick filter', quickSel));
        ctlCard.appendChild(qfRow);
        lay.appendChild(ctlCard);

        var appCard = ui.card({}); appCard.style.cssText += ';flex:1;min-height:300px;display:flex;flex-direction:column';
        appCard.appendChild(el('div', 'j-section-h', 'CATALOG'));
        var appGrid = C.ResultsGrid({
          title: 'Software Center apps', selectable: true,
          // app-list: one row per app but Host repeats -> key by the CCM Id
          keyMode: function (r) { return r.Id != null ? String(r.Id) : (r.Host + '|' + r.Name); },
          columns: [
            { key: 'Name', label: 'NAME', width: 220 },
            { key: 'InstallState', label: 'INSTALL', width: 100, render: function (r) {
                var s = String(r.InstallState || '');
                var cls = /installed/i.test(s) ? 'st-ok' : /(error|failed)/i.test(s) ? 'st-bad' : 'st-warn';
                return { text: s, cls: cls };
            } },
            { key: 'Applicable', label: 'APPLIES', width: 80, render: function (r) { return asBool(r.Applicable) ? { text: 'Yes', cls: 'st-ok' } : { text: 'No', cls: 'cell-dim' }; } },
            { key: 'EvalState', label: 'EVAL', width: 90 },
            { key: 'Version', label: 'VERSION', width: 90 },
            { key: 'Id', label: 'ID', width: 230 },
            { key: 'IsMachineTarget', label: 'MACHINE', width: 80, type: 'bool' }
          ]
        });
        var appHolder = el('div'); appHolder.style.cssText = 'flex:1;min-height:0;display:flex'; appHolder.appendChild(appGrid.el);
        appCard.appendChild(appHolder);
        lay.appendChild(appCard);

        // desktop Populate-AppGrid: filter on Name -like "*key*" (the selected label IS the key)
        quickSel.addEventListener('change', function () {
          var k = quickSel.value;
          appGrid.setFilter(k === 'All Applications' ? null : function (r) {
            return String(r.Name || '').toLowerCase().indexOf(k.toLowerCase()) >= 0;
          });
        });

        var logCard = ui.card({}); logCard.classList.add('j-logdock');
        var log = C.ActivityLog({ title: 'SOFTWARE CENTER ACTIVITY', defaultName: 'WPT_SoftwareCenter' });
        logCard.appendChild(log.el); lay.appendChild(logCard);
        log.append({ text: 'Pick a host, Query Apps, check rows, then Install / Uninstall / Reinstall / Repair.', level: 'accent' });

        queryBtn.onclick = function () {
          var h = picker.host(); if (!h) { notice('Host required', 'Pick or type a host first.'); return; }
          appGrid.clear(); log.banner('Query Software Center apps - ' + h);
          var run = ctx.run('app-list', { host: h }, { keyOf: function (ev) { return ev.Id != null ? String(ev.Id) : (ev.Host + '|' + ev.Name); } });
          // audit 2026-07-23 deferred pass: per-key resub (re-click stacked handlers)
          resub('app-list', run, {
            row: function (r) { appGrid.upsert(r); },
            log: function (l) { log.append(l); },
            status: function (t) { log.append({ text: t, level: 'dim' }); },
            final: function () { log.append({ text: h + ': ' + appGrid.rows().length + ' app(s).', level: 'ok' }); }
          });
        };

        async function doAppAction(method) {
          if (needCred()) return;
          var checked = appGrid.getChecked();
          if (!checked.length) { notice('Nothing checked', 'Query a host then check the app(s) to ' + method + '.'); return; }
          var ids = checked.map(function (r) { return r.Id; }).filter(Boolean);
          var names = checked.map(function (r) { return r.Name; });
          var qHost = picker.host();
          var targets = allTargetsCb._cb.checked ? ctx.targets.raw : qHost;
          var nTargets = allTargetsCb._cb.checked ? ctx.targets.count() : 1;
          if (!targets) { notice('No targets', 'Pick a query host, or check "Run on ALL targets" with a populated list.'); return; }
          var ok = await ctx.confirm({
            title: method + ' Software Center app(s)', danger: (method !== 'Install' && method !== 'Repair'),
            body: method + ' <b>' + ids.length + '</b> app(s) on <b>' + nTargets + '</b> host(s)? Revision + machine/user targeting are auto-resolved from each host\'s live catalog.',
            list: names.slice(0, 8), okText: method, cancelText: 'Cancel'
          });
          if (!ok) { log.append({ text: method + ' cancelled by operator.', level: 'warn' }); return; }
          log.banner(method + ' - ' + ids.length + ' app(s) x ' + nTargets + ' host(s)');
          // app-action emits _rk = host|name|ver (or host|app on failure) -> key by _rk
          var run = ctx.run('app-action', { targets: targets, appids: ids.join('\n'), method: method }, { keyOf: function (ev) { return ev._rk || (ev.Host + '|' + ev.App); } });
          // audit 2026-07-23 deferred pass: per-key resub (re-click stacked handlers)
          resub('app-action', run, {
            row: function (r) {
              var okR = /^(triggered|success|ok|installed|uninstalled|repaired)$/i.test(String(r.Result || ''));
              log.append({ text: '[' + r.Host + '] ' + (r.App || '') + ' ' + (r.Method || method) + ': ' + (r.Result || '') + (r.Detail ? ' - ' + r.Detail : ''), level: okR ? 'ok' : 'err' });
            },
            log: function (l) { log.append(l); },
            status: function (t) { log.append({ text: t, level: 'dim' }); },
            error: function (e) { log.append({ text: e.text, level: 'err' }); },
            final: function () { log.banner(method + ' complete'); }
          });
        }
        installBtn.onclick = function () { doAppAction('Install'); };
        uninstallBtn.onclick = function () { doAppAction('Uninstall'); };
        reinstallBtn.onclick = function () { doAppAction('Reinstall'); };
        repairBtn.onclick = function () { doAppAction('Repair'); };
      }

      // ---- TAB: KB Scanner (kb-scan + trigger cycles + push/download + install) ----
      function buildKbScanner(panel) {
        var tab = makeRunTab(panel, {
          actionId: 'kb-scan', runLabel: 'SCAN INSTALLED KBs', cancelLabel: 'CANCEL KB SCAN',
          title: 'KB SCANNER', logName: 'WPT_KbScan',
          description: 'Parallel Get-HotFix inventory across the target list. One row per host x KB. Then trigger MECM cycles, push & download pending updates, or install specific KBs (MECM-first, .msu fallback).',
          // kb-scan emits _rk = host|kbID -> MUST key by _rk
          keyOf: function (ev) { return ev._rk || (ev.Host + '|' + ev.HotFixID); },
          keyMode: { rk: true },
          columns: [
            { key: 'Host', label: 'HOST', width: 130 },
            { key: 'HotFixID', label: 'KB ID', width: 110, render: function (r) { return { text: String(r.HotFixID || ''), cls: 'st-info' }; } },
            { key: 'Description', label: 'DESCRIPTION', width: 140, render: function (r) {
                var d = String(r.Description || '');
                if (d === 'Present') return { text: d, cls: 'st-ok' };
                if (d === 'Missing') return { text: d, cls: 'st-bad' };
                return { text: d };
            } },
            { key: 'InstalledOn', label: 'INSTALLED ON', width: 120 },
            { key: 'InstalledBy', label: 'INSTALLED BY' }
          ],
          settings: function (h) {
            var lbl = el('span', 'muted', 'Target KB:'); lbl.style.cssText = 'font-size:11px;margin-right:6px';
            var kb = ui.input({ placeholder: 'KB5062552 (optional)', title: 'Optional: per-host Present/Missing verdict + fleet compliance % for ONE KB. Blank lists all hotfixes.' });
            kb.style.cssText = 'width:160px;margin-right:16px';
            h.appendChild(lbl); h.appendChild(kb);
            var t = threadsInput(h, 24);
            return function () { return { threads: t(), kb: (kb.value || '').trim() }; };
          },
          params: function (api) { var s = api.getSettings(); return { threads: s.threads, kb: s.kb }; },
          onFinal: function (log, grid) {
            var hosts = {}, present = 0, missing = 0, verdict = false;
            grid.rows().forEach(function (r) {
              hosts[r.Host] = 1;
              if (r.Description === 'Present') { present++; verdict = true; }
              else if (r.Description === 'Missing') { missing++; verdict = true; }
            });
            if (verdict) {
              var total = Object.keys(hosts).length, reach = present + missing;
              var pct = reach > 0 ? Math.round(present / reach * 100) : 0;
              log.banner('KB verdict: ' + present + ' present, ' + missing + ' missing across ' + total + ' host(s) - ' + pct + '% of reachable have it.');
            } else {
              log.banner('KB scan complete: ' + grid.rows().length + ' hotfix(es) across ' + Object.keys(hosts).length + ' host(s)');
            }
          },
          intro: [{ text: 'KB Scanner ready. Leave Target KB blank to list all hotfixes, or enter one KB (e.g. KB5062552) for a per-host Present/Missing verdict + fleet %. Or use the cycle / install buttons.', level: 'accent' }],
          toolbarButtons: function (getGrid) {
            var exp = ui.ghostButton('Export CSV', { size: 'sm' });
            exp.onclick = function () { exportGridCsv(getGrid(), 'WPT_KbScan'); };
            return [exp];
          }
        });

        // KB cycle / install action bar below the grid
        var bar = el('div'); bar.style.cssText = 'display:flex;gap:10px;align-items:center;margin-top:10px;flex-wrap:wrap';
        var cycleBtn = ui.button('Trigger MECM Cycles', { variant: 'cyan', title: 'Trigger SW Updates Scan / Deploy / MachinePolicy discovery cycles.' });
        var pushBtn = ui.button('Push & Download', { variant: 'cyan', title: 'Query pending MECM updates and trigger download (108) + deployment (114) cycles.' });
        var kbInput = ui.input({ placeholder: 'KB5060999 KB5062552', title: 'KBs to install (comma/space separated).' }); kbInput.style.width = '220px';
        var noRebootCb = ui.checkbox('No auto-reboot', { checked: true, color: 'var(--cyan)' });
        var msuFile = el('input'); msuFile.type = 'file'; msuFile.accept = '.msu'; msuFile.style.display = 'none';
        var msuBtn = ui.ghostButton('MSU fallback...', { size: 'sm', title: 'Optional .msu used as the fallback for any KB not deployed in MECM.' });
        var msuLabel = el('span', 'muted'); msuLabel.style.fontSize = '11px';
        msuBtn.onclick = function () { msuFile.value = ''; msuFile.click(); };
        var msuPath = null;
        msuFile.addEventListener('change', async function () {
          var f = msuFile.files && msuFile.files[0]; if (!f) return;
          msuLabel.textContent = 'uploading ' + f.name + '...';
          try { msuPath = await ctx.uploadFile(f); msuLabel.textContent = 'MSU: ' + f.name; }
          catch (e) { msuPath = null; msuLabel.textContent = 'upload failed'; tab.log.append({ text: 'MSU upload failed: ' + (e && e.message), level: 'err' }); }
        });
        var installBtn = ui.button('Install KBs', { variant: 'danger', title: 'MECM-first install of the listed KBs; .msu fallback for any not deployed.' });
        [cycleBtn, pushBtn, el('span'), ui.label('KBs:'), kbInput, msuBtn, msuLabel, noRebootCb, installBtn].forEach(function (n) { bar.appendChild(n); });
        tab.prog.el.parentNode.appendChild(bar);

        var kbUnsubs = {};   // actionId -> live unsub; a re-click must replace, not stack, its handler
        function kbFleet(actionId, params, label, danger, confirmBody) {
          return async function () {
            if (!ctx.targets.count()) { notice('No Targets', 'Build the host list on Targets first.'); return; }
            var act = findManifestAction(actionId);
            if (act && act.destructive && needCred()) return;
            if (confirmBody) {
              var ok = await ctx.confirm({ title: label, danger: !!danger, body: confirmBody, okText: 'Proceed', cancelText: 'Cancel' });
              if (!ok) { tab.log.append({ text: label + ' cancelled.', level: 'warn' }); return; }
            }
            tab.log.banner(label + ' - ' + ctx.targets.count() + ' host(s)');
            [cycleBtn, pushBtn, installBtn].forEach(function (b) { b.disabled = true; });
            var run = ctx.run(actionId, Object.assign({ targets: ctx.targets.raw }, params));
            if (kbUnsubs[actionId]) { var i = unsubs.indexOf(kbUnsubs[actionId]); if (i >= 0) unsubs.splice(i, 1); kbUnsubs[actionId](); }
            kbUnsubs[actionId] = track(run.subscribe({
              status: function (t) { tab.prog.setPhase(t); },
              progress: function (p) { tab.prog.setProgress(p.done, p.total); },
              row: function (r) { tab.log.append({ text: '[' + r.Host + '] ' + (r.Status || r.Result || JSON.stringify(stripRow(r))), level: /error|fail/i.test(JSON.stringify(r)) ? 'warn' : 'ok' }); },
              log: function (l) { tab.log.append(l); },
              error: function (e) { tab.log.append({ text: e.text, level: 'err' }); },
              final: function () { tab.log.banner(label + ' complete'); },
              active: function (a) { if (!a) [cycleBtn, pushBtn, installBtn].forEach(function (b) { b.disabled = false; }); }
            }));
          };
        }
        function stripRow(r) { var o = {}; Object.keys(r).forEach(function (k) { if (k.charAt(0) !== '_' && k !== 'type' && k !== 'Host') o[k] = r[k]; }); return o; }

        cycleBtn.onclick = kbFleet('kb-trigger-mecm', {}, 'Trigger MECM Cycles', false, null);
        pushBtn.onclick = kbFleet('kb-push-download', {}, 'KB Push & Download', false, null);
        installBtn.onclick = function () {
          var kbs = (kbInput.value || '').trim();
          if (!kbs) { notice('KBs required', 'Enter at least one KB (e.g. KB5060999).'); return; }
          var body = 'Push the listed KB(s) to <b>' + ctx.targets.count() + '</b> workstation(s)?<br>KBs: <b>' + esc(kbs) + '</b><br>MECM is tried first; the optional .msu is the fallback.';
          kbFleet('kb-install', { kbs: kbs, msu: msuPath || '', noreboot: noRebootCb._cb.checked }, 'Install KBs', true, body)();
        };
      }

      // ---- TAB: Verify Patch (read-only post-patch poll) ----
      // SCCM-only polish (NIPR fork): after a patch wave, re-poll each host's
      // pending/installed update state until it settles. Mirrors PIRS post-patch
      // verify, but AFNET-safe (engine reaches hosts over WinRM/TCP, not DCOM/ICMP).
      function buildVerifyPatch(panel) {
        makeRunTab(panel, {
          actionId: 'verify-patch', runLabel: 'VERIFY PATCH', cancelLabel: 'CANCEL VERIFY',
          title: 'VERIFY PATCH', logName: 'WPT_VerifyPatch',
          description: 'Read-only post-patch poll. For each target, re-checks pending/installed update state every interval up to Max polls, until it settles. Requires the SCCM (MECM) client on each target. One row per host x update.',
          // verify-patch emits _rk = host|update -> MUST key by _rk
          keyOf: function (ev) { return ev._rk || (ev.Host + '|' + ev.Update); },
          keyMode: { rk: true },
          columns: [
            { key: 'Host', label: 'HOST', width: 130 },
            { key: 'Update', label: 'UPDATE', width: 200, render: function (r) { return { text: String(r.Update == null ? '' : r.Update), cls: 'st-info' }; } },
            { key: 'State', label: 'STATE', width: 120, render: function (r) {
                var s = String(r.State == null ? '' : r.State);
                return s ? { text: s } : { text: '', cls: 'cell-dim' };
            } },
            { key: 'Status', label: 'STATUS', render: function (r) {
                var s = String(r.Status == null ? '' : r.Status);
                if (!s) return { text: '', cls: 'cell-dim' };
                if (/^installed$/i.test(s)) return { text: s, cls: 'st-ok' };
                if (/error/i.test(s)) return { text: s, cls: 'st-bad' };
                if (/(pending|installing)/i.test(s)) return { text: s, cls: 'st-warn' };
                return { text: s };
            } }
          ],
          settings: function (h) {
            var lbl = el('span', 'muted', 'KB/update filter:'); lbl.style.cssText = 'font-size:11px;margin-right:6px';
            var kb = ui.input({ placeholder: 'KB5062552 (optional)', title: 'Optional: only verify updates whose name matches this KB/text. Blank verifies all pending.' });
            kb.style.cssText = 'width:160px;margin-right:16px';
            h.appendChild(lbl); h.appendChild(kb);
            var polls = ui.number({ value: 6, min: 1, max: 60, title: 'How many times to re-poll each host before giving up (default 6).' });
            polls.style.width = '90px';
            h.appendChild(ui.field('Max polls', polls));
            var iv = ui.number({ value: 30, min: 5, max: 600, title: 'Seconds to wait between polls (default 30).' });
            iv.style.width = '90px';
            h.appendChild(ui.field('Interval (s)', iv));
            return function () {
              return {
                kbFilter: (kb.value || '').trim(),
                maxPolls: Math.max(1, Math.min(60, parseInt(polls.value, 10) || 6)),
                intervalSeconds: Math.max(5, Math.min(600, parseInt(iv.value, 10) || 30))
              };
            };
          },
          params: function (api) { var s = api.getSettings(); return { kbFilter: s.kbFilter, maxPolls: s.maxPolls, intervalSeconds: s.intervalSeconds }; },
          intro: [{ text: 'Verify Patch ready (read-only). Needs the SCCM/MECM client on each target. Add hosts on Targets, set credentials, optionally enter a KB filter, then VERIFY PATCH.', level: 'accent' }],
          toolbarButtons: function (getGrid) {
            var exp = ui.ghostButton('Export CSV', { size: 'sm' });
            exp.onclick = function () { exportGridCsv(getGrid(), 'WPT_VerifyPatch'); };
            return [exp];
          }
        });
      }

      // ---- TAB: App Updater (verify + apply profiles) ----
      function buildAppUpdater(panel) {
        var PROFILES = ['Microsoft 365 - Force Update', 'Windows Defender - Update Definitions', 'Trellix / McAfee - Update Definitions', 'Google Chrome - Update (Software Center)', 'Google Chrome - Update (Internet - Google Update)', 'Microsoft Edge - Update', 'Microsoft 365 - Update (User Visible)', 'Oracle Java - Software Center', 'Windows Unquoted Service Path - Remediate', 'MSXML 4.0 - Uninstall', 'Apache Log4j - Replace Vulnerable Jars', 'Office VBA Project Access - Disable (AccessVBOM)'];
        var profSel;
        var tab = makeRunTab(panel, {
          actionId: 'app-update-verify', runLabel: 'VERIFY PROFILE', cancelLabel: 'CANCEL VERIFY',
          title: 'APP UPDATER', logName: 'WPT_AppUpdate',
          description: 'Verify (read-only) the installed version / last-updated of an app-update profile across the fleet, then Apply the profile (or a custom command) to remediate.',
          columns: [
            { key: 'Host', label: 'HOST', width: 140 },
            { key: 'Version', label: 'VERSION', width: 130 },
            { key: 'LastUpdated', label: 'LAST UPDATED', width: 140 },
            { key: 'Verified', label: 'VERIFIED', width: 90, render: function (r) { return asBool(r.Verified) ? { text: 'Yes', cls: 'st-ok' } : { text: 'No', cls: 'st-warn' }; } },
            { key: 'Detail', label: 'DETAIL' }
          ],
          rowClass: function (r) { return r.Verified == null ? '' : (asBool(r.Verified) ? 'row-ok' : 'row-warn'); },
          selectable: true,   // check the (failed-verify) rows, then Apply to Selected
          settings: function (h) {
            profSel = ui.select({ options: PROFILES });
            profSel.style.minWidth = '300px';
            h.appendChild(ui.field('Profile', profSel));
            var t = threadsInput(h, 16);
            return function () { return { profile: profSel.value, threads: t() }; };
          },
          params: function (api) { return { profile: api.getSettings().profile, threads: api.getSettings().threads }; },
          onFinal: function (log, grid) { log.banner('Verify complete: ' + grid.rows().length + ' host(s)'); },
          intro: [{ text: 'App Updater ready. Choose a profile, VERIFY, then APPLY to remediate.', level: 'accent' }]
        });

        // APPLY action bar (with optional custom command)
        var bar = el('div'); bar.style.cssText = 'display:flex;gap:10px;align-items:flex-end;margin-top:10px;flex-wrap:wrap';
        var customWrap = el('div'); customWrap.style.cssText = 'display:none;flex:1;min-width:240px';
        var customCmd = ui.textarea({ placeholder: 'Custom command (only for "Custom Command" profile)', rows: 2 });
        customWrap.appendChild(ui.field('Custom command', customCmd));
        var applySel = ui.select({ options: PROFILES.concat(['Custom Command']) }); applySel.style.minWidth = '300px';
        applySel.addEventListener('change', function () { customWrap.style.display = (applySel.value === 'Custom Command') ? 'block' : 'none'; });
        var applyBtn = ui.button('APPLY (ALL TARGETS)', { variant: 'danger', title: 'Run the profile (or custom command) remotely on every target.' });
        var applySelBtn = ui.button('Apply to Selected', { variant: 'gold', title: 'Apply only to the CHECKED hosts in the verify grid (e.g. just the ones that failed verify).' });
        bar.appendChild(ui.field('Apply profile', applySel));
        bar.appendChild(applyBtn);
        bar.appendChild(applySelBtn);
        bar.appendChild(customWrap);
        tab.prog.el.parentNode.appendChild(bar);

        // shared apply: whole target list OR a checked subset of the verify grid.
        async function applyProfile(targetsRaw, count, noun) {
          if (!count) { notice('No Targets', noun === 'selected' ? 'Check at least one host in the verify grid first.' : 'Build the host list first.'); return; }
          if (needCred()) return;
          var prof = applySel.value;
          if (prof === 'Custom Command' && !customCmd.value.trim()) { notice('Command required', 'Enter the custom command to run.'); return; }
          var isCustom = (prof === 'Custom Command');
          // audit 2026-07-23: custom commands must go through ctx.arm - ConfirmDialog
          // ignores confirmWord, so the typed-RUN gate passed to ctx.confirm was inert.
          var dlgOpts = {
            title: 'Apply ' + prof, danger: true,
            body: 'Run profile <b>' + esc(prof) + '</b> on <b>' + count + '</b> ' + noun + ' host(s)? This changes machines.'
              + (isCustom ? '<br><br>This runs an <b>arbitrary remote command</b> you typed, with admin rights, on every target above.' : ''),
            okText: 'Apply', cancelText: 'Cancel'
          };
          if (isCustom) { dlgOpts.confirmWord = 'RUN'; dlgOpts.banner = 'ARBITRARY REMOTE COMMAND - RUNS WITH ADMIN RIGHTS ON EVERY TARGET'; }
          var ok = await (isCustom ? ctx.arm(dlgOpts) : ctx.confirm(dlgOpts));
          if (!ok) { tab.log.append({ text: 'Apply cancelled.', level: 'warn' }); return; }
          tab.log.banner('Apply ' + prof + ' - ' + count + ' ' + noun + ' host(s)');
          applyBtn.disabled = applySelBtn.disabled = true;
          var run = ctx.run('app-update-apply', { targets: targetsRaw, profile: prof, customcommand: customCmd.value });
          // audit 2026-07-23 deferred pass: per-key resub (re-click stacked handlers;
          // key shared with the Beta tab's apply) - onReplace unfreezes the buttons.
          resub('app-update-apply', run, {
            status: function (t) { tab.prog.setPhase(t); },
            progress: function (p) { tab.prog.setProgress(p.done, p.total); },
            row: function (r) { tab.log.append({ text: '[' + r.Host + '] ' + (r.Status || '') + (r.Detail ? ' - ' + r.Detail : ''), level: /error|fail/i.test(String(r.Status)) ? 'err' : (/pending/i.test(String(r.Status)) ? 'warn' : 'ok') }); },
            log: function (l) { tab.log.append(l); },
            error: function (e) { tab.log.append({ text: e.text, level: 'err' }); },
            final: function () { tab.log.banner('Apply complete'); },
            active: function (a) { if (!a) { applyBtn.disabled = false; applySelBtn.disabled = false; } }
          }, function () { applyBtn.disabled = false; applySelBtn.disabled = false; });
        }
        applyBtn.onclick = function () { applyProfile(ctx.targets.raw, ctx.targets.count(), 'target'); };
        applySelBtn.onclick = function () { var ch = tab.grid.getChecked().map(function (r) { return r.Host; }).filter(Boolean); applyProfile(ch.join('\n'), ch.length, 'selected'); };
      }

      // ---- TAB: Beta (EXPERIMENTAL, AFNET-unproven fixes; isolated from the proven tabs) ----
      // Reuses the proven app-update-verify / app-update-apply engine actions, but the profiles
      // it lists ([BETA] ...) live only here - never in the App Updater dropdown. Verify is
      // read-only; Apply is destructive (needs an admin session) + an extra "experimental" confirm.
      function buildBeta(panel) {
        // fix metadata: engine profile name + supported methods + optional input + AFNET how-to
        var BETA = [
          { profile: '[BETA] Adobe Acrobat/Reader - Update',
            methods: [{ value: 'sc', label: 'Software Center (MECM)' }, { value: 'direct', label: 'Direct (Adobe updater)' }],
            input: { label: 'Software Center app name (optional)', placeholder: 'blank = trigger all deployed Adobe updates; or the exact app name', methods: ['sc'] },
            howto: 'Adobe Acrobat/Reader is the single biggest finding family (~every host).<br><br>'
                 + '<b>Software Center (MECM) - preferred on AFNET:</b> first deploy the patched Adobe Acrobat/Reader in MECM (a Required or Available deployment to the target collection). Then run this with the box blank to trigger the ConfigMgr Application + Software-Update cycles so the deployed update installs now; or type the exact Software Center application name to install just that app immediately.<br><br>'
                 + '<b>Direct:</b> runs Adobe\'s own update task / AdobeARM on each host. Only works if the host can reach an Adobe update source (internet, or an internal AUSST). On a locked-down box without AUSST this usually does nothing - hence Software Center is preferred.' },
          { profile: '[BETA] SMB Signing - Require',
            methods: [{ value: 'direct', label: 'Direct (registry)' }],
            howto: 'Sets RequireSecuritySignature=1 on the LanmanServer + LanmanWorkstation services (SMB signing required).<br><br>'
                 + '<b>AFNET:</b> normally enforced by GPO; this writes it directly to the host (local registry, no internet). <b>Takes effect after the Server/Workstation service restarts or a reboot.</b> No Software Center path - it is a registry setting. Nothing to fill in.' },
          { profile: '[BETA] RDP - Require NLA',
            methods: [{ value: 'direct', label: 'Direct (registry)' }],
            howto: 'Sets RDP-Tcp UserAuthentication=1 (Network Level Authentication required for RDP).<br><br>'
                 + '<b>AFNET:</b> normally a GPO/STIG setting; this writes it directly. Effective for new RDP connections immediately. No Software Center path. Nothing to fill in.' },
          { profile: '[BETA] ICMP Timestamp - Block (firewall)',
            methods: [{ value: 'direct', label: 'Direct (firewall)' }],
            howto: 'Adds a Windows Firewall rule blocking ICMPv4 type 13 (timestamp request/reply), inbound + outbound, clearing the ICMP Timestamp Disclosure finding.<br><br>'
                 + '<b>AFNET:</b> local firewall change, effective immediately (built-in NetSecurity module, Win10/11). No Software Center path. Nothing to fill in.' }
        ];
        function fixByProfile(p) { for (var i = 0; i < BETA.length; i++) if (BETA[i].profile === p) return BETA[i]; return BETA[0]; }

        var warn = el('div'); warn.style.cssText = 'margin:12px 12px 0;padding:10px 14px;border:1px solid var(--warn);border-left:3px solid var(--warn);border-radius:4px;background:rgba(230,180,70,.10);color:var(--warn);font-size:12px;line-height:1.5';
        warn.innerHTML = '<b>BETA &mdash; experimental remediations.</b> Unproven on AFNET. Some go through <b>Software Center (MECM)</b>, others apply <b>directly</b> (registry / firewall / the app&rsquo;s updater). Click <b>How to</b> for each fix&rsquo;s AFNET steps. <b>VERIFY first, test one host, then Apply.</b>';
        panel.appendChild(warn);

        var fixSel, methodSel, methodField, argInput, argLabel, argWrap;
        function needsInput() { var b = fixByProfile(fixSel.value); return !!(b.input && b.input.methods.indexOf(methodSel.value) >= 0); }
        function betaParams() { return { profile: fixSel.value, method: methodSel.value, arg: needsInput() ? (argInput.value || '') : '' }; }

        var tab = makeRunTab(panel, {
          actionId: 'app-update-verify', runLabel: 'VERIFY (READ-ONLY)', cancelLabel: 'CANCEL VERIFY',
          title: 'BETA FIXES (EXPERIMENTAL)', logName: 'WPT_Beta',
          description: 'Experimental, AFNET-unproven fixes for findings the proven tabs do not cover yet. Pick a fix, choose its method, read How to, VERIFY (read-only), then APPLY.',
          columns: [
            { key: 'Host', label: 'HOST', width: 140 },
            { key: 'Version', label: 'CURRENT STATE', width: 220 },
            { key: 'Verified', label: 'COMPLIANT', width: 100, render: function (r) { return r.Verified == null ? { text: 'info', cls: 'cell-dim', title: 'Informational only - this fix has no pass/fail check (e.g. Adobe reports its installed version). Compare Current State to your patch baseline.' } : (asBool(r.Verified) ? { text: 'Yes', cls: 'st-ok' } : { text: 'No', cls: 'st-warn' }); } },
            { key: 'Detail', label: 'DETAIL' }
          ],
          rowClass: function (r) { return r.Verified == null ? '' : (asBool(r.Verified) ? 'row-ok' : 'row-warn'); },
          selectable: true,
          settings: function (h) {
            fixSel = ui.select({ options: BETA.map(function (b) { return { value: b.profile, label: b.profile.replace('[BETA] ', '') }; }) });
            fixSel.style.minWidth = '280px';
            h.appendChild(ui.field('Beta fix', fixSel));
            methodSel = ui.select({ options: [] });
            methodField = ui.field('Method', methodSel); h.appendChild(methodField);
            argWrap = el('div'); argWrap.style.cssText = 'display:none;flex-direction:column;gap:4px';
            argLabel = el('div'); argLabel.style.cssText = 'font-size:11px;color:var(--text-dim);font-family:var(--ui)';
            argInput = ui.input({}); argInput.style.minWidth = '300px';
            argWrap.appendChild(argLabel); argWrap.appendChild(argInput);
            h.appendChild(argWrap);
            var howtoBtn = ui.ghostButton('How to', { title: 'AFNET instructions for the selected fix' });
            h.appendChild(howtoBtn);
            var t = threadsInput(h, 12);
            function syncInput() {
              var b = fixByProfile(fixSel.value);
              argWrap.style.display = needsInput() ? 'flex' : 'none';
              if (b.input) { argLabel.textContent = b.input.label; argInput.placeholder = b.input.placeholder || ''; }
            }
            function rebuildMethods() {
              var b = fixByProfile(fixSel.value);
              methodSel.innerHTML = '';
              b.methods.forEach(function (m) { var o = document.createElement('option'); o.value = m.value; o.textContent = m.label; methodSel.appendChild(o); });
              methodField.style.display = (b.methods.length > 1) ? '' : 'none';
              syncInput();   // method reset to first option -> resync the input box
            }
            fixSel.addEventListener('change', rebuildMethods);   // fix change: rebuild methods + resync
            methodSel.addEventListener('change', syncInput);     // method change: only resync the input (don't rebuild -> keeps the value)
            howtoBtn.onclick = function () { var b = fixByProfile(fixSel.value); ctx.confirm({ title: 'How to: ' + b.profile.replace('[BETA] ', ''), body: b.howto, okText: 'Got it', cancelText: null }); };
            rebuildMethods();
            return function () { var p = betaParams(); p.threads = t(); return p; };
          },
          params: function (api) { return api.getSettings(); },
          onFinal: function (log, grid) { log.banner('Verify complete: ' + grid.rows().length + ' host(s)'); },
          intro: [{ text: 'BETA tab - experimental fixes. Pick a fix, read How to, VERIFY, then APPLY. Test on one host first.', level: 'warn' }]
        });

        // APPLY bar (uses the SAME fix / method / value chosen above)
        var bar = el('div'); bar.style.cssText = 'display:flex;gap:10px;align-items:center;margin-top:10px;flex-wrap:wrap';
        var applyBtn = ui.button('APPLY (ALL TARGETS)', { variant: 'danger', title: 'Run the selected experimental fix on every target. Test on one host first.' });
        var applySelBtn = ui.button('Apply to Selected', { variant: 'gold', title: 'Apply only to the CHECKED hosts in the verify grid.' });
        bar.appendChild(applyBtn); bar.appendChild(applySelBtn);
        tab.prog.el.parentNode.appendChild(bar);

        async function applyProfile(targetsRaw, count, noun) {
          if (!count) { notice('No Targets', noun === 'selected' ? 'Check at least one host in the verify grid first.' : 'Build the host list first.'); return; }
          if (needCred()) return;
          var bp = betaParams();
          var b = fixByProfile(bp.profile);
          var methodLabel = (b.methods.filter(function (m) { return m.value === bp.method; })[0] || {}).label || bp.method;
          var ok = await ctx.confirm({
            title: 'Apply BETA fix', danger: true,
            body: 'Run <b>' + esc(bp.profile.replace('[BETA] ', '')) + '</b> via <b>' + esc(methodLabel) + '</b>' + (bp.arg ? ' (value: <b>' + esc(bp.arg) + '</b>)' : '') + ' on <b>' + count + '</b> ' + noun + ' host(s)?<br><br>This is <b>experimental / unproven on AFNET</b> and changes machines. Test on a single host first.',
            list: ['Some fixes only take effect after a reboot or service restart.'], okText: 'Apply (beta)', cancelText: 'Cancel'
          });
          if (!ok) { tab.log.append({ text: 'Beta apply cancelled.', level: 'warn' }); return; }
          tab.log.banner('Apply ' + bp.profile + ' [' + methodLabel + '] - ' + count + ' ' + noun + ' host(s)');
          applyBtn.disabled = applySelBtn.disabled = true;
          var run = ctx.run('app-update-apply', { targets: targetsRaw, profile: bp.profile, method: bp.method, arg: bp.arg });
          // audit 2026-07-23 deferred pass: per-key resub (re-click stacked handlers;
          // key shared with the App Updater apply) - onReplace unfreezes the buttons.
          resub('app-update-apply', run, {
            status: function (t) { tab.prog.setPhase(t); },
            progress: function (p) { tab.prog.setProgress(p.done, p.total); },
            row: function (r) { tab.log.append({ text: '[' + r.Host + '] ' + (r.Status || '') + (r.Detail ? ' - ' + r.Detail : ''), level: /error|fail/i.test(String(r.Status)) ? 'err' : (/pending/i.test(String(r.Status)) ? 'warn' : 'ok') }); },
            log: function (l) { tab.log.append(l); },
            error: function (e) { tab.log.append({ text: e.text, level: 'err' }); },
            final: function () { tab.log.banner('Beta apply complete'); },
            active: function (a) { if (!a) { applyBtn.disabled = false; applySelBtn.disabled = false; } }
          }, function () { applyBtn.disabled = false; applySelBtn.disabled = false; });
        }
        applyBtn.onclick = function () { applyProfile(ctx.targets.raw, ctx.targets.count(), 'target'); };
        applySelBtn.onclick = function () { var ch = tab.grid.getChecked().map(function (r) { return r.Host; }).filter(Boolean); applyProfile(ch.join('\n'), ch.length, 'selected'); };
      }

      // ---- TAB: Cleanup (disk cleanup, dry-run default on) ----
      function buildCleanup(panel) {
        var opSel, daysInput, dryCb, getThreads;
        makeRunTab(panel, {
          actionId: 'cleanup-disk', runLabel: 'RUN CLEANUP', cancelLabel: 'STOP CLEANUP',
          title: 'DISK CLEANUP', logName: 'WPT_Cleanup',
          description: 'Temp-file cleanup and/or stale user-profile removal (by age). DRY RUN defaults ON - enumerate only, no deletion. Unchecking Dry run PERMANENTLY deletes.',
          columns: [
            { key: 'Host', label: 'HOST', width: 130 },
            { key: 'TempMB', label: 'TEMP MB', width: 80 },
            { key: 'TempFiles', label: 'FILES', width: 70 },
            { key: 'CacheMB', label: 'CACHE MB', width: 80 },
            { key: 'ProfilesFound', label: 'PROF FOUND', width: 90 },
            { key: 'ProfilesRemoved', label: 'REMOVED', width: 80 },
            { key: 'Skipped', label: 'SKIP', width: 60 },
            { key: 'Status', label: 'STATUS', width: 90, render: function (r) { var s = String(r.Status || ''); return { text: s, cls: /error|fail/i.test(s) ? 'st-bad' : /dry/i.test(s) ? 'st-info' : 'st-ok' }; } },
            { key: 'Detail', label: 'DETAIL' }
          ],
          rowClass: function (r) { var s = String(r.Status || ''); return /error|fail/i.test(s) ? 'row-bad' : ''; },
          settings: function (h) {
            opSel = ui.select({ options: [{ value: 'TempFiles', label: 'Temp files' }, { value: 'OldProfiles', label: 'Old profiles' }, { value: 'CcmCache', label: 'MECM cache (ccmcache)' }, { value: 'Both', label: 'Both (temp + profiles)' }], value: 'TempFiles' });
            h.appendChild(ui.field('Operation', opSel));
            daysInput = ui.number({ value: 60, min: 1, max: 3650, title: 'Stale profile age threshold (days).' }); daysInput.style.width = '90px';
            h.appendChild(ui.field('Profile age (days)', daysInput));
            dryCb = ui.checkbox('Dry run (enumerate, do not delete)', { checked: true, color: 'var(--warn)' });
            h.appendChild(dryCb);
            getThreads = threadsInput(h, 12);
            return function () { return { operation: opSel.value, days: daysInput.value, dryrun: dryCb._cb.checked, threads: getThreads() }; };
          },
          params: function (api) { var s = api.getSettings(); return { operation: s.operation, days: s.days, dryrun: s.dryrun, threads: s.threads }; },
          confirmBeforeRun: function (api) {
            var s = api.getSettings();
            if (s.dryrun) return Promise.resolve(true);   // dry-run is safe
            if (needCred()) return Promise.resolve(false);
            return ctx.arm({
              title: 'Confirm LIVE Disk Cleanup',
              body: 'Dry run is OFF. This PERMANENTLY deletes ' + (s.operation === 'TempFiles' ? 'temp files' : s.operation === 'OldProfiles' ? ('user profiles idle > ' + s.days + ' days') : s.operation === 'CcmCache' ? 'the MECM cache (C:\\Windows\\ccmcache)' : ('temp files AND stale profiles (> ' + s.days + ' days)')) + ' on <b>' + ctx.targets.count() + '</b> host(s) and cannot be undone. Proceed?',
              confirmWord: 'CLEAN',
              okText: 'Delete', cancelText: 'Cancel'
            });
          },
          onFinal: function (log, grid) { log.banner('Cleanup complete: ' + grid.rows().length + ' host(s)'); },
          intro: [{ text: 'Disk Cleanup ready. DRY RUN is on by default - uncheck it to actually delete.', level: 'accent' }]
        });
      }

      // ---- TAB: Reg Key Fixes (registry-key-scan + apply) ----
      function buildRegKeys(panel) {
        var FIXES = ['BHI', 'Edge_ImportSearchEngine'];
        var fixSel, rebootCb, getThreads;
        var tab = makeRunTab(panel, {
          actionId: 'registry-key-scan', runLabel: 'SCAN FIX', cancelLabel: 'CANCEL SCAN',
          title: 'REG KEY FIXES (STIG / CVE)', logName: 'WPT_RegKey',
          description: 'Scan a STIG/CVE fix from the built-in catalog: read current values, compare to expected. Then Apply to write + read back. Apply can optionally notify the user and force-reboot 1 hour later.',
          columns: [
            { key: 'Host', label: 'HOST', width: 130 },
            { key: 'RegPath', label: 'REG PATH', width: 260 },
            { key: 'CurrentValue', label: 'CURRENT', width: 110 },
            { key: 'ExpectedValue', label: 'EXPECTED', width: 110 },
            { key: 'Compliant', label: 'COMPLIANT', width: 90, render: function (r) { return asBool(r.Compliant) ? { text: 'Yes', cls: 'st-ok' } : { text: 'No', cls: 'st-bad' }; } },
            { key: 'Status', label: 'STATUS' }
          ],
          // registry-key-scan is one row per host (default Host key is fine)
          keyMode: { hostCol: 'Host' },
          selectable: true,   // check hosts -> Select Vulnerable / Verify Selected
          rowClass: function (r) { return r.Compliant == null ? '' : (asBool(r.Compliant) ? 'row-ok' : 'row-warn'); },
          settings: function (h) {
            fixSel = ui.select({ options: FIXES }); fixSel.style.minWidth = '240px';
            h.appendChild(ui.field('Fix', fixSel));
            getThreads = threadsInput(h, 24);
            return function () { return { cvekey: fixSel.value, threads: getThreads() }; };
          },
          params: function (api) { var s = api.getSettings(); return { cvekey: s.cvekey, threads: s.threads }; },
          onFinal: function (log, grid) { var nc = grid.rows().filter(function (r) { return !asBool(r.Compliant); }).length; log.banner('Scan complete: ' + grid.rows().length + ' host(s), ' + nc + ' non-compliant'); },
          intro: [{ text: 'Reg Key Fixes ready. Choose a fix, SCAN, then APPLY to remediate. Use Select Vulnerable to check non-compliant hosts and Verify Selected to re-scan after applying.', level: 'accent' }],
          // grid-toolbar follow-ons: check the non-compliant hosts, and re-scan the
          // checked set to confirm a fix took (same cvekey) - results upsert in place.
          toolbarButtons: function (getGrid) {
            var selVuln = ui.ghostButton('Select Vulnerable', { size: 'sm', title: 'Check every host that scanned NON-compliant.' });
            selVuln.onclick = function () { getGrid().selectWhere(function (r) { return !asBool(r.Compliant); }); };
            var verifyBtn = ui.ghostButton('Verify Selected', { size: 'sm', title: 'Re-scan the checked host(s) with the same fix to confirm the change took.' });
            verifyBtn.onclick = function () {
              var hosts = getGrid().getChecked().map(function (r) { return r.Host; }).filter(Boolean);
              if (!hosts.length) { notice('Nothing selected', 'Check one or more hosts to verify (or use Select Vulnerable).'); return; }
              var fix = fixSel.value;
              tab.log.banner('Verify ' + fix + ' - re-scan ' + hosts.length + ' host(s)');
              var vrun = ctx.run('registry-key-scan', { targets: hosts.join('\n'), cvekey: fix, threads: getThreads() });
              // audit 2026-07-23 deferred pass: per-key resub - this shares the
              // 'wpt/registry-key-scan' key with the tab's main SCAN, so re-running
              // either must replace (not stack) the other's handler.
              resub('registry-key-scan', vrun, {
                status: function (t) { tab.prog.setPhase(t); },
                progress: function (p) { tab.prog.setProgress(p.done, p.total); },
                row: function (r) { getGrid().upsert(r); tab.log.append({ text: '[' + r.Host + '] ' + (asBool(r.Compliant) ? 'compliant' : 'NON-COMPLIANT') + (r.Status ? ' - ' + r.Status : ''), level: asBool(r.Compliant) ? 'ok' : 'warn' }); },
                log: function (l) { tab.log.append(l); },
                error: function (e) { tab.log.append({ text: e.text, level: 'err' }); },
                final: function () { var nc = getGrid().rows().filter(function (r) { return !asBool(r.Compliant); }).length; tab.log.banner('Verify complete: ' + nc + ' still non-compliant'); }
              });
            };
            return [selVuln, verifyBtn];
          }
        });

        // Cross-tool handoff: the Reports Remediation Router / Third-Party Catalog can
        // open us straight onto a specific reg-key fix (e.g. BHI for CVE-2022-0001) by
        // staging a cvekey on Janet.handoff. Pre-select it if it names a known fix. We
        // only PEEK (do not take) so the Targets tab still offers the host handoff; the
        // affected hosts were already loaded into the shared target list by the router.
        try {
          var _ho = (window.Janet && Janet.handoff && Janet.handoff.peek) ? Janet.handoff.peek() : null;
          var _ck = (_ho && _ho.extra && _ho.extra.cvekey) ? String(_ho.extra.cvekey) : '';
          if (_ck && fixSel && FIXES.indexOf(_ck) !== -1) { fixSel.value = _ck; }
        } catch (e) {}

        // APPLY bar
        var bar = el('div'); bar.style.cssText = 'display:flex;gap:12px;align-items:center;margin-top:10px;flex-wrap:wrap';
        rebootCb = ui.checkbox('Notify user + reboot 1 hour after a successful apply', { color: 'var(--warn)' });
        var applyUnsub = null;   // re-clicking APPLY FIX must replace, not stack, its handler
        var applyBtn = ui.button('APPLY FIX', { variant: 'danger', title: 'Write the selected STIG/CVE fix to the targets.' });
        bar.appendChild(applyBtn); bar.appendChild(rebootCb);
        tab.prog.el.parentNode.appendChild(bar);

        applyBtn.onclick = async function () {
          if (!ctx.targets.count()) { notice('No Targets', 'Build the host list first.'); return; }
          if (needCred()) return;
          var fix = fixSel.value, rebootAfter = rebootCb._cb.checked;
          var ok = await ctx.confirm({
            title: 'Apply ' + fix, danger: true,
            body: 'Apply the <b>' + esc(fix) + '</b> registry fix to <b>' + ctx.targets.count() + '</b> host(s)?' + (rebootAfter ? '<br><br><b>Every successfully-patched host will be FORCE-rebooted ~1 hour later.</b>' : ''),
            okText: 'Apply', cancelText: 'Cancel'
          });
          if (!ok) { tab.log.append({ text: 'Apply cancelled.', level: 'warn' }); return; }
          tab.log.banner('Apply ' + fix + ' - ' + ctx.targets.count() + ' host(s)' + (rebootAfter ? ' (+reboot 1h)' : ''));
          applyBtn.disabled = true;
          var run = ctx.run('registry-key-apply', { targets: ctx.targets.raw, cvekey: fix, rebootafter: rebootAfter });
          if (applyUnsub) { var i = unsubs.indexOf(applyUnsub); if (i >= 0) unsubs.splice(i, 1); applyUnsub(); }
          applyUnsub = track(run.subscribe({
            status: function (t) { tab.prog.setPhase(t); },
            progress: function (p) { tab.prog.setProgress(p.done, p.total); },
            row: function (r) { tab.log.append({ text: '[' + r.Host + '] ' + (r.Status || '') + (r.NewValue != null ? (' -> ' + r.NewValue) : '') + (asBool(r.Reboot) ? ' [reboot scheduled]' : ''), level: /error|fail/i.test(String(r.Status)) ? 'err' : 'ok' }); },
            log: function (l) { tab.log.append(l); },
            error: function (e) { tab.log.append({ text: e.text, level: 'err' }); },
            final: function () { tab.log.banner('Apply complete'); },
            active: function (a) { if (!a) applyBtn.disabled = false; }
          }));
        };
      }

      // ---- TAB: Unsupported Software (scan + uninstall matched) ----
      function buildUnsupported(panel) {
        var tab = makeRunTab(panel, {
          actionId: 'unsupported-scan', runLabel: 'SCAN UNSUPPORTED', cancelLabel: 'CANCEL SCAN',
          title: 'UNSUPPORTED / SEoL SOFTWARE', logName: 'WPT_Unsupported',
          description: 'Cross-reference each host\'s installed software against the ACAS/Tenable unsupported & SEoL catalog. Returns only host x product matches that need action (Uninstall / Update / Review). Check Uninstall-tagged rows, then "Uninstall Matched".',
          // unsupported-scan emits _rk = host|name|ver -> MUST key by _rk
          keyOf: function (ev) { return ev._rk || (ev.Host + '|' + ev.InstalledName + '|' + ev.Version); },
          keyMode: { rk: true },
          selectable: true,
          columns: [
            { key: 'Host', label: 'HOST', width: 120 },
            { key: 'Product', label: 'PRODUCT', width: 180 },
            { key: 'InstalledName', label: 'INSTALLED NAME', width: 200 },
            { key: 'Version', label: 'VERSION', width: 90 },
            { key: 'Category', label: 'CATEGORY', width: 130 },
            { key: 'Action', label: 'ACTION', width: 90, render: function (r) {
                var a = String(r.Action || '');
                var cls = /uninstall/i.test(a) ? 'st-bad' : /update/i.test(a) ? 'st-warn' : 'st-info';
                return { text: a, cls: cls };
            } },
            { key: 'Notes', label: 'NOTES' }
          ],
          rowClass: function (r) { return /uninstall/i.test(String(r.Action)) ? 'row-warn' : ''; },
          settings: function (h) { var t = threadsInput(h, 12); return function () { return { threads: t() }; }; },
          params: function (api) { return { threads: api.getSettings().threads }; },
          onFinal: function (log, grid) {
            var u = grid.rows().filter(function (r) { return /uninstall/i.test(String(r.Action)); }).length;
            log.banner('Scan complete: ' + grid.rows().length + ' match(es), ' + u + ' uninstall-eligible');
          },
          intro: [{ text: 'Unsupported Software Scan ready. SCAN, check Uninstall rows, then Uninstall Matched.', level: 'accent' }],
          toolbarButtons: function (getGrid) {
            var selU = ui.ghostButton('Select Uninstall rows', { size: 'sm', title: 'Check only the rows tagged Uninstall (Review/Update are skipped).' });
            selU.onclick = function () { getGrid().selectWhere(function (r) { return /uninstall/i.test(String(r.Action)); }); };
            return [selU];
          }
        });

        // Uninstall Matched bar
        var bar = el('div'); bar.style.cssText = 'display:flex;gap:12px;align-items:center;margin-top:10px;flex-wrap:wrap';
        var uBtn = ui.button('Uninstall Matched', { variant: 'danger', title: 'Uninstall the checked Uninstall-tagged products per host with their native uninstaller.' });
        bar.appendChild(uBtn);
        tab.prog.el.parentNode.appendChild(bar);

        uBtn.onclick = async function () {
          if (needCred()) return;
          var checked = tab.grid.getChecked().filter(function (r) { return /uninstall/i.test(String(r.Action)); });
          var skipped = tab.grid.getChecked().length - checked.length;
          if (!checked.length) { notice('Nothing to uninstall', 'Check at least one Uninstall-tagged row (Review/Update are skipped).'); return; }
          // unsupported-uninstall pairs param: "Host<TAB>AppName" per line
          var pairs = checked.map(function (r) { return r.Host + '\t' + r.InstalledName; });
          var hostsSet = {}; checked.forEach(function (r) { hostsSet[r.Host] = 1; });
          var ok = await ctx.confirm({
            title: 'Uninstall Matched', danger: true,
            body: 'Uninstall <b>' + checked.length + '</b> unsupported/SEoL product(s) across <b>' + Object.keys(hostsSet).length + '</b> host(s) with their native uninstaller (NOT MECM)?' + (skipped ? ('<br><br>' + skipped + ' checked Review/Update row(s) will be skipped.') : ''),
            list: checked.slice(0, 8).map(function (r) { return r.Host + ' : ' + r.InstalledName; }),
            okText: 'Uninstall', cancelText: 'Cancel'
          });
          if (!ok) { tab.log.append({ text: 'Uninstall Matched cancelled.', level: 'warn' }); return; }
          tab.log.banner('Uninstall Matched - ' + checked.length + ' product(s)');
          uBtn.disabled = true;
          // unsupported-uninstall emits _rk = host|app -> key by _rk
          var run = ctx.run('unsupported-uninstall', { targets: Object.keys(hostsSet).join('\n'), pairs: pairs.join('\n') }, { keyOf: function (ev) { return ev._rk || (ev.Host + '|' + ev.App); } });
          // audit 2026-07-23 deferred pass: per-key resub (re-click stacked handlers)
          resub('unsupported-uninstall', run, {
            status: function (t) { tab.prog.setPhase(t); },
            progress: function (p) { tab.prog.setProgress(p.done, p.total); },
            row: function (r) {
              var okR = /^(uninstalled|success|removed|ok)$/i.test(String(r.Result || ''));
              tab.log.append({ text: '[' + r.Host + '] ' + r.App + ' (' + (r['Install Type'] || '?') + '): ' + (r.Result || '') + (r.Detail ? ' - ' + r.Detail : ''), level: okR ? 'ok' : 'err' });
            },
            log: function (l) { tab.log.append(l); },
            error: function (e) { tab.log.append({ text: e.text, level: 'err' }); },
            final: function () { tab.log.banner('Uninstall Matched complete'); },
            active: function (a) { if (!a) uBtn.disabled = false; }
          });
        };
      }

      // ---- TAB: Log4j Finder (log4j-scanner) ----
      function buildLog4j(panel) {
        makeRunTab(panel, {
          actionId: 'log4j-scanner', runLabel: 'SCAN FOR LOG4J', cancelLabel: 'CANCEL SCAN',
          title: 'LOG4J FINDER', logName: 'WPT_Log4j',
          description: 'Search Program Files / ProgramData / Users / Java roots for log4j-*.jar and classify versions. One row per host x JAR found.',
          // log4j emits _rk = host|path -> MUST key by _rk
          keyOf: function (ev) { return ev._rk || (ev.Host + '|' + ev.JARPath); },
          keyMode: { rk: true },
          columns: [
            { key: 'Host', label: 'HOST', width: 130 },
            { key: 'JARPath', label: 'JAR PATH', width: 360 },
            { key: 'Filename', label: 'FILENAME', width: 180 },
            { key: 'VulnerableVersion', label: 'VERSION', render: function (r) {
                var v = String(r.VulnerableVersion || '');
                var cls = /patched/i.test(v) ? 'st-ok' : /unknown/i.test(v) ? 'st-warn' : 'st-bad';
                return { text: v, cls: cls };
            } }
          ],
          rowClass: function (r) { var v = String(r.VulnerableVersion || ''); return /patched/i.test(v) ? 'row-ok' : /unknown/i.test(v) ? 'row-warn' : 'row-bad'; },
          settings: function (h) { var t = threadsInput(h, 12); return function () { return { threads: t() }; }; },
          params: function (api) { return { threads: api.getSettings().threads }; },
          onFinal: function (log, grid) {
            var hostsSet = {}; grid.rows().forEach(function (r) { hostsSet[r.Host] = 1; });
            log.banner('Log4j scan complete: ' + grid.rows().length + ' JAR(s) across ' + Object.keys(hostsSet).length + ' host(s)');
          },
          intro: [{ text: 'Log4j Finder ready. SCAN FOR LOG4J across the target list.', level: 'accent' }]
        });
      }

      // ---- TAB: Health / Healers (health-scan + 6 healer actions) ----
      function buildHealth(panel) {
        var tab = makeRunTab(panel, {
          actionId: 'health-scan', runLabel: 'HEALTH SCAN ALL', cancelLabel: 'CANCEL SCAN',
          title: 'HEALTH & HEALERS', logName: 'WPT_Health',
          description: 'Deep diagnostics: MECM state, client version, Software Center, WMI / WU health, reboot-pending age, last check-in, overall verdict. Then run a one-click healer on the fleet.',
          columns: [
            { key: 'Host', label: 'HOST', width: 120 },
            { key: 'MecmState', label: 'MECM', width: 90, render: healthStateCell('MecmState') },
            { key: 'ClientVersion', label: 'CLIENT', width: 90 },
            { key: 'SwCenter', label: 'SW CTR', width: 80, render: healthStateCell('SwCenter') },
            { key: 'WmiHealth', label: 'WMI', width: 80, render: healthStateCell('WmiHealth') },
            { key: 'WuState', label: 'WU', width: 80, render: healthStateCell('WuState') },
            { key: 'RebootPending', label: 'REB', width: 60, render: function (r) { return asBool(r.RebootPending) ? { text: 'YES', cls: 'st-warn' } : { text: 'No', cls: 'st-ok' }; } },
            { key: 'RebootAge', label: 'AGE', width: 70 },
            { key: 'LastCheckIn', label: 'LAST CHK-IN', width: 120 },
            { key: 'OverallHealth', label: 'OVERALL', width: 100, render: function (r) {
                var s = String(r.OverallHealth || '');
                var cls = /(healthy|ok|good)/i.test(s) ? 'st-ok' : /(critical|bad|error|fail|broken|offline)/i.test(s) ? 'st-bad' : 'st-warn';
                return { text: s, cls: cls };
            } }
          ],
          rowClass: function (r) { var s = String(r.OverallHealth || ''); return /(healthy|ok|good)/i.test(s) ? 'row-ok' : /(critical|bad|error|fail|broken|offline)/i.test(s) ? 'row-bad' : (s ? 'row-warn' : ''); },
          settings: function (h) { var t = threadsInput(h, 24); return function () { return { threads: t() }; }; },
          params: function (api) { return { threads: api.getSettings().threads }; },
          onFinal: function (log, grid) { log.banner('Health scan complete: ' + grid.rows().length + ' host(s)'); },
          intro: [{ text: 'Health & Healers ready. HEALTH SCAN ALL, then run a healer below.', level: 'accent' }]
        });

        // Healer action bar - each runs a destructive healer over the whole fleet
        var bar = el('div'); bar.style.cssText = 'display:flex;gap:8px;align-items:center;margin-top:10px;flex-wrap:wrap';
        var healers = [
          ['healer-restart-ccm', 'Restart MECM Client', true],
          ['healer-ccm-repair', 'Repair MECM Client', true],
          ['healer-wmi-repair', 'Repair WMI', true],
          ['healer-wu-reset', 'Reset Windows Update', true],
          ['healer-trigger-checkin', 'Trigger Check-In', false],
          ['healer-gpupdate', 'gpupdate /force', true],
          ['healer-rdp-rebind', 'Repair RDP Listener', true]
        ];
        var healerBtns = [];
        healers.forEach(function (hh) {
          var btn = ui.button(hh[1], { variant: hh[2] ? 'gold' : 'cyan', size: 'sm', title: (findManifestAction(hh[0]) || {}).description });
          btn.onclick = function () { runHealer(hh[0], hh[1], hh[2]); };
          bar.appendChild(btn);
          healerBtns.push(btn);
        });
        tab.prog.el.parentNode.appendChild(bar);

        var healerActive = false;
        var healerUnsubs = {};   // actionId -> live unsub; a healer re-run must replace, not stack, its handler
        async function runHealer(actionId, label, destructive) {
          if (healerActive) { notice('Healer running', 'A healer is already running on the fleet - let it finish first.'); return; }
          if (!ctx.targets.count()) { notice('No Targets', 'Build the host list first.'); return; }
          if (destructive && needCred()) return;
          if (destructive) {
            var ok = await ctx.confirm({ title: 'Confirm ' + label, danger: true, body: 'Run <b>' + esc(label) + '</b> on <b>' + ctx.targets.count() + '</b> host(s)? ' + esc((findManifestAction(actionId) || {}).description || ''), okText: 'Run', cancelText: 'Cancel' });
            if (!ok) { tab.log.append({ text: label + ' cancelled.', level: 'warn' }); return; }
          }
          tab.log.banner(label + ' - ' + ctx.targets.count() + ' host(s)');
          healerActive = true;
          healerBtns.forEach(function (b) { b.disabled = true; });
          var run = ctx.run(actionId, { targets: ctx.targets.raw });
          if (healerUnsubs[actionId]) { var i = unsubs.indexOf(healerUnsubs[actionId]); if (i >= 0) unsubs.splice(i, 1); healerUnsubs[actionId](); }
          healerUnsubs[actionId] = track(run.subscribe({
            status: function (t) { tab.prog.setPhase(t); },
            progress: function (p) { tab.prog.setProgress(p.done, p.total); },
            row: function (r) { tab.log.append({ text: '[' + r.Host + '] ' + (asBool(r.Success) ? 'OK' : 'Failed') + (r.Detail ? ' - ' + r.Detail : ''), level: asBool(r.Success) ? 'ok' : 'err' }); },
            log: function (l) { tab.log.append(l); },
            error: function (e) { tab.log.append({ text: e.text, level: 'err' }); },
            final: function () { tab.log.banner(label + ' complete'); },
            active: function (a) { if (!a) { healerActive = false; healerBtns.forEach(function (b) { b.disabled = false; }); } }
          }));
        }
      }

      // ---- TAB: WinRM Setup (winrm-bootstrap) ----
      function buildWinRM(panel) {
        makeRunTab(panel, {
          actionId: 'winrm-bootstrap', runLabel: 'REPAIR WINRM', cancelLabel: 'CANCEL REPAIR',
          title: 'WINRM SETUP', logName: 'WPT_WinRM',
          description: 'Bootstrap WinRM over DCOM on offline hosts: set the service Automatic, start it, run winrm quickconfig, re-probe 5985. Requires an admin session.',
          columns: [
            { key: 'Host', label: 'HOST', width: 140 },
            { key: 'Success', label: 'RESULT', width: 90, render: function (r) { return asBool(r.Success) ? { text: 'OK', cls: 'st-ok' } : { text: 'Failed', cls: 'st-bad' }; } },
            { key: 'PostProbeOk', label: '5985 UP', width: 80, render: function (r) { return asBool(r.PostProbeOk) ? { text: 'Yes', cls: 'st-ok' } : { text: 'No', cls: 'st-warn' }; } },
            { key: 'Steps', label: 'STEPS' }
          ],
          rowClass: function (r) { return r.Success == null ? '' : (asBool(r.Success) ? 'row-ok' : 'row-bad'); },
          settings: function (h) { var t = threadsInput(h, 12); return function () { return { threads: t() }; }; },
          params: function (api) { return { threads: api.getSettings().threads }; },
          confirmBeforeRun: function () {
            if (needCred()) return Promise.resolve(false);
            return ctx.confirm({ title: 'Repair WinRM', danger: true, body: 'Bootstrap WinRM over DCOM on <b>' + ctx.targets.count() + '</b> host(s)? Sets the WinRM service Automatic, starts it, runs winrm quickconfig, re-probes 5985.', okText: 'Repair', cancelText: 'Cancel' });
          },
          onFinal: function (log, grid) { var ok = grid.rows().filter(function (r) { return asBool(r.Success); }).length; log.banner('WinRM repair complete: ' + ok + '/' + grid.rows().length + ' succeeded'); },
          intro: [{ text: 'WinRM Setup ready. Add offline hosts, then REPAIR WINRM.', level: 'accent' }]
        });
      }

      // ---- TAB: Reboot Countdown (reboot-schedule / reboot-abort + client monitor) ----
      // Faithful to the desktop Reboot Countdown tab: a delayed scheduled reboot
      // (shutdown /r /t) with warning popups every N minutes, a warnings-only mode,
      // Cancel Countdown (shutdown /a), Send Warning Now, and a post-reboot monitor
      // that pings each host back online and beeps on return (Console.Beep parity).
      function buildReboot(panel) {
        var lay = el('div'); lay.style.cssText = 'display:flex;gap:12px;height:100%;min-height:0;padding:12px;box-sizing:border-box';
        panel.appendChild(lay);

        var tg = sharedTargetsCard({ hint: 'Hosts to schedule for reboot' });
        lay.appendChild(tg.box);

        var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:10px;min-height:0';
        lay.appendChild(right);

        // ----- control card -----
        var ctlCard = ui.card({}); ctlCard.style.cssText += ';display:flex;flex-direction:column;gap:10px';
        ctlCard.appendChild(el('div', 'j-section-h', 'REBOOT COUNTDOWN'));
        ctlCard.appendChild((function () { var d = el('div', 'muted', 'Schedule a delayed reboot across the targets (shutdown /r /t) with warning popups every few minutes, or run warnings only with no reboot. Cancel any time before the timer fires; after an auto-reboot the monitor pings each host back online.'); d.style.cssText = 'font-size:11.5px'; return d; })());

        var row1 = el('div'); row1.style.cssText = 'display:flex;align-items:flex-end;gap:14px;flex-wrap:wrap';
        var totalMin = ui.number({ value: 15, min: 1, max: 1440, title: 'Minutes until the scheduled reboot.' }); totalMin.style.width = '90px';
        var warnMin = ui.number({ value: 5, min: 1, max: 120, title: 'Send a warning popup this often during the countdown.' }); warnMin.style.width = '90px';
        var modeSel = ui.select({ options: [{ value: 'auto', label: 'Auto-reboot when timer reaches zero' }, { value: 'warn', label: 'Warnings only (no scheduled reboot)' }] }); modeSel.style.minWidth = '260px';
        row1.appendChild(ui.field('Total time (min)', totalMin));
        row1.appendChild(ui.field('Warn every (min)', warnMin));
        row1.appendChild(ui.field('Mode', modeSel));
        ctlCard.appendChild(row1);

        var titleInput = ui.input({ value: 'Scheduled reboot - 48th Communications Squadron', title: 'Warning popup title.' });
        ctlCard.appendChild(ui.field('Warning title', titleInput));
        var bodyInput = ui.textarea({ value: 'Your computer will restart soon to apply updates. Please save your work now.', rows: 2 });
        ctlCard.appendChild(ui.field('Warning message', bodyInput));

        var btnRow = el('div'); btnRow.style.cssText = 'display:flex;align-items:center;gap:10px;flex-wrap:wrap';
        var armBtn = ui.button('Arm Countdown', { variant: 'danger', title: 'Schedule the reboot (or start warnings) across all targets.' });
        var warnNowBtn = ui.button('Send Warning Now', { variant: 'cyan', title: 'Pop a one-off warning to the logged-on users immediately.' });
        var cancelBtn = ui.button('Cancel Countdown', { variant: 'gold', title: 'Abort the scheduled reboot (shutdown /a) and stop warnings.' });
        cancelBtn.disabled = true;
        btnRow.appendChild(armBtn); btnRow.appendChild(warnNowBtn); btnRow.appendChild(cancelBtn);
        var cdLabel = el('div'); cdLabel.style.cssText = 'font-family:var(--mono);font-size:15px;font-weight:700;color:var(--gold);margin-left:8px';
        btnRow.appendChild(cdLabel);
        ctlCard.appendChild(btnRow);
        right.appendChild(ctlCard);

        // ----- schedule / monitor grid -----
        var resCard = ui.card({}); resCard.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
        resCard.appendChild(el('div', 'j-section-h', 'SCHEDULE / MONITOR'));
        var grid = C.ResultsGrid({
          title: 'Reboot countdown', keyMode: { hostCol: 'Host' },
          columns: [
            { key: 'Host', label: 'HOST', width: 140 },
            { key: 'Phase', label: 'PHASE', width: 130, render: function (r) {
                var s = String(r.Phase || '');
                var cls = /(online|back|armed|cancelled|sent)/i.test(s) ? 'st-ok'
                  : /(offline|wait|warning)/i.test(s) ? 'st-warn'
                  : /(fail|error)/i.test(s) ? 'st-bad' : 'cell-dim';
                return { text: s, cls: cls };
            } },
            { key: 'RebootAt', label: 'REBOOT ~', width: 92, render: function (r) { return { text: String(r.RebootAt || ''), cls: r.RebootAt ? 'st-info' : 'cell-dim' }; } },
            { key: 'Pings', label: 'PINGS', width: 60, render: function (r) { return (r.Pings == null) ? { text: '', cls: 'cell-dim' } : { text: String(r.Pings), cls: 'cell-dim' }; } },
            { key: 'Detail', label: 'DETAIL' }
          ],
          rowClass: function (r) { var s = String(r.Phase || ''); return /(online|back|armed|cancelled)/i.test(s) ? 'row-ok' : /(fail|error)/i.test(s) ? 'row-bad' : ''; }
        });
        var gh = el('div'); gh.style.cssText = 'flex:1;min-height:0;display:flex'; gh.appendChild(grid.el); resCard.appendChild(gh);
        var prog = C.ProgressStatusStrip({ showCount: true }); prog.el.style.marginTop = '8px'; resCard.appendChild(prog.el);
        right.appendChild(resCard);

        // ----- activity log -----
        var logCard = ui.card({}); logCard.classList.add('j-logdock');
        var log = C.ActivityLog({ title: 'REBOOT LOG', defaultName: 'WPT_Reboot' });
        logCard.appendChild(log.el); right.appendChild(logCard);
        log.append({ text: 'Reboot Countdown ready. Set the timing + mode, then Arm Countdown. Cancel any time before it fires.', level: 'accent' });

        // ----- client-side countdown + post-reboot monitor -----
        var state = { armed: false, mode: 'auto', endAt: 0, warnEvery: 0, lastWarn: 0, tick: null, monitor: null, audio: null, armedHosts: null };
        function clearTimers() { if (state.tick) { clearInterval(state.tick); state.tick = null; } if (state.monitor) { clearInterval(state.monitor); state.monitor = null; } }
        track(function () { clearTimers(); });   // unmount cleanup
        function ensureAudio() { try { if (!state.audio) state.audio = new (window.AudioContext || window.webkitAudioContext)(); if (state.audio.state === 'suspended') state.audio.resume(); } catch (e) {} }
        function beep() {
          try {
            ensureAudio(); var ac = state.audio; if (!ac) return;
            var o = ac.createOscillator(), g = ac.createGain();
            o.type = 'sine'; o.frequency.value = 880; g.gain.value = 0.07;
            o.connect(g); g.connect(ac.destination); o.start(); o.stop(ac.currentTime + 0.18);
          } catch (e) {}
        }
        function mmss(sec) { sec = Math.max(0, Math.round(sec)); var m = Math.floor(sec / 60), s = sec % 60; return (m < 10 ? '0' : '') + m + ':' + (s < 10 ? '0' : '') + s; }
        function setArmedUi(on) { state.armed = on; armBtn.disabled = on; cancelBtn.disabled = !on; totalMin.disabled = on; warnMin.disabled = on; modeSel.disabled = on; }
        function warnBody(remainSec) { return (bodyInput.value || '').trim() + ' (about ' + Math.max(1, Math.round(remainSec / 60)) + ' minute(s) remaining)'; }
        function sendWarning(remainSec) {
          // Once armed, always warn the SNAPSHOT hosts - never re-read ctx.targets.raw
          // (the operator may have edited the shared host box mid-countdown).
          var targetsRaw = (state.armedHosts != null) ? state.armedHosts : ctx.targets.raw;
          var run = ctx.run('remote-message', { targets: targetsRaw, title: titleInput.value, body: warnBody(remainSec), timeout: 0, threads: 16 });
          // audit 2026-07-23 deferred pass: per-key resub - warnings repeat every N
          // minutes and the key is shared with the Remote Message tab's SEND.
          resub('remote-message', run, { final: function () { log.append({ text: 'Warning popup sent (' + mmss(remainSec) + ' left).', level: 'info' }); } });
        }
        function startCountdown(totalSec) {
          state.endAt = Date.now() + totalSec * 1000;
          state.warnEvery = Math.max(1, parseInt(warnMin.value, 10) || 5) * 60;
          state.lastWarn = Date.now();   // arming already fired the first warning
          clearTimers();
          state.tick = setInterval(function () {
            var remain = (state.endAt - Date.now()) / 1000;
            if (remain <= 0) {
              clearInterval(state.tick); state.tick = null;
              if (state.mode === 'auto') { cdLabel.textContent = 'Rebooting now...'; log.banner('Countdown reached zero - hosts rebooting. Starting monitor.'); startMonitor(state.armedHosts != null ? ctx.util.parseHosts(state.armedHosts) : null); }
              else { cdLabel.textContent = 'Countdown complete.'; log.banner('Warnings-only countdown complete.'); setArmedUi(false); }
              return;
            }
            cdLabel.textContent = (state.mode === 'auto' ? 'Reboot in ' : 'Warn window ') + mmss(remain);
            if ((Date.now() - state.lastWarn) / 1000 >= state.warnEvery) { state.lastWarn = Date.now(); sendWarning(remain); }
          }, 1000);
        }
        function startMonitor(hostsArg) {
          var hosts = (hostsArg && hostsArg.length) ? hostsArg : ctx.targets.hosts(); if (!hosts.length) { setArmedUi(false); return; }
          var st = {}; var startedAt = Date.now();
          hosts.forEach(function (h) { st[h] = { seenOffline: false, back: false, pings: 0 }; grid.upsert({ Host: h, Phase: 'Waiting', Pings: 0, Detail: 'waiting for host to drop...' }); });
          prog.reset(); prog.setProgress(0, hosts.length);
          var MONITOR_CAP_MS = 30 * 60 * 1000;   // stop ping-sweeping after 30 min even if a host never returns
          function expireMonitor() {
            clearTimers();
            var lost = 0;
            hosts.forEach(function (h) { var s = st[h]; if (s && !s.back) { lost++; grid.upsert({ Host: h, Phase: 'Timed out', Pings: s.pings, Detail: 'did not return within 30 min' }); log.append({ text: '[' + h + '] never came back online (30 min cap).', level: 'warn' }); } });
            var back = hosts.filter(function (h) { return st[h].back; }).length;
            prog.setProgress(back, hosts.length);
            log.banner('Monitor stopped after 30 min - ' + back + '/' + hosts.length + ' back, ' + lost + ' never returned.');
            cdLabel.textContent = 'Monitor timed out (' + lost + ' host(s) not back).';
            setArmedUi(false);
          }
          function poll() {
            if (Date.now() - startedAt >= MONITOR_CAP_MS) { expireMonitor(); return; }
            var run = ctx.run('ping-sweep', { targets: hosts.join('\n') });
            // audit 2026-07-23 deferred pass: per-key resub - this polls every 6s,
            // so a bare subscribe stacked one live handler per poll (O(n^2) fan-out
            // over a 30-min monitor); the key is also shared with Bulk's Ping Sweep.
            resub('ping-sweep', run, {
              row: function (r) {
                var h = r.Host, s = st[h]; if (!s || s.back) return; s.pings++;
                if (!asBool(r.Reachable)) { s.seenOffline = true; grid.upsert({ Host: h, Phase: 'Offline (rebooting)', Pings: s.pings, Detail: 'down - waiting for return' }); }
                else if (s.seenOffline) { s.back = true; grid.upsert({ Host: h, Phase: 'Back online', Pings: s.pings, Detail: 'returned after ' + mmss((Date.now() - startedAt) / 1000) }); log.append({ text: '[' + h + '] back online.', level: 'ok' }); beep(); }
                else { grid.upsert({ Host: h, Phase: 'Waiting', Pings: s.pings, Detail: 'still up - not yet rebooted' }); }
              },
              final: function () {
                var back = hosts.filter(function (h) { return st[h].back; }).length;
                prog.setProgress(back, hosts.length);
                if (back >= hosts.length) { clearTimers(); log.banner('All ' + hosts.length + ' host(s) back online!'); cdLabel.textContent = 'All hosts back online.'; setArmedUi(false); }
              }
            });
          }
          clearTimers(); poll(); state.monitor = setInterval(poll, 6000);
        }
        rebootMonitorFn = startMonitor;   // expose for Bulk "Reboot Selected" post-reboot monitoring

        armBtn.onclick = async function () {
          if (!ctx.targets.count()) { notice('No Targets', 'Add hosts on the Targets tab first.'); return; }
          if (needCred()) return;
          if (!bodyInput.value.trim()) { notice('No Message', 'Enter a warning message body.'); return; }
          var auto = (modeSel.value === 'auto'); state.mode = modeSel.value;
          var totalSec = Math.max(60, (parseInt(totalMin.value, 10) || 15) * 60);
          var ok = await ctx.arm({
            title: auto ? 'Arm scheduled reboot' : 'Start warning countdown',
            banner: auto ? ('Schedule a forced reboot on ' + ctx.targets.count() + ' host(s) in ' + totalMin.value + ' min') : ('Warnings only to ' + ctx.targets.count() + ' host(s) for ' + totalMin.value + ' min - NO reboot'),
            body: auto ? ('Each host gets <b>shutdown /r /t ' + totalSec + ' /f</b> plus a warning popup. You can Cancel Countdown (shutdown /a) any time before it fires.') : 'Warning popups only; no reboot is scheduled.',
            preflight: [
              { label: ctx.targets.count() + ' target(s)', ok: true },
              { label: 'Admin session set', ok: ctx.session.state.credSet },
              { label: auto ? 'Mode: AUTO-REBOOT' : 'Mode: warnings only', ok: true }
            ],
            confirmWord: auto ? 'REBOOT' : null,
            okText: auto ? 'Arm Reboot' : 'Start Warnings', cancelText: 'Cancel'
          });
          if (!ok) { log.append({ text: 'Arm cancelled by operator.', level: 'warn' }); return; }
          // Snapshot the host list NOW - once armed, Cancel/warnings/monitor must all
          // target these exact hosts even if the operator edits the shared host box
          // mid-countdown (P2-3: previously each re-read ctx.targets.raw live).
          state.armedHosts = ctx.targets.raw;
          var armedHostsArr = ctx.util.parseHosts(state.armedHosts);
          ensureAudio();
          grid.clear(); prog.reset(); setArmedUi(true);
          log.banner((auto ? 'Arming scheduled reboot' : 'Starting warnings') + ' - ' + armedHostsArr.length + ' host(s), ' + totalMin.value + ' min, warn every ' + warnMin.value + ' min');
          if (auto) {
            var run = ctx.run('reboot-schedule', { targets: state.armedHosts, seconds: totalSec, message: bodyInput.value, threads: 16 }, {});
            // audit 2026-07-23 deferred pass: per-key resub (re-arm stacked handlers)
            resub('reboot-schedule', run, {
              status: function (t) { prog.setPhase(t); },
              progress: function (p) { prog.setProgress(p.done, p.total); },
              row: function (r) { grid.upsert({ Host: r.Host, Phase: asBool(r.Success) ? 'Armed' : 'Failed', RebootAt: r.RebootAt, Detail: r.Detail }); },
              log: function (l) { log.append(l); },
              error: function (e) { log.append({ text: e.text, level: 'err' }); },
              final: function () { var armed = grid.rows().filter(function (x) { return /armed/i.test(String(x.Phase)); }).length; log.banner('Scheduled on ' + armed + '/' + armedHostsArr.length + ' host(s).'); }
            });
          } else {
            armedHostsArr.forEach(function (h) { grid.upsert({ Host: h, Phase: 'Warning', Detail: 'warnings only' }); });
            sendWarning(totalSec);
          }
          startCountdown(totalSec);
        };

        warnNowBtn.onclick = function () {
          if (!ctx.targets.count()) { notice('No Targets', 'Add hosts on the Targets tab first.'); return; }
          if (needCred()) return;
          if (!bodyInput.value.trim()) { notice('No Message', 'Enter a warning message body.'); return; }
          var remain = state.armed ? (state.endAt - Date.now()) / 1000 : (parseInt(totalMin.value, 10) || 15) * 60;
          log.banner('Send Warning Now - ' + ctx.targets.count() + ' host(s)');
          sendWarning(remain);
        };

        cancelBtn.onclick = async function () {
          if (!state.armed) return;
          clearTimers(); cdLabel.textContent = 'Cancelling...';
          // Cancel the ARMED hosts, not whatever is currently in the shared host box.
          var armedHostsArr = ctx.util.parseHosts(state.armedHosts || '');
          if (state.mode === 'auto') {
            log.banner('Cancelling scheduled reboot (shutdown /a) - ' + armedHostsArr.length + ' host(s)');
            var run = ctx.run('reboot-abort', { targets: state.armedHosts, threads: 16 }, {});
            // audit 2026-07-23 deferred pass: per-key resub (re-cancel stacked handlers)
            resub('reboot-abort', run, {
              row: function (r) { grid.upsert({ Host: r.Host, Phase: asBool(r.Success) ? 'Cancelled' : 'Failed', RebootAt: '', Detail: r.Detail }); },
              log: function (l) { log.append(l); },
              error: function (e) { log.append({ text: e.text, level: 'err' }); },
              final: function () { log.banner('Cancel complete.'); }
            });
          } else { log.append({ text: 'Warnings stopped.', level: 'warn' }); }
          cdLabel.textContent = 'Countdown cancelled.'; setArmedUi(false);
        };
      }

      // ---- TAB: Remote Message (remote-message) ----
      function buildRemoteMessage(panel) {
        var lay = el('div'); lay.style.cssText = 'display:flex;gap:12px;height:100%;min-height:0;padding:12px;box-sizing:border-box';
        panel.appendChild(lay);

        var tg = sharedTargetsCard({});
        lay.appendChild(tg.box);

        var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:10px;min-height:0';
        lay.appendChild(right);

        var compCard = ui.card({}); compCard.style.cssText += ';display:flex;flex-direction:column;gap:8px';
        compCard.appendChild(el('div', 'j-section-h', 'REMOTE MESSAGE'));
        compCard.appendChild((function () { var d = el('div', 'muted', 'Deliver a titled popup to the logged-on user on each target via a scheduled-task/VBS popup.'); d.style.cssText = 'font-size:11.5px'; return d; })());
        var titleInput = ui.input({ value: 'A message from the 48th Communications Squadron', title: 'Popup title line.' });
        compCard.appendChild(ui.field('Title', titleInput));
        var bodyInput = ui.textarea({ placeholder: 'Type the message body...', rows: 5 });
        compCard.appendChild(ui.field('Message', bodyInput));
        var optRow = el('div'); optRow.style.cssText = 'display:flex;align-items:flex-end;gap:14px;flex-wrap:wrap';
        var timeoutInput = ui.number({ value: 300, min: 0, max: 86400, title: 'Seconds before the popup auto-dismisses (0 = never).' }); timeoutInput.style.width = '110px';
        optRow.appendChild(ui.field('Dismiss after (sec, 0=never)', timeoutInput));
        var threads = threadsInput(optRow, 16);
        compCard.appendChild(optRow);
        var runbar = C.RunBar({
          label: 'SEND MESSAGE', cancelLabel: 'CANCEL SEND', morphToCancel: true,
          title: 'Deliver the popup to every target\'s logged-on user.',
          guards: [
            function () { return ctx.targets.count() ? null : 'No Targets|Build the host list first.'; },
            function () { return ctx.session.state.credSet ? null : 'No Credentials|Set your ADW credential (top-right) before sending.'; },
            function () { return bodyInput.value.trim() ? null : 'No Message|The message body is empty.'; }
          ],
          onGuardFail: guardFail,
          onRun: doSend,
          onCancel: function () { if (sendRun) { sendRun.cancel(); log.append({ text: 'CANCEL requested...', level: 'warn' }); } }
        });
        var rbHold = el('div'); rbHold.style.cssText = 'margin-top:8px;max-width:260px'; rbHold.appendChild(runbar.el);
        compCard.appendChild(rbHold);
        right.appendChild(compCard);

        var resCard = ui.card({}); resCard.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
        resCard.appendChild(el('div', 'j-section-h', 'DELIVERY'));
        var grid = C.ResultsGrid({
          title: 'Remote message', keyMode: { hostCol: 'Host' },
          columns: [
            { key: 'Host', label: 'HOST', width: 150 },
            { key: 'Status', label: 'STATUS', width: 110, render: function (r) { var s = String(r.Status || ''); return { text: s, cls: /deliver|sent|ok|success/i.test(s) ? 'st-ok' : 'st-bad' }; } },
            { key: 'Detail', label: 'DETAIL' }
          ],
          rowClass: function (r) { var s = String(r.Status || ''); return /deliver|sent|ok|success/i.test(s) ? 'row-ok' : (s ? 'row-bad' : ''); }
        });
        var gh = el('div'); gh.style.cssText = 'flex:1;min-height:0;display:flex'; gh.appendChild(grid.el); resCard.appendChild(gh);
        var prog = C.ProgressStatusStrip({ showCount: true }); prog.el.style.marginTop = '8px'; resCard.appendChild(prog.el);
        right.appendChild(resCard);

        var logCard = ui.card({}); logCard.classList.add('j-logdock');
        var log = C.ActivityLog({ title: 'MESSAGE LOG', defaultName: 'WPT_RemoteMessage' });
        logCard.appendChild(log.el); right.appendChild(logCard);
        log.append({ text: 'Remote Message ready. Compose, then SEND MESSAGE.', level: 'accent' });

        var sendRun = null;
        async function doSend() {
          var ok = await ctx.confirm({
            title: 'Confirm send', danger: true,
            body: 'Send this popup to the logged-on user on <b>' + ctx.targets.count() + '</b> target(s)?<br>Title: <b>' + esc(titleInput.value) + '</b>',
            list: ctx.targets.hosts().slice(0, 6), okText: 'Send', cancelText: 'Cancel'
          });
          if (!ok) { log.append({ text: 'Send cancelled.', level: 'warn' }); return; }
          grid.clear(); prog.reset();
          log.banner('Send - ' + ctx.targets.count() + ' target(s)');
          sendRun = ctx.run('remote-message', { targets: ctx.targets.raw, title: titleInput.value, body: bodyInput.value, timeout: parseInt(timeoutInput.value, 10) || 0, threads: threads() });
          // audit 2026-07-23 deferred pass: per-key resub (re-send stacked handlers;
          // key shared with the Reboot Countdown warnings) - onReplace un-morphs the runbar.
          resub('remote-message', sendRun, {
            status: function (t) { prog.setPhase(t); },
            progress: function (p) { prog.setProgress(p.done, p.total); },
            row: function (r) { grid.upsert(r); var okR = /deliver|sent|ok|success/i.test(String(r.Status)); log.append({ text: '[' + r.Host + '] ' + (r.Status || '') + (r.Detail ? ' - ' + r.Detail : ''), level: okR ? 'ok' : 'err' }); },
            log: function (l) { log.append(l); },
            error: function (e) { log.append({ text: e.text, level: 'err' }); },
            final: function () { log.banner('Send complete'); },
            active: function (a) { runbar.setActive(a); }
          }, function () { runbar.setActive(false); });
        }
      }

      // ---- TAB: Reports (session stats + action history + export) ----
      function buildReports(panel) {
        var lay = el('div'); lay.style.cssText = 'display:flex;flex-direction:column;gap:12px;height:100%;min-height:0;padding:12px;box-sizing:border-box';
        panel.appendChild(lay);

        var statCard = ui.card({}); statCard.appendChild(el('div', 'j-section-h', 'SESSION STATISTICS'));
        var cards = C.StatCards({ cards: [
          { key: 'scanned', label: 'Scanned', color: 'cyan', value: 0 },
          { key: 'updates', label: 'Updates', color: 'gold', value: 0 },
          { key: 'installed', label: 'Installed', color: 'ok', value: 0 },
          { key: 'uninstalled', label: 'Uninstalled', color: 'bad', value: 0 },
          { key: 'reinstalled', label: 'Reinstalled', color: 'accent', value: 0 },
          { key: 'repaired', label: 'Repaired', color: 'gold', value: 0 },
          { key: 'reboots', label: 'Reboots', color: 'accent', value: 0 }
        ] });
        statCard.appendChild(cards.el); lay.appendChild(statCard);

        var histCard = ui.card({}); histCard.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
        var hh = el('div'); hh.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap';
        hh.appendChild(el('div', 'j-section-h', 'ACTION HISTORY'));
        var btns = el('div'); btns.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap';
        var refreshBtn = ui.ghostButton('Refresh', { size: 'sm' });
        var expBtn = ui.ghostButton('Export CSV', { size: 'sm' });
        var sumBtn = ui.ghostButton('Export Summary', { size: 'sm' });
        var clrBtn = ui.ghostButton('Clear', { size: 'sm' });
        [refreshBtn, expBtn, sumBtn, clrBtn].forEach(function (b) { btns.appendChild(b); });
        hh.appendChild(btns); histCard.appendChild(hh);

        var grid = C.ResultsGrid({
          title: 'Action history', keyMode: { rk: true }, popOut: true,
          columns: [
            { key: 'time', label: 'TIME', width: 90, render: function (r) { return { text: String(r.time || ''), cls: 'cell-dim' }; } },
            { key: 'action', label: 'ACTION', width: 150, render: function (r) { return { text: String(r.action || ''), cls: 'st-accent' }; } },
            { key: 'target', label: 'TARGET', width: 150 },
            { key: 'result', label: 'RESULT', width: 120, render: function (r) {
                var s = String(r.result || '');
                var cls = /(ok|scanned|patched|installed|uninstalled|reinstalled|repaired|sent|armed|cancelled|updated|delivered|healthy)/i.test(s) ? 'st-ok'
                  : /(fail|error|offline|unreachable)/i.test(s) ? 'st-bad' : 'st-warn';
                return { text: s, cls: cls };
            } },
            { key: 'detail', label: 'DETAIL' }
          ]
        });
        var gh = el('div'); gh.style.cssText = 'flex:1;min-height:0;display:flex'; gh.appendChild(grid.el); histCard.appendChild(gh);
        var note = el('div', 'muted', 'Statistics + history are this session, fed live by every WPT run on every tab (the desktop Track-Action -> Stats / ActionHistory). Saved report FILES live under the audit log root; in-browser file browse/open needs a server action (follow-on). Export Summary downloads the live session report.');
        note.style.cssText = 'font-size:11px;margin-top:6px'; histCard.appendChild(note);
        lay.appendChild(histCard);

        var rendered = 0;
        function repaintStats() { cards.setAll(Telemetry.stats()); }
        function repaintHistory(reset) {
          var h = Telemetry.history();
          if (reset) { grid.clear(); rendered = 0; }
          for (var i = rendered; i < h.length; i++) { var e = h[i]; grid.upsert({ _rk: 'h' + e.seq, time: e.time, action: e.action, target: e.target, result: e.result, detail: e.detail }); }
          rendered = h.length;
        }
        repaintStats(); repaintHistory(true);
        track(Telemetry.onChange(function () { repaintStats(); repaintHistory(false); }));

        refreshBtn.onclick = function () { repaintStats(); repaintHistory(true); };
        clrBtn.onclick = async function () {
          var ok = await ctx.confirm({ title: 'Clear session telemetry', danger: true, body: 'Clear the session statistics, action history, and global log? This does NOT touch the central audit CSV on the share.', okText: 'Clear', cancelText: 'Cancel' });
          if (!ok) return; Telemetry.clear(); repaintStats(); repaintHistory(true);
        };
        expBtn.onclick = function () {
          var h = Telemetry.history(); if (!h.length) { notice('Nothing to export', 'No actions have been recorded yet this session.'); return; }
          var csv = ctx.util.toCsv(['Time', 'Action', 'Target', 'Result', 'Detail'], h.map(function (e) { return [e.time, e.action, e.target, e.result, e.detail]; }));
          ctx.util.downloadBlob('WPT_ActionHistory_' + ctx.util.fileStamp() + '.csv', 'text/csv', csv);
        };
        sumBtn.onclick = function () {
          var s = Telemetry.stats(), m = Telemetry.metrics();
          var lines = ['JANET Web - WPT Session Summary', 'Generated:   ' + ctx.util.clockStr(), 'Operator:    ' + (ctx.session.state.user || '(read-only browse)'), 'Started:     ' + (m.started || '-'), 'Runs:        ' + m.runs, 'Hosts:       ' + m.hosts, '',
            'Scanned:     ' + s.scanned, 'Updates:     ' + s.updates, 'Installed:   ' + s.installed, 'Uninstalled: ' + s.uninstalled, 'Reinstalled: ' + s.reinstalled, 'Repaired:    ' + s.repaired, 'Reboots:     ' + s.reboots];
          ctx.util.downloadBlob('WPT_SessionSummary_' + ctx.util.fileStamp() + '.txt', 'text/plain', lines.join('\r\n') + '\r\n');
        };
      }

      // ---- TAB: Usage (session usage metrics grid) ----
      function buildUsage(panel) {
        var lay = el('div'); lay.style.cssText = 'display:flex;flex-direction:column;gap:12px;height:100%;min-height:0;padding:12px;box-sizing:border-box';
        panel.appendChild(lay);
        var card = ui.card({}); card.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
        card.appendChild(el('div', 'j-section-h', 'USAGE METRICS'));
        card.appendChild((function () { var d = el('div', 'muted', 'Live session usage (mirrors the WPT usage CSV row published to the central JANET telemetry share when the tool closes).'); d.style.cssText = 'font-size:11.5px'; return d; })());
        var grid = C.ResultsGrid({ title: 'Usage metrics', keyMode: { rk: true }, columns: [
          { key: 'metric', label: 'METRIC', width: 260 },
          { key: 'value', label: 'VALUE', render: function (r) { return { text: String(r.value == null ? '' : r.value), cls: 'st-info' }; } }
        ] });
        var gh = el('div'); gh.style.cssText = 'flex:1;min-height:0;display:flex'; gh.appendChild(grid.el); card.appendChild(gh); lay.appendChild(card);
        function repaint() {
          var s = Telemetry.stats(), m = Telemetry.metrics(), sess = ctx.session.state;
          var rows = [
            ['Operator', sess.user || '(read-only browse)'],
            ['Session mode', sess.mode || '-'],
            ['Session started', m.started || '(no runs yet)'],
            ['Runs executed', m.runs],
            ['Distinct hosts touched', m.hosts],
            ['Action history entries', m.entries],
            ['Hosts scanned', s.scanned],
            ['Updates triggered', s.updates],
            ['Apps / KBs installed', s.installed],
            ['Apps uninstalled', s.uninstalled],
            ['Apps reinstalled', s.reinstalled],
            ['Agents / components repaired', s.repaired],
            ['Reboots issued', s.reboots],
            ['Log root', sess.logRoot || '-']
          ];
          grid.clear(); rows.forEach(function (p, i) { grid.upsert({ _rk: 'm' + i, metric: p[0], value: p[1] }); });
        }
        repaint();
        track(Telemetry.onChange(repaint));
        track(ctx.session.onChange(repaint));
      }

      // ---- TAB: Logs (global activity sink - all WPT runs stream here) ----
      function buildLogs(panel) {
        var lay = el('div'); lay.style.cssText = 'display:flex;flex-direction:column;height:100%;min-height:0;padding:12px;box-sizing:border-box';
        panel.appendChild(lay);
        var card = ui.card({}); card.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
        card.appendChild(el('div', 'j-section-h', 'GLOBAL ACTIVITY LOG'));
        var holder = el('div'); holder.style.cssText = 'flex:1;min-height:0;display:flex';
        var log = C.ActivityLog({ title: 'ALL WPT ACTIVITY', defaultName: 'WPT_GlobalLog' });
        holder.appendChild(log.el); card.appendChild(holder); lay.appendChild(card);
        var buf = Telemetry.logBuf();
        if (buf.length) buf.forEach(function (l) { log.append(l); });
        else log.append({ text: 'Global activity sink. Every WPT run on every tab streams here.', level: 'accent' });
        track(Telemetry.onLog(function (l) { log.append(l); }));
      }

      // ---- TAB: Compliance Trend (read-only; aggregates saved Bulk Scan snapshots) ----
      function buildTrend(panel) {
        var run = null, unsub = null;
        var maxPending = 1;   // bar-width denominator; grows as snapshots stream, finalised from summary

        var lay = el('div'); lay.style.cssText = 'display:flex;flex-direction:column;gap:12px;height:100%;min-height:0;padding:12px;box-sizing:border-box';
        panel.appendChild(lay);

        // header + description + stat cards + run bar
        var ctlCard = ui.card({}); ctlCard.style.cssText += ';display:flex;flex-direction:column;gap:10px';
        ctlCard.appendChild(el('div', 'j-section-h', 'FLEET COMPLIANCE TREND'));
        var desc = el('div', 'muted', 'Read-only trend from saved Bulk Scan snapshots (JanetLocal\\snapshots, newest 60). Tick "Save snapshot for trending" on the Bulk Scan tab to add a data point each scan. One row per snapshot (newest first); the bar shows how many hosts still have pending work. Hosts pending in 3+ consecutive snapshots are listed in the activity log as "stuck".');
        desc.style.cssText = 'font-size:11.5px'; ctlCard.appendChild(desc);

        var cards = C.StatCards({ cards: [
          { key: 'kept', label: 'Snapshots Kept', color: 'cyan', value: 0 },
          { key: 'latest', label: 'Latest Pending', color: 'gold', value: 0 },
          { key: 'stuck', label: 'Stuck Hosts', color: 'bad', value: 0 }
        ] });
        ctlCard.appendChild(cards.el);

        var runbar = C.RunBar({
          label: 'LOAD TREND', morphToCancel: false,
          title: 'Read-only: aggregate the saved fleet snapshots into a compliance trend.',
          guards: [], onGuardFail: guardFail, onRun: doRun
        });
        var rbWrap = el('div'); rbWrap.appendChild(runbar.el); ctlCard.appendChild(rbWrap);
        lay.appendChild(ctlCard);

        // results grid (one row per snapshot) with a CSS bar for pending count
        var resCard = ui.card({}); resCard.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
        var resHdr = el('div'); resHdr.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:8px';
        resHdr.appendChild(el('div', 'j-section-h', 'SNAPSHOTS (newest first)'));
        var expBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the compliance trend (one row per snapshot) to CSV.' });
        resHdr.appendChild(expBtn);
        resCard.appendChild(resHdr);
        function pendCell(r) {
          var n = parseInt(r.HostsPending, 10); if (isNaN(n)) n = 0;
          var pct = maxPending > 0 ? Math.round(n / maxPending * 100) : 0;
          var cls = n === 0 ? 'st-ok' : 'st-warn';
          return { text: String(n), cls: cls, bar: { pct: pct, cls: cls } };
        }
        var grid = C.ResultsGrid({
          title: 'Compliance trend', keyMode: { rk: true }, popOut: true,
          columns: [
            { key: 'ScanStamp', label: 'SNAPSHOT', width: 165 },
            { key: 'TotalHosts', label: 'HOSTS', width: 70 },
            { key: 'Online', label: 'ONLINE', width: 78, render: function (r) { var on = parseInt(r.Online, 10); if (isNaN(on)) on = 0; var tot = parseInt(r.TotalHosts, 10) || 0; var cls = (tot > 0 && on >= tot) ? 'st-ok' : 'st-warn'; return { text: String(r.Online == null ? '' : r.Online), cls: cls }; } },
            { key: 'RebootPending', label: 'REBOOT', width: 82, render: function (r) { var n = parseInt(r.RebootPending, 10) || 0; return { text: String(n), cls: n > 0 ? 'st-warn' : 'st-ok' }; } },
            { key: 'PendingUpdates', label: 'PEND UPD', width: 92, render: function (r) { var n = parseInt(r.PendingUpdates, 10) || 0; return { text: String(n), cls: n > 0 ? 'st-warn' : 'st-ok' }; } },
            { key: 'HostsPending', label: 'HOSTS PENDING', width: 240, render: pendCell, sortVal: function (r) { return parseInt(r.HostsPending, 10) || 0; } }
          ]
        });
        var gh = el('div'); gh.style.cssText = 'flex:1;min-height:0;display:flex'; gh.appendChild(grid.el); resCard.appendChild(gh);
        var prog = C.ProgressStatusStrip({ showCount: false });
        prog.el.style.marginTop = '8px'; resCard.appendChild(prog.el);
        lay.appendChild(resCard);

        // activity log dock (stuck-host list streams here)
        var logCard = ui.card({}); logCard.classList.add('j-logdock');
        var log = C.ActivityLog({ title: 'ACTIVITY LOG', defaultName: 'WPT_Trend' });
        logCard.appendChild(log.el); lay.appendChild(logCard);
        log.append({ text: 'Compliance Trend ready. Save snapshots on the Bulk Scan tab, then press LOAD TREND.', level: 'accent' });

        // re-paint every row so bar widths track a new maxPending denominator
        function rescaleBars() { grid.rows().forEach(function (x) { grid.upsert(x); }); }

        expBtn.onclick = function () {
          var rows = grid.rows();
          if (!rows.length) { notice('Nothing to export', 'Load the trend first - there are no snapshots yet.'); return; }
          var keys = ['ScanStamp', 'TotalHosts', 'Online', 'RebootPending', 'PendingUpdates', 'HostsPending'];
          var csv = ctx.util.toCsv(keys, rows, keys);
          ctx.util.downloadBlob('WPT_ComplianceTrend_' + ctx.util.fileStamp() + '.csv', 'text/csv', csv);
        };

        function doRun() {
          if (run && run.state && run.state.active) return;
          grid.clear(); prog.reset(); cards.reset(); maxPending = 1;
          log.banner('Loading fleet compliance trend');
          run = ctx.run('trend', {}, { keyOf: function (ev) { return ev._rk || ev.File || ev.ScanStamp; } });
          if (unsub) { var i = unsubs.indexOf(unsub); if (i >= 0) unsubs.splice(i, 1); unsub(); }
          unsub = track(run.subscribe({
            status: function (t) { prog.setPhase(t); },
            // Upsert plainly while streaming; the final handler rescales bar widths once
            // from summary.maxPending (server-computed), avoiding a full-grid repaint per
            // successively-older row that raises the pending maximum.
            row: function (r) { grid.upsert(r); },
            log: function (l) { log.append(l); },
            error: function (e) { log.append({ text: e.text, level: 'err' }); },
            final: function (res) {
              var sum = (res && res.summary) || {};
              var mp = parseInt(sum.maxPending, 10);
              if (!isNaN(mp) && mp > 0) { maxPending = Math.max(1, mp); rescaleBars(); }
              var kept = sum.kept != null ? sum.kept : grid.rows().length;
              cards.setAll({ kept: kept, latest: sum.latestPending || 0, stuck: sum.stuck || 0 });
              log.banner('Trend loaded - ' + kept + ' snapshot(s), latest pending ' + (sum.latestPending || 0) + ', stuck ' + (sum.stuck || 0));
              runbar.setStatus('Loaded ' + kept + ' snapshot(s). Latest pending ' + (sum.latestPending || 0) + ' / stuck ' + (sum.stuck || 0), (sum.stuck ? 'st-warn' : 'st-ok'));
            },
            active: function (a) { runbar.setActive(a); }
          }));
        }
      }

      /* ======================================================================
         TABHOST  (left rail mirrors the desktop numbered sidebar nav)
         ==================================================================== */
      // ---- TAB: Host Info (single-host snapshot; PIRS "Get Info" parity) ----
      function buildHostInfo(panel) {
        var lay = el('div'); lay.style.cssText = 'display:flex;flex-direction:column;gap:12px;min-height:100%;padding:12px;box-sizing:border-box';
        panel.appendChild(lay);
        var ctlCard = ui.card({}); ctlCard.style.cssText += ';display:flex;flex-direction:column;gap:10px';
        ctlCard.appendChild(el('div', 'j-section-h', 'HOST INFO (single host)'));
        ctlCard.appendChild((function () { var d = el('div', 'muted', 'One-shot snapshot of a single workstation: model, BIOS, serial, MAC/IP, OS build, uptime, RAM, C: free, logged-on + recent users, pending reboot. Read-only triage.'); d.style.cssText = 'font-size:11.5px'; return d; })());
        var picker = hostPickerRow('Host');
        ctlCard.appendChild(picker.el);
        var btnRow = el('div'); btnRow.style.cssText = 'display:flex;gap:10px;align-items:center;flex-wrap:wrap';
        var goBtn = ui.button('Get Info', { variant: 'cyan' });
        var expBtn = ui.ghostButton('Export CSV', { size: 'sm' });
        btnRow.appendChild(goBtn); btnRow.appendChild(expBtn);
        ctlCard.appendChild(btnRow);
        lay.appendChild(ctlCard);

        var gridCard = ui.card({}); gridCard.style.cssText += ';flex:1;display:flex;flex-direction:column;min-height:0';
        gridCard.appendChild(el('div', 'j-section-h', 'SYSTEM INFORMATION'));
        var grid = C.ResultsGrid({ title: 'Host info', keyMode: { rk: true }, columns: [{ key: 'Property', label: 'PROPERTY', width: 180 }, { key: 'Value', label: 'VALUE' }] });
        var gh = el('div'); gh.style.cssText = 'flex:1;min-height:0;display:flex'; gh.appendChild(grid.el); gridCard.appendChild(gh);
        var prog = C.ProgressStatusStrip({ showCount: true }); prog.el.style.marginTop = '8px'; gridCard.appendChild(prog.el);
        lay.appendChild(gridCard);

        var logCard = ui.card({}); logCard.classList.add('j-logdock');
        var log = C.ActivityLog({ title: 'ACTIVITY LOG', defaultName: 'WPT_HostInfo' });
        logCard.appendChild(log.el); lay.appendChild(logCard);
        log.append({ text: 'Host Info ready. Pick a host (or type one) and Get Info.', level: 'accent' });

        var run = null;
        goBtn.onclick = function () {
          var hn = picker.host();
          if (!hn) { notice('No host', 'Pick or type a host first.'); return; }
          grid.clear(); prog.reset();
          log.banner('Host Info - ' + hn);
          run = ctx.run('host-info', { host: hn }, { keyOf: function (r) { return r._rk || (r.Host + '|' + r.Property); } });
          // audit 2026-07-23 deferred pass: per-key resub (re-click stacked handlers)
          resub('host-info', run, {
            status: function (t) { prog.setPhase(t); },
            row: function (r) { grid.upsert(r); },
            log: function (l) { log.append(l); },
            error: function (e) { log.append({ text: e.text, level: 'err' }); },
            final: function () { log.banner('Host Info complete - ' + grid.rows().length + ' field(s)'); },
            active: function (a) { goBtn.disabled = a; }
          });
        };
        expBtn.onclick = function () { exportGridCsv(grid, 'WPT_HostInfo_' + (picker.host() || 'host')); };
      }

      // ---- TAB: Event Logs (single-host Error/Critical triage; PIRS error-log parity) ----
      function buildEventLog(panel) {
        var lay = el('div'); lay.style.cssText = 'display:flex;flex-direction:column;gap:12px;min-height:100%;padding:12px;box-sizing:border-box';
        panel.appendChild(lay);
        var ctlCard = ui.card({}); ctlCard.style.cssText += ';display:flex;flex-direction:column;gap:10px';
        ctlCard.appendChild(el('div', 'j-section-h', 'EVENT LOG ERRORS (single host)'));
        ctlCard.appendChild((function () { var d = el('div', 'muted', 'Recent Error + Critical entries (Schannel noise filtered) from a host\'s Application / System / Security logs. Read-only triage.'); d.style.cssText = 'font-size:11.5px'; return d; })());
        var picker = hostPickerRow('Host');
        ctlCard.appendChild(picker.el);
        var optRow = el('div'); optRow.style.cssText = 'display:flex;gap:14px;align-items:flex-end;flex-wrap:wrap';
        var appCb = ui.checkbox('Application', { checked: true });
        var sysCb = ui.checkbox('System', { checked: true });
        var secCb = ui.checkbox('Security', { checked: false });
        var hoursInput = ui.number({ value: 12, min: 1, max: 168, title: 'Look back this many hours.' }); hoursInput.style.width = '80px';
        optRow.appendChild(appCb); optRow.appendChild(sysCb); optRow.appendChild(secCb);
        optRow.appendChild(ui.field('Hours', hoursInput));
        var goBtn = ui.button('Scan Logs', { variant: 'cyan' });
        var expBtn = ui.ghostButton('Export CSV', { size: 'sm' });
        optRow.appendChild(goBtn); optRow.appendChild(expBtn);
        ctlCard.appendChild(optRow);
        lay.appendChild(ctlCard);

        var gridCard = ui.card({}); gridCard.style.cssText += ';flex:1;display:flex;flex-direction:column;min-height:0';
        gridCard.appendChild(el('div', 'j-section-h', 'ERROR / CRITICAL EVENTS'));
        var grid = C.ResultsGrid({
          title: 'Event log errors', keyMode: { rk: true },
          columns: [
            { key: 'Log', label: 'LOG', width: 110 },
            { key: 'TimeCreated', label: 'TIME', width: 150 },
            { key: 'EventId', label: 'ID', width: 70 },
            { key: 'Provider', label: 'PROVIDER', width: 180, render: function (r) { var p = String(r.Provider || ''); return { text: p, cls: /error/i.test(p) ? 'st-bad' : '' }; } },
            { key: 'Message', label: 'MESSAGE' }
          ]
        });
        var gh = el('div'); gh.style.cssText = 'flex:1;min-height:0;display:flex'; gh.appendChild(grid.el); gridCard.appendChild(gh);
        var prog = C.ProgressStatusStrip({ showCount: true }); prog.el.style.marginTop = '8px'; gridCard.appendChild(prog.el);
        lay.appendChild(gridCard);

        var logCard = ui.card({}); logCard.classList.add('j-logdock');
        var log = C.ActivityLog({ title: 'ACTIVITY LOG', defaultName: 'WPT_EventLog' });
        logCard.appendChild(log.el); lay.appendChild(logCard);
        log.append({ text: 'Event Logs ready. Pick a host, choose logs + look-back, then Scan Logs.', level: 'accent' });

        var run = null;
        goBtn.onclick = function () {
          var hn = picker.host();
          if (!hn) { notice('No host', 'Pick or type a host first.'); return; }
          if (!appCb._cb.checked && !sysCb._cb.checked && !secCb._cb.checked) { notice('No logs', 'Tick at least one log to scan.'); return; }
          grid.clear(); prog.reset();
          log.banner('Event Log scan - ' + hn);
          run = ctx.run('eventlog-scan', { host: hn, application: appCb._cb.checked, system: sysCb._cb.checked, security: secCb._cb.checked, hours: hoursInput.value },
            { keyOf: function (r) { return r._rk || (r.Host + '|' + r.Log + '|' + r.TimeCreated + '|' + r.EventId); } });
          // audit 2026-07-23 deferred pass: per-key resub (re-click stacked handlers)
          resub('eventlog-scan', run, {
            status: function (t) { prog.setPhase(t); },
            row: function (r) { grid.upsert(r); },
            log: function (l) { log.append(l); },
            error: function (e) { log.append({ text: e.text, level: 'err' }); },
            final: function () { log.banner('Event Log scan complete - ' + grid.rows().length + ' row(s)'); },
            active: function (a) { goBtn.disabled = a; }
          });
        };
        expBtn.onclick = function () { exportGridCsv(grid, 'WPT_EventLog_' + (picker.host() || 'host')); };
      }

      // ---- TAB: Clean User Apps (per-profile user-binary cleanup; PIRS parity) ----
      function buildCleanUserApps(panel) {
        var cbs = {};
        makeRunTab(panel, {
          actionId: 'clean-user-apps', runLabel: 'CLEAN USER APPS', cancelLabel: 'STOP',
          title: 'CLEAN USER APPS', logName: 'WPT_CleanUserApps',
          description: 'Remove user-installed app BINARIES (per profile) while preserving user data - kills the app, deletes its per-user program folder. DRY RUN defaults ON. Does not touch user data or registry hives.',
          columns: [
            { key: 'Host', label: 'HOST', width: 140 },
            { key: 'Removed', label: 'PATHS', width: 80 },
            { key: 'FreedMB', label: 'FREED MB', width: 90 },
            { key: 'Status', label: 'STATUS', width: 100, render: function (r) { var s = String(r.Status || ''); return { text: s, cls: /error|fail/i.test(s) ? 'st-bad' : /dry/i.test(s) ? 'st-info' : 'st-ok' }; } },
            { key: 'Detail', label: 'DETAIL' }
          ],
          rowClass: function (r) { var s = String(r.Status || ''); return /error|fail/i.test(s) ? 'row-bad' : ''; },
          settings: function (h) {
            ['chrome', 'firefox', 'zoom', 'teams', 'webex'].forEach(function (a) { cbs[a] = ui.checkbox(a.charAt(0).toUpperCase() + a.slice(1), { checked: (a === 'chrome' || a === 'firefox') }); h.appendChild(cbs[a]); });
            var dry = ui.checkbox('Dry run (enumerate, do not delete)', { checked: true, color: 'var(--warn)' });
            h.appendChild(dry); cbs._dry = dry;
            var t = threadsInput(h, 12);
            return function () { return { chrome: cbs.chrome._cb.checked, firefox: cbs.firefox._cb.checked, zoom: cbs.zoom._cb.checked, teams: cbs.teams._cb.checked, webex: cbs.webex._cb.checked, dryrun: dry._cb.checked, threads: t() }; };
          },
          params: function (api) { return api.getSettings(); },
          confirmBeforeRun: function (api) {
            var s = api.getSettings();
            if (s.dryrun) return Promise.resolve(true);
            if (needCred()) return Promise.resolve(false);
            return ctx.arm({ title: 'Confirm LIVE Clean User Apps', body: 'Dry run is OFF. This PERMANENTLY deletes the selected per-user app binaries on <b>' + ctx.targets.count() + '</b> host(s). User data (bookmarks/history/profiles) is preserved. Proceed?', confirmWord: 'DELETE', okText: 'Delete', cancelText: 'Cancel' });
          },
          onFinal: function (log, grid) { log.banner('Clean User Apps complete: ' + grid.rows().length + ' host(s)'); },
          intro: [{ text: 'Clean User Apps ready. DRY RUN is on by default - uncheck it to actually delete. Chrome + Firefox preselected.', level: 'accent' }]
        });
      }

      // ---- TAB: Available Deployments (unified MECM available list + deploy; PIRS Software Center Deployer parity) ----
      function buildSccmAvailable(panel) {
        var lay = el('div'); lay.style.cssText = 'display:flex;flex-direction:column;gap:12px;min-height:100%;padding:12px;box-sizing:border-box';
        panel.appendChild(lay);
        var ctlCard = ui.card({}); ctlCard.style.cssText += ';display:flex;flex-direction:column;gap:10px';
        ctlCard.appendChild(el('div', 'j-section-h', 'AVAILABLE DEPLOYMENTS (single host)'));
        ctlCard.appendChild((function () { var d = el('div', 'muted', 'Everything MECM has available for one host - applicable apps + pending updates - in one list. Already-installed items are auto-unchecked. Check what to push, then Install Checked.'); d.style.cssText = 'font-size:11.5px'; return d; })());
        var picker = hostPickerRow('Host'); ctlCard.appendChild(picker.el);
        var btnRow = el('div'); btnRow.style.cssText = 'display:flex;gap:10px;align-items:center;flex-wrap:wrap';
        var queryBtn = ui.button('Query Available', { variant: 'cyan' });
        var installBtn = ui.button('Install Checked', { variant: 'danger', title: 'Trigger install of the checked apps/updates on this host.' });
        var expBtn = ui.ghostButton('Export CSV', { size: 'sm' });
        btnRow.appendChild(queryBtn); btnRow.appendChild(installBtn); btnRow.appendChild(expBtn);
        ctlCard.appendChild(btnRow);
        lay.appendChild(ctlCard);

        var gridCard = ui.card({}); gridCard.style.cssText += ';flex:1;display:flex;flex-direction:column;min-height:0';
        gridCard.appendChild(el('div', 'j-section-h', 'AVAILABLE (check to deploy)'));
        var grid = C.ResultsGrid({
          title: 'Available deployments', selectable: true, keyMode: { rk: true },
          columns: [
            { key: 'Type', label: 'TYPE', width: 80, render: function (r) { var t = String(r.Type || ''); return { text: t, cls: t === 'App' ? 'st-ok' : (t === 'Update' ? 'st-warn' : 'cell-dim') }; } },
            { key: 'Name', label: 'NAME', width: 300 },
            { key: 'State', label: 'STATE', width: 110, render: function (r) { var s = String(r.State || ''); return { text: s, cls: /installed/i.test(s) ? 'cell-dim' : (/error/i.test(s) ? 'st-bad' : 'st-warn') }; } },
            { key: 'Version', label: 'VERSION', width: 120 }
          ]
        });
        var gh = el('div'); gh.style.cssText = 'flex:1;min-height:0;display:flex'; gh.appendChild(grid.el); gridCard.appendChild(gh);
        var prog = C.ProgressStatusStrip({ showCount: true }); prog.el.style.marginTop = '8px'; gridCard.appendChild(prog.el);
        lay.appendChild(gridCard);

        var logCard = ui.card({}); logCard.classList.add('j-logdock');
        var log = C.ActivityLog({ title: 'ACTIVITY LOG', defaultName: 'WPT_Available' });
        logCard.appendChild(log.el); lay.appendChild(logCard);
        log.append({ text: 'Available Deployments ready. Pick a host, Query Available, check items, then Install Checked.', level: 'accent' });

        var run = null;
        queryBtn.onclick = function () {
          var hn = picker.host(); if (!hn) { notice('No host', 'Pick or type a host first.'); return; }
          grid.clear(); prog.reset(); log.banner('Query Available - ' + hn);
          run = ctx.run('sccm-available', { host: hn }, { keyOf: function (r) { return r._rk || (r.Type + '|' + r.Id + '|' + r.Name); } });
          // audit 2026-07-23 deferred pass: per-key resub (re-click stacked handlers)
          resub('sccm-available', run, {
            status: function (t) { prog.setPhase(t); },
            row: function (r) { grid.upsert(r); },
            log: function (l) { log.append(l); },
            error: function (e) { log.append({ text: e.text, level: 'err' }); },
            final: function () { grid.selectWhere(function (r) { return r.Type && r.Type !== '(info)' && !/installed/i.test(String(r.State || '')); }); log.banner('Query complete - ' + grid.rows().length + ' available; non-installed pre-checked'); },
            active: function (a) { queryBtn.disabled = a; }
          });
        };
        installBtn.onclick = async function () {
          var hn = picker.host(); if (!hn) { notice('No host', 'Pick or type a host first.'); return; }
          if (needCred()) return;
          var checked = grid.getChecked().filter(function (r) { return r.Type === 'App' || r.Type === 'Update'; });
          if (!checked.length) { notice('Nothing checked', 'Check at least one App/Update to deploy.'); return; }
          var ok = await ctx.confirm({ title: 'Install Available', danger: true, body: 'Trigger install of <b>' + checked.length + '</b> deployment(s) on <b>' + esc(hn) + '</b>? Apps via Software Center, updates via the Software Updates agent.', okText: 'Install', cancelText: 'Cancel' });
          if (!ok) { log.append({ text: 'Install cancelled.', level: 'warn' }); return; }
          var items = checked.map(function (r) { return [r.Type, r.Id, r.Revision || '', String(r.Name || '').replace(/[|\r\n]/g, ' ')].join('|'); }).join('\n');
          log.banner('Install Checked - ' + checked.length + ' item(s) on ' + hn);
          prog.reset();
          installBtn.disabled = true;
          var run2 = ctx.run('sccm-install-available', { host: hn, items: items }, { keyOf: function (r) { return (r.Host || '') + '|' + (r.Type || '') + '|' + (r.Name || ''); } });
          // audit 2026-07-23 deferred pass: per-key resub (re-click stacked handlers)
          resub('sccm-install-available', run2, {
            status: function (t) { prog.setPhase(t); },
            row: function (r) { log.append({ text: '[' + (r.Type || '') + '] ' + (r.Name || '') + ' - ' + (r.Result || '') + (r.Detail ? ' (' + r.Detail + ')' : ''), level: /fail/i.test(String(r.Result)) ? 'err' : (/skip/i.test(String(r.Result)) ? 'warn' : 'ok') }); },
            log: function (l) { log.append(l); },
            error: function (e) { log.append({ text: e.text, level: 'err' }); },
            final: function () { log.banner('Install Checked complete'); },
            active: function (a) { if (!a) installBtn.disabled = false; }
          });
        };
        expBtn.onclick = function () { exportGridCsv(grid, 'WPT_Available_' + (picker.host() || 'host')); };
      }

      // ---- TAB: Maintenance (logon banner + optional hard-lock; PIRS Lockout parity) ----
      function buildMaintenance(panel) {
        var capInput, msgInput, hardCb;
        var tab = makeRunTab(panel, {
          actionId: 'maintenance-lock', runLabel: 'LOCK FOR MAINTENANCE', cancelLabel: 'CANCEL',
          title: 'MAINTENANCE LOCK', logName: 'WPT_Maintenance',
          description: 'Set a maintenance logon banner on each target; optionally HARD-LOCK interactive logon to local Administrators (standard users cannot sign in) for a patch window. UNLOCK restores normal logon from a per-host backup. Local admins are never locked out.',
          columns: [
            { key: 'Host', label: 'HOST', width: 150 },
            { key: 'Success', label: 'RESULT', width: 90, render: function (r) { return asBool(r.Success) ? { text: 'OK', cls: 'st-ok' } : { text: 'Failed', cls: 'st-bad' }; } },
            { key: 'Mode', label: 'MODE', width: 110, render: function (r) { var m = String(r.Mode || ''); return { text: m, cls: /hard/i.test(m) ? 'st-warn' : (/fail/i.test(m) ? 'st-bad' : (m ? 'st-ok' : '')) }; } },
            { key: 'Detail', label: 'DETAIL' }
          ],
          rowClass: function (r) { return r.Success == null ? '' : (asBool(r.Success) ? 'row-ok' : 'row-bad'); },
          settings: function (h) {
            capInput = ui.input({ value: 'System Maintenance', title: 'Logon banner caption.' }); capInput.style.minWidth = '200px';
            h.appendChild(ui.field('Banner caption', capInput));
            msgInput = ui.textarea({ rows: 2, value: 'This workstation is undergoing scheduled maintenance by the 48th Communications Squadron. Please do not log in until maintenance is complete.' });
            msgInput.style.minWidth = '360px';
            h.appendChild(ui.field('Banner message', msgInput));
            hardCb = ui.checkbox('Hard lock (block standard-user logon)', { checked: false, color: 'var(--warn)' });
            h.appendChild(hardCb);
            var t = threadsInput(h, 16);
            return function () { return { caption: capInput.value, message: msgInput.value, hardlock: hardCb._cb.checked, threads: t() }; };
          },
          params: function (api) { var s = api.getSettings(); return { caption: s.caption, message: s.message, hardlock: s.hardlock, threads: s.threads }; },
          confirmBeforeRun: function (api) {
            if (needCred()) return Promise.resolve(false);
            var s = api.getSettings();
            if (!s.hardlock) {
              return ctx.confirm({ title: 'Confirm Maintenance Lock', body: 'Set the maintenance banner on <b>' + ctx.targets.count() + '</b> host(s). Logon is NOT blocked (banner only). Proceed?', okText: 'Set Banner', cancelText: 'Cancel' });
            }
            return ctx.arm({
              title: 'Confirm Maintenance Lock',
              body: 'HARD-LOCK <b>' + ctx.targets.count() + '</b> host(s): set the maintenance banner AND restrict interactive logon to local Administrators (standard users cannot sign in) until you Unlock. The original logon right is backed up per host; admins keep access. Proceed?',
              confirmWord: 'LOCK',
              okText: 'Hard Lock', cancelText: 'Cancel'
            });
          },
          onFinal: function (log, grid) { log.banner('Maintenance Lock complete - ' + grid.rows().length + ' host(s)'); },
          intro: [{ text: 'Maintenance Lock ready. Set a banner (and optionally hard-lock) for a patch window, then UNLOCK when done.', level: 'accent' }]
        });

        // UNLOCK bar (clears banner + restores logon across the whole target list)
        var bar = el('div'); bar.style.cssText = 'display:flex;gap:10px;align-items:center;margin-top:10px;flex-wrap:wrap';
        var unlockBtn = ui.button('UNLOCK (CLEAR MAINTENANCE)', { variant: 'gold', title: 'Clear the banner and restore normal logon on every target.' });
        bar.appendChild(unlockBtn);
        tab.prog.el.parentNode.appendChild(bar);
        unlockBtn.onclick = async function () {
          if (!ctx.targets.count()) { notice('No Targets', 'Build the host list first.'); return; }
          if (needCred()) return;
          var ok = await ctx.confirm({ title: 'Confirm Maintenance Unlock', body: 'Clear the maintenance banner and restore normal interactive logon on <b>' + ctx.targets.count() + '</b> host(s)?', okText: 'Unlock', cancelText: 'Cancel' });
          if (!ok) { tab.log.append({ text: 'Unlock cancelled.', level: 'warn' }); return; }
          tab.log.banner('Maintenance Unlock - ' + ctx.targets.count() + ' host(s)');
          unlockBtn.disabled = true;
          var run = ctx.run('maintenance-unlock', { targets: ctx.targets.raw });
          // audit 2026-07-23 deferred pass: per-key resub (re-click stacked handlers)
          resub('maintenance-unlock', run, {
            status: function (t) { tab.prog.setPhase(t); },
            progress: function (p) { tab.prog.setProgress(p.done, p.total); },
            row: function (r) { tab.grid.upsert({ Host: r.Host, Success: r.Success, Mode: 'Unlock', Detail: r.Detail }); tab.log.append({ text: '[' + r.Host + '] ' + (asBool(r.Success) ? 'unlocked' : 'FAILED') + (r.Detail ? ' - ' + r.Detail : ''), level: asBool(r.Success) ? 'ok' : 'err' }); },
            log: function (l) { tab.log.append(l); },
            error: function (e) { tab.log.append({ text: e.text, level: 'err' }); },
            final: function () { tab.log.banner('Maintenance Unlock complete'); },
            active: function (a) { if (!a) unlockBtn.disabled = false; }
          });
        };
      }

      var tabs = [
        { id: 'targets', label: 'Targets', build: buildTargets },
        { id: 'bulk', label: 'Bulk Scan & Patch', build: buildBulk },
        { id: 'software', label: 'Software Manager', build: buildSoftwareManager },
        { id: 'sccm', label: 'Software Center Apps', build: buildSoftwareCenter },
        { id: 'available', label: 'Available Deployments', build: buildSccmAvailable },
        { id: 'kb', label: 'KB Scanner', build: buildKbScanner },
        { id: 'verifypatch', label: 'Verify Patch', build: buildVerifyPatch },
        { id: 'appupd', label: 'App Updater', build: buildAppUpdater },
        { id: 'beta', label: 'Beta', build: buildBeta },
        { id: 'cleanup', label: 'Cleanup', build: buildCleanup },
        { id: 'cleanapps', label: 'Clean User Apps', build: buildCleanUserApps },
        { id: 'regkey', label: 'Reg Key Fixes', build: buildRegKeys },
        { id: 'unsupported', label: 'Unsupported Software', build: buildUnsupported },
        { id: 'log4j', label: 'Log4j Finder', build: buildLog4j },
        { id: 'health', label: 'Health / Healers', build: buildHealth },
        { id: 'hostinfo', label: 'Host Info', build: buildHostInfo },
        { id: 'eventlog', label: 'Event Logs', build: buildEventLog },
        { id: 'winrm', label: 'WinRM Setup', build: buildWinRM },
        { id: 'reboot', label: 'Reboot Countdown', build: buildReboot },
        { id: 'maint', label: 'Maintenance', build: buildMaintenance },
        { id: 'message', label: 'Remote Message', build: buildRemoteMessage },
        { id: 'reports', label: 'Reports', build: buildReports },
        { id: 'trend', label: 'Compliance Trend', build: buildTrend },
        { id: 'usage', label: 'Usage', build: buildUsage },
        { id: 'logs', label: 'Logs', build: buildLogs }
      ];

      var tabHost = C.TabHost({ rail: 'left', helpId: 'wpt', tabs: tabs });
      var tabWrap = el('div'); tabWrap.style.cssText = 'flex:1;min-height:0;display:flex';
      tabWrap.appendChild(tabHost.el);
      root.appendChild(tabWrap);

      // open Targets first (the desktop's gate-after, list-build-first flow)
      tabHost.select('targets');

      host.appendChild(root);
      this._root = root;
      this._unsub = function () { unsubs.forEach(function (u) { try { u(); } catch (e) {} }); unsubs = []; };
    }
  });
})();
