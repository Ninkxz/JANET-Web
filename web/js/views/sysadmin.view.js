/* ============================================================================
   sysadmin.view.js  -  Sysadmin Sweeps (tool id: 'sysadmin')
   Read-only WinRM fleet sweeps for common AFNET findings. Three tabs, each a
   left rail (TARGETS via TargetManager + sweep options + a Run bar) beside a
   StatCards row and a per-host/-cert ResultsGrid, all logging to one shared
   ActivityLog dock along the bottom (history.view.js structure):
     1. Local Admins    - members of the local Administrators group per host.
     2. Cert Expiry     - Cert:\LocalMachine\My certs expiring within N days.
     3. Reboot Pending  - reboot-pending status from the 3 standard signals.
   Every sweep fans one worker per host (reachability -> session -> one read-only
   Invoke-Command) and CHANGES NOTHING. Credentials are UNIVERSAL (shell header);
   this view renders NO per-tool credential control.
   ========================================================================== */
(function () {
  'use strict';

  function yesNoCell(v, badWhenYes) {
    var yes = (v === true || String(v).toLowerCase() === 'true' || String(v) === 'Yes');
    if (v == null || v === '') return { text: '', cls: 'cell-dim' };
    return { text: yes ? 'Yes' : 'No', cls: yes ? (badWhenYes ? 'st-bad' : 'st-ok') : (badWhenYes ? 'cell-dim' : 'st-warn') };
  }
  function daysLeftCell(v) {
    var s = String(v == null ? '' : v);
    if (s === '') return { text: '', cls: 'cell-dim' };
    var n = parseInt(s, 10);
    if (isNaN(n)) return { text: s, cls: '' };
    if (n < 0) return { text: s, cls: 'st-bad' };       // already expired
    if (n <= 30) return { text: s, cls: 'st-warn' };    // expiring soon
    return { text: s, cls: 'st-ok' };
  }
  function errCell(v) {
    var t = String(v == null ? '' : v);
    return { text: t, cls: t ? 'st-warn' : 'cell-dim', title: t };
  }
  function intOr(node, dflt) {
    var n = parseInt(node && node.value, 10);
    if (isNaN(n) || n < 0) return dflt;
    var max = node && parseInt(node.max, 10);
    if (!isNaN(max) && max > 0 && n > max) n = max;
    return n;
  }

  JanetViews.register('sysadmin', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;
      var subs = [];
      function track(u) { if (u) subs.push(u); }
      function ts() { return ctx.util.clockStr(); }

      var actlog = C.ActivityLog({ title: 'ACTIVITY LOG', defaultName: 'SysadminSweeps_ActivityLog' });

      // Generic streaming binder. cfg: { action, params, grid, statusEl, label,
      // runbar, onReset, onRow, onFinal }.
      function startRun(cfg) {
        cfg.grid.clear();
        if (cfg.onReset) cfg.onReset();
        setLine(cfg.statusEl, 'Working...', 'st-info');
        var run = ctx.run(cfg.action, cfg.params, { keyOf: function (ev) { return ev._rk; }, destructive: false });
        var unsub = run.subscribe({
          status: function (t) { setLine(cfg.statusEl, t, 'st-info'); },
          progress: function (p) { if (cfg.onProgress) cfg.onProgress(p); },
          row: function (r) { cfg.grid.upsert(r); if (cfg.onRow) cfg.onRow(r); },
          log: function (l) { actlog.append(l); },
          error: function (e) { setLine(cfg.statusEl, (e && e.text) || 'Error', 'st-bad'); actlog.append({ text: (e && e.text) || 'error', level: 'err' }); },
          active: function (a) { if (cfg.runbar) cfg.runbar.setActive(a); if (cfg.onActive) cfg.onActive(a); },
          final: function (res) { if (cfg.onFinal) cfg.onFinal((res && res.summary) || {}); }
        });
        track(unsub);
        return run;
      }
      function setLine(node, txt, cls) { if (!node) return; node.textContent = txt == null ? '' : String(txt); node.className = cls || 'muted'; }

      function exportGrid(grid, cols, fileBase) {
        var rows = grid.rows();
        if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Run a sweep first - there are no result rows yet.', okText: 'OK', cancelText: null }); return; }
        var keys = cols.map(function (c) { return c[0]; });
        var csv = ctx.util.toCsv(cols.map(function (c) { return c[1]; }), rows, keys);
        ctx.util.downloadBlob(fileBase + '_' + ctx.util.fileStamp() + '.csv', 'text/csv', csv);
        actlog.append({ text: '[' + ts() + '] Exported ' + rows.length + ' row(s) to CSV.', level: 'info' });
      }

      function ctrlRow(labelText, control) {
        var w = el('div'); w.style.cssText = 'display:flex;align-items:center;gap:8px';
        w.appendChild(ui.label(labelText)); w.appendChild(control); return w;
      }

      // ---- generic sweep tab builder ----------------------------------------
      // spec: { action, label, cta, fileBase, gridTitle, gridDesc, columns,
      //         exportCols, cards, hasDays, onRow(counters,row), reconcile(counters,summary) }
      function buildSweepTab(spec) {
        return function (panel) {
          panel.style.cssText = 'display:flex;gap:14px;height:100%;min-height:0;box-sizing:border-box;padding:12px';

          // LEFT: targets + options + run
          var left = el('div'); left.style.cssText = 'flex:0 0 400px;display:flex;flex-direction:column;gap:12px;min-height:0;overflow:auto';
          var compCard = ui.namedCard('TARGETS');   // hint comes from the TargetManager below
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
          var daysIn = null;
          if (spec.hasDays) {
            daysIn = ui.number({ value: 90, min: 0, max: 3650, title: 'Report certs whose NotAfter is within this many days (already-expired always included).' });
            daysIn.style.width = '90px';
            optCard.appendChild(ctrlRow('Expiring within (days)', daysIn));
          }
          var offlineCb = ui.checkbox('Attempt even if offline (host unreachable)', { title: 'Proceed against a host that fails the TCP 5985/445 reachability probe. Reachability is TCP-only - AFNET drops ICMP.' });
          optCard.appendChild(offlineCb);
          var threadsRow = el('div'); threadsRow.style.cssText = 'display:flex;align-items:center;gap:10px';
          threadsRow.appendChild(ui.label('Max concurrent:'));
          var threadsIn = ui.number({ value: 16, min: 1, max: 32, title: 'Parallel hosts (1-32).' }); threadsIn.style.width = '80px';
          threadsRow.appendChild(threadsIn);
          optCard.appendChild(threadsRow);
          var statusLine = el('div', 'muted', 'Ready'); statusLine.style.fontSize = '12px';
          optCard.appendChild(statusLine);
          left.appendChild(optCard);

          var actCard = ui.card({}); actCard.style.cssText += ';display:flex;flex-direction:column;gap:8px';
          var runbar = C.RunBar({
            label: spec.cta, cancelLabel: 'CANCEL SWEEP', morphToCancel: true,
            title: 'Read-only ' + spec.label + ' across every host (changes nothing).',
            guards: [ function () { return targets.count() ? null : 'No Hosts|Add at least one host to the list first.'; } ],
            onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
            onRun: doRun,
            onCancel: function () { if (curRun) { curRun.cancel(); actlog.append({ text: '[' + ts() + '] CANCEL requested - queued hosts skip; in-flight probes finish.', level: 'warn' }); } }
          });
          var rbWrap = el('div'); rbWrap.appendChild(runbar.el); actCard.appendChild(rbWrap);
          left.appendChild(actCard);
          panel.appendChild(left);

          // RIGHT: stats + head + grid
          var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:12px;min-height:0';
          var stats = C.StatCards({ cards: spec.cards });
          right.appendChild(stats.el);

          var head = ui.card({}); head.style.cssText += ';display:flex;align-items:center;gap:12px;flex-wrap:wrap';
          var exportBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the result rows to CSV.' });
          var clearBtn = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the results grid.' });
          var spacer = el('div'); spacer.style.flex = '1'; head.appendChild(spacer);
          head.appendChild(exportBtn); head.appendChild(clearBtn);
          right.appendChild(head);

          var results = ui.namedCard(spec.gridTitle, spec.gridDesc);
          results.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
          var grid = C.ResultsGrid({
            title: spec.gridTitle, keyMode: { rk: true }, popOut: true, selectable: false,
            columns: spec.columns, rowClass: spec.rowClass
          });
          var gh = el('div'); gh.style.cssText = 'flex:1;min-height:0;display:flex'; gh.appendChild(grid.el);
          results.appendChild(gh); right.appendChild(results);
          panel.appendChild(right);

          exportBtn.onclick = function () { exportGrid(grid, spec.exportCols, spec.fileBase); };
          clearBtn.onclick = function () { grid.clear(); stats.reset(); setLine(statusLine, 'Ready'); };

          var curRun = null;
          var counters = {};
          function doRun() {
            var hosts = targets.hosts();
            var params = { targets: hosts.join('\n'), attemptOffline: offlineCb._cb.checked, threads: intOr(threadsIn, 16) };
            if (spec.hasDays) params.days = intOr(daysIn, 90);
            actlog.append({ text: '[' + ts() + '] ' + spec.label + ' on ' + hosts.length + ' host(s).', level: 'accent' });
            lockInputs(true);
            curRun = startRun({
              action: spec.action, label: spec.cta, runbar: runbar, grid: grid, statusEl: statusLine, params: params,
              onReset: function () { stats.reset(); counters = { hosts: {}, online: {}, err: {}, a: 0, b: 0 }; },
              onRow: function (r) { if (spec.onRow) spec.onRow(counters, r); stats.setAll(spec.snapshot(counters)); },
              onActive: function (a) { if (!a) lockInputs(false); },
              onFinal: function (s) {
                if (spec.reconcile) spec.reconcile(counters, s);
                stats.setAll(spec.snapshot(counters, s));
                setLine(statusLine, spec.doneText(counters, s), spec.doneCls(counters, s));
              }
            });
          }
          function lockInputs(on) {
            offlineCb._cb.disabled = on; threadsIn.disabled = on; clearBtn.disabled = on;
            if (daysIn) daysIn.disabled = on;
          }
        };
      }

      // ---- per-sweep specs --------------------------------------------------
      var hostCount = function (c) { return Object.keys(c.hosts).length; };
      var onlineCount = function (c) { return Object.keys(c.online).length; };
      var errCount = function (c) { return Object.keys(c.err).length; };
      function markHost(c, r) {
        var h = String(r.Host == null ? '' : r.Host);
        if (h) { c.hosts[h] = 1; if (r.Online === true || String(r.Online) === 'true') c.online[h] = 1; if (r.Error) c.err[h] = 1; }
      }

      var localAdminTab = buildSweepTab({
        action: 'localadmin-sweep', label: 'Local Admins sweep', cta: 'RUN LOCAL ADMINS SWEEP',
        fileBase: 'Sysadmin_LocalAdmins', gridTitle: 'LOCAL ADMINISTRATORS', gridDesc: 'One row per host: the members of the local Administrators group (resolved by SID S-1-5-32-544).',
        columns: [
          { key: 'Host', label: 'HOST', width: 160 },
          { key: 'Online', label: 'ONLINE', width: 80, render: function (r) { return yesNoCell(r.Online, false); } },
          { key: 'Admins', label: 'ADMINS', render: function (r) { var t = String(r.Admins == null ? '' : r.Admins); return { text: t, title: t }; } },
          { key: 'AdminCount', label: 'COUNT', width: 80, type: 'text' },
          { key: 'Error', label: 'ERROR', width: 200, render: function (r) { return errCell(r.Error); } }
        ],
        exportCols: [['Host', 'Host'], ['Online', 'Online'], ['Admins', 'Admins'], ['AdminCount', 'AdminCount'], ['Error', 'Error']],
        cards: [ { key: 'hosts', label: 'HOSTS', color: 'cyan' }, { key: 'online', label: 'ONLINE', color: 'ok' }, { key: 'errors', label: 'ERRORS', color: 'bad' } ],
        onRow: markHost,
        snapshot: function (c, s) { return { hosts: s && s.total != null ? s.total : hostCount(c), online: s && s.hostsOnline != null ? s.hostsOnline : onlineCount(c), errors: s && s.hostsWithError != null ? s.hostsWithError : errCount(c) }; },
        doneText: function (c, s) { return 'Done - ' + (s.total || hostCount(c)) + ' host(s), ' + (s.hostsOnline != null ? s.hostsOnline : onlineCount(c)) + ' online'; },
        doneCls: function (c, s) { return (s.hostsWithError ? 'st-warn' : 'st-ok'); }
      });

      var certTab = buildSweepTab({
        action: 'certexpiry-sweep', label: 'Cert Expiry sweep', cta: 'RUN CERT EXPIRY SWEEP', hasDays: true,
        fileBase: 'Sysadmin_CertExpiry', gridTitle: 'EXPIRING CERTIFICATES', gridDesc: 'One row per expiring cert in Cert:\\LocalMachine\\My; negative DaysLeft = already expired.',
        columns: [
          { key: 'Host', label: 'HOST', width: 150 },
          { key: 'Online', label: 'ONLINE', width: 80, render: function (r) { return yesNoCell(r.Online, false); } },
          { key: 'Subject', label: 'SUBJECT', render: function (r) { var t = String(r.Subject == null ? '' : r.Subject); return { text: t, title: t }; } },
          { key: 'Issuer', label: 'ISSUER', width: 200, render: function (r) { var t = String(r.Issuer == null ? '' : r.Issuer); return { text: t, title: t }; } },
          { key: 'Expires', label: 'EXPIRES', width: 110 },
          { key: 'DaysLeft', label: 'DAYS LEFT', width: 90, render: function (r) { return daysLeftCell(r.DaysLeft); } },
          { key: 'Thumbprint', label: 'THUMBPRINT', width: 180, render: function (r) { return { text: String(r.Thumbprint == null ? '' : r.Thumbprint), cls: 'cell-dim' }; } },
          { key: 'Error', label: 'ERROR', width: 160, render: function (r) { return errCell(r.Error); } }
        ],
        exportCols: [['Host', 'Host'], ['Online', 'Online'], ['Subject', 'Subject'], ['Issuer', 'Issuer'], ['Expires', 'Expires'], ['DaysLeft', 'DaysLeft'], ['Thumbprint', 'Thumbprint'], ['Error', 'Error']],
        cards: [ { key: 'hosts', label: 'HOSTS', color: 'cyan' }, { key: 'expiring', label: 'EXPIRING CERTS', color: 'gold' }, { key: 'expired', label: 'EXPIRED', color: 'bad' }, { key: 'errors', label: 'ERRORS', color: 'accent' } ],
        rowClass: function (r) { var n = parseInt(r.DaysLeft, 10); if (!isNaN(n) && n < 0) return 'row-bad'; if (!isNaN(n) && n <= 30) return 'row-warn'; return ''; },
        onRow: function (c, r) {
          markHost(c, r);
          var n = parseInt(r.DaysLeft, 10);
          if (!isNaN(n)) { c.a++; if (n < 0) c.b++; }   // a = expiring cert rows, b = already expired
        },
        snapshot: function (c, s) { return { hosts: s && s.total != null ? s.total : hostCount(c), expiring: s && s.expiringCerts != null ? s.expiringCerts : c.a, expired: s && s.expiredCerts != null ? s.expiredCerts : c.b, errors: s && s.hostsWithError != null ? s.hostsWithError : errCount(c) }; },
        doneText: function (c, s) { return 'Done - ' + (s.expiringCerts != null ? s.expiringCerts : c.a) + ' expiring, ' + (s.expiredCerts != null ? s.expiredCerts : c.b) + ' expired'; },
        doneCls: function (c, s) { var expd = (s.expiredCerts != null ? s.expiredCerts : c.b); return (expd ? 'st-bad' : ((s.expiringCerts != null ? s.expiringCerts : c.a) ? 'st-warn' : 'st-ok')); }
      });

      var rebootTab = buildSweepTab({
        action: 'rebootpending-sweep', label: 'Reboot Pending sweep', cta: 'RUN REBOOT PENDING SWEEP',
        fileBase: 'Sysadmin_RebootPending', gridTitle: 'REBOOT PENDING', gridDesc: 'One row per host: reboot-pending from CBS + Windows Update + PendingFileRenameOperations.',
        columns: [
          { key: 'Host', label: 'HOST', width: 160 },
          { key: 'Online', label: 'ONLINE', width: 80, render: function (r) { return yesNoCell(r.Online, false); } },
          { key: 'RebootPending', label: 'REBOOT PENDING', width: 130, render: function (r) { return yesNoCell(r.RebootPending, true); } },
          { key: 'Reasons', label: 'REASONS', render: function (r) { var t = String(r.Reasons == null ? '' : r.Reasons); return { text: t, title: t }; } },
          { key: 'Error', label: 'ERROR', width: 200, render: function (r) { return errCell(r.Error); } }
        ],
        exportCols: [['Host', 'Host'], ['Online', 'Online'], ['RebootPending', 'RebootPending'], ['Reasons', 'Reasons'], ['Error', 'Error']],
        cards: [ { key: 'hosts', label: 'HOSTS', color: 'cyan' }, { key: 'pending', label: 'REBOOT PENDING', color: 'bad' }, { key: 'errors', label: 'ERRORS', color: 'accent' } ],
        rowClass: function (r) { return (r.RebootPending === true || String(r.RebootPending) === 'true') ? 'row-bad' : ''; },
        onRow: function (c, r) { markHost(c, r); if (r.RebootPending === true || String(r.RebootPending) === 'true') c.a++; },
        snapshot: function (c, s) { return { hosts: s && s.total != null ? s.total : hostCount(c), pending: s && s.rebootPending != null ? s.rebootPending : c.a, errors: s && s.hostsWithError != null ? s.hostsWithError : errCount(c) }; },
        doneText: function (c, s) { return 'Done - ' + (s.rebootPending != null ? s.rebootPending : c.a) + ' pending of ' + (s.total || hostCount(c)); },
        doneCls: function (c, s) { return ((s.rebootPending != null ? s.rebootPending : c.a) ? 'st-warn' : 'st-ok'); }
      });

      // ---- assemble: TabHost + bottom activity dock -------------------------
      var root = el('div'); root.style.cssText = 'display:flex;flex-direction:column;gap:12px;height:100%;min-height:0;padding:14px;box-sizing:border-box';
      var tabHolder = el('div'); tabHolder.style.cssText = 'flex:1;min-height:0;display:flex';
      var tabs = C.TabHost({
        rail: 'top',
        helpId: 'sysadmin',
        tabs: [
          { id: 'localadmin', label: 'Local Admins', build: localAdminTab },
          { id: 'certexpiry', label: 'Cert Expiry', build: certTab },
          { id: 'rebootpending', label: 'Reboot Pending', build: rebootTab }
        ]
      });
      tabHolder.appendChild(tabs.el);
      root.appendChild(tabHolder);

      var logCard = ui.card({}); logCard.classList.add('j-logdock');
      logCard.appendChild(actlog.el);
      root.appendChild(logCard);

      actlog.append({ text: 'Sysadmin Sweeps ready. Read-only WinRM sweeps - Local Admins, Cert Expiry, Reboot Pending. Add hosts, pick a tab, run. Changes nothing.', level: 'accent' });

      host.appendChild(root);
      this._root = root;
      this._unsub = function () { subs.forEach(function (u) { try { u(); } catch (e) {} }); };
    },
    unmount: function () { try { if (this._unsub) this._unsub(); } catch (e) {} if (this._root) this._root.remove(); }
  });
})();
