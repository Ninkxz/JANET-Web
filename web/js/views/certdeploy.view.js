/* ============================================================================
   certdeploy.view.js  -  Cert Deploy (tool id: 'certdeploy')
   Proactive DoD/LTMA trust-root deployment. A single-frame layout (sysadmin /
   secureboot idiom): a left rail with a TargetManager (paste / Import TXT), the
   cert-bundle-folder input, an "Import C2C export -> load all PKI-tagged hosts"
   file control, and a run bar with a read-only CHECK and a destructive DEPLOY
   button; beside it a results grid (Host/Ping/Status/Missing/Detail) with Export
   CSV, and a shared activity log along the bottom.

   CHECK  (action 'check')            - read-only; reports which hosts are missing
                                        which roots (+ expired-in-bundle count).
                                        No admin session, no confirm.
   DEPLOY (action 'deploy')           - destructive; admin-session gated + a type-
                                        DEPLOY arm dialog stating it ADDITIVELY
                                        installs the DoD roots and never removes.
                                        Expired certs are skipped by default; an
                                        "Include expired certs" checkbox opts in.
   SCAN CERT MANAGEMENT (action 'scan-cert-management') - read-only, no admin
                                        gate, no confirm; reports whether
                                        InstallRoot / GPO manages trust roots
                                        per host (a manual push may be
                                        reconciled away).
   Import (action 'import-pki-hosts') - parse a C2C export, load every PKI-tagged
                                        host into the TargetManager.
   Credentials are UNIVERSAL (shell header) - this view renders NO cred control.
   ========================================================================== */
(function () {
  'use strict';

  var HOST_RE = /^[A-Za-z0-9._-]+$/;
  var EXPORT_COLS = [['Host', 'Host'], ['Ping', 'Ping'], ['Status', 'Status'], ['Missing', 'Missing'], ['Detail', 'Detail']];

  function statusCellCls(v) {
    var s = String(v == null ? '' : v);
    if (s === 'ALL PRESENT' || s === 'ROOTS INSTALLED' || s === 'ROOTS ALREADY PRESENT') return 'st-ok';
    if (s.indexOf('MISSING') === 0) return 'st-warn';
    if (s === 'OFFLINE' || s === 'SKIPPED') return 'st-warn';
    if (s === 'CHECK ERROR' || s === 'FAILED' || s === 'Cancelled') return 'st-bad';
    if (s === 'Queued') return 'st-info';
    return '';
  }
  function statusRowCls(v) {
    var s = String(v == null ? '' : v);
    if (s === 'ALL PRESENT' || s === 'ROOTS INSTALLED' || s === 'ROOTS ALREADY PRESENT') return 'row-ok';
    if (s.indexOf('MISSING') === 0) return 'row-warn';
    if (s === 'OFFLINE' || s === 'SKIPPED') return 'row-warn';
    if (s === 'CHECK ERROR' || s === 'FAILED' || s === 'Cancelled') return 'row-bad';
    return '';
  }
  function reconcilerCls(v) {
    var s = String(v == null ? '' : v);
    if (s === 'None detected') return 'st-ok';
    if (s === 'InstallRoot' || s === 'GPO' || s === 'InstallRoot+GPO') return 'st-warn';
    if (s === 'OFFLINE') return 'st-warn';
    if (s === 'CHECK ERROR') return 'st-bad';
    return '';
  }

  JanetViews.register('certdeploy', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;
      var run = null, unsub = null;
      var scanRun = null, scanUnsub = null;
      function ts() { return ctx.util.clockStr(); }
      var esc = (ctx.util && ctx.util.esc) ? ctx.util.esc : function (s) { return String(s == null ? '' : s); };

      var actlog = C.ActivityLog({ title: 'ACTIVITY LOG', defaultName: 'CertDeploy_ActivityLog' });

      var root = el('div'); root.style.cssText = 'display:flex;flex-direction:column;gap:12px;height:100%;min-height:0;padding:14px;box-sizing:border-box';
      var main = el('div'); main.style.cssText = 'display:flex;gap:14px;flex:1;min-height:0';

      // ---------- LEFT: targets + bundle + import + run ----------
      var left = el('div'); left.style.cssText = 'flex:0 0 400px;display:flex;flex-direction:column;gap:12px;min-height:0;overflow:auto';

      var tgtCard = ui.namedCard('TARGETS');
      tgtCard.style.cssText += ';flex:0 0 auto;display:flex;flex-direction:column';
      var targets = C.TargetManager({
        model: ctx.util.targetModel(''),
        hint: 'One host per line - comma/space/semicolon ok; # starts a comment. Push the DoD roots to ANY PKI-tagged host to get ahead of non-compliance.',
        placeholder: 'WS-0001\nWS-0002\n# lab row\nWS-0003',
        importLabel: 'Import TXT', importAccept: '.txt', countNoun: 'host',
        onImport: function (n, name) { actlog.append({ text: '[' + ts() + '] Added ' + n + ' host(s) from ' + name, level: 'info' }); }
      });
      var tgHolder = el('div'); tgHolder.style.cssText = 'flex:1;min-height:120px;display:flex'; tgHolder.appendChild(targets.el);
      tgtCard.appendChild(tgHolder);
      left.appendChild(tgtCard);

      // Cert bundle folder + Import C2C export
      var optCard = ui.card({}); optCard.style.cssText += ';display:flex;flex-direction:column;gap:10px';
      optCard.appendChild(ui.label('DoD/LTMA trust bundle folder'));
      var bundleInput = ui.input({ title: 'Server-readable folder with root\\*.cer, Intermediate\\*.cer, Untrusted\\*.cer (or loose *.cer). Leave BLANK to use the shipped Packages\\DoD-Certs bundle.' });
      bundleInput.placeholder = 'blank = shipped Packages\\DoD-Certs';
      bundleInput.style.width = '100%';
      optCard.appendChild(bundleInput);
      var bundleHint = el('div', 'muted', 'Blank uses the shipped Packages\\DoD-Certs bundle.'); bundleHint.style.fontSize = '11px';
      optCard.appendChild(bundleHint);

      // Import C2C export -> load all PKI-tagged hosts
      var importFileInput = el('input'); importFileInput.type = 'file'; importFileInput.accept = '.csv,.txt'; importFileInput.style.display = 'none';
      var importBtn = ui.button('Import C2C export -> load all PKI-tagged hosts', { variant: 'gold', size: 'sm', title: 'Choose a Tanium C2C Compliance Status CSV export; every host carrying the PKI Trust Roots tag (audit OR failed, compliant OR not) loads into the target list.' });
      var importStatus = el('div', 'muted', ''); importStatus.style.fontSize = '11px';
      optCard.appendChild(importBtn); optCard.appendChild(importFileInput); optCard.appendChild(importStatus);

      var offlineCb = ui.checkbox('Attempt even if offline (host unreachable)', { title: 'Proceed against a host that fails the TCP 5985/5986/445 reachability probe. Reachability is TCP-only - AFNET drops ICMP. A host answering only on 5986 uses WinRM-over-HTTPS.' });
      optCard.appendChild(offlineCb);
      var includeExpiredCb = ui.checkbox('Include expired certs (dead anchors - normally skipped)', { title: 'Also push certificates whose NotAfter has already passed. Off by default - expired certs are dead trust anchors and are excluded from the bundle read + push unless ticked.' });
      optCard.appendChild(includeExpiredCb);
      var threadsRow = el('div'); threadsRow.style.cssText = 'display:flex;align-items:center;gap:10px';
      threadsRow.appendChild(ui.label('Max concurrent:'));
      var threadsIn = ui.number({ value: 16, min: 1, max: 32, title: 'Parallel hosts (Check 1-32; Deploy caps at 16).' }); threadsIn.style.width = '80px';
      threadsRow.appendChild(threadsIn);
      optCard.appendChild(threadsRow);
      var statusLine = el('div', 'muted', 'Ready'); statusLine.style.fontSize = '12px';
      optCard.appendChild(statusLine);
      left.appendChild(optCard);

      // Run bar: CHECK (read-only) + DEPLOY (destructive)
      var actCard = ui.card({}); actCard.style.cssText += ';display:flex;flex-direction:column;gap:8px';
      var checkRunbar = C.RunBar({
        label: 'CHECK TRUST CERTS', cancelLabel: 'CANCEL CHECK', morphToCancel: true,
        title: 'Read-only: report which hosts are missing which DoD roots (changes nothing).',
        guards: [
          function () { return targets.hosts().length ? null : 'No Hosts|Add at least one host to the list first.'; },
          function () { var bad = targets.hosts().filter(function (h) { return !HOST_RE.test(h); }); return bad.length ? ('Invalid Target Name|Not valid hostnames: ' + bad.slice(0, 5).join(', ') + '.') : null; }
        ],
        onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
        onRun: doCheck,
        onCancel: function () { if (run) { run.cancel(); actlog.append({ text: '[' + ts() + '] CANCEL requested.', level: 'warn' }); } }
      });
      var deployRunbar = C.RunBar({
        label: 'DEPLOY TRUST CERTS', cancelLabel: 'CANCEL DEPLOY', morphToCancel: true,
        title: 'Destructive: additively install the DoD roots into LocalMachine Root/CA/Disallowed (never removes). Needs an admin session.',
        guards: [
          function () { return targets.hosts().length ? null : 'No Hosts|Add at least one host to the list first.'; },
          function () { var bad = targets.hosts().filter(function (h) { return !HOST_RE.test(h); }); return bad.length ? ('Invalid Target Name|Not valid hostnames: ' + bad.slice(0, 5).join(', ') + '.') : null; },
          function () { return ctx.session.state.credSet ? null : 'Admin session required|Set ADW credentials (top-right) and start an admin session before deploying certificates - it writes to the LocalMachine stores.'; }
        ],
        onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
        onRun: doDeploy,
        onCancel: function () { if (run) { run.cancel(); actlog.append({ text: '[' + ts() + '] CANCEL requested.', level: 'warn' }); } }
      });
      var scanRunbar = C.RunBar({
        label: 'SCAN CERT MANAGEMENT', cancelLabel: 'CANCEL SCAN', morphToCancel: true,
        title: 'Read-only: reports whether InstallRoot policy and/or a GPO manages trust certs on each host (a manual push may be reconciled away). No admin session, no confirm.',
        guards: [
          function () { return targets.hosts().length ? null : 'No Hosts|Add at least one host to the list first.'; },
          function () { var bad = targets.hosts().filter(function (h) { return !HOST_RE.test(h); }); return bad.length ? ('Invalid Target Name|Not valid hostnames: ' + bad.slice(0, 5).join(', ') + '.') : null; }
        ],
        onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
        onRun: doScanMgmt,
        onCancel: function () { if (scanRun) { scanRun.cancel(); actlog.append({ text: '[' + ts() + '] CANCEL requested.', level: 'warn' }); } }
      });
      var checkWrap = el('div'); checkWrap.appendChild(checkRunbar.el); actCard.appendChild(checkWrap);
      var deployWrap = el('div'); deployWrap.appendChild(deployRunbar.el); actCard.appendChild(deployWrap);
      var scanWrap = el('div'); scanWrap.appendChild(scanRunbar.el); actCard.appendChild(scanWrap);
      left.appendChild(actCard);
      main.appendChild(left);

      // ---------- RIGHT: stats + head + grid ----------
      var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:12px;min-height:0';
      var stats = C.StatCards({ cards: [
        { key: 'hosts', label: 'HOSTS', color: 'cyan' },
        { key: 'ok', label: 'ALL PRESENT / INSTALLED', color: 'ok' },
        { key: 'missing', label: 'MISSING / FAILED', color: 'gold' },
        { key: 'errors', label: 'OFFLINE / ERRORS', color: 'accent' }
      ] });
      right.appendChild(stats.el);

      var head = ui.card({}); head.style.cssText += ';display:flex;align-items:center;gap:12px;flex-wrap:wrap';
      var exportBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the result rows to CSV.' });
      var clearBtn = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the results grid.' });
      var expiredBadge = el('div', 'muted', ''); expiredBadge.style.fontSize = '12px';
      head.appendChild(expiredBadge);
      var spacer = el('div'); spacer.style.flex = '1'; head.appendChild(spacer);
      head.appendChild(exportBtn); head.appendChild(clearBtn);
      right.appendChild(head);

      var results = ui.namedCard('CERT DEPLOY RESULTS', 'One row per host: Check reports missing roots per store; Deploy reports the additive install result.');
      results.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
      var grid = C.ResultsGrid({
        title: 'Cert Deploy results',
        emptyText: 'No results yet - add hosts, then Check or Deploy.',
        keyMode: { hostCol: 'Host' }, popOut: true, selectable: false,
        columns: [
          { key: 'Host', label: 'HOST', width: 150 },
          { key: 'Ping', label: 'PING', width: 90 },
          { key: 'Status', label: 'STATUS', width: 160, render: function (r) { return { text: r.Status == null ? '' : String(r.Status), cls: statusCellCls(r.Status) }; } },
          { key: 'Missing', label: 'MISSING', width: 90 },
          { key: 'Detail', label: 'DETAIL', render: function (r) { var t = String(r.Detail == null ? '' : r.Detail); return { text: t, title: t }; } }
        ],
        rowClass: function (r) { return statusRowCls(r.Status); }
      });
      var gh = el('div'); gh.style.cssText = 'flex:1;min-height:0;display:flex'; gh.appendChild(grid.el);
      results.appendChild(gh);
      var prog = C.ProgressStatusStrip({ showCount: true });
      prog.el.style.marginTop = '8px';
      results.appendChild(prog.el);
      right.appendChild(results);
      main.appendChild(right);

      root.appendChild(main);

      // ---------- SCAN CERT MANAGEMENT (read-only, no admin gate, no confirm) ----------
      var scanCard = ui.namedCard('SCAN CERT MANAGEMENT (what manages trust)', 'Read-only fleet scan: is InstallRoot policy and/or a GPO managing trust roots here (a manual push may get silently reconciled away)?');
      scanCard.style.cssText += ';display:flex;flex-direction:column;gap:8px;flex:0 0 auto';
      var scanStats = C.StatCards({ cards: [
        { key: 'total', label: 'HOSTS', color: 'cyan' },
        { key: 'installRoot', label: 'INSTALLROOT MANAGED', color: 'gold' },
        { key: 'gpoManaged', label: 'GPO MANAGED', color: 'gold' },
        { key: 'none', label: 'NONE DETECTED', color: 'ok' },
        { key: 'offline', label: 'OFFLINE', color: 'accent' }
      ] });
      scanCard.appendChild(scanStats.el);
      var scanGrid = C.ResultsGrid({
        title: 'Scan Cert Management results',
        emptyText: 'No results yet - add hosts, then Scan Cert Management.',
        keyMode: { hostCol: 'Host' }, popOut: true, selectable: false,
        columns: [
          { key: 'Host', label: 'HOST', width: 150 },
          { key: 'Ping', label: 'PING', width: 90 },
          { key: 'InstallRoot', label: 'INSTALLROOT', width: 110 },
          { key: 'GPRoots', label: 'GP ROOTS', width: 100 },
          { key: 'Reconciler', label: 'RECONCILER', width: 150, render: function (r) { return { text: r.Reconciler == null ? '' : String(r.Reconciler), cls: reconcilerCls(r.Reconciler) }; } },
          { key: 'Detail', label: 'DETAIL', render: function (r) { var t = String(r.Detail == null ? '' : r.Detail); return { text: t, title: t }; } }
        ]
      });
      var scanGh = el('div'); scanGh.style.cssText = 'min-height:160px;max-height:340px;display:flex'; scanGh.appendChild(scanGrid.el);
      scanCard.appendChild(scanGh);
      var scanProg = C.ProgressStatusStrip({ showCount: true });
      scanProg.el.style.marginTop = '8px';
      scanCard.appendChild(scanProg.el);
      root.appendChild(scanCard);

      var logCard = ui.card({}); logCard.classList.add('j-logdock');
      logCard.appendChild(actlog.el);
      root.appendChild(logCard);

      // ---------- behaviour ----------
      function setStatus(txt, cls) { statusLine.textContent = txt == null ? '' : String(txt); statusLine.className = cls || 'muted'; }
      function isRunning() { return !!(run && run.state && run.state.active) || isScanRunning(); }
      function isScanRunning() { return !!(scanRun && scanRun.state && scanRun.state.active); }
      function threads() { var n = parseInt(threadsIn.value, 10); if (isNaN(n) || n < 1) n = 16; if (n > 32) n = 32; return n; }
      function lockInputs(on) {
        offlineCb._cb.disabled = on; threadsIn.disabled = on; clearBtn.disabled = on;
        bundleInput.disabled = on; importBtn.disabled = on; includeExpiredCb._cb.disabled = on;
      }
      clearBtn.onclick = function () { if (isRunning()) return; grid.clear(); prog.reset(); stats.reset(); expiredBadge.textContent = ''; setStatus('Ready'); };
      exportBtn.onclick = function () {
        var rows = grid.rows();
        if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Run a Check or Deploy first - there are no result rows yet.', okText: 'OK', cancelText: null }); return; }
        var csv = ctx.util.toCsv(EXPORT_COLS.map(function (p) { return p[1]; }), rows, EXPORT_COLS.map(function (p) { return p[0]; }));
        ctx.util.downloadBlob('CertDeploy_Results_' + ctx.util.fileStamp() + '.csv', 'text/csv', csv);
        actlog.append({ text: '[' + ts() + '] Exported ' + rows.length + ' row(s) to CSV.', level: 'info' });
      };

      function summarize() {
        var okC = 0, miss = 0, err = 0, total = 0;
        grid.rows().forEach(function (r) {
          var s = String(r.Status);
          if (s === 'Queued') return;
          total++;
          if (s === 'ALL PRESENT' || s === 'ROOTS INSTALLED' || s === 'ROOTS ALREADY PRESENT') okC++;
          else if (s.indexOf('MISSING') === 0 || s === 'FAILED') miss++;
          else if (s === 'OFFLINE' || s === 'CHECK ERROR' || s === 'SKIPPED' || s === 'Cancelled') err++;
        });
        return { hosts: total, ok: okC, missing: miss, errors: err };
      }

      function bindRun(verb, finalNoun) {
        if (unsub) unsub();
        unsub = run.subscribe({
          status: function (t) { prog.setPhase(t); setStatus(t, (String(t) === 'error') ? 'st-bad' : 'st-info'); },
          progress: function (p) { prog.setProgress(p.done, p.total); setStatus('Running... ' + p.done + ' / ' + p.total + ' done', 'st-info'); },
          row: function (r) { grid.upsert(r); stats.setAll(summarize()); },
          log: function (l) { actlog.append(l); },
          error: function (e) { setStatus((e && e.text) || 'Error', 'st-bad'); actlog.append({ text: '[' + ts() + '] ' + ((e && e.text) || 'error'), level: 'err' }); },
          active: function (a) {
            checkRunbar.setActive(a); deployRunbar.setActive(a);
            if (!a) {
              lockInputs(false);
              var c = summarize(); stats.setAll(c);
              var bad = c.missing + c.errors;
              setStatus(verb + ' complete - ' + c.ok + ' ' + finalNoun + ', ' + c.missing + ' missing/failed, ' + c.errors + ' offline/error', bad ? 'st-warn' : 'st-ok');
              actlog.append({ text: '[' + ts() + '] FINISHED ' + verb + '. OK=' + c.ok + '  MISSING/FAILED=' + c.missing + '  OFFLINE/ERROR=' + c.errors, level: bad ? 'warn' : 'ok' });
            }
          },
          final: function (res) {
            var sum = (res && res.summary) || {};
            var ec = sum.ExpiredCount || 0;
            if (ec > 0) {
              expiredBadge.textContent = ec + ' expired in bundle (skipped)';
              expiredBadge.className = 'st-warn';
              var subs = (sum.Expired || []).map(function (x) { return x && x.Subject; }).filter(function (s) { return !!s; });
              actlog.append({ text: '[' + ts() + '] ' + ec + ' expired cert(s) in bundle (skipped): ' + subs.slice(0, 5).join(', ') + (subs.length > 5 ? ' ...' : ''), level: 'warn' });
            } else {
              expiredBadge.textContent = ''; expiredBadge.className = 'muted';
            }
          }
        });
      }

      // ---- CHECK (read-only) ----
      function doCheck() {
        if (isRunning()) return;
        var hosts = targets.hosts();
        grid.clear(); prog.reset(); stats.reset();
        hosts.forEach(function (h) { grid.upsert({ Host: h, Ping: '', Status: 'Queued', Missing: '', Detail: 'Queued' }); });
        actlog.append({ text: '[' + ts() + '] Check Trust Certs on ' + hosts.length + ' host(s).', level: 'accent' });
        lockInputs(true);
        run = ctx.run('check', {
          targets: hosts.join('\n'),
          certBundleFolder: String(bundleInput.value || ''),
          attemptOffline: !!offlineCb._cb.checked,
          threads: threads()
        }, { keyOf: function (ev) { return ev.Host != null ? String(ev.Host) : null; }, destructive: false });
        bindRun('Check', 'all-present');
      }

      // ---- DEPLOY (destructive; admin-session gated + type-DEPLOY arm dialog) ----
      async function doDeploy() {
        if (isRunning()) return;
        var hosts = targets.hosts();
        var folderTxt = String(bundleInput.value || '').trim() || 'the shipped Packages\\DoD-Certs bundle';
        var includeExpired = !!includeExpiredCb._cb.checked;
        var expiredTxt = includeExpired
          ? 'Expired certs in the bundle are <b>INCLUDED</b> - dead trust anchors WILL be pushed (each flagged EXPIRED - dead trust anchor).'
          : 'Expired certs in the bundle are <b>skipped by default</b> - not pushed.';
        var ok = await ctx.arm({
          title: 'Arm DEPLOY TRUST CERTS',
          banner: 'DESTRUCTIVE - THIS WRITES TO THE LOCALMACHINE CERT STORES',
          body: 'About to <b>additively install</b> the DoD/LTMA trust roots from <b>' + esc(folderTxt) + '</b> into the <b>LocalMachine Root / CA / Disallowed</b> stores on <b>' + hosts.length + ' host(s)</b> over WinRM.'
            + '<br>It adds only the roots that are <b>not already present</b> and <b>never removes</b> anything - a host that already has every root is reported ROOTS ALREADY PRESENT and left untouched.'
            + '<br>' + expiredTxt
            + '<br>The JANET dispatcher host is self-guarded out of the run.',
          preflight: [
            { label: hosts.length + ' host(s) targeted', ok: true },
            { label: 'Bundle: ' + folderTxt, ok: true },
            { label: 'Additive install - never removes a certificate', ok: true },
            { label: includeExpired ? 'Expired certs: INCLUDED (dead anchors will be pushed)' : 'Expired certs: excluded (skipped by default)', ok: true }
          ],
          confirmWord: 'DEPLOY', okText: 'Deploy Trust Certs', cancelText: 'Cancel'
        });
        if (!ok) { actlog.append({ text: '[' + ts() + '] Deploy cancelled at the arming dialog.', level: 'warn' }); return; }
        grid.clear(); prog.reset(); stats.reset();
        hosts.forEach(function (h) { grid.upsert({ Host: h, Ping: '', Status: 'Queued', Missing: '', Detail: 'Queued' }); });
        actlog.append({ text: '[' + ts() + '] Deploy Trust Certs on ' + hosts.length + ' host(s) (additive; never removes).', level: 'accent' });
        lockInputs(true);
        run = ctx.run('deploy', {
          targets: hosts.join('\n'),
          certBundleFolder: String(bundleInput.value || ''),
          confirm: 'DEPLOY',
          attemptOffline: !!offlineCb._cb.checked,
          includeExpired: includeExpired,
          threads: threads()
        }, { keyOf: function (ev) { return ev.Host != null ? String(ev.Host) : null; }, destructive: true });
        bindRun('Deploy', 'installed/present');
      }

      // ---- SCAN CERT MANAGEMENT (read-only; no admin gate, no confirm) ----
      function scanSummarize() {
        var t = 0, ir = 0, gpo = 0, none = 0, off = 0;
        scanGrid.rows().forEach(function (r) {
          var s = String(r.Reconciler == null ? '' : r.Reconciler);
          t++;
          if (s === 'InstallRoot' || s === 'InstallRoot+GPO') ir++;
          if (s === 'GPO' || s === 'InstallRoot+GPO') gpo++;
          if (s === 'None detected') none++;
          if (s === 'OFFLINE') off++;
        });
        return { total: t, installRoot: ir, gpoManaged: gpo, none: none, offline: off };
      }
      function doScanMgmt() {
        if (isRunning()) return;
        var hosts = targets.hosts();
        scanGrid.clear(); scanProg.reset(); scanStats.reset();
        hosts.forEach(function (h) { scanGrid.upsert({ Host: h, Ping: '', InstallRoot: '', GPRoots: '', Reconciler: 'Queued', Detail: 'Queued' }); });
        actlog.append({ text: '[' + ts() + '] Scan Cert Management on ' + hosts.length + ' host(s).', level: 'accent' });
        lockInputs(true);
        scanRun = ctx.run('scan-cert-management', {
          targets: hosts.join('\n'),
          attemptOffline: !!offlineCb._cb.checked,
          threads: threads()
        }, { keyOf: function (ev) { return ev.Host != null ? String(ev.Host) : null; }, destructive: false });
        if (scanUnsub) scanUnsub();
        scanUnsub = scanRun.subscribe({
          status: function (t) { scanProg.setPhase(t); },
          progress: function (p) { scanProg.setProgress(p.done, p.total); },
          row: function (r) { scanGrid.upsert(r); scanStats.setAll(scanSummarize()); },
          log: function (l) { actlog.append(l); },
          error: function (e) { actlog.append({ text: '[' + ts() + '] ' + ((e && e.text) || 'error'), level: 'err' }); },
          active: function (a) {
            scanRunbar.setActive(a);
            if (!a) { lockInputs(false); scanStats.setAll(scanSummarize()); }
          }
        });
      }

      // ---- Import C2C export -> load all PKI-tagged hosts ----
      importBtn.onclick = function () { if (isRunning()) return; importFileInput.value = ''; importFileInput.click(); };
      importFileInput.addEventListener('change', function () { if (importFileInput.files && importFileInput.files.length) doImport(); });
      function doImport() {
        if (isRunning()) return;
        var files = importFileInput.files ? Array.prototype.slice.call(importFileInput.files) : [];
        if (!files.length) { ctx.confirm({ title: 'No file', body: 'Choose a Tanium C2C Compliance Status CSV export first.', okText: 'OK', cancelText: null }); return; }
        var f = files[0];
        if (/\.(xlsx|xlsm|xlsb|xls)$/i.test(f.name || '')) {
          ctx.confirm({ title: 'Excel workbook - not a CSV', body: esc(f.name) + ' is an Excel workbook. Re-export from Tanium as CSV, then import that.', okText: 'OK', cancelText: null });
          return;
        }
        importStatus.textContent = 'Uploading ' + f.name + ' ...'; importStatus.className = 'st-info';
        actlog.append({ text: '[' + ts() + '] Import C2C export: ' + f.name, level: 'accent' });
        ctx.uploadFile(f).then(function (p) {
          actlog.append({ text: 'Uploaded to host: ' + p, level: 'dim' });
          importStatus.textContent = 'Parsing ' + f.name + ' ...'; importStatus.className = 'st-info';
          var irun = ctx.run('import-pki-hosts', { csvPath: p }, { destructive: false });
          irun.subscribe({
            status: function (t) { importStatus.textContent = t; },
            row: function () {},   // rows drive the log; the loaded hosts come from the summary
            log: function (l) { actlog.append(l); },
            error: function (e) { importStatus.textContent = 'Import failed'; importStatus.className = 'st-bad'; actlog.append({ text: '[' + ts() + '] ' + (e && e.text ? e.text : 'error'), level: 'err' }); },
            final: function (res) {
              try { applyImport((res && res.summary) || {}); }
              catch (err) { importStatus.textContent = 'Import parsed but hosts could not be loaded.'; importStatus.className = 'st-bad'; actlog.append({ text: '[' + ts() + '] Import apply error: ' + (err && err.message ? err.message : err), level: 'err' }); }
            }
          });
        }).catch(function (e) {
          importStatus.textContent = 'Upload failed: ' + (e && e.message); importStatus.className = 'st-bad';
          actlog.append({ text: 'Upload failed: ' + (e && e.message), level: 'err' });
        });
      }
      function applyImport(s) {
        var pkiHosts = (s && s.hosts && s.hosts.length) ? s.hosts.slice() : [];
        if (!pkiHosts.length) {
          importStatus.textContent = 'No PKI-tagged hosts found in that export.'; importStatus.className = 'st-warn';
          return;
        }
        var existing = targets.hosts();
        var seen = {}; existing.forEach(function (h) { seen[String(h).toLowerCase()] = true; });
        var added = 0;
        pkiHosts.forEach(function (h) { var k = String(h).toLowerCase(); if (!seen[k]) { seen[k] = true; existing.push(h); added++; } });
        targets.setText(existing.join('\n'));
        importStatus.textContent = 'Loaded ' + pkiHosts.length + ' PKI-tagged host(s) (' + added + ' new).'; importStatus.className = 'st-ok';
        actlog.append({ text: '[' + ts() + '] Loaded ' + pkiHosts.length + ' PKI-tagged host(s) into targets (' + added + ' new). Deploy the roots to get ahead of non-compliance.', level: 'accent' });
      }

      actlog.append({ text: 'Cert Deploy ready. Proactively push the DoD/LTMA trust roots to any PKI-tagged host. Check is read-only; Deploy is additive (never removes) and skips expired certs unless Include expired certs is ticked. Scan Cert Management reports what (if anything) manages/reconciles trust roots per host. Blank bundle folder uses the shipped Packages\\DoD-Certs.', level: 'accent' });

      host.appendChild(root);
      this._root = root;
      this._unsub = function () { try { if (unsub) unsub(); } catch (e) {} try { if (scanUnsub) scanUnsub(); } catch (e) {} };
    },
    unmount: function () { try { if (this._unsub) this._unsub(); } catch (e) {} if (this._root) this._root.remove(); }
  });
})();
