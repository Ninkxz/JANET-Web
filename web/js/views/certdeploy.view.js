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
                                        No admin session, no confirm. MISSING counts
                                        TRUST ANCHORS only; a host with every anchor
                                        present but no Untrusted/blacklist certs reads
                                        BLACKLIST NOT ARMED n - its own state, because
                                        Deploy pushes those only with the default-OFF
                                        pushDisallowed opt-in (audit 2026-07-25).
   DEPLOY (action 'deploy')           - destructive; admin-session gated + a type-
                                        DEPLOY arm dialog stating it ADDITIVELY
                                        installs the DoD roots and never removes.
                                        Expired certs are skipped by default; an
                                        "Include expired certs" checkbox opts in.
                                        The bundle's Untrusted group is a fleet-wide
                                        BLACKLIST (Disallowed store) rather than a
                                        trust add, so it has its OWN opt-in checkbox
                                        (default off) and is labelled DISTRUSTED -
                                        never "trusted" - in the row detail
                                        (audit 2026-07-24).
                                        Two independent opt-in checkboxes
                                        (default off) each arm a PKI-Fix-ScanFix
                                        v1.9 companion after the install:
                                        prunePki (expired-retired-intermediate
                                        prune) and fixRdp (broken-RDP-listener
                                        rebind). A prominent "FIX PKI TRUST ROOTS"
                                        button is a one-click shortcut to the
                                        same gated DEPLOY path.
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
  var EXPORT_COLS = [['Host', 'Host'], ['Ping', 'Ping'], ['Status', 'Status'], ['Missing', 'Missing'], ['Legacy', 'Legacy'], ['Detail', 'Detail']];

  // audit 2026-07-24: Deploy's NOT VERIFIED (added, then absent on the re-read - a reconciler
  // may be stripping it) and REJECTED (non-CA) (a wanted anchor refused and ABSENT) used to hit
  // no branch here, so the two worst deploy outcomes on a TRUST-STORE tool rendered as plain
  // unstyled rows. Both are hard failures -> st-bad/row-bad, same as FAILED.
  function isDeployBadStatus(s) { return s === 'NOT VERIFIED' || s.indexOf('REJECTED') === 0; }
  // audit 2026-07-25 (fable re-audit follow-up), two colour fixes here:
  //   * 'Cancelled' rendered RED (st-bad) in this grid but AMBER in the scan grid below for the
  //     same operator action. An operator cancel is not a probe failure - amber in BOTH grids.
  //   * 'BLACKLIST NOT ARMED n' is the check's new distinct state (every trust anchor present;
  //     only the default-OFF Disallowed blacklist push is absent). It is NOT a missing root, so
  //     it must not read red or share the MISSING amber-with-a-shortfall wording - info-blue.
  function statusCellCls(v) {
    var s = String(v == null ? '' : v);
    if (s === 'ALL PRESENT' || s === 'ROOTS INSTALLED' || s === 'ROOTS ALREADY PRESENT') return 'st-ok';
    if (s.indexOf('MISSING') === 0) return 'st-warn';
    if (s.indexOf('BLACKLIST NOT ARMED') === 0) return 'st-info';
    if (s === 'OFFLINE' || s === 'SKIPPED' || s === 'Cancelled') return 'st-warn';
    if (s === 'CHECK ERROR' || s === 'FAILED' || isDeployBadStatus(s)) return 'st-bad';
    if (s === 'Queued') return 'st-info';
    return '';
  }
  function statusRowCls(v) {
    var s = String(v == null ? '' : v);
    if (s === 'ALL PRESENT' || s === 'ROOTS INSTALLED' || s === 'ROOTS ALREADY PRESENT') return 'row-ok';
    if (s.indexOf('MISSING') === 0) return 'row-warn';
    if (s.indexOf('BLACKLIST NOT ARMED') === 0) return '';
    if (s === 'OFFLINE' || s === 'SKIPPED' || s === 'Cancelled') return 'row-warn';
    if (s === 'CHECK ERROR' || s === 'FAILED' || isDeployBadStatus(s)) return 'row-bad';
    return '';
  }
  function reconcilerCls(v) {
    var s = String(v == null ? '' : v);
    if (s === 'None detected') return 'st-ok';
    if (s === 'InstallRoot' || s === 'GPO' || s === 'InstallRoot+GPO') return 'st-warn';
    if (s === 'OFFLINE') return 'st-warn';
    if (s === 'Cancelled') return 'st-warn';   // audit 2026-07-24: operator cancel, not a probe failure
    if (s === 'CHECK ERROR') return 'st-bad';
    return '';
  }

  JanetViews.register('certdeploy', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;
      var run = null, unsub = null;
      var scanRun = null, scanUnsub = null;
      var importUnsub = null;   // audit 2026-07-23 deferred pass: re-import must replace, not stack, its handler
      function ts() { return ctx.util.clockStr(); }
      var esc = ctx.util.esc;   // always the real escaper - no unescaping fallback (a trap)

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
      // audit 2026-07-24: the Untrusted\ -> Disallowed push BLACKLISTS certs fleet-wide (a DISTRUST,
      // the opposite direction to the rest of the deploy) and is NOT covered by "never removes
      // anything" - so it is armed explicitly, default OFF, like the other trust-changing extras.
      var disallowCb = ui.checkbox('Also BLACKLIST the bundle Untrusted certs (Disallowed store - DISTRUST)', { title: 'Also push the bundle Untrusted\\*.cer group into the LocalMachine Disallowed store. That BLACKLISTS those certificates on every target - nothing is removed, but the certs stop being usable fleet-wide. Off by default: unticked, only Root/CA are pushed and the read-only Check will keep reporting the Untrusted certs as MISSING.' });
      optCard.appendChild(disallowCb);
      var pruneCb = ui.checkbox('Prune expired retired DoD intermediates (CA store; 4 legacy-keeps untouched)', { title: 'After the additive install, also prune EXPIRED retired DOD EMAIL/ID/SW/DERILITY intermediates from the CA store only (the four legacy-keep intermediates this tool intentionally pushes are never touched, nor is any other expired cert). Off by default: unticked, Deploy removes nothing. Independent of the RDP repair.' });
      optCard.appendChild(pruneCb);
      var rdpCb = ui.checkbox('Repair broken RDP listener (rebind CA-issued; healthy untouched)', { title: 'After the additive install, also rebind a broken (self-signed/expired/missing) RDP-tcp listener to the newest valid CA-issued My-store cert for the host - the replacement is located first (no candidate = left untouched), a healthy CA-issued listener is never touched. Off by default. Independent of the intermediate prune.' });
      optCard.appendChild(rdpCb);
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
          function () { var bad = targets.hosts().filter(function (h) { return !HOST_RE.test(h); }); return bad.length ? ('Invalid Target Name|Not valid hostnames: ' + bad.slice(0, 5).map(esc).join(', ') + '.') : null; }
        ],
        onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
        onRun: doCheck,
        onCancel: function () { if (run) { run.cancel(); actlog.append({ text: '[' + ts() + '] CANCEL requested.', level: 'warn' }); } }
      });
      var deployRunbar = C.RunBar({
        label: 'DEPLOY TRUST CERTS', cancelLabel: 'CANCEL DEPLOY', morphToCancel: true,
        title: 'Destructive: additively install the DoD roots into LocalMachine Root/CA (never removes). The Untrusted -> Disallowed BLACKLIST push is a separate opt-in (default off). Needs an admin session.',
        guards: [
          function () { return targets.hosts().length ? null : 'No Hosts|Add at least one host to the list first.'; },
          function () { var bad = targets.hosts().filter(function (h) { return !HOST_RE.test(h); }); return bad.length ? ('Invalid Target Name|Not valid hostnames: ' + bad.slice(0, 5).map(esc).join(', ') + '.') : null; },
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
          function () { var bad = targets.hosts().filter(function (h) { return !HOST_RE.test(h); }); return bad.length ? ('Invalid Target Name|Not valid hostnames: ' + bad.slice(0, 5).map(esc).join(', ') + '.') : null; }
        ],
        onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
        onRun: doScanMgmt,
        onCancel: function () { if (scanRun) { scanRun.cancel(); actlog.append({ text: '[' + ts() + '] CANCEL requested.', level: 'warn' }); } }
      });
      var checkWrap = el('div'); checkWrap.appendChild(checkRunbar.el); actCard.appendChild(checkWrap);
      // PROMINENT one-click shortcut: fire the SAME DEPLOY path (runbar guards -> admin-gate ->
      // type-DEPLOY arm dialog -> self-guard). It just clicks the DEPLOY cta, bypassing NO gate.
      var fixPkiWrap = el('div'); fixPkiWrap.style.cssText = 'display:flex;flex-direction:column;gap:4px;margin:2px 0 4px';
      var fixPkiBtn = ui.button('FIX PKI TRUST ROOTS (deploy DoD bundle)', { variant: 'gold', title: 'One-click shortcut to the core trust-root deploy: pushes the DoD/LTMA trust roots to the targeted hosts. Runs the SAME Deploy path - admin session required, type-DEPLOY arm dialog, self-guard - nothing is bypassed.' });
      fixPkiBtn.style.cssText += ';width:100%;font-size:15px;font-weight:700;padding:12px 16px;letter-spacing:0.5px';
      fixPkiBtn.onclick = function () { if (isRunning()) return; deployRunbar.cta.click(); };
      var fixPkiHint = el('div', 'muted', 'One-click: push the DoD trust roots to the target hosts.'); fixPkiHint.style.fontSize = '11px';
      fixPkiWrap.appendChild(fixPkiBtn); fixPkiWrap.appendChild(fixPkiHint);
      actCard.appendChild(fixPkiWrap);
      var deployWrap = el('div'); deployWrap.appendChild(deployRunbar.el); actCard.appendChild(deployWrap);
      var scanWrap = el('div'); scanWrap.appendChild(scanRunbar.el); actCard.appendChild(scanWrap);
      left.appendChild(actCard);
      main.appendChild(left);

      // ---------- RIGHT: stats + head + grid ----------
      var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:12px;min-height:0';
      var stats = C.StatCards({ cards: [
        { key: 'hosts', label: 'HOSTS', color: 'cyan' },
        { key: 'ok', label: 'ALL PRESENT / INSTALLED', color: 'ok' },
        { key: 'missing', label: 'MISSING / FAILED / NOT VERIFIED', color: 'gold' },   // audit 2026-07-24: NOT VERIFIED + REJECTED land here
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
        keyMode: { hostCol: 'Host' }, popOut: true, selectable: true,
        // Cross-tool harvest. A Check run's MISSING/FAILED set is the list the next
        // tool needs (C2C PkiRoots, WPT, a reboot wave). Staging ONLY: the
        // destination shows a Load banner the operator clicks; Deploy here still
        // needs an admin session and the typed DEPLOY confirm word.
        useHosts: {
          ctx: ctx, source: 'Cert Deploy check',
          flagged: {
            label: 'Hosts MISSING roots or FAILED',
            test: function (r) { var s = String(r.Status == null ? '' : r.Status); return /^MISSING/i.test(s) || /FAIL/i.test(s) || /REJECTED/i.test(s); }
          }
        },
        columns: [
          { key: 'Host', label: 'HOST', width: 150 },
          { key: 'Ping', label: 'PING', width: 90 },
          { key: 'Status', label: 'STATUS', width: 160, render: function (r) { return { text: r.Status == null ? '' : String(r.Status), cls: statusCellCls(r.Status) }; } },
          { key: 'Missing', label: 'MISSING', width: 90 },
          { key: 'Legacy', label: 'LEGACY', width: 80, render: function (r) { var t = String(r.Legacy == null ? '' : r.Legacy); return { text: t, title: 'Allowlisted legacy DoD intermediates present in LocalMachine\\CA (present/total)' }; } },
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
      // audit 2026-07-23 deferred pass: S3 lockInputs consolidation
      var lockInputs = ctx.util.lockable([offlineCb._cb, threadsIn, clearBtn, bundleInput, importBtn, includeExpiredCb._cb, disallowCb._cb, pruneCb._cb, rdpCb._cb]);
      clearBtn.onclick = function () { if (isRunning()) return; grid.clear(); prog.reset(); stats.reset(); expiredBadge.textContent = ''; setStatus('Ready'); };
      exportBtn.onclick = function () {
        var rows = grid.rows();
        if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Run a Check or Deploy first - there are no result rows yet.', okText: 'OK', cancelText: null }); return; }
        ctx.util.exportCsv('CertDeploy_Results', EXPORT_COLS, rows);
        actlog.append({ text: '[' + ts() + '] Exported ' + rows.length + ' row(s) to CSV.', level: 'info' });
      };

      function summarize() {
        var okC = 0, miss = 0, err = 0, total = 0;
        grid.rows().forEach(function (r) {
          var s = String(r.Status);
          if (s === 'Queued') return;
          total++;
          if (s === 'ALL PRESENT' || s === 'ROOTS INSTALLED' || s === 'ROOTS ALREADY PRESENT') okC++;
          // audit 2026-07-24: NOT VERIFIED / REJECTED (non-CA) fell into NO bucket, so a fleet
          // where every deploy failed to persist closed the strip GREEN at 0/0/0. They are
          // failures - "the cert did not land" is the whole point of this tool. Mirror in tallyBucket().
          else if (s.indexOf('MISSING') === 0 || s === 'FAILED' || isDeployBadStatus(s)) miss++;
          else if (s === 'OFFLINE' || s === 'CHECK ERROR' || s === 'SKIPPED' || s === 'Cancelled') err++;
          // audit 2026-07-25: 'BLACKLIST NOT ARMED n' deliberately falls through to no bucket - the
          // host's trust anchors are ALL present (not missing) and nothing failed to read (not an
          // error); it only reports that the default-OFF Disallowed push was never armed. The run's
          // final log names it from the summary (sum.blacklistNotArmed) instead.
        });
        return { hosts: total, ok: okC, missing: miss, errors: err };
      }

      // O(1) running tally for the streamed rows (summarize() per row was O(n^2)).
      // Rows MUTATE Queued -> terminal via upsert (same Host key), so remember each
      // host's last-counted bucket and move it between buckets; the authoritative
      // full summarize() recompute still runs once on active:false (drift-proof).
      // 'other' = counted in hosts but no bucket (mirrors summarize's fall-through).
      var tally = { counts: { hosts: 0, ok: 0, missing: 0, errors: 0 }, byHost: {} };
      function tallyReset() { tally = { counts: { hosts: 0, ok: 0, missing: 0, errors: 0 }, byHost: {} }; }
      function tallyBucket(status) {
        var s = String(status);
        if (s === 'Queued') return null;
        if (s === 'ALL PRESENT' || s === 'ROOTS INSTALLED' || s === 'ROOTS ALREADY PRESENT') return 'ok';
        if (s.indexOf('MISSING') === 0 || s === 'FAILED' || isDeployBadStatus(s)) return 'missing';   // audit 2026-07-24: mirrors summarize()
        if (s === 'OFFLINE' || s === 'CHECK ERROR' || s === 'SKIPPED' || s === 'Cancelled') return 'errors';
        return 'other';   // incl. audit 2026-07-25 'BLACKLIST NOT ARMED n' - neither missing nor error
      }
      function tallyRow(r) {
        var k = String(r.Host == null ? '' : r.Host);
        var b = tallyBucket(r.Status);
        var prev = tally.byHost[k];
        if (prev !== b) {
          if (prev) { tally.counts.hosts--; if (prev !== 'other') tally.counts[prev]--; }
          if (b) { tally.counts.hosts++; if (b !== 'other') tally.counts[b]++; }
          tally.byHost[k] = b;
        }
        return tally.counts;
      }

      function bindRun(verb, finalNoun) {
        if (unsub) unsub();
        unsub = run.subscribe({
          status: function (t) { prog.setPhase(t); setStatus(t, (String(t) === 'error') ? 'st-bad' : 'st-info'); },
          progress: function (p) { prog.setProgress(p.done, p.total); setStatus('Running... ' + p.done + ' / ' + p.total + ' done', 'st-info'); },
          row: function (r) { grid.upsert(r); stats.setAll(tallyRow(r)); },
          log: function (l) { actlog.append(l); },
          error: function (e) { setStatus((e && e.text) || 'Error', 'st-bad'); actlog.append({ text: '[' + ts() + '] ' + ((e && e.text) || 'error'), level: 'err' }); },
          active: function (a) {
            checkRunbar.setActive(a); deployRunbar.setActive(a);
            if (!a) {
              lockInputs(false);
              var c = summarize(); stats.setAll(c);
              var bad = c.missing + c.errors;
              setStatus(verb + ' complete - ' + c.ok + ' ' + finalNoun + ', ' + c.missing + ' missing/failed/not-verified, ' + c.errors + ' offline/error', bad ? 'st-warn' : 'st-ok');
              actlog.append({ text: '[' + ts() + '] FINISHED ' + verb + '. OK=' + c.ok + '  MISSING/FAILED/NOT-VERIFIED=' + c.missing + '  OFFLINE/ERROR=' + c.errors, level: bad ? 'warn' : 'ok' });
            }
          },
          final: function (res) {
            var sum = (res && res.summary) || {};
            // audit 2026-07-24: the module summary returns lowercase expiredCount (+ the new
            // expiredSubjects list) - never ExpiredCount/Expired, so this badge and its log line
            // were dead code that could never fire. Read the ACTUAL contract keys.
            var ec = Number(sum.expiredCount || 0) || 0;
            // expiredExcluded is 0 on an includeExpired run - say "pushed", not "skipped".
            var excluded = (sum.expiredExcluded == null) ? ec : (Number(sum.expiredExcluded) || 0);
            var word = excluded > 0 ? 'skipped' : 'INCLUDED - pushed';
            if (ec > 0) {
              expiredBadge.textContent = ec + ' expired in bundle (' + word + ')';
              expiredBadge.className = 'st-warn';
              var subs = (sum.expiredSubjects || []).map(function (x) { return x == null ? '' : String(x); }).filter(function (s) { return !!s; });
              actlog.append({ text: '[' + ts() + '] ' + ec + ' expired cert(s) in bundle (' + word + '): ' + subs.slice(0, 5).join(', ') + (subs.length > 5 ? ' ...' : ''), level: 'warn' });
            } else {
              expiredBadge.textContent = ''; expiredBadge.className = 'muted';
            }
            // audit 2026-07-24: name the blacklist certs the un-armed Disallowed gate held back, so
            // the operator is not left wondering why they never landed.
            // audit 2026-07-25: Check no longer calls that shortfall MISSING (it is its own
            // BLACKLIST NOT ARMED state) - the old wording promised the opposite, so it is corrected.
            var dx = Number(sum.disallowedExcluded || 0) || 0;
            if (dx > 0) {
              actlog.append({ text: '[' + ts() + '] ' + dx + ' Untrusted/blacklist cert(s) were NOT pushed - the "BLACKLIST the bundle Untrusted certs" opt-in is off (Check reports this as BLACKLIST NOT ARMED, not as missing roots).', level: 'info' });
            }
            // audit 2026-07-25: the check run's distrust shortfall, reported apart from missing roots.
            var bna = Number(sum.blacklistNotArmed || 0) || 0;
            if (bna > 0) {
              actlog.append({ text: '[' + ts() + '] ' + bna + ' host(s) have EVERY trust anchor present but no Untrusted/blacklist certs - Deploy pushes those only with the pushDisallowed opt-in armed (default OFF). Not a missing-roots shortfall.', level: 'info' });
            }
          }
        });
      }

      // ---- CHECK (read-only) ----
      function doCheck() {
        if (isRunning()) return;
        var hosts = targets.hosts();
        grid.clear(); prog.reset(); stats.reset(); tallyReset();
        hosts.forEach(function (h) { grid.upsert({ Host: h, Ping: '', Status: 'Queued', Missing: '', Legacy: '', Detail: 'Queued' }); });
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
        var pushDisallowed = !!disallowCb._cb.checked;
        var prunePki = !!pruneCb._cb.checked;
        var fixRdp = !!rdpCb._cb.checked;
        var runCompanions = prunePki || fixRdp;
        var expiredTxt = includeExpired
          ? 'Expired certs in the bundle are <b>INCLUDED</b> - dead trust anchors WILL be pushed (each flagged EXPIRED - dead trust anchor).'
          : 'Expired certs in the bundle are <b>skipped by default</b> - not pushed.';
        // audit 2026-07-24: the dialog used to promise "never removes anything" while silently
        // BLACKLISTING the bundle Untrusted certs. State the distrust in the operator's face.
        var disallowTxt = pushDisallowed
          ? 'The bundle <b>Untrusted</b> group is <b>ARMED</b>: those certs are added to the LocalMachine <b>Disallowed</b> store, which <b>DISTRUSTS them fleet-wide</b> on every target. Nothing is removed, but those certificates stop being usable.'
          : 'The bundle <b>Untrusted</b> group is <b>off</b> - only <b>Root / CA</b> are pushed, nothing is blacklisted (Check will keep reporting those certs MISSING).';
        var companionsTxt;
        if (runCompanions) {
          var parts = [];
          if (prunePki) parts.push('the expired retired-DoD-intermediate <b>prune</b> (CA store only; the four legacy-keep intermediates never touched) - this CAN REMOVE certs');
          if (fixRdp) parts.push('the broken-RDP-listener <b>rebind</b> (healthy listeners never touched)');
          companionsTxt = 'v1.9 fix companions are <b>ENABLED</b> - after the install each host also gets ' + parts.join(' and ') + '.';
        } else {
          companionsTxt = 'v1.9 fix companions are <b>off</b> - the deploy is purely additive.';
        }
        var ok = await ctx.arm({
          title: 'Arm DEPLOY TRUST CERTS',
          banner: 'DESTRUCTIVE - THIS WRITES TO THE LOCALMACHINE CERT STORES',
          body: 'About to <b>additively install</b> the DoD/LTMA trust roots from <b>' + esc(folderTxt) + '</b> into the <b>LocalMachine ' + (pushDisallowed ? 'Root / CA / Disallowed' : 'Root / CA') + '</b> store(s) on <b>' + hosts.length + ' host(s)</b> over WinRM.'
            + '<br>It adds only the roots that are <b>not already present</b> and <b>never removes</b> anything - a host that already has every root is reported ROOTS ALREADY PRESENT and left untouched.'
            + '<br>' + expiredTxt
            + '<br>' + disallowTxt
            + '<br>' + companionsTxt
            + '<br>The JANET dispatcher host is self-guarded out of the run.',
          preflight: [
            { label: hosts.length + ' host(s) targeted', ok: true },
            { label: 'Bundle: ' + folderTxt, ok: true },
            { label: runCompanions ? 'Install is additive, BUT companions armed below may remove/rebind certs' : 'Additive install - never removes a certificate', ok: true },
            { label: includeExpired ? 'Expired certs: INCLUDED (dead anchors will be pushed)' : 'Expired certs: excluded (skipped by default)', ok: true },
            { label: pushDisallowed ? 'Untrusted -> Disallowed BLACKLIST: ARMED (those certs get DISTRUSTED fleet-wide)' : 'Untrusted -> Disallowed blacklist: off (Root/CA only)', ok: true },
            { label: prunePki ? 'Prune expired retired DoD intermediates: ENABLED (CA store; 4 legacy-keeps untouched)' : 'Prune expired retired DoD intermediates: off', ok: true },
            { label: fixRdp ? 'Repair broken RDP listener: ENABLED (rebind CA-issued; healthy untouched)' : 'Repair broken RDP listener: off', ok: true }
          ],
          confirmWord: 'DEPLOY', okText: 'Deploy Trust Certs', cancelText: 'Cancel'
        });
        if (!ok) { actlog.append({ text: '[' + ts() + '] Deploy cancelled at the arming dialog.', level: 'warn' }); return; }
        grid.clear(); prog.reset(); stats.reset(); tallyReset();
        hosts.forEach(function (h) { grid.upsert({ Host: h, Ping: '', Status: 'Queued', Missing: '', Legacy: '', Detail: 'Queued' }); });
        actlog.append({ text: '[' + ts() + '] Deploy Trust Certs on ' + hosts.length + ' host(s) (additive; never removes)' + (pushDisallowed ? ' + Untrusted BLACKLIST push into Disallowed (DISTRUST).' : '.'), level: 'accent' });
        lockInputs(true);
        run = ctx.run('deploy', {
          targets: hosts.join('\n'),
          certBundleFolder: String(bundleInput.value || ''),
          confirm: 'DEPLOY',
          attemptOffline: !!offlineCb._cb.checked,
          includeExpired: includeExpired,
          pushDisallowed: pushDisallowed,
          prunePki: prunePki,
          fixRdp: fixRdp,
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
      // O(1) running tally (scanSummarize() per streamed row was O(n^2)). A host can
      // sit in BOTH the InstallRoot and GPO buckets ('InstallRoot+GPO'), so remember
      // per-host FLAGS and swap them on mutation (Queued -> result via upsert); every
      // row (Queued included) counts toward total, mirroring scanSummarize. The
      // authoritative full scanSummarize() recompute still runs once on active:false.
      var scanTally = { counts: { total: 0, installRoot: 0, gpoManaged: 0, none: 0, offline: 0 }, byHost: {} };
      function scanTallyReset() { scanTally = { counts: { total: 0, installRoot: 0, gpoManaged: 0, none: 0, offline: 0 }, byHost: {} }; }
      function scanFlags(rec) {
        var s = String(rec == null ? '' : rec);
        return {
          installRoot: (s === 'InstallRoot' || s === 'InstallRoot+GPO') ? 1 : 0,
          gpoManaged: (s === 'GPO' || s === 'InstallRoot+GPO') ? 1 : 0,
          none: (s === 'None detected') ? 1 : 0,
          offline: (s === 'OFFLINE') ? 1 : 0
        };
      }
      function scanTallyRow(r) {
        var k = String(r.Host == null ? '' : r.Host);
        var f = scanFlags(r.Reconciler);
        var c = scanTally.counts, prev = scanTally.byHost[k];
        if (prev) { c.total--; c.installRoot -= prev.installRoot; c.gpoManaged -= prev.gpoManaged; c.none -= prev.none; c.offline -= prev.offline; }
        c.total++; c.installRoot += f.installRoot; c.gpoManaged += f.gpoManaged; c.none += f.none; c.offline += f.offline;
        scanTally.byHost[k] = f;
        return c;
      }
      function doScanMgmt() {
        if (isRunning()) return;
        var hosts = targets.hosts();
        scanGrid.clear(); scanProg.reset(); scanStats.reset(); scanTallyReset();
        hosts.forEach(function (h) { scanGrid.upsert({ Host: h, Ping: '', InstallRoot: '', GPRoots: '', Reconciler: 'Queued', Detail: 'Queued' }); scanTallyRow({ Host: h, Reconciler: 'Queued' }); });
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
          row: function (r) { scanGrid.upsert(r); scanStats.setAll(scanTallyRow(r)); },
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
          if (importUnsub) importUnsub();
          importUnsub = irun.subscribe({
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
      this._unsub = function () { try { if (unsub) unsub(); } catch (e) {} try { if (scanUnsub) scanUnsub(); } catch (e) {} try { if (importUnsub) importUnsub(); } catch (e) {} };
    }
  });
})();
