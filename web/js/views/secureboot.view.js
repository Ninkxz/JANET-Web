/* ============================================================================
   secureboot.view.js  -  Secure Boot Enabler (tool id: 'secureboot')
   Faithful single-window (non-tabbed) re-build per docs/ui-specs/secureboot.md:
   a fixed frame with a left Targets card and a right column of Settings / Action
   bar / Results cards. The activity view IS the colour-coded Results grid + a
   custom progress track (NOT a text log). All runs go through ctx.run ->
   RunController. Credentials are universal (shell header), not per-tool.
   ========================================================================== */
(function () {
  'use strict';

  var HOST_RE = /^[A-Za-z0-9._-]+$/;
  // engine row events are keyed 'Host'; CSV header keeps the desktop label 'Computer'.
  var EXPORT_COLS = [['Host', 'Computer'], ['Status', 'Status'], ['Manufacturer', 'Manufacturer'], ['Before', 'Before'], ['After', 'After'], ['SetResult', 'SetResult'], ['Error', 'Error']];

  function statusCellCls(v) {
    switch (String(v)) {
      case 'Success': return 'st-ok';
      case 'Skipped': return 'st-info';
      case 'DryRun': return 'st-info';
      case 'Running': return 'st-info';
      case 'Timeout': return 'st-warn';
      case 'Error': return 'st-bad';
      default: return '';
    }
  }

  // Read-only scan verdicts (engine action 'scan-secure-boot').
  function verdictCellCls(v) {
    switch (String(v)) {
      case 'ENABLED': return 'st-ok';
      case 'READY TO ENABLE': return 'st-ok';
      case 'OFF - UNSUPPORTED OEM': return 'st-warn';
      case 'BLOCKED - LEGACY/MBR': return 'st-warn';
      case 'OFFLINE': return 'st-warn';
      case 'DNS MISMATCH': return 'st-warn';
      case 'CHECK ERROR': return 'st-bad';
      case 'Cancelled': return 'st-bad';
      case 'Queued': return 'st-info';
      default: return '';
    }
  }
  function verdictRowCls(v) {
    var s = String(v);
    if (s === 'ENABLED' || s === 'READY TO ENABLE') return 'row-ok';
    if (s === 'CHECK ERROR' || s === 'Cancelled') return 'row-bad';
    if (s === 'OFF - UNSUPPORTED OEM' || s === 'BLOCKED - LEGACY/MBR' || s === 'OFFLINE' || s === 'DNS MISMATCH') return 'row-warn';
    return '';
  }
  // engine scan row events -> CSV columns.
  var SCAN_COLS = [['Host', 'Computer'], ['Ping', 'Ping'], ['Verdict', 'Verdict'], ['SecureBoot', 'SecureBoot'], ['Firmware', 'Firmware'], ['Disk', 'Disk'], ['Manufacturer', 'Manufacturer'], ['Model', 'Model'], ['Detail', 'Detail']];

  JanetViews.register('secureboot', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;
      var run = null, unsub = null;
      var scanRun = null, scanUnsub = null, readyHosts = [];

      var card = ui.namedCard;

      var root = el('div'); root.style.cssText = 'display:flex;gap:14px;height:100%;min-height:0;padding:14px;box-sizing:border-box';

      // ---------- LEFT: TARGET MACHINES ----------
      var left = card('TARGET MACHINES', 'One hostname per line. The Scan has no cap; Enable runs in waves of 50 or fewer.');
      left.style.cssText += ';flex:0 0 320px;display:flex;flex-direction:column;min-height:0';
      var targets = C.TargetManager({
        model: ctx.util.targetModel(''),
        hint: 'One hostname per line', max: 50, importLabel: 'Import TXT'
      });
      var tgHolder = el('div'); tgHolder.style.cssText = 'flex:1;min-height:120px;display:flex'; tgHolder.appendChild(targets.el);
      left.appendChild(tgHolder);
      root.appendChild(left);

      // ---------- RIGHT column ----------
      var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:12px;min-height:0';

      // ===== STAGE 1: read-only fleet SCAN =====
      var scanCard = card('SCAN SECURE BOOT (FLEET)', 'Read-only posture scan - no firmware write, no host cap. Run this first, then load the READY hosts into Targets and Enable in waves of 50 or fewer.');
      scanCard.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
      var scanBar = el('div'); scanBar.style.cssText = 'display:flex;flex-wrap:wrap;gap:14px;align-items:flex-end;margin-bottom:8px';
      // parallel hosts (1-32)
      var scanThreadsWrap = el('div');
      scanThreadsWrap.appendChild(ui.label('Parallel hosts'));
      var scanThreads = ui.number({ value: 16, min: 1, max: 32, title: 'Concurrent hosts to probe (1-32).' }); scanThreads.style.width = '90px';
      scanThreadsWrap.appendChild(scanThreads);
      scanBar.appendChild(scanThreadsWrap);
      // attempt offline
      var offlineCb = ui.checkbox('Attempt even if offline', { title: 'Probe over WinRM even when TCP 5985/5986/445 did not answer (slower). A host answering only on 5986 uses WinRM-over-HTTPS.' });
      scanBar.appendChild(offlineCb);
      var scanStatus = el('span', 'muted', 'Ready'); scanStatus.style.minWidth = '160px';
      scanBar.appendChild(scanStatus);
      var scanSpacer = el('div'); scanSpacer.style.flex = '1'; scanBar.appendChild(scanSpacer);
      var loadReadyBtn = ui.button('Load READY-TO-ENABLE hosts -> Targets', { variant: 'gold', size: 'sm', title: 'Run a scan first; this fills the Targets list with the READY-TO-ENABLE hosts.' });
      loadReadyBtn.disabled = true;
      var copyReadyBtn = ui.ghostButton('Copy READY list', { size: 'sm', title: 'Copy the READY-TO-ENABLE host names to the clipboard.' });
      copyReadyBtn.disabled = true;
      var scanExportBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the scan result rows to a CSV file.' });
      var scanCtaHolder = el('div'); scanCtaHolder.style.width = '220px';
      var scanRunbar = C.RunBar({
        label: 'SCAN SECURE BOOT (FLEET)', morphToCancel: false,
        title: 'Read-only fleet Secure Boot posture scan (one WinRM probe per host; no firmware write).',
        guards: [
          function () { return targets.hosts().length ? null : 'Input Required|Enter at least one hostname.'; },
          function () { var bad = targets.hosts().filter(function (h) { return !HOST_RE.test(h); }); return bad.length ? ('Invalid Target Name|Not valid hostnames: ' + bad.slice(0, 5).map(Janet.util.esc).join(', ') + '. Use only letters, digits, dot, hyphen, underscore.') : null; }
        ],
        onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
        onRun: doScan
      });
      scanCtaHolder.appendChild(scanRunbar.el);
      scanBar.appendChild(scanExportBtn); scanBar.appendChild(copyReadyBtn); scanBar.appendChild(loadReadyBtn); scanBar.appendChild(scanCtaHolder);
      scanCard.appendChild(scanBar);
      var scanGrid = C.ResultsGrid({
        title: 'Secure Boot scan results',
        emptyText: 'No scan yet — enter hosts on the left, then Scan Secure Boot (Fleet).',
        keyMode: { hostCol: 'Host' }, popOut: true,
        columns: [
          { key: 'Host', label: 'COMPUTER', width: 120 },
          { key: 'Ping', label: 'PING', width: 80 },
          { key: 'Verdict', label: 'VERDICT', width: 150, render: function (r) { return { text: r.Verdict == null ? '' : String(r.Verdict), cls: verdictCellCls(r.Verdict) }; } },
          { key: 'SecureBoot', label: 'SECURE BOOT', width: 95 },
          { key: 'Firmware', label: 'FIRMWARE', width: 80 },
          { key: 'Disk', label: 'DISK', width: 70 },
          { key: 'Manufacturer', label: 'MANUFACTURER', width: 110 },
          { key: 'Model', label: 'MODEL', width: 120 },
          { key: 'Detail', label: 'DETAIL' }
        ],
        rowClass: function (r) { return verdictRowCls(r.Verdict); }
      });
      var scanGridHolder = el('div'); scanGridHolder.style.cssText = 'flex:1;min-height:0;display:flex'; scanGridHolder.appendChild(scanGrid.el);
      scanCard.appendChild(scanGridHolder);
      var scanProg = C.ProgressStatusStrip({ showCount: true });
      scanProg.el.style.marginTop = '8px';
      scanCard.appendChild(scanProg.el);
      right.appendChild(scanCard);

      // Settings card
      var settings = card('SETTINGS');
      var setRows = el('div'); setRows.style.cssText = 'display:flex;flex-wrap:wrap;gap:18px;align-items:flex-end';
      // BIOS password + Show
      var pwWrap = el('div');
      pwWrap.appendChild(ui.label('BIOS password'));
      var pwRow = el('div'); pwRow.style.cssText = 'display:flex;align-items:center;gap:8px';
      var pwInput = ui.input({ type: 'password', title: 'BIOS/firmware admin password. Leave blank if none is set.' }); pwInput.style.width = '220px';
      var showCb = ui.checkbox('Show', { onChange: function () { pwInput.type = showCb._cb.checked ? 'text' : 'password'; } });
      pwRow.appendChild(pwInput); pwRow.appendChild(showCb);
      pwWrap.appendChild(pwRow);
      pwWrap.appendChild((function () { var n = el('div', 'muted', 'Leave blank if none is set.'); n.style.fontSize = '11px'; return n; })());
      setRows.appendChild(pwWrap);
      // Parallel jobs
      var jobsWrap = el('div');
      jobsWrap.appendChild(ui.label('Parallel jobs'));
      var jobsInput = ui.number({ value: 5, min: 1, max: 10, title: 'Concurrent machines (1-10).' }); jobsInput.style.width = '90px';
      jobsWrap.appendChild(jobsInput);
      jobsWrap.appendChild((function () { var n = el('div', 'muted', 'Concurrent machines (1-10).'); n.style.fontSize = '11px'; return n; })());
      setRows.appendChild(jobsWrap);
      settings.appendChild(setRows);
      // Dry Run
      var dryCb = ui.checkbox('Dry Run - connectivity + manufacturer detection only. No BIOS write.', { color: 'var(--warn)', title: 'Probe reachability + manufacturer via DCOM only; no firmware change.' });
      dryCb.style.marginTop = '12px';
      settings.appendChild(dryCb);
      right.appendChild(settings);

      // Action bar
      var actionCard = ui.card({}); actionCard.style.cssText += ';display:flex;align-items:center;gap:14px;flex-wrap:wrap';
      var statusLine = el('span', 'muted', 'Ready'); statusLine.style.minWidth = '160px';
      actionCard.appendChild(statusLine);
      var spacer = el('div'); spacer.style.flex = '1'; actionCard.appendChild(spacer);
      var exportBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the result rows to a CSV file.' });
      var clearBtn = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the results grid + reset progress.' });
      var ctaHolder = el('div'); ctaHolder.style.width = '260px';
      var runbar = C.RunBar({
        label: 'ENABLE SECURE BOOT', morphToCancel: false,
        title: 'Enable UEFI Secure Boot across the target machines (OEM WMI via SYSTEM scheduled task).',
        guards: [
          function () { return targets.hosts().length ? null : 'Input Required|Enter at least one hostname.'; },
          function () { return targets.hosts().length <= 50 ? null : ('Limit Exceeded|Maximum 50 machines per run; remove ' + (targets.hosts().length - 50) + ' and retry.'); },
          function () { var bad = targets.hosts().filter(function (h) { return !HOST_RE.test(h); }); return bad.length ? ('Invalid Target Name|Not valid hostnames: ' + bad.slice(0, 5).map(Janet.util.esc).join(', ') + '. Use only letters, digits, dot, hyphen, underscore.') : null; },
          function () { if (dryCb._cb.checked) return null; var p = pwInput.value || ''; return /[,'"`]/.test(p) ? "Unsupported Password Character|The BIOS password cannot contain a comma, quote, or backtick. Remove it and retry." : null; },
          function () { return ctx.session.state.credSet ? null : 'Admin session required|Set ADW credentials (top-right) and start an admin session before enabling Secure Boot - it changes firmware.'; }
        ],
        onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
        onRun: doRun
      });
      ctaHolder.appendChild(runbar.el);
      actionCard.appendChild(exportBtn); actionCard.appendChild(clearBtn); actionCard.appendChild(ctaHolder);
      right.appendChild(actionCard);

      // Results card (grid + progress track)
      var results = card('RESULTS');
      results.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
      var grid = C.ResultsGrid({
        title: 'Secure Boot results',
        emptyText: 'No results yet — pick a host set, then Enable Secure Boot.',
        keyMode: { hostCol: 'Host' }, popOut: true,
        columns: [
          { key: 'Host', label: 'COMPUTER', width: 130 },
          { key: 'Status', label: 'STATUS', width: 90, render: function (r) { return { text: r.Status == null ? '' : String(r.Status), cls: statusCellCls(r.Status) }; } },
          { key: 'Manufacturer', label: 'MANUFACTURER', width: 110 },
          { key: 'Before', label: 'BEFORE', width: 95 },
          { key: 'After', label: 'AFTER', width: 95 },
          { key: 'SetResult', label: 'RESULT', width: 90 },
          { key: 'Error', label: 'ERROR / NOTES' }
        ],
        rowClass: function (r) {
          var s = String(r.Status);
          if (s === 'Success' || s === 'Skipped') return 'row-ok';
          if (s === 'Error') return 'row-bad';
          if (s === 'Timeout') return 'row-warn';
          return '';
        }
      });
      var gridHolder = el('div'); gridHolder.style.cssText = 'flex:1;min-height:0;display:flex'; gridHolder.appendChild(grid.el);
      results.appendChild(gridHolder);
      var prog = C.ProgressStatusStrip({ showCount: true });
      prog.el.style.marginTop = '8px';
      results.appendChild(prog.el);
      right.appendChild(results);

      root.appendChild(right);

      // ---------- behaviour ----------
      function setStatus(txt, cls) { statusLine.textContent = txt == null ? '' : String(txt); statusLine.className = cls || 'muted'; }
      function lockInputs(on) { pwInput.disabled = on; jobsInput.disabled = on; dryCb._cb.disabled = on; showCb._cb.disabled = on; clearBtn.disabled = on; }
      clearBtn.onclick = function () { if (run && run.state && run.state.active) return; grid.clear(); prog.reset(); setStatus('Ready'); };
      exportBtn.onclick = function () {
        var rows = grid.rows();
        if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Run an enable first - there are no result rows yet.', okText: 'OK', cancelText: null }); return; }
        var csv = ctx.util.toCsv(EXPORT_COLS.map(function (p) { return p[1]; }), rows, EXPORT_COLS.map(function (p) { return p[0]; }));
        ctx.util.downloadBlob('SecureBoot_Results_' + ctx.util.fileStamp() + '.csv', 'text/csv', csv);
      };

      function summarize() {
        var c = { Success: 0, Skipped: 0, Error: 0, Timeout: 0, DryRun: 0 };
        grid.rows().forEach(function (r) { if (c[r.Status] != null) c[r.Status]++; });
        return c;
      }

      // ---------- STAGE 1: scan behaviour ----------
      function setScanStatus(txt, cls) { scanStatus.textContent = txt == null ? '' : String(txt); scanStatus.className = cls || 'muted'; }
      function lockScan(on) { scanThreads.disabled = on; offlineCb._cb.disabled = on; }
      scanExportBtn.onclick = function () {
        var rows = scanGrid.rows();
        if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Run a scan first - there are no scan rows yet.', okText: 'OK', cancelText: null }); return; }
        var csv = ctx.util.toCsv(SCAN_COLS.map(function (p) { return p[1]; }), rows, SCAN_COLS.map(function (p) { return p[0]; }));
        ctx.util.downloadBlob('SecureBoot_Scan_' + ctx.util.fileStamp() + '.csv', 'text/csv', csv);
      };
      copyReadyBtn.onclick = function () {
        if (!readyHosts.length) return;
        try { if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(readyHosts.join('\n')).catch(function () {}); } catch (e) {}
        setScanStatus('Copied ' + readyHosts.length + ' READY host(s) to clipboard.', 'st-ok');
      };
      loadReadyBtn.onclick = function () {
        if (!readyHosts.length) return;
        // Fill the shared Targets list with the READY hosts (replace). The Enable
        // path still caps a wave at 50 - if there are more, the operator slices.
        targets.setText(readyHosts.join('\n'));
        var over = readyHosts.length > 50;
        setScanStatus(readyHosts.length + ' READY host(s) loaded into Targets' + (over ? ' - over 50; Enable runs in waves of <=50, slice the list.' : '.'), over ? 'st-warn' : 'st-ok');
        if (over) {
          ctx.confirm({ title: 'Wave size', body: '<b>' + readyHosts.length + '</b> READY hosts loaded. Enable Secure Boot runs in waves of <b>50 or fewer</b> - trim the Targets list (or use the Canary split) before enabling.', okText: 'OK', cancelText: null });
        }
      };

      function scanSummarize() {
        var c = {};
        scanGrid.rows().forEach(function (r) { var v = String(r.Verdict); c[v] = (c[v] || 0) + 1; });
        return c;
      }

      function doScan() {
        scanGrid.clear(); scanProg.reset();
        readyHosts = []; loadReadyBtn.disabled = true; copyReadyBtn.disabled = true;
        setScanStatus('Scanning ' + targets.hosts().length + ' host(s)...', 'st-info');
        lockScan(true);
        var threads = Math.max(1, Math.min(32, parseInt(scanThreads.value, 10) || 16));
        scanRun = ctx.run('scan-secure-boot', {
          targets: targets.hosts().join('\n'), attemptOffline: !!offlineCb._cb.checked, threads: threads
        });
        if (scanUnsub) scanUnsub();
        scanUnsub = scanRun.subscribe({
          status: function (t) { setScanStatus(t, (String(t) === 'error') ? 'st-bad' : 'st-info'); scanProg.setPhase(t); },
          progress: function (p) { scanProg.setProgress(p.done, p.total); setScanStatus('Scanning... ' + p.done + ' / ' + p.total + ' done', 'st-info'); },
          row: function (r) { scanGrid.upsert(r); },
          error: function (e) { setScanStatus((e && e.text) || 'Scan error', 'st-bad'); ctx.confirm({ title: 'Secure Boot Scan - Error', body: Janet.util.esc((e && e.text) || 'The scan failed to start.'), okText: 'OK', cancelText: null }); },
          active: function (a) {
            scanRunbar.setActive(a);
            scanRunbar.cta.textContent = a ? 'SCANNING...' : 'SCAN SECURE BOOT (FLEET)';
            if (!a) lockScan(false);
          },
          final: function (res) {
            var sum = (res && res.summary) || {};
            readyHosts = (sum.readyHosts && sum.readyHosts.length) ? sum.readyHosts.slice() : [];
            var c = scanSummarize();
            var ready = readyHosts.length;
            loadReadyBtn.disabled = (ready === 0);
            copyReadyBtn.disabled = (ready === 0);
            loadReadyBtn.textContent = 'Load READY-TO-ENABLE hosts -> Targets (' + ready + ')';
            var anyErr = (c['CHECK ERROR'] || 0) > 0;
            setScanStatus('Scan complete - ' + ready + ' ready, ' + (c['ENABLED'] || 0) + ' enabled, ' + (c['BLOCKED - LEGACY/MBR'] || 0) + ' blocked.', anyErr ? 'st-warn' : 'st-ok');
            ctx.confirm({
              title: 'Secure Boot Scan - Complete',
              body: 'READY to enable: <b>' + ready + '</b><br>'
                + 'Already enabled: <b>' + (c['ENABLED'] || 0) + '</b><br>'
                + 'Unsupported OEM: <b>' + (c['OFF - UNSUPPORTED OEM'] || 0) + '</b><br>'
                + 'Blocked (Legacy/MBR): <b>' + (c['BLOCKED - LEGACY/MBR'] || 0) + '</b><br>'
                + 'Check errors: <b>' + (c['CHECK ERROR'] || 0) + '</b><br>'
                + 'Offline: <b>' + (c['OFFLINE'] || 0) + '</b><br>'
                + 'Total: <b>' + scanGrid.rows().length + '</b>'
                + (ready ? '<br><br>Use <b>Load READY-TO-ENABLE hosts</b> to fill the Targets list, then Enable in waves of &le;50.' : ''),
              okText: 'OK', cancelText: null
            });
          }
        });
      }

      async function doRun() {
        var isDry = dryCb._cb.checked;
        // empty-password gate (live only) -> the desktop's Yes/No confirm
        var allowEmpty = false;
        if (!isDry && (pwInput.value || '') === '') {
          var ok = await ctx.confirm({
            title: 'No Password',
            danger: true,
            body: 'No BIOS password entered. This works <b>only if the BIOS has no password set</b>. Continue anyway?',
            okText: 'Continue', cancelText: 'Cancel'
          });
          if (!ok) return;
          allowEmpty = true;
        }
        grid.clear(); prog.reset();
        setStatus('Starting ' + targets.hosts().length + ' target(s)...', 'st-info');
        lockInputs(true);
        var threads = Math.max(1, Math.min(10, parseInt(jobsInput.value, 10) || 5));
        run = ctx.run('enable-secure-boot', {
          targets: targets.hosts().join('\n'), bios_password: pwInput.value, allowEmptyPassword: allowEmpty,
          dry_run: isDry, threads: threads
        });
        if (unsub) unsub();
        unsub = run.subscribe({
          status: function (t) { setStatus(t, (String(t) === 'error') ? 'st-bad' : 'st-info'); prog.setPhase(t); },
          progress: function (p) { prog.setProgress(p.done, p.total); setStatus('Running... ' + p.done + ' / ' + p.total + ' done', 'st-info'); },
          row: function (r) { grid.upsert(r); },
          error: function (e) { setStatus((e && e.text) || 'Run error', 'st-bad'); ctx.confirm({ title: 'Secure Boot - Error', body: Janet.util.esc((e && e.text) || 'The run failed to start.'), okText: 'OK', cancelText: null }); },
          log: function (l) { if (l && l.level === 'err') setStatus(l.text, 'st-bad'); },
          active: function (a) {
            runbar.setActive(a);
            runbar.cta.textContent = a ? 'RUNNING...' : 'ENABLE SECURE BOOT';
            if (!a) lockInputs(false);
          },
          final: function () {
            var c = summarize();
            var anyErr = (c.Error + c.Timeout) > 0;
            if (isDry) setStatus('Dry run complete - ' + (c.DryRun) + ' reachable, ' + c.Error + ' unreachable.', anyErr ? 'st-warn' : 'st-ok');
            else setStatus('Complete - ' + c.Success + ' enabled, ' + c.Skipped + ' skipped, ' + (c.Error + c.Timeout) + ' error/timeout.', anyErr ? 'st-bad' : 'st-ok');
            ctx.confirm({
              title: isDry ? 'Dry Run Complete' : 'Secure Boot - Run Complete',
              body: isDry
                ? ('Reachable: <b>' + c.DryRun + '</b><br>Unreachable: <b>' + c.Error + '</b><br>Total: <b>' + grid.rows().length + '</b>')
                : ('Enabled: <b>' + c.Success + '</b><br>Already enabled / skipped: <b>' + c.Skipped + '</b><br>Error / timeout: <b>' + (c.Error + c.Timeout) + '</b><br>Total: <b>' + grid.rows().length + '</b>'),
              okText: 'OK', cancelText: null
            });
          }
        });
      }

      host.appendChild(root);
      this._root = root; this._unsub = function () { if (unsub) unsub(); if (scanUnsub) scanUnsub(); };
    },
    unmount: function () { try { if (this._unsub) this._unsub(); } catch (e) {} if (this._root) this._root.remove(); }
  });
})();
