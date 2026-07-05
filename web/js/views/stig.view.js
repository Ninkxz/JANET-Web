/* ============================================================================
   stig.view.js  -  STIG Checker (tool id: 'stig')
   Read-only STIG compliance checker. Pattern-cloned from c2c.view.js: a left
   config column (TARGET COMPUTERS at the top, a short "what this scans" info
   card, scan options, then a single Scan action bar) beside a colour-coded
   per-host Results grid, with a sticky footer carrying progress + Export CSV +
   a streaming ActivityLog.

   PRIMARY action "STIG Compliance Scan" (action id 'scan'): the engine fans one
   worker per host, runs ONE consolidated read-only registry probe over the rules
   in JanetLocal\stig-baseline.json, streams the FULL per-rule report to the
   activity log ([COMPLIANT]/[OPEN]/[ERROR] lines the log colours), and emits one
   final row per host ({ Host, Ping, Compliant, Open, Errors, Verdict, Detail }).
   Rows are keyed by Host. Verdict per host = COMPLIANT / "<n> OPEN" / CHECK
   ERRORS / OFFLINE.

   SECONDARY action "Host Rule Detail" (action id 'host-detail'): CLICK a result
   row to re-probe that single host and stream its per-rule breakdown into the
   activity log. Read-only; changes nothing; not gated on an admin session.

   The baseline (JanetLocal\stig-baseline.json) is hand-edited; there is no
   in-app editor - edit the file then re-run to pick up changes.

   Credentials are UNIVERSAL (shell header top-right) - this view renders NO
   per-tool credential control; it only READS ctx.session.state.credSet.
   ========================================================================== */
(function () {
  'use strict';

  // engine row events are keyed 'Host'; CSV header keeps the desktop label 'Computer'.
  var EXPORT_COLS = [['Host', 'Computer'], ['Ping', 'Ping'], ['Compliant', 'Compliant'], ['Open', 'Open'], ['Errors', 'Errors'], ['Verdict', 'Verdict'], ['Detail', 'Detail']];

  // Short "what this scans" summary shown in the info card (illustrative subset of
  // the editable baseline, NOT the authoritative list - that lives in the JSON).
  var CHECK_GROUPS = [
    ['Legacy protocols', 'SMBv1 off, TLS 1.0/1.1 client+server disabled (SCHANNEL)'],
    ['Authentication', 'LmCompatibilityLevel 5, NoLMHash, RestrictAnonymous(+SAM), LDAP + SMB signing'],
    ['UAC + elevation', 'EnableLUA, ConsentPromptBehaviorAdmin, AlwaysInstallElevated=0 (HKLM+HKCU)'],
    ['Credential theft', 'WDigest UseLogonCredential=0, LSA RunAsPPL, SEHOP'],
    ['Logging', 'PowerShell ScriptBlock + Module logging'],
    ['Remote + removable', 'RDP NLA + High encryption, WinRM no-Basic/no-unencrypted, Autorun/Autoplay off'],
    ['Malware defense', 'SmartScreen enabled, Defender PUA protection']
  ];

  function statusCellCls(v) {
    var s = String(v == null ? '' : v);
    // green: fully compliant.
    if (s === 'COMPLIANT') return 'st-ok';
    // red: one or more open findings ("<n> OPEN"), or unreachable.
    if (/\bOPEN$/i.test(s) || s === 'OFFLINE') return 'st-bad';
    // amber: no open finding but a rule errored / host couldn't be evaluated / cancel.
    if (s === 'CHECK ERRORS' || s === 'Cancelled' || s === 'ERROR' || s === 'DNS MISMATCH') return 'st-warn';
    // live in-progress phases.
    if (s === 'Scanning' || s === 'Probing' || s === 'Working') return 'st-info';
    if (s === 'Queued') return 'cell-dim';
    return '';
  }
  function pingCellCls(v) {
    var s = String(v == null ? '' : v);
    if (s === '') return '';
    if (/^(tcp |\d)/i.test(s)) return 'st-ok';
    if (/unreach|offline/i.test(s)) return 'st-bad';
    if (/dns|error/i.test(s)) return 'st-warn';
    return 'cell-dim';
  }
  // per-rule Result colouring for the host-detail stream (also used defensively).
  function resultCellCls(v) {
    var s = String(v == null ? '' : v);
    if (s === 'Compliant') return 'st-ok';
    if (s === 'Open') return 'st-bad';
    if (s === 'Error') return 'st-warn';
    return '';
  }

  JanetViews.register('stig', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;

      // ---- run/result state ----
      var run = null, unsub = null;          // the fleet scan
      var detailRun = null, detailUnsub = null;  // the single-host detail probe

      // =================== layout ===================
      var root = el('div'); root.style.cssText = 'display:flex;flex-direction:column;height:100%;min-height:0;background:var(--bg)';

      var body = el('div'); body.style.cssText = 'flex:1;min-height:0;display:flex;gap:14px;padding:14px 16px 0';
      root.appendChild(body);

      // ---------- LEFT: CONFIG COLUMN ----------
      var left = el('div'); left.style.cssText = 'flex:0 0 440px;display:flex;flex-direction:column;gap:12px;min-height:0;overflow:auto';
      body.appendChild(left);

      // --- Computers (TargetManager) ---
      var compCard = sectionCard('TARGET COMPUTERS');
      compCard.style.cssText += ';flex:0 0 auto;min-height:150px;max-height:300px;display:flex;flex-direction:column;overflow:hidden';
      var targets = C.TargetManager({
        model: ctx.util.targetModel(''),
        hint: 'One host per line - comma/space/semicolon ok; # starts a comment.',
        placeholder: 'WS-0001\nWS-0002\n# lab row\nWS-0003',
        importLabel: 'Import TXT', importAccept: '.txt',
        countNoun: 'computer',
        onImport: function (n, name) { log.append({ text: '[' + ts() + '] Added ' + n + ' computer(s) from ' + name, level: 'info' }); }
      });
      var tgHolder = el('div'); tgHolder.style.cssText = 'flex:1;min-height:0;display:flex'; tgHolder.appendChild(targets.el);
      compCard.appendChild(tgHolder);
      left.appendChild(compCard);

      // --- What this scans (read-only info) ---
      var infoCard = sectionCard('WHAT THIS SCANS - STIG registry/policy checks', 'cyan');
      var intro = el('div'); intro.style.cssText = 'font-size:12.5px;line-height:1.45;color:var(--text);margin-bottom:8px';
      intro.textContent = 'One consolidated READ-ONLY registry probe per host (changes nothing) over WinRM. '
        + 'Each rule in JanetLocal\\stig-baseline.json scores Compliant / Open / Error. '
        + 'Curated Windows 10/11 member-server-safe checks, for example:';
      infoCard.appendChild(intro);
      var list = el('ul'); list.style.cssText = 'margin:0 0 8px 18px;padding:0;font-size:12px;line-height:1.5;color:var(--text)';
      CHECK_GROUPS.forEach(function (c) {
        var li = el('li'); li.style.margin = '2px 0';
        var strong = el('span'); strong.style.cssText = 'font-weight:700;color:var(--text)'; strong.textContent = c[0] + ' - ';
        li.appendChild(strong);
        li.appendChild(document.createTextNode(c[1]));
        list.appendChild(li);
      });
      infoCard.appendChild(list);
      var verdictNote = el('div'); verdictNote.style.cssText = 'font-size:12px;line-height:1.45;color:var(--muted)';
      verdictNote.textContent = 'Verdict per host: COMPLIANT (0 open, 0 error) / "<n> OPEN" (1+ finding) / CHECK ERRORS '
        + '(0 open but 1+ error). The full per-rule report streams to the activity log. '
        + 'Baseline is hand-edited - edit JanetLocal\\stig-baseline.json, then re-run to reload it. '
        + 'Tip: double-click a result row to stream that host\'s per-rule detail.';
      infoCard.appendChild(verdictNote);
      left.appendChild(infoCard);

      // --- Scan options (attempt-offline + concurrency) ---
      var optCard = sectionCard('SCAN OPTIONS');
      var offlineCb = ui.checkbox('Attempt even if offline (host unreachable)', { title: 'Proceed against a host that fails the TCP 5985/445 reachability probe (e.g. firewalled but WinRM up). Reachability is TCP-only - AFNET drops ICMP.' });
      optCard.appendChild(offlineCb);
      var threadsRow = el('div'); threadsRow.style.cssText = 'display:flex;align-items:center;gap:10px;margin-top:8px';
      threadsRow.appendChild(ui.label('Max concurrent:'));
      var threadsInput = ui.number({ value: 16, min: 1, max: 32, title: 'Parallel hosts (1-32).' });
      threadsInput.style.width = '80px';
      threadsRow.appendChild(threadsInput);
      optCard.appendChild(threadsRow);
      left.appendChild(optCard);

      // --- Action bar (single Scan button via RunBar; read-only, NO admin-session guard) ---
      var actionCard = ui.card({}); actionCard.style.cssText += ';display:flex;flex-direction:column;gap:8px';
      var runbar = C.RunBar({
        label: 'STIG COMPLIANCE SCAN', cancelLabel: 'CANCEL SCAN IN PROGRESS', morphToCancel: true,
        title: 'Read-only STIG compliance probe across every computer (changes nothing).',
        guards: [
          function () { return targets.count() ? null : 'No Computers|Add at least one computer to the list before scanning.'; }
        ],
        onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
        onRun: doRun,
        onCancel: function () { if (run) { run.cancel(); log.append({ text: '[' + ts() + '] CANCEL requested - in-flight probes are stopped and marked Cancelled.', level: 'warn' }); } }
      });
      var rbWrap = el('div'); rbWrap.appendChild(runbar.el);
      actionCard.appendChild(rbWrap);
      left.appendChild(actionCard);

      // ---------- RIGHT: RESULTS ----------
      var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;min-height:0';
      var resultsCard = ui.card({}); resultsCard.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
      var resHdr = el('div', 'j-section-h', 'RESULTS  (double-click a row for per-rule detail)'); resHdr.style.marginBottom = '6px';
      resultsCard.appendChild(resHdr);
      var grid = C.ResultsGrid({
        title: 'STIG compliance results',
        emptyText: 'No results yet — add computers, then run STIG Compliance Scan.',
        keyMode: { hostCol: 'Host' }, popOut: true,
        onRowClick: function (r) { openHostDetail(r); },
        columns: [
          { key: 'Host', label: 'HOST', width: 160 },
          { key: 'Ping', label: 'PING', width: 84, render: function (r) { return { text: r.Ping == null ? '' : String(r.Ping), cls: pingCellCls(r.Ping) }; } },
          { key: 'Compliant', label: 'OK', width: 60, render: function (r) { var t = r.Compliant == null ? '' : String(r.Compliant); return { text: t, cls: (t !== '' && t !== '0') ? 'st-ok' : 'cell-dim' }; } },
          { key: 'Open', label: 'OPEN', width: 62, render: function (r) { var t = r.Open == null ? '' : String(r.Open); return { text: t, cls: (t !== '' && t !== '0') ? 'st-bad' : 'cell-dim' }; } },
          { key: 'Errors', label: 'ERR', width: 58, render: function (r) { var t = r.Errors == null ? '' : String(r.Errors); return { text: t, cls: (t !== '' && t !== '0') ? 'st-warn' : 'cell-dim' }; } },
          { key: 'Verdict', label: 'VERDICT', width: 128, render: function (r) { return { text: r.Verdict == null ? '' : String(r.Verdict), cls: statusCellCls(r.Verdict) }; } },
          { key: 'Detail', label: 'DETAIL', render: function (r) { var t = r.Detail == null ? '' : String(r.Detail); return { text: t, title: t }; } }
        ],
        rowClass: function (r) {
          var s = String(r.Verdict);
          if (s === 'COMPLIANT') return 'row-ok';
          if (/\bOPEN$/i.test(s) || s === 'OFFLINE') return 'row-bad';
          if (s === 'CHECK ERRORS' || s === 'Cancelled' || s === 'ERROR' || s === 'DNS MISMATCH') return 'row-warn';
          return '';
        }
      });
      var gridHolder = el('div'); gridHolder.style.cssText = 'flex:1;min-height:0;display:flex'; gridHolder.appendChild(grid.el);
      resultsCard.appendChild(gridHolder);
      right.appendChild(resultsCard);
      body.appendChild(right);

      // ---------- FOOTER: progress + export ----------
      var footer = el('div'); footer.style.cssText = 'display:flex;gap:14px;padding:12px 16px;min-height:150px;max-height:34%';
      var progCol = el('div'); progCol.style.cssText = 'flex:0 0 320px;display:flex;flex-direction:column;gap:8px';
      var progCard = ui.card({}); progCard.style.cssText += ';display:flex;flex-direction:column;gap:8px';
      var countLine = el('div'); countLine.style.cssText = 'font-family:var(--ui);font-weight:700;font-size:14px;color:var(--text)';
      countLine.textContent = '0 / 0';
      progCard.appendChild(countLine);
      var prog = C.ProgressStatusStrip({ showCount: true });
      progCard.appendChild(prog.el);
      var expRow = el('div'); expRow.style.cssText = 'display:flex;gap:8px';
      var exportBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the per-host result rows to a CSV file.' });
      exportBtn.onclick = doExport;
      var clearBtn = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the results grid + reset progress.' });
      clearBtn.onclick = function () { if (isRunning()) return; grid.clear(); prog.reset(); countLine.textContent = '0 / 0'; runbar.setStatus('', 'muted'); };
      expRow.appendChild(exportBtn); expRow.appendChild(clearBtn);
      progCard.appendChild(expRow);
      progCol.appendChild(progCard);
      footer.appendChild(progCol);
      root.appendChild(footer);

      // ---------- ACTIVITY LOG: full-width dock across the bottom ----------
      var logCard = ui.card({}); logCard.classList.add('j-logdock'); logCard.style.cssText += ';margin:0 16px 14px';
      var log = C.ActivityLog({ title: 'ACTIVITY LOG', defaultName: 'STIGChecker_ActivityLog' });
      logCard.appendChild(log.el);
      root.appendChild(logCard);

      // =================== helpers ===================
      function sectionCard(title, headerColor) {
        var box = ui.card({});
        var h = el('div', 'j-section-h', title); h.style.marginBottom = '8px';
        if (headerColor === 'cyan') h.style.color = 'var(--cyan)';
        box.insertBefore(h, box.firstChild);
        return box;
      }
      function ts() { return ctx.util.clockStr(); }
      function isRunning() { return !!(run && run.state && run.state.active); }
      function isDetailRunning() { return !!(detailRun && detailRun.state && detailRun.state.active); }
      function threads() { return Math.max(1, Math.min(32, parseInt(threadsInput.value, 10) || 16)); }

      function lockInputs(on) {
        offlineCb._cb.disabled = on; threadsInput.disabled = on; clearBtn.disabled = on;
      }

      function summarize() {
        var compliant = 0, open = 0, offline = 0, errors = 0;
        grid.rows().forEach(function (r) {
          var s = String(r.Verdict);
          if (s === 'COMPLIANT') compliant++;
          else if (/\bOPEN$/i.test(s)) open++;
          else if (s === 'OFFLINE') offline++;
          else if (s === 'CHECK ERRORS') errors++;
        });
        var total = grid.rows().length;
        // 'other' catches Cancelled / leftover Queued rows so buckets reconcile to
        // total without folding them into CHECK ERRORS (mirrors the engine's Other tally).
        var other = total - compliant - open - offline - errors;
        return { compliant: compliant, open: open, errors: errors, offline: offline, other: other, total: total };
      }

      // ---- bind the fleet scan run to the grid/log/progress surfaces ----
      function bindRun(verb) {
        if (unsub) unsub();
        unsub = run.subscribe({
          status: function (t) { prog.setPhase(t); runbar.setStatus(t, 'st-info'); },
          progress: function (p) { prog.setProgress(p.done, p.total); countLine.textContent = p.done + ' / ' + p.total; },
          row: function (r) { grid.upsert(r); },
          // append engine log lines VERBATIM - the full per-rule report, uncut, so
          // the log colours each [COMPLIANT]/[OPEN]/[ERROR] line.
          log: function (l) { log.append(l); },
          error: function (e) { log.append({ text: '[' + ts() + '] ' + (e && e.text ? e.text : 'error'), level: 'err' }); },
          active: function (a) {
            runbar.setActive(a);
            if (!a) {
              lockInputs(false);
              var c = summarize();
              countLine.textContent = c.total + ' / ' + c.total;
              var bad = c.open + c.offline;
              log.append({ text: '[' + ts() + '] FINISHED ' + verb + '. COMPLIANT=' + c.compliant + '  OPEN=' + c.open + '  CHECK ERRORS=' + c.errors + '  OFFLINE=' + c.offline + '  OTHER=' + c.other, level: bad ? 'warn' : 'ok' });
              runbar.setStatus('Done - Compliant ' + c.compliant + ' / Open ' + c.open + ' / Errors ' + c.errors + ' / Offline ' + c.offline + ' / Other ' + c.other, bad ? 'st-bad' : 'st-ok');
            }
          }
        });
      }

      // ---- STIG Compliance Scan (read-only; no admin session, no confirm) ----
      function doRun() {
        if (isRunning()) return;
        var hosts = targets.hosts();
        grid.clear(); prog.reset(); countLine.textContent = '0 / ' + hosts.length;
        hosts.forEach(function (h) { grid.upsert({ Host: h, Ping: '', Compliant: '', Open: '', Errors: '', Verdict: 'Queued', Detail: 'Queued' }); });
        log.banner('STIG Compliance Scan on ' + hosts.length + ' computer(s)');
        lockInputs(true);
        run = ctx.run('scan', {
          targets: hosts.join('\n'),
          attemptOffline: offlineCb._cb.checked,
          threads: threads()
        }, { keyOf: keyByHost, destructive: false });
        bindRun('STIG Compliance Scan');
      }

      function keyByHost(ev) { return ev.Host != null ? String(ev.Host) : (ev.host != null ? String(ev.host) : null); }

      // ---- Host Rule Detail (secondary action; click a result row) ----
      function openHostDetail(r) {
        if (!r || r.Host == null) return;
        var h = String(r.Host);
        var v = String(r.Verdict == null ? '' : r.Verdict);
        if (v === 'Queued' || v === '') return;               // nothing scanned yet
        if (isRunning()) { log.append({ text: '[' + ts() + '] Finish the fleet scan before pulling per-rule detail.', level: 'warn' }); return; }
        if (isDetailRunning()) { log.append({ text: '[' + ts() + '] A host-detail probe is already running - wait for it to finish.', level: 'warn' }); return; }
        log.banner('Host Rule Detail: ' + h);
        detailRun = ctx.run('host-detail', { host: h, attemptOffline: true }, { keyOf: function (ev) { return ev._rk || (ev.Rule != null ? String(ev.Rule) : null); }, destructive: false });
        if (detailUnsub) detailUnsub();
        detailUnsub = detailRun.subscribe({
          status: function (t) { runbar.setStatus(t, 'st-info'); },
          // stream the per-rule report lines VERBATIM into the shared activity log.
          log: function (l) { log.append(l); },
          // per-rule rows are summarized into the log (not merged into the host grid).
          row: function (row) {
            var res = String(row.Result == null ? '' : row.Result);
            var lvl = res === 'Open' ? 'error' : (res === 'Error' ? 'warn' : 'ok');
            log.append({ text: '  ' + (row.Severity || '') + '  ' + (row.Rule || '') + ' [' + res + ']  ' + (row.Title || ''), level: lvl });
          },
          error: function (e) { log.append({ text: '[' + ts() + '] ' + (e && e.text ? e.text : 'error'), level: 'err' }); },
          active: function (a) { if (!a) { log.append({ text: '[' + ts() + '] Host Rule Detail complete: ' + h, level: 'info' }); } }
        });
      }

      function doExport() {
        var rows = grid.rows();
        if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Run a scan first - there are no result rows yet.', okText: 'OK', cancelText: null }); return; }
        var csv = ctx.util.toCsv(EXPORT_COLS.map(function (p) { return p[1]; }), rows, EXPORT_COLS.map(function (p) { return p[0]; }));
        ctx.util.downloadBlob('STIGChecker_results_' + ctx.util.fileStamp() + '.csv', 'text/csv', csv);
        log.append({ text: '[' + ts() + '] Exported ' + rows.length + ' row(s) to CSV.', level: 'info' });
      }

      // =================== init ===================
      log.append({ text: 'STIG Checker ready. Add computers, then run the STIG Compliance Scan (read-only - changes nothing, no admin session needed).', level: 'accent' });
      log.append({ text: 'Rules load from JanetLocal\\stig-baseline.json (hand-edited). Double-click a result row to stream that host\'s per-rule detail. The full per-rule report streams here.', level: 'dim' });

      host.appendChild(root);
      this._root = root;
      this._unsub = function () { if (unsub) unsub(); if (detailUnsub) detailUnsub(); };
    },
    unmount: function () { try { if (this._unsub) this._unsub(); } catch (e) {} if (this._root) this._root.remove(); }
  });
})();
