/* ============================================================================
   message.view.js  -  Remote Message (tool id: 'message')  THE REFERENCE VIEW
   Faithful re-build of the desktop J.A.N.E.T. Remote Message Tool v1.2 (file
   v1.3.3) per docs/ui-specs/message.md: a single-window THREE-COLUMN dashboard
   (Targets | Composer | Activity), NOT tabs. The live "activity run" is the
   point: SEND fans out one msg.exe popup per host and results stream back into
   a colour-coded ActivityLog (canonical), three StatCards (SENT/FAILED/TOTAL),
   and a ProgressStrip, while the gold SEND button morphs to a red CANCEL.

   Composes the shared kit only; ALL runs go through ctx.run -> RunController
   (the view never fetches/polls). This view is the blueprint every later tool
   copies.
   ========================================================================== */
(function () {
  'use strict';

  var DEFAULT_TITLE = 'Message from the 48 Communications Squadron';
  var XLSX_HEADERS = ['Timestamp', 'Hostname', 'Pingable', 'Delivered', 'Undelivered', 'Sessions', 'MessageTitle', 'Mode', 'Reason', 'Diagnostic'];
  // audit 2026-07-24: the engine (JanetWeb.message.psm1 1.3.5) now separates a real
  // FAILURE from a SKIP - unconfirmed delivery, nobody logged on, and the operator's
  // own TCP-probe skip all audit as Skipped - and reports a watchdog-/cancel-abandoned
  // host as 'Timed out'/'Abandoned' instead of claiming an unmeasured 'Unreachable'.
  // The view must bucket in step or a skip is painted red and exported Undelivered=Yes.
  var SKIP_STATUS = /^(unknown|skipped|no sessions)$/i;

  JanetViews.register('message', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;

      // ---- run/result state (per the desktop $script: state) ----
      var results = [];                 // export rows (10-col schema)
      var stat = { sent: 0, fail: 0, unconfirmed: 0, total: 0 };
      var lastSendMeta = { title: '', mode: '' };
      // Ping and Send get INDEPENDENT run/unsub pairs (kev.view.js pattern): they are
      // separate parallel actions, so neither may detach the other's handlers. Sharing
      // one pair let a mid-flight SEND unsubscribe an active Ping All (button stuck).
      var pingRun = null, pingUnsub = null;   // Ping All RunController handle + unsub
      var sendRun = null, sendUnsub = null;   // Send RunController handle + unsub

      function tsNow() {
        var d = new Date(), p = function (n) { return String(n).padStart(2, '0'); };
        return d.getFullYear() + '-' + p(d.getMonth() + 1) + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
      }

      // =================== layout ===================
      var root = el('div'); root.style.cssText = 'display:flex;flex-direction:column;height:100%;min-height:0;background:var(--bg)';

      // NOTE: credentials are UNIVERSAL - the single Set Credentials control lives in
      // the shell header (top-right), shared across every tool. A per-tool view must
      // NEVER render its own cred strip; it only reads ctx.session.state.credSet.

      // three columns
      var cols = el('div'); cols.style.cssText = 'flex:1;min-height:0;display:flex;gap:14px;padding:14px 16px';
      root.appendChild(cols);

      // ---------- LEFT: TARGET MACHINES ----------
      var left = ui.card({ title: 'TARGET MACHINES' }); left.style.cssText += ';flex:0 0 320px;display:flex;flex-direction:column;min-height:0';
      var targets = C.TargetManager({
        model: ctx.util.targetModel(''),
        hint: 'Hostnames, comma or newline separated',
        importLabel: 'Import TXT',
        importAccept: '.txt,.csv,.tsv',
        pingAll: true,
        countNoun: 'target',
        onImport: function (n, name) { log.append({ text: 'Imported ' + n + ' host(s) from ' + name, level: 'info' }); },
        onPingAll: doPing
      });
      var tgHolder = el('div'); tgHolder.style.cssText = 'flex:1;min-height:120px;display:flex'; tgHolder.appendChild(targets.el);
      left.appendChild(tgHolder);
      // Restored: operator-tunable ping concurrency for the Ping All sweep.
      var pingThreadsRow = el('div'); pingThreadsRow.style.cssText = 'display:flex;align-items:center;gap:8px;margin-top:8px';
      var pingThreads = ui.number({ value: 32, min: 1, max: 64, title: 'How many hosts to ping at once during Ping All.' }); pingThreads.style.width = '80px';
      pingThreadsRow.appendChild(ui.label('Ping parallel hosts')); pingThreadsRow.appendChild(pingThreads);
      left.appendChild(pingThreadsRow);
      cols.appendChild(left);

      // ---------- MIDDLE: MESSAGE COMPOSER ----------
      var mid = ui.card({ title: 'MESSAGE COMPOSER' }); mid.style.cssText += ';flex:0 0 460px;display:flex;flex-direction:column;min-height:0';

      var titleInput = ui.input({ value: DEFAULT_TITLE, title: 'Popup title line.' });
      mid.appendChild(ui.field('Title', titleInput));

      // body + char counter
      var bodyLabelRow = el('div'); bodyLabelRow.style.cssText = 'display:flex;align-items:baseline;justify-content:space-between';
      bodyLabelRow.appendChild(ui.label('Message'));
      var charCount = el('span', 'muted'); charCount.style.fontSize = '11px'; charCount.textContent = '0 chars';
      bodyLabelRow.appendChild(charCount);
      mid.appendChild(bodyLabelRow);
      var bodyInput = ui.textarea({ placeholder: 'Type the message body...', rows: 8 });
      bodyInput.style.flex = '1'; bodyInput.style.minHeight = '120px';
      bodyInput.addEventListener('input', function () { charCount.textContent = bodyInput.value.length + ' chars'; });
      mid.appendChild(bodyInput);

      // DISPLAY OPTIONS
      var opt = el('div'); opt.style.cssText = 'margin-top:12px';
      opt.appendChild(ui.eyebrow('DISPLAY OPTIONS'));
      var timeoutInput = ui.number({ value: 60, min: 5, max: 3600, title: 'Seconds before the popup auto-dismisses (ignored when Require OK is on).' });
      timeoutInput.style.width = '110px';
      var timeoutLabel = ui.label('Auto-dismiss timeout (seconds)');
      var reqOK = ui.checkbox('Require user to click OK (popup stays until dismissed)', {
        color: 'var(--cyan)', title: 'Sends /TIME:99999 - the popup stays until the user dismisses it.',
        onChange: function () {
          var on = reqOK._cb.checked;
          timeoutInput.disabled = on;
          timeoutLabel.style.opacity = on ? '0.45' : '1';
        }
      });
      opt.appendChild(reqOK);
      opt.appendChild(el('div', 'muted', 'When unchecked, message auto-dismisses after the timeout below.')).style.cssText = 'font-size:11px;margin:3px 0 8px';
      var toRow = el('div'); toRow.style.cssText = 'display:flex;align-items:center;gap:10px;margin-bottom:8px';
      toRow.appendChild(timeoutLabel); toRow.appendChild(timeoutInput);
      opt.appendChild(toRow);
      var parallel = ui.checkbox('Send in parallel (faster for large target lists)', { checked: true, title: 'Fan out to many hosts at once. Unchecked = one host at a time.' });
      opt.appendChild(parallel);
      // Restored desktop controls: explicit parallel-host count + skip-non-pingable.
      var sendThreadsRow = el('div'); sendThreadsRow.style.cssText = 'display:flex;align-items:center;gap:10px;margin:6px 0';
      var sendThreads = ui.number({ value: 16, min: 1, max: 64, title: 'How many hosts to message at once (when Send in parallel is on).' }); sendThreads.style.width = '90px';
      sendThreadsRow.appendChild(ui.label('Parallel hosts')); sendThreadsRow.appendChild(sendThreads);
      opt.appendChild(sendThreadsRow);
      var reqPing = ui.checkbox('Skip hosts that fail the TCP 5985/5986/445 probe', { title: 'When checked, a host that fails the TCP 5985/5986/445 reachability probe is skipped instead of attempting WinRM (a host answering only on 5986 uses WinRM-over-HTTPS). (AFNET drops ICMP, so reachability is TCP-only.)' });
      opt.appendChild(reqPing);
      mid.appendChild(opt);

      // SEND button (morph to CANCEL)
      var runbar = C.RunBar({
        label: 'SEND MESSAGE TO TARGETS', cancelLabel: 'CANCEL SEND IN PROGRESS', morphToCancel: true,
        title: 'Broadcast the message to every interactive session on each target.',
        guards: [
          function () { return targets.count() ? null : 'No Targets|Add at least one hostname to the target list.'; },
          function () { return ctx.session.state.credSet ? null : 'No Credentials|Set your ADW credential (Set Credentials...) before sending. Sending changes machines, so an admin session is required.'; },
          function () { return bodyInput.value.trim() ? null : 'No Message|The message body is empty. Type a message to broadcast.'; }
        ],
        onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
        onRun: doSend,
        onCancel: function () { if (sendRun) { sendRun.cancel(); log.append({ text: 'CANCEL requested - stopping in-flight jobs...', level: 'warn' }); } }
      });
      var sendWrap = el('div'); sendWrap.style.cssText = 'margin-top:12px'; sendWrap.appendChild(runbar.el);
      mid.appendChild(sendWrap);
      cols.appendChild(mid);

      // ---------- RIGHT: ACTIVITY ----------
      var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:10px;min-height:0';

      var statCard = ui.card({}); statCard.style.padding = '10px 12px';
      var stats = C.StatCards({ cards: [
        { key: 'sent', label: 'SENT', color: 'ok' },
        { key: 'fail', label: 'FAILED', color: 'bad' },
        { key: 'unconfirmed', label: 'SKIPPED', color: 'gold' },   // audit 2026-07-24: unconfirmed + nobody-logged-on + probe skips
        { key: 'total', label: 'TOTAL', color: 'accent' }
      ] });
      statCard.appendChild(stats.el);
      var prog = C.ProgressStatusStrip({});
      prog.el.style.marginTop = '10px';
      statCard.appendChild(prog.el);
      right.appendChild(statCard);

      // ---------- RESULTS GRID (one sortable/filterable row per host) ----------
      // The ActivityLog stays the narrative; the grid is the structured, drill-down
      // view: double-click a row to read its full Diagnostic, sort by Status, etc.
      var csvBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the results grid to a .csv file (wpt parity).' });
      var GRID_CSV_COLS = ['Host', 'Pingable', 'Sessions', 'Status', 'Detail', 'Diagnostic'];
      csvBtn.onclick = function () {
        var rows = grid.rows();
        if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Run a send or ping first.', okText: 'OK', cancelText: null }); return; }
        var csv = ctx.util.toCsv(GRID_CSV_COLS, rows, GRID_CSV_COLS);
        ctx.util.downloadBlob('JRMT_Results_' + ctx.util.fileStamp() + '.csv', 'text/csv', csv);
      };
      var grid = C.ResultsGrid({
        title: 'Remote message',
        emptyText: 'No results yet — enter hosts + a message, then Send.',
        keyMode: { hostCol: 'Host' }, popOut: true,
        columns: [
          { key: 'Host', label: 'HOST', width: 150 },
          { key: 'Pingable', label: 'REACHABLE', width: 90, render: function (r) {
              if (r.Pingable == null || r.Pingable === '') return { text: '' };
              var up = (r.Pingable === true || r.Pingable === 'true');
              return up ? { text: 'Yes', cls: 'st-ok' } : { text: 'No', cls: 'st-bad' };
          } },
          { key: 'Sessions', label: 'SESSIONS', width: 80 },
          { key: 'Status', label: 'STATUS', width: 110, render: function (r) {
              var s = String(r.Status || '');
              var cls = (s === 'Delivered') ? 'st-ok' : SKIP_STATUS.test(s) ? 'st-warn' : (s ? 'st-bad' : '');
              return { text: s, cls: cls };
          } },
          { key: 'Detail', label: 'DETAIL' }
        ],
        rowClass: function (r) {
          var s = String(r.Status || '');
          if (s === 'Delivered') return 'row-ok';
          if (SKIP_STATUS.test(s)) return 'row-warn';
          return s ? 'row-bad' : '';
        },
        toolbarButtons: [csvBtn]
      });
      var gridCard = ui.card({}); gridCard.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column;padding:8px';
      gridCard.appendChild(grid.el);
      right.appendChild(gridCard);

      // export row
      var expRow = el('div'); expRow.style.cssText = 'display:flex;align-items:center;gap:8px';
      expRow.appendChild(ui.eyebrow('EXPORT RESULTS'));
      var expSent = ui.ghostButton('Sent XLSX', { size: 'sm', title: 'Export delivered hosts to an .xlsx workbook.' });
      var expFailed = ui.ghostButton('Failed XLSX', { size: 'sm', title: 'Export undelivered/failed hosts.' });
      var expAll = ui.ghostButton('All XLSX', { size: 'sm', title: 'Export every result row.' });
      expSent.disabled = expFailed.disabled = expAll.disabled = true;
      expSent.onclick = function () { exportXlsx('Sent'); };
      expFailed.onclick = function () { exportXlsx('Failed'); };
      expAll.onclick = function () { exportXlsx('All'); };
      [expSent, expFailed, expAll].forEach(function (b) { expRow.appendChild(b); });
      right.appendChild(expRow);

      var logCard = ui.card({}); logCard.classList.add('j-logdock'); logCard.style.cssText += ';margin:0 16px 14px';
      var log = C.ActivityLog({ title: 'ACTIVITY LOG', defaultName: 'JRMT_ActivityLog' });
      logCard.appendChild(log.el);
      // full-width activity dock across the bottom of the tool (was boxed in the right column)
      root.appendChild(logCard);

      cols.appendChild(right);

      // footer credit + log path (mirrors the desktop footer)
      var footer = el('div', 'j-footer');
      footer.appendChild(el('span', 'credit', 'Created by: THOMPSON, BRAXTON - 48 CS'));
      var logPath = el('span'); logPath.textContent = 'Log: ' + (ctx.session.state.logRoot || '(local)');
      footer.appendChild(logPath);
      root.appendChild(footer);

      // =================== helpers ===================
      function resetRun(total) {
        results = []; stat = { sent: 0, fail: 0, unconfirmed: 0, total: total || 0 };
        if (statsRaf) { caf(statsRaf); statsRaf = 0; }
        stats.setAll({ sent: 0, fail: 0, unconfirmed: 0, total: stat.total });
        grid.clear();
        prog.reset();
        expSent.disabled = expFailed.disabled = expAll.disabled = true;
      }
      function refreshExportButtons() {
        var anySent = results.some(function (r) { return r.Delivered === 'Yes'; });
        var anyFailed = results.some(function (r) { return r.Undelivered === 'Yes'; });
        expSent.disabled = !anySent;
        expFailed.disabled = !anyFailed;
        expAll.disabled = !results.length;
      }
      // StatCards repaint is rAF-coalesced: a mass send streams hundreds/thousands of
      // rows, and a setAll (3+ DOM writes) per row is wasteful. We accumulate counts
      // synchronously and paint at most once per frame; flushStats() forces a final
      // paint (rAF can be throttled when the tab is backgrounded).
      var raf = window.requestAnimationFrame ? window.requestAnimationFrame.bind(window) : function (f) { return setTimeout(f, 16); };
      var caf = window.cancelAnimationFrame ? window.cancelAnimationFrame.bind(window) : clearTimeout;
      var statsRaf = 0;
      function flushStats() { stats.setAll({ sent: stat.sent, fail: stat.fail, unconfirmed: stat.unconfirmed, total: stat.total }); }
      function pushStats() {
        if (statsRaf) return;
        statsRaf = raf(function () { statsRaf = 0; flushStats(); });
      }

      // ---- Ping All (left) ----
      function doPing() {
        if (pingRun && pingRun.state && pingRun.state.active) return;
        // Cross-guard: Ping and Send share results[]/stat/prog (via resetRun), so they
        // cannot run concurrently without one wiping the other's export rows and counters.
        if (sendRun && sendRun.state && sendRun.state.active) { ctx.confirm({ title: 'Send In Progress', body: 'A message send is still running. Wait for it to finish (or CANCEL it) before Ping All - they share the results grid and stat cards.', okText: 'OK', cancelText: null }); return; }
        if (!targets.count()) { ctx.confirm({ title: 'No Targets', body: 'Add at least one hostname to ping.', okText: 'OK', cancelText: null }); return; }
        var hosts = targets.hosts();
        resetRun(hosts.length);
        log.banner('Ping All (' + hosts.length + ' host(s))');
        var online = 0, offline = 0, unmeasured = 0;
        targets.setPingEnabled(false); targets.setPingLabel('Pinging...');
        pingRun = ctx.run('ping', { targets: hosts.join('\n'), threads: Math.max(1, Math.min(64, parseInt(pingThreads.value, 10) || 32)) });
        if (pingUnsub) pingUnsub();
        pingUnsub = pingRun.subscribe({
          progress: function (p) { prog.setProgress(p.done, p.total); },
          row: function (r) {
            // audit 2026-07-25 (fable re-audit follow-up): the engine now ships a BLANK
            // Pingable for a host it never probed (sweep cancelled / worker error), so an
            // unmeasured host must NOT be logged, painted, or exported as OFFLINE - that is
            // the same unmeasured-network claim the send path already stopped making.
            var unknown = (r.Pingable == null || r.Pingable === '');
            var up = (r.Pingable === true || r.Pingable === 'true');
            if (unknown) { unmeasured++; log.append({ text: '[' + r.Host + '] NOT MEASURED (never probed)', level: 'warn' }); }
            else if (up) { online++; log.append({ text: '[' + r.Host + '] ONLINE', level: 'ok' }); }
            else { offline++; log.append({ text: '[' + r.Host + '] OFFLINE / not pingable', level: 'err' }); }
            grid.upsert({ Host: r.Host, Pingable: unknown ? '' : up });
            results.push(rowRecord(r.Host, unknown ? '' : (up ? 'Yes' : 'No'), 'N/A', 'N/A', 0, '', 'Ping', '', ''));
            refreshExportButtons();
          },
          log: function (l) { log.append(l); },
          final: function () { log.banner('Ping complete: ' + online + ' online, ' + offline + ' offline' + (unmeasured ? ', ' + unmeasured + ' not measured' : '')); },
          active: function (a) { if (!a) { targets.setPingEnabled(true); targets.setPingLabel('Ping All'); } }
        });
      }

      // ---- SEND (middle) ----
      function doSend() {
        if (sendRun && sendRun.state && sendRun.state.active) return;
        // Cross-guard: a running Ping All shares results[]/stat/prog, so block Send until
        // it finishes rather than let resetRun() wipe the ping's rows mid-sweep.
        if (pingRun && pingRun.state && pingRun.state.active) { ctx.confirm({ title: 'Ping In Progress', body: 'Ping All is still running. Wait for it to finish before sending - they share the results grid and stat cards.', okText: 'OK', cancelText: null }); return; }
        var hosts = targets.hosts();
        if (!titleInput.value.trim()) titleInput.value = DEFAULT_TITLE;   // empty title auto-fills the default
        var requireOK = reqOK._cb.checked;
        var timeout = Math.max(5, Math.min(3600, parseInt(timeoutInput.value, 10) || 60));
        var mode = requireOK ? 'REQUIRE OK CLICK' : ('Auto-dismiss after ' + timeout + 's');

        ctx.confirm({
          title: 'Confirm Mass Send',
          danger: true,
          body: 'Send a popup to <b>' + hosts.length + '</b> target(s)?<br>Mode: <b>' + mode + '</b><br>Title: <b>' + escHtml(titleInput.value) + '</b><br><br>First few targets:',
          list: hosts.slice(0, 5),
          okText: 'Send', cancelText: 'Cancel'
        }).then(function (ok) {
          if (!ok) return;
          lastSendMeta = { title: titleInput.value, mode: mode };
          resetRun(hosts.length);
          log.banner('Sending message to ' + hosts.length + ' target(s)');
          log.append({ text: 'Mode: ' + mode, level: 'mode' });
          log.append({ text: 'Title: ' + titleInput.value, level: 'dim' });
          if (!requireOK) log.append({ text: 'Auto-dismiss after ' + timeout + 's', level: 'dim' });

          sendRun = ctx.run('send', {
            targets: hosts.join('\n'), title: titleInput.value, body: bodyInput.value,
            requireOK: requireOK, timeout: timeout, parallel: parallel._cb.checked,
            threads: Math.max(1, Math.min(64, parseInt(sendThreads.value, 10) || 16)),
            requirePing: reqPing._cb.checked
          });
          if (sendUnsub) sendUnsub();
          sendUnsub = sendRun.subscribe({
            status: function (t) { prog.setPhase(t); },
            progress: function (p) { prog.setProgress(p.done, p.total); },
            row: function (r) {
              var st = String(r.Status || '');
              var delivered = (st === 'Delivered');
              // audit 2026-07-24: the skip bucket is the honest middle ground - msg.exe gave
              // no clear signal ('Unknown'), nobody was logged on ('No sessions'), or the
              // operator asked us to skip unreachable hosts ('Skipped'). The engine audits
              // all three as Skipped, so they are neither SENT nor FAILED here.
              var skipped = SKIP_STATUS.test(st);
              if (delivered) {
                stat.sent++; log.append({ text: '[' + r.Host + '] Delivered to ' + (r.Sessions || 0) + ' session(s)', level: 'ok' });
              } else if (skipped) {
                stat.unconfirmed++; log.append({ text: '[' + r.Host + '] SKIPPED (' + st + ')' + (r.Detail ? ' - ' + r.Detail : ''), level: 'warn' });
                if (r.Diagnostic) log.append({ text: '  diag: ' + r.Diagnostic, level: 'diag' });
              } else {
                stat.fail++; log.append({ text: '[' + r.Host + '] FAILED: ' + (r.Detail || st || 'unknown'), level: 'err' });
                if (r.Diagnostic) log.append({ text: '  diag: ' + r.Diagnostic, level: 'diag' });
              }
              grid.upsert(r);
              pushStats();
              // An abandoned host ships a BLANK Pingable (the probe never ran), so the export
              // must not turn that into a 'No' reachability claim (audit 2026-07-24).
              var ping = (r.Pingable === true || r.Pingable === 'true') ? 'Yes'
                : (r.Pingable == null || r.Pingable === '') ? '' : 'No';
              results.push(rowRecord(r.Host, ping,
                delivered ? 'Yes' : (skipped ? st : 'No'), (delivered || skipped) ? 'No' : 'Yes', r.Sessions || 0,
                lastSendMeta.title, lastSendMeta.mode, r.Detail || '', r.Diagnostic || ''));
              refreshExportButtons();
            },
            log: function (l) { log.append(l); },
            final: function () { flushStats(); log.banner('Send complete: ' + stat.sent + ' sent, ' + stat.unconfirmed + ' skipped, ' + stat.fail + ' failed'); refreshExportButtons(); },
            active: function (a) { runbar.setActive(a); if (!a) runbar.setStatus('Results ready: use the Export buttons to save.', 'st-ok'); }
          });
        });
      }

      function rowRecord(hostName, pingable, delivered, undelivered, sessions, title, mode, reason, diag) {
        return { Timestamp: tsNow(), Hostname: hostName, Pingable: pingable, Delivered: delivered, Undelivered: undelivered, Sessions: sessions, MessageTitle: title, Mode: mode, Reason: reason, Diagnostic: diag };
      }
      function exportXlsx(which) {
        var subset = which === 'Sent' ? results.filter(function (r) { return r.Delivered === 'Yes'; })
          : which === 'Failed' ? results.filter(function (r) { return r.Undelivered === 'Yes'; })
          : results;
        if (!subset.length) return;
        var rows = subset.map(function (r) { return XLSX_HEADERS.map(function (h) { return r[h]; }); });
        var prefix = which === 'Sent' ? 'JRMT_Delivered' : which === 'Failed' ? 'JRMT_Failed' : 'JRMT_AllResults';
        ctx.util.downloadXlsx(prefix + '_' + ctx.util.fileStamp() + '.xlsx', XLSX_HEADERS, rows, which);
      }
      var escHtml = Janet.util.esc;

      host.appendChild(root);
      this._root = root; this._unsub = function () { if (pingUnsub) pingUnsub(); if (sendUnsub) sendUnsub(); };
    }
  });
})();
