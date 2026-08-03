/* ============================================================================
   remoteadmin.view.js  -  Remote Admin (tool id: 'remoteadmin')
   Two operator hands-on-keyboard capabilities, one per tab, sharing one bottom
   ActivityLog dock:
     1. Open C$   - launch \\<computer>\C$ in Explorer on the operator's OWN
                    session by computer name. Non-destructive; no admin session.
     2. Run Script- fan an operator-authored PowerShell block to one/many hosts
                    over WinRM. DESTRUCTIVE (arbitrary remote code): needs a live
                    admin session, confirms with a typed RUN word, and is fully
                    SHA256-audited server-side.
   Credentials are UNIVERSAL (shell header); this view renders NO cred control.
   ========================================================================== */
(function () {
  'use strict';

  function statusCell(v) {
    var s = String(v == null ? '' : v);
    var low = s.toLowerCase();
    if (low === 'success' || low.indexOf('opened') === 0) return { text: s, cls: 'st-ok' };
    // loop 2026-08-03: 'skipped' was in neither list, so the wrong-box DNS-mismatch
    // abort (psm1:324) - the row that most needs to stand out, because the operator's
    // arbitrary block did NOT run - rendered as the blandest row in the grid.
    if (low === 'offline' || low === 'timeout' || low === 'rejected' || low === 'session error' || low === 'skipped') return { text: s, cls: 'st-warn' };
    if (low === 'failed') return { text: s, cls: 'st-bad' };
    return { text: s, cls: '' };
  }
  function onlineCell(v) {
    if (v == null || v === '') return { text: '', cls: 'cell-dim' };
    var yes = (v === true || String(v).toLowerCase() === 'true');
    return { text: yes ? 'Yes' : 'No', cls: yes ? 'st-ok' : 'st-warn' };
  }
  function wrapCell(v) { var t = String(v == null ? '' : v); return { text: t, title: t }; }
  function errCell(v) { var t = String(v == null ? '' : v); return { text: t, cls: t ? 'st-warn' : 'cell-dim', title: t }; }
  function intOr(node, dflt) {
    var n = parseInt(node && node.value, 10);
    if (isNaN(n)) return dflt;
    var mn = node && parseInt(node.min, 10); var mx = node && parseInt(node.max, 10);
    if (!isNaN(mn) && n < mn) n = mn;
    if (!isNaN(mx) && mx > 0 && n > mx) n = mx;
    return n;
  }

  JanetViews.register('remoteadmin', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;
      var subs = [];
      function track(u) { if (u) subs.push(u); }
      function ts() { return ctx.util.clockStr(); }
      function setLine(node, txt, cls) { if (!node) return; node.textContent = txt == null ? '' : String(txt); node.className = cls || 'muted'; }

      var actlog = C.ActivityLog({ title: 'ACTIVITY LOG', defaultName: 'RemoteAdmin_ActivityLog' });

      // ---- TAB 1: Open C$ ---------------------------------------------------
      function buildOpenCShare(panel) {
        panel.style.cssText = 'display:flex;gap:14px;height:100%;min-height:0;box-sizing:border-box;padding:12px';

        var left = el('div'); left.style.cssText = 'flex:0 0 380px;display:flex;flex-direction:column;gap:12px;min-height:0';
        var card = ui.namedCard('OPEN ADMIN SHARE (C$)', 'Type a computer name and open \\\\<computer>\\C$ in Explorer on your own machine. Non-destructive; needs no admin session.');
        card.style.cssText += ';display:flex;flex-direction:column;gap:10px';

        var compIn = ui.input({ placeholder: 'WS-0001  (hostname or IPv4)', title: 'A single computer name - bare hostname or IPv4 only.' });
        compIn.style.cssText = 'width:100%;font-family:var(--mono)';
        var openBtn = ui.button('Open C$', { variant: 'gold', size: 'sm', title: 'Launch \\\\<computer>\\C$ in Explorer on this session.' });
        var statusLine = el('div', 'muted', 'Ready'); statusLine.style.fontSize = '12px';

        var row = el('div'); row.style.cssText = 'display:flex;align-items:center;gap:8px';
        row.appendChild(ui.label('Computer')); row.appendChild(compIn);
        card.appendChild(row);
        var btnRow = el('div'); btnRow.style.cssText = 'display:flex;gap:8px;align-items:center';
        btnRow.appendChild(openBtn); card.appendChild(btnRow);
        card.appendChild(statusLine);
        left.appendChild(card);
        panel.appendChild(left);

        var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:12px;min-height:0';
        var results = ui.namedCard('OPEN RESULTS', 'One row per Open C$ request this session.');
        results.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
        var grid = C.ResultsGrid({
          title: 'OPEN RESULTS', keyMode: { rk: true }, popOut: true, selectable: false,
          columns: [
            { key: 'Computer', label: 'COMPUTER', width: 180 },
            { key: 'Path', label: 'PATH', width: 200, render: function (r) { return { text: String(r.Path == null ? '' : r.Path), cls: 'cell-dim' }; } },
            { key: 'Status', label: 'STATUS', width: 220, render: function (r) { return statusCell(r.Status); } },
            { key: 'Detail', label: 'DETAIL', render: function (r) { return wrapCell(r.Detail); } }
          ]
        });
        var gh = el('div'); gh.style.cssText = 'flex:1;min-height:0;display:flex'; gh.appendChild(grid.el);
        results.appendChild(gh); right.appendChild(results);
        panel.appendChild(right);

        var openUnsub = null;   // audit 2026-07-23 deferred pass: a re-click must replace, not stack, its handler
        function doOpen() {
          var name = String(compIn.value || '').trim();
          if (!name) { setLine(statusLine, 'Enter a computer name first.', 'st-warn'); compIn.focus(); return; }
          setLine(statusLine, 'Opening \\\\' + name + '\\C$ ...', 'st-info');
          actlog.append({ text: '[' + ts() + '] Open C$ requested for ' + name, level: 'accent' });
          openBtn.disabled = true;
          var run = ctx.run('open-cshare', { computer: name }, { keyOf: function (ev) { return ev._rk; }, destructive: false });
          if (openUnsub) { var pi = subs.indexOf(openUnsub); if (pi >= 0) subs.splice(pi, 1); openUnsub(); }
          openUnsub = track(run.subscribe({
            status: function (t) { setLine(statusLine, t, 'st-info'); },
            row: function (r) { grid.upsert(r); },
            log: function (l) { actlog.append(l); },
            error: function (e) { setLine(statusLine, (e && e.text) || 'Error', 'st-bad'); actlog.append({ text: (e && e.text) || 'error', level: 'err' }); },
            active: function (a) { if (!a) openBtn.disabled = false; },
            final: function () { setLine(statusLine, 'Done.', 'st-ok'); }
          }));
        }
        openBtn.onclick = doOpen;
        compIn.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); doOpen(); } });
      }

      // ---- TAB 2: Run Script (DESTRUCTIVE) ----------------------------------
      function buildRunScript(panel) {
        panel.style.cssText = 'display:flex;gap:14px;height:100%;min-height:0;box-sizing:border-box;padding:12px';

        // LEFT: targets + options + run
        var left = el('div'); left.style.cssText = 'flex:0 0 400px;display:flex;flex-direction:column;gap:12px;min-height:0;overflow:auto';
        var compCard = ui.namedCard('TARGETS');
        compCard.style.cssText += ';flex:0 0 auto;display:flex;flex-direction:column';
        var targets = C.TargetManager({
          model: ctx.util.targetModel(''),
          // audit 2026-07-24: the '# starts a comment' hint advertised a syntax that does
          // NOT exist - the shared client host parser (shell.js parseHosts, not this
          // tool's to change) splits on whitespace, so '# lab row' handed the server the
          // live targets 'lab' and 'row' for an ARBITRARY remote script block. The claim
          // is removed rather than half-honoured; the server-side parser strips '#'
          // comments defensively for raw-text callers.
          hint: 'One host per line - comma/space/semicolon ok. No comment syntax: every word here is a TARGET.',
          placeholder: 'WS-0001\nWS-0002\nWS-0003',
          importLabel: 'Import TXT', importAccept: '.txt', countNoun: 'host',
          onImport: function (n, name) { actlog.append({ text: '[' + ts() + '] Added ' + n + ' host(s) from ' + name, level: 'info' }); }
        });
        var tgHolder = el('div'); tgHolder.style.cssText = 'flex:1;min-height:0;display:flex'; tgHolder.appendChild(targets.el);
        compCard.appendChild(tgHolder);
        left.appendChild(compCard);

        var optCard = ui.card({}); optCard.style.cssText += ';display:flex;flex-direction:column;gap:10px';
        var tRow = el('div'); tRow.style.cssText = 'display:flex;align-items:center;gap:10px;flex-wrap:wrap';
        tRow.appendChild(ui.label('Max concurrent:'));
        var threadsIn = ui.number({ value: 8, min: 1, max: 32, title: 'Parallel hosts (1-32).' }); threadsIn.style.width = '70px';
        tRow.appendChild(threadsIn);
        tRow.appendChild(ui.label('Timeout (s):'));
        var timeoutIn = ui.number({ value: 120, min: 15, max: 900, title: 'Per-host timeout in seconds (15-900). A host still running the block after this is abandoned as Timeout.' }); timeoutIn.style.width = '80px';
        tRow.appendChild(timeoutIn);
        optCard.appendChild(tRow);
        var statusLine = el('div', 'muted', 'Ready'); statusLine.style.fontSize = '12px';
        optCard.appendChild(statusLine);
        left.appendChild(optCard);

        var actCard = ui.card({}); actCard.style.cssText += ';display:flex;flex-direction:column;gap:8px';
        var runbar = C.RunBar({
          label: 'RUN SCRIPT', cancelLabel: 'CANCEL RUN', morphToCancel: true,
          title: 'DESTRUCTIVE: run your PowerShell block on every target over WinRM.',
          guards: [
            function () { return targets.count() ? null : 'No Hosts|Add at least one host to the list first.'; },
            function () { return String(scriptTa.value || '').trim() ? null : 'No Script|Type a PowerShell script block to run.'; },
            function () { return (ctx.session.state.credSet && ctx.session.state.ack) ? null : 'Admin Session Required|Run Script runs arbitrary remote code, so it needs a live admin session: Set Credentials AND Start Admin Session (top of the window) first.'; }
          ],
          onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
          onRun: doRun,
          onCancel: function () { if (curRun) { curRun.cancel(); actlog.append({ text: '[' + ts() + '] CANCEL requested - queued hosts skip; in-flight blocks are stopped.', level: 'warn' }); } }
        });
        var rbWrap = el('div'); rbWrap.appendChild(runbar.el); actCard.appendChild(rbWrap);
        left.appendChild(actCard);
        panel.appendChild(left);

        // RIGHT: script editor + stats + grid
        var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:12px;min-height:0';

        var scriptCard = ui.namedCard('POWERSHELL SCRIPT BLOCK', 'Runs verbatim on each target inside Invoke-Command. Output (all streams) is captured and shown per host, truncated at ~4000 chars.');
        scriptCard.style.cssText += ';display:flex;flex-direction:column;gap:6px;flex:0 0 auto';
        var scriptTa = ui.textarea({ placeholder: 'Get-Service -Name Spooler | Select-Object Status, StartType', rows: 8 });
        scriptTa.style.cssText += ';width:100%;font-family:var(--mono);font-size:12.5px';
        scriptCard.appendChild(scriptTa);
        right.appendChild(scriptCard);

        var stats = C.StatCards({ cards: [
          { key: 'hosts', label: 'HOSTS', color: 'cyan' },
          { key: 'ok', label: 'SUCCEEDED', color: 'ok' },
          { key: 'fail', label: 'FAILED', color: 'bad' }
        ] });
        right.appendChild(stats.el);

        var head = ui.card({}); head.style.cssText += ';display:flex;align-items:center;gap:12px;flex-wrap:wrap';
        var exportBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the result rows to CSV.' });
        var clearBtn = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the results grid.' });
        var spacer = el('div'); spacer.style.flex = '1'; head.appendChild(spacer);
        head.appendChild(exportBtn); head.appendChild(clearBtn);
        right.appendChild(head);

        var results = ui.namedCard('RUN RESULTS', 'One row per host: Online, Status, captured Output, and Error.');
        results.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
        var grid = C.ResultsGrid({
          title: 'RUN RESULTS', keyMode: { rk: true }, popOut: true, selectable: false,
          columns: [
            { key: 'Host', label: 'HOST', width: 150 },
            { key: 'Online', label: 'ONLINE', width: 80, render: function (r) { return onlineCell(r.Online); } },
            { key: 'Status', label: 'STATUS', width: 110, render: function (r) { return statusCell(r.Status); } },
            { key: 'Output', label: 'OUTPUT', render: function (r) { return wrapCell(r.Output); } },
            { key: 'Error', label: 'ERROR', width: 200, render: function (r) { return errCell(r.Error); } }
          ],
          rowClass: function (r) { var s = String(r.Status || '').toLowerCase(); if (s === 'failed') return 'row-bad'; if (s === 'offline' || s === 'timeout' || s === 'session error' || s === 'skipped') return 'row-warn'; return ''; }
        });
        var gh = el('div'); gh.style.cssText = 'flex:1;min-height:0;display:flex'; gh.appendChild(grid.el);
        results.appendChild(gh); right.appendChild(results);
        panel.appendChild(right);

        exportBtn.onclick = function () {
          var rows = grid.rows();
          if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Run a script first - there are no result rows yet.', okText: 'OK', cancelText: null }); return; }
          var cols = [['Host', 'Host'], ['Online', 'Online'], ['Status', 'Status'], ['Output', 'Output'], ['Error', 'Error']];
          ctx.util.exportCsv('RemoteAdmin_RunScript', cols, rows);
          actlog.append({ text: '[' + ts() + '] Exported ' + rows.length + ' row(s) to CSV.', level: 'info' });
        };
        clearBtn.onclick = function () { grid.clear(); stats.reset(); setLine(statusLine, 'Ready'); };

        var curRun = null, scriptUnsub = null;
        var counters = { hosts: {}, ok: 0, fail: 0 };
        var lockInputs = ctx.util.lockable([threadsIn, timeoutIn, clearBtn, scriptTa]);   // audit 2026-07-23 deferred pass: S3 lockInputs consolidation

        function doRun() {
          var hosts = targets.hosts();
          var scriptText = String(scriptTa.value || '').trim();
          var threads = intOr(threadsIn, 8);
          var timeoutSeconds = intOr(timeoutIn, 120);
          // audit 2026-07-24 (S2): this was ctx.confirm, which silently DROPPED the
          // confirmWord - the typed-RUN gate on fleet-wide arbitrary RCE never rendered.
          // Destructive actions must go through ctx.arm (ArmingDialog).
          ctx.arm({
            title: 'Run arbitrary PowerShell on ' + hosts.length + ' host(s)?',
            banner: 'ARBITRARY REMOTE CODE - RUNS WITH ADMIN RIGHTS ON EVERY TARGET',
            danger: true,
            confirmWord: 'RUN',
            body: 'You are about to run an <b>arbitrary PowerShell script block, with admin rights, on ' + hosts.length + ' target host(s)</b> over WinRM. This is <b>destructive</b> - JANET cannot preview or undo what your script does. The exact script body is recorded to the audit trail by SHA256 hash before it runs.<br><br>First few targets:',
            list: hosts.slice(0, 6),
            preflight: [
              { label: hosts.length + ' target host(s)', ok: hosts.length > 0 },
              { label: 'Admin credential set (' + (ctx.session.state.user || 'session') + ')', ok: !!ctx.session.state.credSet },
              { label: 'Script body is ' + scriptText.length + ' char(s) - JANET cannot preview or undo it', ok: false }
            ],
            okText: 'Run', cancelText: 'Cancel'
          }).then(function (ok) {
            if (!ok) { actlog.append({ text: '[' + ts() + '] Run cancelled at confirm.', level: 'warn' }); return; }
            grid.clear(); stats.reset();
            counters = { hosts: {}, ok: 0, fail: 0 };
            setLine(statusLine, 'Working...', 'st-info');
            actlog.banner ? actlog.banner('Run Script on ' + hosts.length + ' host(s)') : actlog.append({ text: '[' + ts() + '] Run Script on ' + hosts.length + ' host(s).', level: 'accent' });
            lockInputs(true);
            // confirm:'RUN' satisfies the server-side typed barrier (audit 2026-07-24 S2).
            // The ArmingDialog above is what actually validated the operator typed it.
            curRun = ctx.run('run-script', { targets: hosts.join('\n'), script: scriptText, threads: threads, timeoutSeconds: timeoutSeconds, confirm: 'RUN' }, { keyOf: function (ev) { return ev._rk; }, destructive: true });
            // audit 2026-07-23 deferred pass: a re-run must replace, not stack, its
            // handler - the stale copy shared the live `counters` and double-counted.
            if (scriptUnsub) { var pi = subs.indexOf(scriptUnsub); if (pi >= 0) subs.splice(pi, 1); scriptUnsub(); }
            scriptUnsub = track(curRun.subscribe({
              status: function (t) { setLine(statusLine, t, 'st-info'); },
              progress: function () {},
              row: function (r) {
                grid.upsert(r);
                var h = String(r.Host == null ? '' : r.Host); if (h) counters.hosts[h] = 1;
                var s = String(r.Status || '').toLowerCase();
                if (s === 'success') counters.ok++; else counters.fail++;
                stats.setAll({ hosts: Object.keys(counters.hosts).length, ok: counters.ok, fail: counters.fail });
              },
              log: function (l) { actlog.append(l); },
              error: function (e) { setLine(statusLine, (e && e.text) || 'Error', 'st-bad'); actlog.append({ text: (e && e.text) || 'error', level: 'err' }); },
              active: function (a) { runbar.setActive(a); if (!a) lockInputs(false); },
              final: function (res) {
                var s = (res && res.summary) || {};
                if (s.total != null) stats.setAll({ hosts: s.total, ok: (s.succeeded != null ? s.succeeded : counters.ok), fail: (s.failed != null ? s.failed : counters.fail) });
                setLine(statusLine, 'Done - ' + (s.succeeded != null ? s.succeeded : counters.ok) + ' ok, ' + (s.failed != null ? s.failed : counters.fail) + ' failed', (s.failed ? 'st-warn' : 'st-ok'));
              }
            }));
          });
        }
      }

      // ---- assemble: TabHost + bottom activity dock -------------------------
      var root = el('div'); root.style.cssText = 'display:flex;flex-direction:column;gap:12px;height:100%;min-height:0;padding:14px;box-sizing:border-box';
      var tabHolder = el('div'); tabHolder.style.cssText = 'flex:1;min-height:0;display:flex';
      var tabs = C.TabHost({
        rail: 'top',
        helpId: 'remoteadmin',
        tabs: [
          { id: 'opencshare', label: 'Open C$', build: buildOpenCShare },
          { id: 'runscript', label: 'Run Script', build: buildRunScript }
        ]
      });
      tabHolder.appendChild(tabs.el);
      root.appendChild(tabHolder);

      var logCard = ui.card({}); logCard.classList.add('j-logdock');
      logCard.appendChild(actlog.el);
      root.appendChild(logCard);

      actlog.append({ text: 'Remote Admin ready. Open C$ launches \\\\<computer>\\C$ in Explorer on your session (no admin session needed). Run Script fans a PowerShell block to your hosts over WinRM (destructive - needs an admin session, fully SHA256-audited).', level: 'accent' });

      host.appendChild(root);
      this._root = root;
      this._unsub = function () { subs.forEach(function (u) { try { u(); } catch (e) {} }); };
    }
  });
})();
