/* ============================================================================
   beta.view.js  -  Beta Lab (tool id: 'beta')
   ACTIVE FEATURE: C2C Quarantine Killer. Install a persistent SYSTEM watchdog
   scheduled task ("JANET C2C Quarantine Killer") on each host that deletes the
   recreated "C2C Quarantine" task every N minutes (default 90). A one-shot fleet
   delete would just come back; the watchdog self-heals it.

   STATUS  (action 'status')  - read-only; per host: is "C2C Quarantine" present,
                                is the watchdog installed. No admin session, no confirm.
   INSTALL (action 'install') - destructive; admin-gated + type-INSTALL arm dialog.
                                Registers the SYSTEM watchdog and runs it once now.
   REMOVE  (action 'remove')  - destructive; admin-gated + type-REMOVE arm dialog.
                                Unregisters the watchdog (undo).
   Single-frame layout (certdeploy idiom): left rail (targets + options + run bars),
   right results grid, shared activity log along the bottom. Credentials are UNIVERSAL
   (shell header) - this view renders no cred control.
   ========================================================================== */
(function () {
  'use strict';

  var HOST_RE = /^[A-Za-z0-9._-]+$/;
  var TASK_RE = /^[A-Za-z0-9 ._-]+$/;
  var EXPORT_COLS = [['Host', 'Host'], ['Ping', 'Ping'], ['Status', 'Status'], ['Watchdog', 'Watchdog'], ['Detail', 'Detail']];
  var OK = ['INSTALLED', 'UPDATED', 'REMOVED', 'CLEAN', 'NOT PRESENT'];
  var WARN = ['QUARANTINE PRESENT', 'OFFLINE', 'SKIPPED'];
  var BAD = ['FAILED', 'CHECK ERROR', 'Cancelled'];

  function statusCellCls(v) {
    var s = String(v == null ? '' : v);
    if (OK.indexOf(s) >= 0) return 'st-ok';
    if (WARN.indexOf(s) >= 0) return 'st-warn';
    if (BAD.indexOf(s) >= 0) return 'st-bad';
    if (s === 'Queued') return 'st-info';
    return '';
  }
  // Watchdog RUN-health (status action): green = confirmed running, red = installed but
  // not running, amber = installed-unproven, blank/muted = not installed / not applicable.
  function watchdogCellCls(v) {
    var s = String(v == null ? '' : v);
    if (s === 'HEALTHY' || s === 'RUNNING') return 'st-ok';
    if (s === 'DISABLED' || s === 'LAST FAILED') return 'st-bad';
    if (s === 'NEVER RAN') return 'st-warn';
    if (s === 'NOT INSTALLED') return 'st-warn';
    return '';
  }
  function statusRowCls(v) {
    var s = String(v == null ? '' : v);
    if (OK.indexOf(s) >= 0) return 'row-ok';
    if (WARN.indexOf(s) >= 0) return 'row-warn';
    if (BAD.indexOf(s) >= 0) return 'row-bad';
    return '';
  }

  JanetViews.register('beta', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;
      var run = null, unsub = null;
      function ts() { return ctx.util.clockStr(); }
      var esc = (ctx.util && ctx.util.esc) ? ctx.util.esc : function (s) { return String(s == null ? '' : s); };

      var actlog = C.ActivityLog({ title: 'ACTIVITY LOG', defaultName: 'Beta_C2CQuarantineKiller_ActivityLog' });

      var root = el('div'); root.style.cssText = 'display:flex;flex-direction:column;gap:12px;height:100%;min-height:0;padding:14px;box-sizing:border-box';
      var main = el('div'); main.style.cssText = 'display:flex;gap:14px;flex:1;min-height:0';

      // ---------- LEFT: targets + options + run bars ----------
      var left = el('div'); left.style.cssText = 'flex:0 0 400px;display:flex;flex-direction:column;gap:12px;min-height:0;overflow:auto';

      var tgtCard = ui.namedCard('TARGETS');
      tgtCard.style.cssText += ';flex:0 0 auto;display:flex;flex-direction:column';
      var targets = C.TargetManager({
        model: ctx.util.targetModel(''),
        hint: 'One host per line - comma/space/semicolon ok; # starts a comment. Install the watchdog on every affected machine.',
        placeholder: 'WS-0001\nWS-0002\n# lab row\nWS-0003',
        importLabel: 'Import TXT', importAccept: '.txt', countNoun: 'host',
        onImport: function (n, name) { actlog.append({ text: '[' + ts() + '] Added ' + n + ' host(s) from ' + name, level: 'info' }); }
      });
      var tgHolder = el('div'); tgHolder.style.cssText = 'flex:1;min-height:120px;display:flex'; tgHolder.appendChild(targets.el);
      tgtCard.appendChild(tgHolder);
      left.appendChild(tgtCard);

      // Options: target task name, interval, offline, threads
      var optCard = ui.card({}); optCard.style.cssText += ';display:flex;flex-direction:column;gap:10px';
      optCard.appendChild(ui.label('Target task to delete'));
      var taskInput = ui.input({ title: 'The scheduled task the watchdog deletes on each run. Deleted by name across all task folders. Letters, digits, space, dot, underscore, hyphen only.' });
      taskInput.value = 'C2C Quarantine'; taskInput.placeholder = 'C2C Quarantine'; taskInput.style.width = '100%';
      optCard.appendChild(taskInput);

      var intRow = el('div'); intRow.style.cssText = 'display:flex;align-items:center;gap:10px';
      intRow.appendChild(ui.label('Run every (minutes):'));
      var intIn = ui.number({ value: 90, min: 5, max: 1440, title: 'How often the watchdog runs (Install only). Default 90.' }); intIn.style.width = '90px';
      intRow.appendChild(intIn);
      optCard.appendChild(intRow);

      var offlineCb = ui.checkbox('Attempt even if offline (host unreachable)', { title: 'Proceed against a host that fails the TCP 5985/5986/445 reachability probe. Reachability is TCP-only - AFNET drops ICMP. A host answering only on 5986 uses WinRM-over-HTTPS.' });
      optCard.appendChild(offlineCb);

      var threadsRow = el('div'); threadsRow.style.cssText = 'display:flex;align-items:center;gap:10px';
      threadsRow.appendChild(ui.label('Max concurrent:'));
      var threadsIn = ui.number({ value: 16, min: 1, max: 32, title: 'Parallel hosts (Status 1-32; Install/Remove cap at 16).' }); threadsIn.style.width = '80px';
      threadsRow.appendChild(threadsIn);
      optCard.appendChild(threadsRow);

      var statusLine = el('div', 'muted', 'Ready'); statusLine.style.fontSize = '12px';
      optCard.appendChild(statusLine);
      left.appendChild(optCard);

      // Run bars: STATUS (read-only) + INSTALL + REMOVE (destructive)
      var actCard = ui.card({}); actCard.style.cssText += ';display:flex;flex-direction:column;gap:8px';
      function hostGuards(needCred) {
        var g = [
          function () { return targets.hosts().length ? null : 'No Hosts|Add at least one host to the list first.'; },
          function () { var bad = targets.hosts().filter(function (h) { return !HOST_RE.test(h); }); return bad.length ? ('Invalid Target Name|Not valid hostnames: ' + bad.slice(0, 5).map(esc).join(', ') + '.') : null; }
        ];
        if (needCred) g.push(function () { return ctx.session.state.credSet ? null : 'Admin session required|Set ADW credentials (top-right) and start an admin session first - this registers/removes a SYSTEM scheduled task on the target.'; });
        return g;
      }
      function guardFail(m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); }

      var statusRunbar = C.RunBar({
        label: 'CHECK STATUS', cancelLabel: 'CANCEL', morphToCancel: true,
        title: 'Read-only: report whether the target task and the watchdog are present per host (changes nothing).',
        guards: hostGuards(false), onGuardFail: guardFail, onRun: doStatus,
        onCancel: function () { if (run) { run.cancel(); actlog.append({ text: '[' + ts() + '] CANCEL requested.', level: 'warn' }); } }
      });
      var installRunbar = C.RunBar({
        label: 'INSTALL KILLER', cancelLabel: 'CANCEL INSTALL', morphToCancel: true,
        title: 'Destructive: register the SYSTEM watchdog (every N min) and run it once now. Needs an admin session.',
        guards: hostGuards(true), onGuardFail: guardFail, onRun: doInstall,
        onCancel: function () { if (run) { run.cancel(); actlog.append({ text: '[' + ts() + '] CANCEL requested.', level: 'warn' }); } }
      });
      var removeRunbar = C.RunBar({
        label: 'REMOVE KILLER', cancelLabel: 'CANCEL REMOVE', morphToCancel: true,
        title: 'Destructive: unregister the SYSTEM watchdog (undo). Needs an admin session.',
        guards: hostGuards(true), onGuardFail: guardFail, onRun: doRemove,
        onCancel: function () { if (run) { run.cancel(); actlog.append({ text: '[' + ts() + '] CANCEL requested.', level: 'warn' }); } }
      });
      var sw = el('div'); sw.appendChild(statusRunbar.el); actCard.appendChild(sw);
      var iw = el('div'); iw.appendChild(installRunbar.el); actCard.appendChild(iw);
      var rw = el('div'); rw.appendChild(removeRunbar.el); actCard.appendChild(rw);
      left.appendChild(actCard);
      main.appendChild(left);

      // ---------- RIGHT: stats + head + grid ----------
      var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:12px;min-height:0';
      var stats = C.StatCards({ cards: [
        { key: 'hosts', label: 'HOSTS', color: 'cyan' },
        { key: 'ok', label: 'INSTALLED / CLEAN', color: 'ok' },
        { key: 'attention', label: 'QUARANTINE / FAILED', color: 'gold' },
        { key: 'errors', label: 'OFFLINE / SKIPPED', color: 'accent' }
      ] });
      right.appendChild(stats.el);

      var head = ui.card({}); head.style.cssText += ';display:flex;align-items:center;gap:12px;flex-wrap:wrap';
      var exportBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the result rows to CSV.' });
      var clearBtn = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the results grid.' });
      var spacer = el('div'); spacer.style.flex = '1'; head.appendChild(spacer);
      head.appendChild(exportBtn); head.appendChild(clearBtn);
      right.appendChild(head);

      var results = ui.namedCard('C2C QUARANTINE KILLER RESULTS', 'One row per host. On a Status check the WATCHDOG column confirms it is actually running (HEALTHY / RUNNING = firing; NEVER RAN / DISABLED / LAST FAILED = installed but not running); Detail shows last run, result and next run.');
      results.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
      var grid = C.ResultsGrid({
        title: 'C2C Quarantine Killer results',
        emptyText: 'No results yet - add hosts, then Check Status, Install or Remove.',
        keyMode: { hostCol: 'Host' }, popOut: true, selectable: false,
        columns: [
          { key: 'Host', label: 'HOST', width: 150 },
          { key: 'Ping', label: 'PING', width: 90 },
          { key: 'Status', label: 'STATUS', width: 160, render: function (r) { return { text: r.Status == null ? '' : String(r.Status), cls: statusCellCls(r.Status) }; } },
          { key: 'Watchdog', label: 'WATCHDOG', width: 120, render: function (r) { var t = String(r.Watchdog == null ? '' : r.Watchdog); return { text: t, cls: watchdogCellCls(r.Watchdog), title: t ? ('Watchdog run-health: ' + t) : '' }; } },
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

      var logCard = ui.card({}); logCard.classList.add('j-logdock');
      logCard.appendChild(actlog.el);
      root.appendChild(logCard);

      // ---------- behaviour ----------
      function setStatus(txt, cls) { statusLine.textContent = txt == null ? '' : String(txt); statusLine.className = cls || 'muted'; }
      function isRunning() { return !!(run && run.state && run.state.active); }
      function threads() { var n = parseInt(threadsIn.value, 10); if (isNaN(n) || n < 1) n = 16; if (n > 32) n = 32; return n; }
      function interval() { var n = parseInt(intIn.value, 10); if (isNaN(n) || n < 5) n = 90; if (n > 1440) n = 1440; return n; }
      function lockInputs(on) {
        offlineCb._cb.disabled = on; threadsIn.disabled = on; clearBtn.disabled = on; taskInput.disabled = on; intIn.disabled = on;
      }
      clearBtn.onclick = function () { if (isRunning()) return; grid.clear(); prog.reset(); stats.reset(); setStatus('Ready'); };
      exportBtn.onclick = function () {
        var rows = grid.rows();
        if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Run Status, Install or Remove first - there are no result rows yet.', okText: 'OK', cancelText: null }); return; }
        var csv = ctx.util.toCsv(EXPORT_COLS.map(function (p) { return p[1]; }), rows, EXPORT_COLS.map(function (p) { return p[0]; }));
        ctx.util.downloadBlob('C2CQuarantineKiller_Results_' + ctx.util.fileStamp() + '.csv', 'text/csv', csv);
        actlog.append({ text: '[' + ts() + '] Exported ' + rows.length + ' row(s) to CSV.', level: 'info' });
      };

      function summarize() {
        var okC = 0, attn = 0, err = 0, total = 0;
        grid.rows().forEach(function (r) {
          var s = String(r.Status);
          if (s === 'Queued') return;
          total++;
          if (OK.indexOf(s) >= 0) okC++;
          else if (s === 'QUARANTINE PRESENT' || s === 'FAILED') attn++;
          else if (s === 'OFFLINE' || s === 'CHECK ERROR' || s === 'SKIPPED' || s === 'Cancelled') err++;
        });
        return { hosts: total, ok: okC, attention: attn, errors: err };
      }

      function bindRun(verb) {
        if (unsub) unsub();
        unsub = run.subscribe({
          status: function (t) { prog.setPhase(t); setStatus(t, (String(t) === 'error') ? 'st-bad' : 'st-info'); },
          progress: function (p) { prog.setProgress(p.done, p.total); setStatus('Running... ' + p.done + ' / ' + p.total + ' done', 'st-info'); },
          row: function (r) { grid.upsert(r); stats.setAll(summarize()); },
          log: function (l) { actlog.append(l); },
          error: function (e) { setStatus((e && e.text) || 'Error', 'st-bad'); actlog.append({ text: '[' + ts() + '] ' + ((e && e.text) || 'error'), level: 'err' }); },
          active: function (a) {
            statusRunbar.setActive(a); installRunbar.setActive(a); removeRunbar.setActive(a);
            if (!a) {
              lockInputs(false);
              var c = summarize(); stats.setAll(c);
              var bad = c.attention + c.errors;
              setStatus(verb + ' complete - ' + c.ok + ' ok, ' + c.attention + ' attention, ' + c.errors + ' offline/skipped', bad ? 'st-warn' : 'st-ok');
              actlog.append({ text: '[' + ts() + '] FINISHED ' + verb + '. OK=' + c.ok + '  ATTENTION=' + c.attention + '  OFFLINE/SKIPPED=' + c.errors, level: bad ? 'warn' : 'ok' });
            }
          }
        });
      }

      function startRun(action, params, destructive, verb, queueStatus) {
        var hosts = targets.hosts();
        grid.clear(); prog.reset(); stats.reset();
        hosts.forEach(function (h) { grid.upsert({ Host: h, Ping: '', Status: 'Queued', Detail: queueStatus }); });
        lockInputs(true);
        run = ctx.run(action, params, { keyOf: function (ev) { return ev.Host != null ? String(ev.Host) : null; }, destructive: destructive });
        bindRun(verb);
      }

      // ---- STATUS (read-only) ----
      function doStatus() {
        if (isRunning()) return;
        var task = String(taskInput.value || '').trim() || 'C2C Quarantine';
        actlog.append({ text: '[' + ts() + '] Check Status on ' + targets.hosts().length + " host(s) (target task '" + task + "').", level: 'accent' });
        startRun('status', {
          targets: targets.hosts().join('\n'),
          targetTask: task,
          attemptOffline: !!offlineCb._cb.checked,
          threads: threads()
        }, false, 'Status', 'Queued');
      }

      // ---- INSTALL (destructive; admin-gated + type-INSTALL arm dialog) ----
      async function doInstall() {
        if (isRunning()) return;
        var hosts = targets.hosts();
        var task = String(taskInput.value || '').trim() || 'C2C Quarantine';
        if (!TASK_RE.test(task)) { ctx.confirm({ title: 'Invalid task name', body: 'Target task name may only contain letters, digits, space, dot, underscore and hyphen (no quotes/semicolons) - it is embedded in a SYSTEM command.', okText: 'OK', cancelText: null }); return; }
        var mins = interval();
        var ok = await ctx.arm({
          title: 'Arm INSTALL QUARANTINE KILLER',
          banner: 'DESTRUCTIVE - REGISTERS A SYSTEM SCHEDULED TASK ON EACH HOST',
          body: 'About to register the SYSTEM watchdog <b>"JANET C2C Quarantine Killer"</b> on <b>' + hosts.length + ' host(s)</b> over WinRM.'
            + '<br>It runs as SYSTEM <b>every ' + mins + ' minute(s)</b> (and after a missed run at boot) and deletes the <b>' + esc(task) + '</b> scheduled task by name wherever it lives.'
            + '<br>It also runs <b>once now</b> so ' + esc(task) + ' is gone immediately.'
            + '<br>Re-installing on a host that already has it is an UPDATE. The JANET dispatcher host is self-guarded out of the run.',
          preflight: [
            { label: hosts.length + ' host(s) targeted', ok: true },
            { label: 'Deletes task: ' + task, ok: true },
            { label: 'Watchdog interval: every ' + mins + ' minute(s)', ok: true },
            { label: 'Runs as SYSTEM; fires once immediately', ok: true }
          ],
          confirmWord: 'INSTALL', okText: 'Install Killer', cancelText: 'Cancel'
        });
        if (!ok) { actlog.append({ text: '[' + ts() + '] Install cancelled at the arming dialog.', level: 'warn' }); return; }
        actlog.append({ text: '[' + ts() + '] Install Quarantine Killer on ' + hosts.length + ' host(s), every ' + mins + 'm, deleting "' + task + '".', level: 'accent' });
        startRun('install', {
          targets: hosts.join('\n'),
          targetTask: task,
          intervalMinutes: mins,
          confirm: 'INSTALL',
          attemptOffline: !!offlineCb._cb.checked,
          threads: threads()
        }, true, 'Install', 'Queued');
      }

      // ---- REMOVE (destructive; admin-gated + type-REMOVE arm dialog) ----
      async function doRemove() {
        if (isRunning()) return;
        var hosts = targets.hosts();
        var ok = await ctx.arm({
          title: 'Arm REMOVE QUARANTINE KILLER',
          banner: 'DESTRUCTIVE - UNREGISTERS THE SYSTEM WATCHDOG',
          body: 'About to unregister the SYSTEM watchdog <b>"JANET C2C Quarantine Killer"</b> from <b>' + hosts.length + ' host(s)</b> over WinRM.'
            + '<br>After this the <b>C2C Quarantine</b> task will no longer be auto-deleted on those hosts. This does not touch the C2C Quarantine task itself.'
            + '<br>The JANET dispatcher host is self-guarded out of the run.',
          preflight: [
            { label: hosts.length + ' host(s) targeted', ok: true },
            { label: 'Unregisters: JANET C2C Quarantine Killer', ok: true },
            { label: 'C2C Quarantine will no longer be auto-deleted', ok: true }
          ],
          confirmWord: 'REMOVE', okText: 'Remove Killer', cancelText: 'Cancel'
        });
        if (!ok) { actlog.append({ text: '[' + ts() + '] Remove cancelled at the arming dialog.', level: 'warn' }); return; }
        actlog.append({ text: '[' + ts() + '] Remove Quarantine Killer on ' + hosts.length + ' host(s).', level: 'accent' });
        startRun('remove', {
          targets: hosts.join('\n'),
          confirm: 'REMOVE',
          attemptOffline: !!offlineCb._cb.checked,
          threads: threads()
        }, true, 'Remove', 'Queued');
      }

      actlog.append({ text: 'Beta Lab - C2C Quarantine Killer. The "C2C Quarantine" task keeps coming back, so instead of a one-shot delete this installs a SYSTEM watchdog on each host that deletes it every 90 minutes (tunable) and once immediately. Check Status is read-only; Install/Remove need an admin session and a typed confirm word. Remove undoes the watchdog.', level: 'accent' });

      host.appendChild(root);
      this._root = root;
      this._unsub = function () { try { if (unsub) unsub(); } catch (e) {} };
    },
    unmount: function () { try { if (this._unsub) this._unsub(); } catch (e) {} if (this._root) this._root.remove(); }
  });
})();
