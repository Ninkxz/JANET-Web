/* ============================================================================
   winrmbridge.view.js  -  WinRM Bridge (tool id: 'winrmbridge')
   Stand up a TEMPORARY, self-reverting WinRM-over-HTTPS (5986) channel on hosts
   whose WinRM is GPO-blocked. Check (read-only) / Enable / Revert. Bootstraps over
   DCOM as a SYSTEM task that arms its own revert FIRST. Designed to run server-side
   under a SERVICE ACCOUNT with local admin on the targets. Enable/Revert are
   destructive: admin session + typed confirm (ENABLE / REVERT).
   ========================================================================== */
(function () {
  'use strict';

  var HOST_RE = /^[A-Za-z0-9._-]+$/;
  var EXPORT_COLS = [['Host', 'Host'], ['Ping', 'Ping'], ['State', 'State'], ['Reverts', 'Reverts'], ['Detail', 'Detail']];

  function stateOf(r) { return r.Status != null && r.Status !== '' ? String(r.Status) : String(r.Bridge == null ? '' : r.Bridge); }
  function stateCls(s) {
    s = String(s);
    if (s === 'ACTIVE' || s === 'BRIDGING') return 'st-info';
    if (s === 'REVERTING') return 'st-info';
    if (s === 'none') return 'st-ok';
    if (s === 'OFFLINE' || s === 'FAILED') return 'st-bad';
    if (s === 'SKIPPED' || s === 'LEFTOVER') return 'st-warn';
    return '';
  }

  JanetViews.register('winrmbridge', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;
      var run = null, unsub = null;
      var card = ui.namedCard;

      var root = el('div'); root.style.cssText = 'display:flex;flex-direction:column;gap:14px;height:100%;min-height:0;padding:14px;box-sizing:border-box';
      var workRow = el('div'); workRow.style.cssText = 'display:flex;gap:14px;flex:1;min-height:0';

      // LEFT: targets + settings
      var left = el('div'); left.style.cssText = 'flex:0 0 340px;display:flex;flex-direction:column;gap:12px;min-height:0';
      var tCard = card('TARGET HOSTS', 'One host per line. Enable/Revert bootstrap over DCOM (135/445) - no WinRM needed - so the service account must have LOCAL ADMIN on the targets.');
      tCard.style.cssText += ';flex:1;display:flex;flex-direction:column;min-height:0';
      var targets = C.TargetManager({ model: ctx.util.targetModel(''), hint: 'One host per line', importLabel: 'Import TXT/CSV' });
      var tgHolder = el('div'); tgHolder.style.cssText = 'flex:1;min-height:120px;display:flex'; tgHolder.appendChild(targets.el);
      tCard.appendChild(tgHolder);
      left.appendChild(tCard);

      var sCard = card('SETTINGS', 'The bridge auto-reverts on the target clock (below) AND at every startup. GPO stays authoritative; this is a stopgap.');
      var row1 = el('div'); row1.style.cssText = 'display:flex;gap:16px;flex-wrap:wrap;align-items:flex-end';
      var rmWrap = el('div'); rmWrap.appendChild(ui.label('Auto-revert after (min)'));
      var revMin = ui.number({ value: 90, min: 5, max: 1440, title: 'Minutes until the bridge self-reverts on the target (floor 5). Also reverts at every startup.' }); revMin.style.width = '90px';
      rmWrap.appendChild(revMin); row1.appendChild(rmWrap);
      var thWrap = el('div'); thWrap.appendChild(ui.label('Parallel hosts'));
      var threads = ui.number({ value: 8, min: 1, max: 32, title: 'Concurrent hosts.' }); threads.style.width = '80px';
      thWrap.appendChild(threads); row1.appendChild(thWrap);
      sCard.appendChild(row1);
      var cRow = el('div'); cRow.style.cssText = 'display:flex;gap:8px;align-items:center;margin-top:10px;flex-wrap:wrap';
      cRow.appendChild(ui.label('Confirm:'));
      var confirmInput = ui.input({ title: 'Type ENABLE to arm Enable, or REVERT to arm Revert (exactly).' });
      confirmInput.placeholder = 'ENABLE or REVERT'; confirmInput.style.width = '150px';
      cRow.appendChild(confirmInput);
      sCard.appendChild(cRow);
      var warn = el('div', 'muted', 'Enable / Revert are destructive and need a live admin session (a service account with local admin on the targets). Check is read-only.');
      warn.style.cssText = 'font-size:11px;line-height:1.4;margin-top:8px'; sCard.appendChild(warn);
      left.appendChild(sCard);
      workRow.appendChild(left);

      // RIGHT: actions + results
      var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:12px;min-height:0';
      var actionCard = ui.card({}); actionCard.style.cssText += ';display:flex;align-items:center;gap:10px;flex-wrap:wrap';
      var statusLine = el('span', 'muted', 'Ready'); statusLine.style.minWidth = '160px'; actionCard.appendChild(statusLine);
      var sp = el('div'); sp.style.flex = '1'; actionCard.appendChild(sp);
      var checkBtn = ui.button('CHECK STATE', { variant: 'cyan', size: 'sm', title: 'Read-only: probe 5985/5986 and report any JANET bridge + when it reverts.' });
      var enableBtn = ui.button('ENABLE BRIDGE', { variant: 'danger', size: 'sm', title: 'Push a temporary 5986 HTTPS listener (revert-first). Type ENABLE + admin session.' });
      var revertBtn = ui.button('REVERT (FORCE)', { variant: 'gold', size: 'sm', title: 'Force-remove the bridge now. Type REVERT + admin session.' });
      var exportBtn = ui.ghostButton('Export CSV', { size: 'sm' });
      var clearBtn = ui.ghostButton('Clear', { size: 'sm' });
      [checkBtn, enableBtn, revertBtn, exportBtn, clearBtn].forEach(function (b) { actionCard.appendChild(b); });
      right.appendChild(actionCard);

      var results = card('RESULTS'); results.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
      var grid = C.ResultsGrid({
        title: 'WinRM Bridge results', emptyText: 'No results yet - add hosts, then Check / Enable / Revert.',
        keyMode: { hostCol: 'Host' }, popOut: true,
        columns: [
          { key: 'Host', label: 'HOST', width: 150 },
          { key: 'Ping', label: 'PING', width: 90 },
          { key: 'State', label: 'STATE', width: 110, render: function (r) { var s = stateOf(r); return { text: s, cls: stateCls(s) }; } },
          { key: 'Reverts', label: 'REVERTS', width: 150, render: function (r) { return { text: r.Reverts == null ? '' : String(r.Reverts) }; } },
          { key: 'Detail', label: 'DETAIL', render: function (r) { var t = r.Detail == null ? '' : String(r.Detail); return { text: t, title: t }; } }
        ],
        rowClass: function (r) { var s = stateOf(r); if (s === 'OFFLINE' || s === 'FAILED') return 'row-bad'; if (s === 'SKIPPED' || s === 'LEFTOVER') return 'row-warn'; return ''; }
      });
      var gridHolder = el('div'); gridHolder.style.cssText = 'flex:1;min-height:0;display:flex'; gridHolder.appendChild(grid.el);
      results.appendChild(gridHolder);
      var prog = C.ProgressStatusStrip({ showCount: true }); prog.el.style.marginTop = '8px'; results.appendChild(prog.el);
      right.appendChild(results);
      workRow.appendChild(right);
      root.appendChild(workRow);

      var logCard = ui.card({}); logCard.classList.add('j-logdock');
      var actlog = C.ActivityLog({ title: 'ACTIVITY LOG', defaultName: 'WinRMBridge' });
      logCard.appendChild(actlog.el); root.appendChild(logCard);

      // behaviour
      function setStatus(t, cls) { statusLine.textContent = t == null ? '' : String(t); statusLine.className = cls || 'muted'; }
      function isRunning() { return !!(run && run.state && run.state.active); }
      var lockInputs = ctx.util.lockable([revMin, threads, confirmInput, checkBtn, enableBtn, revertBtn, clearBtn]);   // audit 2026-07-23 deferred pass: S3 lockInputs consolidation
      function validHosts() { var h = targets.hosts(); var bad = h.filter(function (x) { return !HOST_RE.test(x); }); return { hosts: h, bad: bad }; }

      clearBtn.onclick = function () { if (isRunning()) return; grid.clear(); prog.reset(); setStatus('Ready'); };
      exportBtn.onclick = function () {
        var rows = grid.rows(); if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Run an action first.', okText: 'OK', cancelText: null }); return; }
        var mapped = rows.map(function (r) { return { Host: r.Host, Ping: r.Ping, State: stateOf(r), Reverts: r.Reverts || '', Detail: r.Detail }; });
        ctx.util.exportCsv('WinRMBridge', EXPORT_COLS, mapped);
      };

      function preflight(needConfirmWord) {
        var v = validHosts();
        if (!v.hosts.length) { ctx.confirm({ title: 'No hosts', body: 'Add at least one target host.', okText: 'OK', cancelText: null }); return null; }
        if (v.bad.length) { ctx.confirm({ title: 'Invalid host name(s)', body: 'These entries are not valid host names:', list: v.bad.slice(0, 5), okText: 'OK', cancelText: null }); return null; }
        if (needConfirmWord) {
          if (!ctx.session.state.credSet) { ctx.confirm({ title: 'Admin session required', body: 'Set a service-account credential (top-right) and start an admin session - Enable/Revert change machines.', okText: 'OK', cancelText: null }); return null; }
          if (confirmInput.value !== needConfirmWord) { ctx.confirm({ title: 'Type ' + needConfirmWord, body: 'Type ' + needConfirmWord + ' (exactly) in Confirm to arm this action.', okText: 'OK', cancelText: null }); return null; }
        }
        return v.hosts;
      }

      function bindRun(verb) {
        if (unsub) unsub();
        unsub = run.subscribe({
          status: function (t) { setStatus(t, 'st-info'); prog.setPhase(t); },
          progress: function (p) { prog.setProgress(p.done, p.total); setStatus(verb + '... ' + p.done + ' / ' + p.total, 'st-info'); },
          row: function (r) { grid.upsert(r); },
          log: function (l) { actlog.append(l); },
          error: function (e) { setStatus((e && e.text) || 'error', 'st-bad'); if (e && e.text) actlog.append({ text: e.text, level: 'err' }); },
          active: function (a) { if (!a) { lockInputs(false); setStatus(verb + ' done - ' + grid.rows().length + ' host(s).', 'st-ok'); } }
        });
      }

      function startCheck() {
        if (isRunning()) return;
        var hosts = preflight(null); if (!hosts) return;
        grid.clear(); prog.reset(); lockInputs(true); setStatus('Checking...', 'st-info');
        run = ctx.run('check', { targets: hosts.join('\n'), threads: parseInt(threads.value, 10) || 16 }, { keyOf: function (ev) { return ev.Host != null ? String(ev.Host) : null; }, destructive: false });
        bindRun('Check');
      }
      async function startEnable() {
        if (isRunning()) return;
        var hosts = preflight('ENABLE'); if (!hosts) return;
        var mins = Math.max(5, parseInt(revMin.value, 10) || 90);
        var ok = await ctx.arm({
          title: 'Arm Enable WinRM Bridge', banner: 'DESTRUCTIVE - OPENS A TEMPORARY NETWORK LISTENER',
          body: 'About to open a temporary <b>5986 HTTPS</b> listener on <b>' + hosts.length + '</b> host(s) over DCOM. It arms a <b>self-revert first</b> (auto-reverts in <b>' + mins + ' min</b> and at every startup) then opens the listener + firewall rule. GPO stays authoritative.',
          preflight: [
            { label: hosts.length + ' host(s)', ok: true },
            { label: 'Service account has local admin on targets (DCOM)', ok: !!ctx.session.state.credSet },
            { label: 'Revert-first: auto-reverts in ' + mins + ' min + at startup', ok: true }
          ], okText: 'Enable Bridge', cancelText: 'Cancel'
        });
        if (!ok) { actlog.append({ text: 'Enable cancelled at arming.', level: 'warn' }); return; }
        grid.clear(); prog.reset(); lockInputs(true); setStatus('Enabling...', 'st-info');
        run = ctx.run('enable', { targets: hosts.join('\n'), revertMinutes: mins, confirm: confirmInput.value, threads: parseInt(threads.value, 10) || 8 }, { keyOf: function (ev) { return ev.Host != null ? String(ev.Host) : null; }, destructive: true });
        bindRun('Enable');
      }
      async function startRevert() {
        if (isRunning()) return;
        var hosts = preflight('REVERT'); if (!hosts) return;
        var ok = await ctx.arm({
          title: 'Arm Revert WinRM Bridge', banner: 'DESTRUCTIVE - REMOVES THE BRIDGE NOW',
          body: 'About to force-remove the WinRM Bridge on <b>' + hosts.length + '</b> host(s): listener + firewall rule + temp cert + tasks, over DCOM.',
          preflight: [{ label: hosts.length + ' host(s)', ok: true }, { label: 'Admin session', ok: !!ctx.session.state.credSet }], okText: 'Revert Now', cancelText: 'Cancel'
        });
        if (!ok) { actlog.append({ text: 'Revert cancelled at arming.', level: 'warn' }); return; }
        grid.clear(); prog.reset(); lockInputs(true); setStatus('Reverting...', 'st-info');
        run = ctx.run('revert', { targets: hosts.join('\n'), confirm: confirmInput.value, threads: parseInt(threads.value, 10) || 8 }, { keyOf: function (ev) { return ev.Host != null ? String(ev.Host) : null; }, destructive: true });
        bindRun('Revert');
      }

      checkBtn.onclick = startCheck;
      enableBtn.onclick = function () { startEnable(); };
      revertBtn.onclick = function () { startRevert(); };

      host.appendChild(root);
      this._root = root; this._unsub = function () { if (unsub) unsub(); };
    }
  });
})();
