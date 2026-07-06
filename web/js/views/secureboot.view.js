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

  JanetViews.register('secureboot', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;
      var run = null, unsub = null;

      var card = ui.namedCard;

      var root = el('div'); root.style.cssText = 'display:flex;gap:14px;height:100%;min-height:0;padding:14px;box-sizing:border-box';

      // ---------- LEFT: TARGET MACHINES ----------
      var left = card('TARGET MACHINES', 'One hostname per line - up to 50.');
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
          function () { var bad = targets.hosts().filter(function (h) { return !HOST_RE.test(h); }); return bad.length ? ('Invalid Target Name|Not valid hostnames: ' + bad.slice(0, 5).join(', ') + '. Use only letters, digits, dot, hyphen, underscore.') : null; },
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
      this._root = root; this._unsub = function () { if (unsub) unsub(); };
    },
    unmount: function () { try { if (this._unsub) this._unsub(); } catch (e) {} if (this._root) this._root.remove(); }
  });
})();
