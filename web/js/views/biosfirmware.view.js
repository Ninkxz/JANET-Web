/* ============================================================================
   biosfirmware.view.js  -  BIOS Firmware (tool id: 'biosfirmware')
   Read-only fleet BIOS firmware compliance. Left Targets card, right Settings /
   Action bar / Results. Scan reads Win32_BIOS over WinRM and scores each model
   Current/Outdated/Unknown against the per-model baseline (editable JanetLocal
   catalog). "List Baselines" shows the baseline currently in effect + its source.
   All runs go through ctx.run -> RunController. Credentials are universal (shell
   header), not per-tool; a read-only scan needs no admin session.
   ========================================================================== */
(function () {
  'use strict';

  var HOST_RE = /^[A-Za-z0-9._-]+$/;
  var MAX_HOSTS = 500;
  var EXPORT_COLS = [['Host', 'Host'], ['Manufacturer', 'Manufacturer'], ['Model', 'Model'],
    ['InstalledBIOS', 'InstalledBIOS'], ['TargetBIOS', 'TargetBIOS'], ['Status', 'Status'],
    ['BiosDate', 'BiosDate'], ['Error', 'Error']];

  function statusCellCls(v) {
    var s = String(v == null ? '' : v);
    if (s === 'Current') return 'st-ok';
    if (s === 'Outdated') return 'st-bad';
    if (s === 'Error') return 'st-bad';
    if (s.indexOf('Unknown') === 0 || s.indexOf('Parse') === 0 || s === 'Offline') return 'st-warn';
    return '';
  }

  JanetViews.register('biosfirmware', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;
      var run = null, unsub = null, blUnsub = null;

      var card = ui.namedCard;

      var root = el('div'); root.style.cssText = 'display:flex;flex-direction:column;gap:14px;height:100%;min-height:0;padding:14px;box-sizing:border-box';
      var workRow = el('div'); workRow.style.cssText = 'display:flex;gap:14px;flex:1;min-height:0';

      // ---------- LEFT: TARGET MACHINES ----------
      var left = card('TARGET MACHINES', 'One hostname per line.');
      left.style.cssText += ';flex:0 0 320px;display:flex;flex-direction:column;min-height:0';
      var targets = C.TargetManager({
        model: ctx.util.targetModel(''),
        hint: 'One hostname per line', importLabel: 'Import TXT/CSV'
      });
      var tgHolder = el('div'); tgHolder.style.cssText = 'flex:1;min-height:120px;display:flex'; tgHolder.appendChild(targets.el);
      left.appendChild(tgHolder);
      workRow.appendChild(left);

      // ---------- RIGHT column ----------
      var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:12px;min-height:0';

      // Settings card
      var settings = card('SETTINGS', 'Read-only scan - no firmware is written. Baseline = JanetLocal\\BiosFirmwareCatalog.json (falls back to the built-in default).');
      var setRows = el('div'); setRows.style.cssText = 'display:flex;flex-wrap:wrap;gap:18px;align-items:flex-end';
      var jobsWrap = el('div');
      jobsWrap.appendChild(ui.label('Parallel jobs'));
      var jobsInput = ui.number({ value: 16, min: 1, max: 32, title: 'Concurrent machines (1-32).' }); jobsInput.style.width = '90px';
      jobsWrap.appendChild(jobsInput);
      jobsWrap.appendChild((function () { var n = el('div', 'muted', 'Concurrent machines (1-32).'); n.style.fontSize = '11px'; return n; })());
      setRows.appendChild(jobsWrap);
      settings.appendChild(setRows);
      right.appendChild(settings);

      // Action bar
      var actionCard = ui.card({}); actionCard.style.cssText += ';display:flex;align-items:center;gap:14px;flex-wrap:wrap';
      var statusLine = el('span', 'muted', 'Ready'); statusLine.style.minWidth = '160px';
      actionCard.appendChild(statusLine);
      var spacer = el('div'); spacer.style.flex = '1'; actionCard.appendChild(spacer);
      var baselineBtn = ui.ghostButton('List Baselines', { size: 'sm', title: 'Show the per-model target-firmware baseline currently in effect and where it loaded from.' });
      var exportBtn = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the result rows to a CSV file.' });
      var clearBtn = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the results grid + reset progress.' });
      var ctaHolder = el('div'); ctaHolder.style.width = '240px';
      var runbar = C.RunBar({
        label: 'SCAN BIOS FIRMWARE', morphToCancel: false,
        title: 'Read-only WinRM scan of each host BIOS version, scored against the per-model baseline.',
        guards: [
          function () { return targets.count() ? null : 'Input Required|Enter at least one hostname.'; },
          function () { return targets.count() <= MAX_HOSTS ? null : ('Limit Exceeded|Maximum ' + MAX_HOSTS + ' machines per run; remove ' + (targets.count() - MAX_HOSTS) + ' and retry.'); },
          function () { var bad = targets.hosts().filter(function (h) { return !HOST_RE.test(h); }); return bad.length ? ('Invalid Target Name|Not valid hostnames: ' + bad.slice(0, 5).map(Janet.util.esc).join(', ') + '. Use only letters, digits, dot, hyphen, underscore.') : null; }
        ],
        onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
        onRun: doRun
      });
      ctaHolder.appendChild(runbar.el);
      actionCard.appendChild(baselineBtn); actionCard.appendChild(exportBtn); actionCard.appendChild(clearBtn); actionCard.appendChild(ctaHolder);
      right.appendChild(actionCard);

      // Results card (grid + progress track)
      var results = card('RESULTS');
      results.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
      var grid = C.ResultsGrid({
        title: 'BIOS firmware results',
        emptyText: 'No results yet — pick a host set, then Scan BIOS Firmware.',
        keyMode: { hostCol: 'Host' }, popOut: true,
        columns: [
          { key: 'Host', label: 'COMPUTER', width: 130 },
          { key: 'Manufacturer', label: 'MAKE', width: 90 },
          { key: 'Model', label: 'MODEL', width: 150 },
          { key: 'InstalledBIOS', label: 'INSTALLED', width: 90 },
          { key: 'TargetBIOS', label: 'TARGET', width: 90 },
          { key: 'Status', label: 'STATUS', width: 110, render: function (r) { return { text: r.Status == null ? '' : String(r.Status), cls: statusCellCls(r.Status) }; } },
          { key: 'BiosDate', label: 'BIOS DATE', width: 95 },
          { key: 'Error', label: 'ERROR / NOTES' }
        ],
        rowClass: function (r) {
          var s = String(r.Status);
          if (s === 'Current') return 'row-ok';
          if (s === 'Outdated' || s === 'Error') return 'row-bad';
          if (s.indexOf('Unknown') === 0 || s.indexOf('Parse') === 0 || s === 'Offline') return 'row-warn';
          return '';
        }
      });
      var gridHolder = el('div'); gridHolder.style.cssText = 'flex:1;min-height:0;display:flex'; gridHolder.appendChild(grid.el);
      results.appendChild(gridHolder);
      var prog = C.ProgressStatusStrip({ showCount: true });
      prog.el.style.marginTop = '8px';
      results.appendChild(prog.el);
      right.appendChild(results);

      workRow.appendChild(right);
      root.appendChild(workRow);

      // ---------- ACTIVITY LOG: full-width dock across the bottom (mirrors every other tool) ----------
      var logCard = ui.card({}); logCard.classList.add('j-logdock');
      var actlog = C.ActivityLog({ title: 'ACTIVITY LOG', defaultName: 'BiosFirmware' });
      logCard.appendChild(actlog.el);
      root.appendChild(logCard);

      // ---------- behaviour ----------
      function setStatus(txt, cls) { statusLine.textContent = txt == null ? '' : String(txt); statusLine.className = cls || 'muted'; }
      function lockInputs(on) { jobsInput.disabled = on; clearBtn.disabled = on; baselineBtn.disabled = on; }
      clearBtn.onclick = function () { if (run && run.state && run.state.active) return; grid.clear(); prog.reset(); setStatus('Ready'); };
      exportBtn.onclick = function () {
        var rows = grid.rows();
        if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Run a scan first - there are no result rows yet.', okText: 'OK', cancelText: null }); return; }
        ctx.util.exportCsv('BiosFirmware_Results', EXPORT_COLS, rows);
      };

      // List Baselines: run the read-only action, collect the Model->Target rows,
      // show them (with the catalog source) in a dialog - keeps the host-keyed grid clean.
      baselineBtn.onclick = function () {
        if (run && run.state && run.state.active) return;
        var blRows = [], src = '';
        var r2 = ctx.run('list-baselines', {});
        if (blUnsub) blUnsub();
        blUnsub = r2.subscribe({
          status: function (t) { if (t && t.indexOf('Baseline source:') === 0) src = t.replace('Baseline source:', '').trim(); },
          row: function (r) { blRows.push(r); },
          log: function (l) { actlog.append(l); },
          final: function () {
            blRows.sort(function (a, b) { return String(a.Model).localeCompare(String(b.Model)); });
            var list = blRows.map(function (r) { return Janet.util.esc(String(r.Model)) + ' &rarr; <b>' + Janet.util.esc(String(r.TargetBIOS)) + '</b>'; }).join('<br>');
            ctx.confirm({
              title: 'BIOS Baselines (' + blRows.length + ' models)',
              body: '<div class="muted" style="margin-bottom:8px">Source: ' + Janet.util.esc(src || '(unknown)') + '</div><div style="max-height:50vh;overflow:auto;font-size:12px;line-height:1.7">' + (list || '(no baselines)') + '</div>',
              okText: 'OK', cancelText: null
            });
          }
        });
      };

      function summarize() {
        var c = { Current: 0, Outdated: 0, Unknown: 0, Error: 0, Offline: 0 };
        grid.rows().forEach(function (r) {
          var s = String(r.Status);
          if (s === 'Current') c.Current++;
          else if (s === 'Outdated') c.Outdated++;
          else if (s === 'Error') c.Error++;
          else if (s === 'Offline') c.Offline++;
          else c.Unknown++;
        });
        return c;
      }

      async function doRun() {
        grid.clear(); prog.reset();
        setStatus('Starting scan of ' + targets.count() + ' target(s)...', 'st-info');
        lockInputs(true);
        var threads = Math.max(1, Math.min(32, parseInt(jobsInput.value, 10) || 16));
        run = ctx.run('scan-bios', { targets: targets.hosts().join('\n'), threads: threads });
        if (unsub) unsub();
        unsub = run.subscribe({
          status: function (t) { setStatus(t, 'st-info'); prog.setPhase(t); },
          progress: function (p) { prog.setProgress(p.done, p.total); setStatus('Scanning... ' + p.done + ' / ' + p.total + ' done', 'st-info'); },
          row: function (r) { grid.upsert(r); },
          log: function (l) { actlog.append(l); },
          error: function (e) { setStatus(e.text || 'Scan error', 'st-bad'); if (actlog) actlog.append({ text: e.text, level: 'err' }); },
          active: function (a) {
            runbar.setActive(a);
            runbar.cta.textContent = a ? 'SCANNING...' : 'SCAN BIOS FIRMWARE';
            if (!a) lockInputs(false);
          },
          final: function () {
            var c = summarize();
            var anyBad = (c.Outdated + c.Error) > 0;
            var total = grid.rows().length;
            var withData = c.Current + c.Outdated;
            var pct = withData > 0 ? Math.round(c.Current / withData * 100) : 0;
            setStatus('Done - ' + c.Current + ' current, ' + c.Outdated + ' outdated, ' + c.Unknown + ' unknown, ' + (c.Error + c.Offline) + ' error/offline.', anyBad ? 'st-warn' : 'st-ok');
            ctx.confirm({
              title: 'BIOS Firmware - Scan Complete',
              body: 'Current: <b>' + c.Current + '</b><br>Outdated: <b>' + c.Outdated + '</b><br>Unknown (no baseline / parse): <b>' + c.Unknown + '</b><br>Error / offline: <b>' + (c.Error + c.Offline) + '</b><br>Total: <b>' + total + '</b><br><br>Measured compliance: <b>' + pct + '%</b> (current / models with a baseline + data)',
              okText: 'OK', cancelText: null
            });
          }
        });
      }

      host.appendChild(root);
      this._root = root; this._unsub = function () { if (unsub) unsub(); if (blUnsub) blUnsub(); };
    }
  });
})();
