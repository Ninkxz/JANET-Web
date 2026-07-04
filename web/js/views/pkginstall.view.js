/* ============================================================================
   pkginstall.view.js  -  Remote Package Installer (tool id: 'pkginstall')
   Faithful single-window (non-tabbed) re-build per docs/ui-specs/pkginstall.md:
   a left Target Workstations card over a right column of Package Source / Action
   bar / Deployment Results / Execution Log cards (dark purple/gold theme). The
   live "activity run" IS the point: Deploy fans out one runspace-per-host and
   results stream back into a colour-coded ResultsGrid keyed by HOST that mutates
   each row through its lifecycle (Queued -> Probing -> Copying -> Deploying ->
   Success/Failed/Deferred), a sidebar Success/Failed StatCards tally, a Progress
   strip, and an Execution Log. The gold Deploy CTA morphs to CANCEL mid-run.

   Two deploy modes (one card, a toggle): PSADT package (action 'deploy-psadt')
   and MSI bundle (action 'deploy-msi-bundle'). The package/MSI dropdowns are the
   ONLY non-run server I/O: read-only helper GETs via ctx.api
   (GET /tool/pkginstall/packages?kind=..., GET /tool/pkginstall/msis?path=...).
   Every actual deploy/export goes through ctx.run -> RunController. Credentials
   are universal (shell header) - this view only reads ctx.session.state.credSet.
   ========================================================================== */
(function () {
  'use strict';

  var EXPORT_COLS = ['Host', 'Status', 'Detail', 'ExitCode', 'Time'];

  // Engine streams one row per HOST that mutates through its lifecycle; phase
  // values ('Probing','Repairing','Copying','Deploying') and terminal values
  // ('Success','Failed','Deferred','Skipped','Rejected','Queued') all arrive as
  // Status on the SAME Host key. Colour is hand-written per status (never regex).
  function statusCellCls(v) {
    switch (String(v)) {
      case 'Success': return 'st-ok';
      case 'Failed': return 'st-bad';
      case 'Rejected': return 'st-bad';
      case 'Deferred': return 'st-warn';
      case 'Repairing': return 'st-warn';
      case 'Deploying': return 'st-warn';
      case 'Copying': return 'st-info';
      case 'Skipped': return 'st-info';
      case 'Probing': return 'cell-dim';
      case 'Queued': return 'cell-dim';
      default: return '';
    }
  }
  function rowClassFor(v) {
    switch (String(v)) {
      case 'Success': return 'row-ok';
      case 'Skipped': return 'row-ok';
      case 'Failed': return 'row-bad';
      case 'Rejected': return 'row-bad';
      case 'Deferred': return 'row-warn';
      default: return '';        // in-flight phases stay neutral
    }
  }
  function isTerminal(v) {
    var s = String(v);
    return s === 'Success' || s === 'Failed' || s === 'Deferred' || s === 'Skipped' || s === 'Rejected';
  }

  JanetViews.register('pkginstall', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;

      // ---- run/result state (mirrors the desktop $script: state) ----
      var mode = 'psadt';               // 'psadt' | 'msi'
      var packages = [];                // [{name,path,detail}] from the helper GET
      var msiItems = [];                // [{rel, checked}] for the MSI checklist
      var run = null, unsub = null;
      var stat = { ok: 0, fail: 0, deferred: 0, skipped: 0, total: 0 };

      var card = ui.namedCard;
      var esc = Janet.util.esc;

      // =================== layout ===================
      // root is a vertical column: the horizontal work content rides in workRow,
      // and the Execution Log docks full-width across the bottom below it.
      var root = el('div'); root.style.cssText = 'display:flex;flex-direction:column;height:100%;min-height:0;background:var(--bg)';
      var workRow = el('div'); workRow.style.cssText = 'display:flex;gap:14px;flex:1;min-height:0;padding:14px;box-sizing:border-box';

      // ---------- LEFT: TARGET WORKSTATIONS ----------
      var left = card('TARGET WORKSTATIONS', 'One host per line or comma-separated. Retry Failed re-loads failed hosts here.');
      left.style.cssText += ';flex:0 0 320px;display:flex;flex-direction:column;min-height:0';
      var targets = C.TargetManager({
        model: ctx.util.targetModel(''),
        hint: 'Hostnames, comma or newline separated',
        importLabel: 'Import TXT',
        importAccept: '.txt,.csv,.tsv',
        countNoun: 'target',
        onImport: function (n, name) { log.append({ text: 'Imported ' + n + ' host(s) from ' + name, level: 'info' }); }
      });
      var tgHolder = el('div'); tgHolder.style.cssText = 'flex:1;min-height:120px;display:flex'; tgHolder.appendChild(targets.el);
      left.appendChild(tgHolder);
      workRow.appendChild(left);

      // ---------- RIGHT column ----------
      var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:12px;min-height:0';

      // ===== Package Source card =====
      var pkgCard = card('PACKAGE SOURCE');

      // mode toggle (PSADT package vs MSI bundle) -> selects which manifest action runs
      var modeRow = el('div'); modeRow.style.cssText = 'display:flex;gap:8px;margin-bottom:10px';
      var btnPsadt = ui.button('PSADT Package', { variant: 'gold', size: 'sm', title: 'Deploy a folder with Deploy-Application.ps1 (action: deploy-psadt).' });
      var btnMsi = ui.ghostButton('MSI Bundle', { size: 'sm', title: 'Deploy selected .msi files from a bundle folder via msiexec (action: deploy-msi-bundle).' });
      modeRow.appendChild(btnPsadt); modeRow.appendChild(btnMsi);
      pkgCard.appendChild(modeRow);

      // package dropdown + refresh
      var pkgRow = el('div'); pkgRow.style.cssText = 'display:flex;align-items:flex-end;gap:8px;flex-wrap:wrap';
      var pkgSelect = ui.select({ options: [{ value: '', label: '(loading packages...)' }], value: '', onChange: onPkgSelect });
      pkgSelect.style.minWidth = '320px';
      var refreshBtn = ui.button('Refresh', { variant: 'cyan', size: 'sm', title: 'Re-scan the packages folder for newly added packages/bundles.' });
      pkgRow.appendChild(ui.field('Package', pkgSelect));
      pkgRow.appendChild(refreshBtn);
      pkgCard.appendChild(pkgRow);
      var pkgRootNote = el('div', 'muted'); pkgRootNote.style.cssText = 'font-size:11px;margin-top:4px';
      pkgRootNote.textContent = 'Packages folder: (scanning...)';
      pkgCard.appendChild(pkgRootNote);

      // resolved-path echo
      var pkgEcho = el('div', 'muted'); pkgEcho.style.cssText = 'font-family:var(--mono);font-size:11.5px;margin-top:6px';
      pkgEcho.textContent = '// no package selected';
      pkgCard.appendChild(pkgEcho);

      // custom path override
      var customWrap = el('div'); customWrap.style.cssText = 'margin-top:10px';
      var customInput = ui.input({ placeholder: '\\\\server\\share\\Package  (overrides the dropdown when filled)', title: 'A custom UNC/local package path. When non-empty it overrides the dropdown selection.' });
      customWrap.appendChild(ui.field('Custom package path (optional)', customInput));
      pkgCard.appendChild(customWrap);
      customInput.addEventListener('input', refreshMsiChecklist);

      // package display name (audit/display)
      var nameInput = ui.input({ placeholder: 'blank = folder name', title: 'Display/audit name for this deployment. Blank uses the package folder name.' });
      var nameWrap = el('div'); nameWrap.style.cssText = 'margin-top:8px'; nameWrap.appendChild(ui.field('Package name (audit/display)', nameInput));
      pkgCard.appendChild(nameWrap);

      // ----- MSI-mode extras (checklist + msiexec args) -----
      var msiBox = el('div'); msiBox.style.cssText = 'margin-top:10px;display:none';
      msiBox.appendChild(ui.eyebrow('MSIs TO INSTALL (check the .msi files to deploy)'));
      var msiListWrap = el('div'); msiListWrap.style.cssText = 'max-height:140px;overflow:auto;border:1px solid var(--edge);border-radius:2px;background:var(--input);padding:4px 2px;margin:4px 0';
      msiBox.appendChild(msiListWrap);
      var msiSelRow = el('div'); msiSelRow.style.cssText = 'display:flex;gap:6px;align-items:center;margin-bottom:8px';
      var msiAll = ui.ghostButton('Check All', { size: 'sm' }); msiAll.onclick = function () { setAllMsi(true); };
      var msiNone = ui.ghostButton('Uncheck All', { size: 'sm' }); msiNone.onclick = function () { setAllMsi(false); };
      var msiCount = el('span', 'muted'); msiCount.style.fontSize = '11px';
      msiSelRow.appendChild(msiAll); msiSelRow.appendChild(msiNone); msiSelRow.appendChild(msiCount);
      msiBox.appendChild(msiSelRow);
      var msiArgsInput = ui.input({ value: '/qn /norestart', title: 'msiexec arguments appended after /i and /L*v. Must not contain a double-quote.' });
      msiBox.appendChild(ui.field('msiexec arguments', msiArgsInput));
      pkgCard.appendChild(msiBox);

      right.appendChild(pkgCard);

      // ===== Action bar =====
      var actionCard = ui.card({}); actionCard.style.cssText += ';display:flex;align-items:center;gap:14px;flex-wrap:wrap';
      // PARALLEL
      var parWrap = el('div');
      parWrap.appendChild(ui.eyebrow('PARALLEL HOSTS'));
      var threadsInput = ui.number({ value: 8, min: 1, max: 32, title: 'Concurrent hosts (1-32).' }); threadsInput.style.width = '90px';
      parWrap.appendChild(threadsInput);
      actionCard.appendChild(parWrap);

      var statusLine = el('span', 'muted', 'Ready'); statusLine.style.minWidth = '160px';
      actionCard.appendChild(statusLine);

      var spacer = el('div'); spacer.style.flex = '1'; actionCard.appendChild(spacer);

      var exportBtn = ui.ghostButton('Export Results', { size: 'sm', title: 'Export the result grid to a CSV file.' });
      exportBtn.disabled = true; exportBtn.onclick = doExport;
      var retryBtn = ui.button('Retry Failed', { variant: 'gold', size: 'sm', title: 'Load the FAILED hosts back into the target list and re-run.' });
      retryBtn.disabled = true; retryBtn.onclick = doRetryFailed;
      var ctaHolder = el('div'); ctaHolder.style.width = '260px';
      var runbar = C.RunBar({
        label: 'DEPLOY', cancelLabel: 'CANCEL DEPLOY', morphToCancel: true,
        title: 'Push and install the package to every target in parallel.',
        guards: [
          function () { return targets.count() ? null : 'No Targets|Add at least one hostname to the target list.'; },
          function () { return ctx.session.state.credSet ? null : 'No Credentials|Set your ADW credential (Set Credentials, top-right) before deploying. Deploying installs software on remote machines, so an admin session is required.'; },
          function () { return resolvedPkgPath() ? null : 'No Package|Pick a package from the dropdown, or type a custom package path.'; },
          function () { if (mode !== 'msi') return null; return checkedMsis().length ? null : 'No MSIs Selected|Check at least one .msi to install (or pick a bundle with MSIs in it).'; },
          function () { if (mode !== 'msi') return null; return /"/.test(msiArgsInput.value || '') ? 'Bad msiexec Arguments|msiexec arguments must not contain a double-quote (") - it would break the /i and /L*v quoting.' : null; }
        ],
        onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
        onRun: doDeploy,
        onCancel: function () { if (run) { run.cancel(); log.append({ text: 'CANCEL requested - watching stops; never-dispatched hosts are skipped, in-flight hosts finish.', level: 'warn' }); } }
      });
      ctaHolder.appendChild(runbar.el);
      actionCard.appendChild(exportBtn); actionCard.appendChild(retryBtn); actionCard.appendChild(ctaHolder);
      right.appendChild(actionCard);

      // ===== Deployment Results (grid) =====
      var resultsCard = card('DEPLOYMENT RESULTS', 'One row per host - mutates Queued -> Probing -> Copying -> Deploying -> Success/Failed. Double-click a row for full stdout.');
      resultsCard.style.cssText += ';flex:1 1 50%;min-height:160px;display:flex;flex-direction:column';
      var grid = C.ResultsGrid({
        title: 'Deployment results', keyMode: { hostCol: 'Host' }, popOut: true,
        columns: [
          { key: 'Host', label: 'HOST', width: 180 },
          { key: 'Status', label: 'STATUS', width: 110, render: function (r) { return { text: r.Status == null ? '' : String(r.Status), cls: statusCellCls(r.Status) }; } },
          { key: 'Detail', label: 'DETAIL' },
          { key: 'ExitCode', label: 'EXIT', width: 70 },
          { key: 'Time', label: 'TIME', width: 90 }
        ],
        rowClass: function (r) { return rowClassFor(r.Status); }
      });
      var gridHolder = el('div'); gridHolder.style.cssText = 'flex:1;min-height:0;display:flex'; gridHolder.appendChild(grid.el);
      resultsCard.appendChild(gridHolder);
      // sidebar tally + progress
      var tallyRow = el('div'); tallyRow.style.cssText = 'display:flex;align-items:center;gap:14px;margin-top:8px;flex-wrap:wrap';
      var stats = C.StatCards({ cards: [
        { key: 'ok', label: 'SUCCESS', color: 'ok' },
        { key: 'fail', label: 'FAILED', color: 'bad' },
        { key: 'deferred', label: 'DEFERRED', color: 'gold' },
        { key: 'skipped', label: 'SKIPPED', color: 'cyan' },
        { key: 'total', label: 'TOTAL', color: 'accent' }
      ] });
      tallyRow.appendChild(stats.el);
      var progHolder = el('div'); progHolder.style.cssText = 'flex:1;min-width:200px';
      var prog = C.ProgressStatusStrip({ showCount: true });
      progHolder.appendChild(prog.el);
      tallyRow.appendChild(progHolder);
      resultsCard.appendChild(tallyRow);
      right.appendChild(resultsCard);

      workRow.appendChild(right);
      root.appendChild(workRow);

      // ===== Execution Log (full-width bottom dock, was boxed in the right column) =====
      var logCard = ui.card({}); logCard.classList.add('j-logdock'); logCard.style.cssText += ';margin:0 16px 14px';
      var log = C.ActivityLog({ title: 'EXECUTION LOG', defaultName: 'RPI_ExecutionLog' });
      logCard.appendChild(log.el);
      root.appendChild(logCard);

      // =================== helpers ===================
      function setStatus(txt, cls) { statusLine.textContent = txt == null ? '' : String(txt); statusLine.className = cls || 'muted'; }
      function pushStats() { stats.setAll({ ok: stat.ok, fail: stat.fail, deferred: stat.deferred, skipped: stat.skipped, total: stat.total }); }
      function resetTally(total) { stat = { ok: 0, fail: 0, deferred: 0, skipped: 0, total: total || 0 }; pushStats(); prog.reset(); }

      function selectedPkg() {
        var v = pkgSelect.value;
        for (var i = 0; i < packages.length; i++) { if (packages[i].path === v) return packages[i]; }
        return null;
      }
      function resolvedPkgPath() {
        var custom = (customInput.value || '').trim();
        if (custom) return custom;
        var p = selectedPkg();
        return p ? p.path : '';
      }
      function onPkgSelect() {
        var p = selectedPkg();
        if (p) pkgEcho.textContent = '// ' + p.path + '  (' + (p.detail || '') + ')';
        else pkgEcho.textContent = '// no package selected';
        refreshMsiChecklist();
      }

      // ----- MSI checklist -----
      function checkedMsis() { return msiItems.filter(function (m) { return m.checked; }).map(function (m) { return m.rel; }); }
      function setAllMsi(on) { msiItems.forEach(function (m) { m.checked = on; }); renderMsiList(); }
      function renderMsiList() {
        msiListWrap.innerHTML = '';
        if (!msiItems.length) {
          var none = el('div', 'muted', mode === 'msi' ? (resolvedPkgPath() ? 'No .msi files found in the selected bundle.' : 'Pick a bundle to list its .msi files.') : '');
          none.style.cssText = 'font-size:11px;padding:6px 8px';
          msiListWrap.appendChild(none);
        } else {
          msiItems.forEach(function (m, i) {
            var rowCb = ui.checkbox(m.rel, { checked: m.checked, onChange: function () { msiItems[i].checked = rowCb._cb.checked; updateMsiCount(); } });
            rowCb.style.cssText = 'display:flex;padding:2px 8px;font-family:var(--mono);font-size:12px';
            msiListWrap.appendChild(rowCb);
          });
        }
        updateMsiCount();
      }
      function updateMsiCount() { msiCount.textContent = checkedMsis().length + ' / ' + msiItems.length + ' selected'; }

      // ----- read-only helper GETs (the ONLY non-run server I/O) -----
      function loadPackages() {
        pkgSelect.innerHTML = ''; pkgSelect.appendChild(new Option('(loading...)', ''));
        ctx.api('GET', '/tool/pkginstall/packages?kind=' + (mode === 'msi' ? 'msi' : 'psadt')).then(function (res) {
          packages = (res && res.packages) || [];
          pkgRootNote.textContent = 'Packages folder: ' + ((res && res.root) || '(unknown)');
          pkgSelect.innerHTML = '';
          if (!packages.length) {
            pkgSelect.appendChild(new Option(mode === 'msi' ? '(no MSI bundles found)' : '(no PSADT packages found)', ''));
          } else {
            pkgSelect.appendChild(new Option('(select a ' + (mode === 'msi' ? 'bundle' : 'package') + ')', ''));
            packages.forEach(function (p) { pkgSelect.appendChild(new Option(p.name + '  -  ' + (p.detail || ''), p.path)); });
          }
          onPkgSelect();
        }).catch(function (e) {
          pkgSelect.innerHTML = ''; pkgSelect.appendChild(new Option('(failed to list packages)', ''));
          pkgRootNote.textContent = 'Packages folder: (enumeration failed)';
          log.append({ text: 'Could not list packages: ' + (e && e.message || e), level: 'err' });
        });
      }
      function refreshMsiChecklist() {
        if (mode !== 'msi') { msiItems = []; return; }
        var path = resolvedPkgPath();
        if (!path) { msiItems = []; renderMsiList(); return; }
        msiItems = []; renderMsiList();
        msiCount.textContent = 'scanning bundle...';
        ctx.api('GET', '/tool/pkginstall/msis?path=' + encodeURIComponent(path)).then(function (res) {
          var msis = (res && res.msis) || [];
          msiItems = msis.map(function (rel) { return { rel: rel, checked: true }; });   // all checked by default
          renderMsiList();
        }).catch(function (e) {
          msiItems = []; renderMsiList();
          log.append({ text: 'Could not list MSIs in bundle: ' + (e && e.message || e), level: 'err' });
        });
      }

      // ----- mode switch -----
      function setMode(m) {
        if (m === mode) return;
        mode = m;
        styleModeButtons();
        msiBox.style.display = (m === 'msi') ? 'block' : 'none';
        loadPackages();   // re-list for the new kind (re-runs the MSI checklist via onPkgSelect)
      }
      function styleModeButtons() {
        // reflect active mode using the existing themed button classes
        var active = ui.button('x', { variant: 'gold', size: 'sm' }).className;
        var inactive = ui.ghostButton('x', { size: 'sm' }).className;
        btnPsadt.className = (mode === 'psadt') ? active : inactive;
        btnMsi.className = (mode === 'msi') ? active : inactive;
      }
      btnPsadt.onclick = function () { setMode('psadt'); };
      btnMsi.onclick = function () { setMode('msi'); };
      refreshBtn.onclick = function () { loadPackages(); if (mode === 'msi') refreshMsiChecklist(); };

      function lockInputs(on) {
        pkgSelect.disabled = on; refreshBtn.disabled = on; customInput.disabled = on; nameInput.disabled = on;
        threadsInput.disabled = on; btnPsadt.disabled = on; btnMsi.disabled = on;
        msiArgsInput.disabled = on; msiAll.disabled = on; msiNone.disabled = on;
        retryBtn.disabled = on || !hasFailed();
      }
      function hasFailed() { return grid.rows().some(function (r) { return String(r.Status) === 'Failed' || String(r.Status) === 'Rejected'; }); }
      function refreshActionButtons() {
        exportBtn.disabled = !grid.rows().length;
        retryBtn.disabled = !hasFailed();
      }

      // ===================== RUN =====================
      function doDeploy() {
        var hosts = targets.hosts();
        var pkgPath = resolvedPkgPath();
        var pkgName = (nameInput.value || '').trim();
        var threads = Math.max(1, Math.min(32, parseInt(threadsInput.value, 10) || 8));
        var msis = checkedMsis();
        var pkgLabel = pkgName || (selectedPkg() ? selectedPkg().name : pkgPath.replace(/[\\/]+$/, '').split(/[\\/]/).pop());
        var modeLabel = (mode === 'msi') ? 'MSI bundle' : 'PSADT package';

        var bodyHtml = 'Deploy <b>' + esc(pkgLabel) + '</b> (' + modeLabel + ') to <b>' + hosts.length + '</b> target(s)?'
          + '<br>Path: <b>' + esc(pkgPath) + '</b>'
          + '<br>Parallel: <b>' + threads + '</b>';
        if (mode === 'msi') bodyHtml += '<br>MSIs: <b>' + msis.length + '</b>  |  args: <b>' + esc(msiArgsInput.value) + '</b>';
        bodyHtml += '<br><br>This installs software on remote machines. First few targets:';

        ctx.confirm({
          title: 'Confirm Deployment', danger: true,
          body: bodyHtml, list: hosts.slice(0, 5),
          okText: 'Deploy', cancelText: 'Cancel'
        }).then(function (ok) {
          if (!ok) { log.append({ text: 'Deploy cancelled by operator.', level: 'warn' }); return; }

          grid.clear(); resetTally(hosts.length);
          log.banner("=== Deploying '" + pkgLabel + "' to " + hosts.length + ' target(s) ===');
          log.append({ text: 'Mode: ' + modeLabel + '  |  Path: ' + pkgPath + '  |  Parallel: ' + threads, level: 'mode' });
          if (mode === 'msi') {
            log.append({ text: 'MSI args: ' + msiArgsInput.value, level: 'dim' });
            msis.forEach(function (m) { log.append({ text: '  + ' + m, level: 'dim' }); });
          }
          setStatus('Deploying to ' + hosts.length + ' target(s)...', 'st-info');
          lockInputs(true);

          var actionId = (mode === 'msi') ? 'deploy-msi-bundle' : 'deploy-psadt';
          var params = {
            targets: hosts.join('\n'),
            packagePath: pkgPath,
            packagePathManual: '',     // pkgPath already resolves custom override
            packageName: pkgName,
            threads: threads
          };
          if (mode === 'msi') { params.msiList = msis.join('\n'); params.msiArgs = msiArgsInput.value; }

          run = ctx.run(actionId, params, { keyOf: function (ev) { return ev.Host != null ? String(ev.Host) : null; } });
          if (unsub) unsub();
          unsub = run.subscribe({
            status: function (t) { prog.setPhase(t); },
            progress: function (p) { prog.setProgress(p.done, p.total); setStatus('Running... ' + p.done + ' / ' + p.total + ' done', 'st-info'); },
            row: function (r) {
              grid.upsert(r);
              if (isTerminal(r.Status)) {
                var s = String(r.Status);
                if (s === 'Success') { stat.ok++; log.append({ text: '[' + r.Host + '] SUCCESS' + (r.ExitCode !== '' && r.ExitCode != null ? ' (exit=' + r.ExitCode + ')' : ''), level: 'ok' }); }
                else if (s === 'Deferred') { stat.deferred++; log.append({ text: '[' + r.Host + '] ' + s + ': ' + (r.Detail || ''), level: 'warn' }); }
                else if (s === 'Skipped') { stat.skipped++; log.append({ text: '[' + r.Host + '] ' + s + ': ' + (r.Detail || ''), level: 'warn' }); }
                else { stat.fail++; log.append({ text: '[' + r.Host + '] ' + s.toUpperCase() + ': ' + (r.Detail || ''), level: 'err' }); }
                pushStats();
              }
            },
            log: function (l) { log.append(l); },
            active: function (a) {
              runbar.setActive(a);
              if (!a) { lockInputs(false); refreshActionButtons(); }
            },
            final: function () {
              refreshActionButtons();
              var anyFail = stat.fail > 0;
              // Reconcile the full tally: ok+fail+deferred+skipped == total. Deferred
              // and skipped are shown only when non-zero so a clean run stays terse.
              var parts = stat.ok + ' success, ' + stat.fail + ' failed';
              if (stat.deferred) parts += ', ' + stat.deferred + ' deferred';
              if (stat.skipped) parts += ', ' + stat.skipped + ' skipped';
              setStatus('Complete - ' + parts + ' of ' + stat.total + '.', anyFail ? 'st-bad' : 'st-ok');
              log.banner('=== Deployment complete : ' + parts + ' ===');
            }
          });
        });
      }

      // ----- Retry Failed: harvest FAILED/Rejected rows back into the target box -----
      function doRetryFailed() {
        if (run && run.state && run.state.active) return;
        var failed = grid.rows().filter(function (r) { return String(r.Status) === 'Failed' || String(r.Status) === 'Rejected'; })
          .map(function (r) { return r.Host; }).filter(Boolean);
        if (!failed.length) { ctx.confirm({ title: 'Nothing to Retry', body: 'There are no failed hosts in the results grid.', okText: 'OK', cancelText: null }); return; }
        targets.setText(failed.join('\n'));
        log.append({ text: 'Loaded ' + failed.length + ' failed host(s) into the target list. Review, then click Deploy to re-run.', level: 'accent' });
        setStatus(failed.length + ' failed host(s) loaded for retry.', 'st-warn');
        targets.focus();
      }

      // ----- Export Results: client-side CSV of the grid rows (Host,Status,Detail,ExitCode,Time) -----
      function doExport() {
        var rows = grid.rows();
        if (!rows.length) { ctx.confirm({ title: 'Nothing to Export', body: 'Run a deployment first - there are no result rows yet.', okText: 'OK', cancelText: null }); return; }
        var csv = ctx.util.toCsv(EXPORT_COLS, rows);
        ctx.util.downloadBlob('RPI_DeployResults_' + ctx.util.fileStamp() + '.csv', 'text/csv', csv);
        log.append({ text: 'Exported ' + rows.length + ' result row(s) to CSV.', level: 'ok' });
      }

      // ---- init ----
      styleModeButtons();
      renderMsiList();
      loadPackages();
      log.append({ text: 'Remote Package Installer ready. Add targets, pick a package, Set Credentials (top-right), then Deploy.', level: 'accent' });
      log.append({ text: 'PSADT mode runs Deploy-Application.ps1; MSI mode runs msiexec /i per checked .msi.', level: 'dim' });

      host.appendChild(root);
      this._root = root; this._unsub = function () { if (unsub) unsub(); };
    },
    unmount: function () { try { if (this._unsub) this._unsub(); } catch (e) {} if (this._root) this._root.remove(); }
  });
})();
