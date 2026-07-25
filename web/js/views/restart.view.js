/* ============================================================================
   restart.view.js  -  Remote Restart Scheduler (tool id: 'restart')
   Faithful re-build per docs/ui-specs/restart.md of the desktop J.A.N.E.T.
   Remote Restart Scheduler v1.6.0: a multi-step coordinated fleet-reboot tool.
   The desktop's Targets / Schedule / Run-Results TabControl maps to a left-rail
   TabHost; the live run IS the point - dispatch-restart streams one row per host
   into a colour-coded ResultsGrid (keyed by Host), a nine-cell StatCards bar is
   recomputed LIVE from the grid's row statuses on every row event, and a second
   grid streams reboot ping-back rows from verify-reboots.

   Composes the shared kit only. ALL server I/O goes through ctx.run ->
   RunController (the view never fetches/polls). dispatch-restart is destructive:
   it is guarded on ctx.session.state.credSet and an ArmingDialog that restates
   the host count + consequence. Credentials are universal (shell header).
   ========================================================================== */
(function () {
  'use strict';

  // --- dispatch-restart row Status -> stat bucket + cell colour ------------
  // (engine status set: Pending | In-Flight | Consent-Launching/Awaiting-Consent/
  //  Consent-Polling/Consent-Approved | Dispatched | Already-Scheduled | Declined |
  //  Failed | Unreachable | Skipped-Server | Consent-Unverified | Timeout |
  //  Cancelled | Aborted | Abort Failed | Dry-Run | No-Pending)
  function dispatchBucket(status) {
    var s = String(status || '');
    if (s === 'Pending') return 'pending';
    if (s === 'Consent-Launching' || s === 'Awaiting-Consent' || s === 'Consent-Polling') return 'consent';
    if (s === 'In-Flight' || s === 'Consent-Approved') return 'inflight';
    if (s === 'Dispatched' || s === 'Already-Scheduled') return 'sent';
    if (s === 'Declined') return 'declined';
    // audit 2026-07-24: 'Timeout' is what the engine emits for a host it ABANDONS - the
    // wave's wall-clock backstop or the per-host watchdog - and it books that host as a
    // FAILURE. With no bucket here it fell through to 'pending' below, so an abandoned
    // host sat in PENDING for the rest of the run and logDispatchRow's default dropped
    // its line entirely: the operator never saw the host had been given up on.
    if (s === 'Failed' || s === 'Unreachable' || s === 'Abort Failed' || s === 'Consent-Unverified' || s === 'Timeout') return 'failed';
    if (s === 'Aborted') return 'aborted';
    if (s === 'Skipped-Server' || s === 'Cancelled') return 'skipped';
    if (s === 'Dry-Run' || s === 'No-Pending' || s === 'Skipped') return 'skipped';
    return 'pending';
  }
  function dispatchStatusCls(status) {
    switch (dispatchBucket(status)) {
      case 'sent': return 'st-ok';
      case 'declined': case 'aborted': return 'st-warn';
      case 'failed': return 'st-bad';
      case 'consent': case 'inflight': return 'st-info';
      case 'skipped': return 'cell-dim';
      default: return '';
    }
  }
  function dispatchRowCls(status) {
    switch (dispatchBucket(status)) {
      case 'sent': return 'row-ok';
      case 'failed': return 'row-bad';
      case 'declined': case 'aborted': return 'row-warn';
      default: return '';
    }
  }

  // --- verify-reboots State display -> cell colour ------------------------
  function rebootStateCls(state) {
    var s = String(state || '');
    if (/^Rebooted/i.test(s) || /^RESTARTED/i.test(s)) return 'st-ok';   // RESTARTED = WinRM boot-time confirmed
    if (/^Did NOT/i.test(s)) return 'st-bad';                            // boot-time confirmed no-reboot
    if (/^Online/i.test(s)) return 'st-warn';
    if (/^Offline/i.test(s)) return 'st-info';
    if (/^No contact/i.test(s)) return 'st-bad';
    if (/Boot-time check failed/i.test(s)) return 'st-warn';
    if (/^Cancelled/i.test(s)) return 'cell-dim';
    return 'st-info';
  }
  function rebootRowCls(state) {
    var s = String(state || '');
    if (/^Rebooted/i.test(s) || /^RESTARTED/i.test(s)) return 'row-ok';
    if (/^No contact/i.test(s) || /^Did NOT/i.test(s)) return 'row-bad';
    if (/^Online/i.test(s)) return 'row-warn';
    return '';
  }

  var esc = Janet.util.esc;

  JanetViews.register('restart', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;

      // shared host-list model (one source of truth across tabs)
      var targetsModel = ctx.util.targetModel('');

      // live run handles + unsubscribers (one per concurrent action)
      var dispatchRun = null, dispatchUnsub = null;
      var verifyRun = null, verifyUnsub = null;
      var bootRun = null, bootUnsub = null;
      var abortRun = null, abortUnsub = null;
      var pingUnsub = null, testUnsub = null;   // read-only side-runs (Ping All / Test Single)
      // Delayed start ("begin at the scheduled time") is held BY THE SERVER now.
      // armTimer only paints a smooth 1 s countdown between the shell's 5 s polls
      // of /api/jobs; armWatchUnsub listens for the arm firing or being stood down.
      // Neither one owns the wave: closing this tab loses nothing.
      var armTimer = null, armWatchUnsub = null;

      // tab + control refs filled by the lazy panel builders
      var refs = {};

      var root = el('div'); root.style.cssText = 'display:flex;flex-direction:column;height:100%;min-height:0;background:var(--bg)';

      // =====================================================================
      //  helpers
      // =====================================================================
      function card(title, hintTxt) {
        var box = ui.card({});
        if (title) { var h = el('div', 'j-section-h', title); h.style.marginBottom = '6px'; box.appendChild(h); }
        if (hintTxt) { var n = el('div', 'muted', hintTxt); n.style.cssText = 'font-size:11px;margin-bottom:8px'; box.appendChild(n); }
        return box;
      }
      function rowFlex(gap) { var d = el('div'); d.style.cssText = 'display:flex;align-items:flex-end;gap:' + (gap || 14) + 'px;flex-wrap:wrap'; return d; }
      function intOf(input, def, lo, hi) { var v = parseInt(input.value, 10); if (isNaN(v)) v = def; return Math.max(lo, Math.min(hi, v)); }

      // =====================================================================
      //  STAT BAR (nine cells) - recomputed LIVE from the dispatch grid rows
      //  Total / Pending / Consent / In-Flight / Sent / Declined / Failed /
      //  Aborted / Skipped  (mirrors the desktop nine-cell stats bar).
      // =====================================================================
      var statCard = ui.card({}); statCard.style.padding = '10px 12px';
      var stats = C.StatCards({ cards: [
        { key: 'total',    label: 'TOTAL',     color: 'accent' },
        { key: 'pending',  label: 'PENDING',   color: 'gold' },
        { key: 'consent',  label: 'CONSENT',   color: 'cyan' },
        { key: 'inflight', label: 'IN-FLIGHT', color: 'cyan' },
        { key: 'sent',     label: 'SENT',      color: 'ok' },
        { key: 'declined', label: 'DECLINED',  color: 'gold' },
        { key: 'failed',   label: 'FAILED',    color: 'bad' },
        { key: 'aborted',  label: 'ABORTED',   color: 'gold' },
        { key: 'skipped',  label: 'SKIPPED',   color: 'accent' }
      ] });
      statCard.appendChild(stats.el);
      statCard.style.margin = '12px 14px 0';
      root.appendChild(statCard);

      // recompute every bucket from the live grid row-set (the contract: derive
      // the StatCards from grid rows on each row event, never from deltas).
      function recomputeStats() {
        var c = { total: 0, pending: 0, consent: 0, inflight: 0, sent: 0, declined: 0, failed: 0, aborted: 0, skipped: 0 };
        if (refs.dispatchGrid) {
          refs.dispatchGrid.rows().forEach(function (r) {
            c.total++;
            var b = dispatchBucket(r.Status);
            if (c[b] != null) c[b]++;
          });
        }
        stats.setAll(c);
        return c;
      }

      // =====================================================================
      //  TAB HOST (left rail) - Targets/Config | Dispatch/Monitor | Reboot Verify
      // =====================================================================
      var tabWrap = el('div'); tabWrap.style.cssText = 'flex:1;min-height:0;display:flex;padding:12px 14px';
      var tabs = C.TabHost({
        rail: 'left',
        helpId: 'restart',
        tabs: [
          { id: 'targets',  label: 'TARGETS / CONFIG',          build: buildTargetsTab },
          { id: 'dispatch', label: 'DISPATCH / MONITOR',        build: buildDispatchTab },
          { id: 'verify',   label: 'REBOOT VERIFICATION',       build: buildVerifyTab }
        ]
      });
      tabWrap.appendChild(tabs.el);
      root.appendChild(tabWrap);

      // footer credit + log path (mirrors the desktop footer)
      var footer = el('div', 'j-footer');
      footer.appendChild(el('span', 'credit', 'Created by: THOMPSON, BRAXTON - 48 CS'));
      var logPath = el('span'); logPath.textContent = 'Log: ' + (ctx.session.state.logRoot || '(local)');
      footer.appendChild(logPath);
      root.appendChild(footer);

      // =====================================================================
      //  TAB 1 - TARGETS / CONFIG
      // =====================================================================
      function buildTargetsTab(panel) {
        panel.style.cssText = 'display:flex;gap:14px;height:100%;min-height:0;overflow:auto';

        // ---- LEFT: targets + exceptions ----
        var leftCol = el('div'); leftCol.style.cssText = 'flex:0 0 360px;display:flex;flex-direction:column;gap:12px;min-height:0';

        var tgCard = card('TARGET MACHINES', 'Paste hostnames (one per line, or comma/space/tab separated). Case-insensitive dedup.');
        tgCard.style.cssText += ';flex:1;display:flex;flex-direction:column;min-height:160px';
        var targets = C.TargetManager({
          model: targetsModel,
          hint: 'One host per line - or use Import',
          importLabel: 'Import targets CSV...',
          importAccept: '.txt,.csv,.tsv',
          pingAll: true,
          countNoun: 'target',
          onPingAll: doPing,
          onImport: function (n, name) { if (refs.dispatchLog) refs.dispatchLog.append({ text: 'Imported ' + n + ' host(s) from ' + name, level: 'info' }); }
        });
        refs.targets = targets;
        var tgHolder = el('div'); tgHolder.style.cssText = 'flex:1;min-height:120px;display:flex'; tgHolder.appendChild(targets.el);
        tgCard.appendChild(tgHolder);
        leftCol.appendChild(tgCard);

        var exCard = card('EXCEPTION LIST (NEVER RESTART)', 'Filtered out of any plan before dispatch. Saved in this browser across sessions.');
        exCard.style.cssText += ';flex:0 0 auto;display:flex;flex-direction:column';
        // header row: Import CSV + Clear (the desktop had an exceptions CSV import)
        var exHdr = el('div'); exHdr.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:6px';
        var exImport = ui.ghostButton('Import CSV...', { size: 'sm', title: 'Append never-restart hosts from a .txt/.csv file (one per line or comma/space separated).' });
        var exClear = ui.ghostButton('Clear', { size: 'sm', title: 'Empty the exception list.' });
        var exHsp = el('div'); exHsp.style.flex = '1'; exHdr.appendChild(exHsp); exHdr.appendChild(exImport); exHdr.appendChild(exClear);
        exCard.appendChild(exHdr);
        var exTa = ui.textarea({ placeholder: 'Hosts that must never be restarted - one per line', rows: 5 });
        exTa.style.minHeight = '90px';
        refs.exceptions = exTa;
        // ponytail: cross-session persistence via localStorage (per-browser). The desktop
        // wrote JanetLocal\Remote_Restart\<user>\exceptions.txt; localStorage gives the same
        // "my never-restart list survives restarts" with no engine/server/file I/O. Upgrade
        // to a JanetLocal file (per-user, shared across machines) only if operators need that.
        var EXC_KEY = 'janetWeb.restart.exceptions';
        // One-time migrate from the TWO-era key so saved exception lists survive the rebrand.
        try {
          var savedEx = window.localStorage.getItem(EXC_KEY);
          if (savedEx === null) {
            savedEx = window.localStorage.getItem('janetTwo.restart.exceptions');
            if (savedEx !== null) { window.localStorage.setItem(EXC_KEY, savedEx); window.localStorage.removeItem('janetTwo.restart.exceptions'); }
          }
          if (savedEx) exTa.value = savedEx;
        } catch (e) {}
        function exSave() { try { window.localStorage.setItem(EXC_KEY, exTa.value); } catch (e) {} }
        exTa.addEventListener('input', exSave);
        exClear.onclick = function () { exTa.value = ''; exSave(); };
        exImport.onclick = function () {
          var fi = el('input'); fi.type = 'file'; fi.accept = '.txt,.csv,.tsv'; fi.style.display = 'none';
          document.body.appendChild(fi);
          fi.addEventListener('change', function () {
            var f = fi.files && fi.files[0]; document.body.removeChild(fi);
            if (!f) return;
            var rd = new FileReader();
            rd.onload = function () {
              var before = ctx.util.parseHosts(exTa.value).length;
              exTa.value = ctx.util.parseHosts(exTa.value + '\n' + String(rd.result || '')).join('\n');
              exSave();
              var added = ctx.util.parseHosts(exTa.value).length - before;
              if (refs.dispatchLog) refs.dispatchLog.append({ text: 'Imported ' + added + ' new exception host(s) from ' + f.name + ' (' + ctx.util.parseHosts(exTa.value).length + ' total).', level: 'info' });
            };
            rd.readAsText(f);
          });
          fi.click();
        };
        exCard.appendChild(exTa);
        leftCol.appendChild(exCard);
        panel.appendChild(leftCol);

        // ---- RIGHT: restart config ----
        var cfg = card('RESTART CONFIGURATION');
        cfg.style.cssText += ';flex:1;min-width:0;overflow:auto';

        // restart mode (burst-converge vs rolling/go-fast vs time-gated)
        cfg.appendChild(ui.eyebrow('RESTART MODE'));
        var modeSelect = ui.select({
          options: [
            { value: 'burst', label: 'Burst converge - every approved host reboots together at the scheduled time' },
            { value: 'timegated', label: 'Time-gated - each host holds until RestartAt - lead, then fires /t = lead x 60' },
            { value: 'rolling', label: 'Rolling / go-fast - reboot each host ~grace sec after IT approves (no shared time)' }
          ],
          value: 'burst',
          onChange: syncModeFields
        });
        modeSelect.style.maxWidth = '640px';
        refs.mode = modeSelect;
        cfg.appendChild(ui.field('Mode', modeSelect));

        var timeRow = rowFlex();
        var restartTime = ui.input({ placeholder: 'YYYY-MM-DDTHH:mm  or  HH:mm', title: 'Shared reboot time (burst + time-gated). Ignored in rolling mode.' });
        restartTime.style.width = '220px';
        // default to +15 min, local, in the engine-friendly HH:mm form
        (function () { var d = new Date(Date.now() + 15 * 60000); var p = function (n) { return String(n).padStart(2, '0'); }; restartTime.value = p(d.getHours()) + ':' + p(d.getMinutes()); })();
        refs.restartTime = restartTime;
        timeRow.appendChild(ui.field('Restart time', restartTime));

        var leadMin = ui.number({ value: 15, min: 1, max: 60, title: 'Time-gated /t lead in minutes.' }); leadMin.style.width = '90px';
        refs.leadMinutes = leadMin;
        var leadField = ui.field('Lead minutes', leadMin); refs.leadField = leadField;
        timeRow.appendChild(leadField);

        var rollGrace = ui.number({ value: 60, min: 5, max: 3600, title: 'Rolling: reboot grace after IT approves (seconds).' }); rollGrace.style.width = '110px';
        refs.rollingGrace = rollGrace;
        var rollField = ui.field('Rolling grace (sec)', rollGrace); refs.rollField = rollField;
        timeRow.appendChild(rollField);

        var threads = ui.number({ value: 96, min: 1, max: 256, title: 'Parallel hosts (RunspacePool size).' }); threads.style.width = '90px';
        refs.threads = threads;
        timeRow.appendChild(ui.field('Parallel hosts', threads));
        cfg.appendChild(timeRow);

        // message
        var msg = ui.textarea({ value: 'System is restarting for maintenance. Save your work.', rows: 3, title: 'Countdown popup message. {LEAD} expands to the warning minutes.' });
        msg.style.cssText += ';margin-top:4px';
        refs.message = msg;
        cfg.appendChild(ui.field('Countdown message ({LEAD} token)', msg));

        // gates
        cfg.appendChild((function () { var h = ui.eyebrow('PRE-FLIGHT GATES'); h.style.marginTop = '12px'; return h; })());
        var gates = el('div'); gates.style.cssText = 'display:flex;flex-direction:column;gap:8px';
        var pingGate = ui.checkbox('Skip unreachable (pre-flight ping gate) - no WinRM to dead hosts', { checked: true, color: 'var(--cyan)', title: 'Parallel TCP reachability probe (WinRM 5985 / SMB 445) before any WinRM; unreachable hosts are marked Unreachable.' });
        refs.pingGate = pingGate;
        gates.appendChild(pingGate);
        var skipSrvRow = el('div'); skipSrvRow.style.cssText = 'display:flex;align-items:center;gap:10px;flex-wrap:wrap';
        var skipSrvCb = ui.checkbox('Skip servers matching regex', { checked: true, color: 'var(--gold)', title: 'Server-named hosts are excluded from the wave before WinRM.' });
        refs.skipServers = skipSrvCb;
        var skipSrvRe = ui.input({ value: '^MSEK-[A-Za-z]{2,4}-', title: 'Hostname regex; matches are marked Skipped-Server.' }); skipSrvRe.style.width = '220px';
        refs.skipServersRegex = skipSrvRe;
        skipSrvRow.appendChild(skipSrvCb); skipSrvRow.appendChild(skipSrvRe);
        gates.appendChild(skipSrvRow);
        var onlyPendingCb = ui.checkbox('Only restart hosts with a pending reboot (skip the rest)', { color: 'var(--cyan)', title: 'Pre-flight WinRM probe per host (CBS / WindowsUpdate / PendingFileRenameOperations); hosts with nothing pending are skipped, not rebooted.' });
        refs.onlyPending = onlyPendingCb;
        gates.appendChild(onlyPendingCb);
        cfg.appendChild(gates);

        // consent
        cfg.appendChild((function () { var h = ui.eyebrow('USER CONSENT'); h.style.marginTop = '12px'; return h; })());
        var consentCb = ui.checkbox('Require user consent prompt (Accept/Decline in the user session)', { checked: true, color: 'var(--gold)', title: 'A one-time task shows an Accept/Decline dialog in the user session before reboot.' });
        refs.consent = consentCb;
        consentCb.addEventListener('change', syncConsentFields);
        cfg.appendChild(consentCb);
        var consentRow = rowFlex(); consentRow.style.marginTop = '6px';
        var consentMin = ui.number({ value: 5, min: 1, max: 60, title: 'How long the prompt stays up (minutes).' }); consentMin.style.width = '90px';
        refs.consentMin = consentMin;
        consentRow.appendChild(ui.field('Prompt window (min)', consentMin));
        var consentGrace = ui.number({ value: 60, min: 10, max: 3600, title: 'Accept grace / save-work seconds after Accept.' }); consentGrace.style.width = '110px';
        refs.consentGrace = consentGrace;
        consentRow.appendChild(ui.field('Accept grace (sec)', consentGrace));
        var consentFail = ui.select({ options: [{ value: 'proceed', label: 'Proceed (no response / no user)' }, { value: 'skip', label: 'Skip the host' }], value: 'proceed', title: 'What to do if the prompt cannot run or gets no answer.' });
        consentFail.style.width = '230px';
        refs.consentFail = consentFail;
        consentRow.appendChild(ui.field('If consent prompt fails', consentFail));
        refs.consentRow = consentRow;
        cfg.appendChild(consentRow);

        // dry run
        var dry = ui.checkbox('Dry run - log the commands only, contact no hosts', { color: 'var(--warn)', title: 'No machine is contacted; every host is logged as a would-be dispatch.' });
        dry.style.marginTop = '12px';
        refs.dryRun = dry;
        cfg.appendChild(dry);

        // delayed-start arming + auto-monitor (desktop "Begin at the scheduled time"
        // + the auto-opening Reboot Verification Monitor).
        cfg.appendChild((function () { var h = ui.eyebrow('DELAYED START / MONITOR'); h.style.marginTop = '12px'; return h; })());
        // audit 2026-07-25 (C1): this used to be a browser setInterval, so the tooltip
        // had to beg operators not to close the tab - a stray F5 silently lost the
        // wave. The countdown now lives on the SERVER (in memory, never on disk): the
        // browser can close, and the wave is stood down automatically if the admin
        // session ends before it fires.
        var beginAtCb = ui.checkbox('Begin at the scheduled time - Start Dispatch arms the wave ON THE SERVER and it fires when the clock reaches Restart time', { color: 'var(--cyan)', title: 'Start Dispatch hands the confirmed wave to the server, which holds it in memory and fires it at the Restart time. You can close this browser tab. The armed wave shows in a red bar across the bottom of the window and can be disarmed from there at any time. It is discarded (never fired) if the admin session ends or the server restarts. Ignored in rolling mode.' });
        refs.beginAt = beginAtCb;
        cfg.appendChild(beginAtCb);
        var autoMonCb = ui.checkbox('Auto-open the Reboot Verification Monitor when the dispatch completes', { checked: true, color: 'var(--gold)', title: 'On a real run with at least one host dispatched, switch to the monitor and start pinging the dispatched hosts.' });
        refs.autoMonitor = autoMonCb;
        cfg.appendChild(autoMonCb);

        // single-host test
        cfg.appendChild((function () { var h = ui.eyebrow('SINGLE-HOST TEST'); h.style.marginTop = '14px'; return h; })());
        var testRow = el('div'); testRow.style.cssText = 'display:flex;align-items:center;gap:8px;flex-wrap:wrap';
        var testHost = ui.input({ placeholder: 'hostname', title: 'Synchronous single-host restart test (returns exit code + hint).' }); testHost.style.width = '180px';
        var testBtn = ui.button('Test single host...', { variant: 'gold', size: 'sm', title: 'Fire one synchronous shutdown /r and show the exit code + error hint.' });
        testBtn.onclick = function () { doTestSingle(testHost.value); };
        // audit 2026-07-24 (S3): defaults to CHECKED. This box previously defaulted off,
        // so a button labelled "Test single host..." rebooted a production machine on one
        // click with no dialog at all. Safe reading of "test" is now the default one.
        var testDry = ui.checkbox('Dry run', { checked: true, color: 'var(--warn)', title: 'Preview only - no machine is contacted and nothing reboots.' });
        refs.testDry = testDry;
        var testOut = el('span', 'muted'); testOut.style.cssText = 'font-family:var(--mono);font-size:12px';
        refs.testOut = testOut;
        testRow.appendChild(testHost); testRow.appendChild(testBtn); testRow.appendChild(testDry); testRow.appendChild(testOut);
        cfg.appendChild(testRow);

        // proceed CTA -> jump to Dispatch tab
        var proceed = el('div'); proceed.style.cssText = 'margin-top:18px';
        var goBtn = ui.button('Continue to Dispatch / Monitor  ->', { variant: 'go', title: 'Move to the dispatch tab to arm and launch the wave.' });
        goBtn.onclick = function () { tabs.select('dispatch'); };
        proceed.appendChild(goBtn);
        cfg.appendChild(proceed);

        panel.appendChild(cfg);

        syncModeFields();
        syncConsentFields();
      }

      // mode-dependent field enable/disable (lead vs rolling-grace vs shared time)
      function syncModeFields() {
        var m = refs.mode ? refs.mode.value : 'burst';
        var rolling = (m === 'rolling'), timegated = (m === 'timegated');
        if (refs.leadField) refs.leadField.style.opacity = timegated ? '1' : '0.5';
        if (refs.leadMinutes) refs.leadMinutes.disabled = !timegated;
        if (refs.rollField) refs.rollField.style.opacity = rolling ? '1' : '0.5';
        if (refs.rollingGrace) refs.rollingGrace.disabled = !rolling;
        if (refs.restartTime) refs.restartTime.disabled = rolling;
      }
      function syncConsentFields() {
        var on = refs.consent && refs.consent._cb.checked;
        if (refs.consentRow) {
          refs.consentRow.style.opacity = on ? '1' : '0.5';
          [refs.consentMin, refs.consentGrace, refs.consentFail].forEach(function (c) { if (c) c.disabled = !on; });
        }
      }

      // =====================================================================
      //  TAB 2 - DISPATCH / MONITOR  (the live run)
      // =====================================================================
      function buildDispatchTab(panel) {
        panel.style.cssText = 'display:flex;flex-direction:column;gap:10px;height:100%;min-height:0';

        // toolbar: CTA (dispatch) morphs to Cancel-Pending; Abort + Verify + Export
        var bar = el('div'); bar.style.cssText = 'display:flex;align-items:center;gap:12px;flex-wrap:wrap';

        var cancelBtn = ui.button('Cancel Pending', { variant: 'gold', size: 'sm', title: 'Stop the in-progress dispatch: remaining hosts are abandoned, in-flight WinRM calls are stopped.' });
        cancelBtn.disabled = true;
        cancelBtn.onclick = function () {
          if (cancelArm()) return;   // stand down a pending delayed-start arm
          if (dispatchRun) { dispatchRun.cancel(); if (refs.dispatchLog) refs.dispatchLog.append({ text: 'Cancel Pending requested - abandoning remaining hosts, stopping in-flight calls...', level: 'warn' }); }
        };
        refs.cancelBtn = cancelBtn;

        var abortBtn = ui.button('Abort Already-Dispatched', { variant: 'danger', size: 'sm', title: 'Send shutdown /a to every host that already received a restart command.' });
        abortBtn.disabled = true;
        abortBtn.onclick = doAbort;
        refs.abortBtn = abortBtn;

        var verifyBtn = ui.button('Verify Reboots', { variant: 'cyan', size: 'sm', title: 'Open the reboot-verification monitor for the dispatched hosts.' });
        verifyBtn.onclick = function () { tabs.select('verify'); };

        var exportBtn = ui.ghostButton('Export Results CSV...', { size: 'sm', title: 'Export the per-host dispatch results.' });
        exportBtn.onclick = exportDispatchCsv;

        // CTA (gold dispatch, morphs to red Cancel via RunBar.morphToCancel)
        var runbar = C.RunBar({
          label: 'START DISPATCH', cancelLabel: 'CANCEL DISPATCH IN PROGRESS', morphToCancel: true,
          title: 'Fan out shutdown /r to every target. Destructive - confirms host count + consequence.',
          guards: [
            function () { return (refs.targets ? refs.targets.count() : targetsModel.count()) ? null : 'No Targets|Add at least one hostname on the Targets / Config tab.'; },
            function () { return ctx.session.state.credSet ? null : 'No Credentials|Set your ADW credential (Set Credentials, top-right) before dispatching. A coordinated reboot changes machines, so an admin session is required.'; },
            function () { var m = refs.mode ? refs.mode.value : 'burst'; if (m === 'rolling') return null; return (refs.restartTime && refs.restartTime.value.trim()) ? null : 'No Restart Time|Burst and time-gated modes need a shared restart time (HH:mm or ISO 8601).'; }
          ],
          onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
          onRun: doDispatch,
          onCancel: function () { if (cancelArm()) return; if (dispatchRun) { dispatchRun.cancel(); if (refs.dispatchLog) refs.dispatchLog.append({ text: 'CANCEL requested - abandoning remaining hosts...', level: 'warn' }); } }
        });
        refs.runbar = runbar;
        var ctaHolder = el('div'); ctaHolder.style.width = '280px'; ctaHolder.appendChild(runbar.el);

        bar.appendChild(ctaHolder);
        bar.appendChild(cancelBtn); bar.appendChild(abortBtn); bar.appendChild(verifyBtn);
        var spacer = el('div'); spacer.style.flex = '1'; bar.appendChild(spacer);
        bar.appendChild(exportBtn);
        panel.appendChild(bar);

        // progress strip (numeric, like the desktop Elapsed/Done lines)
        var prog = C.ProgressStatusStrip({ showCount: true });
        refs.dispatchProg = prog;
        panel.appendChild(prog.el);

        // results grid (one row per host) fills; the activity log docks as a
        // click-to-open drawer across the bottom (Dock=Bottom in the desktop tool).
        var gridCard = card('DISPATCH RESULTS'); gridCard.style.cssText += ';flex:1;min-width:0;min-height:0;display:flex;flex-direction:column';
        var grid = C.ResultsGrid({
          title: 'Restart dispatch results', emptyText: 'No dispatch yet — paste hosts, set a restart time, then Dispatch Restart.', keyMode: { hostCol: 'Host' }, popOut: true,
          columns: [
            { key: 'Host', label: 'HOST', width: 150 },
            { key: 'Status', label: 'STATUS', width: 130, render: function (r) { return { text: r.Status == null ? '' : String(r.Status), cls: dispatchStatusCls(r.Status) }; } },
            { key: 'DispatchAt', label: 'DISPATCH AT', width: 150 },
            { key: 'RestartAt', label: 'RESTART AT', width: 150 },
            { key: 'ConsentState', label: 'CONSENT', width: 110 },
            { key: 'Result', label: 'RESULT' }
          ],
          rowClass: function (r) { return dispatchRowCls(r.Status); }
        });
        refs.dispatchGrid = grid;
        var gridHolder = el('div'); gridHolder.style.cssText = 'flex:1;min-height:0;display:flex'; gridHolder.appendChild(grid.el);
        gridCard.appendChild(gridHolder);
        panel.appendChild(gridCard);

        var logCard = card(null); logCard.classList.add('j-logdock');
        var log = C.ActivityLog({ title: 'ACTIVITY LOG', defaultName: 'RRS_DispatchLog' });
        refs.dispatchLog = log;
        logCard.appendChild(log.el);
        panel.appendChild(logCard);

        log.append({ text: 'Workflow: Targets -> Config -> Start Dispatch -> Verify Reboots.', level: 'accent' });
        log.append({ text: 'Start Dispatch arms a destructive coordinated reboot - it confirms the host count first.', level: 'dim' });
        recomputeStats();
      }

      // =====================================================================
      //  TAB 3 - REBOOT VERIFICATION MONITOR
      // =====================================================================
      function buildVerifyTab(panel) {
        panel.style.cssText = 'display:flex;flex-direction:column;gap:10px;height:100%;min-height:0';

        var bar = el('div'); bar.style.cssText = 'display:flex;align-items:flex-end;gap:12px;flex-wrap:wrap';

        var interval = ui.number({ value: 15, min: 3, max: 600, title: 'Ping every N seconds.' }); interval.style.width = '90px';
        refs.verifyInterval = interval;
        bar.appendChild(ui.field('Ping every (s)', interval));
        var timeout = ui.number({ value: 1800, min: 10, max: 86400, title: 'Stop the monitor after this many seconds.' }); timeout.style.width = '110px';
        refs.verifyTimeout = timeout;
        bar.appendChild(ui.field('Timeout (s)', timeout));
        var vThreads = ui.number({ value: 32, min: 1, max: 64, title: 'Parallel pings.' }); vThreads.style.width = '90px';
        refs.verifyThreads = vThreads;
        bar.appendChild(ui.field('Parallel pings', vThreads));

        var exportBtn = ui.ghostButton('Export CSV...', { size: 'sm', title: 'Export the reboot-verification rows.' });
        exportBtn.onclick = exportVerifyCsv;

        // On-demand WinRM boot-time confirmation (desktop "Verify (WinRM)"): queries
        // LastBootUpTime and overwrites each host's ping-inferred verdict with an
        // authoritative RESTARTED / Did-NOT-restart one.
        var bootBtn = ui.button('Verify (WinRM)', { variant: 'gold', size: 'sm', title: 'Query LastBootUpTime over WinRM and confirm reboots AUTHORITATIVELY (trumps ping). Compares boot time to the Restart time on the Config tab; blank = report boot time only.' });
        bootBtn.onclick = doVerifyBootTime; refs.bootBtn = bootBtn;

        var verifyRunbar = C.RunBar({
          label: 'START REBOOT MONITOR', cancelLabel: 'STOP MONITOR', morphToCancel: true,
          title: 'Ping each target on an interval and confirm a DOWN-then-UP reboot transition.',
          guards: [
            function () { return (refs.targets ? refs.targets.count() : targetsModel.count()) ? null : 'No Targets|Add at least one hostname on the Targets / Config tab to monitor.'; }
          ],
          onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
          onRun: doVerify,
          onCancel: function () { if (verifyRun) { verifyRun.cancel(); if (refs.verifyLog) refs.verifyLog.append({ text: 'Stop requested - abandoning remaining hosts.', level: 'warn' }); } }
        });
        refs.verifyRunbar = verifyRunbar;
        var ctaHolder = el('div'); ctaHolder.style.width = '260px'; ctaHolder.appendChild(verifyRunbar.el);
        bar.appendChild(ctaHolder);
        var spacer = el('div'); spacer.style.flex = '1'; bar.appendChild(spacer);
        bar.appendChild(bootBtn);
        bar.appendChild(exportBtn);
        panel.appendChild(bar);

        var prog = C.ProgressStatusStrip({ showCount: true });
        refs.verifyProg = prog;
        panel.appendChild(prog.el);

        var gridCard = card('REBOOT VERIFICATION'); gridCard.style.cssText += ';flex:1;min-width:0;min-height:0;display:flex;flex-direction:column';
        var grid = C.ResultsGrid({
          title: 'Reboot verification', emptyText: 'No verification yet — dispatch a wave or run Verify Reboots.', keyMode: { hostCol: 'Host' }, popOut: true,
          columns: [
            { key: 'Host', label: 'HOST', width: 160 },
            { key: 'State', label: 'STATE', width: 220, render: function (r) { return { text: r.State == null ? '' : String(r.State), cls: rebootStateCls(r.State) }; } },
            { key: 'Went-Down', label: 'WENT DOWN', width: 110 },
            { key: 'Came-Back', label: 'CAME BACK', width: 110 },
            { key: 'Boot-Time', label: 'BOOT TIME', width: 150 },
            { key: 'Result', label: 'RESULT' }
          ],
          rowClass: function (r) { return rebootRowCls(r.State); }
        });
        refs.verifyGrid = grid;
        var gridHolder = el('div'); gridHolder.style.cssText = 'flex:1;min-height:0;display:flex'; gridHolder.appendChild(grid.el);
        gridCard.appendChild(gridHolder);
        panel.appendChild(gridCard);

        var logCard = card(null); logCard.classList.add('j-logdock');
        var log = C.ActivityLog({ title: 'MONITOR LOG', defaultName: 'RRS_RebootMonitor' });
        refs.verifyLog = log;
        logCard.appendChild(log.el);
        panel.appendChild(logCard);
        log.append({ text: 'Reboot Verification Monitor: pings each target until it goes DOWN then comes back UP.', level: 'accent' });
      }

      // =====================================================================
      //  ACTIONS
      // =====================================================================

      // ---- Ping All (Targets tab) ----
      function doPing() {
        if (dispatchRun && dispatchRun.state && dispatchRun.state.active) return;
        var hosts = refs.targets ? refs.targets.hosts() : targetsModel.hosts();
        if (!hosts.length) { ctx.confirm({ title: 'No Targets', body: 'Add at least one hostname to ping.', okText: 'OK', cancelText: null }); return; }
        if (refs.dispatchLog) refs.dispatchLog.banner('Ping All (' + hosts.length + ' host(s))');
        if (refs.targets) { refs.targets.setPingEnabled(false); refs.targets.setPingLabel('Pinging...'); }
        var online = 0, offline = 0;
        var pr = ctx.run('ping', { targets: hosts.join('\n') });
        if (pingUnsub) pingUnsub();
        pingUnsub = pr.subscribe({
          row: function (r) {
            var up = (r.Pingable === true || r.Pingable === 'true');
            if (up) online++; else offline++;
            if (refs.dispatchLog) refs.dispatchLog.append({ text: '[' + r.Host + '] ' + (up ? 'ONLINE' : 'OFFLINE / not pingable'), level: up ? 'ok' : 'err' });
          },
          log: function (l) { if (refs.dispatchLog) refs.dispatchLog.append(l); },
          final: function () { if (refs.dispatchLog) refs.dispatchLog.banner('Ping complete: ' + online + ' online, ' + offline + ' offline'); },
          active: function (a) { if (!a && refs.targets) { refs.targets.setPingEnabled(true); refs.targets.setPingLabel('Ping All'); } }
        });
      }

      // ---- Single-host test (Targets tab) ----
      async function doTestSingle(hostname) {
        var h = String(hostname || '').trim();
        if (!h) { ctx.confirm({ title: 'Hostname required', body: 'Enter a hostname to test.', okText: 'OK', cancelText: null }); return; }
        var testDryRun = refs.testDry ? refs.testDry._cb.checked : false;
        // audit 2026-07-24 (S3): the LIVE single-host test had NO confirmation of any kind -
        // it called ctx.run directly. Every other reboot path in this view is behind ctx.arm
        // with a typed word; this one reboots a named production box on one click. Gate it.
        // Dry runs stay ungated (nothing is contacted).
        if (!testDryRun) {
          var okTest = await ctx.arm({
            title: 'Restart ' + h + ' now?',
            banner: 'LIVE SINGLE-HOST RESTART - THIS MACHINE WILL REBOOT',
            danger: true,
            confirmWord: 'RESTART',
            body: 'This is a <b>live</b> restart of <b>' + Janet.util.esc(h) + '</b>, not a preview. The host is given a 60-second lead and then reboots. Tick <b>Dry run</b> beside the button if you only want to check reachability and the exit code.',
            preflight: [
              { label: 'Target: ' + h, ok: true },
              { label: 'Admin credential set (' + (ctx.session.state.user || 'session') + ')', ok: !!ctx.session.state.credSet },
              { label: 'LIVE - this machine WILL restart in 60 seconds', ok: false }
            ],
            okText: 'Restart ' + h, cancelText: 'Cancel'
          });
          if (!okTest) {
            if (refs.dispatchLog) refs.dispatchLog.append({ text: '[' + ts() + '] Single-host test cancelled at the arming dialog.', level: 'warn' });
            return;
          }
        }
        if (refs.testOut) { refs.testOut.textContent = (testDryRun ? 'Dry-run check of ' : 'Testing ') + h + '...'; refs.testOut.className = 'st-info'; }
        var tr = ctx.run('test-single-host', { hostname: h, leadSeconds: 60, message: 'TEST: this machine will restart shortly.', dryRun: testDryRun });
        if (testUnsub) testUnsub();
        testUnsub = tr.subscribe({
          row: function (r) {
            var ok = (r.Success === true || r.Success === 'true');
            if (refs.testOut) {
              refs.testOut.textContent = (ok ? 'OK' : 'FAILED') + '  rc=' + (r.ExitCode == null ? '?' : r.ExitCode) + (r.ErrorHint ? '  - ' + r.ErrorHint : '');
              refs.testOut.className = ok ? 'st-ok' : 'st-bad';
            }
            if (refs.dispatchLog) refs.dispatchLog.append({ text: '[TEST ' + r.Host + '] ' + (ok ? 'SUCCESS' : 'FAILED') + ' rc=' + r.ExitCode + (r.ErrorHint ? ' (' + r.ErrorHint + ')' : ''), level: ok ? 'ok' : 'err' });
          },
          log: function (l) { if (refs.dispatchLog) refs.dispatchLog.append(l); }
        });
      }

      // ---- DISPATCH (destructive) ----
      function readDispatchParams() {
        var m = refs.mode ? refs.mode.value : 'burst';
        return {
          targets: refs.targets ? refs.targets.hosts().join('\n') : (targetsModel.getText ? targetsModel.getText() : targetsModel.raw),
          exceptions: refs.exceptions ? refs.exceptions.value : '',
          restartTime: refs.restartTime ? refs.restartTime.value.trim() : '',
          leadMinutes: refs.leadMinutes ? intOf(refs.leadMinutes, 15, 1, 60) : 15,
          message: refs.message ? refs.message.value : '',
          burstMode: (m === 'burst'),
          rollingMode: (m === 'rolling'),
          rollingGraceSeconds: refs.rollingGrace ? intOf(refs.rollingGrace, 60, 5, 3600) : 60,
          dryRun: refs.dryRun ? refs.dryRun._cb.checked : false,
          requireConsent: refs.consent ? refs.consent._cb.checked : true,
          consentPromptMinutes: refs.consentMin ? intOf(refs.consentMin, 5, 1, 60) : 5,
          consentGraceSeconds: refs.consentGrace ? intOf(refs.consentGrace, 60, 10, 3600) : 60,
          consentFailMode: refs.consentFail ? refs.consentFail.value : 'proceed',
          skipServersRegex: (refs.skipServers && refs.skipServers._cb.checked && refs.skipServersRegex) ? refs.skipServersRegex.value : '',
          skipUnreachablePing: refs.pingGate ? refs.pingGate._cb.checked : true,
          onlyIfPending: refs.onlyPending ? refs.onlyPending._cb.checked : false,
          threads: refs.threads ? intOf(refs.threads, 96, 1, 256) : 96,
          _mode: m
        };
      }

      async function doDispatch() {
        var p = readDispatchParams();
        var hosts = refs.targets ? refs.targets.hosts() : targetsModel.hosts();
        var modeLabel = p.rollingMode ? 'ROLLING / go-fast (no shared time)' : (p.burstMode ? 'BURST converge @ ' + p.restartTime : 'TIME-GATED, lead ' + p.leadMinutes + ' min @ ' + p.restartTime);

        // ArmingDialog: restate host count + consequence (destructive guard).
        var ok = await ctx.arm({
          title: p.dryRun ? 'Arm Dispatch (DRY RUN)' : 'Arm Coordinated Restart',
          banner: p.dryRun ? 'DRY RUN - no host will be contacted' : 'DESTRUCTIVE - THIS WILL RESTART LIVE MACHINES',
          body: 'About to dispatch a coordinated restart to <b>' + hosts.length + '</b> host(s).<br>' +
                'Mode: <b>' + esc(modeLabel) + '</b><br>' +
                'User consent: <b>' + (p.requireConsent ? 'required (' + p.consentPromptMinutes + ' min window)' : 'OFF') + '</b><br>' +
                'Ping gate: <b>' + (p.skipUnreachablePing ? 'ON' : 'off') + '</b> | Server-skip: <b>' + (p.skipServersRegex ? esc(p.skipServersRegex) : 'off') + '</b><br>' +
                'Only pending-reboot hosts: <b>' + (p.onlyIfPending ? 'ON' : 'off') + '</b><br>' +
                (p.dryRun ? '<br>Dry run: commands are logged only.' : '<br>Every reachable, approved host will reboot.'),
          preflight: [
            { label: hosts.length + ' target host(s) queued', ok: hosts.length > 0 },
            { label: 'Admin credential set (' + (ctx.session.state.user || 'session') + ')', ok: !!ctx.session.state.credSet },
            { label: p.dryRun ? 'DRY RUN - safe, no machines contacted' : 'LIVE - machines WILL restart', ok: p.dryRun }
          ],
          confirmWord: p.dryRun ? null : 'RESTART',
          okText: p.dryRun ? 'Run Dry' : 'Dispatch Restart',
          cancelText: 'Cancel'
        });
        if (!ok) { if (refs.dispatchLog) refs.dispatchLog.append({ text: 'Dispatch cancelled at the arming dialog.', level: 'warn' }); return; }

        // audit 2026-07-23: the server now enforces the typed RESTART word for LIVE
        // dispatches (refuses without it - pkginstall lesson: gate + param must land
        // together). The operator just typed it in the ArmingDialog above (confirmWord
        // is only demanded when live); dry-run needs no word server-side either.
        if (!p.dryRun) p.confirm = 'RESTART';

        // Delayed start: "Begin at the scheduled time" hands the wave to the SERVER,
        // which holds it (in memory only) until the Restart time and fires it there.
        // The operator has just confirmed the whole thing - host count, mode, and the
        // typed RESTART word - so the fire itself is unattended; the server re-checks
        // the word and refuses to fire at all if the admin session ended meanwhile.
        var fireAt = (refs.beginAt && refs.beginAt._cb.checked && !p.rollingMode) ? parseRestartTime(p.restartTime) : null;
        if (fireAt && fireAt.getTime() > Date.now() + 1500) { armDispatchServerSide(fireAt, p, hosts, modeLabel); return; }
        launchDispatch(p, hosts, modeLabel);
      }

      // parse the Restart-time field ("HH:mm" -> today/tomorrow, or ISO) to a Date.
      function parseRestartTime(s) {
        s = String(s || '').trim(); if (!s) return null;
        var now = new Date();
        if (/^\d{1,2}:\d{2}$/.test(s)) {
          var pp = s.split(':'); var d = new Date(now.getTime()); d.setHours(parseInt(pp[0], 10), parseInt(pp[1], 10), 0, 0);
          if (d.getTime() <= now.getTime()) d.setDate(d.getDate() + 1);   // already past today -> tomorrow
          return d;
        }
        var iso = new Date(s.replace(' ', 'T'));
        return isNaN(iso.getTime()) ? null : iso;
      }

      function pad2(n) { return (n < 10 ? '0' : '') + n; }
      function hms(total) {
        total = Math.max(0, Math.round(total || 0));
        var h = Math.floor(total / 3600), m = Math.floor((total % 3600) / 60), s = total % 60;
        return (h > 0 ? pad2(h) + ':' : '') + pad2(m) + ':' + pad2(s);
      }
      // Local wall-clock 'YYYY-MM-DDTHH:mm:ss' - no zone suffix, because the server
      // parses it in ITS local time and both processes are on the same box.
      function isoLocal(d) {
        return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) + 'T' +
               pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
      }

      // ---- ARM the wave ON THE SERVER (was a browser setInterval) --------------
      // audit 2026-07-25 (convergence C1): the delayed start used to be a
      // setInterval in this file. It died with the tab, so a stray F5 lost a 2 AM
      // reboot wave and the checkbox tooltip had to beg operators to leave the tool
      // open. The already-confirmed param set now goes to the server, which holds it
      // IN MEMORY ONLY (never on disk, no credential in it) and fires it through the
      // normal dispatch path at the scheduled time. What did NOT change: the
      // ArmingDialog above, the typed RESTART word (it rides in p.confirm and the
      // engine re-checks it at fire time), the admin-session gate, and every
      // engine-side guard. The gate simply happens EARLIER.
      function armDispatchServerSide(fireAt, p, hosts, modeLabel) {
        if (armTimer) { clearInterval(armTimer); armTimer = null; }
        refs.dispatchGrid.clear(); refs.dispatchProg.reset(); recomputeStats();
        refs.dispatchLog.banner('Arming on the server: ' + hosts.length + ' host(s), ' + modeLabel);
        refs.runbar.setStatus('Arming...', 'st-info');
        var payload = {};
        Object.keys(p).forEach(function (k) { if (k !== '_mode') payload[k] = p[k]; });
        ctx.jobs.armRestart(isoLocal(fireAt), payload, modeLabel).then(function () {
          refs.dispatchLog.append({ text: 'ARMED on the server - fires at ' + fireAt.toLocaleString() + '. You can close this tab; the server holds the wave. Disarm from the red bar across the bottom of the window, or Cancel here.', level: 'mode' });
          refs.dispatchLog.append({ text: 'The arm is held in server memory only: it is discarded (never fired) if the admin session ends or the server restarts.', level: 'dim' });
          refs.runbar.setActive(true);            // morph the CTA to Cancel
          refs.cancelBtn.disabled = false;
          watchArm();
        }).catch(function (e) {
          var msg = (e && e.status === 403) ? 'the server refused the arm: an admin session is required.'
                  : (e && e.status === 409) ? 'a restart wave is already armed on the server - disarm it first.'
                  : ('the server refused the arm (' + ((e && e.message) || 'error') + ').');
          refs.runbar.setActive(false);
          refs.runbar.setStatus('Arm refused.', 'st-bad');
          refs.dispatchLog.append({ text: 'NOT armed - ' + msg + ' Nothing is scheduled and nothing will reboot.', level: 'err' });
        });
      }

      // Follow the server-held arm: paint the countdown, and notice the moment it
      // leaves the server (it fired, or somebody disarmed it from any tab).
      function watchArm() {
        if (armWatchUnsub) { armWatchUnsub(); armWatchUnsub = null; }
        if (armTimer) { clearInterval(armTimer); armTimer = null; }
        armTimer = setInterval(function () {
          var s = ctx.jobs.secondsLeft();
          if (s == null || !refs.runbar) return;
          refs.runbar.setStatus('ARMED on the server - starts in ' + hms(s), 'st-info');
        }, 1000);
        armWatchUnsub = ctx.jobs.onChange(function (st) {
          if (st.armed) return;                       // still waiting
          if (armWatchUnsub) { armWatchUnsub(); armWatchUnsub = null; }
          if (armTimer) { clearInterval(armTimer); armTimer = null; }
          // The arm is gone. Either the server fired it (a dispatch job exists now -
          // adopt its stream, which never re-runs anything) or it was stood down.
          var h = ctx.adopt('dispatch-restart', { keyOf: function (ev) { return ev.Host; } });
          if (h) {
            refs.dispatchLog.banner('Armed dispatch FIRED on the server - streaming results.');
            dispatchRun = h;
            if (dispatchUnsub) dispatchUnsub();
            dispatchUnsub = h.subscribe(dispatchHandlers(null));
          } else {
            refs.runbar.setActive(false);
            refs.runbar.setStatus('Armed dispatch stood down.', 'st-warn');
            if (refs.cancelBtn) refs.cancelBtn.disabled = true;
            refs.dispatchLog.append({ text: 'The armed dispatch is no longer held by the server (disarmed, expired, or the server restarted). Nothing was dispatched.', level: 'warn' });
          }
        });
      }

      // Stand a server-held arm down; returns true if there was one to stand down.
      // Any tab can do this, and so can the red DISARM button in the shell bar.
      function cancelArm() {
        // A LIVE dispatch always wins the Cancel button: never let "Cancel Pending"
        // silently disarm some other armed wave while a wave is actually running.
        if (dispatchRun && dispatchRun.state && dispatchRun.state.active) return false;
        if (!ctx.jobs || !ctx.jobs.state.armed) return false;
        if (armTimer) { clearInterval(armTimer); armTimer = null; }
        if (refs.runbar) refs.runbar.setStatus('Disarming...', 'st-warn');
        ctx.jobs.disarm().then(function () {
          if (armWatchUnsub) { armWatchUnsub(); armWatchUnsub = null; }
          if (refs.runbar) { refs.runbar.setActive(false); refs.runbar.setStatus('Delayed start disarmed.', 'st-warn'); }
          if (refs.cancelBtn) refs.cancelBtn.disabled = true;
          if (refs.dispatchLog) refs.dispatchLog.append({ text: 'Armed dispatch disarmed before it fired - nothing was dispatched.', level: 'warn' });
        }).catch(function () {
          if (refs.dispatchLog) refs.dispatchLog.append({ text: 'Could not reach the server to disarm - check the JANET Web console window and retry.', level: 'err' });
        });
        return true;
      }

      // Re-attach to a dispatch this server is ALREADY running: the page was
      // reloaded, this is a second tab, or an armed wave fired while the browser
      // was closed. Status only - ctx.adopt subscribes to the existing event
      // stream and never re-POSTs the action, so nothing can be double-dispatched.
      function reattachOrWatchArm() {
        if (!ctx.jobs) return;
        if (ctx.jobs.state.armed) {
          tabs.select('dispatch');                       // builds the panel so the refs exist
          if (refs.runbar) refs.runbar.setActive(true);  // CTA morphs to Cancel (= disarm)
          if (refs.cancelBtn) refs.cancelBtn.disabled = false;
          if (refs.dispatchLog) refs.dispatchLog.banner('A restart wave is ARMED on this server - see the red bar across the bottom of the window.');
          watchArm();
          return;
        }
        if (!ctx.jobs.findJob('restart', 'dispatch-restart')) return;
        tabs.select('dispatch');   // builds the panel so the grid/log refs exist
        var h = ctx.adopt('dispatch-restart', { keyOf: function (ev) { return ev.Host; } });
        if (!h) return;
        dispatchRun = h;
        if (dispatchUnsub) dispatchUnsub();
        dispatchUnsub = h.subscribe(dispatchHandlers(null));
        refs.dispatchLog.banner('Re-attached to a dispatch already running on this server.');
        refs.dispatchLog.append({ text: 'This is the live status of a run that is already going - nothing was re-dispatched. Use Cancel to stop it.', level: 'mode' });
      }

      function launchDispatch(p, hosts, modeLabel) {
        // reset the run surface
        refs.dispatchGrid.clear();
        refs.dispatchProg.reset();
        recomputeStats();
        refs.dispatchLog.banner((p.dryRun ? 'DRY RUN - ' : '') + 'Dispatch armed: ' + hosts.length + ' host(s), ' + modeLabel);
        refs.dispatchLog.append({ text: 'Concurrency ' + p.threads + ' | consent ' + (p.requireConsent ? 'on' : 'off') + ' | dry-run ' + p.dryRun, level: 'mode' });

        dispatchRun = ctx.run('dispatch-restart', p, { keyOf: function (ev) { return ev.Host; } });
        if (dispatchUnsub) dispatchUnsub();
        dispatchUnsub = dispatchRun.subscribe(dispatchHandlers(p));
      }

      // The dispatch stream handlers, shared by a run this tab STARTED (p = the
      // params) and one it merely ADOPTED - a server-fired armed wave or a run that
      // outlived a page reload (p = null, so the post-run auto-monitor, which needs
      // to know whether the run was a dry run, stays off).
      function dispatchHandlers(p) {
        return {
          status: function (t) { refs.dispatchProg.setPhase(t); },
          progress: function (pp) { refs.dispatchProg.setProgress(pp.done, pp.total); },
          row: function (r) {
            refs.dispatchGrid.upsert(r);
            recomputeStats();                 // recompute the 9 cells from the live grid
            refreshDispatchButtons();
            logDispatchRow(r);
          },
          log: function (l) { refs.dispatchLog.append(l); },
          error: function (e) { refs.dispatchLog.append({ text: e.text, level: 'err' }); },
          final: function (res) {
            recomputeStats();
            var sm = (res && res.summary) || {};
            refs.dispatchLog.banner('Dispatch complete: ' + (sm.sent || 0) + ' sent, ' + (sm.declined || 0) + ' declined, ' + (sm.failed || 0) + ' failed, ' + (sm.skipped || 0) + ' skipped-server' + ((sm.dryRun || 0) ? ', ' + sm.dryRun + ' dry-run' : '') + ((sm.noPending || 0) ? ', ' + sm.noPending + ' no-pending' : '') + '.');
            refreshDispatchButtons();
            // auto-open the Reboot Verification Monitor on a real run that dispatched at least one host
            var dispatched = refs.dispatchGrid.rows().filter(function (r) { var s = String(r.Status); return s === 'Dispatched' || s === 'Already-Scheduled'; }).map(function (r) { return r.Host; });
            if (p && !p.dryRun && dispatched.length && refs.autoMonitor && refs.autoMonitor._cb.checked) {
              refs.dispatchLog.append({ text: 'Auto-opening Reboot Verification Monitor for ' + dispatched.length + ' dispatched host(s)...', level: 'accent' });
              tabs.select('verify');
              doVerify(dispatched);
            } else if (p && !p.dryRun && (sm.sent || 0) > 0) {
              refs.dispatchLog.append({ text: 'Tip: open Reboot Verification to confirm the fleet actually went down and came back.', level: 'accent' });
            } else if (!p && dispatched.length) {
              refs.dispatchLog.append({ text: 'Tip: open Reboot Verification to confirm these ' + dispatched.length + ' host(s) went down and came back.', level: 'accent' });
            }
          },
          active: function (a) {
            refs.runbar.setActive(a);
            refs.cancelBtn.disabled = !a;
            refreshDispatchButtons();
          }
        };
      }

      function logDispatchRow(r) {
        if (!refs.dispatchLog) return;
        var b = dispatchBucket(r.Status), lvl, tag;
        switch (b) {
          case 'sent': lvl = 'ok'; tag = (r.Status === 'Already-Scheduled') ? 'ALREADY' : 'SENT'; break;
          case 'declined': lvl = 'warn'; tag = 'DECLINED'; break;
          case 'aborted': lvl = 'warn'; tag = 'ABORTED'; break;
          // audit 2026-07-24: a watchdog-abandoned host gets its own TIMEOUT tag; it used
          // to hit the 'Pending' default below and never reach the log at all.
          case 'failed': lvl = 'err'; tag = (r.Status === 'Unreachable') ? 'UNREACHABLE' : (r.Status === 'Timeout') ? 'TIMEOUT' : 'FAIL'; break;
          case 'skipped': lvl = 'dim'; tag = (r.Status === 'Cancelled') ? 'CANCELLED' : 'SKIPPED'; break;
          case 'consent': lvl = 'info'; tag = 'PROMPT'; break;
          case 'inflight': lvl = 'info'; tag = 'IN-FLIGHT'; break;
          default: return;   // Pending - no log line (avoid noise)
        }
        refs.dispatchLog.append({ text: '[' + r.Host + '] ' + tag + (r.Result ? ': ' + r.Result : ''), level: lvl });
      }

      function refreshDispatchButtons() {
        if (!refs.dispatchGrid) return;
        var active = !!(dispatchRun && dispatchRun.state && dispatchRun.state.active);
        if (refs.cancelBtn) refs.cancelBtn.disabled = !active;
        // Abort enabled once any host actually received a restart command
        var anyDispatched = refs.dispatchGrid.rows().some(function (r) { var s = String(r.Status); return s === 'Dispatched' || s === 'Already-Scheduled'; });
        if (refs.abortBtn) refs.abortBtn.disabled = !anyDispatched || (abortRun && abortRun.state && abortRun.state.active);
      }

      // ---- ABORT already-dispatched (destructive) ----
      async function doAbort() {
        if (!refs.dispatchGrid) return;
        var dispatched = refs.dispatchGrid.rows().filter(function (r) { var s = String(r.Status); return s === 'Dispatched' || s === 'Already-Scheduled'; });
        if (!dispatched.length) { ctx.confirm({ title: 'Nothing to abort', body: 'No host has received a restart command yet.', okText: 'OK', cancelText: null }); return; }
        if (!ctx.session.state.credSet) { ctx.confirm({ title: 'No Credentials', body: 'Set your ADW credential (top-right) before aborting - it changes machines.', okText: 'OK', cancelText: null }); return; }
        var hosts = dispatched.map(function (r) { return r.Host; });
        var ok = await ctx.arm({
          title: 'Abort Scheduled Restarts',
          banner: 'Send shutdown /a to cancel pending restart timers',
          body: 'Send <b>shutdown /a</b> to <b>' + hosts.length + '</b> already-dispatched host(s) to stand them down before they reboot?',
          preflight: [{ label: hosts.length + ' dispatched host(s) to abort', ok: true }],
          confirmWord: 'ABORT', okText: 'Abort Now', cancelText: 'Cancel'
        });
        if (!ok) return;
        refs.dispatchLog.banner('Aborting ' + hosts.length + ' host(s) (shutdown /a)...');
        var aborted = 0, failedA = 0;
        abortRun = ctx.run('abort-scheduled', { targets: hosts.join('\n'), threads: 32 }, { keyOf: function (ev) { return ev.Host; } });
        if (abortUnsub) abortUnsub();
        abortUnsub = abortRun.subscribe({
          status: function (t) { refs.dispatchProg.setPhase(t); },
          row: function (r) {
            var done = (r.Status === 'Aborted');
            if (done) aborted++; else failedA++;
            // reflect the abort back into the dispatch grid (same Host key)
            refs.dispatchGrid.upsert({ Host: r.Host, Status: r.Status, Result: r.Result });
            recomputeStats();
            refs.dispatchLog.append({ text: '[' + r.Host + '] ' + (done ? 'ABORT OK' : 'ABORT FAIL') + (r.Result ? ': ' + r.Result : ''), level: done ? 'ok' : 'err' });
          },
          log: function (l) { refs.dispatchLog.append(l); },
          final: function () { refs.dispatchLog.banner('Abort complete: ' + aborted + ' aborted, ' + failedA + ' failed.'); refreshDispatchButtons(); },
          active: function (a) { if (refs.abortBtn) refs.abortBtn.disabled = a || !refs.dispatchGrid.rows().some(function (r) { var s = String(r.Status); return s === 'Dispatched' || s === 'Already-Scheduled'; }); }
        });
      }

      // ---- VERIFY REBOOTS (reboot monitor) ----
      // hostsOverride: when auto-opened after a dispatch, monitor exactly the
      // dispatched hosts; otherwise monitor the whole target list.
      function doVerify(hostsOverride) {
        var hosts = (hostsOverride && hostsOverride.length) ? hostsOverride : (refs.targets ? refs.targets.hosts() : targetsModel.hosts());
        refs.verifyGrid.clear();
        refs.verifyProg.reset();
        refs.verifyLog.banner('Reboot monitor: ' + hosts.length + ' host(s)');
        var params = {
          targets: hosts.join('\n'),
          pingIntervalSeconds: intOf(refs.verifyInterval, 15, 3, 600),
          timeoutSeconds: intOf(refs.verifyTimeout, 1800, 10, 86400),
          threads: intOf(refs.verifyThreads, 32, 1, 64)
        };
        verifyRun = ctx.run('verify-reboots', params, { keyOf: function (ev) { return ev.Host; } });
        if (verifyUnsub) verifyUnsub();
        verifyUnsub = verifyRun.subscribe({
          status: function (t) { refs.verifyProg.setPhase(t); },
          progress: function (pp) { refs.verifyProg.setProgress(pp.done, pp.total); },
          row: function (r) {
            refs.verifyGrid.upsert(r);
            var st = String(r.State || '');
            var lvl = /^Rebooted/i.test(st) ? 'ok' : /^No contact/i.test(st) ? 'err' : /^Online/i.test(st) ? 'warn' : /^Cancelled/i.test(st) ? 'warn' : 'info';
            refs.verifyLog.append({ text: '[' + r.Host + '] ' + st + (r['Came-Back'] ? ' (back ' + r['Came-Back'] + ')' : ''), level: lvl });
          },
          log: function (l) { refs.verifyLog.append(l); },
          error: function (e) { refs.verifyLog.append({ text: e.text, level: 'err' }); },
          final: function (res) {
            var sm = (res && res.summary) || {};
            refs.verifyLog.banner('Monitor finished: ' + (sm.rebooted || 0) + ' rebooted, ' + (sm.notConfirmed || 0) + ' not confirmed of ' + (sm.total || 0) + '.');
          },
          active: function (a) { refs.verifyRunbar.setActive(a); }
        });
      }

      // ---- VERIFY (WinRM boot time) ----
      // Authoritative reboot confirmation: query LastBootUpTime over WinRM and
      // overwrite each host's ping-inferred verdict (the grid keys by Host, so the
      // boot-time row merges onto + trumps the ping row). Compares boot time to the
      // Config-tab Restart time; blank reference = report boot time without a verdict.
      function doVerifyBootTime() {
        var hosts = refs.targets ? refs.targets.hosts() : targetsModel.hosts();
        if (!hosts.length) { ctx.confirm({ title: 'No Targets', body: 'Add at least one hostname on the Targets / Config tab.', okText: 'OK', cancelText: null }); return; }
        var ref = refs.restartTime ? refs.restartTime.value.trim() : '';
        if (refs.verifyLog) refs.verifyLog.banner('WinRM boot-time verify: ' + hosts.length + ' host(s)' + (ref ? (' vs restart @ ' + ref) : ' (no reference time)'));
        var params = { targets: hosts.join('\n'), referenceTime: ref, threads: intOf(refs.verifyThreads, 32, 1, 64) };
        bootRun = ctx.run('verify-boottime', params, { keyOf: function (ev) { return ev.Host; } });
        if (bootUnsub) bootUnsub();
        bootUnsub = bootRun.subscribe({
          status: function (t) { refs.verifyProg.setPhase(t); },
          progress: function (pp) { refs.verifyProg.setProgress(pp.done, pp.total); },
          row: function (r) {
            refs.verifyGrid.upsert(r);
            var st = String(r.State || '');
            var lvl = /^RESTARTED/i.test(st) ? 'ok' : /^Did NOT/i.test(st) ? 'err' : /failed/i.test(st) ? 'warn' : 'info';
            refs.verifyLog.append({ text: '[' + r.Host + '] ' + st, level: lvl });
          },
          log: function (l) { refs.verifyLog.append(l); },
          error: function (e) { refs.verifyLog.append({ text: e.text, level: 'err' }); },
          final: function (res) {
            var sm = (res && res.summary) || {};
            refs.verifyLog.banner('Boot-time verify: ' + (sm.restarted || 0) + ' restarted, ' + (sm.notRestarted || 0) + ' did-not-restart, ' + (sm.online || 0) + ' online, ' + (sm.failed || 0) + ' failed of ' + (sm.total || 0) + '.');
          },
          active: function (a) { if (refs.bootBtn) refs.bootBtn.disabled = a; }
        });
      }

      // =====================================================================
      //  EXPORTS
      // =====================================================================
      function exportDispatchCsv() {
        if (!refs.dispatchGrid) return;
        var rows = refs.dispatchGrid.rows();
        if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Run a dispatch first - there are no result rows yet.', okText: 'OK', cancelText: null }); return; }
        ctx.util.downloadBlob('RRS_DispatchResults_' + ctx.util.fileStamp() + '.csv', 'text/csv', ctx.util.toCsv(['Host', 'Status', 'DispatchAt', 'RestartAt', 'ConsentState', 'Result'], rows));
      }
      function exportVerifyCsv() {
        if (!refs.verifyGrid) return;
        var rows = refs.verifyGrid.rows();
        if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Run the reboot monitor first - there are no rows yet.', okText: 'OK', cancelText: null }); return; }
        ctx.util.downloadBlob('RRS_RebootVerify_' + ctx.util.fileStamp() + '.csv', 'text/csv', ctx.util.toCsv(['Host', 'State', 'Went-Down', 'Came-Back', 'Boot-Time', 'Result'], rows));
      }

      // =====================================================================
      host.appendChild(root);

      // On mount, ask the server what it is already doing for this tool: a wave
      // armed earlier (possibly from another tab / before a reload) or a dispatch
      // still streaming. Neither one starts anything - see reattachOrWatchArm.
      if (ctx.jobs) { ctx.jobs.refresh().then(reattachOrWatchArm).catch(function () {}); }

      this._root = root;
      this._unsub = function () {
        // Only the local countdown paint and the arm listener are torn down here.
        // The ARM ITSELF lives on the server and deliberately survives this view
        // being unmounted, the tab being closed, and the browser being shut.
        try { if (armWatchUnsub) { armWatchUnsub(); armWatchUnsub = null; } } catch (e) {}
        try { if (armTimer) { clearInterval(armTimer); armTimer = null; } } catch (e) {}
        try { if (dispatchUnsub) dispatchUnsub(); } catch (e) {}
        try { if (verifyUnsub) verifyUnsub(); } catch (e) {}
        try { if (bootUnsub) bootUnsub(); } catch (e) {}
        try { if (abortUnsub) abortUnsub(); } catch (e) {}
        try { if (pingUnsub) pingUnsub(); } catch (e) {}
        try { if (testUnsub) testUnsub(); } catch (e) {}
      };
    },
    unmount: function () {
      try { if (this._unsub) this._unsub(); } catch (e) {}
      if (this._root) this._root.remove();
    }
  });
})();
