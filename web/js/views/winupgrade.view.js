/* ============================================================================
   winupgrade.view.js  -  Windows Upgrade Tool (tool id: 'winupgrade')  v0.3.0
   Faithful single-window (non-tabbed) re-build per docs/ui-specs/winupgrade.md:
   a left config column (Scenario chooser -> Operation radios -> per-op inputs ->
   Guide hand-holding -> Options) beside a colour-coded per-host Results grid,
   with a sticky footer carrying progress, count, Export CSV and a streaming
   ActivityLog. The operator picks a scenario or operation, optionally sets the
   universal credential (shell header), pastes/imports computers, then PINGs or
   RUNs (Pin / Unpin / Install CAB).

   The engine fans out one worker per host and streams one final row per host
   ({ Host, Ping, Status, Detail }); rows are keyed by Host. installcab is
   destructive (firmware/OS feature change) -> guarded on an admin session
   (ctx.session.state.credSet) + a reboot-warning ctx.confirm. ALL server I/O
   goes through ctx.run -> RunController; the view never fetches/polls.

   Credentials are UNIVERSAL (shell header top-right) - this view renders NO
   per-tool credential control; it only READS ctx.session.state.credSet.
   ========================================================================== */
(function () {
  'use strict';

  // engine row events are keyed 'Host'; CSV header keeps the desktop label 'Computer'.
  var EXPORT_COLS = [['Host', 'Computer'], ['Ping', 'Ping'], ['Status', 'Status'], ['Detail', 'Detail']];

  // Operation metadata: radio value -> action id, label, plain-language Guide copy.
  var OPS = {
    pin: {
      action: 'pin',
      radio: 'Pin to a feature version (stay on / hold at)',
      guide: function (product, version) {
        return 'PIN holds these PCs at a feature version using the Windows Update for Business "Target Release Version" policy '
          + '(Product "' + (product || 'Windows 11') + '", Version "' + (version || '24H2') + '").\n\n'
          + 'This is the gpedit policy: Computer Configuration > Administrative Templates > Windows Components > Windows Update > '
          + 'Manage updates offered from Windows Update > "Select the Target Feature Update" = Enabled, set to this Product + Version.\n\n'
          + 'Windows still offers monthly quality fixes, but it will NOT move the PC to a newer feature build until you Unpin. '
          + 'Pin sets a CEILING - it does not push the install; each PC applies the pin on its next Windows Update / MECM check. '
          + 'Tick "Also trigger a Windows Update scan" to kick the agent now (the "then run Windows Update" step).';
      }
    },
    unpin: {
      action: 'unpin',
      radio: 'Unpin (remove the version hold)',
      guide: function () {
        return 'UNPIN removes the Target Release Version policy so the PC follows its normal Windows Update path again and can '
          + 'move to newer feature builds.\n\n'
          + 'Use this to reverse a Pin - e.g. run Unpin FIRST before pushing the 25H2 update to a fleet that was pinned to 24H2 '
          + '(keeps the WU policy consistent; a CAB install works regardless of the pin).';
      }
    },
    installcab: {
      action: 'installcab',
      radio: 'Install a feature update package (CAB/MSU via DISM)',
      guide: function () {
        return 'INSTALL copies a feature-update .cab/.msu (e.g. the 25H2 enablement package KB5054156) to C:\\Temp on each target '
          + 'and installs it with DISM /Online /Add-Package, optionally rebooting ~10s after a successful install.\n\n'
          + 'A CAB install changes the build directly and IGNORES a Pin - if the fleet is pinned to 24H2, run Unpin FIRST to keep '
          + 'the WU policy consistent.\n\nThis is a firmware/OS feature change: an admin session is required, and ticked targets '
          + 'will REBOOT shortly after a successful install unless this is a Dry-run.';
      }
    },
    setpagefile: {
      action: 'setpagefile',
      radio: 'Set page file (fix upgrade memory exhaustion)',
      guide: function (sizeMb) {
        var gb = Math.round((parseInt(sizeMb, 10) || 16384) / 1024);
        return 'SET PAGE FILE fixes the in-place upgrade "out of memory" failure (0x8007000E in setuperr.log). It disables '
          + 'Windows automatic page-file management and sets the C: page file to a FIXED size (' + (sizeMb || 16384) + ' MB / ~' + gb + ' GB), '
          + 'then reboots to apply (a restart is REQUIRED for the new size to take effect).\n\n'
          + 'Manual equivalent: sysdm.cpl > Advanced > Performance Settings > Advanced > Virtual memory > Change, untick '
          + '"Automatically manage", set a custom size, restart.\n\n'
          + 'Workflow: run Check Errors first; on the hosts it flags MEMORY, run this, then re-run the feature update. '
          + 'This changes machine config: an admin session is required (or tick Dry-run).';
      }
    },
    diagnose: {
      action: 'diagnose',
      radio: 'Run Diagnostic Scan (read-only compatibility + policy check)',
      guide: function () {
        return 'DIAGNOSE runs a comprehensive READ-ONLY scan on each PC and changes NOTHING. It reports:\n\n'
          + '  - System info + current OS build (24H2 = build 26100+).\n'
          + '  - Hardware compatibility: CPU (supported-model list), TPM 2.0+, Secure Boot, RAM (4 GB+), disk (64 GB+ free).\n'
          + '  - Registry state: the Target Release Version policy and the CPU/TPM MoSetup bypass.\n'
          + '  - Deferrals + blocks: DeferFeatureUpdates, DisableDualScan, pause windows, WSUS mode.\n'
          + '  - Windows Update health (services, SoftwareDistribution) and SCCM client + 24H2 deployment visibility.\n\n'
          + 'Each host gets a one-word STATUS verdict (ON 24H2 / READY / NEEDS POLICY / BLOCKED / HW INCOMPAT) and the FULL '
          + 'multi-line report streams into the Activity Log, colour-coded by [PASS]/[FAIL]/[WARN]/[BLOCK]/[REC]/[INFO]. '
          + 'Read-only: no admin session or Dry-run needed - run it first to see the picture before acting.';
      }
    },
    forcediscovery: {
      action: 'forcediscovery',
      radio: 'Force Update Discovery (safe re-scan, or Aggressive WU reset)',
      guide: function (product, version, aggressive) {
        var head = 'FORCE DISCOVERY re-applies the Target Release Version policy (Product "' + (product || 'Windows 11')
          + '", Version "' + (version || '24H2') + '") then forces the update agent to look again.\n\n';
        var safe = 'SAFE mode (default): re-apply the policy, REPORT (but do NOT remove) any deferrals, trigger the SCCM client '
          + 'cycles, refresh Group Policy (gpupdate /force), and kick a WU + UsoClient StartScan. Status DONE.\n\n';
        var aggr = 'AGGRESSIVE mode: additionally REMOVES deferral/pause policy values, STOPS the WU services, renames '
          + 'SoftwareDistribution + catroot2 (cache clear), RE-REGISTERS the WU DLLs, restarts the services, re-applies the '
          + 'policy and re-scans. Status RESET. Use only if safe mode does not surface the build.\n\n';
        var foot = 'Destructive - an admin session is required unless Dry-run (Dry-run reports the intended steps and changes nothing).';
        return head + safe + aggr + (aggressive ? '>> Aggressive is currently TICKED.\n\n' : '') + foot;
      }
    }
  };

  // Scenario presets (mirror the desktop Scenario combo + Apply-Scenario seeding).
  var SCENARIOS = [
    { value: 'manual', label: '-- Manual (pick an operation below) --' },
    {
      value: '24h2', label: '24H2 upgrade  -  Pin to Windows 11 24H2',
      op: 'pin', product: 'Windows 11', version: '24H2', reboot: true,
      guide: 'SCENARIO: Upgrade the fleet to Windows 11 24H2.\n\n'
        + '  1. Pin Product "Windows 11" Version "24H2" (sets the feature-update ceiling).\n'
        + '  2. Let Windows Update / MECM offer and install 24H2 on each PC (reboot + Check for updates applies it promptly).\n'
        + '  3. Once the fleet is on 24H2 you may Unpin (optional) to resume the normal ring.\n\n'
        + 'This screen performs step 1. Add your computers, then RUN.'
    },
    {
      value: '25h2', label: '25H2 update  -  Install KB5054156 (25H2 enablement)',
      op: 'installcab', reboot: true,
      guide: 'SCENARIO: Install the 25H2 enablement package (KB5054156).\n\n'
        + '  1. If the fleet is pinned to 24H2, run Unpin FIRST so the WU policy stays consistent.\n'
        + '  2. Point CAB/MSU at the 25H2 enablement package (path on this admin box / a share, or Browse to upload).\n'
        + '  3. RUN Install CAB - DISM /Add-Package installs it; ticked targets reboot ~10s after success.\n\n'
        + 'This screen performs step 2-3 (Install CAB + Reboot pre-ticked). Add your computers, then RUN.'
    }
  ];

  function statusCellCls(v) {
    switch (String(v)) {
      // green: success / already-good verdicts.
      // ON 24H2 = already on the target build; READY = compatible + policy in place;
      // DONE = safe force-discovery ok; RESET = aggressive force-discovery ok.
      case 'DONE':
      case 'RESET':
      case 'READY':
      case 'ON 24H2':
      case 'CLEAN':
      case 'DRIVEN':
      case 'Online': return 'st-ok';
      // live in-progress phases streamed by the engine's step queue
      case 'Working':
      case 'Copying':
      case 'DISM':
      case 'Pinning':
      case 'Unpinning':
      case 'Scanning':
      case 'Reading':
      case 'PageFile':
      case 'Triggering':
      case 'Checking':
      case 'REBOOTING':
      case 'Rebooting': return 'st-info';
      case 'Pinged': return 'cell-dim';
      case 'NO LOG': return 'cell-dim';
      case 'Queued': return 'cell-dim';
      case 'FAILED':
      case 'Offline': return 'st-bad';
      // amber: needs operator attention but not a hard failure.
      // DRY-RUN = preview only; NEEDS POLICY = target-version policy missing;
      // BLOCKED = a deferral/pause is holding the build back; HW INCOMPAT = CPU/TPM fails + no bypass;
      // MEMORY = setuperr.log out-of-memory hit (run Set Page File); ERRORS = other setup error;
      // NEEDS REBOOT = change applied but a restart is still pending.
      case 'DRY-RUN':
      case 'NEEDS POLICY':
      case 'BLOCKED':
      case 'HW INCOMPAT':
      case 'MEMORY':
      case 'ERRORS':
      case 'NEEDS REBOOT':
      case 'STAGED':
      case 'Skipped':
      case 'Cancelled': return 'st-warn';
      default: return '';
    }
  }
  function pingCellCls(v) {
    var s = String(v == null ? '' : v);
    if (s === '' ) return '';
    if (/^\d/.test(s)) return 'st-ok';                 // "<n> ms"
    if (/unreach|offline/i.test(s)) return 'st-bad';
    if (/dns|error/i.test(s)) return 'st-warn';
    return 'cell-dim';
  }
  // Fleet Status board: colour the single Win24H2Status verdict.
  //   Ready = ok/green ; Blocked = bad/red ; Already 24H2+ = accent/cyan ;
  //   Pending reboot = warn/amber ; Offline/Error dim/red.
  function fleetStatusCell(v) {
    var s = String(v == null ? '' : v);
    if (s === 'Ready') return { text: s, cls: 'st-ok' };
    if (s.indexOf('Blocked') === 0) return { text: s, cls: 'st-bad', title: s };
    if (s === 'Already 24H2+') return { text: s, cls: 'st-info' };
    if (s === 'Pending reboot') return { text: s, cls: 'st-warn' };
    if (s === 'Offline') return { text: s, cls: 'st-bad' };
    if (s === 'Error') return { text: s, cls: 'st-warn' };
    if (s === 'Queued') return { text: s, cls: 'cell-dim' };
    return { text: s, cls: '' };
  }
  function yesNoDim(v, badWhenYes) {
    var yes = (v === true || String(v).toLowerCase() === 'true' || String(v) === 'Yes');
    if (v == null || v === '') return { text: '', cls: 'cell-dim' };
    return { text: yes ? 'Yes' : 'No', cls: yes ? (badWhenYes ? 'st-bad' : 'st-ok') : 'cell-dim' };
  }

  JanetViews.register('winupgrade', {
    mount: function (host, ctx) {
      var ui = ctx.ui, C = ctx.components, el = ctx.util.el;

      // ---- run/result state ----
      var run = null, unsub = null;
      var applyingScenario = false;     // guards the scenario<->radio bidirectional link
      var uploadedCabPath = null;       // server temp path returned by ctx.uploadFile
      var uploadedCabName = '';
      var currentOp = 'pin';

      // =================== layout ===================
      var root = el('div'); root.style.cssText = 'display:flex;flex-direction:column;height:100%;min-height:0;background:var(--bg)';

      // The existing operation console lives in opsPanel; a TabHost (built at the
      // bottom of mount) puts a read-only "Fleet Status" board FIRST, then this
      // "Operations" tab, sharing the one Activity Log dock across the bottom.
      var opsPanel = el('div'); opsPanel.style.cssText = 'flex:1;min-height:0;display:flex;flex-direction:column';

      var body = el('div'); body.style.cssText = 'flex:1;min-height:0;display:flex;gap:14px;padding:14px 16px 0';
      opsPanel.appendChild(body);

      // ---------- LEFT: CONFIG COLUMN ----------
      var left = el('div'); left.style.cssText = 'flex:0 0 440px;display:flex;flex-direction:column;gap:12px;min-height:0;overflow:auto';
      body.appendChild(left);

      // --- Scenario ---
      var scenarioCard = sectionCard('SCENARIO');
      scenarioCard.appendChild(ui.label("I'm doing:"));
      var scenarioSelect = ui.select({
        options: SCENARIOS.map(function (s) { return { value: s.value, label: s.label }; }),
        value: 'manual', onChange: onScenarioPick
      });
      scenarioSelect.style.width = '100%';
      scenarioCard.appendChild(scenarioSelect);
      left.appendChild(scenarioCard);

      // --- Operation ---
      var opCard = sectionCard('OPERATION');
      var opRadios = {};
      ['diagnose', 'pin', 'unpin', 'forcediscovery', 'installcab', 'setpagefile'].forEach(function (k) {
        var rowWrap = el('label'); rowWrap.style.cssText = 'display:flex;align-items:flex-start;gap:8px;margin:4px 0;cursor:pointer';
        var rb = el('input'); rb.type = 'radio'; rb.name = 'winupg-op'; rb.value = k; rb.style.marginTop = '3px';
        rb.checked = (k === 'pin');
        rb.addEventListener('change', function () { if (rb.checked) onOpChanged(k); });
        opRadios[k] = rb;
        var txt = el('span', null, OPS[k].radio); txt.style.cssText = 'font-size:13px;color:var(--text)';
        rowWrap.appendChild(rb); rowWrap.appendChild(txt);
        opCard.appendChild(rowWrap);

        // Pin inputs (Product / Version) sit under the Pin radio.
        if (k === 'pin') {
          var pinInputs = el('div'); pinInputs.style.cssText = 'display:flex;gap:10px;margin:2px 0 6px 24px';
          var prodInput = ui.input({ value: 'Windows 11', title: 'Windows Update for Business ProductVersion value, e.g. "Windows 11".' });
          prodInput.style.width = '150px';
          var verInput = ui.input({ value: '24H2', title: 'TargetReleaseVersionInfo value, e.g. "24H2" - the build to hold at.' });
          verInput.style.width = '90px';
          prodInput.addEventListener('input', function () { if (!applyingScenario && currentOp === 'pin') refreshGuide(); });
          verInput.addEventListener('input', function () { if (!applyingScenario && currentOp === 'pin') refreshGuide(); });
          pinInputs.appendChild(ui.field('Product', prodInput));
          pinInputs.appendChild(ui.field('Version', verInput));
          opCard.appendChild(pinInputs);
          var runWuCb = ui.checkbox('Also trigger a Windows Update scan after pinning', { title: 'After writing the policy, kick the WU agent (Scheduled Start task) so the pinned build is detected sooner - the "then run Windows Update" step.' });
          runWuCb.style.cssText += ';margin:0 0 6px 24px';
          opCard.appendChild(runWuCb);
          var sccmRefreshCb = ui.checkbox('Also refresh the SCCM / MECM client (pull policy so Software Center updates)', { title: 'After the policy write (and WU scan), trigger the 5 SCCM client schedule cycles so the client pulls machine policy and any assigned 24H2 deployment surfaces in Software Center.' });
          sccmRefreshCb.style.cssText += ';margin:0 0 6px 24px';
          opCard.appendChild(sccmRefreshCb);
          var bypassCb = ui.checkbox('Apply CPU/TPM bypass for unsupported hardware (MoSetup)', { color: 'var(--warn)', title: 'Sets HKLM\\SYSTEM\\Setup\\MoSetup\\AllowUpgradesWithUnsupportedTPMOrCPU = 1. Microsoft-unsupported config - devices may not receive all updates. Only needed when the CPU/TPM fail the diagnostic.' });
          bypassCb.style.cssText += ';margin:0 0 6px 24px';
          opCard.appendChild(bypassCb);
          opCard._prodInput = prodInput; opCard._verInput = verInput; opCard._pinInputs = pinInputs; opCard._runWuCb = runWuCb;
          opCard._sccmRefreshCb = sccmRefreshCb; opCard._bypassCb = bypassCb;
        }

        // Unpin option (remove the MoSetup bypass too) sits under the Unpin radio.
        if (k === 'unpin') {
          var unpinWrap = el('div'); unpinWrap.style.cssText = 'margin:2px 0 4px 24px;display:flex;flex-direction:column;gap:6px';
          var removeBypassCb = ui.checkbox('Also remove the CPU/TPM bypass key (MoSetup)', { checked: true, title: 'Along with the Target Release Version policy, delete HKLM\\SYSTEM\\Setup\\MoSetup\\AllowUpgradesWithUnsupportedTPMOrCPU so the machine returns to a fully-supported update state.' });
          unpinWrap.appendChild(removeBypassCb);
          opCard.appendChild(unpinWrap);
          opCard._removeBypassCb = removeBypassCb; opCard._unpinWrap = unpinWrap;
        }

        // Force Discovery inputs (Product / Version / Aggressive) sit under the Force discovery radio.
        if (k === 'forcediscovery') {
          var fdWrap = el('div'); fdWrap.style.cssText = 'margin:2px 0 4px 24px;display:flex;flex-direction:column;gap:6px';
          var fdRow = el('div'); fdRow.style.cssText = 'display:flex;gap:10px';
          var fdProd = ui.input({ value: 'Windows 11', title: 'ProductVersion re-applied by Force Discovery (same as the Pin policy Product).' });
          fdProd.style.width = '150px';
          var fdVer = ui.input({ value: '24H2', title: 'TargetReleaseVersionInfo re-applied by Force Discovery (the build to hold at).' });
          fdVer.style.width = '90px';
          fdProd.addEventListener('input', function () { if (!applyingScenario && currentOp === 'forcediscovery') refreshGuide(); });
          fdVer.addEventListener('input', function () { if (!applyingScenario && currentOp === 'forcediscovery') refreshGuide(); });
          fdRow.appendChild(ui.field('Product', fdProd));
          fdRow.appendChild(ui.field('Version', fdVer));
          fdWrap.appendChild(fdRow);
          var fdAggr = ui.checkbox('Aggressive mode (stop WU services, rename SoftwareDistribution + catroot2, re-register WU DLLs)', { color: 'var(--warn)', title: 'Safe mode re-applies the policy + triggers scans only. Aggressive additionally removes deferrals, clears the WU caches and re-registers the WU DLLs. Use only if safe mode does not surface the build.' });
          fdAggr._cb.addEventListener('change', function () { if (currentOp === 'forcediscovery') refreshGuide(); });
          fdWrap.appendChild(fdAggr);
          opCard.appendChild(fdWrap);
          opCard._fdProdInput = fdProd; opCard._fdVerInput = fdVer; opCard._fdAggressive = fdAggr; opCard._fdWrap = fdWrap;
        }

        // Install CAB inputs (path / Browse-upload / reboot) sit under the Install radio.
        if (k === 'installcab') {
          var cabWrap = el('div'); cabWrap.style.cssText = 'margin:2px 0 4px 24px;display:flex;flex-direction:column;gap:6px';
          var cabPathInput = ui.input({ placeholder: 'C:\\path\\KB5054156.cab  or  \\\\share\\pkg.msu', title: 'Full local or UNC path to the .cab/.msu readable by the machine running JANET Web. OR use Browse to upload one.' });
          cabPathInput.style.width = '100%';
          cabPathInput.addEventListener('input', function () { uploadedCabPath = null; uploadedCabName = ''; updateCabHint(); });
          cabWrap.appendChild(ui.field('CAB / MSU path', cabPathInput));

          var browseRow = el('div'); browseRow.style.cssText = 'display:flex;align-items:center;gap:8px';
          var fileInput = el('input'); fileInput.type = 'file'; fileInput.accept = '.cab,.msu'; fileInput.style.display = 'none';
          var browseBtn = ui.button('Browse / upload...', { variant: 'cyan', size: 'sm', title: 'Pick a .cab/.msu in your browser; it uploads to a server temp path the engine copies to each target (1 GB cap).' });
          browseBtn.onclick = function () { fileInput.value = ''; fileInput.click(); };
          fileInput.addEventListener('change', function () { var f = fileInput.files && fileInput.files[0]; if (f) doUpload(f); });
          var cabHint = el('span', 'muted'); cabHint.style.fontSize = '11px';
          browseRow.appendChild(browseBtn); browseRow.appendChild(fileInput); browseRow.appendChild(cabHint);
          cabWrap.appendChild(browseRow);

          var rebootLbl = ui.checkbox('Reboot target ~10s after a successful install', {
            checked: true, color: 'var(--warn)', title: 'Issues shutdown /r /t 10 after DISM succeeds (skipped on Dry-run / Cancel).'
          });
          cabWrap.appendChild(rebootLbl);
          opCard.appendChild(cabWrap);
          opCard._cabPathInput = cabPathInput; opCard._cabHint = cabHint; opCard._rebootCb = rebootLbl; opCard._cabWrap = cabWrap;
        }

        // Set Page File inputs (size / reboot) sit under the Set page file radio.
        if (k === 'setpagefile') {
          var pfWrap = el('div'); pfWrap.style.cssText = 'margin:2px 0 4px 24px;display:flex;flex-direction:column;gap:6px';
          var pfSize = ui.number({ value: 16384, min: 1024, max: 131072, title: 'Fixed initial = maximum C: page-file size in MB. 16384 = 16 GB.' });
          pfSize.style.width = '110px';
          pfSize.addEventListener('input', function () { if (!applyingScenario && currentOp === 'setpagefile') refreshGuide(); });
          pfWrap.appendChild(ui.field('Page file (MB)', pfSize));
          var pfReboot = ui.checkbox('Reboot target ~10s after setting (required to apply)', { checked: true, color: 'var(--warn)', title: 'A reboot is required for the new page-file size to take effect (skipped on Dry-run / Cancel).' });
          pfWrap.appendChild(pfReboot);
          opCard.appendChild(pfWrap);
          opCard._pfSize = pfSize; opCard._pfReboot = pfReboot; opCard._pfWrap = pfWrap;
        }
      });
      left.appendChild(opCard);

      // --- Guide ---
      var guideCard = sectionCard('GUIDE - what this does / step-by-step', 'cyan');
      var guideBox = ui.textarea({ rows: 7, title: 'Plain-language explanation of the selected scenario / operation.' });
      guideBox.readOnly = true;
      guideBox.style.cssText += ';width:100%;resize:vertical;font-size:12.5px;line-height:1.45';
      guideCard.appendChild(guideBox);
      left.appendChild(guideCard);

      // --- Options ---
      var optCard = sectionCard('OPTIONS');
      var dryCb = ui.checkbox('Dry-run (no changes - reports "Would..." instead of acting)', { color: 'var(--warn)', title: 'Probe + report the intended change without writing the policy or installing the CAB.' });
      optCard.appendChild(dryCb);
      var offlineCb = ui.checkbox('Attempt even if offline (host unreachable)', { title: 'Proceed against a host that fails the TCP 5985/445 reachability probe (e.g. firewalled but WinRM up). Reachability is TCP-only - AFNET drops ICMP.' });
      offlineCb.style.marginTop = '4px';
      optCard.appendChild(offlineCb);
      var threadsRow = el('div'); threadsRow.style.cssText = 'display:flex;align-items:center;gap:10px;margin-top:8px';
      threadsRow.appendChild(ui.label('Max concurrent:'));
      var threadsInput = ui.number({ value: 16, min: 1, max: 64, title: 'Parallel hosts (1-64). Install CAB defaults lower (8) as DISM is heavy.' });
      threadsInput.style.width = '80px';
      threadsRow.appendChild(threadsInput);
      optCard.appendChild(threadsRow);
      left.appendChild(optCard);

      // --- Computers (TargetManager) --- moved to the TOP of the config column; bounded
      // height so Scenario / Operation / Options stay visible below (left column scrolls).
      var compCard = sectionCard('COMPUTERS');
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
      left.insertBefore(compCard, left.firstChild);   // append FIRST, above the SCENARIO card

      // --- Action bar (Test Ping / RUN / Cancel via RunBar) ---
      var actionCard = ui.card({}); actionCard.style.cssText += ';display:flex;flex-direction:column;gap:8px';
      var topBtns = el('div'); topBtns.style.cssText = 'display:flex;gap:8px;align-items:center';
      var pingBtn = ui.button('Test Ping', { variant: 'cyan', size: 'sm', title: 'Reachability sweep across the computer list (changes nothing).' });
      pingBtn.onclick = doPing;
      topBtns.appendChild(pingBtn);
      var checkBtn = ui.button('Check Errors', { variant: 'cyan', size: 'sm', title: 'Read setuperr.log on each computer and flag the out-of-memory upgrade failure 0x8007000E (changes nothing).' });
      checkBtn.onclick = doCheck;
      topBtns.appendChild(checkBtn);
      actionCard.appendChild(topBtns);

      var runbar = C.RunBar({
        label: 'RUN', cancelLabel: 'CANCEL RUN IN PROGRESS', morphToCancel: true,
        title: 'Run the selected operation (Pin / Unpin / Install CAB) across every computer.',
        guards: [
          function () { return targets.count() ? null : 'No Computers|Add at least one computer to the list before running.'; },
          function () {
            if (currentOp !== 'pin') return null;
            var p = (opCard._prodInput.value || '').trim(), v = (opCard._verInput.value || '').trim();
            return (p && v) ? null : 'Pin Needs Product + Version|Pin requires both a Product (e.g. "Windows 11") and a Version (e.g. "24H2").';
          },
          function () {
            if (currentOp !== 'installcab' || dryCb._cb.checked) return null;
            return effectiveCabPath() ? null : 'No CAB / MSU|Enter a readable .cab/.msu path or use Browse to upload one (skipped only on Dry-run).';
          },
          function () {
            if (!OPS[currentOp]) return null;            // ping isn't routed through RUN
            if (currentOp === 'diagnose') return null;   // read-only scan - no admin session (like ping / checkupgrade)
            // destructive ops (pin/unpin/installcab/setpagefile/forcediscovery)
            // require an admin session unless this is a Dry-run.
            if (dryCb._cb.checked) return null;
            return ctx.session.state.credSet ? null : 'Admin Session Required|This operation changes machines (WU policy / DISM / WU reset). Set credentials (top-right) and start an admin session, or tick Dry-run.';
          }
        ],
        onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
        onRun: doRun,
        onCancel: function () { if (run) { run.cancel(); log.append({ text: '[' + ts() + '] CANCEL requested - queued targets will skip; in-flight operations finish.', level: 'warn' }); } }
      });
      var rbWrap = el('div'); rbWrap.appendChild(runbar.el);
      actionCard.appendChild(rbWrap);
      left.appendChild(actionCard);

      // ---------- RIGHT: RESULTS ----------
      var right = el('div'); right.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;min-height:0';
      var resultsCard = ui.card({}); resultsCard.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
      var resHdr = el('div', 'j-section-h', 'RESULTS'); resHdr.style.marginBottom = '6px';
      resultsCard.appendChild(resHdr);
      var grid = C.ResultsGrid({
        title: 'Windows Upgrade results',
        emptyText: 'No results yet — pick hosts and an operation, then RUN.',
        keyMode: { hostCol: 'Host' }, popOut: true,
        columns: [
          { key: 'Host', label: 'COMPUTER', width: 170 },
          { key: 'Ping', label: 'PING', width: 90, render: function (r) { return { text: r.Ping == null ? '' : String(r.Ping), cls: pingCellCls(r.Ping) }; } },
          { key: 'Status', label: 'STATUS', width: 100, render: function (r) { return { text: r.Status == null ? '' : String(r.Status), cls: statusCellCls(r.Status) }; } },
          { key: 'Detail', label: 'DETAIL', render: function (r) { var t = r.Detail == null ? '' : String(r.Detail); return { text: t, title: t }; } }
        ],
        rowClass: function (r) {
          var s = String(r.Status);
          if (s === 'DONE' || s === 'RESET' || s === 'READY' || s === 'ON 24H2' || s === 'Online' || s === 'CLEAN') return 'row-ok';
          if (s === 'FAILED' || s === 'Offline') return 'row-bad';
          if (s === 'DRY-RUN' || s === 'NEEDS POLICY' || s === 'BLOCKED' || s === 'HW INCOMPAT' || s === 'MEMORY' || s === 'ERRORS' || s === 'NEEDS REBOOT' || s === 'Skipped' || s === 'Cancelled') return 'row-warn';
          return '';
        }
      });
      var gridHolder = el('div'); gridHolder.style.cssText = 'flex:1;min-height:0;display:flex'; gridHolder.appendChild(grid.el);
      resultsCard.appendChild(gridHolder);
      right.appendChild(resultsCard);
      body.appendChild(right);

      // ---------- FOOTER: progress + log ----------
      var footer = el('div'); footer.style.cssText = 'display:flex;gap:14px;padding:12px 16px;min-height:150px;max-height:34%';
      // progress + count + export (left of footer)
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
      opsPanel.appendChild(footer);

      // ---------- ACTIVITY LOG: full-width dock across the bottom (shared by both tabs) ----------
      var logCard = ui.card({}); logCard.classList.add('j-logdock'); logCard.style.cssText += ';margin:0 16px 14px';
      var log = C.ActivityLog({ title: 'ACTIVITY LOG', defaultName: 'WindowsUpgrade_ActivityLog' });
      logCard.appendChild(log.el);

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
      function effectiveCabPath() { return uploadedCabPath || (opCard._cabPathInput.value || '').trim(); }

      function setOpControlsEnabled() {
        // Enable only the inputs relevant to the checked operation (Update-OpControls parity).
        var isPin = currentOp === 'pin', isCab = currentOp === 'installcab', isPf = currentOp === 'setpagefile';
        var isUnpin = currentOp === 'unpin', isFd = currentOp === 'forcediscovery';
        opCard._prodInput.disabled = !isPin; opCard._verInput.disabled = !isPin; opCard._runWuCb._cb.disabled = !isPin;
        opCard._sccmRefreshCb._cb.disabled = !isPin; opCard._bypassCb._cb.disabled = !isPin;
        opCard._pinInputs.style.opacity = isPin ? '1' : '0.45';
        opCard._runWuCb.style.opacity = isPin ? '1' : '0.45';
        opCard._sccmRefreshCb.style.opacity = isPin ? '1' : '0.45';
        opCard._bypassCb.style.opacity = isPin ? '1' : '0.45';
        opCard._removeBypassCb._cb.disabled = !isUnpin;
        opCard._unpinWrap.style.opacity = isUnpin ? '1' : '0.45';
        opCard._fdProdInput.disabled = !isFd; opCard._fdVerInput.disabled = !isFd; opCard._fdAggressive._cb.disabled = !isFd;
        opCard._fdWrap.style.opacity = isFd ? '1' : '0.45';
        opCard._cabPathInput.disabled = !isCab; opCard._rebootCb._cb.disabled = !isCab;
        opCard._cabWrap.style.opacity = isCab ? '1' : '0.45';
        opCard._pfSize.disabled = !isPf; opCard._pfReboot._cb.disabled = !isPf;
        opCard._pfWrap.style.opacity = isPf ? '1' : '0.45';
      }
      function refreshGuide() {
        if (currentOp === 'pin') guideBox.value = OPS.pin.guide((opCard._prodInput.value || '').trim(), (opCard._verInput.value || '').trim());
        else if (currentOp === 'setpagefile') guideBox.value = OPS.setpagefile.guide(parseInt(opCard._pfSize.value, 10) || 16384);
        else if (currentOp === 'forcediscovery') guideBox.value = OPS.forcediscovery.guide((opCard._fdProdInput.value || '').trim(), (opCard._fdVerInput.value || '').trim(), opCard._fdAggressive._cb.checked);
        else if (OPS[currentOp]) guideBox.value = OPS[currentOp].guide();
      }
      function updateCabHint() {
        var h = opCard._cabHint;
        if (uploadedCabPath) { h.textContent = 'Uploaded: ' + uploadedCabName; h.style.color = 'var(--ok)'; }
        else { h.textContent = '(no upload - path field used)'; h.style.color = 'var(--muted)'; }
      }

      function onScenarioPick() {
        var s = SCENARIOS.filter(function (x) { return x.value === scenarioSelect.value; })[0];
        if (!s || s.value === 'manual') { refreshGuide(); return; }
        applyingScenario = true;
        try {
          currentOp = s.op;
          opRadios[s.op].checked = true;
          if (s.op === 'pin') { if (s.product) opCard._prodInput.value = s.product; if (s.version) opCard._verInput.value = s.version; }
          if (s.op === 'installcab' && typeof s.reboot === 'boolean') opCard._rebootCb._cb.checked = s.reboot;
          setOpControlsEnabled();
          guideBox.value = s.guide;     // scenario steps override the per-op blurb
        } finally { applyingScenario = false; }
      }
      function onOpChanged(k) {
        currentOp = k;
        setOpControlsEnabled();
        refreshGuide();
        if (!applyingScenario) scenarioSelect.value = 'manual';   // hand-pick snaps chooser back to Manual
      }

      async function doUpload(file) {
        opCard._cabHint.textContent = 'Uploading ' + file.name + ' ...'; opCard._cabHint.style.color = 'var(--warn)';
        log.append({ text: '[' + ts() + '] Uploading ' + file.name + ' (' + Math.round(file.size / 1024) + ' KB)...', level: 'accent' });
        try {
          var path = await ctx.uploadFile(file);
          uploadedCabPath = path; uploadedCabName = file.name;
          opCard._cabPathInput.value = file.name;   // show the package name; effectiveCabPath uses the server temp path
          updateCabHint();
          log.append({ text: '[' + ts() + '] Upload complete -> ' + path, level: 'ok' });
        } catch (e) {
          uploadedCabPath = null; uploadedCabName = '';
          opCard._cabHint.textContent = 'Upload failed'; opCard._cabHint.style.color = 'var(--bad)';
          log.append({ text: '[' + ts() + '] Upload FAILED: ' + (e && e.message ? e.message : e), level: 'err' });
          ctx.confirm({ title: 'Upload failed', body: 'Could not upload the package: ' + escHtml(e && e.message ? e.message : String(e)) + '<br><br>You can still type a path to a share instead.', okText: 'OK', cancelText: null });
        }
      }

      function lockInputs(on) {
        scenarioSelect.disabled = on;
        Object.keys(opRadios).forEach(function (k) { opRadios[k].disabled = on; });
        opCard._prodInput.disabled = on || currentOp !== 'pin';
        opCard._verInput.disabled = on || currentOp !== 'pin';
        opCard._runWuCb._cb.disabled = on || currentOp !== 'pin';
        opCard._sccmRefreshCb._cb.disabled = on || currentOp !== 'pin';
        opCard._bypassCb._cb.disabled = on || currentOp !== 'pin';
        opCard._removeBypassCb._cb.disabled = on || currentOp !== 'unpin';
        opCard._fdProdInput.disabled = on || currentOp !== 'forcediscovery';
        opCard._fdVerInput.disabled = on || currentOp !== 'forcediscovery';
        opCard._fdAggressive._cb.disabled = on || currentOp !== 'forcediscovery';
        opCard._cabPathInput.disabled = on || currentOp !== 'installcab';
        opCard._rebootCb._cb.disabled = on || currentOp !== 'installcab';
        opCard._pfSize.disabled = on || currentOp !== 'setpagefile';
        opCard._pfReboot._cb.disabled = on || currentOp !== 'setpagefile';
        dryCb._cb.disabled = on; offlineCb._cb.disabled = on; threadsInput.disabled = on;
        pingBtn.disabled = on; checkBtn.disabled = on; clearBtn.disabled = on;
      }

      function threads() { return Math.max(1, Math.min(64, parseInt(threadsInput.value, 10) || 16)); }

      function summarize() {
        var ok = 0, reboot = 0, nolog = 0, fail = 0, skip = 0;
        grid.rows().forEach(function (r) {
          var s = String(r.Status);
          if (s === 'NEEDS REBOOT') reboot++;
          else if (s === 'NO LOG') nolog++;
          else if (s === 'DONE' || s === 'RESET' || s === 'READY' || s === 'ON 24H2' || s === 'Online' || s === 'CLEAN') ok++;
          else if (s === 'FAILED' || s === 'Offline') fail++;
          else if (s === 'DRY-RUN' || s === 'NEEDS POLICY' || s === 'BLOCKED' || s === 'HW INCOMPAT' || s === 'MEMORY' || s === 'ERRORS' || s === 'Skipped' || s === 'Cancelled') skip++;
        });
        return { ok: ok, reboot: reboot, nolog: nolog, fail: fail, skip: skip, total: grid.rows().length };
      }

      // ---- bind a streaming run handle to the grid/log/progress surfaces ----
      function bindRun(verb) {
        if (unsub) unsub();
        unsub = run.subscribe({
          status: function (t) { prog.setPhase(t); runbar.setStatus(t, 'st-info'); },
          progress: function (p) { prog.setProgress(p.done, p.total); countLine.textContent = p.done + ' / ' + p.total; },
          row: function (r) { grid.upsert(r); },
          log: function (l) { log.append(l); },
          error: function (e) { log.append({ text: '[' + ts() + '] ' + (e && e.text ? e.text : 'error'), level: 'err' }); },
          active: function (a) {
            runbar.setActive(a); pingBtn.disabled = a; checkBtn.disabled = a;
            if (!a) {
              lockInputs(false);
              var c = summarize();
              countLine.textContent = c.total + ' / ' + c.total;
              log.append({ text: '[' + ts() + '] FINISHED ' + verb + '. OK=' + c.ok + '  Reboot pending=' + c.reboot + '  No log=' + c.nolog + '  Failed=' + c.fail + '  Skipped/Cancelled=' + c.skip, level: c.fail ? 'warn' : 'ok' });
              runbar.setStatus('Done - OK ' + c.ok + ' / Reboot pending ' + c.reboot + ' / No log ' + c.nolog + ' / Failed ' + c.fail + ' / Skipped ' + c.skip, c.fail ? 'st-bad' : 'st-ok');
            }
          }
        });
      }

      // ---- Test Ping (no confirmation) ----
      function doPing() {
        if (isRunning()) return;
        if (!targets.count()) { ctx.confirm({ title: 'No Computers', body: 'Add at least one computer to ping.', okText: 'OK', cancelText: null }); return; }
        var hosts = targets.hosts();
        grid.clear(); prog.reset(); countLine.textContent = '0 / ' + hosts.length;
        log.banner('Test Ping (' + hosts.length + ' computer(s))');
        lockInputs(true);
        run = ctx.run('ping', { targets: hosts.join('\n'), threads: threads() }, { keyOf: keyByHost });
        bindRun('Ping');
      }

      // ---- Check Errors (read-only: setuperr.log harvest, no confirmation) ----
      function doCheck() {
        if (isRunning()) return;
        if (!targets.count()) { ctx.confirm({ title: 'No Computers', body: 'Add at least one computer to check.', okText: 'OK', cancelText: null }); return; }
        var hosts = targets.hosts();
        grid.clear(); prog.reset(); countLine.textContent = '0 / ' + hosts.length;
        log.banner('Check Upgrade Errors (' + hosts.length + ' computer(s))');
        lockInputs(true);
        run = ctx.run('checkupgrade', { targets: hosts.join('\n'), attemptOffline: offlineCb._cb.checked, threads: threads() }, { keyOf: keyByHost });
        bindRun('Check');
      }

      // ---- RUN (Pin / Unpin / Install CAB) ----
      async function doRun() {
        var opMeta = OPS[currentOp];
        if (!opMeta) return;
        var hosts = targets.hosts();
        var dry = dryCb._cb.checked && currentOp !== 'diagnose';   // diagnose is read-only: no Dry-run
        // reboot is per-operation: Install CAB and Set Page File each carry their own reboot toggle.
        var reboot = (currentOp === 'installcab') ? opCard._rebootCb._cb.checked
                   : (currentOp === 'setpagefile') ? opCard._pfReboot._cb.checked
                   : false;
        var aggressive = (currentOp === 'forcediscovery') && opCard._fdAggressive._cb.checked;
        var readonly = (currentOp === 'diagnose');
        var cabPath = effectiveCabPath();
        var pfMb = parseInt(opCard._pfSize.value, 10) || 16384;

        // Build the desktop-style op label + Yes/No confirm.
        var opLabel;
        if (currentOp === 'diagnose') opLabel = 'DIAGNOSTIC SCAN (read-only)';
        else if (currentOp === 'pin') opLabel = 'PIN to ' + (opCard._prodInput.value || '').trim() + ' ' + (opCard._verInput.value || '').trim()
          + (opCard._runWuCb._cb.checked ? ' + RUN WU' : '')
          + (opCard._sccmRefreshCb._cb.checked ? ' + SCCM REFRESH' : '')
          + (opCard._bypassCb._cb.checked ? ' + BYPASS SET' : '');
        else if (currentOp === 'unpin') opLabel = 'UNPIN (remove target version policy)' + (opCard._removeBypassCb._cb.checked ? ' + remove bypass' : '');
        else if (currentOp === 'forcediscovery') opLabel = 'FORCE DISCOVERY' + (aggressive ? ' [AGGRESSIVE]' : ' [safe]');
        else if (currentOp === 'setpagefile') opLabel = 'SET PAGE FILE ' + pfMb + ' MB' + (reboot ? ' + REBOOT' : '');
        else opLabel = 'INSTALL ' + (uploadedCabName || (cabPath ? cabPath.replace(/^.*[\\/]/, '') : 'CAB')) + (reboot ? ' + REBOOT' : '');
        if (dry) opLabel += ' [DRY-RUN]';

        var authLabel = ctx.session.state.credSet ? (ctx.session.state.user ? ('as ' + ctx.session.state.user) : 'set credential') : 'current Windows session';
        var warnReboot = ((currentOp === 'installcab' || currentOp === 'setpagefile') && reboot && !dry);
        var warnAggressive = aggressive && !dry;

        var rebootMsg = (currentOp === 'setpagefile')
          ? 'WARNING: targets will REBOOT ~10 seconds after the page file is set (required to apply).'
          : 'WARNING: targets will REBOOT ~10 seconds after a successful install.';
        var aggressiveMsg = 'WARNING: Aggressive mode STOPS the Windows Update services, renames SoftwareDistribution + catroot2, and re-registers the WU DLLs before re-scanning.';
        var extraWarn = '';
        if (warnReboot) extraWarn = '<br><br><span style="color:var(--bad);font-weight:700">' + rebootMsg + '</span>';
        else if (warnAggressive) extraWarn = '<br><br><span style="color:var(--bad);font-weight:700">' + aggressiveMsg + '</span>';

        var confirmBody = 'Operation: <b>' + escHtml(opLabel) + '</b><br>'
          + 'Targets: <b>' + hosts.length + '</b><br>'
          + 'Auth: <b>' + escHtml(authLabel) + '</b>'
          + extraWarn;

        var ok = await ctx.confirm({
          title: 'Confirm Run', danger: !dry && !readonly,
          body: confirmBody, list: hosts.slice(0, 6),
          preflight: { targets: hosts, actionLabel: opLabel },
          okText: dry ? 'Preview' : (readonly ? 'Scan' : 'Run'), cancelText: 'Cancel'
        });
        if (!ok) { log.append({ text: '[' + ts() + '] Run cancelled at confirm.', level: 'warn' }); return; }

        grid.clear(); prog.reset(); countLine.textContent = '0 / ' + hosts.length;
        // seed a Queued row per host so nothing looks empty before the first stream-back.
        hosts.forEach(function (h) { grid.upsert({ Host: h, Ping: '', Status: 'Queued', Detail: 'Queued' }); });
        log.banner(opLabel + ' on ' + hosts.length + ' computer(s)');   // opLabel already carries [DRY-RUN]
        lockInputs(true);

        var params = {
          targets: hosts.join('\n'),
          attemptOffline: offlineCb._cb.checked,
          threads: threads()
        };
        if (!readonly) params.dryRun = dry;   // diagnose takes no dryRun input
        if (currentOp === 'pin') {
          params.product = (opCard._prodInput.value || '').trim();
          params.version = (opCard._verInput.value || '').trim();
          params.runWu = opCard._runWuCb._cb.checked;
          params.sccmRefresh = opCard._sccmRefreshCb._cb.checked;
          params.bypass = opCard._bypassCb._cb.checked;
        }
        if (currentOp === 'unpin') { params.removeBypass = opCard._removeBypassCb._cb.checked; }
        if (currentOp === 'forcediscovery') {
          params.product = (opCard._fdProdInput.value || '').trim();
          params.version = (opCard._fdVerInput.value || '').trim();
          params.aggressive = aggressive;
        }
        if (currentOp === 'installcab') {
          params.reboot = reboot;
          // a Browse/drag upload (server temp path) wins; else the typed path.
          if (uploadedCabPath) params.cabUpload = uploadedCabPath;
          params.cabPath = (opCard._cabPathInput.value && !uploadedCabPath) ? (opCard._cabPathInput.value || '').trim() : '';
        }
        if (currentOp === 'setpagefile') { params.reboot = reboot; params.sizeMb = pfMb; }

        run = ctx.run(opMeta.action, params, {
          keyOf: keyByHost,
          destructive: !dry && !readonly && !!(ctx.manifest)  // read-only diagnose is never destructive
        });
        bindRun(opLabel.replace(/ \[DRY-RUN\]$/, ''));
      }

      function keyByHost(ev) { return ev.Host != null ? String(ev.Host) : (ev.host != null ? String(ev.host) : null); }

      function doExport() {
        var rows = grid.rows();
        if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Run an operation first - there are no result rows yet.', okText: 'OK', cancelText: null }); return; }
        var csv = ctx.util.toCsv(EXPORT_COLS.map(function (p) { return p[1]; }), rows, EXPORT_COLS.map(function (p) { return p[0]; }));
        ctx.util.downloadBlob('WindowsUpgrade_results_' + ctx.util.fileStamp() + '.csv', 'text/csv', csv);
        log.append({ text: '[' + ts() + '] Exported ' + rows.length + ' row(s) to CSV.', level: 'info' });
      }

      var escHtml = Janet.util.esc;

      // =================== FLEET STATUS board (read-only) ===================
      // Runs the SAME per-host readiness scan (action 'fleet-status') across the
      // targets and rolls it up: "where is the whole fleet on the 24H2 journey?".
      // Changes NOTHING - no admin session, no reboots, no policy writes.
      var fleetRun = null, fleetUnsub = null;
      var driveRun = null, driveUnsub = null;
      var fleetGridRef = null;   // set by buildFleetPanel so Drive can seed Ready hosts
      function buildFleetPanel(panel) {
        panel.style.cssText = 'display:flex;gap:14px;height:100%;min-height:0;box-sizing:border-box;padding:12px 16px';

        // LEFT: targets + options + Scan Fleet
        var fl = el('div'); fl.style.cssText = 'flex:0 0 400px;display:flex;flex-direction:column;gap:12px;min-height:0';
        var compCard = ui.namedCard('COMPUTERS', 'One host per line - comma/space/semicolon ok; # starts a comment.');
        compCard.style.cssText += ';flex:0 0 auto;min-height:160px;max-height:300px;display:flex;flex-direction:column;overflow:hidden';
        var fTargets = C.TargetManager({
          model: ctx.util.targetModel(''),
          hint: 'One host per line - comma/space/semicolon ok; # starts a comment.',
          placeholder: 'WS-0001\nWS-0002\n# lab row\nWS-0003',
          importLabel: 'Import TXT', importAccept: '.txt', countNoun: 'computer',
          onImport: function (n, name) { log.append({ text: '[' + ts() + '] Added ' + n + ' computer(s) from ' + name, level: 'info' }); }
        });
        var fth = el('div'); fth.style.cssText = 'flex:1;min-height:0;display:flex'; fth.appendChild(fTargets.el);
        compCard.appendChild(fth); fl.appendChild(compCard);

        var fOpt = ui.card({}); fOpt.style.cssText += ';display:flex;flex-direction:column;gap:10px';
        var fOffline = ui.checkbox('Attempt even if offline (host unreachable)', { title: 'Scan a host that fails the TCP 5985/445 reachability probe. Reachability is TCP-only - AFNET drops ICMP.' });
        fOpt.appendChild(fOffline);
        var ftr = el('div'); ftr.style.cssText = 'display:flex;align-items:center;gap:10px';
        ftr.appendChild(ui.label('Max concurrent:'));
        var fThreads = ui.number({ value: 16, min: 1, max: 64, title: 'Parallel hosts (1-64).' }); fThreads.style.width = '80px';
        ftr.appendChild(fThreads); fOpt.appendChild(ftr);
        var fStatus = el('div', 'muted', 'Ready'); fStatus.style.fontSize = '12px'; fOpt.appendChild(fStatus);
        fl.appendChild(fOpt);

        var fAct = ui.card({}); fAct.style.cssText += ';display:flex;flex-direction:column;gap:8px';
        var fRunbar = C.RunBar({
          label: 'SCAN FLEET', cancelLabel: 'CANCEL SCAN', morphToCancel: true,
          title: 'Read-only fleet posture scan across every computer (changes nothing).',
          guards: [ function () { return fTargets.count() ? null : 'No Computers|Add at least one computer to scan.'; } ],
          onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
          onRun: doFleetScan,
          onCancel: function () { if (fleetRun) { fleetRun.cancel(); log.append({ text: '[' + ts() + '] CANCEL requested - queued computers skip; in-flight scans finish.', level: 'warn' }); } }
        });
        var frb = el('div'); frb.appendChild(fRunbar.el); fAct.appendChild(frb); fl.appendChild(fAct);
        panel.appendChild(fl);

        // RIGHT: stat cards + grid
        var fr = el('div'); fr.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:12px;min-height:0';
        var fStats = C.StatCards({ cards: [
          { key: 'already', label: 'ALREADY 24H2', color: 'cyan' },
          { key: 'ready', label: 'READY', color: 'ok' },
          { key: 'blocked', label: 'BLOCKED', color: 'bad' },
          { key: 'pending', label: 'PENDING REBOOT', color: 'gold' }
        ] });
        fr.appendChild(fStats.el);

        var fHead = ui.card({}); fHead.style.cssText += ';display:flex;align-items:center;gap:12px;flex-wrap:wrap';
        var fProg = C.ProgressStatusStrip({ showCount: true });
        fProg.el.style.flex = '1'; fHead.appendChild(fProg.el);
        var fExport = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the fleet-status rows to CSV.' });
        var fClear = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the fleet-status grid.' });
        fHead.appendChild(fExport); fHead.appendChild(fClear);
        fr.appendChild(fHead);

        var fResults = ui.namedCard('FLEET STATUS', 'One row per computer: where it sits on the 23H2 -> 24H2 journey. Read-only.');
        fResults.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
        var fGrid = C.ResultsGrid({
          title: 'Fleet Status', emptyText: 'No results yet - add computers and Scan Fleet.',
          keyMode: { hostCol: 'Host' }, popOut: true, selectable: false,
          columns: [
            { key: 'Host', label: 'COMPUTER', width: 160 },
            { key: 'Online', label: 'ONLINE', width: 78, render: function (r) { return yesNoDim(r.Online, false); } },
            { key: 'DisplayVersion', label: 'VERSION', width: 90, render: function (r) { return { text: String(r.DisplayVersion == null ? '' : r.DisplayVersion), cls: 'cell-dim' }; } },
            { key: 'OsBuild', label: 'BUILD', width: 80, render: function (r) { var b = parseInt(r.OsBuild, 10); return { text: (b > 0 ? String(b) : ''), cls: (b >= 26100 ? 'st-ok' : 'cell-dim') }; } },
            { key: 'Win24H2Status', label: '24H2 STATUS', width: 210, render: function (r) { return fleetStatusCell(r.Win24H2Status); } },
            { key: 'Eligible', label: 'ELIGIBLE', width: 84, render: function (r) { return yesNoDim(r.Eligible, false); } },
            { key: 'BlockReason', label: 'BLOCK REASON', render: function (r) { var t = String(r.BlockReason == null ? '' : r.BlockReason); return { text: t, title: t, cls: t ? 'st-bad' : 'cell-dim' }; } },
            { key: 'Pinned', label: 'PINNED', width: 78, render: function (r) { return yesNoDim(r.Pinned, false); } },
            { key: 'PinnedVersion', label: 'PIN VER', width: 84, render: function (r) { return { text: String(r.PinnedVersion == null ? '' : r.PinnedVersion), cls: 'cell-dim' }; } },
            { key: 'PendingReboot', label: 'REBOOT PENDING', width: 130, render: function (r) { return yesNoDim(r.PendingReboot, true); } },
            { key: 'Error', label: 'ERROR', width: 160, render: function (r) { var t = String(r.Error == null ? '' : r.Error); return { text: t, title: t, cls: t ? 'st-warn' : 'cell-dim' }; } }
          ],
          rowClass: function (r) {
            var s = String(r.Win24H2Status);
            if (s === 'Ready') return 'row-ok';
            if (s.indexOf('Blocked') === 0 || s === 'Offline') return 'row-bad';
            if (s === 'Pending reboot' || s === 'Error') return 'row-warn';
            return '';
          }
        });
        fleetGridRef = fGrid;   // Drive 24H2 tab can seed itself from the Ready rows here
        var fgh = el('div'); fgh.style.cssText = 'flex:1;min-height:0;display:flex'; fgh.appendChild(fGrid.el);
        fResults.appendChild(fgh); fr.appendChild(fResults);
        panel.appendChild(fr);

        var FLEET_EXPORT = [['Host', 'Computer'], ['Online', 'Online'], ['DisplayVersion', 'DisplayVersion'], ['OsBuild', 'OsBuild'], ['Win24H2Status', 'Win24H2Status'], ['Eligible', 'Eligible'], ['BlockReason', 'BlockReason'], ['Pinned', 'Pinned'], ['PinnedVersion', 'PinnedVersion'], ['PendingReboot', 'PendingReboot'], ['Error', 'Error']];
        fExport.onclick = function () {
          var rows = fGrid.rows();
          if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Scan the fleet first - there are no rows yet.', okText: 'OK', cancelText: null }); return; }
          var csv = ctx.util.toCsv(FLEET_EXPORT.map(function (p) { return p[1]; }), rows, FLEET_EXPORT.map(function (p) { return p[0]; }));
          ctx.util.downloadBlob('WindowsUpgrade_FleetStatus_' + ctx.util.fileStamp() + '.csv', 'text/csv', csv);
          log.append({ text: '[' + ts() + '] Exported ' + rows.length + ' fleet-status row(s) to CSV.', level: 'info' });
        };
        fClear.onclick = function () { if (fleetRun && fleetRun.state && fleetRun.state.active) return; fGrid.clear(); fStats.reset(); fProg.reset(); fStatus.textContent = 'Ready'; fStatus.className = 'muted'; };

        function recount() {
          var c = { already: 0, ready: 0, blocked: 0, pending: 0 };
          fGrid.rows().forEach(function (r) {
            var s = String(r.Win24H2Status);
            if (s === 'Already 24H2+') c.already++;
            else if (s === 'Ready') c.ready++;
            else if (s.indexOf('Blocked') === 0) c.blocked++;
            else if (s === 'Pending reboot') c.pending++;
          });
          fStats.setAll(c);
        }

        function doFleetScan() {
          var hosts = fTargets.hosts();
          fGrid.clear(); fStats.reset(); fProg.reset();
          fStatus.textContent = 'Scanning...'; fStatus.className = 'st-info';
          log.banner('Fleet Status scan (' + hosts.length + ' computer(s))');
          fOffline.disabled = true; fThreads.disabled = true; fClear.disabled = true;
          fleetRun = ctx.run('fleet-status', {
            targets: hosts.join('\n'),
            attemptOffline: fOffline._cb.checked,
            threads: Math.max(1, Math.min(64, parseInt(fThreads.value, 10) || 16))
          }, { keyOf: keyByHost, destructive: false });
          if (fleetUnsub) fleetUnsub();
          fleetUnsub = fleetRun.subscribe({
            status: function (t) { fStatus.textContent = t; fStatus.className = 'st-info'; },
            progress: function (p) { fProg.setProgress(p.done, p.total); },
            row: function (r) { fGrid.upsert(r); recount(); },
            log: function (l) { log.append(l); },
            error: function (e) { fStatus.textContent = (e && e.text) || 'Error'; fStatus.className = 'st-bad'; log.append({ text: (e && e.text) || 'error', level: 'err' }); },
            active: function (a) { fRunbar.setActive(a); if (!a) { fOffline.disabled = false; fThreads.disabled = false; fClear.disabled = false; } },
            final: function (res) {
              var s = (res && res.summary) || {};
              if (s.already24h2 != null) { fStats.setAll({ already: s.already24h2, ready: s.ready, blocked: s.blocked, pending: s.pendingReboot }); }
              else { recount(); }
              var done = 'Done - ' + (s.already24h2 || 0) + ' on 24H2, ' + (s.ready || 0) + ' ready, ' + (s.blocked || 0) + ' blocked, ' + (s.pendingReboot || 0) + ' pending reboot';
              fStatus.textContent = done; fStatus.className = (s.blocked ? 'st-warn' : 'st-ok');
              log.append({ text: '[' + ts() + '] FLEET STATUS ' + done, level: (s.blocked ? 'warn' : 'ok') });
            }
          });
        }
      }

      // =================== DRIVE 24H2 (WUfB) board ===================
      // Actively drives 23H2 -> 24H2 over Windows Update for Business per host: read
      // readiness, skip already-24H2 / hardware-blocked (unless bypass), PIN the target,
      // TRIGGER Windows Update, re-read staged state, and (only if "Reboot when staged"
      // is ticked AND a host is CONFIRMED staged) reboot it on a per-host countdown.
      // Destructive -> gated on an admin session (unless Dry-run) + a danger confirm.
      function buildDrivePanel(panel) {
        panel.style.cssText = 'display:flex;gap:14px;height:100%;min-height:0;box-sizing:border-box;padding:12px 16px';

        // LEFT: targets + options + Drive
        var dl = el('div'); dl.style.cssText = 'flex:0 0 420px;display:flex;flex-direction:column;gap:12px;min-height:0;overflow:auto';

        var dCompCard = ui.namedCard('COMPUTERS', 'One host per line - comma/space/semicolon ok; # starts a comment.');
        dCompCard.style.cssText += ';flex:0 0 auto;min-height:150px;max-height:260px;display:flex;flex-direction:column;overflow:hidden';
        var dTargets = C.TargetManager({
          model: ctx.util.targetModel(''),
          hint: 'One host per line - comma/space/semicolon ok; # starts a comment.',
          placeholder: 'WS-0001\nWS-0002\n# lab row\nWS-0003',
          importLabel: 'Import TXT', importAccept: '.txt', countNoun: 'computer',
          onImport: function (n, name) { log.append({ text: '[' + ts() + '] Added ' + n + ' computer(s) from ' + name, level: 'info' }); }
        });
        var dth = el('div'); dth.style.cssText = 'flex:1;min-height:0;display:flex'; dth.appendChild(dTargets.el);
        dCompCard.appendChild(dth);
        var seedBtn = ui.ghostButton('Seed READY hosts from Fleet Status', { size: 'sm', title: 'Copy the hosts the Fleet Status board classified "Ready" (on 23H2, hardware OK) into this list.' });
        seedBtn.style.marginTop = '6px';
        seedBtn.onclick = function () {
          if (!fleetGridRef) { ctx.confirm({ title: 'No Fleet Status yet', body: 'Open the Fleet Status tab and Scan Fleet first - then this copies its READY hosts here.', okText: 'OK', cancelText: null }); return; }
          var ready = fleetGridRef.rows().filter(function (r) { return String(r.Win24H2Status) === 'Ready'; }).map(function (r) { return String(r.Host); });
          if (!ready.length) { ctx.confirm({ title: 'No READY hosts', body: 'The Fleet Status board has no hosts classified READY. Scan the fleet first, or add hosts manually.', okText: 'OK', cancelText: null }); return; }
          dTargets.setText(ready.join('\n'));
          log.append({ text: '[' + ts() + '] Seeded ' + ready.length + ' READY host(s) from Fleet Status.', level: 'info' });
        };
        dCompCard.appendChild(seedBtn);
        dl.appendChild(dCompCard);

        var dOpt = ui.card({}); dOpt.style.cssText += ';display:flex;flex-direction:column;gap:10px';
        var dOptH = el('div', 'j-section-h', 'DRIVE OPTIONS'); dOptH.style.marginBottom = '2px'; dOpt.appendChild(dOptH);
        var pvRow = el('div'); pvRow.style.cssText = 'display:flex;gap:10px';
        var dProd = ui.input({ value: 'Windows 11', title: 'Windows Update for Business ProductVersion to pin, e.g. "Windows 11".' }); dProd.style.width = '150px';
        var dVer  = ui.input({ value: '24H2', title: 'TargetReleaseVersionInfo to pin/drive to, e.g. "24H2".' }); dVer.style.width = '90px';
        pvRow.appendChild(ui.field('Product', dProd)); pvRow.appendChild(ui.field('Version', dVer));
        dOpt.appendChild(pvRow);
        var dBypass = ui.checkbox('Apply CPU/TPM bypass for unsupported hardware (MoSetup)', { color: 'var(--warn)', title: 'Sets MoSetup\\AllowUpgradesWithUnsupportedTPMOrCPU = 1 and lets this tool drive an otherwise hardware-blocked host. Microsoft-unsupported config. Without it, hardware-blocked hosts are SKIPPED.' });
        dOpt.appendChild(dBypass);

        // --- REBOOT-WHEN-STAGED: the customer-affecting control, visually distinct ---
        var dangerBox = el('div');
        dangerBox.style.cssText = 'border:1px solid var(--bad);border-radius:6px;padding:8px 10px;display:flex;flex-direction:column;gap:8px;background:rgba(255,80,80,0.06)';
        var dangerH = el('div', null, 'CUSTOMER-AFFECTING'); dangerH.style.cssText = 'font-size:11px;font-weight:700;letter-spacing:.06em;color:var(--bad)';
        dangerBox.appendChild(dangerH);
        var dReboot = ui.checkbox('Reboot a host when it is CONFIRMED staged (per-host countdown)', { color: 'var(--bad)', title: 'After triggering WU, any host confirmed staged (feature update pending) will REBOOT after the countdown to complete 24H2. An un-staged host is never rebooted. The JANET dispatcher box is dropped from the wave.' });
        dangerBox.appendChild(dReboot);
        var cdRow = el('div'); cdRow.style.cssText = 'display:flex;align-items:center;gap:10px';
        cdRow.appendChild(ui.label('Countdown (seconds):'));
        var dCountdown = ui.number({ value: 300, min: 30, max: 86400, title: 'Per-host reboot countdown before a staged host restarts. Default 300 (5 min).' }); dCountdown.style.width = '100px';
        cdRow.appendChild(dCountdown);
        dangerBox.appendChild(cdRow);
        dOpt.appendChild(dangerBox);

        var dDry = ui.checkbox('Dry-run (no changes - reports what WOULD happen)', { color: 'var(--warn)', title: 'Reads readiness and reports the intended pin / trigger / reboot per host without writing or rebooting anything.' });
        dOpt.appendChild(dDry);
        var dOffline = ui.checkbox('Attempt even if offline (host unreachable)', { title: 'Proceed against a host that fails the TCP 5985/445 probe. Reachability is TCP-only - AFNET drops ICMP.' });
        dOpt.appendChild(dOffline);
        var dThrRow = el('div'); dThrRow.style.cssText = 'display:flex;align-items:center;gap:10px';
        dThrRow.appendChild(ui.label('Max concurrent:'));
        var dThreads = ui.number({ value: 8, min: 1, max: 64, title: 'Parallel hosts (1-64). Drive is heavy per host, so it defaults low (8).' }); dThreads.style.width = '80px';
        dThrRow.appendChild(dThreads); dOpt.appendChild(dThrRow);
        var dStatus = el('div', 'muted', 'Ready'); dStatus.style.fontSize = '12px'; dOpt.appendChild(dStatus);
        dl.appendChild(dOpt);

        var dActCard = ui.card({}); dActCard.style.cssText += ';display:flex;flex-direction:column;gap:8px';
        var dRunbar = C.RunBar({
          label: 'DRIVE 24H2', cancelLabel: 'CANCEL DRIVE', morphToCancel: true,
          title: 'Pin + trigger Windows Update (and optionally reboot staged hosts) across every computer.',
          guards: [
            function () { return dTargets.count() ? null : 'No Computers|Add at least one computer before driving.'; },
            function () {
              var p = (dProd.value || '').trim(), v = (dVer.value || '').trim();
              return (p && v) ? null : 'Product + Version Required|Drive needs both a Product (e.g. "Windows 11") and a Version (e.g. "24H2").';
            },
            function () {
              if (dDry._cb.checked) return null;   // dry-run never changes anything
              return ctx.session.state.credSet ? null : 'Admin Session Required|Driving 24H2 pins policy, triggers WU and (optionally) reboots hosts. Set credentials (top-right) and start an admin session, or tick Dry-run.';
            }
          ],
          onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
          onRun: doDrive,
          onCancel: function () { if (driveRun) { driveRun.cancel(); log.append({ text: '[' + ts() + '] CANCEL requested - queued computers skip; in-flight drives finish.', level: 'warn' }); } }
        });
        var drb = el('div'); drb.appendChild(dRunbar.el); dActCard.appendChild(drb); dl.appendChild(dActCard);
        panel.appendChild(dl);

        // RIGHT: stat cards + progress + grid
        var dr = el('div'); dr.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:12px;min-height:0';
        var dStats = C.StatCards({ cards: [
          { key: 'driven', label: 'DRIVEN', color: 'ok' },
          { key: 'staged', label: 'STAGED', color: 'gold' },
          { key: 'rebooting', label: 'REBOOTING', color: 'cyan' },
          { key: 'skipped', label: 'SKIPPED', color: 'bad' }
        ] });
        dr.appendChild(dStats.el);

        var dHead = ui.card({}); dHead.style.cssText += ';display:flex;align-items:center;gap:12px;flex-wrap:wrap';
        var dProg = C.ProgressStatusStrip({ showCount: true });
        dProg.el.style.flex = '1'; dHead.appendChild(dProg.el);
        var dExport = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the drive result rows to CSV.' });
        var dClear = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the drive grid.' });
        dHead.appendChild(dExport); dHead.appendChild(dClear);
        dr.appendChild(dHead);

        var dResults = ui.namedCard('DRIVE RESULTS', 'One row per computer: what was pinned / triggered / staged / rebooted on the 24H2 drive.');
        dResults.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
        var dGrid = C.ResultsGrid({
          title: 'Drive 24H2', emptyText: 'No results yet - add computers and DRIVE 24H2.',
          keyMode: { hostCol: 'Host' }, popOut: true, selectable: false,
          columns: [
            { key: 'Host', label: 'COMPUTER', width: 150 },
            { key: 'Online', label: 'ONLINE', width: 74, render: function (r) { return yesNoDim(r.Online, false); } },
            { key: 'OsBuild', label: 'BUILD', width: 76, render: function (r) { var b = parseInt(r.OsBuild, 10); return { text: (b > 0 ? String(b) : ''), cls: (b >= 26100 ? 'st-ok' : 'cell-dim') }; } },
            { key: 'DisplayVersion', label: 'VER', width: 74, render: function (r) { return { text: String(r.DisplayVersion == null ? '' : r.DisplayVersion), cls: 'cell-dim' }; } },
            { key: 'Status', label: 'STATUS', width: 104, render: function (r) { return { text: String(r.Status == null ? '' : r.Status), cls: statusCellCls(r.Status) }; } },
            { key: 'WasPinned', label: 'PINNED', width: 74, render: function (r) { return yesNoDim(r.WasPinned, false); } },
            { key: 'TriggerResult', label: 'WU TRIGGER', width: 220, render: function (r) { var t = String(r.TriggerResult == null ? '' : r.TriggerResult); return { text: t, title: t, cls: 'cell-dim' }; } },
            { key: 'Staged', label: 'STAGED', width: 74, render: function (r) { var y = yesNoDim(r.Staged, false); if (y.text === 'Yes') y.cls = 'st-warn'; return y; } },
            { key: 'Rebooted', label: 'REBOOTED', width: 88, render: function (r) { return yesNoDim(r.Rebooted, true); } },
            { key: 'CountdownSec', label: 'COUNTDOWN', width: 92, render: function (r) { var c = parseInt(r.CountdownSec, 10); return { text: (c > 0 ? (c + 's') : ''), cls: (c > 0 ? 'st-warn' : 'cell-dim') }; } },
            { key: 'Skipped', label: 'SKIPPED', width: 150, render: function (r) { var t = String(r.Skipped == null ? '' : r.Skipped); return { text: t, title: t, cls: t ? 'st-warn' : 'cell-dim' }; } },
            { key: 'Detail', label: 'DETAIL', render: function (r) { var t = String(r.Detail == null ? '' : r.Detail); return { text: t, title: t }; } },
            { key: 'Error', label: 'ERROR', width: 150, render: function (r) { var t = String(r.Error == null ? '' : r.Error); return { text: t, title: t, cls: t ? 'st-bad' : 'cell-dim' }; } }
          ],
          rowClass: function (r) {
            var s = String(r.Status);
            if (s === 'DRIVEN' || s === 'REBOOTING') return 'row-ok';
            if (s === 'FAILED' || s === 'Offline') return 'row-bad';
            if (s === 'STAGED' || s === 'NEEDS REBOOT' || s === 'Skipped' || s === 'DRY-RUN' || s === 'Cancelled') return 'row-warn';
            return '';
          }
        });
        var dgh = el('div'); dgh.style.cssText = 'flex:1;min-height:0;display:flex'; dgh.appendChild(dGrid.el);
        dResults.appendChild(dgh); dr.appendChild(dResults);
        panel.appendChild(dr);

        var DRIVE_EXPORT = [['Host', 'Computer'], ['Online', 'Online'], ['OsBuild', 'OsBuild'], ['DisplayVersion', 'DisplayVersion'], ['Status', 'Status'], ['WasPinned', 'Pinned'], ['TriggerResult', 'TriggerResult'], ['Staged', 'Staged'], ['Rebooted', 'Rebooted'], ['CountdownSec', 'CountdownSec'], ['Skipped', 'Skipped'], ['Detail', 'Detail'], ['Error', 'Error']];
        dExport.onclick = function () {
          var rows = dGrid.rows();
          if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Drive the fleet first - there are no rows yet.', okText: 'OK', cancelText: null }); return; }
          var csv = ctx.util.toCsv(DRIVE_EXPORT.map(function (p) { return p[1]; }), rows, DRIVE_EXPORT.map(function (p) { return p[0]; }));
          ctx.util.downloadBlob('WindowsUpgrade_Drive24H2_' + ctx.util.fileStamp() + '.csv', 'text/csv', csv);
          log.append({ text: '[' + ts() + '] Exported ' + rows.length + ' drive row(s) to CSV.', level: 'info' });
        };
        dClear.onclick = function () { if (driveRun && driveRun.state && driveRun.state.active) return; dGrid.clear(); dStats.reset(); dProg.reset(); dStatus.textContent = 'Ready'; dStatus.className = 'muted'; };

        function dRecount() {
          var c = { driven: 0, staged: 0, rebooting: 0, skipped: 0 };
          dGrid.rows().forEach(function (r) {
            var s = String(r.Status);
            if (s === 'DRIVEN') c.driven++;
            else if (s === 'STAGED' || s === 'NEEDS REBOOT') c.staged++;
            else if (s === 'REBOOTING') c.rebooting++;
            else if (s === 'Skipped' || s === 'DRY-RUN') c.skipped++;
          });
          dStats.setAll(c);
        }

        function lockDrive(on) {
          dProd.disabled = on; dVer.disabled = on; dBypass._cb.disabled = on;
          dReboot._cb.disabled = on; dCountdown.disabled = on;
          dDry._cb.disabled = on; dOffline._cb.disabled = on; dThreads.disabled = on;
          dClear.disabled = on; seedBtn.disabled = on;
        }

        async function doDrive() {
          var hosts = dTargets.hosts();
          var dry = dDry._cb.checked;
          var rebootWhenStaged = dReboot._cb.checked;
          var countdown = Math.max(30, Math.min(86400, parseInt(dCountdown.value, 10) || 300));
          var product = (dProd.value || '').trim(), version = (dVer.value || '').trim();

          var label = 'DRIVE ' + product + ' ' + version
            + (dBypass._cb.checked ? ' + BYPASS' : '')
            + (rebootWhenStaged ? (' + REBOOT-WHEN-STAGED (' + countdown + 's)') : '')
            + (dry ? ' [DRY-RUN]' : '');
          var authLabel = ctx.session.state.credSet ? (ctx.session.state.user ? ('as ' + ctx.session.state.user) : 'set credential') : 'current Windows session';
          var warnReboot = rebootWhenStaged && !dry;
          var extraWarn = warnReboot
            ? ('<br><br><span style="color:var(--bad);font-weight:700">WARNING: any host CONFIRMED staged (feature update pending) will REBOOT ~' + countdown + 's after the trigger. Un-staged hosts are not rebooted; the JANET dispatcher box is dropped from the wave.</span>')
            : '';
          var confirmBody = 'Operation: <b>' + escHtml(label) + '</b><br>'
            + 'Targets: <b>' + hosts.length + '</b><br>'
            + 'Auth: <b>' + escHtml(authLabel) + '</b><br>'
            + '<span class="muted">Pins the target + triggers Windows Update. A trigger accelerates but does not guarantee a headless install - completion is pin &rarr; WU stages &rarr; reboot.</span>'
            + extraWarn;

          var ok = await ctx.confirm({
            title: 'Confirm Drive 24H2', danger: warnReboot,
            body: confirmBody, list: hosts.slice(0, 6),
            preflight: { targets: hosts, actionLabel: 'Drive 24H2' },
            okText: dry ? 'Preview' : 'Drive', cancelText: 'Cancel'
          });
          if (!ok) { log.append({ text: '[' + ts() + '] Drive cancelled at confirm.', level: 'warn' }); return; }

          dGrid.clear(); dStats.reset(); dProg.reset();
          hosts.forEach(function (h) { dGrid.upsert({ Host: h, Online: false, OsBuild: 0, DisplayVersion: '', WasPinned: false, TriggerResult: '', Staged: false, Rebooted: false, CountdownSec: 0, Skipped: '', Error: '', Status: 'Queued', Detail: 'Queued' }); });
          dStatus.textContent = 'Driving...'; dStatus.className = 'st-info';
          log.banner(label + ' on ' + hosts.length + ' computer(s)');
          lockDrive(true);

          var params = {
            targets: hosts.join('\n'),
            product: product, version: version,
            bypass: dBypass._cb.checked,
            rebootWhenStaged: rebootWhenStaged,
            countdownSeconds: countdown,
            attemptOffline: dOffline._cb.checked,
            dryRun: dry,
            threads: Math.max(1, Math.min(64, parseInt(dThreads.value, 10) || 8))
          };
          driveRun = ctx.run('upgrade-drive', params, { keyOf: keyByHost, destructive: !dry });
          if (driveUnsub) driveUnsub();
          driveUnsub = driveRun.subscribe({
            status: function (t) { dStatus.textContent = t; dStatus.className = 'st-info'; },
            progress: function (p) { dProg.setProgress(p.done, p.total); },
            row: function (r) { dGrid.upsert(r); dRecount(); },
            log: function (l) { log.append(l); },
            error: function (e) { dStatus.textContent = (e && e.text) || 'Error'; dStatus.className = 'st-bad'; log.append({ text: (e && e.text) || 'error', level: 'err' }); },
            active: function (a) { dRunbar.setActive(a); if (!a) { lockDrive(false); dRecount(); } },
            final: function (res) {
              var c = { driven: 0, staged: 0, rebooting: 0, skipped: 0 };
              dGrid.rows().forEach(function (r) { var s = String(r.Status); if (s === 'DRIVEN') c.driven++; else if (s === 'STAGED' || s === 'NEEDS REBOOT') c.staged++; else if (s === 'REBOOTING') c.rebooting++; else if (s === 'Skipped' || s === 'DRY-RUN') c.skipped++; });
              dStats.setAll(c);
              var done = 'Done - ' + c.driven + ' driven, ' + c.staged + ' staged, ' + c.rebooting + ' rebooting, ' + c.skipped + ' skipped';
              dStatus.textContent = done; dStatus.className = (c.rebooting ? 'st-warn' : 'st-ok');
              log.append({ text: '[' + ts() + '] DRIVE 24H2 ' + done, level: 'ok' });
            }
          });
        }
      }

      // =================== assemble: TabHost + shared log dock ===================
      var tabHolder = el('div'); tabHolder.style.cssText = 'flex:1;min-height:0;display:flex';
      var tabs = C.TabHost({
        rail: 'top', helpId: 'winupgrade',
        tabs: [
          { id: 'fleet', label: 'Fleet Status', build: buildFleetPanel },
          { id: 'drive', label: 'Drive 24H2 (WUfB)', build: buildDrivePanel },
          { id: 'operations', label: 'Operations', build: function (panel) { panel.style.cssText = 'display:flex;flex-direction:column;height:100%;min-height:0'; panel.appendChild(opsPanel); } }
        ]
      });
      tabHolder.appendChild(tabs.el);
      root.appendChild(tabHolder);
      root.appendChild(logCard);

      // =================== init ===================
      setOpControlsEnabled();
      updateCabHint();
      refreshGuide();
      log.append({ text: 'Windows Upgrade Tool ready. Fleet Status (first tab) is a read-only board - Scan Fleet to see where every computer sits on the 24H2 journey. Operations tab runs Diagnose / Pin / Unpin / Install CAB / Force Discovery.', level: 'accent' });
      log.append({ text: 'Pin holds a feature build (optional SCCM refresh / CPU-TPM bypass); Install CAB pushes a feature update via DISM; Force Discovery re-scans (safe) or resets WU (aggressive).', level: 'dim' });

      host.appendChild(root);
      this._root = root;
      this._unsub = function () { try { if (unsub) unsub(); } catch (e) {} try { if (fleetUnsub) fleetUnsub(); } catch (e) {} try { if (driveUnsub) driveUnsub(); } catch (e) {} };
    },
    unmount: function () { try { if (this._unsub) this._unsub(); } catch (e) {} if (this._root) this._root.remove(); }
  });
})();
