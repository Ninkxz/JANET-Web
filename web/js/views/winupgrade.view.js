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
  var EXPORT_COLS = [['Host', 'Computer'], ['Ping', 'Ping'], ['Status', 'Status'], ['Category', 'Category'], ['Severity', 'Severity'], ['Evidence', 'Evidence'], ['Detail', 'Detail'], ['Fix', 'RecommendedFix']];

  // Two feature-update targets this tool understands - MinBuild is the Windows build
  // number that OS build must meet/exceed to count as "already on target".
  var VERSION_MINBUILD = { '24H2': 26100, '25H2': 26200 };

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
          + '  - System info + current OS build (24H2 = build 26100+, 25H2 = build 26200+).\n'
          + '  - Hardware compatibility: CPU (supported-model list), TPM 2.0+, Secure Boot, RAM (4 GB+), disk (64 GB+ free).\n'
          + '  - Registry state: the Target Release Version policy and the CPU/TPM MoSetup bypass.\n'
          + '  - Deferrals + blocks: DeferFeatureUpdates, DisableDualScan, pause windows, WSUS mode.\n'
          + '  - Windows Update health (services, SoftwareDistribution) and SCCM client + feature-update deployment visibility.\n\n'
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
    },
    'error-report': {
      action: 'error-report',
      radio: 'Error Report (read-only per-device error/blocker inventory)',
      guide: function (version) {
        return 'ERROR REPORT runs a comprehensive READ-ONLY scan for the target version "' + (version || '24H2') + '" and changes NOTHING.\n\n'
          + 'Unlike Diagnose (one verdict per host), this emits ONE ROW PER DETECTED ISSUE - a host with three problems produces '
          + 'three rows. Each row carries a Category (DISK / DRIVER / REGISTRY / COMPONENT_STORE / PAUSED / POLICY / STAGING / '
          + 'MEMORY / ADLDS / SETUPDIAG / NONE), a Severity (BLOCK / WARN / INFO), the raw Evidence found, and a Recommended Fix.\n\n'
          + 'Use this to see WHAT is wrong across the fleet before running Auto-Fix or Repair Health - export it as the log.'
        ;
      }
    },
    'auto-fix': {
      action: 'auto-fix',
      radio: 'Auto-Fix per device (only applies the fixes each host needs)',
      guide: function () {
        return 'AUTO-FIX analyzes EACH device individually and applies only the fixes it needs - it never touches a host that is '
          + 'already clean. Depending on which boxes are ticked it can: re-apply a missing/half-written target-release policy, set '
          + 'the CPU/TPM bypass only where hardware is genuinely unsupported, remove drivers that failed injection (optionally only '
          + 'when the device is disconnected), clear expired update-pause values, repair the component store (slow), clear stale '
          + 'rolled-back $WINDOWS.~BT staging, and refresh the SCCM/MECM client.\n\n'
          + 'Status per host: FIXED (something was changed) / NO CHANGES / ALREADY ON TARGET / DRY-RUN / FAILED / OFFLINE. '
          + 'Destructive - an admin session is required unless Dry-run.';
      }
    },
    'repair-health': {
      action: 'repair-health',
      radio: 'Repair Health (DISM /RestoreHealth + sfc /scannow)',
      guide: function () {
        return 'REPAIR HEALTH runs DISM /Online /Cleanup-Image /RestoreHealth followed by sfc /scannow on each device - the classic '
          + '"the component store or system files are corrupt" fix. This is SLOW: 15-45 minutes per device, so keep concurrency low.\n\n'
          + 'Status per host: CLEAN (nothing to repair) / REPAIRED / PARTIAL (one of DISM/SFC fixed something, the other did not) / '
          + 'DRY-RUN / FAILED / OFFLINE / Cancelled. Optionally reboots afterwards if required and no user is logged on. '
          + 'Destructive - an admin session is required unless Dry-run.';
      }
    },
    'os-audit': {
      action: 'os-audit',
      radio: 'OS Version Audit (read-only PASS/FAIL - Win11 / 24H2+ / Enterprise)',
      guide: function () {
        return 'OS VERSION AUDIT runs a READ-ONLY pass/fail check on each PC and changes NOTHING (it is a scan; self is included). '
          + 'It reads CurrentBuild / DisplayVersion / EditionID from the target and computes THREE checks with NO partial state:\n\n'
          + '  - Gen11      = Windows 11 generation (CurrentBuild >= 22000).\n'
          + '  - Rel24H2    = release 24H2 or newer (CurrentBuild >= 26100; 25H2 = 26200 and newer also PASS).\n'
          + '  - EntEdition = EditionID is EXACTLY "Enterprise" (Pro / Education / Home / Enterprise multi-session / IoT all FAIL).\n\n'
          + 'Verdict = PASS only when ALL THREE pass, otherwise FAIL with the failing-check list. Read-only: no admin session or '
          + 'Dry-run needed. Mirrors the C2C audit-tier pass/fail idiom.';
      }
    },
    'install-updates': {
      action: 'install-updates',
      radio: 'Install Windows Updates (SYSTEM task - WSUS + optional Microsoft Update)',
      guide: function () {
        return 'INSTALL WINDOWS UPDATES installs ALL available updates on each target by registering a JANET_WUA scheduled task that '
          + 'runs a Windows Update Agent driver as NT AUTHORITY\\SYSTEM (the only context in which WUA reliably Download()/Install()s - '
          + 'a remote logon token blocks it), then polls C:\\ProgramData\\JANET\\WUA\\result.json.\n\n'
          + 'It searches WSUS and - when "Also search Windows/Microsoft Update" is ticked - also Windows Update + the Microsoft Update '
          + 'catalog (catching Defender / security-platform KBs WSUS/SCCM miss). Transport cascade per host, first success wins: WinRM '
          + 'HTTPS 5986 -> WinRM HTTP 5985 -> WMI/DCOM 135.\n\nPILOT-PENDING: needs a live domain / WSUS ring to truly validate. This '
          + 'INSTALLS updates and some FORCE A REBOOT - the JANET dispatcher host is always dropped from the run. Admin session required '
          + 'unless Dry-run.';
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
      case 'REPAIRED':
      case 'FIXED':
      case 'DRIVEN':
      // os-audit verdict PASS + install-updates success statuses.
      case 'PASS':
      case 'Installed':
      case 'Online': return 'st-ok';
      // install-updates: no updates were pending (a quiet good outcome).
      case 'NoUpdates': return 'cell-dim';
      // dim: nothing needed doing (still a "good" outcome, just quieter than a fix).
      case 'NO CHANGES':
      case 'ALREADY ON TARGET': return 'cell-dim';
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
      case 'OFFLINE':
      case 'Offline':
      // os-audit verdict FAIL + install-updates hard failures.
      case 'FAIL':
      case 'InstallFailed':
      case 'Unreachable': return 'st-bad';
      // amber: needs operator attention but not a hard failure.
      // DRY-RUN = preview only; NEEDS POLICY = target-version policy missing;
      // BLOCKED = a deferral/pause is holding the build back; HW INCOMPAT = CPU/TPM fails + no bypass;
      // MEMORY = setuperr.log out-of-memory hit (run Set Page File); ERRORS = other setup error;
      // NEEDS REBOOT = change applied but a restart is still pending; PARTIAL = repair-health
      // fixed one of DISM/SFC but not the other.
      case 'DRY-RUN':
      case 'NEEDS POLICY':
      case 'BLOCKED':
      case 'HW INCOMPAT':
      case 'MEMORY':
      case 'ERRORS':
      case 'NEEDS REBOOT':
      case 'STAGED':
      case 'PARTIAL':
      // install-updates: installed but WUA reported per-update errors (needs a look).
      case 'InstalledWithErrors':
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
  //   Ready = ok/green ; Blocked = bad/red ; "Already <ver>+" (prefix match - version-
  //   aware text, e.g. "Already 25H2+") = accent/cyan ; Pending reboot = warn/amber ;
  //   Offline/Error dim/red.
  function fleetStatusCell(v) {
    var s = String(v == null ? '' : v);
    if (s === 'Ready') return { text: s, cls: 'st-ok' };
    if (s.indexOf('Blocked') === 0) return { text: s, cls: 'st-bad', title: s };
    if (s.indexOf('Already ') === 0) return { text: s, cls: 'st-info' };
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
      ['diagnose', 'os-audit', 'pin', 'unpin', 'forcediscovery', 'installcab', 'install-updates', 'setpagefile', 'error-report', 'auto-fix', 'repair-health'].forEach(function (k) {
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

        // Error Report inputs (target version) sit under the Error Report radio.
        if (k === 'error-report') {
          var erWrap = el('div'); erWrap.style.cssText = 'margin:2px 0 4px 24px;display:flex;flex-direction:column;gap:6px';
          var erVersion = ui.select({ options: [{ value: '24H2', label: '24H2' }, { value: '25H2', label: '25H2' }], value: '24H2', title: 'Target version this scan checks readiness/blockers against.' });
          erVersion.addEventListener('change', function () { if (currentOp === 'error-report') refreshGuide(); });
          erWrap.appendChild(ui.field('Target version', erVersion));
          opCard.appendChild(erWrap);
          opCard._erVersion = erVersion; opCard._erWrap = erWrap;
        }

        // Auto-Fix inputs (target version + per-device fix categories + reboot) sit under the Auto-Fix radio.
        if (k === 'auto-fix') {
          var afWrap = el('div'); afWrap.style.cssText = 'margin:2px 0 4px 24px;display:flex;flex-direction:column;gap:6px';
          var afVersion = ui.select({ options: [{ value: '24H2', label: '24H2' }, { value: '25H2', label: '25H2' }], value: '24H2', title: 'Target version to drive each device toward.' });
          afWrap.appendChild(ui.field('Target version', afVersion));
          var afCaption = el('div', 'muted', 'Each device is analyzed and gets only the fixes it needs.'); afCaption.style.fontSize = '11px';
          afWrap.appendChild(afCaption);
          var afPolicy = ui.checkbox('Target-release policy where missing/half-written', { checked: true });
          var afBypass = ui.checkbox('CPU/TPM bypass only where hardware is unsupported', { checked: true });
          var afDrivers = ui.checkbox('Remove drivers that failed injection (per device logs)', { checked: true });
          var afDriverSafe = ui.checkbox('Only remove a driver when its device is disconnected', { checked: true });
          afDriverSafe.style.marginLeft = '18px';
          var afPause = ui.checkbox('Clear expired update-pause values', { checked: true });
          var afRepair = ui.checkbox('Repair component store where logs show corruption - SLOW', { color: 'var(--warn)' });
          var afStaging = ui.checkbox('Clear stale rolled-back $WINDOWS.~BT staging', {});
          var afSccm = ui.checkbox('SCCM policy/eval refresh', { checked: true });
          var afReboot = ui.checkbox('Reboot when required and no user logged on', { color: 'var(--warn)' });
          [afPolicy, afBypass, afDrivers, afDriverSafe, afPause, afRepair, afStaging, afSccm, afReboot].forEach(function (cb) { afWrap.appendChild(cb); });
          opCard.appendChild(afWrap);
          opCard._afVersion = afVersion; opCard._afWrap = afWrap;
          opCard._afPolicy = afPolicy; opCard._afBypass = afBypass; opCard._afDrivers = afDrivers; opCard._afDriverSafe = afDriverSafe;
          opCard._afPause = afPause; opCard._afRepair = afRepair; opCard._afStaging = afStaging; opCard._afSccm = afSccm; opCard._afReboot = afReboot;
        }

        // Install Windows Updates inputs (includeMU / allowHttp / allowWmi / timeout) sit under its radio.
        if (k === 'install-updates') {
          var iuWrap = el('div'); iuWrap.style.cssText = 'margin:2px 0 4px 24px;display:flex;flex-direction:column;gap:6px';
          var iuCaption = el('div', 'muted', 'PILOT-PENDING: needs a live domain / WSUS ring. Installs updates as SYSTEM; some force a reboot.'); iuCaption.style.cssText = 'font-size:11px;color:var(--warn)';
          iuWrap.appendChild(iuCaption);
          var iuMu = ui.checkbox('Also search Windows Update + Microsoft Update (Defender / security-platform KBs)', { checked: true, title: 'On: the driver also queries Windows Update and the Microsoft Update catalog, catching KBs WSUS/SCCM does not carry. Off: WSUS/SCCM source only.' });
          var iuHttp = ui.checkbox('Allow WinRM HTTP (5985) fallback', { checked: true, title: 'Fall back to plain WinRM HTTP on 5985 if HTTPS (5986) does not connect.' });
          var iuWmi = ui.checkbox('Allow WMI/DCOM (135) fallback', { checked: true, title: 'Bootstrap the SYSTEM task over WMI/DCOM and poll result.json via \\\\host\\C$ if neither WinRM transport connects.' });
          [iuMu, iuHttp, iuWmi].forEach(function (cb) { iuWrap.appendChild(cb); });
          var iuTo = ui.number({ value: 45, min: 5, max: 720, title: 'How long to poll result.json for the SYSTEM task to finish before giving up on a host (minutes).' });
          iuTo.style.width = '90px';
          iuWrap.appendChild(ui.field('Per-host timeout (min)', iuTo));
          opCard.appendChild(iuWrap);
          opCard._iuMu = iuMu; opCard._iuHttp = iuHttp; opCard._iuWmi = iuWmi; opCard._iuTo = iuTo; opCard._iuWrap = iuWrap;
        }

        // Repair Health inputs (reboot) sit under the Repair Health radio.
        if (k === 'repair-health') {
          var rhWrap = el('div'); rhWrap.style.cssText = 'margin:2px 0 4px 24px;display:flex;flex-direction:column;gap:6px';
          var rhCaption = el('div', 'muted', 'DISM /RestoreHealth + sfc /scannow - 15-45 min per device.'); rhCaption.style.fontSize = '11px';
          rhWrap.appendChild(rhCaption);
          var rhReboot = ui.checkbox('Reboot when required and no user logged on', { color: 'var(--warn)' });
          rhWrap.appendChild(rhReboot);
          opCard.appendChild(rhWrap);
          opCard._rhReboot = rhReboot; opCard._rhWrap = rhWrap;
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
      var offlineCb = ui.checkbox('Attempt even if offline (host unreachable)', { title: 'Proceed against a host that fails the TCP 5985/5986/445 reachability probe (e.g. firewalled but WinRM up). Reachability is TCP-only - AFNET drops ICMP. A host answering only on 5986 uses WinRM-over-HTTPS.' });
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
      // Auto height (no cap): the bar/group rows wrap at narrow widths, so a fixed
      // max-height clips them - the left column scrolls instead.
      compCard.style.cssText += ';flex:0 0 auto;display:flex;flex-direction:column';
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
            if (currentOp !== 'auto-fix') return null;
            var any = opCard._afPolicy._cb.checked || opCard._afBypass._cb.checked || opCard._afDrivers._cb.checked
              || opCard._afPause._cb.checked || opCard._afRepair._cb.checked || opCard._afStaging._cb.checked || opCard._afSccm._cb.checked;
            return any ? null : 'No Fixes Enabled|Tick at least one fix category for Auto-Fix to apply.';
          },
          function () {
            if (!OPS[currentOp]) return null;            // ping isn't routed through RUN
            if (currentOp === 'diagnose' || currentOp === 'error-report' || currentOp === 'os-audit') return null;   // read-only scans - no admin session (like ping / checkupgrade)
            // destructive ops (pin/unpin/installcab/setpagefile/forcediscovery/auto-fix/repair-health)
            // require an admin session EVEN for Dry-run: the server gates on the manifest's
            // destructive flag (it never trusts a client-sent dryRun), so exempting Dry-run
            // here just trades this dialog for a server 403 and a stuck Queued row.
            return ctx.session.state.credSet ? null : 'Admin Session Required|This operation changes machines (WU policy / DISM / WU reset). Set credentials (top-right) and start an admin session (required even for Dry-run).';
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
      // keyMode is a function (not a plain hostCol) because Error Report emits MULTIPLE
      // rows per host - a Host-only key would collapse them onto one row. Every other op
      // still keys by Host, unchanged.
      function opsGridKeyOf(r) {
        if (currentOp === 'error-report') return String(r.Host || '') + '|' + String(r.Category || '') + '|' + String(r.Evidence || '').slice(0, 60);
        return r.Host != null ? String(r.Host) : null;
      }
      function severityCellCls(v) {
        var s = String(v == null ? '' : v);
        if (s === 'BLOCK') return 'st-bad'; if (s === 'WARN') return 'st-warn'; if (s === 'INFO') return 'cell-dim';
        return '';
      }
      var grid = C.ResultsGrid({
        title: 'Windows Upgrade results',
        emptyText: 'No results yet — pick hosts and an operation, then RUN.',
        keyMode: opsGridKeyOf, popOut: true,
        columns: [
          { key: 'Host', label: 'COMPUTER', width: 170 },
          { key: 'Ping', label: 'PING', width: 90, render: function (r) { return { text: r.Ping == null ? '' : String(r.Ping), cls: pingCellCls(r.Ping) }; } },
          { key: 'Status', label: 'STATUS', width: 100, render: function (r) { return { text: r.Status == null ? '' : String(r.Status), cls: statusCellCls(r.Status) }; } },
          // Category/Severity/Fix are Error Report-only columns - blank for every other op.
          { key: 'Category', label: 'CATEGORY', width: 120, render: function (r) { var t = r.Category == null ? '' : String(r.Category); return { text: t, cls: t ? 'cell-dim' : '' }; } },
          { key: 'Severity', label: 'SEVERITY', width: 80, render: function (r) { var t = r.Severity == null ? '' : String(r.Severity); return { text: t, cls: severityCellCls(t) }; } },
          { key: 'Detail', label: 'DETAIL', render: function (r) { var t = r.Detail != null ? String(r.Detail) : (r.Evidence != null ? String(r.Evidence) : ''); return { text: t, title: t }; } },
          { key: 'Fix', label: 'RECOMMENDED FIX', render: function (r) { var t = r.Fix == null ? '' : String(r.Fix); return { text: t, title: t }; } }
        ],
        rowClass: function (r) {
          if (r.Severity != null) { var sv = String(r.Severity); if (sv === 'BLOCK') return 'row-bad'; if (sv === 'WARN') return 'row-warn'; return ''; }
          var s = String(r.Status);
          if (s === 'DONE' || s === 'RESET' || s === 'READY' || s === 'ON 24H2' || s === 'Online' || s === 'CLEAN' || s === 'REPAIRED' || s === 'FIXED' || s === 'PASS' || s === 'Installed') return 'row-ok';
          if (s === 'FAILED' || s === 'Offline' || s === 'OFFLINE' || s === 'FAIL' || s === 'InstallFailed' || s === 'Unreachable') return 'row-bad';
          if (s === 'DRY-RUN' || s === 'NEEDS POLICY' || s === 'BLOCKED' || s === 'HW INCOMPAT' || s === 'MEMORY' || s === 'ERRORS' || s === 'NEEDS REBOOT' || s === 'PARTIAL' || s === 'InstalledWithErrors' || s === 'Skipped' || s === 'Cancelled') return 'row-warn';
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
        var isEr = currentOp === 'error-report', isAf = currentOp === 'auto-fix', isRh = currentOp === 'repair-health';
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
        opCard._erVersion.disabled = !isEr;
        opCard._erWrap.style.opacity = isEr ? '1' : '0.45';
        opCard._afVersion.disabled = !isAf;
        [opCard._afPolicy, opCard._afBypass, opCard._afDrivers, opCard._afDriverSafe, opCard._afPause, opCard._afRepair, opCard._afStaging, opCard._afSccm, opCard._afReboot].forEach(function (cb) { cb._cb.disabled = !isAf; });
        opCard._afWrap.style.opacity = isAf ? '1' : '0.45';
        opCard._rhReboot._cb.disabled = !isRh;
        opCard._rhWrap.style.opacity = isRh ? '1' : '0.45';
        var isIu = currentOp === 'install-updates';
        [opCard._iuMu, opCard._iuHttp, opCard._iuWmi].forEach(function (cb) { cb._cb.disabled = !isIu; });
        opCard._iuTo.disabled = !isIu;
        opCard._iuWrap.style.opacity = isIu ? '1' : '0.45';
      }
      function refreshGuide() {
        if (currentOp === 'pin') guideBox.value = OPS.pin.guide((opCard._prodInput.value || '').trim(), (opCard._verInput.value || '').trim());
        else if (currentOp === 'setpagefile') guideBox.value = OPS.setpagefile.guide(parseInt(opCard._pfSize.value, 10) || 16384);
        else if (currentOp === 'forcediscovery') guideBox.value = OPS.forcediscovery.guide((opCard._fdProdInput.value || '').trim(), (opCard._fdVerInput.value || '').trim(), opCard._fdAggressive._cb.checked);
        else if (currentOp === 'error-report') guideBox.value = OPS['error-report'].guide(opCard._erVersion.value);
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
        opCard._erVersion.disabled = on || currentOp !== 'error-report';
        opCard._afVersion.disabled = on || currentOp !== 'auto-fix';
        [opCard._afPolicy, opCard._afBypass, opCard._afDrivers, opCard._afDriverSafe, opCard._afPause, opCard._afRepair, opCard._afStaging, opCard._afSccm, opCard._afReboot].forEach(function (cb) { cb._cb.disabled = on || currentOp !== 'auto-fix'; });
        opCard._rhReboot._cb.disabled = on || currentOp !== 'repair-health';
        [opCard._iuMu, opCard._iuHttp, opCard._iuWmi].forEach(function (cb) { cb._cb.disabled = on || currentOp !== 'install-updates'; });
        opCard._iuTo.disabled = on || currentOp !== 'install-updates';
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
        var dry = dryCb._cb.checked && currentOp !== 'diagnose' && currentOp !== 'error-report' && currentOp !== 'os-audit';   // read-only ops: no Dry-run
        // reboot is per-operation: Install CAB / Set Page File / Auto-Fix / Repair Health each carry their own reboot toggle.
        var reboot = (currentOp === 'installcab') ? opCard._rebootCb._cb.checked
                   : (currentOp === 'setpagefile') ? opCard._pfReboot._cb.checked
                   : (currentOp === 'auto-fix') ? opCard._afReboot._cb.checked
                   : (currentOp === 'repair-health') ? opCard._rhReboot._cb.checked
                   : false;
        var aggressive = (currentOp === 'forcediscovery') && opCard._fdAggressive._cb.checked;
        var readonly = (currentOp === 'diagnose' || currentOp === 'error-report' || currentOp === 'os-audit');
        var cabPath = effectiveCabPath();
        var pfMb = parseInt(opCard._pfSize.value, 10) || 16384;

        // Build the desktop-style op label + Yes/No confirm.
        var opLabel;
        if (currentOp === 'diagnose') opLabel = 'DIAGNOSTIC SCAN (read-only)';
        else if (currentOp === 'os-audit') opLabel = 'OS VERSION AUDIT (read-only PASS/FAIL)';
        else if (currentOp === 'install-updates') opLabel = 'INSTALL WINDOWS UPDATES (SYSTEM task)' + (opCard._iuMu._cb.checked ? ' +MU' : '');
        else if (currentOp === 'pin') opLabel = 'PIN to ' + (opCard._prodInput.value || '').trim() + ' ' + (opCard._verInput.value || '').trim()
          + (opCard._runWuCb._cb.checked ? ' + RUN WU' : '')
          + (opCard._sccmRefreshCb._cb.checked ? ' + SCCM REFRESH' : '')
          + (opCard._bypassCb._cb.checked ? ' + BYPASS SET' : '');
        else if (currentOp === 'unpin') opLabel = 'UNPIN (remove target version policy)' + (opCard._removeBypassCb._cb.checked ? ' + remove bypass' : '');
        else if (currentOp === 'forcediscovery') opLabel = 'FORCE DISCOVERY' + (aggressive ? ' [AGGRESSIVE]' : ' [safe]');
        else if (currentOp === 'setpagefile') opLabel = 'SET PAGE FILE ' + pfMb + ' MB' + (reboot ? ' + REBOOT' : '');
        else if (currentOp === 'error-report') opLabel = 'ERROR REPORT (read-only, ' + opCard._erVersion.value + ')';
        else if (currentOp === 'auto-fix') opLabel = 'AUTO-FIX (' + opCard._afVersion.value + ')' + (reboot ? ' + REBOOT' : '');
        else if (currentOp === 'repair-health') opLabel = 'REPAIR HEALTH (DISM + SFC)' + (reboot ? ' + REBOOT' : '');
        else opLabel = 'INSTALL ' + (uploadedCabName || (cabPath ? cabPath.replace(/^.*[\\/]/, '') : 'CAB')) + (reboot ? ' + REBOOT' : '');
        if (dry) opLabel += ' [DRY-RUN]';

        var authLabel = ctx.session.state.credSet ? (ctx.session.state.user ? ('as ' + ctx.session.state.user) : 'set credential') : 'current Windows session';
        var warnReboot = ((currentOp === 'installcab' || currentOp === 'setpagefile' || currentOp === 'auto-fix' || currentOp === 'repair-health') && reboot && !dry);
        var warnAggressive = aggressive && !dry;

        var rebootMsg = (currentOp === 'setpagefile')
          ? 'WARNING: targets will REBOOT ~10 seconds after the page file is set (required to apply).'
          : (currentOp === 'auto-fix' || currentOp === 'repair-health')
          ? 'WARNING: a target may REBOOT if required and no user is logged on.'
          : 'WARNING: targets will REBOOT ~10 seconds after a successful install.';
        var aggressiveMsg = 'WARNING: Aggressive mode STOPS the Windows Update services, renames SoftwareDistribution + catroot2, and re-registers the WU DLLs before re-scanning.';
        var warnInstallUpdates = (currentOp === 'install-updates' && !dry);
        var installUpdatesMsg = 'WARNING: this INSTALLS all available Windows Updates via a SYSTEM task and some updates will FORCE A REBOOT. The JANET dispatcher host is always skipped. (Pilot-pending: validate on a small ring first.)';
        var extraWarn = '';
        if (warnReboot) extraWarn = '<br><br><span style="color:var(--bad);font-weight:700">' + rebootMsg + '</span>';
        else if (warnAggressive) extraWarn = '<br><br><span style="color:var(--bad);font-weight:700">' + aggressiveMsg + '</span>';
        else if (warnInstallUpdates) extraWarn = '<br><br><span style="color:var(--bad);font-weight:700">' + installUpdatesMsg + '</span>';

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
        // seed a Queued row per host so nothing looks empty before the first stream-back
        // (skipped for Error Report - it keys by Host+Category+Evidence, so a bare
        // Host-only placeholder would just be an extra stale row once real rows land).
        if (currentOp === 'error-report') grid.setLoading(true);
        else hosts.forEach(function (h) { grid.upsert({ Host: h, Ping: '', Status: 'Queued', Detail: 'Queued' }); });
        log.banner(opLabel + ' on ' + hosts.length + ' computer(s)');   // opLabel already carries [DRY-RUN]
        lockInputs(true);

        var params = {
          targets: hosts.join('\n'),
          attemptOffline: offlineCb._cb.checked,
          threads: threads()
        };
        if (!readonly) params.dryRun = dry;   // read-only ops take no dryRun input
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
        if (currentOp === 'error-report') { params.version = opCard._erVersion.value; }
        if (currentOp === 'install-updates') {
          params.includeMU = opCard._iuMu._cb.checked;
          params.allowHttp = opCard._iuHttp._cb.checked;
          params.allowWmi = opCard._iuWmi._cb.checked;
          params.timeoutMin = parseInt(opCard._iuTo.value, 10) || 45;
        }
        if (currentOp === 'auto-fix') {
          params.version = opCard._afVersion.value;
          params.fixPolicy = opCard._afPolicy._cb.checked;
          params.fixBypass = opCard._afBypass._cb.checked;
          params.fixDrivers = opCard._afDrivers._cb.checked;
          params.driverSafe = opCard._afDriverSafe._cb.checked;
          params.fixPause = opCard._afPause._cb.checked;
          params.fixRepair = opCard._afRepair._cb.checked;
          params.clearStaging = opCard._afStaging._cb.checked;
          params.sccmRefresh = opCard._afSccm._cb.checked;
          params.reboot = reboot;
        }
        if (currentOp === 'repair-health') { params.reboot = reboot; }
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
      // targets and rolls it up: "where is the whole fleet on the journey to the
      // selected target version (24H2 / 25H2)?".
      // Changes NOTHING - no admin session, no reboots, no policy writes.
      var fleetRun = null, fleetUnsub = null;
      var fleetGridRef = null;   // set by buildFleetPanel so both version panels can seed Ready hosts
      // Each buildVersionPanel(cfg) instance owns its OWN run/unsub state (no sharing
      // between the 24H2 and 25H2 tabs) - it registers an unsubscribe-current-run
      // callback here so unmount() can tear down whichever run is live in each tab.
      var versionPanelUnsubs = [];
      function buildFleetPanel(panel) {
        panel.style.cssText = 'display:flex;gap:14px;height:100%;min-height:0;box-sizing:border-box;padding:12px 16px';

        // LEFT: targets + options + Scan Fleet
        var fl = el('div'); fl.style.cssText = 'flex:0 0 400px;display:flex;flex-direction:column;gap:12px;min-height:0;overflow:auto';
        var compCard = ui.namedCard('COMPUTERS');   // hint comes from the TargetManager below
        compCard.style.cssText += ';flex:0 0 auto;display:flex;flex-direction:column';
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
        var fverRow = el('div'); fverRow.style.cssText = 'display:flex;align-items:center;gap:10px';
        fverRow.appendChild(ui.label('Target version:'));
        var fVersion = ui.select({ options: [{ value: '24H2', label: '24H2' }, { value: '25H2', label: '25H2' }], value: '24H2', title: 'Feature-update target the scan measures every host against ("Already on target" / build threshold).' });
        fVersion.style.width = '110px';
        fVersion.addEventListener('change', function () { fGrid.rows().length && recount(); });
        fverRow.appendChild(fVersion); fOpt.appendChild(fverRow);
        var fOffline = ui.checkbox('Attempt even if offline (host unreachable)', { title: 'Scan a host that fails the TCP 5985/5986/445 reachability probe. Reachability is TCP-only - AFNET drops ICMP. A host answering only on 5986 uses WinRM-over-HTTPS.' });
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
          { key: 'already', label: 'ALREADY ON TARGET', color: 'cyan' },
          { key: 'ready', label: 'READY', color: 'ok' },
          { key: 'blocked', label: 'BLOCKED', color: 'bad' },
          { key: 'pending', label: 'PENDING REBOOT', color: 'gold' }
        ] });
        fr.appendChild(fStats.el);

        var fHead = ui.card({}); fHead.style.cssText += ';display:flex;align-items:center;gap:12px;flex-wrap:wrap';
        var fProg = C.ProgressStatusStrip({ showCount: true });
        fProg.el.style.flex = '1'; fHead.appendChild(fProg.el);
        var fExport = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the fleet-status rows to CSV.' });
        var fCleanup = ui.ghostButton('Clean Up (low disk)', { size: 'sm', title: 'Hand every host under 64 GB free to Workstation Patching > Cleanup (temp files / ccmcache / stale profiles) to reclaim space before the upgrade.' });
        var fClear = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the fleet-status grid.' });
        fHead.appendChild(fExport); fHead.appendChild(fCleanup); fHead.appendChild(fClear);
        fCleanup.onclick = function () {
          var low = fGrid.rows().filter(function (r) { var g = parseFloat(r.FreeGB); return !isNaN(g) && g >= 0 && g < 64; }).map(function (r) { return String(r.Host); });
          if (!low.length) {
            ctx.confirm({ title: 'No Low-Disk Hosts', body: 'No scanned host is under 64 GB free. Scan Fleet first if the grid is empty.', okText: 'OK', cancelText: null });
            return;
          }
          if (window.Janet && Janet.handoff) { try { Janet.handoff.send(low, 'Windows Upgrade: low disk (<64 GB free)'); } catch (e) {} }
          log.append({ text: '[' + ts() + '] Handed ' + low.length + ' low-disk host(s) to Workstation Patching > Cleanup.', level: 'info' });
          ctx.openTool('wpt', 'cleanup');
        };
        fr.appendChild(fHead);

        var fResults = ui.namedCard('FLEET STATUS', 'One row per computer: where it sits on the feature-update journey toward the target version above. Read-only.');
        fResults.style.cssText += ';flex:1;min-height:0;display:flex;flex-direction:column';
        var fGrid = C.ResultsGrid({
          title: 'Fleet Status', emptyText: 'No results yet - add computers and Scan Fleet.',
          keyMode: { hostCol: 'Host' }, popOut: true, selectable: false,
          columns: [
            { key: 'Host', label: 'COMPUTER', width: 160 },
            { key: 'Online', label: 'ONLINE', width: 78, render: function (r) { return yesNoDim(r.Online, false); } },
            { key: 'DisplayVersion', label: 'VERSION', width: 90, render: function (r) { return { text: String(r.DisplayVersion == null ? '' : r.DisplayVersion), cls: 'cell-dim' }; } },
            { key: 'OsBuild', label: 'BUILD', width: 80, render: function (r) { var b = parseInt(r.OsBuild, 10); return { text: (b > 0 ? String(b) : ''), cls: (b >= (VERSION_MINBUILD[fVersion.value] || 26100) ? 'st-ok' : 'cell-dim') }; } },
            // System-drive free space from the scan: the upgrade needs 64+ GB free (module
            // MinDisk gate); -1 = not read (offline / pre-FreeGB scan). Red = cannot take it.
            { key: 'FreeGB', label: 'DISK FREE', width: 90, render: function (r) { var g = parseFloat(r.FreeGB); if (isNaN(g) || g < 0) { return { text: '', cls: 'cell-dim' }; } return { text: g.toFixed(1) + ' GB', cls: (g < 64 ? 'st-bad' : 'st-ok'), title: (g < 64 ? 'Below the 64 GB free the upgrade needs - use Clean Up (low disk).' : 'Enough free space for the feature update.') }; } },
            { key: 'Win24H2Status', label: 'STATUS', width: 210, render: function (r) { return fleetStatusCell(r.Win24H2Status); } },
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
        fleetGridRef = fGrid;   // Drive 24H2 / Drive 25H2 tabs can seed themselves from the Ready rows here
        var fgh = el('div'); fgh.style.cssText = 'flex:1;min-height:0;display:flex'; fgh.appendChild(fGrid.el);
        fResults.appendChild(fgh); fr.appendChild(fResults);
        panel.appendChild(fr);

        var FLEET_EXPORT = [['Host', 'Computer'], ['Online', 'Online'], ['DisplayVersion', 'DisplayVersion'], ['OsBuild', 'OsBuild'], ['FreeGB', 'FreeGB'], ['Win24H2Status', 'Win24H2Status'], ['Eligible', 'Eligible'], ['BlockReason', 'BlockReason'], ['Pinned', 'Pinned'], ['PinnedVersion', 'PinnedVersion'], ['PendingReboot', 'PendingReboot'], ['Error', 'Error']];
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
            if (s.indexOf('Already ') === 0) c.already++;
            else if (s === 'Ready') c.ready++;
            else if (s.indexOf('Blocked') === 0) c.blocked++;
            else if (s === 'Pending reboot') c.pending++;
          });
          fStats.setAll(c);
        }

        function doFleetScan() {
          var hosts = fTargets.hosts();
          var ver = fVersion.value;
          fGrid.clear(); fStats.reset(); fProg.reset();
          fStatus.textContent = 'Scanning...'; fStatus.className = 'st-info';
          log.banner('Fleet Status scan (' + ver + ', ' + hosts.length + ' computer(s))');
          fOffline.disabled = true; fThreads.disabled = true; fClear.disabled = true; fVersion.disabled = true;
          fleetRun = ctx.run('fleet-status', {
            targets: hosts.join('\n'),
            version: ver,
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
            active: function (a) { fRunbar.setActive(a); if (!a) { fOffline.disabled = false; fThreads.disabled = false; fClear.disabled = false; fVersion.disabled = false; } },
            final: function (res) {
              var s = (res && res.summary) || {};
              if (s.already24h2 != null) { fStats.setAll({ already: s.already24h2, ready: s.ready, blocked: s.blocked, pending: s.pendingReboot }); }
              else { recount(); }
              var done = 'Done - ' + (s.already24h2 || 0) + ' on ' + ver + ', ' + (s.ready || 0) + ' ready, ' + (s.blocked || 0) + ' blocked, ' + (s.pendingReboot || 0) + ' pending reboot';
              fStatus.textContent = done; fStatus.className = (s.blocked ? 'st-warn' : 'st-ok');
              log.append({ text: '[' + ts() + '] FLEET STATUS ' + done, level: (s.blocked ? 'warn' : 'ok') });
            }
          });
        }
      }

      // =================== DRIVE <VERSION> (WUfB) + REMEDIATION board ===================
      // Factory (not a single function) - called once per version tab ('24H2', '25H2')
      // so each tab gets its OWN targets/options/grids/run state; nothing is shared
      // between the two tabs except fleetGridRef (read-only seeding from Fleet Status).
      // Actively drives $Product/$version over Windows Update for Business per host: read
      // readiness, skip already-on-target / hardware-blocked (unless bypass), PIN the
      // target, TRIGGER Windows Update, re-read staged state, and (only if "Reboot when
      // staged" is ticked AND a host is CONFIRMED staged) reboot it on a per-host countdown.
      // The same tab also hosts Auto-Fix (per-device targeted remediation), Repair Health
      // (DISM+SFC) and Error Report (read-only per-issue inventory) - Drive / Auto-Fix /
      // Repair Health results land in ONE shared grid; only one of the four actions in
      // this tab can run at a time (the others' buttons disable while one is active).
      function buildVersionPanel(cfg) {
        return function (panel) {
          panel.style.cssText = 'display:flex;gap:14px;height:100%;min-height:0;box-sizing:border-box;padding:12px 16px';

          // This tab's own run/unsub - never touched by the other version tab.
          var driveRun = null, driveUnsub = null;
          function panelBusy() { return !!(driveRun && driveRun.state && driveRun.state.active); }

          // LEFT: targets + options + Drive + Remediation
          var dl = el('div'); dl.style.cssText = 'flex:0 0 420px;display:flex;flex-direction:column;gap:12px;min-height:0;overflow:auto';

          var dCompCard = ui.namedCard('COMPUTERS');   // hint comes from the TargetManager below
          dCompCard.style.cssText += ';flex:0 0 auto;display:flex;flex-direction:column';
          var dTargets = C.TargetManager({
            model: ctx.util.targetModel(''),
            hint: 'One host per line - comma/space/semicolon ok; # starts a comment.',
            placeholder: 'WS-0001\nWS-0002\n# lab row\nWS-0003',
            importLabel: 'Import TXT', importAccept: '.txt', countNoun: 'computer',
            onImport: function (n, name) { log.append({ text: '[' + ts() + '] Added ' + n + ' computer(s) from ' + name, level: 'info' }); }
          });
          var dth = el('div'); dth.style.cssText = 'flex:1;min-height:0;display:flex'; dth.appendChild(dTargets.el);
          dCompCard.appendChild(dth);
          var seedBtn = ui.ghostButton('Seed READY hosts from Fleet Status', { size: 'sm', title: 'Copy the hosts the Fleet Status board classified "Ready" into this list.' });
          seedBtn.style.marginTop = '6px';
          seedBtn.onclick = function () {
            if (!fleetGridRef) { ctx.confirm({ title: 'No Fleet Status yet', body: 'Open the Fleet Status tab and Scan Fleet first - then this copies its READY hosts here.', okText: 'OK', cancelText: null }); return; }
            var ready = fleetGridRef.rows().filter(function (r) { return String(r.Win24H2Status) === 'Ready'; }).map(function (r) { return String(r.Host); });
            if (!ready.length) { ctx.confirm({ title: 'No READY hosts', body: 'The Fleet Status board has no hosts classified READY. Scan the fleet first, or add hosts manually.', okText: 'OK', cancelText: null }); return; }
            dTargets.setText(ready.join('\n'));
            log.append({ text: '[' + ts() + '] Seeded ' + ready.length + ' READY host(s) from Fleet Status.', level: 'info' });
          };
          dCompCard.appendChild(seedBtn);
          var errorReportBtn = ui.ghostButton('ERROR REPORT (read-only)', { size: 'sm', title: 'Scan every computer for detected errors/blockers against ' + cfg.label + ' - one row per issue found, changes nothing.' });
          errorReportBtn.style.marginTop = '6px';
          errorReportBtn.onclick = doErrorReport;
          dCompCard.appendChild(errorReportBtn);
          dl.appendChild(dCompCard);

          var dOpt = ui.card({}); dOpt.style.cssText += ';display:flex;flex-direction:column;gap:10px';
          var dOptH = el('div', 'j-section-h', 'DRIVE OPTIONS'); dOptH.style.marginBottom = '2px'; dOpt.appendChild(dOptH);
          var pvRow = el('div'); pvRow.style.cssText = 'display:flex;gap:10px';
          var dProd = ui.input({ value: 'Windows 11', title: 'Windows Update for Business ProductVersion to pin, e.g. "Windows 11".' }); dProd.style.width = '150px';
          var dVer  = ui.input({ value: cfg.key, title: 'TargetReleaseVersionInfo to pin/drive to, e.g. "' + cfg.key + '".' }); dVer.style.width = '90px';
          pvRow.appendChild(ui.field('Product', dProd)); pvRow.appendChild(ui.field('Version', dVer));
          dOpt.appendChild(pvRow);
          var dBypass = ui.checkbox('Apply CPU/TPM bypass for unsupported hardware (MoSetup)', { color: 'var(--warn)', title: 'Sets MoSetup\\AllowUpgradesWithUnsupportedTPMOrCPU = 1 and lets this tool drive an otherwise hardware-blocked host. Microsoft-unsupported config. Without it, hardware-blocked hosts are SKIPPED.' });
          dOpt.appendChild(dBypass);

          // --- REBOOT-WHEN-STAGED: the customer-affecting control, visually distinct ---
          var dangerBox = el('div');
          dangerBox.style.cssText = 'border:1px solid var(--bad);border-radius:6px;padding:8px 10px;display:flex;flex-direction:column;gap:8px;background:rgba(255,80,80,0.06)';
          var dangerH = el('div', null, 'CUSTOMER-AFFECTING'); dangerH.style.cssText = 'font-size:11px;font-weight:700;letter-spacing:.06em;color:var(--bad)';
          dangerBox.appendChild(dangerH);
          var dReboot = ui.checkbox('Reboot a host when it is CONFIRMED staged (per-host countdown)', { color: 'var(--bad)', title: 'After triggering WU, any host confirmed staged (feature update pending) will REBOOT after the countdown to complete ' + cfg.label + '. An un-staged host is never rebooted. The JANET dispatcher box is dropped from the wave.' });
          dangerBox.appendChild(dReboot);
          var cdRow = el('div'); cdRow.style.cssText = 'display:flex;align-items:center;gap:10px';
          cdRow.appendChild(ui.label('Countdown (seconds):'));
          var dCountdown = ui.number({ value: 300, min: 30, max: 86400, title: 'Per-host reboot countdown before a staged host restarts. Default 300 (5 min).' }); dCountdown.style.width = '100px';
          cdRow.appendChild(dCountdown);
          dangerBox.appendChild(cdRow);
          dOpt.appendChild(dangerBox);

          var dDry = ui.checkbox('Dry-run (no changes - reports what WOULD happen)', { color: 'var(--warn)', title: 'Reads readiness and reports the intended change per host without writing or rebooting anything. Applies to Drive, Auto-Fix and Repair Health (Error Report is always read-only).' });
          dOpt.appendChild(dDry);
          var dOffline = ui.checkbox('Attempt even if offline (host unreachable)', { title: 'Proceed against a host that fails the TCP 5985/5986/445 probe. Reachability is TCP-only - AFNET drops ICMP. A host answering only on 5986 uses WinRM-over-HTTPS.' });
          dOpt.appendChild(dOffline);
          var dThrRow = el('div'); dThrRow.style.cssText = 'display:flex;align-items:center;gap:10px';
          dThrRow.appendChild(ui.label('Max concurrent:'));
          var dThreads = ui.number({ value: 8, min: 1, max: 64, title: 'Parallel hosts (1-64). Drive/Auto-Fix are heavy per host, so this defaults low (8); Repair Health is throttled further regardless of this value.' }); dThreads.style.width = '80px';
          dThrRow.appendChild(dThreads); dOpt.appendChild(dThrRow);
          var dStatus = el('div', 'muted', 'Ready'); dStatus.style.fontSize = '12px'; dOpt.appendChild(dStatus);
          dl.appendChild(dOpt);

          var dActCard = ui.card({}); dActCard.style.cssText += ';display:flex;flex-direction:column;gap:8px';
          var dRunbar = C.RunBar({
            label: 'DRIVE ' + cfg.key, cancelLabel: 'CANCEL DRIVE', morphToCancel: true,
            title: 'Pin + trigger Windows Update (and optionally reboot staged hosts) across every computer.',
            guards: [
              function () { return panelBusy() ? 'Run In Progress|Another action is already running in this tab - wait for it to finish or cancel it first.' : null; },
              function () { return dTargets.count() ? null : 'No Computers|Add at least one computer before driving.'; },
              function () {
                var p = (dProd.value || '').trim(), v = (dVer.value || '').trim();
                return (p && v) ? null : 'Product + Version Required|Drive needs both a Product (e.g. "Windows 11") and a Version (e.g. "' + cfg.key + '").';
              },
              function () {
                // Admin session required EVEN for Dry-run: the server gates on the manifest's
                // destructive flag and never trusts a client-sent dryRun (403 otherwise).
                return ctx.session.state.credSet ? null : 'Admin Session Required|Driving ' + cfg.key + ' pins policy, triggers WU and (optionally) reboots hosts. Set credentials (top-right) and start an admin session (required even for Dry-run).';
              }
            ],
            onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
            onRun: doDrive,
            onCancel: function () { if (driveRun) { driveRun.cancel(); log.append({ text: '[' + ts() + '] CANCEL requested - queued computers skip; in-flight drives finish.', level: 'warn' }); } }
          });
          var drb = el('div'); drb.appendChild(dRunbar.el); dActCard.appendChild(drb); dl.appendChild(dActCard);

          // --- REMEDIATION: Auto-Fix (per-device targeted) + Repair Health (DISM+SFC) ---
          var remCard = ui.namedCard('REMEDIATION');
          remCard.style.cssText += ';display:flex;flex-direction:column;gap:8px';

          var afH = el('div', 'j-section-h', 'AUTO-FIX'); afH.style.marginBottom = '2px'; remCard.appendChild(afH);
          var afCaption = el('div', 'muted', 'Each device is analyzed and gets only the fixes it needs.'); afCaption.style.fontSize = '11px'; remCard.appendChild(afCaption);
          var afPolicy = ui.checkbox('Target-release policy where missing/half-written', { checked: true }); remCard.appendChild(afPolicy);
          var afBypass = ui.checkbox('CPU/TPM bypass only where hardware is unsupported', { checked: true }); remCard.appendChild(afBypass);
          var afDrivers = ui.checkbox('Remove drivers that failed injection (per device logs)', { checked: true }); remCard.appendChild(afDrivers);
          var afDriverSafe = ui.checkbox('Only remove a driver when its device is disconnected', { checked: true }); afDriverSafe.style.marginLeft = '18px'; remCard.appendChild(afDriverSafe);
          var afPause = ui.checkbox('Clear expired update-pause values', { checked: true }); remCard.appendChild(afPause);
          var afRepair = ui.checkbox('Repair component store where logs show corruption - SLOW', { color: 'var(--warn)' }); remCard.appendChild(afRepair);
          var afStaging = ui.checkbox('Clear stale rolled-back $WINDOWS.~BT staging', {}); remCard.appendChild(afStaging);
          var afSccm = ui.checkbox('SCCM policy/eval refresh', { checked: true }); remCard.appendChild(afSccm);
          var afReboot = ui.checkbox('Reboot when required and no user logged on', { color: 'var(--warn)' }); remCard.appendChild(afReboot);
          var afRunbar = C.RunBar({
            label: 'AUTO-FIX', cancelLabel: 'CANCEL AUTO-FIX', morphToCancel: true,
            title: 'Analyze each device against ' + cfg.label + ' and apply only the fixes it needs.',
            guards: [
              function () { return panelBusy() ? 'Run In Progress|Another action is already running in this tab - wait for it to finish or cancel it first.' : null; },
              function () { return dTargets.count() ? null : 'No Computers|Add at least one computer before running Auto-Fix.'; },
              function () {
                var any = afPolicy._cb.checked || afBypass._cb.checked || afDrivers._cb.checked || afPause._cb.checked || afRepair._cb.checked || afStaging._cb.checked || afSccm._cb.checked;
                return any ? null : 'No Fixes Enabled|Tick at least one fix category for Auto-Fix to apply.';
              },
              function () {
                // Server enforces this even for Dry-run (manifest destructive flag).
                return ctx.session.state.credSet ? null : 'Admin Session Required|Auto-Fix can change policy/drivers/component store. Set credentials (top-right) and start an admin session (required even for Dry-run).';
              }
            ],
            onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
            onRun: doAutoFix,
            onCancel: function () { if (driveRun) { driveRun.cancel(); log.append({ text: '[' + ts() + '] CANCEL requested - queued computers skip; in-flight fixes finish.', level: 'warn' }); } }
          });
          var afrb = el('div'); afrb.style.marginTop = '4px'; afrb.appendChild(afRunbar.el); remCard.appendChild(afrb);

          var rhH = el('div', 'j-section-h', 'REPAIR HEALTH'); rhH.style.cssText += ';margin-top:8px'; remCard.appendChild(rhH);
          var rhCaption = el('div', 'muted', 'DISM /RestoreHealth + sfc /scannow - 15-45 min per device.'); rhCaption.style.fontSize = '11px'; remCard.appendChild(rhCaption);
          var rhReboot = ui.checkbox('Reboot when required and no user logged on', { color: 'var(--warn)' }); remCard.appendChild(rhReboot);
          var rhRunbar = C.RunBar({
            label: 'REPAIR HEALTH (DISM + SFC)', cancelLabel: 'CANCEL REPAIR', morphToCancel: true,
            title: 'DISM /RestoreHealth + sfc /scannow on every computer (slow - concurrency is capped low regardless of Max concurrent).',
            guards: [
              function () { return panelBusy() ? 'Run In Progress|Another action is already running in this tab - wait for it to finish or cancel it first.' : null; },
              function () { return dTargets.count() ? null : 'No Computers|Add at least one computer before running Repair Health.'; },
              function () {
                // Server enforces this even for Dry-run (manifest destructive flag).
                return ctx.session.state.credSet ? null : 'Admin Session Required|Repair Health runs DISM/SFC and can reboot. Set credentials (top-right) and start an admin session (required even for Dry-run).';
              }
            ],
            onGuardFail: function (m) { var p = m.split('|'); ctx.confirm({ title: p[0], body: p[1] || p[0], okText: 'OK', cancelText: null }); },
            onRun: doRepairHealth,
            onCancel: function () { if (driveRun) { driveRun.cancel(); log.append({ text: '[' + ts() + '] CANCEL requested - queued computers skip; in-flight repairs finish.', level: 'warn' }); } }
          });
          var rhrb = el('div'); rhrb.style.marginTop = '4px'; rhrb.appendChild(rhRunbar.el); remCard.appendChild(rhrb);
          dl.appendChild(remCard);
          panel.appendChild(dl);

          // RIGHT: stat cards + progress + main grid (Drive/Auto-Fix/Repair Health share it), then Errors grid
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
          var dExport = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the result rows to CSV.' });
          var dClear = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the results grid.' });
          dHead.appendChild(dExport); dHead.appendChild(dClear);
          dr.appendChild(dHead);

          var dResults = ui.namedCard('RESULTS', 'One row per computer: Drive / Auto-Fix / Repair Health all stream into this grid (only one runs at a time).');
          dResults.style.cssText += ';flex:1.4;min-height:0;display:flex;flex-direction:column';
          var dGrid = C.ResultsGrid({
            title: cfg.label + ' results', emptyText: 'No results yet - add computers, then Drive / Auto-Fix / Repair Health.',
            keyMode: { hostCol: 'Host' }, popOut: true, selectable: false,
            columns: [
              { key: 'Host', label: 'COMPUTER', width: 150 },
              { key: 'Ping', label: 'PING', width: 74, render: function (r) { return { text: r.Ping == null ? '' : String(r.Ping), cls: pingCellCls(r.Ping) }; } },
              { key: 'Online', label: 'ONLINE', width: 70, render: function (r) { return yesNoDim(r.Online, false); } },
              { key: 'OsBuild', label: 'BUILD', width: 76, render: function (r) { var b = parseInt(r.OsBuild, 10); return { text: (b > 0 ? String(b) : ''), cls: (b >= cfg.minBuild ? 'st-ok' : 'cell-dim') }; } },
              { key: 'DisplayVersion', label: 'VER', width: 74, render: function (r) { return { text: String(r.DisplayVersion == null ? '' : r.DisplayVersion), cls: 'cell-dim' }; } },
              { key: 'Status', label: 'STATUS', width: 104, render: function (r) { return { text: String(r.Status == null ? '' : r.Status), cls: statusCellCls(r.Status) }; } },
              { key: 'WasPinned', label: 'PINNED', width: 68, render: function (r) { return yesNoDim(r.WasPinned, false); } },
              { key: 'TriggerResult', label: 'WU TRIGGER', width: 200, render: function (r) { var t = String(r.TriggerResult == null ? '' : r.TriggerResult); return { text: t, title: t, cls: 'cell-dim' }; } },
              { key: 'Staged', label: 'STAGED', width: 70, render: function (r) { var y = yesNoDim(r.Staged, false); if (y.text === 'Yes') y.cls = 'st-warn'; return y; } },
              { key: 'Rebooted', label: 'REBOOTED', width: 84, render: function (r) { return yesNoDim(r.Rebooted, true); } },
              { key: 'CountdownSec', label: 'COUNTDOWN', width: 92, render: function (r) { var c = parseInt(r.CountdownSec, 10); return { text: (c > 0 ? (c + 's') : ''), cls: (c > 0 ? 'st-warn' : 'cell-dim') }; } },
              // Dism/Sfc (Repair Health) and Fixes/RebootNeeded (Auto-Fix + Repair Health) are
              // blank-tolerant: they render empty/dim for Drive rows, which don't send them.
              { key: 'Dism', label: 'DISM', width: 84, render: function (r) { var t = r.Dism == null ? '' : String(r.Dism); return { text: t, cls: t ? statusCellCls(t) : 'cell-dim' }; } },
              { key: 'Sfc', label: 'SFC', width: 84, render: function (r) { var t = r.Sfc == null ? '' : String(r.Sfc); return { text: t, cls: t ? statusCellCls(t) : 'cell-dim' }; } },
              { key: 'Fixes', label: 'FIXES', width: 160, render: function (r) { var t = r.Fixes == null ? '' : String(r.Fixes); return { text: t, title: t, cls: t ? 'cell-dim' : '' }; } },
              { key: 'RebootNeeded', label: 'REBOOT NEEDED', width: 120, render: function (r) { return yesNoDim(r.RebootNeeded, true); } },
              { key: 'Skipped', label: 'SKIPPED', width: 140, render: function (r) { var t = String(r.Skipped == null ? '' : r.Skipped); return { text: t, title: t, cls: t ? 'st-warn' : 'cell-dim' }; } },
              { key: 'Detail', label: 'DETAIL', render: function (r) { var t = String(r.Detail == null ? '' : r.Detail); return { text: t, title: t }; } },
              { key: 'Error', label: 'ERROR', width: 150, render: function (r) { var t = String(r.Error == null ? '' : r.Error); return { text: t, title: t, cls: t ? 'st-bad' : 'cell-dim' }; } }
            ],
            rowClass: function (r) {
              var s = String(r.Status);
              if (s === 'DRIVEN' || s === 'REBOOTING' || s === 'REPAIRED' || s === 'FIXED' || s === 'CLEAN') return 'row-ok';
              if (s === 'FAILED' || s === 'Offline' || s === 'OFFLINE') return 'row-bad';
              if (s === 'STAGED' || s === 'NEEDS REBOOT' || s === 'PARTIAL' || s === 'Skipped' || s === 'DRY-RUN' || s === 'Cancelled') return 'row-warn';
              return '';
            }
          });
          var dgh = el('div'); dgh.style.cssText = 'flex:1;min-height:0;display:flex'; dgh.appendChild(dGrid.el);
          dResults.appendChild(dgh); dr.appendChild(dResults);

          // --- ERRORS: second grid, fed only by Error Report (composite keyOf - multiple rows per host) ---
          var eHead = el('div'); eHead.style.cssText = 'display:flex;align-items:center;gap:8px';
          var eSpacer = el('div'); eSpacer.style.flex = '1'; eHead.appendChild(eSpacer);
          var eExport = ui.ghostButton('Export CSV', { size: 'sm', title: 'Export the error-report rows to CSV.' });
          var eClear = ui.button('Clear', { variant: 'danger', size: 'sm', title: 'Clear the errors grid.' });
          eHead.appendChild(eExport); eHead.appendChild(eClear);
          var eResults = ui.namedCard('ERRORS', 'One row per detected error - export for the log.');
          eResults.style.cssText += ';flex:1;min-height:180px;display:flex;flex-direction:column';
          eResults.appendChild(eHead);
          function errKeyOf(r) { return String(r.Host || '') + '|' + String(r.Category || '') + '|' + String(r.Evidence || '').slice(0, 60); }
          var eGrid = C.ResultsGrid({
            title: cfg.label + ' errors', emptyText: 'No results yet - run ERROR REPORT.',
            keyMode: errKeyOf, popOut: true, selectable: false,
            columns: [
              { key: 'Host', label: 'COMPUTER', width: 140 },
              { key: 'Category', label: 'CATEGORY', width: 130, render: function (r) { var t = r.Category == null ? '' : String(r.Category); return { text: t, cls: 'cell-dim' }; } },
              { key: 'Severity', label: 'SEVERITY', width: 90, render: function (r) { var t = r.Severity == null ? '' : String(r.Severity); return { text: t, cls: severityCellCls(t) }; } },
              { key: 'Evidence', label: 'EVIDENCE', render: function (r) { var t = r.Evidence == null ? '' : String(r.Evidence); return { text: t, title: t }; } },
              { key: 'Fix', label: 'RECOMMENDED FIX', render: function (r) { var t = r.Fix == null ? '' : String(r.Fix); return { text: t, title: t }; } }
            ],
            rowClass: function (r) { var s = String(r.Severity); if (s === 'BLOCK') return 'row-bad'; if (s === 'WARN') return 'row-warn'; return ''; }
          });
          var egh = el('div'); egh.style.cssText = 'flex:1;min-height:0;display:flex'; egh.appendChild(eGrid.el);
          eResults.appendChild(egh); dr.appendChild(eResults);
          panel.appendChild(dr);

          var MAIN_EXPORT = [['Host', 'Computer'], ['Ping', 'Ping'], ['Online', 'Online'], ['OsBuild', 'OsBuild'], ['DisplayVersion', 'DisplayVersion'], ['Status', 'Status'], ['WasPinned', 'Pinned'], ['TriggerResult', 'TriggerResult'], ['Staged', 'Staged'], ['Rebooted', 'Rebooted'], ['CountdownSec', 'CountdownSec'], ['Dism', 'Dism'], ['Sfc', 'Sfc'], ['Fixes', 'Fixes'], ['RebootNeeded', 'RebootNeeded'], ['Skipped', 'Skipped'], ['Detail', 'Detail'], ['Error', 'Error']];
          dExport.onclick = function () {
            var rows = dGrid.rows();
            if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Run Drive / Auto-Fix / Repair Health first - there are no rows yet.', okText: 'OK', cancelText: null }); return; }
            var csv = ctx.util.toCsv(MAIN_EXPORT.map(function (p) { return p[1]; }), rows, MAIN_EXPORT.map(function (p) { return p[0]; }));
            ctx.util.downloadBlob('WindowsUpgrade_' + cfg.key + '_Results_' + ctx.util.fileStamp() + '.csv', 'text/csv', csv);
            log.append({ text: '[' + ts() + '] Exported ' + rows.length + ' result row(s) to CSV.', level: 'info' });
          };
          dClear.onclick = function () { if (panelBusy()) return; dGrid.clear(); dStats.reset(); dProg.reset(); dStatus.textContent = 'Ready'; dStatus.className = 'muted'; };

          var ERR_EXPORT = [['Host', 'Computer'], ['Category', 'Category'], ['Severity', 'Severity'], ['Evidence', 'Evidence'], ['Fix', 'RecommendedFix']];
          eExport.onclick = function () {
            var rows = eGrid.rows();
            if (!rows.length) { ctx.confirm({ title: 'Nothing to export', body: 'Run ERROR REPORT first - there are no rows yet.', okText: 'OK', cancelText: null }); return; }
            var csv = ctx.util.toCsv(ERR_EXPORT.map(function (p) { return p[1]; }), rows, ERR_EXPORT.map(function (p) { return p[0]; }));
            ctx.util.downloadBlob('WindowsUpgrade_Errors_' + cfg.key + '_' + ctx.util.fileStamp() + '.csv', 'text/csv', csv);
            log.append({ text: '[' + ts() + '] Exported ' + rows.length + ' error row(s) to CSV.', level: 'info' });
          };
          eClear.onclick = function () { if (panelBusy()) return; eGrid.clear(); };

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

          // Full-tab lock: only one of Drive / Auto-Fix / Repair Health / Error Report can
          // run at a time, so every input + the OTHER buttons' cta lock while any one runs.
          function lockPanel(on) {
            dProd.disabled = on; dVer.disabled = on; dBypass._cb.disabled = on;
            dReboot._cb.disabled = on; dCountdown.disabled = on;
            dDry._cb.disabled = on; dOffline._cb.disabled = on; dThreads.disabled = on;
            dClear.disabled = on; seedBtn.disabled = on; errorReportBtn.disabled = on; eClear.disabled = on;
            [afPolicy, afBypass, afDrivers, afDriverSafe, afPause, afRepair, afStaging, afSccm, afReboot].forEach(function (cb) { cb._cb.disabled = on; });
            rhReboot._cb.disabled = on;
          }
          function lockOtherRunbars(mine, on) {
            [dRunbar, afRunbar, rhRunbar].forEach(function (rb) { if (rb !== mine) rb.cta.disabled = on; });
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
              title: 'Confirm Drive ' + cfg.key, danger: warnReboot,
              body: confirmBody, list: hosts.slice(0, 6),
              preflight: { targets: hosts, actionLabel: 'Drive ' + cfg.key },
              okText: dry ? 'Preview' : 'Drive', cancelText: 'Cancel'
            });
            if (!ok) { log.append({ text: '[' + ts() + '] Drive cancelled at confirm.', level: 'warn' }); return; }

            dGrid.clear(); dStats.reset(); dProg.reset();
            hosts.forEach(function (h) { dGrid.upsert({ Host: h, Online: false, OsBuild: 0, DisplayVersion: '', WasPinned: false, TriggerResult: '', Staged: false, Rebooted: false, CountdownSec: 0, Skipped: '', Error: '', Status: 'Queued', Detail: 'Queued' }); });
            dStatus.textContent = 'Driving...'; dStatus.className = 'st-info';
            log.banner(label + ' on ' + hosts.length + ' computer(s)');
            lockPanel(true);

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
              active: function (a) { dRunbar.setActive(a); lockOtherRunbars(dRunbar, a); lockPanel(a); if (!a) dRecount(); },
              final: function (res) {
                var c = { driven: 0, staged: 0, rebooting: 0, skipped: 0 };
                dGrid.rows().forEach(function (r) { var s = String(r.Status); if (s === 'DRIVEN') c.driven++; else if (s === 'STAGED' || s === 'NEEDS REBOOT') c.staged++; else if (s === 'REBOOTING') c.rebooting++; else if (s === 'Skipped' || s === 'DRY-RUN') c.skipped++; });
                dStats.setAll(c);
                var done = 'Done - ' + c.driven + ' driven, ' + c.staged + ' staged, ' + c.rebooting + ' rebooting, ' + c.skipped + ' skipped';
                dStatus.textContent = done; dStatus.className = (c.rebooting ? 'st-warn' : 'st-ok');
                log.append({ text: '[' + ts() + '] DRIVE ' + cfg.key + ' ' + done, level: 'ok' });
              }
            });
          }

          async function doAutoFix() {
            var hosts = dTargets.hosts();
            var dry = dDry._cb.checked;
            var reboot = afReboot._cb.checked;
            var label = 'AUTO-FIX (' + cfg.key + ')' + (reboot ? ' + REBOOT' : '') + (dry ? ' [DRY-RUN]' : '');
            var authLabel = ctx.session.state.credSet ? (ctx.session.state.user ? ('as ' + ctx.session.state.user) : 'set credential') : 'current Windows session';
            var warnReboot = reboot && !dry;
            var extraWarn = warnReboot ? '<br><br><span style="color:var(--bad);font-weight:700">WARNING: a device may REBOOT if required and no user is logged on.</span>' : '';
            var confirmBody = 'Operation: <b>' + escHtml(label) + '</b><br>'
              + 'Targets: <b>' + hosts.length + '</b><br>'
              + 'Auth: <b>' + escHtml(authLabel) + '</b>'
              + extraWarn;

            var ok = await ctx.confirm({
              title: 'Confirm Auto-Fix', danger: !dry,
              body: confirmBody, list: hosts.slice(0, 6),
              preflight: { targets: hosts, actionLabel: 'Auto-Fix' },
              okText: dry ? 'Preview' : 'Run', cancelText: 'Cancel'
            });
            if (!ok) { log.append({ text: '[' + ts() + '] Auto-Fix cancelled at confirm.', level: 'warn' }); return; }

            dGrid.clear(); dStats.reset(); dProg.reset();
            hosts.forEach(function (h) { dGrid.upsert({ Host: h, Status: 'Queued', Detail: 'Queued' }); });
            dStatus.textContent = 'Auto-fixing...'; dStatus.className = 'st-info';
            log.banner(label + ' on ' + hosts.length + ' computer(s)');
            lockPanel(true);

            var params = {
              targets: hosts.join('\n'), version: cfg.key,
              fixPolicy: afPolicy._cb.checked, fixBypass: afBypass._cb.checked, fixDrivers: afDrivers._cb.checked,
              driverSafe: afDriverSafe._cb.checked, fixPause: afPause._cb.checked, fixRepair: afRepair._cb.checked,
              clearStaging: afStaging._cb.checked, sccmRefresh: afSccm._cb.checked, reboot: reboot,
              attemptOffline: dOffline._cb.checked, dryRun: dry,
              threads: Math.max(1, Math.min(64, parseInt(dThreads.value, 10) || 8))
            };
            driveRun = ctx.run('auto-fix', params, { keyOf: keyByHost, destructive: !dry });
            if (driveUnsub) driveUnsub();
            driveUnsub = driveRun.subscribe({
              status: function (t) { dStatus.textContent = t; dStatus.className = 'st-info'; },
              progress: function (p) { dProg.setProgress(p.done, p.total); },
              row: function (r) { dGrid.upsert(r); },
              log: function (l) { log.append(l); },
              error: function (e) { dStatus.textContent = (e && e.text) || 'Error'; dStatus.className = 'st-bad'; log.append({ text: (e && e.text) || 'error', level: 'err' }); },
              active: function (a) { afRunbar.setActive(a); lockOtherRunbars(afRunbar, a); lockPanel(a); },
              final: function () {
                var done = 'Done - Auto-Fix complete on ' + hosts.length + ' computer(s).';
                dStatus.textContent = done; dStatus.className = 'st-ok';
                log.append({ text: '[' + ts() + '] AUTO-FIX ' + done, level: 'ok' });
              }
            });
          }

          async function doRepairHealth() {
            var hosts = dTargets.hosts();
            var dry = dDry._cb.checked;
            var reboot = rhReboot._cb.checked;
            var label = 'REPAIR HEALTH (DISM + SFC)' + (reboot ? ' + REBOOT' : '') + (dry ? ' [DRY-RUN]' : '');
            var authLabel = ctx.session.state.credSet ? (ctx.session.state.user ? ('as ' + ctx.session.state.user) : 'set credential') : 'current Windows session';
            var warnReboot = reboot && !dry;
            var extraWarn = warnReboot ? '<br><br><span style="color:var(--bad);font-weight:700">WARNING: a device may REBOOT if required and no user is logged on.</span>' : '';
            var confirmBody = 'Operation: <b>' + escHtml(label) + '</b><br>'
              + 'Targets: <b>' + hosts.length + '</b><br>'
              + 'Auth: <b>' + escHtml(authLabel) + '</b><br>'
              + '<span class="muted">DISM /RestoreHealth + sfc /scannow - allow 15-45 minutes per device.</span>'
              + extraWarn;

            var ok = await ctx.confirm({
              title: 'Confirm Repair Health', danger: !dry,
              body: confirmBody, list: hosts.slice(0, 6),
              preflight: { targets: hosts, actionLabel: 'Repair Health' },
              okText: dry ? 'Preview' : 'Run', cancelText: 'Cancel'
            });
            if (!ok) { log.append({ text: '[' + ts() + '] Repair Health cancelled at confirm.', level: 'warn' }); return; }

            dGrid.clear(); dStats.reset(); dProg.reset();
            hosts.forEach(function (h) { dGrid.upsert({ Host: h, Status: 'Queued', Detail: 'Queued' }); });
            dStatus.textContent = 'Repairing...'; dStatus.className = 'st-info';
            log.banner(label + ' on ' + hosts.length + ' computer(s)');
            lockPanel(true);

            var params = {
              targets: hosts.join('\n'),
              reboot: reboot,
              attemptOffline: dOffline._cb.checked,
              dryRun: dry,
              threads: Math.max(1, Math.min(4, parseInt(dThreads.value, 10) || 4))
            };
            driveRun = ctx.run('repair-health', params, { keyOf: keyByHost, destructive: !dry });
            if (driveUnsub) driveUnsub();
            driveUnsub = driveRun.subscribe({
              status: function (t) { dStatus.textContent = t; dStatus.className = 'st-info'; },
              progress: function (p) { dProg.setProgress(p.done, p.total); },
              row: function (r) { dGrid.upsert(r); },
              log: function (l) { log.append(l); },
              error: function (e) { dStatus.textContent = (e && e.text) || 'Error'; dStatus.className = 'st-bad'; log.append({ text: (e && e.text) || 'error', level: 'err' }); },
              active: function (a) { rhRunbar.setActive(a); lockOtherRunbars(rhRunbar, a); lockPanel(a); },
              final: function () {
                var done = 'Done - Repair Health complete on ' + hosts.length + ' computer(s).';
                dStatus.textContent = done; dStatus.className = 'st-ok';
                log.append({ text: '[' + ts() + '] REPAIR HEALTH ' + done, level: 'ok' });
              }
            });
          }

          function doErrorReport() {
            if (panelBusy()) { ctx.confirm({ title: 'Run In Progress', body: 'Another action is already running in this tab - wait for it to finish or cancel it first.', okText: 'OK', cancelText: null }); return; }
            if (!dTargets.count()) { ctx.confirm({ title: 'No Computers', body: 'Add at least one computer to scan.', okText: 'OK', cancelText: null }); return; }
            var hosts = dTargets.hosts();
            eGrid.clear(); eGrid.setLoading(true);
            dStatus.textContent = 'Error Report scanning...'; dStatus.className = 'st-info';
            log.banner('ERROR REPORT (' + cfg.key + ', ' + hosts.length + ' computer(s))');
            lockPanel(true); lockOtherRunbars(null, true);

            driveRun = ctx.run('error-report', {
              targets: hosts.join('\n'), version: cfg.key,
              attemptOffline: dOffline._cb.checked,
              threads: Math.max(1, Math.min(64, parseInt(dThreads.value, 10) || 16))
            }, { keyOf: errKeyOf, destructive: false });
            if (driveUnsub) driveUnsub();
            driveUnsub = driveRun.subscribe({
              status: function (t) { dStatus.textContent = t; dStatus.className = 'st-info'; },
              progress: function (p) { dProg.setProgress(p.done, p.total); },
              row: function (r) { eGrid.upsert(r); },
              log: function (l) { log.append(l); },
              error: function (e) { dStatus.textContent = (e && e.text) || 'Error'; dStatus.className = 'st-bad'; log.append({ text: (e && e.text) || 'error', level: 'err' }); },
              active: function (a) { errorReportBtn.disabled = a; lockOtherRunbars(null, a); lockPanel(a); },
              final: function () {
                var n = eGrid.rows().length;
                var done = 'Done - ' + n + ' issue(s) found across ' + hosts.length + ' computer(s).';
                dStatus.textContent = done; dStatus.className = (n ? 'st-warn' : 'st-ok');
                log.append({ text: '[' + ts() + '] ERROR REPORT ' + done, level: (n ? 'warn' : 'ok') });
              }
            });
          }

          versionPanelUnsubs.push(function () { try { if (driveUnsub) driveUnsub(); } catch (e) {} });
        };
      }

      // =================== assemble: TabHost + shared log dock ===================
      var tabHolder = el('div'); tabHolder.style.cssText = 'flex:1;min-height:0;display:flex';
      var tabs = C.TabHost({
        rail: 'top', helpId: 'winupgrade',
        tabs: [
          { id: 'fleet', label: 'Fleet Status', build: buildFleetPanel },
          { id: 'drive24h2', label: 'Drive 24H2', build: buildVersionPanel({ key: '24H2', minBuild: VERSION_MINBUILD['24H2'], label: '24H2' }) },
          { id: 'drive25h2', label: 'Drive 25H2', build: buildVersionPanel({ key: '25H2', minBuild: VERSION_MINBUILD['25H2'], label: '25H2' }) },
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
      log.append({ text: 'Windows Upgrade Tool ready. Fleet Status is a read-only board - Scan Fleet to see where every computer sits on the journey to 24H2/25H2. Drive 24H2 / Drive 25H2 each drive + remediate (Auto-Fix, Repair Health, Error Report) toward their target. Operations tab runs Diagnose / Pin / Unpin / Install CAB / Force Discovery / Auto-Fix / Repair Health / Error Report.', level: 'accent' });
      log.append({ text: 'Pin holds a feature build (optional SCCM refresh / CPU-TPM bypass); Install CAB pushes a feature update via DISM; Force Discovery re-scans (safe) or resets WU (aggressive); Auto-Fix applies only the fixes each device needs; Repair Health runs DISM+SFC; Error Report lists every detected blocker (read-only).', level: 'dim' });

      host.appendChild(root);
      this._root = root;
      this._unsub = function () {
        try { if (unsub) unsub(); } catch (e) {}
        try { if (fleetUnsub) fleetUnsub(); } catch (e) {}
        versionPanelUnsubs.forEach(function (fn) { try { fn(); } catch (e) {} });
      };
    },
    unmount: function () { try { if (this._unsub) this._unsub(); } catch (e) {} if (this._root) this._root.remove(); }
  });
})();
