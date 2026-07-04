# SESSION 7 HANDOFF — OG→TWO parity fixes (Reports CSV + tool-by-tool gaps)

**Date:** 2026-06-25
**Branch:** main (working-tree edits, nothing committed this session)
**Related memory:** `og-vs-two-parity-audit.md`, `janet-one-vs-two-parity.md` (STIG stays excluded)

---

## 0. ⚠️ READ FIRST — an external process was reverting my edits

During this session, an external process kept **restoring source files to their pre-edit state** on disk — flip-flopping: whichever file I was *not* actively editing got reverted. Signature of **an editor with these files open auto-saving stale buffers**, a **file-watcher / running dev-server**, or a **sync process** (e.g. the "Take to work" mirror) writing over the working tree.

**Before doing ANY work in the new session:**
1. Close all JANET TWO files in every editor (especially the `.psm1` and `.view.js` below).
2. Stop any file-watcher / running JANET TWO server / auto-sync / format-on-save.
3. Then **re-verify each edit below is present** (greps given in §5) and re-apply any that reverted.

The repo may currently be in a **broken half-applied state** (e.g. `restart.view.js` calls a `verify-boottime` engine action that `restart.psm1` may not contain). **Do not run JANET TWO until §5 verification is green.**

Full detail of this session is in the transcript:
`C:\Users\bth0m\.claude\projects\X--J-A-N-E-T-TWO\e32e8e4c-5fa8-4d30-b8d8-c408faf623c0.jsonl`

---

## 1. What this work is

A tool-by-tool functional-parity audit (OG desktop JANET → JANET TWO web) found **16 confirmed gaps** (see `og-vs-two-parity-audit.md`). The user selected **10** to implement now:

- Quick wins **#2, #3, #4, #5** + #6, #7, #8 (the low-effort ones)
- The one High item **#1** (Restart WinRM boot-time verify)
- The full **Reports cluster #6–#10**

Net selected set: **#1–#10** (deferred: #11 Secure Boot per-host status, #12 UPR finding-scoped scan, #13 WPT Log4j jar override, #14 Pkg persisted root, #15 WPT XLSX import, #16 Restart plan preview).

---

## 2. Status

| # | Tool | Gap | State |
|---|------|-----|-------|
| 1 | Restart | WinRM `LastBootUpTime` verify (+ "Verify (WinRM)" button) | **Implemented** (verify after revert) |
| 2 | ACAS | KB regex: "Security Update N" / "Apply…" + 6–8 digits | **Implemented** (verify after revert) |
| 3 | UPR | Uninstall grid: Type + Publisher columns | **Implemented** (verify after revert) |
| 4 | ACAS | Multi-CSV import (Multiselect) | **Implemented** (verify after revert) |
| 5 | Restart | Dispatch-at column | **Implemented** (verify after revert) |
| 6 | Reports | ACAS findings grid: Status + Solution columns | **NOT started** |
| 7 | Reports | ACAS Import: Status/Category(/Host) filter dropdowns | **NOT started** |
| 8 | Reports | ACAS Import: "Mark All Visible" Patched / NOT OUR PATCH | **NOT started** |
| 9 | Reports | Remediation tab: per-app Copy Hosts / Export CSV | **NOT started** |
| 10 | Reports | ACAS Import: Online/Offline ping toggle + Re-Ping Hosts | **NOT started** |

All implemented edits PASSED `node --check` / PS parser **when present** — the only problem is persistence (§0).

---

## 3. EXACT EDITS for #1–#5 (re-apply any that reverted)

### #2 ACAS KB regex — `modules/JanetTwo.acas.psm1` (action `kb-scan-findings`, ~line 2834)

Replace:
```powershell
            $kbRe = [regex]'(?i)KB\d{6,7}'
```
with:
```powershell
            # KB rollups: "KB[ ]NNNNNN(NN)" or "(Apply )Security Update NNNNNN(NN)" -> normalize to KB<num>
            # (mirrors OG Get-NemKbParsedFindings: both patterns, 6-8 digits, optional space after KB).
            $kbRe = [regex]'(?i)\bKB\s*(\d{6,8})\b|(?:Apply\s+)?Security\s+Update\s+(\d{6,8})\b'
```
Replace:
```powershell
                $kbs = @($kbRe.Matches($text) | ForEach-Object { $_.Value.ToUpperInvariant() } | Select-Object -Unique)
```
with:
```powershell
                $kbs = @($kbRe.Matches($text) | ForEach-Object {
                    $d = if ($_.Groups[1].Success) { $_.Groups[1].Value } else { $_.Groups[2].Value }
                    'KB' + $d
                } | Select-Object -Unique)
```

### #4 ACAS multi-CSV — `web/js/views/acas.view.js`

Replace the fileInput/import-button block:
```js
        var fileInput = el('input'); fileInput.type = 'file'; fileInput.accept = '.csv,.txt,.tsv'; fileInput.style.display = 'none';
        var importBtn = ui.ctaButton('IMPORT ACAS CSV', { title: 'Choose a Tenable/ACAS-Nessus CSV export, upload it to the JANET TWO host, and parse it.' });
        importBtn.style.maxWidth = '260px';
        fileInput.addEventListener('change', function () { if (fileInput.files && fileInput.files[0]) doImport(); });
```
with:
```js
        var fileInput = el('input'); fileInput.type = 'file'; fileInput.accept = '.csv,.txt,.tsv'; fileInput.multiple = true; fileInput.style.display = 'none';
        var importBtn = ui.ctaButton('IMPORT ACAS CSV', { title: 'Choose one or more Tenable/ACAS-Nessus CSV exports, upload them to the JANET TWO host, and parse them together (desktop Multiselect).' });
        importBtn.style.maxWidth = '260px';
        fileInput.addEventListener('change', function () { if (fileInput.files && fileInput.files.length) doImport(); });
```
Replace the head of `doImport` (from `function doImport() {` through `run = ctx.run('import-acas', { csvPaths: csvPath });`) with:
```js
      function doImport() {
        // the file input lives in the import panel; find it within our root
        var fi = root.querySelector('input[type=file]');
        var files = (fi && fi.files) ? Array.prototype.slice.call(fi.files) : [];
        if (!files.length) { ctx.confirm({ title: 'No file', body: 'Choose one or more ACAS / Nessus CSV exports first.', okText: 'OK', cancelText: null }); return; }
        if (runActive()) return;
        var label = files.length > 1 ? (files.length + ' files') : files[0].name;
        importStatus.textContent = 'Uploading ' + label + ' ...'; importStatus.className = 'st-info';
        importGrid.clear(); importProg.reset();
        importedHosts = [];
        log.banner('Import ' + label);
        // upload every selected export, then parse them TOGETHER (engine accumulates
        // newline-joined csvPaths into one finding set) - desktop OpenFileDialog Multiselect loop.
        Promise.all(files.map(function (f) {
          return ctx.uploadFile(f).then(function (p) { log.append({ text: 'Uploaded to host: ' + p, level: 'dim' }); return p; });
        })).then(function (paths) {
          csvPath = paths.join('\n'); csvName = label;
          importStatus.textContent = 'Parsing ' + label + ' ...'; importStatus.className = 'st-info';
          run = ctx.run('import-acas', { csvPaths: csvPath });
```
(The rest of `doImport` — `if (unsub) unsub(); … unsub = run.subscribe({…}); }).catch(…)` — is UNCHANGED and chains off the new `.then`. Engine `import-acas` already splits `csvPaths` on `[\r\n]+` and accumulates.)

### #3 UPR Type/Publisher — `web/js/views/upr.view.js`

Grid columns (Uninstall candidates grid): after the `Product` column, insert:
```js
            { key: 'Publisher', label: 'PUBLISHER', width: 150 },
            { key: 'Type', label: 'TYPE', width: 80 },
```
Export (`exportScanResults`): replace
```js
        var cols = ['Host', 'Plugin', 'Product', 'Version', 'Decision', lastScanWasUninstall ? 'Result' : 'Detail'];
        var labelRow = ['Host', 'Plugin', 'Display Name', 'Version', 'Decision', lastScanWasUninstall ? 'Result' : 'Detail'];
```
with:
```js
        var cols = ['Host', 'Plugin', 'Product', 'Publisher', 'Type', 'Version', 'Decision', lastScanWasUninstall ? 'Result' : 'Detail'];
        var labelRow = ['Host', 'Plugin', 'Display Name', 'Publisher', 'Type', 'Version', 'Decision', lastScanWasUninstall ? 'Result' : 'Detail'];
```
(Engine already emits `Publisher` and `Type` per row — display/export only.)

### #5 Restart Dispatch-at — `modules/JanetTwo.restart.psm1` + `web/js/views/restart.view.js`

**Engine — manifest `dispatch-restart` columns:**
```powershell
                columns      = @('Host','Status','DispatchAt','RestartAt','Result','ConsentState')
```
**Engine — after the `$restartStr = …` line in the `dispatch-restart` action, add:**
```powershell
            # DispatchAt: when each host actually fires shutdown.exe. Burst/rolling never
            # hold (dispatch is immediate) so they show '-'; time-gated holds until
            # RestartAt - lead (- the consent prompt window when consent is on).
            $dispatchStr = if ($rolling -or $burst) { '-' } else {
                $da = $restartTime.AddMinutes(-1 * [int]$leadMinutes)
                if ($consent) { $da = $da.AddSeconds(-1 * [int]$promptSec) }
                $da.ToString('yyyy-MM-dd HH:mm:ss')
            }
```
**Engine — `$rowOf` ordered hash: add `DispatchAt = $dispatchStr` between `Status` and `RestartAt`.**
**Engine — the two gate rows (`Skipped-Server` and `Unreachable`): add `DispatchAt='';` after `Status=…;`.**

**View — dispatch grid: add `{ key: 'DispatchAt', label: 'DISPATCH AT', width: 150 },` before the RestartAt column.**
**View — `exportDispatchCsv`: header array becomes `['Host', 'Status', 'DispatchAt', 'RestartAt', 'ConsentState', 'Result']`.**

### #1 Restart WinRM boot-time verify — `modules/JanetTwo.restart.psm1` + `web/js/views/restart.view.js`

**Engine — add manifest action (after the `verify-reboots` entry, before `cancel-pending`):**
```powershell
            @{
                id          = 'verify-boottime'
                label       = 'Verify (WinRM Boot Time)'
                description  = 'Query Win32_OperatingSystem.LastBootUpTime over WinRM for each target and, against an optional reference (the scheduled restart time), return an AUTHORITATIVE verdict that trumps ping inference: RESTARTED - confirmed by boot time; Did NOT restart - confirmed; Online (no reference to compare); or boot-time check failed.'
                kind         = 'stream-table'
                destructive  = $false
                columns      = @('Host','State','Boot-Time','Result')
                inputs       = @(
                    @{ name='targets';       label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='referenceTime'; label='Restart time to compare (ISO 8601 or HH:mm; blank = report boot time only)'; type='text'; required=$false },
                    @{ name='threads';       label='Parallel hosts'; type='int'; required=$false; default=32 }
                )
            },
```
**Engine — add the worker (right after `$script:PingWorker = { … }`):**
```powershell
# Single WinRM boot-time probe: Win32_OperatingSystem.LastBootUpTime, compared
# against an optional reference (the scheduled restart) to confirm a reboot
# AUTHORITATIVELY - this trumps the ping-only DOWN/UP inference (OG Verify-RrsBootTime).
$script:BootTimeWorker = {
    param($hostname, $refTicks, $cred)
    $o = [ordered]@{ Host = $hostname; Online = $false; BootTicks = [long]0; Verdict = 'failed'; Detail = '' }
    try {
        $wsOpt = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
        $icArgs = @{
            ComputerName   = $hostname
            Authentication = 'Negotiate'
            SessionOption  = $wsOpt
            ErrorAction    = 'Stop'
            ScriptBlock    = { (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime }
        }
        if ($cred) { $icArgs.Credential = $cred }
        $bt = Invoke-Command @icArgs | Select-Object -First 1
        if ($bt) {
            $boot = [datetime]$bt
            $o.Online = $true
            $o.BootTicks = $boot.Ticks
            if ([long]$refTicks -gt 0) {
                if ($boot.Ticks -ge [long]$refTicks) { $o.Verdict = 'restarted' } else { $o.Verdict = 'did-not-restart' }
            } else { $o.Verdict = 'online-no-ref' }
        }
    } catch {
        $o.Online = $false; $o.Verdict = 'failed'; $o.Detail = $_.Exception.Message
    }
    return [pscustomobject]$o
}
```
**Engine — add the action case (right after the `verify-reboots` case's closing `}`):**
```powershell
        # ---------------------------------------------------------------------
        'verify-boottime' {
            $targets = ConvertTo-JanetHostList ([string]$Params['targets'])
            if ($targets.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No valid targets.' }
                return @{ rows=@(); summary=@{ total=0 } }
            }
            $threads = Get-RrsInt $Params['threads'] 32 1 64
            $refTicks = [long]0; $refShown = ''
            $refStr = ([string]$Params['referenceTime']).Trim()
            if (-not [string]::IsNullOrWhiteSpace($refStr)) {
                $refDt = [datetime]::MinValue
                if ([datetime]::TryParse($refStr, [ref]$refDt)) { $refTicks = $refDt.Ticks; $refShown = $refDt.ToString('yyyy-MM-dd HH:mm:ss') }
                else { & $send @{ type='log'; level='warn'; text="Could not parse reference time '$refStr' - reporting boot time only (no restarted/not verdict)." } }
            }
            & $send @{ type='status'; text="WinRM boot-time verify: $($targets.Count) host(s)$(if ($refShown) { " vs restart @ $refShown" }) with $threads thread(s)..." }

            $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            $pmax = [Math]::Min($threads, [Math]::Max(4, $targets.Count))
            $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $pmax, $iss, $Host)
            $rows = New-Object System.Collections.ArrayList
            $confirmed = 0; $notRestarted = 0; $online = 0; $failed = 0; $done = 0; $cancelled = $false
            $jobs = @{}
            try {
                $pool.Open()
                foreach ($h in $targets) {
                    $ps = [powershell]::Create(); $ps.RunspacePool = $pool
                    [void]$ps.AddScript($script:BootTimeWorker); [void]$ps.AddArgument($h); [void]$ps.AddArgument($refTicks); [void]$ps.AddArgument($Credential)
                    $jobs[$h] = @{ PS = $ps; Async = $ps.BeginInvoke() }
                }
                while ($jobs.Count -gt 0) {
                    $finished = @()
                    foreach ($k in @($jobs.Keys)) { if ($jobs[$k].Async.IsCompleted) { $finished += $k } }
                    foreach ($k in $finished) {
                        $jp = $jobs[$k]; $res = $null
                        try { $res = $jp.PS.EndInvoke($jp.Async) | Select-Object -First 1 } catch { $res = $null }
                        try { $jp.PS.Dispose() } catch {}
                        $jobs.Remove($k)
                        $vk = if ($res) { [string]$res.Verdict } else { 'failed' }
                        $bootStr = ''
                        if ($res -and [long]$res.BootTicks -gt 0) { $bootStr = ([datetime]::new([long]$res.BootTicks)).ToString('yyyy-MM-dd HH:mm:ss') }
                        switch ($vk) {
                            'restarted'       { $verdict = "RESTARTED - confirmed by boot time ($bootStr)"; $confirmed++;   $auditRes='Success' }
                            'did-not-restart' { $verdict = "Did NOT restart - confirmed (last boot $bootStr)"; $notRestarted++; $auditRes='Failure' }
                            'online-no-ref'   { $verdict = "Online (last boot $bootStr - no restart time to compare)"; $online++; $auditRes='Info' }
                            default           { $verdict = "Boot-time check failed$(if ($res -and $res.Detail) { ' - ' + $res.Detail })"; $failed++; $auditRes='Info' }
                        }
                        $row = [ordered]@{ Host = $k; State = $verdict; 'Boot-Time' = $bootStr; Result = $verdict }
                        [void]$rows.Add($row)
                        & $send (@{ type='row' } + $row)
                        & $send @{ type='audit'; action='TouchHost'; target=$k; result=$auditRes; itemCount=0; detail=$verdict }
                        $done++
                        & $send @{ type='progress'; done=$done; total=$targets.Count }
                    }
                    if ($jobs.Count -gt 0) {
                        if ($script:RrsCancelCheck -and (& $script:RrsCancelCheck)) {
                            $cancelled = $true
                            foreach ($k in @($jobs.Keys)) { try { [void]$jobs[$k].PS.BeginStop($null, $null) } catch {}; $jobs[$k].PS = $null }
                            $jobs.Clear()
                            & $send @{ type='log'; level='warn'; text='Cancelled by operator; remaining boot-time checks abandoned.' }
                            break
                        }
                        Start-Sleep -Milliseconds 80
                    }
                }
            } finally {
                try { $pool.Close(); $pool.Dispose() } catch {}
            }
            & $send @{ type='status'; text="Boot-time verify done: $confirmed restarted, $notRestarted did-not-restart, $online online-no-ref, $failed failed of $($targets.Count)$(if ($cancelled) { ' (cancelled)' })." }
            return @{ rows=@($rows); summary=@{ total=$targets.Count; restarted=$confirmed; notRestarted=$notRestarted; online=$online; failed=$failed; cancelled=$cancelled } }
        }
```

**View `restart.view.js`:**
- `rebootStateCls`: add `if (/^Rebooted/i.test(s) || /^RESTARTED/i.test(s)) return 'st-ok';`, `if (/^Did NOT/i.test(s)) return 'st-bad';`, `if (/Boot-time check failed/i.test(s)) return 'st-warn';` (keep existing Online/Offline/No-contact/Cancelled lines).
- `rebootRowCls`: `RESTARTED`→row-ok with Rebooted; `Did NOT`→row-bad with No-contact.
- Add `var bootRun = null, bootUnsub = null;` next to `verifyRun`.
- In the Verify tab bar, create the button and append it before `exportBtn`:
  ```js
  var bootBtn = ui.button('Verify (WinRM)', { variant: 'gold', size: 'sm', title: 'Query LastBootUpTime over WinRM and confirm reboots AUTHORITATIVELY (trumps ping). Compares boot time to the Restart time on the Config tab; blank = report boot time only.' });
  bootBtn.onclick = doVerifyBootTime; refs.bootBtn = bootBtn;
  ```
- Reboot-verification grid: add `{ key: 'Boot-Time', label: 'BOOT TIME', width: 150 },` before the Result column.
- `exportVerifyCsv` header: add `'Boot-Time'` before `'Result'`.
- Add the handler (next to `doVerify`):
  ```js
  function doVerifyBootTime() {
    var hosts = targetsModel.hosts();
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
        refs.verifyGrid.upsert(r);   // merges Boot-Time + authoritative State/Result onto any ping row (grid keys by Host)
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
  ```
- unmount `_unsub`: add `try { if (bootUnsub) bootUnsub(); } catch (e) {}`.

---

## 4. PLAN for #6–#10 (Reports — NOT started)

All in `web/js/views/reports.view.js` + `modules/JanetTwo.reports.psm1`. Engine facts already gathered:
- Finding objects carry `.Status` and `.Solution` (psm1 ~385–392).
- `acas-parse-file` row emit: psm1 ~2801 (`$row = @{ Host=…; Hostname=…; PluginID=…; VulnName=…; Severity=…; CVE=…; Category=… }`).
- `Build-RemediationPlan` (psm1 677–787): bucket is keyed **per (host,app)**; OtherGroups carry a `Hosts` set. **Must read the `remediation-refresh` action handler** (grep `'remediation-refresh'`) to see how it aggregates to the per-App grid rows the view shows (App/TargetCount/TargetVersion/Critical/High) before adding host lists.
- Ping worker to reuse for #10: `$script:TargetIpResolveWorker` (psm1 ~1818) used by the `resolve-target-ips` action (~3595).
- **Still must read:** the `acas-load-report` row emit (~3580) and the `acas-mark-status` action handler (manifest ~216; find the case) for #6.

### #6 Status + Solution columns
- Engine: add `Status=$f.Status; Solution=$f.Solution` to the emitted `$row` in **acas-parse-file** AND **acas-load-report**. In **acas-mark-status**, include the new `Status` on the emitted row so the grid repaints.
- View (`buildAcasImport`, grid ~346–353): add columns
  `{ key:'Status', label:'STATUS', width:110, colorRule: statusCls }` and `{ key:'Solution', label:'SOLUTION', width:280 }`.
  Add helper: `function statusCls(v){ v=String(v); if(/Patched/i.test(v))return 'st-ok'; if(/NOT OUR PATCH/i.test(v))return 'st-info'; if(/Open/i.test(v))return 'st-bad'; return ''; }` (OG: Patched=green, Open=red, NOT OUR PATCH=purple→st-info is nearest).
  In `markStatus` row handler (~454), also `grid.upsert({ _rk:k, …, Status: r.NewStatus })`.

### #7 Filter dropdowns
- View filter row (~357–381): add `ui.select` for **Status** (`All / Open / Patched / NOT OUR PATCH`) and **Category** (`All` + distinct categories seen). Include both in `applyFindingFilter` alongside the existing severity + free-text. (Optional Host dropdown populated from loaded findings.)

### #8 "Mark All Visible" buttons
- View: two buttons "Mark All Visible: Patched" / "Mark All Visible: NOT OUR PATCH". Gather the rows that pass the **current** filter predicate (reuse the predicate from `applyFindingFilter`; `grid.rows()` returns all, so filter client-side), confirm the count, build the `keys` (`Hostname|PluginID` joined by `\n`), and submit via the existing `acas-mark-status` path (same as `markStatus` but with an explicit key list; Patched reuses the Patched-By/Date inputs).

### #9 Remediation Copy Hosts / Export CSV
- Engine: include the per-bucket **Hostname list** in `remediation-refresh` emitted rows (and per-Other-group). Read the handler first to match its row shape.
- View (`buildRemediation`): add **Copy Hosts** and **Export CSV** buttons that act on the selected/!current bucket using the host list now present on the row (or add a per-row action). Minimal: a global Copy/Export for the highlighted App row.

### #10 Online/Offline ping toggle + Re-Ping
- Engine: new action **`acas-ping-hosts`** — distinct hosts from `$script:AcasFindings`, ping in parallel via `$script:TargetIpResolveWorker`, store an online map in a new `$script:AcasHostOnline` script var, emit per-host `{ Host, Online }` + summary `{ online, offline, total }`. Add a manifest entry.
- View (`buildAcasImport`): a ping bar showing **Online / Offline / All** counts + a toggle that filters the findings grid by host online-state (build a `host→online` map from the action rows; fold into `applyFindingFilter`), plus a **Re-Ping Hosts** button. Add an **Offline** subset to the findings export.

---

## 5. VERIFY before/after (run after the reverter is stopped)

```powershell
# presence check (ripgrep via the Grep tool, or:)
Select-String -LiteralPath "X:\J.A.N.E.T TWO\modules\JanetTwo.acas.psm1"     -Pattern 'KB rollups' -SimpleMatch
Select-String -LiteralPath "X:\J.A.N.E.T TWO\web\js\views\acas.view.js"       -Pattern 'upload every selected' -SimpleMatch
Select-String -LiteralPath "X:\J.A.N.E.T TWO\web\js\views\upr.view.js"        -Pattern "label: 'PUBLISHER'" -SimpleMatch
Select-String -LiteralPath "X:\J.A.N.E.T TWO\modules\JanetTwo.restart.psm1"   -Pattern 'BootTimeWorker' -SimpleMatch
Select-String -LiteralPath "X:\J.A.N.E.T TWO\web\js\views\restart.view.js"    -Pattern 'doVerifyBootTime' -SimpleMatch

# syntax
node --check "X:\J.A.N.E.T TWO\web\js\views\acas.view.js"
node --check "X:\J.A.N.E.T TWO\web\js\views\upr.view.js"
node --check "X:\J.A.N.E.T TWO\web\js\views\restart.view.js"
node --check "X:\J.A.N.E.T TWO\web\js\views\reports.view.js"
$e=$null; [System.Management.Automation.Language.Parser]::ParseFile("X:\J.A.N.E.T TWO\modules\JanetTwo.restart.psm1",[ref]$null,[ref]$e); $e.Count   # expect 0
$e=$null; [System.Management.Automation.Language.Parser]::ParseFile("X:\J.A.N.E.T TWO\modules\JanetTwo.acas.psm1",   [ref]$null,[ref]$e); $e.Count   # expect 0
$e=$null; [System.Management.Automation.Language.Parser]::ParseFile("X:\J.A.N.E.T TWO\modules\JanetTwo.reports.psm1",[ref]$null,[ref]$e); $e.Count   # expect 0
```
KB-regex sanity (all should map to `KB…`, 5-digit should be blank):
`KB5034441`, `KB 5034441`, `Security Update 5034441`, `Apply Security Update 5034441`, `KB12345678` → KB…; `KB12345` → (none).

**All server-side changes (`.psm1`) require a SERVER RESTART; view changes need only a browser refresh.**

---

## 6. Earlier this session (already landed, not part of #1–#10)
- **Reports "Future Target IPs"** CSV import was rebuilt to detect the hostname column (Computer Name / Hostname / Host / FQDN / Name) + ASID, mirroring OG (was dumping raw CSV rows as hostnames). Client-only; `reports.view.js` `buildFuture`. This survived the session (not reverted) — keep it.

## 7. Do NOT
- Port the STIG tool into TWO (deliberately excluded — `janet-one-vs-two-parity.md`).
- Treat web-port adaptations as gaps: ACAS per-host exclusion, DHCP empty-list delete requiring a Remove-option checkbox, Remote Message advisory-ping-by-default. (See audit memory.)
