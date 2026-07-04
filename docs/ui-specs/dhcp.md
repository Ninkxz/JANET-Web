# JANET TWO - UI Rebuild Spec: dhcp

> Engine is re-forked from `fork-source\Tools`; THIS is the faithful FRONTEND to reproduce (screens, run model, live activity view).

## Summary

The J.A.N.E.T. DHCP Scope Option Tool (v1.1.5) is a single-window WinForms admin app for editing IPv4-array DHCP scope options (003 Router, 006 DNS, 042 NTP, 044/045 WINS, or any custom option 1-254) on a remote Microsoft DHCP server over PowerShell remoting (Invoke-Command/WSMan port 5985). Unlike a tabbed tool, it presents one 1400x900 window with a fixed vertical stack of full-width strips (header, credential strip, server-connect strip) above a three-column main work area (left: checkable Scopes ListView; middle: single-scope Option editor with an ordered IP list and reorder/add/remove controls; right: a colour-coded Activity Log RichTextBox), plus a full-width BULK APPLY footer strip and a one-line status bar. Two workflows coexist: single-scope editing (click a scope -> values auto-load -> reorder/add/remove -> APPLY commits the whole list) and bulk apply (check N scopes -> type IPs in the footer -> APPEND/PREPEND/REMOVE across all checked scopes). Every mutating action pops a detailed Yes/No MessageBox confirmation, streams per-scope before/after results into the Activity Log with colour-coded outcomes, updates the status line, and records each per-scope change to the JANET central session log via Write-JanetAction. The theme is JANET house style: gold (#DAB452) + purple (#8C64DC) accents on near-black, Segoe UI for chrome and Cascadia Mono/Consolas for data and the log.

---

# J.A.N.E.T. DHCP Scope Option Tool -- UI/UX Rebuild Spec (tool id: `dhcp`)

Source: `X:\J.A.N.E.T\Tools\DHCPScopeOptionTool_1.1.5.ps1`. This is a faithful front-end rebuild spec. The engine (PowerShell-remoting calls into the `DhcpServer` module) is re-forked separately; this document describes the operator-facing window, controls, workflow, and -- most importantly -- the run/activity experience.

## 1. Window + Navigation Layout

This tool does **NOT** use a TabControl. It is a single resizable window with a fixed vertical stack of full-width strips on top of a three-column work area, a full-width footer, and a status bar. Recreate that exact vertical composition.

- **Window**: title `J.A.N.E.T. DHCP Scope Option Tool v1.1.5`, size 1400x900, min 1280x800, centered, near-black background `(8,8,12)`, primary text `(240,240,245)`, base font Segoe UI 9.5. All full-width strips are built to the form's client width and anchored `Top,Left,Right` (or `Bottom,...`) so they track resizes.

Top-to-bottom regions, **in order**:

1. **Header strip** (height 70, `TopBar` `(6,6,10)`): gold (`#DAB452`) title `J.A.N.E.T. DHCP Scope Option Tool` (Segoe UI 15 Bold), grey italic subtitle `Joint Administration and Network Execution Toolkit`, dim-gold tiny line `v1.1.5  |  IP-Array Scope Option Editor  |  Bulk Apply`. Top-right: red **Close Tool** button (110x28, `Top,Right`). A 2px gold line sits immediately below the header.
2. **ADW Credentials strip** (height 44, `Panel` `(16,16,22)`): tiny dim-gold header `ADW CREDENTIALS`; purple **Set Credentials...** button; cyan checkbox **Use current session (run as logged-in user)**; a bold credential-status label (right side, stretches with width) that is green when creds are active, red when none set, cyan in current-session mode.
3. **DHCP Server strip** (height 56): tiny header `DHCP SERVER`; dim hint `Hostname or FQDN of the authorized DHCP server`; a monospace **hostname textbox** (280 wide); purple **Connect** button; grey **Disconnect** button (disabled until connected); a wide connect-status label (`Not connected` grey -> `Connecting...` amber -> `Connected to HOST (DhcpServer vX)` green -> red on failure).
4. **Main content panel** (anchored all sides) -- three columns (see 2).
5. **Bulk Apply footer strip** (height 160, `Panel`, 2px dim-gold top line, `Bottom,Left,Right`) -- see 3.
6. **Status bar** (height 24, `TopBar`): left status text (`Ready` initial), right gold-dim `User: <name>    Host: <machine>`.

## 2. Per-Column Controls + Workflow

### Left column -- SCOPES (width ~360, panel `(16,16,22)`)
Gold section header `SCOPES`; hint `Click a row to edit one scope. Check the box to include in BULK APPLY.` A **ListView** in Details view, `FullRowSelect`, single-select, **CheckBoxes=true**, monospace font, columns **Scope ID (110) / Name (130) / State (60)**. Inactive (non-`Active`) scopes render in dim grey text. Below: a button row **All / None / Active / Invert** (Active is green-tinted) that bulk-toggle the row checkboxes. A bold count label at the bottom: `N scopes  |  M checked` -- colored gold when any are checked, green when scopes exist, grey otherwise.

Behavior: selecting a row sets `CurrentScopeId`, updates the middle column's scope label, and **auto-loads** that scope's current option values (silent). Important subtlety: clicking a row's **checkbox** must NOT trigger an option auto-load (that would mean one WSMan round-trip per tick) -- the original suppresses this via an `ItemCheck`-sets-a-flag / `SelectedIndexChanged`-honors-it dance. Checking rows only updates the count and the bulk-button enablement.

### Middle column -- SCOPE OPTION editor (width ~540, fixed; does NOT grow with the window)
Gold header `SCOPE OPTION`; a scope label (`No scope selected` -> `Scope: 10.0.5.0 / 255.255.255.0 -- Floor 3 [Active]`). Controls:
- **Option** combo (DropDownList): `003 Router`, `006 DNS Servers` (default), `042 NTP Servers`, `044 WINS / NBNS Servers`, `045 NetBIOS over TCP/IP NBDD`, `Other (specify ID) ...`.
- **ID** NumericUpDown (1-254), enabled only when `Other` is chosen.
- **Load Values** button (cyan) -- fetches current values for the chosen option.
- Gold-tiny header `IP ADDRESS LIST  (order matters)` over a **ListBox** (monospace) whose rows are rendered `' n.  a.b.c.d'` so 1-based position is explicit. Order is meaningful (DHCP hands out option values in list order).
- Right-side reorder button stack: **Move Up / Move Down / Move Top / Move Bottom**, then a red **Remove**.
- `ADD IP ADDRESS` row: a textbox + purple **Add** (inserts after the current selection) + dimmer-purple **Add to Bottom**. Enter in the textbox = Add. Invalid IPv4 -> warning MessageBox; duplicates are skipped with an amber log line.
- Bottom: large gold **APPLY  ->  COMMIT TO SCOPE** (380x38, black text) + grey **Revert**. Both are disabled until the working list differs (order-sensitive) from the loaded values.

Single-scope workflow: connect -> click a scope (values auto-load) -> choose option (re-loads) -> add/remove/reorder IPs -> **APPLY** (confirm) -> list becomes the new baseline.

### Right column -- ACTIVITY LOG (absorbs all extra width)
Gold header `ACTIVITY LOG`; dim label `Log: <path>`; a read-only **RichTextBox** (`BorderStyle None`, near-black `(6,6,10)`, monospace). This is the live run narrative (see 3).

## 3. THE RUN MODEL + ACTIVITY VIEW (most important -- preserve this exactly)

**Single remoting helper.** Every server call goes through `Invoke-OnDhcp($Script,$Arguments)`, which runs `Invoke-Command -ComputerName $DhcpServer -ScriptBlock $Script -ArgumentList $Arguments`. If **Use current session** is ticked it omits `-Credential` (Kerberos/NTLM as logged-in user); otherwise it passes `-Credential $Cred -Authentication Default`. There is **no runspace pool, no BeginInvoke, no background job** -- calls are synchronous on the UI thread, so the window briefly blocks during a round-trip.

**Connect** (the gateway, launched by the Connect button): trim hostname -> guard that creds-or-current-session is set (else warning MessageBox) -> disable button, set status `Connecting to <srv> ...`, `$f.Refresh()` -> **TCP pre-check to port 5985 with a 3s timeout** (so an unreachable host gives a clean "did not respond" error, not a remoting timeout) -> run a probe scriptblock that imports `DhcpServer`, runs `Get-DhcpServerv4Scope`, and projects each scope to a plain object with **ScopeId/SubnetMask flattened to dotted-quad strings** (raw `[ipaddress]` objects corrupt over PSRemoting). Populate the ListView (inactive rows dimmed), set connect-status green `Connected to HOST (DhcpServer vX)`, enable Disconnect + the editor, log `Connected to <srv> -- N scope(s) loaded.` in green.

**Launching an operation.** Mutations are launched by four gold/red buttons: single-scope **APPLY** (middle) and bulk **APPEND (gold) / Prepend (purple) / Remove (red)** (footer). Each is enabled only when preconditions hold (connected + a real diff for APPLY; connected + >=1 checked scope + >=1 valid IP + an option for bulk).

**Confirmations.** Every mutating action shows a **detailed Yes/No MessageBox** before touching the server:
- *Single APPLY* lists Server, Scope, Option, then a diff block (`ADD: + ...`, `REMOVE: - ...`, or `REORDER ONLY (same set, new order)`), then `NEW ORDER (top -> bottom):` numbered, then `Apply this change to the live DHCP scope?`.
- *Bulk* lists Server, Option, the Action label (e.g. "APPEND to bottom of each scope's option 6 list"), the count and list of target scope IDs, the list of IPs, then `Proceed?` (title `Confirm BULK APPEND`). If some tokens were invalid, a prior Yes/No asks whether to continue with the valid ones.
Cancelling logs `... cancelled by user.` in amber and aborts.

**Execution + result streaming.** On Yes: disable the action button(s), set status to `... running on N scope(s) ...`, `$f.Refresh()`, then ONE synchronous `Invoke-OnDhcp`. Bulk runs a **server-side foreach** over checked scope IDs, computing per scope: Append = existing + new(not already present); Prepend = new(not present) + existing; Remove = existing minus IPs; then `Set-DhcpServerv4OptionValue -Force` (or `Remove-...` if the list empties), with same-order equality producing `NoChange`. It returns an array of **per-scope records** `{ScopeId, Status (Changed|Removed|NoChange|Error), Before, After, Error}`.

Back on the client, the tool iterates those records and **replays them line-by-line into the Activity Log**, each indented two spaces and colour-coded:
- `  [10.0.5.0] 2 -> 3 value(s): a, b, c` -> **green** (Changed)
- `  [10.0.5.0] option 6 removed (list now empty).` -> **green** (Removed)
- `  [10.0.5.0] no change (already in desired state).` -> **grey** (NoChange)
- `  [10.0.5.0] ERROR: <msg>` -> **red** (Error)
Then a roll-up: `BULK APPEND complete: X changed, Y unchanged, Z error(s).` (green if no errors, amber otherwise), also pushed to the status bar. Each per-scope record is additionally written to the JANET central log (`Write-JanetAction`: Changed/Removed -> VulnPatched/Success, NoChange -> TouchHost/Skipped, Error -> VulnPatched/Failure).

**The Activity Log mechanics** (`Log-Activity($Message,$Color)`): append a dim `[HH:mm:ss] ` timestamp, then the message in the per-call colour, newline, `ScrollToCaret()`, and mirror to the on-disk log via `Write-JLog`. Colour vocabulary (reuse verbatim across the suite): green=success/connect/load, amber=not-set/empty/cancelled/skipped, red=error/failure, cyan=selection/auth-mode/reorder, purple=add/init, gold=bulk-run start, grey=no-change/tips. On `Add_Shown` the log is seeded with a banner: init line, credential state, an auth tip, and one-line how-tos for single-scope and bulk editing.

**Progress / cancel.** There is intentionally **no progress bar and no cancel/abort**. Progress is conveyed solely by (a) the action button disabling during the call, (b) the `... running ...` status line, and (c) the burst of per-scope log lines + roll-up afterward. A rebuild may add a determinate progress bar over the per-scope loop, but must keep the per-scope log lines and the summary line as the primary feedback.

**Error handling.** Session-level failures are caught, logged red (`APPLY FAILED: ...` / `BULK ... FAILED at the session level: ...`), and if the message matches WSMan auth-rejection patterns, a multi-cause hint is appended (DHCP Users vs DHCP Administrators, stale launcher cred, auth-mode toggled between Connect and Apply, missing domain prefix, account lockout) and shown in an error MessageBox.

## 4. Targets / Host-List / Credentials / Shared State

There is exactly **one target**: a single DHCP server (hostname/FQDN in the server strip). The "host list" within it is the **scope list**; per-scope checkboxes select bulk targets. Shared script-scope state: `DhcpServer`, `Scopes`, `CurrentScopeId`, `CurrentOptionId`, `OriginalValues` (as-loaded), `WorkingValues` (live-edited ArrayList), `UseCurrentSession`. Credentials: `$global:Cred` is inherited from the JANET launcher via `$env:JANET_CRED_FILE` (Import-Clixml) or set via **Set Credentials...** (`Get-Credential`); the **Use current session** checkbox disables the Set button and switches the auth branch. The chosen option ID is genuinely cross-cutting: the middle-column option selector also drives the footer's bulk operations (the bulk strip shows `Option: N` echoed from the same selector).

## 5. Engine Functions / Scriptblocks the UI Calls

- `Invoke-OnDhcp($Script,$Arguments)` -- the only remoting entry point.
- Connect probe scriptblock -- module check + `Get-DhcpServerv4Scope` projected to dotted-quad strings.
- `Load-CurrentOption([-Silent])` -> `Get-DhcpServerv4OptionValue` (treats not-found as empty).
- APPLY scriptblocks -> `Set-DhcpServerv4OptionValue -Force` / `Remove-DhcpServerv4OptionValue`.
- `Invoke-BulkApply -Mode Append|Prepend|Remove` -> server-side foreach returning per-scope records.
- Helpers: `Get-SelectedOptionId`, `Get-BulkIps`, `Test-Ipv4`, `Add-IpToWorking`, `Move-Working`, `Compare-Lists`, `Sync-WorkingToList`, `Update-ScopeCountLabel`, `Update-BulkButtons`.
- JANET plumbing: `Start-JanetSession('DHCP_Scope', version)`, `Write-JanetAction`, `Stop-JanetSession`, `Write-JLog`/`Log-Activity`.

A web rebuild should expose these as endpoints: `connect` (returns scopes), `loadOption(scope,opt)`, `applyScope(scope,opt,orderedValues)`, `bulkApply(mode,scopeIds,opt,ips)` returning the same per-scope records the activity view replays.

## 6. UX Details + Theme to Preserve

- **Order matters** everywhere -- IP rows are numbered and reordering alone is a committable change (order-sensitive dirty check).
- Auto-load on scope/option change so the operator never edits blind; checkbox clicks must not auto-load.
- APPLY/Revert gated on an order-sensitive diff vs the loaded baseline.
- Detailed pre-flight confirmations that spell out the exact diff and final order.
- De-dup on add and on bulk-append; `NoChange` is a first-class outcome, not silence.
- Guarded close: only the red **Close Tool** button exits (sets an allow-flag then closes); X / Alt-F4 / title-bar Close are cancelled by the `FormClosing` guard (Windows shutdown excepted).
- **Theme**: gold `#DAB452` (+ dim `(155,125,52)`) and purple `#8C64DC` (accent) over near-black panels `(16,16,22)` on background `(8,8,12)`; success green `(92,198,120)`, warning amber `(230,180,70)`, danger red `(224,80,90)`, cyan `(88,180,210)`. Fonts: Segoe UI / Segoe UI Semibold for chrome, **Cascadia Mono,Consolas** for the scope list, IP list, hostname box, and activity log. Flat buttons with a hover-lighten (+30 RGB) and luminance-based auto-foreground (dark text on light buttons).