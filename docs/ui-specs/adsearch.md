# JANET Web - UI Rebuild Spec: adsearch

> Engine is re-forked from `fork-source\Tools`; THIS is the faithful FRONTEND to reproduce (screens, run model, live activity view).

## Summary

The J.A.N.E.T. AD Search Tool is a single-window WinForms admin app (1300x800, fixed, dark purple-on-black "tactical" theme) for read-only Active Directory lookups against the live domain via ADSI/ADSISearcher -- no RSAT required. Its layout is NOT a TabControl: a horizontal MODE radio-button bar (USERS, COMPUTERS, GROUPS, ORG BOXES, BY EMAIL, BY MANAGER, BULK COMPUTERS, BASE USERS EXPORT, BY LAST PC) acts as the navigation, swapping the visible input fields below it for the selected mode. The screen is split into a left RESULTS card (a ListView whose columns and per-row colour-coding change per mode) and a right EXTENDED INFO card (a read-only RichTextBox console showing summaries and the detail of a double-clicked row). Every search runs asynchronously on a dedicated STA runspace; a 200ms WinForms timer polls completion, and a custom status strip with blinking pulse-dots, a live clock, and a "LIVE" heartbeat conveys run state. Double-clicking a result row opens an "OBJECT DETAIL" popup window and mirrors the same detail into the EXTENDED INFO console. Reproducing this live single-shot async "search wave" experience -- status flips to SEARCHING, dot pulses olive, results stream into the grid colour-coded by status, summary fills the console, status flips to OK :: NNN RESULTS or SEARCH ERROR -- is the core thing JANET Web must preserve.

---

# J.A.N.E.T. AD Search Tool -- UI/UX Rebuild Spec (tool id: `adsearch`)

Source: `X:\J.A.N.E.T\Tools\ADSearchTool.ps1` (~187 KB, WinForms, PowerShell 5.1). This spec describes the **operator-facing frontend and run experience** to recreate as a pure-PowerShell web-local app. The AD query engine is re-forked separately; the entry points it must expose are listed in Section 6.

## 1. Window + Navigation Layout

Single fixed window, **1300 x 800**, `FixedSingle`, no maximize, centered, dark theme. There is **no TabControl** -- navigation is a **MODE radio bar** that swaps the input fields below it. Vertical bands top-to-bottom:

1. **Header strip** (y=0, h=55, `#06060A`, scanline overlay): eyebrow `/ JOINT ADMINISTRATION AND NETWORK EXECUTION TOOLKIT` (amber mono), wordmark `J.A.N.E.T.` (Cascadia Mono 14 bold, purple), subtitle `AD SEARCH TOOL // DIRECTORY LOOKUP`, version tag `v<n>`. Right side: a **CRED cluster** (`/ CRED` eyebrow + pulse-dot + mono state line) showing `INHERITED :: <user>` in green when a launcher cred was inherited via `$env:JANET_CRED_FILE`, else `STANDALONE :: current user token` in gray. Far top-right: **CLOSE TOOL** ghost button (red) -- the only sanctioned form-close.
2. **Options/action bar** (y=55, h=55, corner-bracket card): `/ MODE` eyebrow + **9 mode radio buttons** in two rows, plus the action buttons **SEARCH** (striped amber CTA), **SAVE**, **CLEAR** (red), **ABOUT** (ghost).
3. **Input band** (y=110): either `pnlSearchInputs` (600x55 corner-bracket card holding the per-mode fields) **or** `pnlBulk` (240x620 `MACHINE LIST` card) when Bulk mode is active.
4. **Results area** (y=165, h=602): two side-by-side corner-bracket cards -- **`/ RESULTS`** (left, ListView) and **`/ EXTENDED INFO`** (right, RichTextBox console). In Bulk mode both cards shift right to make room for the machine-list panel.
5. **Status strip** (y=770, h=30, `#06060A`, scanline + 1px amber top hairline): pulse-dot, status label, live clock, `LIVE` heartbeat.

The 9 MODES (in order, radio-selected; amber-coloured radios denote the heavier/export modes):
**USERS * COMPUTERS * GROUPS * ORG BOXES * BY EMAIL * BY MANAGER * BULK COMPUTERS * BASE USERS EXPORT * BY LAST PC.**

## 2. Per-Mode Controls + Workflow

`Update-SearchFieldVisibility -ActiveSearch X` runs on every radio click: it hides all field controls, shows only the ones for the chosen mode, swaps in `pnlBulk` for Bulk, repositions/resizes the result cards, clears the grid, and updates a one-line mode description. Per mode:

- **USERS / BY LAST PC**: First Name, Last Name, EDIPI/DOD # (three side-by-side textboxes, auto-UPPERCASE). LastPC adds a small **Days Back** box (default `14`, range 1-90).
- **COMPUTERS**: Computer Name (350px, upper).
- **GROUPS**: Security Group / Distribution List (450px, upper).
- **ORG BOXES**: Org Box Name (450px, upper).
- **BY EMAIL**: Email Address (450px, not uppercased).
- **BY MANAGER**: Manager's Display Name (450px).
- **BASE USERS EXPORT**: Base/Location Name (e.g. LAKENHEATH, RAMSTEIN), upper.
- **BULK COMPUTERS**: replaces the input card with the `MACHINE LIST` panel -- multiline upper-case textbox (one host per line), **IMPORT TXT** button (OpenFileDialog, accepts .txt/.csv, strips comments/headers), a live `NN TARGETS` counter that updates on text change, **EXPORT CSV** and **CLEAR** buttons.

**Operator flow** (also printed in the EXTENDED INFO brief on launch): pick MODE -> enter criteria (partial allowed) -> **SEARCH** (or Enter) -> rows stream into RESULTS, summary into EXTENDED INFO -> **double-click a row** for full detail (popup + console) -> **SAVE** (RTF of detail, or CSV for bulk/base) -> **CLEAR** to reset.

## 3. THE RUN MODEL + ACTIVITY VIEW (preserve exactly)

### Launch & validation
Launch via the **SEARCH** CTA, **Enter** in any field, or Bulk after paste/import. `ChooseSearchOptions` reads the checked radio and enforces per-mode minimum input (last name >=2, computer/group/orgbox >=4, email >=3, EDIPI >=10, base >=3; Bulk needs >=1 line; LastPC needs a name or EDIPI). On failure it writes a guidance string into the **EXTENDED INFO** console and returns -- no dialog. On success it calls `Start-AsyncSearch -SearchType X -SearchParams @{...}`.

### Async single-shot (no streaming, no progress bar, no cancel button)
`Start-AsyncSearch` cancels any in-flight search, **disables SEARCH**, sets status `SEARCHING :: <MODE> :: please wait`, flips the status pulse-dot to **Active (olive blink)**, creates a fresh **STA runspace** + `[PowerShell]` instance loaded with one scriptblock (a `switch` over `SearchType`; each branch sets an `[ADSISearcher]` LDAP filter with `PageSize=15000` and returns property hashtables), and fires **`BeginInvoke()`**. The UI thread stays free. There is **no per-host progress and no abort button** -- it is fire-and-poll; the only "cancel" is implicit (a new search disposes the prior one).

### Completion polling
A **200 ms `System.Windows.Forms.Timer`** ticks; when `currentAsyncResult.IsCompleted` it stops, calls `EndInvoke`, then:
- **Error** (`Streams.Error` non-empty or exception): writes the error to EXTENDED INFO, status `STATUS :: SEARCH ERROR`, pulse-dot -> **Error (red blink)**.
- **Success**: `Process-SearchResults` populates the grid + console; status `STATUS :: OK :: NNN RESULTS` (zero-padded), pulse-dot -> **Idle**.
A `finally` disposes the runspace, **re-enables SEARCH**.

### Activity view = RESULTS grid + EXTENDED INFO console + status strip
**RESULTS ListView** (Details view, gridlines, full-row-select, single-select, console-black bg, mono 9). Columns rebuilt **per mode**; rows **colour-coded by semantic status**:
- USERS/COMPUTERS/GROUPS/ORG BOXES -> one name column, dim-gray rows.
- EMAIL -> Display Name + Email Address.
- MANAGER -> Name + Role; the **manager row is gold text on an alt-panel background**, reports dim-gray.
- BULK -> Computer Name, Organization, Location Info, Squadron/OU, Last Logon, **Status**; rows **green=Active, amber=Stale (90+ d), red=Not Found/Error**.
- BASE USERS -> Display Name, Account, Privilege, Organization, Title, Email; **amber=Privileged, gray=Standard**.
- LAST PC -> User, Computer, IP Address, Last Seen, Event, DC (sorted most-recent-first).
After load: `AutoResizeColumns("HeaderSize")`.

**EXTENDED INFO RichTextBox** (read-only console, amber-ish text): on completion shows count + echoed criteria + "Double click a name to view extended information"; for Bulk/Base/LastPC it renders a full **ASCII summary report** -- totals, found/not-found, per-organization breakdown (`NN  ORGNAME`), privileged-account list with reasons, DCs scanned `X of Y`, event counts, DC errors skipped, and a legend (`Amber = Privileged | Gray = Standard`).

**Double-click (ItemActivate)**: indexes `cachedResults` by row, builds a long labelled attribute block (user: name/EDIPI/title/manager/phones/email/base/building/created/last-logon/locked-out/OU/groups; computer: OS/version/last-logon/DNS/location/OU/groups), writes it to EXTENDED INFO, **and opens a centered `OBJECT DETAIL` popup window** (520x690, corner-bracket card, mono console, dark title bar) showing the same text.

**Confirmations**: Bulk and Base completion each pop a **YesNo MessageBox** ("Scan complete... Export results to CSV now?") that runs the CSV exporter on Yes. SAVE/CLEAR/import errors use informational MessageBoxes.

**Status strip** (the run telemetry): left -> right: state-driven **pulse-dot** (Idle gray / Active olive-blink / Error red-blink), **status label** in `KEY :: VALUE` uppercase mono (`STATUS :: READY`, `SEARCHING :: USER :: please wait`, `STATUS :: OK :: 042 RESULTS`, `IMPORTED :: 200 HOSTNAMES`), a **live HH:mm:ss clock** (1s timer), and a right-anchored green **`LIVE`** label + always-blinking olive **heartbeat dot** proving the UI/timer pipeline is alive.

> For JANET Web: model each search as a single async job whose POST returns immediately; the browser polls (or SSE) until done, then renders the per-mode column set + row colour classes and the summary console in one shot. The pulse-dot/status/clock/LIVE telemetry and the `KEY :: VALUE` status phrasing must be reproduced.

## 4. Targets / Host-List / Credential / Shared State

- **Host list (Bulk)**: free-text multiline (one host/line) or **IMPORT TXT** (cleans blanks, `#` comments, quoted CSV first-column, header rows; uppercases). Live `NN TARGETS` counter. Cleaned again in-engine (trim/upper/dedupe).
- **Credentials**: no in-tool credential UI. The tool **inherits** a launcher credential via `$env:JANET_CRED_FILE`; presence is surfaced read-only in the header CRED cluster (green INHERITED vs gray STANDALONE). Searches otherwise run under the current user token via ADSI.
- **Shared state**: `$script:cachedResults` holds the last result set (full objects) -- the grid shows a subset; double-click/SAVE index back into it. `$script:currentSearchType`, `currentRunspace`, `currentPowerShell`, `currentAsyncResult` track the live run. Mode radios drive field visibility and which detail/SAVE branch executes. CLEAR resets all inputs, grid, console, cache, and status.

## 5. Save / Export
**SAVE** button: if no cache -> "No data" MessageBox. Bulk -> `Export-BulkCSV`; Base -> `Export-BaseUsersCSV`; otherwise saves the EXTENDED INFO **RTF** of the selected row (`<name>.rtf` in the script dir) -- requires a row selected first. CSV exporters write to disk and confirm via MessageBox.

## 6. Engine Functions / Scriptblocks (re-fork entry points)
- `Start-AsyncSearch -SearchType -SearchParams` -> the per-mode `switch` scriptblock is the **engine boundary**; branches: User, Computer, Group, OrgBox, Email, Manager (manager + direct reports via `manager=<DN>`), BulkComputer (DN->squadron via `Parse-OUFromDN`, location-field org parse, Active/Stale/Not-Found status), BaseUsers (Users + AFB/Administrative OUs, privilege split by suffix), LastPC (DC Security-log scan for events 4624/4768/4769/4776, IP->host reverse resolve).
- `Process-SearchResults -SearchType -Results` (grid + console renderer), `Update-SearchFieldVisibility`, `ChooseSearchOptions`, `popUpChildWindow`, `Export-BulkCSV` / `Export-BaseUsersCSV` / `Build-UserCSVLines`, `Escape-LdapFilterValue` (LDAP-injection guard, host + in-runspace copies).
- JANET shared audit/session helpers wrap the tool: `Initialize-JanetSession`, `Start-JanetSession`, `Write-JanetAction`, `Stop-JanetSession`.

## 7. UX Details + Theme to Preserve
- **Palette**: bg `#08080C`, header/console `#06060A`, panel `#101016`, accent purple `#8C64DC`, success green `#5CC678`, danger red `#E0505A`, warning orange `#E6B446`, lavender-white text `#F0F0F5` with dim/muted tiers.
- **Type**: Cascadia Mono (display/mono/buttons), Segoe UI Variable Display (body). Status/labels mono, uppercase, `KEY :: VALUE`.
- **Chrome**: corner-bracket "brief box" cards with eyebrow headers; scanline overlay on header + status; one striped caution CTA; ghost outline secondary buttons; dark DWM title bar + rounded Win11 corners on every form.
- **Behaviours**: auto-UPPERCASE inputs; Enter = search; hover help on buttons/fields; double-click = detail+popup; hardened FormClosing (only CLOSE TOOL closes); blinking pulse-dots as the universal run-state language; ADSI/ADSISearcher means **no RSAT dependency** -- keep that in the ABOUT text.