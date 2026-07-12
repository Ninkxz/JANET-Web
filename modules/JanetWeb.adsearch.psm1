# =============================================================================
#  JanetWeb.adsearch.psm1  -  Active Directory Search engine for JANET Web
#  (Re-forked for JANET Web from the proven JANET ONE engine; cross-checked vs the desktop tool + ui-spec.)
#
#  Ported from Tools\ADSearchTool.ps1 (v3.3.3) - the multithreaded ADSI search
#  engine is reused verbatim; the WinForms layer (theme, ListView, detail popup,
#  CSV export prompts) is dropped. Read-only tool: directory queries run under
#  the current Kerberos identity; no remote ops, no destructive actions.
#
#  Every search runs the original $scriptBlock inside an isolated child runspace
#  ([RunspaceFactory]::CreateRunspace) exactly as the original did, so the inline
#  Escape-LdapFilterValue helper resolves in-runspace and AD state does not bleed
#  between invocations. The harvest loop turns each result hashtable into a
#  streamed grid row, an audit entry, and a returned row.
#
#  Contract:
#    Get-JanetToolManifest                          -> tool + action descriptors
#    Invoke-JanetToolAction -ActionId -Params -Credential -Emit  -> { rows; summary }
#  -Emit event shapes consumed by the UI: status / progress / row / log / audit.
# =============================================================================

function Get-JanetToolManifest {
    @{
        id       = 'adsearch'
        name     = 'AD Search'
        version  = '3.3.5'
        category = 'Reporting'
        summary  = 'Search Active Directory for users, computers, groups, org boxes, email, managers, bulk computers, base users, and last-PC logon (DC Security-log scan). RSAT-free ADSI; read-only.'
        actions  = @(
            @{
                id          = 'search-user'
                label       = 'Search Users'
                description  = 'Find user accounts by first name, last name, and/or EDIPI (sAMAccountName). LDAP filters are RFC 4515 escaped.'
                kind         = 'table'
                destructive  = $false
                columns      = @('DisplayName','SamAccountName','Email','Title','Department','Company','LockedOut','LastLogon','Manager','DistinguishedName')
                inputs       = @(
                    @{ name='FirstName'; label='First Name'; type='text'; required=$false },
                    @{ name='LastName';  label='Last Name';  type='text'; required=$false },
                    @{ name='EDIPI';     label='EDIPI (sAMAccountName)'; type='text'; required=$false },
                    @{ name='SearchBase'; label='Limit to OU / base-DN (optional)'; type='text'; required=$false }
                )
            },
            @{
                id          = 'search-computer'
                label       = 'Search Computers'
                description  = 'Find computer objects by name wildcard. Returns OS, last logon, DNS name, location, OU.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Name','OperatingSystem','OSVersion','LastLogon','DnsHostName','Location','DistinguishedName')
                inputs       = @(
                    @{ name='ComputerName'; label='Computer Name'; type='text'; required=$true },
                    @{ name='SearchBase'; label='Limit to OU / base-DN (optional)'; type='text'; required=$false }
                )
            },
            @{
                id          = 'search-group'
                label       = 'Search Groups'
                description  = 'Find security groups or distribution lists by name wildcard. Returns members, managed-by, OU.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Name','MemberCount','ManagedBy','WhenCreated','WhenChanged','DistinguishedName')
                inputs       = @(
                    @{ name='GroupName'; label='Group Name'; type='text'; required=$true },
                    @{ name='SearchBase'; label='Limit to OU / base-DN (optional)'; type='text'; required=$false }
                )
            },
            @{
                id          = 'search-orgbox'
                label       = 'Search Org Box'
                description  = 'Find organization / functional mailbox objects (user class) by name wildcard.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Name','DisplayName','Email','DistinguishedName')
                inputs       = @(
                    @{ name='OrgBoxName'; label='Org Box Name'; type='text'; required=$true },
                    @{ name='SearchBase'; label='Limit to OU / base-DN (optional)'; type='text'; required=$false }
                )
            },
            @{
                id          = 'search-email'
                label       = 'Search Email'
                description  = 'Find user accounts by email (mail attribute) wildcard.'
                kind         = 'table'
                destructive  = $false
                columns      = @('DisplayName','SamAccountName','Email','Title','Department','Company','DistinguishedName')
                inputs       = @(
                    @{ name='EmailAddress'; label='Email Address'; type='text'; required=$true },
                    @{ name='SearchBase'; label='Limit to OU / base-DN (optional)'; type='text'; required=$false }
                )
            },
            @{
                id          = 'search-manager'
                label       = 'Search Manager & Reports'
                description  = 'Find a manager by display name, then list all direct reports. First (highlighted) row is the manager.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Role','DisplayName','SamAccountName','Title','Department','Email','DirectReportCount')
                inputs       = @(
                    @{ name='ManagerName'; label='Manager Display Name'; type='text'; required=$true },
                    @{ name='SearchBase'; label='Limit to OU / base-DN (optional)'; type='text'; required=$false }
                )
            },
            @{
                id          = 'search-bulk-computer'
                label       = 'Bulk Computer Lookup'
                description  = 'Batch-resolve many machine names at once. Classifies each as Active / Stale (90+d) / Not Found and parses the OU chain for squadron/base.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Name','Organization','Squadron','OUChain','OperatingSystem','LastLogon','Status')
                inputs       = @(
                    @{ name='MachineList'; label='Machine Names (one per line)'; type='hostlist'; required=$true }
                )
            },
            @{
                id          = 'search-base-users'
                label       = 'Base Users Export'
                description  = 'Enumerate all users under a base (Users + AFB/Administrative OUs), classifying each account as Privileged or Standard.'
                kind         = 'table'
                destructive  = $false
                columns      = @('DisplayName','SamAccountName','Privilege','Organization','ParentOU','Title','Email','PrivReason')
                inputs       = @(
                    @{ name='BaseName'; label='Base / Location Name'; type='text'; required=$true }
                )
            },
            @{
                id          = 'search-last-pc'
                label       = 'Search Last PC'
                description  = 'Discover which workstation a person was last logged into by scanning every DC Security log for logon events (4624/4768/4769/4776). Requires DC Security-log read access. Optional OU / base-DN narrows which account the name/EDIPI resolves to (DCs are still scanned domain-wide).'
                kind         = 'table'
                destructive  = $false
                columns      = @('User','SamAccountName','Computer','IPAddress','LastSeen','EventId','LogonType','DC')
                inputs       = @(
                    @{ name='FirstName'; label='First Name'; type='text'; required=$false },
                    @{ name='LastName';  label='Last Name';  type='text'; required=$false },
                    @{ name='EDIPI';     label='EDIPI';      type='text'; required=$false },
                    @{ name='SearchBase'; label='Limit to OU / base-DN (optional)'; type='text'; required=$false },
                    @{ name='DaysBack';  label='Days Back (1-90)'; type='int'; required=$false; default=14 },
                    @{ name='MaxScanSeconds'; label='Max scan seconds (10-600)'; type='int'; required=$false; default=120 }
                )
            }
        )
    }
}

function ConvertTo-JanetMachineList {
    # Split a pasted blob into clean, unique, upper-cased machine names. Mirrors
    # the original BulkComputer cleanList step (trim, upper, dedupe).
    param([object]$Raw)
    $out  = New-Object System.Collections.ArrayList
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $tokens = @()
    if ($Raw -is [array]) {
        foreach ($item in $Raw) { $tokens += ([string]$item -split '[\r\n,;\t ]+') }
    } else {
        $tokens = ([string]$Raw -split '[\r\n,;\t ]+')
    }
    foreach ($tok in $tokens) {
        $m = $tok.Trim()
        if ($m -and $seen.Add($m)) { [void]$out.Add($m.ToUpperInvariant()) }
    }
    return $out.ToArray()
}

# -----------------------------------------------------------------------------
#  The search engine, lifted verbatim from Start-AsyncSearch's $scriptBlock
#  (Tools\ADSearchTool.ps1 lines 1298-1957). Returns an array of result
#  hashtables. Escape-LdapFilterValue and Parse-OUFromDN are defined inline so
#  they resolve inside the bare child runspace.
# -----------------------------------------------------------------------------
$script:AdSearchEngine = {
    param($SearchType, $SearchParams, $Cred)

    function Escape-LdapFilterValue {
        param([string]$Value)
        if ($null -eq $Value) { return '' }
        $r = $Value -replace '\\', '\5c'
        $r = $r     -replace '\*', '\2a'
        $r = $r     -replace '\(', '\28'
        $r = $r     -replace '\)', '\29'
        $r = $r     -replace "`0", '\00'
        return $r
    }

    # Build an AD bind that honors the operator-supplied credential when present.
    # Without a credential this is identical to the original [ADSI] binds (current
    # Kerberos identity). With one, it returns a DirectoryEntry constructed with the
    # operator user/password so EVERY search (and the SearchBase reassignment, the
    # RootDSE lookup, and the per-OU sub-searchers) binds under that credential.
    # An empty Path means the serverless domain root: resolve defaultNamingContext
    # via a credentialed RootDSE bind, then bind that DN with the same credential.
    function New-AdEntry {
        param([string]$Path)
        $hasCred = ($null -ne $Cred -and $Cred -is [System.Management.Automation.PSCredential])
        if (-not $hasCred) {
            if ([string]::IsNullOrEmpty($Path)) { return [ADSI]'' }
            return [ADSI]$Path
        }
        $u = $Cred.UserName
        $p = $Cred.GetNetworkCredential().Password
        if ([string]::IsNullOrEmpty($Path)) {
            $rd = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE', $u, $p)
            $dnc = "$($rd.Properties['defaultNamingContext'].Value)"
            if ($dnc -eq '') { $dnc = "$($rd.defaultNamingContext)" }
            return New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dnc", $u, $p)
        }
        return New-Object System.DirectoryServices.DirectoryEntry($Path, $u, $p)
    }

    # Reachability (AFNET-safe): reachable = TCP 5985 (WinRM), 5986 (WinRM HTTPS)
    # OR 445 (SMB) succeeds. Never uses ICMP (blocked on AFNET; a DC that answers
    # only ICMP cannot serve the WinRM/SMB Security-log query anyway); short timeouts.
    function Test-AdReachable {
        param([string]$ComputerName)
        foreach ($port in 5985, 5986, 445) {
            $tcp = $null
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $iar = $tcp.BeginConnect($ComputerName, $port, $null, $null)
                if ($iar.AsyncWaitHandle.WaitOne(1000, $false)) {
                    try { $tcp.EndConnect($iar); return $true } catch {}
                }
            } catch {} finally { if ($tcp) { try { $tcp.Close() } catch {} } }
        }
        return $false
    }

    # Bounded reverse-DNS: [System.Net.Dns]::GetHostEntry has no timeout and runs
    # AFTER the scan budget is spent, so a batch of stale/unresolvable IPs can each
    # block for the OS DNS timeout and make the tool look hung. Run the lookup on a
    # child runspace abandoned after a short WaitOne (same pattern as the per-DC
    # query); return '' on timeout/failure.
    function Resolve-IpBounded {
        param([string]$Ip)
        $name = ""
        $psr = [powershell]::Create()
        [void]$psr.AddScript({ param($i) [System.Net.Dns]::GetHostEntry($i).HostName })
        [void]$psr.AddArgument($Ip)
        $ar = $psr.BeginInvoke()
        if ($ar.AsyncWaitHandle.WaitOne(2000, $false)) {
            try { $name = "$($psr.EndInvoke($ar) | Select-Object -First 1)" } catch { $name = "" }
            try { $psr.Dispose() } catch {}
        } else {
            try { [void]$psr.BeginStop($null, $null) } catch {}
            $name = ""
        }
        return $name
    }

    # Restrict an ADSI searcher to exactly the attributes its row projector consumes
    # (see ConvertTo-AdGridRow), so FindAll stops pulling every attribute of every
    # object - including large multi-valued ones (memberof/member/proxyaddresses)
    # that are mostly popup-only. Clears any prior set first because the shared
    # $searcher is reused across search types. Each list must stay in sync with the
    # matching projector arm or that field goes blank.
    function Set-AdLoad {
        param($Searcher, [string[]]$Attrs)
        try { $Searcher.PropertiesToLoad.Clear() } catch {}
        foreach ($a in $Attrs) { [void]$Searcher.PropertiesToLoad.Add($a) }
    }

    $root = New-AdEntry ''
    $searcher = [ADSISEARCHER]$root
    $searcher.PageSize = 15000
    # Cap any single wildcard search at 2000 objects so a broad filter cannot dump
    # the whole directory (the handler also rejects all-wildcard user/computer
    # filters). NOTE: setting PageSize turns FindAll() into a PAGED search, which
    # makes ADSI IGNORE SizeLimit entirely - so this SizeLimit does NOT cap anything
    # on its own. The real cap is enforced manually in each single-searcher harvest
    # loop below, which stops accumulating once $results hits $adSizeCap; SizeLimit
    # is left set only as a harmless secondary guard for any non-paged fallback.
    $searcher.SizeLimit = 2000
    $adSizeCap = 2000
    $results = @()

    # Operator-cancel bridge inside the child runspace: the handler injects the
    # synchronized job hashtable as $SearchParams.__cancel so the long DC scan loop
    # in LastPC can break promptly when Cancel is set. Absent in direct/test calls.
    $cancelJob = $null
    if ($SearchParams -is [hashtable] -and $SearchParams.ContainsKey('__cancel')) { $cancelJob = $SearchParams['__cancel'] }
    $isCancelled = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }

    # Optional OU / base-DN scope: when the operator supplies SearchBase, limit the
    # shared directory searcher to that subtree instead of the whole domain. Applies
    # to the wildcard object searches below AND to LastPC's user-resolution lookup
    # (which reuses this shared searcher); LastPC's DC discovery + Security-log scan
    # stay domain-wide. BaseUsers/BulkComputer use their own roots, so they ignore this.
    if ($SearchParams -is [hashtable] -and $SearchParams.ContainsKey('SearchBase')) {
        $sb = ([string]$SearchParams['SearchBase']).Trim()
        if (-not [string]::IsNullOrWhiteSpace($sb)) {
            # LDAP://<searchBase> is a BIND path, not a filter: a value like 'evildc/DC=x' or a
            # full 'LDAP://evil' URL would redirect the search root bind to an attacker-chosen host.
            # Require a plain distinguished name (starts with a DN RDN, no path chars) - same guard
            # the AD TO scan ships (JanetWeb.adto.psm1:342). This drops the old LDAP://-prefix
            # tolerance for a SEARCH BASE, which was the bind-redirect vector (audit P3).
            if ($sb -notmatch '^[A-Za-z]{1,8}=' -or $sb -match '[/\\]') {
                return @(@{ _Error = "Rejected SearchBase '$sb': must be a plain distinguished name (e.g. OU=Squadron,DC=area52,DC=mil) with no server prefix or path characters."; _Failure = $true })
            }
            if ($sb -notmatch '^(?i)LDAP://') { $sb = "LDAP://$sb" }
            try {
                $searcher.SearchRoot = New-AdEntry $sb
                # ADSI binds lazily: neither [ADSI]$sb nor the SearchRoot assignment
                # contacts the directory, so a typo'd/nonexistent (but syntactically
                # valid) OU slips past this catch and throws later at an uncaught
                # FindAll(), surfacing as a raw COM error instead of this friendly
                # message. Touch NativeObject to force the bind NOW so the catch fires.
                $null = $searcher.SearchRoot.NativeObject
            } catch { return @(@{ _Error = "Invalid OU / base-DN: $($SearchParams['SearchBase'])`n`n$($_.Exception.Message)"; _Failure = $true }) }
        }
    }

    # Per-action attribute projections (see Set-AdLoad). Manager rows route through
    # the same rich user detail set as Search Users, so Manager reuses $userAttrs.
    $userAttrs       = @('samaccountname','displayname','employeeid','givenname','initials','sn','o','c','employeetype','proxyaddresses','mail','title','department','company','l','manager','lockouttime','lastlogontimestamp','userprincipalname','cn','paygrade','physicaldeliveryofficename','telephonenumber','mobile','buildingname','roomnumber','streetaddress','st','postalcode','homedirectory','iatrainingdate','logoncount','whencreated','whenchanged','distinguishedname','memberof','directreports')
    $computerAttrs   = @('name','operatingsystem','operatingsystemversion','lastlogontimestamp','dnshostname','location','logoncount','whencreated','whenchanged','distinguishedname','memberof')
    $groupAttrs      = @('name','member','managedby','whencreated','whenchanged','distinguishedname')
    $orgboxAttrs     = @('name','displayname','mail','title','lockouttime','lastlogontimestamp','othertelephone','manager','msexchdelegatelistlink','whencreated','whenchanged','distinguishedname','memberof')
    $emailAttrs      = @('samaccountname','displayname','employeeid','givenname','initials','sn','o','c','employeetype','proxyaddresses','mail','title','department','company','manager','lockouttime','lastlogontimestamp','userprincipalname','physicaldeliveryofficename','telephonenumber','mobile','distinguishedname','memberof')
    $bulkAttrs       = @('name','distinguishedname','lastlogontimestamp','location','operatingsystem','operatingsystemversion','dnshostname','whencreated','whenchanged','memberof')
    $baseUserAttrs   = @('samaccountname','displayname','cn','distinguishedname','location','mail','title','employeeid','manager','department','company','paygrade','physicaldeliveryofficename','telephonenumber','othertelephone','mobile','l','c','lockouttime','lastlogon','logoncount','whencreated','whenchanged','memberof')
    $lastPcUserAttrs = @('samaccountname','displayname','distinguishedname')

    switch ($SearchType) {
        "User" {
            $firstName = $SearchParams.FirstName
            $lastName  = $SearchParams.LastName
            $edipi     = $SearchParams.EDIPI
            Set-AdLoad $searcher $userAttrs
            $searcher.filter = "(&(objectCategory=person)(objectClass=user)(givenName=$(Escape-LdapFilterValue $firstName)*)(sn=$(Escape-LdapFilterValue $lastName)*)(samaccountname=$(Escape-LdapFilterValue $edipi)*))"
            $adResults = $searcher.FindAll()
            foreach ($user in $adResults) {
                if ($results.Count -ge $adSizeCap) { break }
                $props = @{}
                foreach ($key in $user.Properties.PropertyNames) {
                    $val = $user.Properties[$key]
                    if ($val.Count -eq 1) { $props[$key] = $val[0] } else { $props[$key] = @($val) }
                }
                $results += $props
            }
        }
        "Computer" {
            $computerName = $SearchParams.ComputerName
            Set-AdLoad $searcher $computerAttrs
            $searcher.filter = "(&(objectCategory=Computer)(name=$(Escape-LdapFilterValue $computerName)*))"
            $adResults = $searcher.FindAll()
            foreach ($computer in $adResults) {
                if ($results.Count -ge $adSizeCap) { break }
                $props = @{}
                foreach ($key in $computer.Properties.PropertyNames) {
                    $val = $computer.Properties[$key]
                    if ($val.Count -eq 1) { $props[$key] = $val[0] } else { $props[$key] = @($val) }
                }
                $results += $props
            }
        }
        "Group" {
            $groupName = $SearchParams.GroupName
            Set-AdLoad $searcher $groupAttrs
            $searcher.filter = "(&(objectCategory=group)(name=$(Escape-LdapFilterValue $groupName)*))"
            $adResults = $searcher.FindAll()
            foreach ($group in $adResults) {
                if ($results.Count -ge $adSizeCap) { break }
                $props = @{}
                foreach ($key in $group.Properties.PropertyNames) {
                    $val = $group.Properties[$key]
                    if ($val.Count -eq 1) { $props[$key] = $val[0] } else { $props[$key] = @($val) }
                }
                $results += $props
            }
        }
        "OrgBox" {
            $orgBoxName = $SearchParams.OrgBoxName
            Set-AdLoad $searcher $orgboxAttrs
            $searcher.filter = "(&(objectCategory=person)(objectClass=user)(name=$(Escape-LdapFilterValue $orgBoxName)*))"
            $adResults = $searcher.FindAll()
            foreach ($orgBox in $adResults) {
                if ($results.Count -ge $adSizeCap) { break }
                $props = @{}
                foreach ($key in $orgBox.Properties.PropertyNames) {
                    $val = $orgBox.Properties[$key]
                    if ($val.Count -eq 1) { $props[$key] = $val[0] } else { $props[$key] = @($val) }
                }
                $results += $props
            }
        }
        "Email" {
            $emailAddress = $SearchParams.EmailAddress
            Set-AdLoad $searcher $emailAttrs
            $searcher.filter = "(&(objectCategory=person)(objectClass=user)(mail=$(Escape-LdapFilterValue $emailAddress)*))"
            $adResults = $searcher.FindAll()
            foreach ($user in $adResults) {
                if ($results.Count -ge $adSizeCap) { break }
                $props = @{}
                foreach ($key in $user.Properties.PropertyNames) {
                    $val = $user.Properties[$key]
                    if ($val.Count -eq 1) { $props[$key] = $val[0] } else { $props[$key] = @($val) }
                }
                $results += $props
            }
        }
        "Manager" {
            $managerName = $SearchParams.ManagerName
            Set-AdLoad $searcher $userAttrs
            $searcher.filter = "(&(objectCategory=person)(objectClass=user)(displayName=$(Escape-LdapFilterValue $managerName)*))"
            $managerResults = $searcher.FindAll()
            if ($managerResults.Count -gt 0) {
                $managerDN = $managerResults[0].Properties["distinguishedname"][0]
                $reportSearcher = [ADSISEARCHER]$root
                $reportSearcher.PageSize = 15000
                Set-AdLoad $reportSearcher $userAttrs
                $reportSearcher.filter = "(&(objectCategory=person)(objectClass=user)(manager=$(Escape-LdapFilterValue $managerDN)))"
                $reportResults = $reportSearcher.FindAll()
                $managerProps = @{}
                foreach ($key in $managerResults[0].Properties.PropertyNames) {
                    $val = $managerResults[0].Properties[$key]
                    if ($val.Count -eq 1) { $managerProps[$key] = $val[0] } else { $managerProps[$key] = @($val) }
                }
                $managerProps["_isManager"] = $true
                $managerProps["_directReportCount"] = $reportResults.Count
                $results += $managerProps
                foreach ($report in $reportResults) {
                    $props = @{}
                    foreach ($key in $report.Properties.PropertyNames) {
                        $val = $report.Properties[$key]
                        if ($val.Count -eq 1) { $props[$key] = $val[0] } else { $props[$key] = @($val) }
                    }
                    $props["_isManager"] = $false
                    $results += $props
                }
            }
            return $results
        }
        "BulkComputer" {
            $machineList = $SearchParams.MachineList
            $now = Get-Date
            $staleThreshold = $now.AddDays(-90)

            $foundMachines = @{}

            function Parse-OUFromDN {
                param([string]$DN)
                $ouPath = ($DN -split ",", 2)[1]
                $ouParts = $ouPath -split ","
                $ouNames = @()
                foreach ($part in $ouParts) {
                    if ($part -match "^OU=(.+)$") { $ouNames += $Matches[1] }
                }
                $parentOU = if ($ouNames.Count -ge 1) { $ouNames[0] } else { "(Root)" }
                $squadron = $parentOU
                $genericNames = @("Workstations","Computers","Servers","Desktops","Laptops","Devices","Resources","Members")
                if ($ouNames.Count -ge 2 -and $genericNames -contains $parentOU) {
                    $squadron = $ouNames[1]
                }
                $reversed = @($ouNames)
                [array]::Reverse($reversed)
                $ouChain = $reversed -join " > "
                if ($ouChain -eq "") { $ouChain = "(Root)" }

                return @{
                    Squadron = $squadron
                    ParentOU = $parentOU
                    OUChain  = $ouChain
                    FullOU   = $ouPath
                }
            }

            Set-AdLoad $searcher $bulkAttrs
            $batchSize = 50
            for ($i = 0; $i -lt $machineList.Count; $i += $batchSize) {
                $batch = $machineList[$i..[math]::Min(($i + $batchSize - 1), ($machineList.Count - 1))]

                $filterParts = ""
                foreach ($name in $batch) {
                    $filterParts += "(name=$(Escape-LdapFilterValue $name))"
                }
                if ($batch.Count -eq 1) {
                    $searcher.Filter = "(&(objectCategory=Computer)$filterParts)"
                } else {
                    $searcher.Filter = "(&(objectCategory=Computer)(|$filterParts))"
                }

                try {
                    $adResults = $searcher.FindAll()
                    foreach ($entry in $adResults) {
                        $props = @{}
                        foreach ($key in $entry.Properties.PropertyNames) {
                            $val = $entry.Properties[$key]
                            if ($val.Count -eq 1) { $props[$key] = $val[0] } else { $props[$key] = @($val) }
                        }

                        $dn = $props.distinguishedname
                        $ouInfo = Parse-OUFromDN -DN $dn
                        $props["_squadron"] = $ouInfo.Squadron
                        $props["_parentOU"] = $ouInfo.ParentOU
                        $props["_ouChain"]  = $ouInfo.OUChain
                        $props["_fullOU"]   = $ouInfo.FullOU

                        $lastLogon = "Never"; $isStale = $true
                        try {
                            $tsVal = $props.lastlogontimestamp
                            if ($tsVal -ne $null -and $tsVal -gt 0) {
                                $lastLogonDate = [DateTime]::FromFileTime([Int64]$tsVal)
                                $lastLogon = $lastLogonDate.ToString("yyyy-MM-dd HH:mm")
                                if ($lastLogonDate -ge $staleThreshold) { $isStale = $false }
                            }
                        } catch {}
                        $props["_lastLogon"] = $lastLogon
                        $props["_isStale"]   = $isStale
                        $props["_status"]    = if ($isStale) { "Stale" } else { "Active" }

                        $pcName = "$($props.name)".ToUpper()
                        $foundMachines[$pcName] = $true
                        $results += $props
                    }
                } catch {
                    foreach ($name in $batch) {
                        $searcher.Filter = "(&(objectCategory=Computer)(name=$(Escape-LdapFilterValue $name)))"
                        try {
                            $fallbackResults = $searcher.FindAll()
                            if ($fallbackResults.Count -gt 0) {
                                foreach ($entry in $fallbackResults) {
                                    $props = @{}
                                    foreach ($key in $entry.Properties.PropertyNames) {
                                        $val = $entry.Properties[$key]
                                        if ($val.Count -eq 1) { $props[$key] = $val[0] } else { $props[$key] = @($val) }
                                    }
                                    $dn = $props.distinguishedname
                                    $ouInfo = Parse-OUFromDN -DN $dn
                                    $props["_squadron"] = $ouInfo.Squadron
                                    $props["_parentOU"] = $ouInfo.ParentOU
                                    $props["_ouChain"]  = $ouInfo.OUChain
                                    $props["_fullOU"]   = $ouInfo.FullOU
                                    $lastLogon = "Never"; $isStale = $true
                                    try {
                                        $tsVal = $props.lastlogontimestamp
                                        if ($tsVal -ne $null -and $tsVal -gt 0) {
                                            $lastLogonDate = [DateTime]::FromFileTime([Int64]$tsVal)
                                            $lastLogon = $lastLogonDate.ToString("yyyy-MM-dd HH:mm")
                                            if ($lastLogonDate -ge $staleThreshold) { $isStale = $false }
                                        }
                                    } catch {}
                                    $props["_lastLogon"] = $lastLogon; $props["_isStale"] = $isStale
                                    $props["_status"] = if ($isStale) { "Stale" } else { "Active" }
                                    $foundMachines["$($props.name)".ToUpper()] = $true
                                    $results += $props
                                }
                            }
                        } catch {}
                    }
                }
            }

            foreach ($name in $machineList) {
                if (-not $foundMachines.ContainsKey($name)) {
                    $results += @{
                        name            = $name
                        _squadron       = "NOT FOUND"
                        _parentOU       = "N/A"
                        _ouChain        = "N/A"
                        _fullOU         = "N/A"
                        _lastLogon      = "N/A"
                        _isStale        = $false
                        _status         = "Not Found"
                        operatingsystem = "N/A"
                    }
                }
            }
        }
        "BaseUsers" {
            $baseName = $SearchParams.BaseName
            $allFound = [System.Collections.ArrayList]::new()
            $seenDNs = @{}
            $searchedOUs = [System.Collections.ArrayList]::new()

            $rootDSE = New-AdEntry "LDAP://RootDSE"
            $domainDN = $rootDSE.defaultNamingContext.ToString()

            $ouSearcher = [ADSISEARCHER]$root
            $ouSearcher.PageSize = 1000
            Set-AdLoad $ouSearcher @('distinguishedname')
            $ouSearcher.Filter = "(&(objectCategory=organizationalUnit)(name=$(Escape-LdapFilterValue $baseName)*))"
            $baseOUs = @()
            try {
                $baseOUResults = $ouSearcher.FindAll()
                foreach ($ou in $baseOUResults) {
                    $baseOUs += "$($ou.Properties['distinguishedname'][0])"
                }
            } catch {}

            foreach ($baseOUDN in $baseOUs) {
                $childSearcher = New-Object System.DirectoryServices.DirectorySearcher
                $childSearcher.SearchRoot = New-AdEntry "LDAP://$baseOUDN"
                $childSearcher.PageSize = 1000
                $childSearcher.SearchScope = "Subtree"
                Set-AdLoad $childSearcher @('distinguishedname','name')
                $childSearcher.Filter = "(&(objectCategory=organizationalUnit)(|(name=*Users*)(name=*Administrative*)(name=*AFB*)))"
                try {
                    $childOUs = $childSearcher.FindAll()
                    foreach ($childOU in $childOUs) {
                        $childOUDN = "$($childOU.Properties['distinguishedname'][0])"
                        $childOUName = "$($childOU.Properties['name'][0])"
                        [void]$searchedOUs.Add($childOUDN)

                        $userSearcher = New-Object System.DirectoryServices.DirectorySearcher
                        $userSearcher.SearchRoot = New-AdEntry "LDAP://$childOUDN"
                        $userSearcher.PageSize = 15000
                        $userSearcher.SearchScope = "Subtree"
                        Set-AdLoad $userSearcher $baseUserAttrs

                        if ($childOUName -match "Users") {
                            $userSearcher.Filter = "(&(objectCategory=person)(objectClass=user))"
                        } else {
                            $userSearcher.Filter = "(&(objectCategory=person)(objectClass=user)(|(samaccountname=*.adw)(samaccountname=*.adf)(samaccountname=*.adm)(samaccountname=*.ada)(samaccountname=*.adn)(samaccountname=*.SA)))"
                        }
                        try {
                            $userResults = $userSearcher.FindAll()
                            foreach ($user in $userResults) {
                                $dn = "$($user.Properties['distinguishedname'][0])"
                                if (-not $seenDNs.ContainsKey($dn)) {
                                    $seenDNs[$dn] = $true
                                    [void]$allFound.Add($user)
                                }
                            }
                        } catch {}
                    }
                } catch {}
            }

            if ($searchedOUs.Count -eq 0) {
                $msg = "No 'Users', 'Administrative', or 'AFB' OU found under '$baseName'.`n`n"
                if ($baseOUs.Count -gt 0) {
                    $msg += "Found base OU(s):`n"
                    foreach ($b in $baseOUs) { $msg += "  $b`n" }
                    $msg += "`nBut none contained a child OU with 'Users', 'Administrative', or 'AFB' in the name.`n"
                    $msg += "`nCheck your AD structure for the correct OU names."
                } else {
                    $msg += "No OU matching '$baseName' was found in the domain.`n"
                    $msg += "`nTry: LAKENHEATH, RAMSTEIN, SPANGDAHLEM, MILDENHALL"
                }
                return @(@{ _Error = $msg })
            }

            if ($allFound.Count -eq 0) {
                $msg = "Searched the following OU(s) but found 0 user accounts:`n`n"
                foreach ($s in $searchedOUs) { $msg += "  $s`n" }
                return @(@{ _Error = $msg })
            }

            foreach ($user in $allFound) {
                $props = @{}
                foreach ($key in $user.Properties.PropertyNames) {
                    $val = $user.Properties[$key]
                    if ($val.Count -eq 1) { $props[$key] = $val[0] } else { $props[$key] = @($val) }
                }

                $isPriv = $false
                $privReason = ""
                $sam = "$($props.samaccountname)"
                $displayName = "$($props.displayname)"
                $cn = "$($props.cn)"

                $privSuffixes = @('.adw','.adf','.adm','.ada','.adn','.SA')
                foreach ($suffix in $privSuffixes) {
                    if ($sam.EndsWith($suffix) -or $sam.EndsWith($suffix.ToUpper()) -or $sam.EndsWith($suffix.ToLower())) {
                        $isPriv = $true
                        $privReason = "Account suffix: $suffix"
                        break
                    }
                }

                if (-not $isPriv) {
                    if ($sam -like "*_adm" -or $sam -like "*-adm" -or $sam -like "*_ada" -or $sam -like "*-ada") {
                        $isPriv = $true
                        $privReason = "Account name pattern: admin suffix"
                    }
                }

                if (-not $isPriv) {
                    if ($displayName -match "\(ADM\)" -or $cn -match "\(ADM\)" -or $displayName -match "^ADM[\s\-]") {
                        $isPriv = $true
                        $privReason = "Display name contains (ADM)"
                    }
                }

                $props["_isPrivileged"] = $isPriv
                $props["_privLevel"]    = if ($isPriv) { "Privileged" } else { "Standard" }
                $props["_privReason"]   = $privReason

                $dn = "$($props.distinguishedname)"
                $ouParts = $dn -split ","
                $ouNames = @()
                foreach ($part in $ouParts) {
                    if ($part -match "^OU=(.+)$") { $ouNames += $Matches[1] }
                }
                $parentOU = if ($ouNames.Count -ge 1) { $ouNames[0] } else { "(Root)" }
                $props["_parentOU"] = $parentOU

                $locVal = "$($props.location)"
                $org = ""
                if ($locVal -ne "" -and $locVal -match "ORGANIZATION:\s*([^;]+)") {
                    $org = $Matches[1].Trim()
                }
                $props["_organization"] = $org

                $email = $props.mail
                if ($email -eq $null) { $email = "" }
                $props["_email"] = "$email"

                $props["_sourceOU"] = ""
                foreach ($sou in $searchedOUs) {
                    if ($dn -like "*$sou*") { $props["_sourceOU"] = $sou; break }
                }

                $results += $props
            }

            # Sort: privileged first, then alphabetical (mirrors the original
            # ListView sort so output order matches the desktop tool).
            $results = @($results | Sort-Object { $_["_isPrivileged"] } -Descending | Sort-Object { $_["_privLevel"] }, { $_.displayname })
        }
        "LastPC" {
            $firstName = "$($SearchParams.FirstName)"
            $lastName  = "$($SearchParams.LastName)"
            $edipi     = "$($SearchParams.EDIPI)"
            $daysBack  = if ($SearchParams.DaysBack) { [int]$SearchParams.DaysBack } else { 14 }
            if ($daysBack -lt 1)  { $daysBack = 1 }
            if ($daysBack -gt 90) { $daysBack = 90 }

            # Escape operator input (parity with the other search types) - prevents a
            # malformed/injected LDAP filter from a name with ( ) * \ characters.
            $userFilter = "(&(objectCategory=person)(objectClass=user)"
            if ($firstName) { $userFilter += "(givenName=$(Escape-LdapFilterValue $firstName)*)" }
            if ($lastName)  { $userFilter += "(sn=$(Escape-LdapFilterValue $lastName)*)" }
            if ($edipi)     { $userFilter += "(samaccountname=$(Escape-LdapFilterValue $edipi)*)" }
            $userFilter += ")"
            Set-AdLoad $searcher $lastPcUserAttrs
            $searcher.filter = $userFilter
            $userResults = $searcher.FindAll()
            if ($userResults.Count -eq 0) {
                return @(@{ _Error = "No matching user found.`n`nFirst Name: $firstName`nLast Name: $lastName`nEDIPI: $edipi" })
            }

            $maxUsers = 5
            $matchedUsers = @()
            $u_i = 0
            foreach ($u in $userResults) {
                if ($u_i -ge $maxUsers) { break }
                $matchedUsers += $u
                $u_i++
            }
            $truncated = ($userResults.Count -gt $maxUsers)

            $samToDisplay = @{}
            $samToDN      = @{}
            $samEsc       = @()
            foreach ($mu in $matchedUsers) {
                $sam = "$($mu.Properties['samaccountname'][0])"
                if ($sam -eq "") { continue }
                $samToDisplay[$sam] = "$($mu.Properties['displayname'][0])"
                $samToDN[$sam]      = "$($mu.Properties['distinguishedname'][0])"
                # audit#15: escape for XML ( & < > ) but NOT the apostrophe. A
                # sAMAccountName may legally contain ' ; escaping it to &apos; only
                # deferred the problem - the XML parser de-escapes it back to ' BEFORE
                # XPath runs, closing the single-quoted starts-with() literal and making
                # Get-WinEvent throw on every DC. The apostrophe is handled below by
                # building an XPath concat() expression instead of a bare literal.
                $sXml = $sam -replace "&","&amp;" -replace "<","&lt;" -replace ">","&gt;"
                $samEsc += $sXml
            }
            if ($samEsc.Count -eq 0) {
                return @(@{ _Error = "Matched user record(s) had empty sAMAccountName." })
            }

            $dcSearcher = [ADSISEARCHER]$root
            $dcSearcher.PageSize = 500
            Set-AdLoad $dcSearcher @('dnshostname')
            $dcSearcher.Filter = "(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
            $dcs = @()
            foreach ($dc in $dcSearcher.FindAll()) {
                $h = "$($dc.Properties['dnshostname'][0])"
                if ($h -ne "") { $dcs += $h }
            }
            if ($dcs.Count -eq 0) {
                return @(@{ _Error = "No domain controllers were discovered via LDAP."; _Failure = $true })
            }

            $daysBackMs = [int64]$daysBack * 86400000
            # Build an XPath 1.0 string expression that is safe even when the value
            # contains a single quote (XPath has no in-literal quote escape; use
            # concat('a', "'", 'b')). No apostrophe -> a plain 'literal'.
            $xpathLiteral = {
                param($v)
                if ($v -notmatch "'") { return "'$v'" }
                $parts = $v -split "'"
                $pieces = New-Object System.Collections.ArrayList
                for ($i = 0; $i -lt $parts.Count; $i++) {
                    if ($parts[$i] -ne '') { [void]$pieces.Add("'$($parts[$i])'") }
                    if ($i -lt $parts.Count - 1) { [void]$pieces.Add('"' + "'" + '"') }  # the apostrophe as a double-quoted piece
                }
                return 'concat(' + ($pieces -join ', ') + ')'
            }
            $startsWith = ($samEsc | ForEach-Object { "starts-with(Data, $(& $xpathLiteral $_))" }) -join " or "
            $xmlFilter = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4624 or EventID=4768 or EventID=4769 or EventID=4776) and TimeCreated[timediff(@SystemTime) &lt;= $daysBackMs]] and EventData[Data[@Name='TargetUserName'] and ($startsWith)]]</Select>
  </Query>
</QueryList>
"@

            $allHits    = New-Object System.Collections.ArrayList
            $dcErrors   = New-Object System.Collections.ArrayList
            $dcsScanned = 0

            # Bound the scan so the last-PC lookup can't run long / hang: an overall
            # wall-clock deadline (checked between DCs, like the WPT fan-outs) PLUS a
            # per-DC query timeout (a wedged Get-WinEvent is abandoned, not awaited).
            # MaxScanSeconds is operator-tunable (10-600, default 120).
            $scanSeconds = if ($SearchParams.MaxScanSeconds) { [int]$SearchParams.MaxScanSeconds } else { 120 }
            if ($scanSeconds -lt 10)  { $scanSeconds = 10 }
            if ($scanSeconds -gt 600) { $scanSeconds = 600 }
            $scanDeadline = (Get-Date).AddSeconds($scanSeconds)
            $perDcMs      = 20000
            $timedOut     = $false

            # Fan the per-DC Security-log scan out across a bounded RunspacePool
            # (mirroring wpt's bulk-scan) instead of scanning serially. A serial scan
            # tripped the wall-clock deadline after only a handful of reachable-but-slow
            # DCs, silently skipping the rest and missing a genuine last-PC hit on an
            # unscanned DC. The pool scans the whole DC set within the same budget,
            # raising coverage dramatically. Concurrency is capped so a large forest
            # can't open hundreds of WinRM sessions at once; the per-DC timeout, the
            # overall $scanDeadline, the $Cred wiring, and the operator $isCancelled
            # check are all preserved.
            $maxDcThreads = 8
            $poolSize = $maxDcThreads
            if ($dcs.Count -lt $poolSize) { $poolSize = $dcs.Count }
            if ($poolSize -lt 1) { $poolSize = 1 }

            # Worker (one per DC): AFNET-safe reachability (TCP 5985/5986/445, never
            # ICMP) then read the DC Security log over WinRM (Invoke-Command) under the
            # operator credential, falling back to RPC/135 (Get-WinEvent -ComputerName)
            # only if WinRM is unavailable. Both honor $cred. Reachability runs inside
            # the worker so unreachable DCs are probed in parallel too. $useSsl tracks
            # whether ONLY 5986 answered (5985 is tried first and wins on tie), so the
            # Invoke-Command below auto-switches that DC to -UseSSL. Returns a
            # structured result the harvest loop turns into hits or a DC-error line.
            $dcWorker = {
                param($c, $x, $cred)
                $reachable = $false; $useSsl = $false
                foreach ($port in 5985, 5986, 445) {
                    $tcp = $null
                    try {
                        $tcp = New-Object System.Net.Sockets.TcpClient
                        $iar = $tcp.BeginConnect($c, $port, $null, $null)
                        if ($iar.AsyncWaitHandle.WaitOne(1000, $false)) {
                            try { $tcp.EndConnect($iar); $reachable = $true; if ($port -eq 5986) { $useSsl = $true } } catch {}
                        }
                    } catch {} finally { if ($tcp) { try { $tcp.Close() } catch {} } }
                    if ($reachable) { break }
                }
                if (-not $reachable) { return @{ DC = $c; Reachable = $false; Events = $null; Error = 'unreachable (WinRM/SMB)' } }
                try {
                    $icArgs = @{ ComputerName = $c; ErrorAction = 'Stop'; ArgumentList = $x;
                                 ScriptBlock = { param($xf) Get-WinEvent -FilterXml $xf -MaxEvents 2000 -ErrorAction Stop } }
                    if ($useSsl) { $icArgs['UseSSL'] = $true; $icArgs['SessionOption'] = New-PSSessionOption -SkipCACheck -SkipCNCheck }
                    if ($cred) { $icArgs['Credential'] = $cred }
                    $ev = Invoke-Command @icArgs
                    return @{ DC = $c; Reachable = $true; Events = $ev; Error = $null }
                } catch {
                    try {
                        $gwArgs = @{ ComputerName = $c; FilterXml = $x; MaxEvents = 2000; ErrorAction = 'Stop' }
                        if ($cred) { $gwArgs['Credential'] = $cred }
                        $ev = Get-WinEvent @gwArgs
                        return @{ DC = $c; Reachable = $true; Events = $ev; Error = $null }
                    } catch {
                        return @{ DC = $c; Reachable = $true; Events = $null; Error = "$($_.Exception.Message)" }
                    }
                }
            }

            $dcPool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $poolSize)
            $dcPool.Open()
            $dcJobs = New-Object System.Collections.ArrayList
            foreach ($dc in $dcs) {
                $psDc = [powershell]::Create(); $psDc.RunspacePool = $dcPool
                [void]$psDc.AddScript($dcWorker)
                [void]$psDc.AddArgument($dc); [void]$psDc.AddArgument($xmlFilter); [void]$psDc.AddArgument($Cred)
                [void]$dcJobs.Add([pscustomobject]@{ DC = $dc; PS = $psDc; Async = $psDc.BeginInvoke(); StartedAt = $null })
            }

            $dcDone = 0
            try {
                while ($dcDone -lt $dcJobs.Count) {
                    $activeCount = @($dcJobs | Where-Object { $_.PS -and $_.StartedAt }).Count
                    foreach ($j in $dcJobs) {
                        # Stamp real start only up to the pool's real concurrency, in queue order: a PS queued
                        # in a saturated pool reports State='Running' at once, which would false-time-out the backlog.
                        if ($j.PS -and -not $j.StartedAt -and $activeCount -lt $dcPool.GetMaxRunspaces()) { $j.StartedAt = Get-Date; $activeCount++ }
                        if ($j.PS -and $j.Async.IsCompleted) {
                            $res = $null
                            try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 } catch { $res = @{ DC = $j.DC; Reachable = $true; Events = $null; Error = "$($_.Exception.Message)" } }
                            try { $j.PS.Dispose() } catch {}
                            $j.PS = $null
                            if ($null -eq $res) { $res = @{ DC = $j.DC; Reachable = $true; Events = $null; Error = 'no result' } }
                            $dc = $res.DC
                            $events = $res.Events
                            if ($res.Reachable -ne $true) {
                                [void]$dcErrors.Add("$dc :: $($res.Error)")
                            } elseif ($null -ne $events) {
                                $dcsScanned++
                                foreach ($evt in $events) {
                                    try {
                                        $xml = [xml]$evt.ToXml()
                                        $data = @{}
                                        foreach ($d in $xml.Event.EventData.Data) {
                                            $data["$($d.Name)"] = "$($d.'#text')"
                                        }
                                        $tu = "$($data.TargetUserName)"
                                        if ($tu -eq "" -or $tu -like "*$") { continue }

                                        $matchedSam = $null
                                        foreach ($mu in $matchedUsers) {
                                            $sam = "$($mu.Properties['samaccountname'][0])"
                                            if ($sam -eq "") { continue }
                                            if ($tu -ieq $sam -or $tu -ilike "$sam@*") {
                                                $matchedSam = $sam
                                                break
                                            }
                                        }
                                        if (-not $matchedSam) { continue }

                                        $ip  = "$($data.IpAddress)"
                                        $wks = "$($data.WorkstationName)"
                                        if ($wks -eq "") { $wks = "$($data.Workstation)" }
                                        if ($ip -eq "::1" -or $ip -eq "127.0.0.1" -or $ip -eq "-") { $ip = "" }
                                        if ($ip -like "::ffff:*") { $ip = $ip.Substring(7) }
                                        if ($ip -eq "" -and $wks -eq "") { continue }

                                        [void]$allHits.Add(@{
                                            Time      = $evt.TimeCreated
                                            EventId   = $evt.Id
                                            DC        = $dc
                                            IP        = $ip
                                            Wks       = $wks
                                            Sam       = $matchedSam
                                            LogonType = "$($data.LogonType)"
                                        })
                                    } catch {}
                                }
                            } else {
                                [void]$dcErrors.Add("$dc :: $($res.Error)")
                            }
                            $dcDone++
                        }
                    }
                    # Per-DC watchdog: abandon ONLY a DC that overran its own query clock
                    # (BeginStop, not Dispose - Dispose on a stuck pipeline blocks) so one
                    # slow DC can't pin a pool thread for the whole scan.
                    if ($dcDone -lt $dcJobs.Count) {
                        $nowDc = Get-Date
                        foreach ($j in $dcJobs) {
                            if ($j.PS -and $j.StartedAt -and ($nowDc - $j.StartedAt).TotalMilliseconds -gt $perDcMs) {
                                try { [void]$j.PS.BeginStop($null, $null) } catch {}
                                $j.PS = $null
                                [void]$dcErrors.Add("$($j.DC) :: query timed out after $([int]($perDcMs / 1000))s (abandoned)")
                                $dcDone++
                            }
                        }
                    }
                    if ($dcDone -lt $dcJobs.Count) {
                        # Operator Cancel -> stop scanning the rest; wall-clock deadline ->
                        # mark timed out. Either way abandon in-flight / un-started DC jobs
                        # (BeginStop) and break with the partial results already in hand.
                        $stopScan = $false
                        if (& $isCancelled) { $stopScan = $true }
                        elseif ((Get-Date) -gt $scanDeadline) { $timedOut = $true; $stopScan = $true }
                        if ($stopScan) {
                            foreach ($j in $dcJobs) {
                                if ($j.PS) {
                                    try { [void]$j.PS.BeginStop($null, $null) } catch {}
                                    $j.PS = $null
                                    $dcDone++
                                }
                            }
                            break
                        }
                        Start-Sleep -Milliseconds 120
                    }
                }
            } finally {
                try { $dcPool.Close(); $dcPool.Dispose() } catch {}
            }

            if ($allHits.Count -eq 0) {
                $msg = "No matching logon events found across $dcsScanned of $($dcs.Count) DC(s) in the last $daysBack day(s)."
                if ($timedOut) { $msg += "`n`n** Scan stopped at the $scanSeconds-second time limit - only $dcsScanned of $($dcs.Count) DC(s) were scanned. Raise 'Max scan seconds' or reduce 'Days Back' to cover more DCs. **" }
                $msg += "`n`nMatched user(s):"
                foreach ($mu in $matchedUsers) {
                    $msg += "`n  $($mu.Properties['displayname'][0])  ($($mu.Properties['samaccountname'][0]))"
                }
                if ($dcErrors.Count -gt 0) {
                    $msg += "`n`nDC errors:"
                    foreach ($e in $dcErrors) { $msg += "`n  $e" }
                    $msg += "`n`nIf every DC failed with 'access denied' you do not have permission to read the Security log on the DCs.  Re-launch from a privileged account."
                }
                return @(@{ _Error = $msg })
            }

            $resolvedIp = @{}
            $byKey = @{}
            foreach ($h in $allHits) {
                $hostName = ""
                # Prefer the WorkstationName carried on the event; only fall back to a
                # (bounded) reverse-DNS lookup when Wks is empty (Kerberos 4768/4769
                # often carry an IP but no Wks). The lookup is time-boxed so a batch of
                # stale IPs can't hang the post-scan aggregation.
                if ($h.Wks -ne "") {
                    $hostName = $h.Wks
                } elseif ($h.IP -ne "" -and $h.IP -match "[\d\.:]") {
                    if (-not $resolvedIp.ContainsKey($h.IP)) {
                        $resolvedIp[$h.IP] = Resolve-IpBounded $h.IP
                    }
                    $hostName = $resolvedIp[$h.IP]
                }
                if ($hostName -eq "" -and $h.IP -ne "") { $hostName = $h.IP }
                if ($hostName -eq "") { continue }

                $hostShort = ($hostName -split '\.')[0].ToUpper()
                $key = "$($h.Sam.ToLower())|$hostShort"
                if (-not $byKey.ContainsKey($key) -or $byKey[$key]._time -lt $h.Time) {
                    $byKey[$key] = @{
                        _sam          = $h.Sam
                        _computerName = $hostShort
                        _ipAddress    = $h.IP
                        _time         = $h.Time
                        _eventId      = $h.EventId
                        _dc           = $h.DC
                        _logonType    = $h.LogonType
                    }
                }
            }

            $sorted = $byKey.Values | Sort-Object { $_._time } -Descending
            foreach ($row in $sorted) {
                $row["_displayName"]       = $samToDisplay["$($row._sam)"]
                $row["_distinguishedName"] = $samToDN["$($row._sam)"]
                $row["_timeStr"]           = $row._time.ToString("yyyy-MM-dd HH:mm:ss")
                $row["_dcShort"]           = ($row._dc -split '\.')[0].ToUpper()
                $row["_daysBack"]          = $daysBack
                $row["_dcsScanned"]        = $dcsScanned
                $row["_dcsTotal"]          = $dcs.Count
                $row["_eventCount"]        = $allHits.Count
                $row["_userTruncated"]     = $truncated
                $row["_timedOut"]          = $timedOut
                $row["_scanSeconds"]       = $scanSeconds
                $row["_dcErrors"]          = $(if ($timedOut) { "** Scan hit the $scanSeconds s time limit - results are PARTIAL ($dcsScanned of $($dcs.Count) DC(s) scanned). **`n" } else { "" }) + ($dcErrors -join "`n")
                $results += $row
            }
        }
    }
    return $results
}

# -----------------------------------------------------------------------------
#  Row projectors: turn an engine result hashtable into a grid row matching the
#  manifest columns for each action. Mirrors Process-SearchResults' per-type
#  column selection (Tools\ADSearchTool.ps1 lines 1978-2327).
# -----------------------------------------------------------------------------
function Get-AdPropString {
    param([hashtable]$Props, [string]$Key)
    if ($null -eq $Props) { return '' }
    if (-not $Props.ContainsKey($Key)) { return '' }
    $v = $Props[$Key]
    if ($null -eq $v) { return '' }
    if ($v -is [array]) { return (($v | ForEach-Object { [string]$_ }) -join '; ') }
    return [string]$v
}

function Get-AdRowCount {
    param([hashtable]$Props, [string]$Key)
    if ($null -eq $Props -or -not $Props.ContainsKey($Key)) { return 0 }
    $v = $Props[$Key]
    if ($null -eq $v) { return 0 }
    if ($v -is [array]) { return $v.Count }
    return 1
}

# --- detail-projection helpers (rich per-result detail, ported from ADSearcher.ps1) ---
function Get-AdCn {
    # CN-strip a DN to a readable name: "CN=Doe\, John,OU=...,DC=..." -> "Doe, John"
    param([string]$Dn)
    if ([string]::IsNullOrWhiteSpace($Dn)) { return '' }
    $m = [regex]::Match($Dn, '^CN=((?:[^,\\]|\\.)+)')
    if ($m.Success) { return ($m.Groups[1].Value -replace '\\(.)', '$1') }
    return $Dn
}
function Get-AdCnList {
    # CN-strip every DN in a (possibly multi-valued) property and join for the popup.
    param([hashtable]$Props, [string]$Key, [int]$Max = 60)
    if ($null -eq $Props -or -not $Props.ContainsKey($Key)) { return '' }
    $v = $Props[$Key]; if ($null -eq $v) { return '' }
    $arr = @($v)
    $names = @($arr | ForEach-Object { Get-AdCn ([string]$_) } | Where-Object { $_ -ne '' })
    if ($names.Count -gt $Max) { $names = @($names | Select-Object -First $Max) + @("...(+$($arr.Count - $Max) more)") }
    return ($names -join '; ')
}
function Format-AdFileTime {
    # lastLogon / lastLogonTimestamp are Int64 FILETIME ticks; 0/empty = never.
    param([hashtable]$Props, [string]$Key)
    if ($null -eq $Props -or -not $Props.ContainsKey($Key)) { return '' }
    $raw = $Props[$Key]; if ($raw -is [array]) { $raw = @($raw)[0] }
    if ($null -eq $raw) { return '' }
    $ft = [int64]0
    if (-not [int64]::TryParse([string]$raw, [ref]$ft)) { return [string]$raw }
    if ($ft -le 0) { return 'never' }
    try { return ([datetime]::FromFileTime($ft).ToString('yyyy-MM-dd HH:mm')) } catch { return [string]$raw }
}
function Get-AdLockedOut {
    # lockoutTime > 0 => locked (same test ADSearcher uses).
    param([hashtable]$Props)
    if ($null -eq $Props -or -not $Props.ContainsKey('lockouttime')) { return 'No' }
    $raw = $Props['lockouttime']; if ($raw -is [array]) { $raw = @($raw)[0] }
    $lt = [int64]0
    if ($raw -and [int64]::TryParse([string]$raw, [ref]$lt) -and $lt -gt 0) { return 'Yes' }
    return 'No'
}
function Get-AdOuFromDn {
    # The container path (the OU chain) parsed from a DN, for the popup.
    param([string]$Dn)
    if ([string]::IsNullOrWhiteSpace($Dn)) { return '' }
    $parts = $Dn -split '(?<!\\),'
    $ous = @($parts | Where-Object { $_ -match '^OU=' } | ForEach-Object { ($_ -replace '^OU=', '') -replace '\\(.)', '$1' })
    if ($ous.Count -gt 0) { return ($ous -join ' / ') }
    return ''
}

function Get-AdDisplayName {
    # Display-name with sAMAccountName fallback (used by ConvertTo-AdGridRow user arms).
    param([hashtable]$P)
    $v = Get-AdPropString $P 'displayname'
    if ($v -eq '') { $v = Get-AdPropString $P 'samaccountname' }
    return $v
}

function ConvertTo-AdGridRow {
    param([string]$ActionId, [hashtable]$P, [int]$Index)
    switch ($ActionId) {
        'search-user' {
            $dn = Get-AdDisplayName $P
            # Grid shows the lean columns; every extra key here surfaces only in the
            # click-through detail popup (showRowModal renders all non-_/type keys).
            return [ordered]@{
                Host              = (Get-AdPropString $P 'samaccountname')
                DisplayName       = $dn
                SamAccountName    = (Get-AdPropString $P 'samaccountname')
                EmployeeID        = (Get-AdPropString $P 'employeeid')
                FirstName         = (Get-AdPropString $P 'givenname')
                MiddleName        = (Get-AdPropString $P 'initials')
                LastName          = (Get-AdPropString $P 'sn')
                SubMajcom         = (Get-AdPropString $P 'o')
                Country           = (Get-AdPropString $P 'c')
                EmployeeType      = (Get-AdPropString $P 'employeetype')
                ProxyAddresses    = (Get-AdPropString $P 'proxyaddresses')
                Email             = (Get-AdPropString $P 'mail')
                Title             = (Get-AdPropString $P 'title')
                Department        = (Get-AdPropString $P 'department')
                Company           = (Get-AdPropString $P 'company')
                Location          = (Get-AdPropString $P 'l')
                Manager           = (Get-AdCn (Get-AdPropString $P 'manager'))
                LockedOut         = (Get-AdLockedOut $P)
                LastLogon         = (Format-AdFileTime $P 'lastlogontimestamp')
                UPN               = (Get-AdPropString $P 'userprincipalname')
                CN                = (Get-AdPropString $P 'cn')
                PayGrade          = (Get-AdPropString $P 'paygrade')
                Office            = (Get-AdPropString $P 'physicaldeliveryofficename')
                Phone             = (Get-AdPropString $P 'telephonenumber')
                Mobile            = (Get-AdPropString $P 'mobile')
                Building          = (Get-AdPropString $P 'buildingname')
                Room              = (Get-AdPropString $P 'roomnumber')
                Street            = (Get-AdPropString $P 'streetaddress')
                State             = (Get-AdPropString $P 'st')
                PostalCode        = (Get-AdPropString $P 'postalcode')
                HomeDirectory     = (Get-AdPropString $P 'homedirectory')
                IATrainingDate    = (Get-AdPropString $P 'iatrainingdate')
                LogonCount        = (Get-AdPropString $P 'logoncount')
                WhenCreated       = (Get-AdPropString $P 'whencreated')
                WhenChanged       = (Get-AdPropString $P 'whenchanged')
                OU                = (Get-AdOuFromDn (Get-AdPropString $P 'distinguishedname'))
                Groups            = (Get-AdCnList $P 'memberof')
                DirectReports     = (Get-AdCnList $P 'directreports')
                DistinguishedName = (Get-AdPropString $P 'distinguishedname')
            }
        }
        'search-computer' {
            return [ordered]@{
                Host              = (Get-AdPropString $P 'name')
                Name              = (Get-AdPropString $P 'name')
                OperatingSystem   = (Get-AdPropString $P 'operatingsystem')
                OSVersion         = (Get-AdPropString $P 'operatingsystemversion')
                LastLogon         = (Format-AdFileTime $P 'lastlogontimestamp')   # was the raw FILETIME integer
                DnsHostName       = (Get-AdPropString $P 'dnshostname')
                Location          = (Get-AdPropString $P 'location')
                LogonCount        = (Get-AdPropString $P 'logoncount')
                WhenCreated       = (Get-AdPropString $P 'whencreated')
                WhenChanged       = (Get-AdPropString $P 'whenchanged')
                OU                = (Get-AdOuFromDn (Get-AdPropString $P 'distinguishedname'))
                Groups            = (Get-AdCnList $P 'memberof')
                DistinguishedName = (Get-AdPropString $P 'distinguishedname')
            }
        }
        'search-group' {
            return [ordered]@{
                Host              = (Get-AdPropString $P 'name')
                Name              = (Get-AdPropString $P 'name')
                MemberCount       = (Get-AdRowCount $P 'member')
                ManagedBy         = (Get-AdCn (Get-AdPropString $P 'managedby'))
                WhenCreated       = (Get-AdPropString $P 'whencreated')
                WhenChanged       = (Get-AdPropString $P 'whenchanged')
                OU                = (Get-AdOuFromDn (Get-AdPropString $P 'distinguishedname'))
                Members           = (Get-AdCnList $P 'member')
                DistinguishedName = (Get-AdPropString $P 'distinguishedname')
            }
        }
        'search-orgbox' {
            return [ordered]@{
                Host              = (Get-AdPropString $P 'name')
                Name              = (Get-AdPropString $P 'name')
                DisplayName       = (Get-AdPropString $P 'displayname')
                Email             = (Get-AdPropString $P 'mail')
                Title             = (Get-AdPropString $P 'title')
                LockedOut         = (Get-AdLockedOut $P)
                LastLogon         = (Format-AdFileTime $P 'lastlogontimestamp')
                Phone             = (Get-AdPropString $P 'othertelephone')
                Manager           = (Get-AdCn (Get-AdPropString $P 'manager'))
                Delegates         = (Get-AdCnList $P 'msexchdelegatelistlink')
                WhenCreated       = (Get-AdPropString $P 'whencreated')
                WhenChanged       = (Get-AdPropString $P 'whenchanged')
                OU                = (Get-AdOuFromDn (Get-AdPropString $P 'distinguishedname'))
                Groups            = (Get-AdCnList $P 'memberof')
                DistinguishedName = (Get-AdPropString $P 'distinguishedname')
            }
        }
        'search-email' {
            $dn = Get-AdDisplayName $P
            return [ordered]@{
                Host              = (Get-AdPropString $P 'samaccountname')
                DisplayName       = $dn
                SamAccountName    = (Get-AdPropString $P 'samaccountname')
                EmployeeID        = (Get-AdPropString $P 'employeeid')
                FirstName         = (Get-AdPropString $P 'givenname')
                MiddleName        = (Get-AdPropString $P 'initials')
                LastName          = (Get-AdPropString $P 'sn')
                SubMajcom         = (Get-AdPropString $P 'o')
                Country           = (Get-AdPropString $P 'c')
                EmployeeType      = (Get-AdPropString $P 'employeetype')
                ProxyAddresses    = (Get-AdPropString $P 'proxyaddresses')
                Email             = (Get-AdPropString $P 'mail')
                Title             = (Get-AdPropString $P 'title')
                Department        = (Get-AdPropString $P 'department')
                Company           = (Get-AdPropString $P 'company')
                Manager           = (Get-AdCn (Get-AdPropString $P 'manager'))
                LockedOut         = (Get-AdLockedOut $P)
                LastLogon         = (Format-AdFileTime $P 'lastlogontimestamp')
                UPN               = (Get-AdPropString $P 'userprincipalname')
                Office            = (Get-AdPropString $P 'physicaldeliveryofficename')
                Phone             = (Get-AdPropString $P 'telephonenumber')
                Mobile            = (Get-AdPropString $P 'mobile')
                OU                = (Get-AdOuFromDn (Get-AdPropString $P 'distinguishedname'))
                Groups            = (Get-AdCnList $P 'memberof')
                DistinguishedName = (Get-AdPropString $P 'distinguishedname')
            }
        }
        'search-manager' {
            $isMgr = ($P.ContainsKey('_isManager') -and $P['_isManager'] -eq $true)
            $dn = Get-AdDisplayName $P
            $rc = ''
            if ($P.ContainsKey('_directReportCount')) { $rc = [string]$P['_directReportCount'] }
            # Grid shows the manifest columns; the extra keys mirror the full
            # search-user detail set (desktop routes Manager rows through the
            # same user detail handler, ADSearchTool.ps1 line 3408) and surface
            # only in the click-through detail popup.
            return [ordered]@{
                Host              = (Get-AdPropString $P 'samaccountname')
                Role              = $(if ($isMgr) { 'Manager' } else { 'Direct Report' })
                DisplayName       = $dn
                SamAccountName    = (Get-AdPropString $P 'samaccountname')
                EmployeeID        = (Get-AdPropString $P 'employeeid')
                FirstName         = (Get-AdPropString $P 'givenname')
                MiddleName        = (Get-AdPropString $P 'initials')
                LastName          = (Get-AdPropString $P 'sn')
                SubMajcom         = (Get-AdPropString $P 'o')
                Country           = (Get-AdPropString $P 'c')
                EmployeeType      = (Get-AdPropString $P 'employeetype')
                ProxyAddresses    = (Get-AdPropString $P 'proxyaddresses')
                Title             = (Get-AdPropString $P 'title')
                Department        = (Get-AdPropString $P 'department')
                Email             = (Get-AdPropString $P 'mail')
                DirectReportCount = $rc
                Company           = (Get-AdPropString $P 'company')
                Location          = (Get-AdPropString $P 'l')
                Manager           = (Get-AdCn (Get-AdPropString $P 'manager'))
                LockedOut         = (Get-AdLockedOut $P)
                LastLogon         = (Format-AdFileTime $P 'lastlogontimestamp')
                UPN               = (Get-AdPropString $P 'userprincipalname')
                CN                = (Get-AdPropString $P 'cn')
                PayGrade          = (Get-AdPropString $P 'paygrade')
                Office            = (Get-AdPropString $P 'physicaldeliveryofficename')
                Phone             = (Get-AdPropString $P 'telephonenumber')
                Mobile            = (Get-AdPropString $P 'mobile')
                Building          = (Get-AdPropString $P 'buildingname')
                Room              = (Get-AdPropString $P 'roomnumber')
                Street            = (Get-AdPropString $P 'streetaddress')
                State             = (Get-AdPropString $P 'st')
                PostalCode        = (Get-AdPropString $P 'postalcode')
                HomeDirectory     = (Get-AdPropString $P 'homedirectory')
                IATrainingDate    = (Get-AdPropString $P 'iatrainingdate')
                LogonCount        = (Get-AdPropString $P 'logoncount')
                WhenCreated       = (Get-AdPropString $P 'whencreated')
                WhenChanged       = (Get-AdPropString $P 'whenchanged')
                OU                = (Get-AdOuFromDn (Get-AdPropString $P 'distinguishedname'))
                Groups            = (Get-AdCnList $P 'memberof')
                DirectReports     = (Get-AdCnList $P 'directreports')
                DistinguishedName = (Get-AdPropString $P 'distinguishedname')
            }
        }
        'search-bulk-computer' {
            $loc = Get-AdPropString $P 'location'
            $org = ''
            if ($loc -ne '' -and $loc -match 'ORGANIZATION:\s*([^;]+)') { $org = $Matches[1].Trim() }
            if ($org -eq '') { $org = (Get-AdPropString $P '_squadron') }
            # USER / LAST UPDATE sub-fields parsed from the raw location string
            # (desktop bulk detail handler, ADSearchTool.ps1 lines 3534-3549).
            # Everything past Status is popup-only detail.
            $assigned = ''; $lastUpdate = ''
            if ($loc -ne '') {
                if ($loc -match 'USER:\s*([^;]+)')     { $assigned   = $Matches[1].Trim() }
                if ($loc -match 'LAST UPDATE:\s*(.+)') { $lastUpdate = $Matches[1].Trim() }
            }
            return [ordered]@{
                Host              = (Get-AdPropString $P 'name')
                Name              = (Get-AdPropString $P 'name')
                Organization      = $org
                Squadron          = (Get-AdPropString $P '_squadron')
                OUChain           = (Get-AdPropString $P '_ouChain')
                OperatingSystem   = (Get-AdPropString $P 'operatingsystem')
                LastLogon         = (Get-AdPropString $P '_lastLogon')
                Status            = (Get-AdPropString $P '_status')
                Location          = $loc
                AssignedUser      = $assigned
                LastUpdate        = $lastUpdate
                ParentOU          = (Get-AdPropString $P '_parentOU')
                OSVersion         = (Get-AdPropString $P 'operatingsystemversion')
                DnsHostName       = (Get-AdPropString $P 'dnshostname')
                WhenCreated       = (Get-AdPropString $P 'whencreated')
                WhenChanged       = (Get-AdPropString $P 'whenchanged')
                Groups            = (Get-AdCnList $P 'memberof')
                DistinguishedName = (Get-AdPropString $P 'distinguishedname')
            }
        }
        'search-base-users' {
            $dn = Get-AdDisplayName $P
            $org = Get-AdPropString $P '_organization'
            if ($org -eq '') { $org = Get-AdPropString $P '_parentOU' }
            # Keys past PrivReason mirror the desktop Base Users detail pane
            # (ADSearchTool.ps1 lines 3573-3631) and are popup-only.
            return [ordered]@{
                Host              = (Get-AdPropString $P 'samaccountname')
                DisplayName       = $dn
                SamAccountName    = (Get-AdPropString $P 'samaccountname')
                Privilege         = (Get-AdPropString $P '_privLevel')
                Organization      = $org
                ParentOU          = (Get-AdPropString $P '_parentOU')
                Title             = (Get-AdPropString $P 'title')
                Email             = (Get-AdPropString $P '_email')
                PrivReason        = (Get-AdPropString $P '_privReason')
                EmployeeID        = (Get-AdPropString $P 'employeeid')
                Manager           = (Get-AdCn (Get-AdPropString $P 'manager'))
                Department        = (Get-AdPropString $P 'department')
                Company           = (Get-AdPropString $P 'company')
                PayGrade          = (Get-AdPropString $P 'paygrade')
                Office            = (Get-AdPropString $P 'physicaldeliveryofficename')
                Phone             = (Get-AdPropString $P 'telephonenumber')
                Commercial        = (Get-AdPropString $P 'othertelephone')
                Mobile            = (Get-AdPropString $P 'mobile')
                Base              = (Get-AdPropString $P 'l')
                Country           = (Get-AdPropString $P 'c')
                LockedOut         = (Get-AdLockedOut $P)
                LastLogon         = (Format-AdFileTime $P 'lastlogon')
                LogonCount        = (Get-AdPropString $P 'logoncount')
                WhenCreated       = (Get-AdPropString $P 'whencreated')
                WhenChanged       = (Get-AdPropString $P 'whenchanged')
                Groups            = (Get-AdCnList $P 'memberof')
                DistinguishedName = (Get-AdPropString $P 'distinguishedname')
            }
        }
        'search-last-pc' {
            $user = Get-AdPropString $P '_displayName'
            if ($user -eq '') { $user = Get-AdPropString $P '_sam' }
            return @{
                Host           = (Get-AdPropString $P '_computerName')
                User           = $user
                SamAccountName = (Get-AdPropString $P '_sam')
                Computer       = (Get-AdPropString $P '_computerName')
                IPAddress      = (Get-AdPropString $P '_ipAddress')
                LastSeen       = (Get-AdPropString $P '_timeStr')
                EventId        = (Get-AdPropString $P '_eventId')
                LogonType      = (Get-AdPropString $P '_logonType')
                DC             = (Get-AdPropString $P '_dcShort')
            }
        }
        default { return @{ Host = "row$Index" } }
    }
}

function Invoke-JanetToolAction {
    param(
        [string]$ActionId,
        [hashtable]$Params,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Emit
    )
    $send = { param($e) if ($Emit) { & $Emit $e } }

    # Operator-cancel bridge: the server injects the synchronized job hashtable as
    # $Params['__job']; its 'Cancel' flag (set by POST /job/<id>/cancel) lets a
    # running search break. Absent in direct/test calls -> $cancelCheck returns
    # $false. Mirrors the same closure other modules (e.g. c2c.psm1) build.
    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }

    $searchType = $null; $searchParams = $null
    switch ($ActionId) {
        'search-user'     { $searchType='User';     $searchParams=@{ FirstName=[string]$Params['FirstName']; LastName=[string]$Params['LastName']; EDIPI=[string]$Params['EDIPI']; SearchBase=[string]$Params['SearchBase'] } }
        'search-computer' { $searchType='Computer'; $searchParams=@{ ComputerName=[string]$Params['ComputerName']; SearchBase=[string]$Params['SearchBase'] } }
        'search-group'    { $searchType='Group';    $searchParams=@{ GroupName=[string]$Params['GroupName']; SearchBase=[string]$Params['SearchBase'] } }
        'search-orgbox'   { $searchType='OrgBox';   $searchParams=@{ OrgBoxName=[string]$Params['OrgBoxName']; SearchBase=[string]$Params['SearchBase'] } }
        'search-email'    { $searchType='Email';    $searchParams=@{ EmailAddress=[string]$Params['EmailAddress']; SearchBase=[string]$Params['SearchBase'] } }
        'search-manager'  { $searchType='Manager';  $searchParams=@{ ManagerName=[string]$Params['ManagerName']; SearchBase=[string]$Params['SearchBase'] } }
        'search-bulk-computer' { $searchType='BulkComputer'; $searchParams=@{ MachineList=@(ConvertTo-JanetMachineList $Params['MachineList']) } }
        'search-base-users' { $searchType='BaseUsers'; $searchParams=@{ BaseName=[string]$Params['BaseName'] } }
        'search-last-pc' {
            # Digits-only check first (desktop ADSearchTool.ps1 line 3272): a
            # failed TryParse zeroes its [ref] target, which would silently
            # collapse the 14-day default instead of preserving it.
            $db = 14
            $rawDays = ([string]$Params['DaysBack']).Trim()
            $parsedDays = 0
            if ($rawDays -match '^\d+$' -and [int]::TryParse($rawDays, [ref]$parsedDays)) { $db = $parsedDays }
            # Max scan seconds (engine clamps to 10-600; default 120). Parse defensively
            # so a non-numeric value can't throw the [int] cast inside the engine.
            $msec = 120
            $rawSec = ([string]$Params['MaxScanSeconds']).Trim()
            $parsedSec = 0
            if ($rawSec -match '^\d+$' -and [int]::TryParse($rawSec, [ref]$parsedSec) -and $parsedSec -gt 0) { $msec = $parsedSec }
            $searchType='LastPC'; $searchParams=@{
                FirstName=[string]$Params['FirstName']; LastName=[string]$Params['LastName']; EDIPI=[string]$Params['EDIPI']; SearchBase=[string]$Params['SearchBase']
                DaysBack=$db; MaxScanSeconds=$msec
            }
        }
    }
    if ($null -eq $searchType) {
        & $send @{ type='error'; text="Unknown action '$ActionId'." }
        return @{ rows=@(); summary=@{} }
    }
    # Hand the cancel job to the child runspace so the long DC-scan loop in LastPC
    # can break promptly (the engine reads $SearchParams.__cancel).
    if ($cancelJob -and $searchParams -is [hashtable]) { $searchParams['__cancel'] = $cancelJob }

    # Audit target: the search term itself (this is a directory query, not a
    # per-host op). Read/scan/lookup = TouchHost per the JANET two-bucket model.
    $auditTarget =
        switch ($ActionId) {
            'search-user'         { "$($searchParams.FirstName) $($searchParams.LastName) $($searchParams.EDIPI)".Trim() }
            'search-computer'     { $searchParams.ComputerName }
            'search-group'        { $searchParams.GroupName }
            'search-orgbox'       { $searchParams.OrgBoxName }
            'search-email'        { $searchParams.EmailAddress }
            'search-manager'      { $searchParams.ManagerName }
            'search-bulk-computer'{ "$($searchParams.MachineList.Count) machine(s)" }
            'search-base-users'   { $searchParams.BaseName }
            'search-last-pc'      { "$($searchParams.FirstName) $($searchParams.LastName) $($searchParams.EDIPI)".Trim() }
            default               { $ActionId }
        }
    if ([string]::IsNullOrWhiteSpace($auditTarget)) { $auditTarget = $ActionId }

    # Input-threshold guard: the desktop per-field minimums, enforced engine-side
    # (Tools\ADSearchTool.ps1 ChooseSearchOptions, lines 3224-3280) so the ENGINE
    # refuses short/empty terms regardless of client-side validation. Every term
    # is wildcard-suffixed in the LDAP filter, so a 1-char (or blank) term is a
    # directory-wide scan at PageSize 15000.
    $guardMsg = $null
    switch ($searchType) {
        'User' {
            $ln = ([string]$searchParams.LastName).Trim()
            $ed = ([string]$searchParams.EDIPI).Trim()
            if ($ed.Length -lt 10 -and $ln.Length -lt 2) {
                $guardMsg = 'Enter at least 2 characters for Last Name, or an EDIPI of at least 10 characters.'
            }
        }
        'Computer' {
            if (([string]$searchParams.ComputerName).Trim().Length -lt 4) {
                $guardMsg = 'Enter at least 4 characters for Computer Name.'
            }
        }
        'Group' {
            if (([string]$searchParams.GroupName).Trim().Length -lt 4) {
                $guardMsg = 'Enter at least 4 characters for Group Name.'
            }
        }
        'OrgBox' {
            if (([string]$searchParams.OrgBoxName).Trim().Length -lt 4) {
                $guardMsg = 'Enter at least 4 characters for Org Box Name.'
            }
        }
        'Email' {
            if (([string]$searchParams.EmailAddress).Trim().Length -lt 3) {
                $guardMsg = 'Enter at least 3 characters for Email Address.'
            }
        }
        'Manager' {
            if (([string]$searchParams.ManagerName).Trim().Length -lt 3) {
                $guardMsg = 'Enter at least 3 characters for the Manager display name.'
            }
        }
        'BulkComputer' {
            if (@($searchParams.MachineList).Count -lt 1) {
                $guardMsg = 'Enter or import at least one machine name (one per line).'
            }
        }
        'BaseUsers' {
            if (([string]$searchParams.BaseName).Trim().Length -lt 3) {
                $guardMsg = 'Enter at least 3 characters for the Base/Location name (e.g. LAKENHEATH, RAMSTEIN).'
            }
        }
        'LastPC' {
            $fn = ([string]$searchParams.FirstName).Trim()
            $ln = ([string]$searchParams.LastName).Trim()
            $ed = ([string]$searchParams.EDIPI).Trim()
            $hasName  = ($fn.Length -ge 2) -or ($ln.Length -ge 2)
            $hasEdipi = ($ed.Length -ge 10)
            if (-not ($hasName -or $hasEdipi)) {
                $guardMsg = 'Enter a first or last name (2+ characters), or a 10-digit EDIPI.'
            }
        }
    }
    if ($guardMsg) {
        & $send @{ type='log'; level='warn'; text=$guardMsg }
        & $send @{ type='audit'; action='TouchHost'; target=[string]$auditTarget; result='Skipped'; itemCount=0; detail='rejected: search term below minimum length' }
        & $send @{ type='progress'; done=1; total=1 }
        & $send @{ type='status'; text='Done. Search refused (input below minimum).' }
        return @{ rows=@(); summary=@{ total=0; ok=0; failed=0; message=$guardMsg } }
    }

    & $send @{ type='status'; text="Running '$ActionId' against Active Directory..." }
    & $send @{ type='progress'; done=0; total=1 }

    # Run the engine in an isolated STA child runspace, exactly as the original
    # Start-AsyncSearch did (Tools\ADSearchTool.ps1 lines 1290-1965). Read-only:
    # when the operator supplies a credential the engine binds AD/LDAP and the
    # LastPC remote query under it; otherwise the current Kerberos identity is used.
    $runspace   = $null
    $powershell = $null
    $rawResults = @()
    $engineError = $null
    $cancelled   = $false
    try {
        $runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
        try { $runspace.ApartmentState = 'STA' } catch {}
        $runspace.Open()
        $powershell = [System.Management.Automation.PowerShell]::Create()
        $powershell.Runspace = $runspace
        [void]$powershell.AddScript($script:AdSearchEngine)
        [void]$powershell.AddArgument($searchType)
        [void]$powershell.AddArgument($searchParams)
        # Wire the operator-supplied credential into every AD/LDAP bind and the LastPC
        # remote log query (engine binds null = current Kerberos identity, unchanged).
        [void]$powershell.AddArgument($Credential)
        # Drive the engine with BeginInvoke + a 150ms poll loop (mirrors the
        # BeginInvoke/poll/BeginStop pattern in c2c.psm1) so an operator Cancel
        # can break a long DC scan instead of blocking on a single Invoke().
        $output = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
        $async  = $powershell.BeginInvoke($output, $output)
        while (-not $async.IsCompleted) {
            if (& $cancelCheck) {
                $cancelled = $true
                try { [void]$powershell.BeginStop($null, $null) } catch {}
                break
            }
            Start-Sleep -Milliseconds 150
        }
        if (-not $cancelled) {
            try { [void]$powershell.EndInvoke($async) } catch { $engineError = $_.Exception.Message }
        }
        # Harvest whatever the engine produced (full result on completion, any
        # partial output already flushed when cancelled).
        $rawResults = @($output)
        if (-not $cancelled -and $powershell.HadErrors -and $powershell.Streams.Error.Count -gt 0) {
            $engineError = [string]$powershell.Streams.Error[0]
        }
    } catch {
        $engineError = $_.Exception.Message
    } finally {
        if ($powershell) { try { $powershell.Dispose() } catch {} }
        if ($runspace)   { try { $runspace.Close(); $runspace.Dispose() } catch {} }
    }

    # Operator cancelled mid-scan: project any partial rows, log + Skipped audit,
    # and return what we accumulated (default behaviour for a non-cancel run is
    # unchanged - this branch only runs when the Cancel flag was observed).
    if ($cancelled) {
        $cancelRows = New-Object System.Collections.ArrayList
        $ci = 0
        foreach ($res in $rawResults) {
            if ($res -isnot [hashtable]) { continue }
            if ($res.ContainsKey('_Error')) { continue }
            $row = ConvertTo-AdGridRow -ActionId $ActionId -P $res -Index $ci
            [void]$cancelRows.Add($row)
            & $send (@{ type='row' } + $row)
            $ci++
        }
        $cc = $cancelRows.Count
        & $send @{ type='log'; level='warn'; text='Cancelled by operator; search stopped (in-flight DC scan abandoned).' }
        & $send @{ type='audit'; action='TouchHost'; target=[string]$auditTarget; result='Skipped'; itemCount=$cc; detail='cancelled by operator' }
        & $send @{ type='progress'; done=1; total=1 }
        & $send @{ type='status'; text="Cancelled. $cc partial result(s)." }
        return @{ rows=@($cancelRows); summary=@{ total=$cc; ok=$cc; failed=0; cancelled=$true } }
    }

    # Hard engine failure (e.g. not domain-joined) -> error row + Failure audit.
    if ($engineError) {
        & $send @{ type='log'; level='err'; text="AD search failed: $engineError" }
        & $send @{ type='audit'; action='TouchHost'; target=[string]$auditTarget; result='Failure'; itemCount=0; detail=("error: $engineError") }
        & $send @{ type='progress'; done=1; total=1 }
        & $send @{ type='status'; text='Done. Search failed.' }
        # Render the error into the FIRST manifest column for this action so the
        # manifest-driven grid actually paints it (the old @{Host;Error} row
        # declared no real columns and showed a blank line). Fall back to the log
        # line alone if the manifest lookup fails.
        $errRow = $null
        try {
            $firstCol = ((Get-JanetToolManifest).actions | Where-Object { $_.id -eq $ActionId } | Select-Object -First 1).columns[0]
            if ($firstCol) { $errRow = @{ $firstCol = "(error) $engineError" } }
        } catch {}
        if ($errRow) {
            & $send (@{ type='row' } + $errRow)
            return @{ rows=@($errRow); summary=@{ total=0; ok=0; failed=1; error=$engineError } }
        }
        return @{ rows=@(); summary=@{ total=0; ok=0; failed=1; error=$engineError } }
    }

    # The engine signals soft errors (no match, denied DC logs, missing OU) as a
    # single hashtable carrying _Error - surface it without throwing.
    if ($rawResults.Count -eq 1 -and ($rawResults[0] -is [hashtable]) -and $rawResults[0].ContainsKey('_Error')) {
        $msg = [string]$rawResults[0]['_Error']
        # An invalid SearchBase / failed AD bind (or no DC discoverable) is a real
        # failure, not a 'nothing found' outcome: the engine tags those with _Failure,
        # so audit them Failure. Genuine empty-result conditions stay Skipped.
        $isFail = ($rawResults[0].ContainsKey('_Failure') -and $rawResults[0]['_Failure'] -eq $true)
        if ($isFail) {
            & $send @{ type='log'; level='err'; text=$msg }
            & $send @{ type='audit'; action='TouchHost'; target=[string]$auditTarget; result='Failure'; itemCount=0; detail=("error: $msg") }
            & $send @{ type='progress'; done=1; total=1 }
            & $send @{ type='status'; text='Done. Search failed.' }
            return @{ rows=@(); summary=@{ total=0; ok=0; failed=1; message=$msg } }
        }
        & $send @{ type='log'; level='warn'; text=$msg }
        & $send @{ type='audit'; action='TouchHost'; target=[string]$auditTarget; result='Skipped'; itemCount=0; detail='no results' }
        & $send @{ type='progress'; done=1; total=1 }
        & $send @{ type='status'; text='Done. No results.' }
        return @{ rows=@(); summary=@{ total=0; ok=0; failed=0; message=$msg } }
    }

    # Project each result into a grid row and stream it.
    $rows = New-Object System.Collections.ArrayList
    $idx  = 0
    foreach ($res in $rawResults) {
        if ($res -isnot [hashtable]) { continue }
        $row = ConvertTo-AdGridRow -ActionId $ActionId -P $res -Index $idx
        [void]$rows.Add($row)
        & $send (@{ type='row' } + $row)
        $idx++
    }

    $count = $rows.Count
    $summary = @{ total=$count; ok=$count; failed=0 }
    # Audit itemCount / Success-vs-Skipped reflect REAL units of work only. By default
    # that is every projected row, but placeholder rows that mean 'nothing found'
    # (bulk-computer Not Found) are excluded below so they cannot inflate the count or
    # force a Success.
    $auditCount = $count

    # Per-action rollups + coverage warnings, mirroring the desktop
    # Process-SearchResults summary pane (ADSearchTool.ps1 lines 2051-2327).
    if ($ActionId -eq 'search-last-pc') {
        # Every LastPC row carries the same scan metadata; read it off the
        # first raw result so DC failures / truncation are no longer dropped.
        $meta = $null
        foreach ($res in $rawResults) {
            if ($res -is [hashtable] -and $res.ContainsKey('_dcsTotal')) { $meta = $res; break }
        }
        if ($meta) {
            $dcErrList = @()
            if ("$($meta['_dcErrors'])" -ne '') {
                $dcErrList = @("$($meta['_dcErrors'])" -split "`n" | Where-Object { $_.Trim() -ne '' })
            }
            # The engine prepends a '** Scan hit the time limit ... **' coverage banner
            # to _dcErrors when the wall-clock deadline trips with results already in
            # hand. Surface that as a coverage warning, NOT as a bogus 'DC skipped'
            # line, and keep it out of the real DC-error count.
            $realDcErr = New-Object System.Collections.ArrayList
            foreach ($de in $dcErrList) {
                if ($de.Trim().StartsWith('**')) {
                    & $send @{ type='log'; level='warn'; text=$de.Trim() }
                } else {
                    & $send @{ type='log'; level='warn'; text="DC skipped: $de" }
                    [void]$realDcErr.Add($de)
                }
            }
            if ($meta['_userTruncated'] -eq $true) {
                & $send @{ type='log'; level='warn'; text='More than 5 users matched; only the first 5 were scanned. Narrow the name or pass an EDIPI.' }
            }
            & $send @{ type='log'; text="Coverage: scanned $($meta['_dcsScanned']) of $($meta['_dcsTotal']) DC(s) over the last $($meta['_daysBack']) day(s); $($meta['_eventCount']) matching event(s), $($realDcErr.Count) DC error(s)." }
            $summary['daysBack']      = [int]$meta['_daysBack']
            $summary['dcsScanned']    = [int]$meta['_dcsScanned']
            $summary['dcsTotal']      = [int]$meta['_dcsTotal']
            $summary['eventCount']    = [int]$meta['_eventCount']
            $summary['dcErrors']      = $realDcErr.Count
            $summary['userTruncated'] = [bool]$meta['_userTruncated']
            $summary['timedOut']      = [bool]$meta['_timedOut']
            $summary['scanSeconds']   = [int]$meta['_scanSeconds']
        }
    } elseif ($ActionId -eq 'search-bulk-computer') {
        $active = 0; $stale = 0; $notFound = 0
        foreach ($res in $rawResults) {
            if ($res -isnot [hashtable]) { continue }
            switch ([string]$res['_status']) {
                'Active' { $active++ }
                'Stale'  { $stale++ }
                default  { $notFound++ }   # Not Found / Error (desktop counts both as not-found)
            }
        }
        & $send @{ type='log'; text="Bulk lookup: $($active + $stale) found in AD (Active: $active, Stale 90+d: $stale); Not Found: $notFound." }
        $summary['active']   = $active
        $summary['stale']    = $stale
        $summary['notFound'] = $notFound
        # Only machines actually resolved in AD (Active + Stale) are real results;
        # Not Found placeholders are excluded from the audit count / Success decision.
        $auditCount = $active + $stale
    } elseif ($ActionId -eq 'search-base-users') {
        $priv = 0; $std = 0
        $ouSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($res in $rawResults) {
            if ($res -isnot [hashtable]) { continue }
            if ($res['_isPrivileged'] -eq $true) { $priv++ } else { $std++ }
            $sou = Get-AdPropString $res '_sourceOU'
            if ($sou -ne '') { [void]$ouSet.Add($sou) }
        }
        & $send @{ type='log'; text="Base users: Privileged: $priv, Standard: $std across $($ouSet.Count) searched OU(s)." }
        $summary['privileged']  = $priv
        $summary['standard']    = $std
        $summary['searchedOUs'] = $ouSet.Count
        # Base Users runs its own child userSearcher at PageSize 15000 with no SizeLimit
        # (unlike the single-searcher modes the 2000 cap below covers), so a whole base
        # can stream tens of thousands of rows. Surface a large-export advisory at the
        # same 2000 threshold the other modes warn at - advisory only, nothing is
        # truncated, so existing behaviour is unchanged.
        if ($count -ge 2000) {
            & $send @{ type='log'; level='warn'; text="Base Users returned $count account(s) - a large export. Narrow the Base/Location name to reduce load." }
            $summary['largeExport'] = $true
        }
    }

    # The engine manually caps every single-searcher harvest at 2000 objects
    # (paging makes ADSI ignore SizeLimit, so it stops accumulating at the cap
    # itself). A harvest that comes back at the cap was truncated - flag it.
    if ($count -ge 2000 -and (@('search-user','search-computer','search-group','search-orgbox','search-email') -contains $ActionId)) {
        & $send @{ type='log'; level='warn'; text='Results capped at 2000 - narrow the search (results are truncated).' }
        $summary['capped'] = $true
    }

    & $send @{ type='audit'; action='TouchHost'; target=[string]$auditTarget; result=$(if ($auditCount -gt 0) { 'Success' } else { 'Skipped' }); itemCount=$auditCount; detail=("$auditCount result(s)") }
    & $send @{ type='progress'; done=1; total=1 }
    & $send @{ type='status'; text="Done. $count result(s)." }

    return @{ rows = @($rows); summary = $summary }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
