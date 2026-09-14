# Regression tests: isolated HKCU key and temporary files; no real VPN changes.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('amnezia-sync-test-' + [Guid]::NewGuid().ToString('N'))
$testRegistry = 'Software\AmneziaRouteSync-Tests\' + [Guid]::NewGuid().ToString('N')
$updater = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'update-amnezia-routes.ps1') -Raw -Encoding UTF8
# Load declarations only, never the entry point that uses the user's settings.
$declarations = $updater.Substring(0, $updater.IndexOf('# --- self-test'))
. ([scriptblock]::Create($declarations)) -StateDir $testRoot
$RegistryConfSubKey = $testRegistry + '\Conf'
$RegistryServersSubKey = $testRegistry + '\Servers'
[IO.Directory]::CreateDirectory($testRoot) | Out-Null

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Assert-Throws([scriptblock]$Action, [string]$Message) {
    $thrown = $false
    try { & $Action } catch { $thrown = $true }
    Assert-True $thrown $Message
}

try {
    Assert-QtCodec
    # This failed with Object[] instead of Byte[] in Windows PowerShell 5.1.
    $original = @{'example.com' = @('93.184.216.34'); '5.255.0.0/16' = @()}
    Write-RoutingRegistry $original
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($RegistryConfSubKey, $true)
    try {
        $key.SetValue('untouched', 'sentinel')
        $key.SetValue('killSwitchEnabled', 'false')
    } finally { $key.Dispose() }
    $snapshot = Read-RoutingRegistrySnapshot | ConvertTo-Json -Depth 12 | ConvertFrom-Json
    Write-RoutingRegistry @{'other.example' = @('8.8.8.8')}
    Restore-RoutingRegistrySnapshot $snapshot
    Assert-RoutingRegistry $original
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($RegistryConfSubKey)
    try { Assert-True ($key.GetValue('untouched') -ceq 'sentinel') 'Rollback changed an unrelated value' } finally { $key.Dispose() }
    Write-Host 'PASS: real registry binary backup/restore'

    foreach ($bad in @('bad-.example.com', 'ok.-bad.com', 'a..example.com')) {
        Assert-True (-not (Test-Hostname $bad)) "Invalid hostname accepted: $bad"
    }
    $current = @{'manual.example'=@('8.8.8.8'); 'old.example'=@('9.9.9.9'); 'example.com'=@('93.184.216.34')}
    $desired = Get-DesiredSites $current @('old.example','example.com') @('example.com','5.255.0.0/16') @{'example.com'=@('1.1.1.1')}
    Assert-True ($desired.ContainsKey('manual.example') -and -not $desired.ContainsKey('old.example')) 'Manual/managed merge failed'
    Assert-True ($desired['example.com'][0] -ceq '1.1.1.1') 'DNS rotation kept stale addresses'
    $fallback = Get-DesiredSites $current @('example.com') @('example.com') @{}
    Assert-True ($fallback['example.com'][0] -ceq '93.184.216.34') 'DNS failure discarded existing addresses'
    Assert-True ((@(Get-PublicIPv4Values @('10.0.0.1','127.0.0.1','::1','1.1.1.1')) -join ',') -ceq '1.1.1.1') 'DNS accepted non-public addresses'
    Write-Host 'PASS: DNS rotation, fallback, manual entries, reserved addresses'

    # End-to-end migration from domain keys to a minimal union of actual routes.
    $routeList = [pscustomobject]@{
        Domains = @('inside.example','same.example','adjacent.example','lost.example','snapshot.example','missing.example')
        Cidrs = @('5.255.0.0/16')
        DomainAddresses = @{'snapshot.example'=@('9.9.9.9'); 'inside.example'=@('4.4.4.4')}
    }
    $routeDns = [pscustomobject]@{
        Addresses = @{'inside.example'=@('5.255.1.1'); 'same.example'=@('1.1.1.0'); 'adjacent.example'=@('1.1.1.0','1.1.1.1')}
        PreviousAddresses = @{'lost.example'=@('8.8.8.8'); 'removed.example'=@('4.4.4.4')}
    }
    $oldSites = @{'manual.example'=@('7.7.7.7'); 'lost.example'=@('8.8.4.4'); 'snapshot.example'=@(); 'inside.example'=@('4.4.4.4')}
    $plan = Get-ManagedRoutePlan $routeList $routeDns $oldSites $routeList.Domains
    Assert-True (($plan.Entries -join ',') -ceq '1.1.1.0/31,5.255.0.0/16,8.8.8.8/32,9.9.9.9/32') 'Compaction changed coverage or retained stale/removed DNS'
    Assert-True ($plan.UnresolvedDomainCount -eq 1 -and $plan.RemovedRouteCount -eq 3) 'Compaction accounting failed'
    $migrated = Get-DesiredSites $oldSites $routeList.Domains $plan.Entries
    Assert-True ($migrated.Count -eq 5 -and $migrated['manual.example'][0] -eq '7.7.7.7') 'Migration lost manual settings'
    Assert-True (-not $migrated.ContainsKey('inside.example') -and -not $migrated.ContainsKey('missing.example')) 'Migration left domain keys or empty routes'
    # DNS churn inside a covered prefix no longer restarts the VPN.
    $routeDns.Addresses['inside.example'] = @('5.255.2.2')
    $plan2 = Get-ManagedRoutePlan $routeList $routeDns $migrated $plan.Entries
    Assert-True (Test-SitesEqual $migrated (Get-DesiredSites $migrated $plan.Entries $plan2.Entries)) 'Equivalent DNS coverage changed settings'
    $routeLimit = $MaximumEffectiveRoutes
    $MaximumEffectiveRoutes = 3
    Assert-Throws { Get-ManagedRoutePlan $routeList $routeDns $oldSites $routeList.Domains } 'Effective route budget was not enforced'
    $MaximumEffectiveRoutes = $routeLimit
    # Test both import fields, invalid addresses, and empty-registry fallback.
    $fixtureEntries = @(0..299 | ForEach-Object { @{hostname="5.255.$([int]($_ / 256)).$($_ % 256)/32";ip=''} })
    $fixtureEntries += @{hostname='snapshot.example';ip='1.1.1.1';ips=@('9.9.9.9','10.1.2.3','::1','invalid')}
    $minimumRoutesBefore = $MinimumRoutes
    $MinimumRoutes = 1
    $imported = ConvertFrom-ImportList (ConvertTo-Json -InputObject $fixtureEntries -Depth 5) 'fixture'
    $MinimumRoutes = $minimumRoutesBefore
    Assert-True (($imported.DomainAddresses['snapshot.example'] -join ',') -ceq '1.1.1.1,9.9.9.9') 'Snapshot validation failed'
    $localEntries = @(Get-LocalSubnetEntries)
    foreach ($hostRoute in @('172.20.15.255/32','172.29.239.255/32','192.168.90.255/32','10.42.0.1/32')) {
        $combined = @(Compress-Cidrs @(@($localEntries | ForEach-Object { ConvertTo-Cidr $_ }) + (ConvertTo-Cidr $hostRoute)))
        Assert-True ($combined.Count -eq 3) 'LAN policy missed a subnet created after login'
    }
    $NoLocalSubnets = $true
    Assert-True (@(Get-LocalSubnetEntries).Count -eq 0) 'Private tunnel opt-out failed'
    $NoLocalSubnets = $false
    Write-Host 'PASS: route coverage, migration, DNS churn, snapshots, route budget, stable LAN'

    $originalLookup = ${function:Start-DomainLookup}
    $script:lookupCount = 0
    function Start-DomainLookup([string]$Hostname) {
        $script:lookupCount++
        $completion = New-Object 'System.Threading.Tasks.TaskCompletionSource[System.Net.IPAddress[]]'
        if ($Hostname -eq 'fail.example') {
            $completion.SetException([Exception]::new('DNS failure'))
        } else {
            $completion.SetResult([Net.IPAddress[]]@([Net.IPAddress]::Parse('1.1.1.1'),[Net.IPAddress]::Parse('::1')))
        }
        return ,$completion.Task
    }
    $dns = Resolve-ManagedDomains @('ok.example','fail.example')
    Assert-True ($dns.Addresses.Count -eq 1 -and $dns.Addresses['ok.example'][0] -eq '1.1.1.1') 'DNS resolver result failed'
    Write-JsonAtomic $DnsCachePath $dns.Cache
    $cached = Resolve-ManagedDomains @('fail.example','ok.example')
    Assert-True ($cached.Cached -and $script:lookupCount -eq 2) 'Fresh cache triggered DNS requests'
    $subset = Resolve-ManagedDomains @('ok.example')
    Assert-True ($subset.Cached -and $subset.Addresses.Count -eq 1 -and $script:lookupCount -eq 2) 'Catalog reduction unnecessarily repeated DNS'
    $empty = Resolve-ManagedDomains @()
    Assert-True ($empty.Addresses.Count -eq 0) 'IP-only list needs no DNS'
    # Even multiple failed refreshes keep last-known IPs after domain keys have
    # been removed from Registry. They never count as fresh successful answers.
    Write-JsonAtomic $DnsCachePath ([ordered]@{
        version=1; updated_at=[DateTime]::UtcNow.AddHours(-5).ToString('o')
        domains=@('fail.example'); addresses=@{}; last_known_addresses=@{'fail.example'=@('9.9.9.9')}
    })
    $failedAgain = Resolve-ManagedDomains @('fail.example')
    Assert-True ($failedAgain.Addresses.Count -eq 0 -and $failedAgain.PreviousAddresses['fail.example'][0] -eq '9.9.9.9') 'Failed refresh lost last-known DNS or marked it fresh'
    Remove-Item -LiteralPath $DnsCachePath -Force
    $script:lookupCount = 0
    function Start-DomainLookup([string]$Hostname) {
        $script:lookupCount++
        $completion = New-Object 'System.Threading.Tasks.TaskCompletionSource[System.Net.IPAddress[]]'
        return ,$completion.Task
    }
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $timedOut = Resolve-ManagedDomains @('a.example','b.example','c.example','d.example') -TimeoutSeconds 1 -Concurrency 2
    Assert-True ($timer.Elapsed.TotalSeconds -lt 3 -and $script:lookupCount -eq 2 -and $timedOut.Addresses.Count -eq 0) 'DNS timeout/concurrency not bounded'
    ${function:Start-DomainLookup} = $originalLookup
    Write-Host 'PASS: DNS cache, timeout and concurrency'

    $up = [Net.NetworkInformation.OperationalStatus]::Up
    Assert-True (Test-AmneziaAdapter ([pscustomobject]@{Name='AmneziaVPN';Description='WireGuard Tunnel';OperationalStatus=$up})) 'Amnezia adapter missed'
    foreach ($name in @('Corporate WireGuard','Wintun Userspace Tunnel','TAP-Windows Adapter V9')) {
        Assert-True (-not (Test-AmneziaAdapter ([pscustomobject]@{Name=$name;Description=$name;OperationalStatus=$up}))) 'Other VPN mistaken for Amnezia'
    }
    $getTunnel = ${function:Get-TunnelService}
    $daemonHandshake = ${function:Test-DaemonHandshake}
    function Test-DaemonHandshake { return $true }
    $adapterUp = ${function:Test-VpnAdapterUp}
    function Get-TunnelService {
        $mockService = [pscustomobject]@{Status=[ServiceProcess.ServiceControllerStatus]::Running}
        $mockService | Add-Member -MemberType ScriptMethod -Name Refresh -Value { }
        return $mockService
    }
    function Test-VpnAdapterUp { return $false }
    Assert-True (-not (Test-TunnelReady)) 'Running service with no adapter reported a restored VPN'
    function Test-VpnAdapterUp { return $true }
    Assert-True (Test-TunnelReady) 'Running tunnel and adapter not ready'
    function Test-DaemonHandshake { return $false }
    Assert-True (-not (Test-TunnelReady)) 'Interface without handshake reported a ready VPN'
    ${function:Test-DaemonHandshake} = $daemonHandshake
    ${function:Get-TunnelService} = $getTunnel
    ${function:Test-VpnAdapterUp} = $adapterUp
    Write-Host 'PASS: adapter ownership'

    # The daemon deletes the temporary WireGuard service while SCM callers may
    # still hold a ServiceController. Only ERROR_SERVICE_DOES_NOT_EXIST is benign.
    $raceGetTunnel = ${function:Get-TunnelService}
    $raceService = [pscustomobject]@{ Status=[ServiceProcess.ServiceControllerStatus]::Stopped }
    $raceService | Add-Member ScriptMethod Refresh {
        throw [InvalidOperationException]::new('Service was deleted', [ComponentModel.Win32Exception]::new(1060))
    }
    $raceService | Add-Member ScriptMethod WaitForStatus {
        param($status, $timeout)
        throw [InvalidOperationException]::new('Service was deleted', [ComponentModel.Win32Exception]::new(1060))
    }
    function Get-TunnelService { return $raceService }
    Assert-True (-not (Test-TunnelServiceRunning)) 'Deleted tunnel service reported running'
    Assert-True (-not (Test-TunnelReady)) 'Deleted tunnel service reported ready'
    Assert-True (Stop-ServiceHard $raceService) 'Deleted service was not considered stopped'
    Assert-True (Wait-ServiceStatus $raceService ([ServiceProcess.ServiceControllerStatus]::Stopped) 1) 'Deletion during stop wait failed'
    Assert-True (-not (Wait-ServiceStatus $raceService ([ServiceProcess.ServiceControllerStatus]::Running) 1)) 'Deleted service was considered started'
    $raceService | Add-Member ScriptMethod Refresh {
        throw [InvalidOperationException]::new('Access denied', [ComponentModel.Win32Exception]::new(5))
    } -Force
    Assert-Throws { Test-TunnelServiceRunning } 'Service access denial was hidden'
    ${function:Get-TunnelService} = $raceGetTunnel
    Write-Host 'PASS: temporary tunnel service deletion race'

    $raceDisconnect = ${function:Request-AmneziaDisconnect}
    $raceRunning = ${function:Test-TunnelRunning}
    $script:disconnectRequests = 0
    $script:raceTunnelRunning = $true
    function Request-AmneziaDisconnect {
        $script:disconnectRequests++
        $script:raceTunnelRunning = $false
        return $true
    }
    function Test-TunnelRunning { return $script:raceTunnelRunning }
    function Get-TunnelService { throw 'SCM was used after the daemon already disconnected' }
    Stop-AmneziaTunnel
    Assert-True ($script:disconnectRequests -eq 1) 'Daemon cleanup was not requested'
    ${function:Get-TunnelService} = $raceGetTunnel
    ${function:Request-AmneziaDisconnect} = $raceDisconnect
    ${function:Test-TunnelRunning} = $raceRunning
    Write-Host 'PASS: disconnect cleans daemon state before stopping services'

    # All process/service functions below are mocks. Transactions still exercise
    # the real codec, temporary HKCU data, journal, and managed-entry files.
    $restoreSession = ${function:Restore-AmneziaSession}
    $getSession = ${function:Get-AmneziaSession}
    function Test-GuiRunning { return $false }
    function Test-TunnelRunning { return $false }
    function Test-Elevated { return $true }
    function Stop-AmneziaGui { $script:stops++ }
    function Stop-AmneziaTunnel { }
    function Start-AmneziaDaemon { }
    $script:stops = 0
    $serverKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($RegistryServersSubKey)
    try { $serverKey.SetValue('defaultServerIndex', 3); $serverKey.SetValue('defaultServerId', 'new-id') } finally { $serverKey.Dispose() }
    $session = Get-AmneziaSession
    Assert-True ($session.ServerIndex -eq -1) 'Stale legacy server index trusted'
    $ServerIndex = 2
    Assert-True ((Get-AmneziaSession).ServerIndex -eq 2) 'Explicit server index ignored'
    $ServerIndex = -1

    function Get-AmneziaSession { return [pscustomobject]@{GuiRunning=$true;Connected=$true;AutoConnect=$true;ServerIndex=-1} }
    $script:restoreFails = $true
    function Restore-AmneziaSession($Session, [string]$ExePath) {
        if ($script:restoreFails) { throw 'Simulated reconnect failure' }
    }
    Write-JsonAtomic $ManagedPath @('example.com','5.255.0.0/16')
    Assert-Throws { Invoke-RoutingTransaction @('example.com','5.255.0.0/16') 'mock.exe' @{'example.com'=@('1.1.1.1')} } 'Reconnect failure reported success'
    Assert-True ((Read-JsonFile $JournalPath).phase -ceq 'restoring') 'Reconnect failure lost committed journal'
    $script:restoreFails = $false
    Restore-PendingTransaction 'mock.exe'
    Assert-True (-not (Test-Path -LiteralPath $JournalPath)) 'Recovery left a completed journal'
    Assert-True ((Read-ExceptSites)['example.com'][0] -ceq '1.1.1.1') 'Recovery rolled back a committed update'
    $stopsBefore = $script:stops
    $unchanged = Invoke-RoutingTransaction @('example.com','5.255.0.0/16') 'mock.exe' @{'example.com'=@('1.1.1.1')}
    Assert-True (-not $unchanged.Changed -and $script:stops -eq $stopsBefore) 'Unchanged list restarted VPN'
    Write-Host 'PASS: reconnect failure, crash recovery, no-op update'

    # Enabled/unknown KillSwitch must stop the transaction BEFORE closing the
    # GUI, disconnecting, writing settings, or creating a recovery journal.
    $protectedSites = Read-ExceptSites
    $protectedManaged = (Get-Content -LiteralPath $ManagedPath -Raw)
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($RegistryConfSubKey, $true)
    try { $key.SetValue('killSwitchEnabled', 'true') } finally { $key.Dispose() }
    Assert-Throws { Invoke-RoutingTransaction @('new.example') 'mock.exe' } 'KillSwitch allowed an automatic reconnect'
    Assert-True ($script:stops -eq $stopsBefore) 'KillSwitch guard ran after stopping the GUI'
    Assert-True (Test-SitesEqual $protectedSites (Read-ExceptSites)) 'KillSwitch guard changed routes'
    Assert-True ((Get-Content -LiteralPath $ManagedPath -Raw) -ceq $protectedManaged) 'KillSwitch guard changed managed ownership'
    Assert-True (-not (Test-Path -LiteralPath $JournalPath)) 'KillSwitch guard created a transaction'
    $protectedNoOp = Invoke-RoutingTransaction @('example.com','5.255.0.0/16') 'mock.exe' @{'example.com'=@('1.1.1.1')}
    Assert-True (-not $protectedNoOp.Changed -and $script:stops -eq $stopsBefore) 'KillSwitch blocked or restarted a no-op update'

    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($RegistryConfSubKey, $true)
    try { $key.DeleteValue('killSwitchEnabled') } finally { $key.Dispose() }
    Assert-Throws { Assert-SafeAmneziaRestart (Get-AmneziaSession) } 'Missing KillSwitch setting permitted a disconnect'
    Assert-SafeAmneziaRestart ([pscustomobject]@{GuiRunning=$false;Connected=$false})
    $AllowVpnReconnect = $true
    Assert-SafeAmneziaRestart (Get-AmneziaSession)
    $AllowVpnReconnect = $false

    # A legacy writing journal cannot bypass the guard. A restoring journal
    # only brings the VPN back, so it must still recover with KillSwitch enabled.
    $protectedBackup = Join-Path $testRoot 'protected-routing-backup.json'
    Write-JsonAtomic $protectedBackup (Read-RoutingRegistrySnapshot)
    $protectedJournal = [ordered]@{
        version=1; phase='writing'; session=(ConvertTo-SessionDocument (Get-AmneziaSession))
        backup=$protectedBackup; previous_managed=@('example.com','5.255.0.0/16')
    }
    Write-JsonAtomic $JournalPath $protectedJournal
    Assert-Throws { Restore-PendingTransaction 'mock.exe' } 'Legacy rollback disconnected a protected VPN'
    Assert-True ($script:stops -eq $stopsBefore -and (Read-JsonFile $JournalPath).phase -eq 'writing') 'Blocked rollback changed the session or journal'
    $protectedJournal.phase = 'restoring'
    Write-JsonAtomic $JournalPath $protectedJournal
    Restore-PendingTransaction 'mock.exe'
    Assert-True (-not (Test-Path -LiteralPath $JournalPath)) 'KillSwitch prevented restoring connectivity'
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($RegistryConfSubKey, $true)
    try { $key.SetValue('killSwitchEnabled', 'false') } finally { $key.Dispose() }
    Write-Host 'PASS: KillSwitch blocks automatic disconnect, allows no-op and reconnect-only recovery'

    # Simulate a failed write, including a failed reconnect after rollback.
    $writeRegistry = ${function:Write-RoutingRegistry}
    function Write-RoutingRegistry($Sites) { throw 'Simulated write failure' }
    $script:restoreFails = $true
    Assert-Throws { Invoke-RoutingTransaction @('new.example') 'mock.exe' @{'new.example'=@('9.9.9.9')} } 'Write failure reported success'
    Assert-True ((Read-ExceptSites)['example.com'][0] -ceq '1.1.1.1') 'Failed write did not restore the previous list'
    Assert-True ((Read-JsonFile $JournalPath).phase -ceq 'restoring') 'Rollback lost reconnect journal'
    $script:restoreFails = $false
    Restore-PendingTransaction 'mock.exe'
    ${function:Write-RoutingRegistry} = $writeRegistry
    Write-Host 'PASS: write failure rolls back without losing recovery'

    function Get-AmneziaSession { return [pscustomobject]@{GuiRunning=$true;Connected=$true;AutoConnect=$false;ServerIndex=-1} }
    Assert-Throws { Invoke-RoutingTransaction @('new.example') 'mock.exe' } 'Unknown server index did not block restart'
    function Get-AmneziaSession { return [pscustomobject]@{GuiRunning=$true;Connected=$false;AutoConnect=$true;ServerIndex=-1} }
    Assert-Throws { Invoke-RoutingTransaction @('new.example') 'mock.exe' } 'Disconnected autoconnect session was restarted'
    Assert-True (-not (Test-Path -LiteralPath $JournalPath)) 'Preflight guard created a journal'

    ${function:Restore-AmneziaSession} = $restoreSession
    $script:started = $false
    $script:startArguments = @()
    function Test-GuiRunning { return $script:started }
    function Test-TunnelRunning { return $script:started }
    function Test-TunnelReady { return $script:started }
    # Прямой Start-Process из updater запустил бы AmneziaVPN с токеном задачи, то есть
    # с правами администратора: такое окно не открывается из трея (UIPI).
    function Start-Process { throw 'GUI must not inherit the updater token' }
    $startGui = ${function:Start-AmneziaGui}
    function Start-AmneziaGui([string]$ExePath, [string[]]$Arguments) {
        Assert-True ($ExePath -ceq 'mock.exe') 'Restore launched another executable'
        $script:started = $true
        $script:startArguments = @($Arguments)
    }
    Restore-AmneziaSession ([pscustomobject]@{GuiRunning=$false;Connected=$true;AutoConnect=$false;ServerIndex=2}) 'mock.exe'
    Assert-True ($script:started -and ($script:startArguments -join ' ') -ceq '--connect 2') 'Connected session with no GUI was not restored'
    Write-Host 'PASS: session preservation and server selection guards'

    Remove-Item function:Start-Process -ErrorAction SilentlyContinue
    ${function:Start-AmneziaGui} = $startGui
    # Test-Elevated is mocked above; ask the real token before registering a task.
    $realAdmin = ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($realAdmin) {
        # Настоящая регистрация разовой задачи: проверяем, что RunLevel Limited проходит
        # в обеих оболочках и временная задача убирается за собой.
        $launchTask = "Amnezia-Route-Sync-Launch-$PID"
        function Test-GuiRunning { return $true }
        Start-AmneziaGui "$env:SystemRoot\System32\cmd.exe" @('/c', 'exit')
        Assert-True (-not (Get-ScheduledTask -TaskName $launchTask -ErrorAction SilentlyContinue)) `
            'Temporary launch task was left registered'
        Write-Host 'PASS: unelevated GUI launch task'
    } else {
        Write-Host 'SKIP: unelevated GUI launch task (нужны права администратора)'
    }
    Write-Host 'Windows regression tests: OK'
} finally {
    if (-not $testRegistry.StartsWith('Software\AmneziaRouteSync-Tests\')) { throw 'Unsafe registry cleanup target' }
    [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($testRegistry, $false)
    $resolvedRoot = [IO.Path]::GetFullPath($testRoot)
    $tempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $resolvedRoot.StartsWith($tempParent, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $resolvedRoot) -notlike 'amnezia-sync-test-*') { throw 'Unsafe temporary cleanup target' }
    Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
}
