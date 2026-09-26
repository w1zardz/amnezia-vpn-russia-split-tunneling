# Isolated regression tests: temporary files and mocks; no VPN or registry access.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('amnezia-recovery-ipv6-test-' + [Guid]::NewGuid().ToString('N'))
$updater = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'update-amnezia-routes.ps1') -Raw -Encoding UTF8
$declarations = $updater.Substring(0, $updater.IndexOf('# --- self-test'))
. ([scriptblock]::Create($declarations)) -StateDir $testRoot

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

# Every external dependency of the transaction is mocked. Journal and backup
# writes remain real, so failures must leave a readable, recoverable journal.
function Read-ExceptSites { return @{} }
function Read-ManagedEntries { return @() }
function Get-DesiredSites($Current, $PreviousManaged, $Entries, $DomainAddresses) {
    $desired = @{}
    foreach ($entry in $Entries) { $desired[$entry] = @() }
    return $desired
}
function Read-RoutingScalars { return @{ mode = 2; enabled = 'true' } }
function Get-AmneziaSession {
    return [pscustomobject]@{ GuiRunning = $true; Connected = $true; AutoConnect = $true; ServerIndex = -1 }
}
function Assert-SafeAmneziaRestart { }
function Get-Process { return @() }
function Test-Elevated { return $true }
function Stop-AmneziaGui {
    $script:stopAttempts++
    if ($script:failStop) { throw [InvalidOperationException]::new('StopFailure') }
}
function Stop-AmneziaTunnel { }
function Read-RoutingRegistrySnapshot { return @{ version = 1; values = @{} } }
function Write-RoutingRegistry {
    if ($script:failRegistry) { throw [InvalidOperationException]::new('PrimaryWriteFailure') }
}
function Assert-RoutingRegistry { }
function Restore-RoutingRegistrySnapshot {
    $script:rollbackAttempts++
    if ($script:failRollback) { throw [InvalidOperationException]::new('SnapshotRestoreFailure') }
}
function Restore-AmneziaSession {
    $script:restoreAttempts++
    if ($script:failRestore) { throw [InvalidOperationException]::new('ReconnectFailure') }
}
function Remove-OldRoutingBackups { $script:backupCleanups++ }
$script:realWriteJsonAtomic = ${function:Write-JsonAtomic}
function Write-JsonAtomic([string]$Path, $Value) {
    if ($Path -ceq $ManagedPath -and $script:failManaged) {
        throw [IO.IOException]::new('ManagedWriteFailure')
    }
    if ($Path -ceq $JournalPath -and $Value.phase -eq 'restoring' -and $script:failJournal) {
        throw [IO.IOException]::new('RestoringJournalFailure')
    }
    & $script:realWriteJsonAtomic $Path $Value
}

function Reset-TransactionCase([string]$Name) {
    $script:JournalPath = Join-Path $testRoot ($Name + '-journal.json')
    $script:ManagedPath = Join-Path $testRoot ($Name + '-managed.json')
    $script:failRegistry = $false
    $script:failRestore = $false
    $script:failJournal = $false
    $script:failManaged = $false
    $script:failRollback = $false
    $script:failStop = $false
    $script:stopAttempts = 0
    $script:restoreAttempts = 0
    $script:rollbackAttempts = 0
    $script:backupCleanups = 0
}

function Initialize-RecoveryCase([string]$Name) {
    Reset-TransactionCase $Name
    $backup = Join-Path $testRoot ($Name + '-backup.json')
    & $script:realWriteJsonAtomic $backup (Read-RoutingRegistrySnapshot)
    & $script:realWriteJsonAtomic $JournalPath ([ordered]@{
        version = 1; phase = 'writing'; session = (ConvertTo-SessionDocument (Get-AmneziaSession))
        backup = $backup; previous_managed = @('1.1.1.1/32')
    })
}

function Assert-RecoveryFailure([string]$Message, [string]$JournalPhase) {
    $failure = $null
    try { Restore-PendingTransaction 'mock.exe' 3>$null } catch { $failure = $_ }
    Assert-True ($null -ne $failure) 'Recovery unexpectedly succeeded'
    Assert-True ($failure.Exception.Message -ceq $Message) "Original recovery error was replaced: $($failure.Exception.Message)"
    Assert-True ($script:restoreAttempts -eq 1) 'Recovery skipped or repeated VPN restoration'
    Assert-True ((Read-JsonFile $JournalPath).phase -ceq $JournalPhase) 'Incomplete recovery lost its journal'
}

function Assert-TransactionFailure([string]$Message, [string]$JournalPhase) {
    $failure = $null
    try { $null = Invoke-RoutingTransaction @('8.8.8.8/32') 'mock.exe' 3>$null }
    catch { $failure = $_ }
    Assert-True ($null -ne $failure) 'Transaction unexpectedly succeeded'
    Assert-True ($failure.Exception.Message -ceq $Message) "Original error was replaced: $($failure.Exception.Message)"
    Assert-True ($script:restoreAttempts -eq 1) 'VPN restoration was skipped or repeated'
    if ($JournalPhase) {
        Assert-True ((Read-JsonFile $JournalPath).phase -ceq $JournalPhase) 'Recovery journal was deleted or its phase changed'
        Assert-True ($script:backupCleanups -eq 0) 'Backups were cleaned after incomplete finalization'
    } else {
        Assert-True (-not (Test-Path -LiteralPath $JournalPath)) 'Completed rollback left a journal'
    }
}

# Network discovery and the TCP probe are also mocked, including error paths.
function Get-NetAdapter {
    if ($script:failAdapters) { throw 'AdapterDiscoveryFailure' }
    return $script:adapters
}
function Get-NetIPAddress {
    $script:addressQueries++
    return $script:addresses
}
function Find-NetRoute {
    $script:routeQueries++
    if ($script:failRoute) { throw 'RouteDiscoveryFailure' }
    return $script:probeRoutes
}
function Test-IPv6Reachable {
    $script:probeCalls++
    return $script:probeReachable
}

function Reset-IPv6Case {
    $script:failAdapters = $false
    $script:failRoute = $false
    $script:addressQueries = 0
    $script:routeQueries = 0
    $script:probeCalls = 0
    $script:probeReachable = $false
    $script:adapters = @(
        [pscustomobject]@{ Name = 'AmneziaVPN'; InterfaceDescription = 'WireGuard Tunnel'; Status = 'Up' }
        [pscustomobject]@{ Name = 'Corporate VPN'; InterfaceDescription = 'Wintun Userspace Tunnel'; Status = 'Up' }
        [pscustomobject]@{ Name = 'Amnezia old'; InterfaceDescription = 'WireGuard Tunnel'; Status = 'Disconnected' }
    )
    $script:addresses = @(
        [pscustomobject]@{ InterfaceAlias = 'Ethernet'; IPAddress = '2001:db8::1' }
        [pscustomobject]@{ InterfaceAlias = 'AmneziaVPN'; IPAddress = '2001:db8:1::1' }
    )
    $script:probeRoutes = @(
        [pscustomobject]@{ InterfaceAlias = 'AmneziaVPN'; IPAddress = '2001:db8:1::1' }
        [pscustomobject]@{ InterfaceAlias = 'AmneziaVPN'; NextHop = '::'; DestinationPrefix = '::/0' }
    )
}

function Get-IPv6Warnings {
    return @(Write-IPv6TunnelWarning 3>&1 6>$null | Where-Object { $_ -is [Management.Automation.WarningRecord] })
}

try {
    Reset-TransactionCase 'journal'
    $script:failJournal = $true
    Assert-TransactionFailure 'RestoringJournalFailure' 'writing'
    Assert-True (Test-Path -LiteralPath $ManagedPath) 'Committed ownership state disappeared'

    Reset-TransactionCase 'journal-and-reconnect'
    $script:failJournal = $true
    $script:failRestore = $true
    Assert-TransactionFailure 'RestoringJournalFailure' 'writing'

    Reset-TransactionCase 'primary-journal-and-reconnect'
    $script:failRegistry = $true
    $script:failJournal = $true
    $script:failRestore = $true
    Assert-TransactionFailure 'PrimaryWriteFailure' 'writing'
    Assert-True ($script:rollbackAttempts -eq 1) 'Failed registry write did not roll back'

    Reset-TransactionCase 'rolled-back'
    $script:failRegistry = $true
    Assert-TransactionFailure 'PrimaryWriteFailure' ''

    Reset-TransactionCase 'reconnect'
    $script:failRestore = $true
    Assert-TransactionFailure 'ReconnectFailure' 'restoring'

    Reset-TransactionCase 'successful'
    $result = Invoke-RoutingTransaction @('8.8.8.8/32') 'mock.exe'
    Assert-True ($result.Changed -and $script:restoreAttempts -eq 1) 'Successful transaction did not restore VPN'
    Assert-True (-not (Test-Path -LiteralPath $JournalPath)) 'Successful transaction left a journal'
    Assert-True ($script:backupCleanups -eq 1) 'Successful transaction did not clean old backups'
    Write-Host 'PASS: journal write failure, original errors, mandatory reconnect, retained recovery state'

    Initialize-RecoveryCase 'recovery-journal'
    $script:failJournal = $true
    Assert-RecoveryFailure 'RestoringJournalFailure' 'writing'
    Assert-True ($script:rollbackAttempts -eq 1) 'Recovery did not restore the registry before its journal failed'

    Initialize-RecoveryCase 'recovery-managed-and-reconnect'
    $script:failManaged = $true
    $script:failRestore = $true
    Assert-RecoveryFailure 'ManagedWriteFailure' 'writing'

    Initialize-RecoveryCase 'recovery-registry-and-reconnect'
    $script:failRollback = $true
    $script:failRestore = $true
    Assert-RecoveryFailure 'SnapshotRestoreFailure' 'writing'

    Initialize-RecoveryCase 'recovery-stop'
    $script:failStop = $true
    Assert-RecoveryFailure 'StopFailure' 'writing'
    Assert-True ($script:rollbackAttempts -eq 0) 'Recovery wrote registry after a failed stop'

    Initialize-RecoveryCase 'recovery-reconnect'
    $script:failRestore = $true
    Assert-RecoveryFailure 'ReconnectFailure' 'restoring'

    Initialize-RecoveryCase 'recovery-success'
    Restore-PendingTransaction 'mock.exe'
    Assert-True ($script:restoreAttempts -eq 1 -and $script:rollbackAttempts -eq 1) 'Successful recovery did not restore registry and VPN'
    Assert-True (-not (Test-Path -LiteralPath $JournalPath)) 'Successful recovery left its journal'
    $recoveredManaged = Read-JsonFile $ManagedPath
    Assert-True ((@($recoveredManaged) -join ',') -ceq '1.1.1.1/32') 'Recovery lost previous ownership'
    Write-Host 'PASS: interrupted transaction recovery restores VPN despite stop, registry, managed-state and journal failures'

    Reset-IPv6Case
    $aliases = Get-TunnelAliases
    Assert-True ($aliases.Count -eq 1 -and $aliases.Contains('amneziavpn')) 'Tunnel aliases lost collection type or case-insensitive lookup'
    Assert-True (-not $aliases.Contains('Corporate VPN') -and -not $aliases.Contains('Amnezia old')) 'Unrelated or stopped adapter mistaken for active Amnezia'
    $script:adapters += [pscustomobject]@{ Name = 'Renamed tunnel'; InterfaceDescription = 'Amnezia VPN'; Status = 'Up' }
    Assert-True ((Get-TunnelAliases).Contains('Renamed tunnel')) 'Amnezia interface description was ignored'
    $warnings = @(Get-IPv6Warnings)
    Assert-True ($warnings.Count -eq 1 -and $script:probeCalls -eq 1 -and $script:routeQueries -eq 1) 'Failed tunnel IPv6 probe did not produce a warning'
    Assert-True ($warnings[0].Message.Contains($IPv6ProbeAddress)) 'IPv6 warning omitted the address actually tested'

    Reset-IPv6Case
    $script:probeReachable = $true
    Assert-True (@(Get-IPv6Warnings).Count -eq 0 -and $script:probeCalls -eq 1) 'Working IPv6 produced a warning'

    Reset-IPv6Case
    $script:probeRoutes = @([pscustomobject]@{ InterfaceAlias = 'Ethernet'; NextHop = 'fe80::1'; DestinationPrefix = '2000::/3' })
    Assert-True (@(Get-IPv6Warnings).Count -eq 0 -and $script:probeCalls -eq 0) 'A direct probe route was attributed to VPN'

    Reset-IPv6Case
    $script:addresses = @([pscustomobject]@{ InterfaceAlias = 'Ethernet'; IPAddress = 'fe80::1' })
    Assert-True (@(Get-IPv6Warnings).Count -eq 0 -and $script:routeQueries -eq 0) 'Native link-local address triggered IPv6 diagnosis'

    Reset-IPv6Case
    $script:adapters = @([pscustomobject]@{ Name = 'Corporate VPN'; InterfaceDescription = 'WireGuard Tunnel'; Status = 'Up' })
    Assert-True ((Get-TunnelAliases).Count -eq 0) 'Empty alias set was unwrapped'
    Assert-True (@(Get-IPv6Warnings).Count -eq 0 -and $script:addressQueries -eq 0) 'Unrelated VPN triggered IPv6 diagnosis'

    Reset-IPv6Case
    $script:failAdapters = $true
    $warnings = @(Get-IPv6Warnings)
    Assert-True ($warnings.Count -eq 1 -and $warnings[0].Message.Contains('AdapterDiscoveryFailure') -and $script:probeCalls -eq 0) 'Adapter discovery failure was silent'

    Reset-IPv6Case
    $script:failRoute = $true
    $warnings = @(Get-IPv6Warnings)
    Assert-True ($warnings.Count -eq 1 -and $warnings[0].Message.Contains('RouteDiscoveryFailure') -and $script:probeCalls -eq 0) 'Route discovery failure was silent'
    Write-Host 'PASS: IPv6 interface ownership, selected route, probe result, unavailable diagnostics'
    Write-Host 'Recovery and IPv6 regression tests: OK'
} finally {
    $resolvedRoot = [IO.Path]::GetFullPath($testRoot)
    $tempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $resolvedRoot.StartsWith($tempParent, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $resolvedRoot) -notlike 'amnezia-recovery-ipv6-test-*') { throw 'Unsafe temporary cleanup target' }
    if (Test-Path -LiteralPath $resolvedRoot) { Remove-Item -LiteralPath $resolvedRoot -Recurse -Force }
}
