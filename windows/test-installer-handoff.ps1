# Integration harness: real installer/updater entrypoints, isolated files and
# mocked OS/network boundaries. Requires neither elevation nor a running VPN.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('amnezia-handoff-test-' + [Guid]::NewGuid().ToString('N'))
$originalLocalAppData = $env:LOCALAPPDATA
$originalTemp = $env:TEMP
$enginePath = (Get-Process -Id $PID).Path
$utf8Bom = New-Object Text.UTF8Encoding($true)
$installerText = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'install.ps1') -Raw -Encoding UTF8
$updaterText = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'update-amnezia-routes.ps1') -Raw -Encoding UTF8

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Quote-Literal([string]$Value) { return "'" + $Value.Replace("'", "''") + "'" }

# The installer still constructs and registers the real action/trigger arguments;
# these functions store them in memory instead of touching Task Scheduler.
function New-Object {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$TypeName, [Parameter(Position = 1)][object[]]$ArgumentList)
    if ($TypeName -eq 'Security.Principal.WindowsPrincipal') {
        $mockPrincipal = [pscustomobject]@{}
        $mockPrincipal | Add-Member ScriptMethod IsInRole { param($role) return $true }
        return $mockPrincipal
    }
    return Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
}
function Get-ScheduledTask {
    [CmdletBinding()] param([string]$TaskName)
    if ($null -ne $global:AmneziaHandoffMockTask) { return $global:AmneziaHandoffMockTask }
}
function New-ScheduledTaskAction {
    param([string]$Execute, [string]$Argument, [string]$WorkingDirectory)
    return [pscustomobject]@{ Execute = $Execute; Arguments = $Argument; WorkingDirectory = $WorkingDirectory }
}
function New-ScheduledTaskTrigger {
    param([switch]$AtLogOn, [string]$User, [switch]$Once, [DateTime]$At,
        [TimeSpan]$RepetitionInterval, [TimeSpan]$RepetitionDuration)
    return [pscustomobject]@{ Delay = ''; Interval = $RepetitionInterval }
}
function New-ScheduledTaskPrincipal { return [pscustomobject]@{ Mock = $true } }
function New-ScheduledTaskSettingsSet { return [pscustomobject]@{ Mock = $true } }
function New-ScheduledTask {
    param($Action, $Trigger, $Principal, $Settings, [string]$Description)
    return [pscustomobject]@{ State = 'Ready'; Actions = @($Action); Triggers = @($Trigger) }
}
function Register-ScheduledTask {
    [CmdletBinding()] param([string]$TaskName, $InputObject, [switch]$Force, [string]$Xml)
    if ($Xml) { throw 'Unexpected restoration of an existing real task' }
    $global:AmneziaHandoffMockTask = $InputObject
    return $InputObject
}
function Unregister-ScheduledTask {
    [CmdletBinding()] param([string]$TaskName, [switch]$Confirm)
    $global:AmneziaHandoffMockTask = $null
}
function Stop-ScheduledTask { throw 'Unexpected attempt to stop a task' }
function Export-ScheduledTask { throw 'Unexpected attempt to export a task' }

# A separate native child is used for each updater invocation. Exit statements,
# parameter binding, defaults, prepared-file persistence and entrypoint branches
# therefore run exactly as they do during installation.
$updaterHooks = @'
function Write-HandoffEvent([string]$Kind, $Data = @{}) {
    [ordered]@{ kind = $Kind; mode = $(if ($DryRun) { 'dry-run' } elseif ($RecoverOnly) { 'recovery' } elseif ($SelfTest) { 'self-test' } else { 'apply' }); data = $Data } |
        ConvertTo-Json -Depth 8 -Compress | Add-Content -LiteralPath (Join-Path $handoffRoot 'events.jsonl') -Encoding UTF8
}
function New-Object {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$TypeName, [Parameter(Position = 1)][object[]]$ArgumentList)
    if ($TypeName -eq 'Threading.Mutex') {
        $mockMutex = [pscustomobject]@{}
        $mockMutex | Add-Member ScriptMethod WaitOne { param($timeout) return $true }
        $mockMutex | Add-Member ScriptMethod ReleaseMutex { }
        $mockMutex | Add-Member ScriptMethod Dispose { }
        return $mockMutex
    }
    return Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
}
function Get-SourceText([string]$SourceValue) {
    Write-HandoffEvent 'source' @{ source = $SourceValue }
    # Match the production boundary's plain .NET string. Get-Content strings
    # carry provider metadata that PS5.1 recursively serializes into JSON.
    return [IO.File]::ReadAllText((Join-Path $handoffRoot 'fixture.json'), [Text.Encoding]::UTF8)
}
function Resolve-ManagedDomains([string[]]$Domains, [int]$TimeoutSeconds = 45, [int]$Concurrency = 24) {
    Write-HandoffEvent 'dns' @{ count = $Domains.Count; cache_hours = $DnsCacheHours }
    $addresses = @{}
    foreach ($domain in $Domains) { $addresses[$domain] = @('8.8.8.8') }
    return [pscustomobject]@{
        Addresses = $addresses; PreviousAddresses = @{}; Cached = $false
        Cache = [ordered]@{ version = 1; updated_at = [DateTime]::UtcNow.ToString('o'); domains = @($Domains); addresses = $addresses }
    }
}
function Get-AmneziaExePath { return 'mock-amnezia.exe' }
function Assert-AmneziaVersion { return '5.0.1.5' }
function Write-IPv6TunnelWarning { }
function Restore-PendingTransaction { Write-HandoffEvent 'recovery' }
function Read-ExceptSites {
    $lateManual = Test-Path -LiteralPath (Join-Path $handoffRoot 'late-registry-change')
    Write-HandoffEvent 'registry-read' @{ late_manual = $lateManual }
    if ($lateManual) { return @{ 'late-manual.example' = @('9.9.9.9') } }
    return @{}
}
function Invoke-RoutingTransaction([string[]]$Entries, [string]$ExePath, $DomainAddresses = @{}) {
    $desired = Get-DesiredSites (Read-ExceptSites) @(Read-ManagedEntries) $Entries $DomainAddresses
    Write-HandoffEvent 'transaction' @{ count = $Entries.Count; dns_present = ($Entries -contains '8.8.8.8/32'); late_manual = $desired.ContainsKey('late-manual.example') }
    return [pscustomobject]@{ Changed = $true; ManualCount = ($desired.Count - $Entries.Count) }
}
function Write-RoutingRegistry { throw 'Harness forbids registry writes' }
function Restore-RoutingRegistrySnapshot { throw 'Harness forbids registry writes' }
function Stop-AmneziaGui { throw 'Harness forbids VPN process control' }
function Stop-AmneziaTunnel { throw 'Harness forbids VPN service control' }
function Restore-AmneziaSession { throw 'Harness forbids VPN process control' }
'@

$launcherBody = @'
$launchArguments = @($args)
$mode = if ($launchArguments -contains '-SelfTest') { 'self-test' }
        elseif ($launchArguments -contains '-RecoverOnly') { 'recovery' }
        elseif ($launchArguments -contains '-DryRun') { 'dry-run' }
        else { 'apply' }
$preparedIndex = [Array]::IndexOf([object[]]$launchArguments, '-PreparedPlanPath')
$preparedPath = if ($preparedIndex -ge 0) { [string]$launchArguments[$preparedIndex + 1] } else { '' }
[ordered]@{ kind = 'launch'; mode = $mode; data = @{ arguments = $launchArguments; prepared_path = $preparedPath } } |
    ConvertTo-Json -Depth 8 -Compress | Add-Content -LiteralPath (Join-Path $handoffRoot 'events.jsonl') -Encoding UTF8
if ($mode -eq 'apply') {
    if (-not $preparedPath -or -not (Test-Path -LiteralPath $preparedPath)) { throw 'Initial application has no preflight handoff' }
    Copy-Item -LiteralPath $preparedPath -Destination (Join-Path $handoffRoot 'prepared-before-apply.json') -Force
    [IO.File]::WriteAllText((Join-Path $handoffRoot 'late-registry-change'), 'manual entry added after preflight')
    if ($tamperMode) {
        $saved = Get-Content -LiteralPath $preparedPath -Raw -Encoding UTF8 | ConvertFrom-Json
        switch ($tamperMode) {
            'dns' { $saved.dns.addresses.'domain0.example' = @('10.0.0.1') }
            'expired' { $saved.created_at = [DateTime]::UtcNow.AddMinutes(-16).ToString('o') }
            'parameters' { $saved.lite = -not $saved.lite }
            'youtube' { $saved.youtube_ingest_direct = -not $saved.youtube_ingest_direct }
            'source' { $saved.text = '[{"hostname":"10.0.0.0/12","ip":""}]' }
            default { throw 'Unknown corruption scenario' }
        }
        [IO.File]::WriteAllText($preparedPath, ($saved | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    }
}
# Native stderr must be captured even for intentional validation failures.
$ErrorActionPreference = 'Continue'
& $handoffEngine @launchArguments > (Join-Path $handoffRoot ($mode + '.log')) 2>&1
$childExit = $LASTEXITCODE
[ordered]@{ kind = 'exit'; mode = $mode; data = @{ code = $childExit } } |
    ConvertTo-Json -Depth 8 -Compress | Add-Content -LiteralPath (Join-Path $handoffRoot 'events.jsonl') -Encoding UTF8
exit $childExit
'@

function Invoke-HandoffCase([string]$Name, [int]$CacheHours, [string]$Tamper = '', [string]$ExpectedError = '', [bool]$YouTube = $false) {
    $caseRoot = Join-Path $testRoot $Name
    $sourceDir = Join-Path $caseRoot 'source'
    $tempDir = Join-Path $caseRoot 'temp'
    [IO.Directory]::CreateDirectory($sourceDir) | Out-Null
    [IO.Directory]::CreateDirectory($tempDir) | Out-Null
    $env:LOCALAPPDATA = Join-Path $caseRoot 'local-app-data'
    $env:TEMP = $tempDir
    $global:AmneziaHandoffMockTask = $null

    $fixture = @(0..299 | ForEach-Object { @{ hostname = "domain$_.example"; ip = '' } })
    $fixture += @(0..39 | ForEach-Object { @{ hostname = "5.255.$($_ * 2).0/24"; ip = '' } })
    [IO.File]::WriteAllText((Join-Path $caseRoot 'fixture.json'), ($fixture | ConvertTo-Json -Depth 4), $utf8Bom)
    $hooksPath = Join-Path $caseRoot 'updater-hooks.ps1'
    [IO.File]::WriteAllText($hooksPath, ('$handoffRoot = ' + (Quote-Literal $caseRoot) + "`r`n" + $updaterHooks), $utf8Bom)
    $marker = '# --- self-test'
    $markerIndex = $updaterText.IndexOf($marker, [StringComparison]::Ordinal)
    Assert-True ($markerIndex -gt 0 -and $markerIndex -eq $updaterText.LastIndexOf($marker, [StringComparison]::Ordinal)) 'Updater injection boundary is ambiguous'
    $instrumentedUpdater = $updaterText.Insert($markerIndex, ('. ' + (Quote-Literal $hooksPath) + "`r`n"))
    [IO.File]::WriteAllText((Join-Path $sourceDir 'update-amnezia-routes.ps1'), $instrumentedUpdater, $utf8Bom)

    $launcherPath = Join-Path $caseRoot 'test-launcher.ps1'
    $launcherPrefix = '$handoffRoot = ' + (Quote-Literal $caseRoot) + "`r`n" +
        '$handoffEngine = ' + (Quote-Literal $enginePath) + "`r`n" + '$tamperMode = ' + (Quote-Literal $Tamper) + "`r`n"
    [IO.File]::WriteAllText($launcherPath, ($launcherPrefix + $launcherBody), $utf8Bom)

    # Change one executable assignment by its parsed extent, not string matching.
    # The installer body, invocations, argument lists and transaction are unchanged.
    $parseTokens = $null
    $parseErrors = $null
    $installerAst = [Management.Automation.Language.Parser]::ParseInput($installerText, [ref]$parseTokens, [ref]$parseErrors)
    Assert-True ($parseErrors.Count -eq 0) 'Installer does not parse'
    $assignments = @($installerAst.FindAll({ param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
        $node.Left.VariablePath.UserPath -ceq 'PowerShellExe'
    }, $true))
    Assert-True ($assignments.Count -eq 1) 'Installer subprocess boundary is ambiguous'
    $extent = $assignments[0].Extent
    $instrumentedInstaller = $installerText.Remove($extent.StartOffset, $extent.EndOffset - $extent.StartOffset).
        Insert($extent.StartOffset, ('$PowerShellExe = ' + (Quote-Literal $launcherPath)))
    $installerPath = Join-Path $sourceDir 'install.ps1'
    [IO.File]::WriteAllText($installerPath, $instrumentedInstaller, $utf8Bom)

    $failure = $null
    try {
        & $installerPath -Source 'https://fixture.invalid/routes.json' -Lite -NoLocalSubnets -AllowVpnReconnect -DnsCacheHours $CacheHours -YouTubeIngestDirect:$YouTube 6>$null
    } catch { $failure = $_ }
    $events = @(Get-Content -LiteralPath (Join-Path $caseRoot 'events.jsonl') -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json })
    $launches = @($events | Where-Object { $_.kind -eq 'launch' })
    if (($launches.mode -join ',') -cne 'self-test,recovery,dry-run,apply') {
        $logs = @(Get-ChildItem -LiteralPath $caseRoot -Filter '*.log' | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
        throw "$Name did not run all actual installer phases: $failure`n$logs"
    }
    Assert-True (@($events | Where-Object { $_.kind -eq 'source' }).Count -eq 1) "$Name fetched the source more than once"
    Assert-True (@($events | Where-Object { $_.kind -eq 'dns' }).Count -eq 1) "$Name repeated DNS instead of consuming preflight"
    $dryLaunch = @($launches | Where-Object { $_.mode -eq 'dry-run' })[0]
    $applyLaunch = @($launches | Where-Object { $_.mode -eq 'apply' })[0]
    Assert-True ($dryLaunch.data.prepared_path -and $dryLaunch.data.prepared_path -ceq $applyLaunch.data.prepared_path) "$Name used different handoff paths"
    $saved = Get-Content -LiteralPath (Join-Path $caseRoot 'prepared-before-apply.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ($saved.dns_cache_hours -eq $CacheHours -and $saved.lite -and $saved.no_local_subnets) "$Name preflight lost installer parameters"
    Assert-True ($saved.youtube_ingest_direct -eq $YouTube) "$Name preflight lost the YouTube profile"
    Assert-True (($saved.dns.addresses.PSObject.Properties.Name -contains 'a.rtmps.youtube.com') -eq $YouTube) "$Name preflight lost YouTube DNS"
    Assert-True ($null -ne $global:AmneziaHandoffMockTask) "$Name did not register the mocked task"
    $taskArguments = [string]$global:AmneziaHandoffMockTask.Actions[0].Arguments
    Assert-True ($taskArguments -match ('(?:^|\s)-DnsCacheHours ' + $CacheHours + '(?:\s|$)')) "$Name task lost the cache policy"
    Assert-True ($taskArguments -notmatch '-PreparedPlanPath|-AllowVpnReconnect' -and -not $taskArguments.Contains([string]$applyLaunch.data.prepared_path)) "$Name persisted a one-time argument in the task"
    Assert-True ($taskArguments -match '-Lite' -and $taskArguments -match '-NoLocalSubnets') "$Name task lost list policy"
    Assert-True (($taskArguments -match '-YouTubeIngestDirect') -eq $YouTube) "$Name task lost the YouTube profile"
    Assert-True (-not (Test-Path -LiteralPath $applyLaunch.data.prepared_path)) "$Name installer did not remove its temporary handoff"
    $transactions = @($events | Where-Object { $_.kind -eq 'transaction' })
    if ($Tamper) {
        Assert-True ($null -ne $failure) "$Name accepted a tampered handoff"
        Assert-True ($transactions.Count -eq 0) "$Name reached a routing write with invalid inputs"
        $applyLog = Get-Content -LiteralPath (Join-Path $caseRoot 'apply.log') -Raw
        Assert-True ($applyLog.Contains($ExpectedError)) "$Name failed for an unexpected reason: $applyLog"
    } else {
        if ($null -ne $failure) { throw $failure }
        Assert-True ($transactions.Count -eq 1 -and $transactions[0].data.dns_present -and $transactions[0].data.late_manual) "$Name lost DNS or manual edits made after preflight"
        Assert-True (@($events | Where-Object { $_.kind -eq 'registry-read' -and $_.mode -eq 'dry-run' -and -not $_.data.late_manual }).Count -gt 0) "$Name did not read original registry state during preflight"
        Assert-True (@($events | Where-Object { $_.kind -eq 'registry-read' -and $_.mode -eq 'apply' -and $_.data.late_manual }).Count -gt 0) "$Name reused preflight registry state"
        $status = Get-Content -LiteralPath (Join-Path $env:LOCALAPPDATA 'AmneziaRouteSync\status.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        Assert-True ($status.dns_cache_hours -eq $CacheHours) "$Name status lost cache policy"
        Assert-True ($status.youtube_ingest_direct -eq $YouTube) "$Name status lost the YouTube profile"
    }
    Write-Host "PASS: $Name; one source fetch, one DNS pass, validated handoff, isolated scheduled arguments"
}

try {
    Invoke-HandoffCase 'fresh-install' 6
    Invoke-HandoffCase 'cache-disabled' 0
    Invoke-HandoffCase 'youtube-ingest' 6 '' '' $true
    Invoke-HandoffCase 'reject-youtube-mismatch' 6 'youtube' 'не соответствует параметрам' $true
    Invoke-HandoffCase 'reject-private-dns' 6 'dns' 'непубличный IPv4'
    Invoke-HandoffCase 'reject-expired-plan' 6 'expired' 'устарел'
    Invoke-HandoffCase 'reject-parameter-mismatch' 6 'parameters' 'не соответствует параметрам'
    Invoke-HandoffCase 'reject-invalid-source' 6 'source' 'не является публичной'
    Write-Host 'Installer handoff integration tests: OK'
} finally {
    $env:LOCALAPPDATA = $originalLocalAppData
    $env:TEMP = $originalTemp
    Remove-Variable -Name AmneziaHandoffMockTask -Scope Global -ErrorAction SilentlyContinue
    $resolvedRoot = [IO.Path]::GetFullPath($testRoot)
    $tempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $resolvedRoot.StartsWith($tempParent, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $resolvedRoot) -notlike 'amnezia-handoff-test-*') { throw 'Unsafe temporary cleanup target' }
    if (Test-Path -LiteralPath $resolvedRoot) { Remove-Item -LiteralPath $resolvedRoot -Recurse -Force }
}
