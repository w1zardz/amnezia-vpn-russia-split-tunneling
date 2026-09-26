# Isolated ownership and installer handoff regressions; no real VPN changes.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('amnezia-plan-test-' + [Guid]::NewGuid().ToString('N'))
$updater = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'update-amnezia-routes.ps1') -Raw -Encoding UTF8
. ([scriptblock]::Create($updater.Substring(0, $updater.IndexOf('# --- self-test')))) -StateDir $testRoot

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Assert-Throws([scriptblock]$Action, [string]$Message) {
    $thrown = $false
    try { & $Action | Out-Null } catch { $thrown = $true }
    Assert-True $thrown $Message
}

try {
    # Transactions run against an in-memory registry, but the actual ownership
    # file is saved/reloaded across successive runs, including the no-op path.
    $script:sites = @{'5.255.0.0/16'=@(); 'manual.example'=@('9.9.9.9')}
    function Read-ExceptSites { return $script:sites.Clone() }
    function Read-RoutingScalars { return @{ mode=2; enabled='true' } }
    function Read-RoutingRegistrySnapshot { return @{ sites=$script:sites.Clone() } }
    function Write-RoutingRegistry($Sites) { $script:sites = $Sites.Clone() }
    function Assert-RoutingRegistry($Sites) { Assert-True (Test-SitesEqual $Sites $script:sites) 'Registry readback mismatch' }
    function Get-AmneziaSession { return [pscustomobject]@{GuiRunning=$false;Connected=$false;AutoConnect=$false;ServerIndex=-1} }
    function Get-Process { return @() }
    function Test-GuiRunning { return $false }
    function Test-TunnelRunning { return $false }
    function Stop-AmneziaGui { throw 'Test must not stop any GUI' }
    function Stop-AmneziaTunnel { throw 'Test must not stop any tunnel' }
    function Restore-AmneziaSession { throw 'Test must not start any VPN' }
    $NoRestart = $true

    $first = Invoke-RoutingTransaction @('5.255.0.0/16') 'unused.exe'
    Assert-True (-not $first.Changed -and $first.ManualCount -eq 2) 'Manual overlap was not a no-op'
    Assert-True (@(Read-ManagedEntries).Count -eq 0) 'Manual overlap was adopted on a no-op'
    Assert-True (((Get-Content -LiteralPath $ManagedPath -Raw) -replace '\s','') -ceq '[]') 'Empty ownership must serialize as an array'
    $second = Invoke-RoutingTransaction @('8.8.8.8/32') 'unused.exe'
    Assert-True ($second.Changed -and $second.ManualCount -eq 2) 'Changed import lost manual accounting'
    Assert-True ($script:sites.ContainsKey('5.255.0.0/16')) 'A former catalog overlap deleted the manual CIDR'
    Assert-True ((@(Read-ManagedEntries) -join ',') -ceq '8.8.8.8/32') 'Only the newly added CIDR should be owned'
    $third = Invoke-RoutingTransaction @('manual.example','1.1.1.1/32') 'unused.exe' @{'manual.example'=@('8.8.4.4')}
    Assert-True ($script:sites['manual.example'][0] -ceq '9.9.9.9') 'Catalog overwrote manual domain addresses'
    Assert-True (-not $script:sites.ContainsKey('8.8.8.8/32')) 'Removed managed CIDR was retained'
    Assert-True ((@(Read-ManagedEntries) -join ',') -ceq '1.1.1.1/32') 'Manual domain was adopted on a changed import'
    $null = Invoke-RoutingTransaction @('1.1.1.1/32') 'unused.exe'
    Assert-True ($script:sites.ContainsKey('manual.example')) 'A former catalog overlap deleted the manual domain'
    $ReplaceAll = $true
    $replacement = Invoke-RoutingTransaction @('5.255.0.0/16') 'unused.exe'
    Assert-True ($replacement.ManualCount -eq 0 -and $script:sites.Count -eq 1) 'ReplaceAll did not explicitly replace manual entries'
    $ReplaceAll = $false
    $null = Invoke-RoutingTransaction @('8.8.8.8/32') 'unused.exe'
    Assert-True (-not $script:sites.ContainsKey('5.255.0.0/16')) 'Explicitly adopted CIDR was not removed'
    Write-Host 'PASS: successive imports preserve manual CIDRs/domains, track ownership, and honor ReplaceAll'

    # Use a valid input of realistic minimum size, with deterministic async DNS.
    $fixture = @(0..299 | ForEach-Object { @{hostname="5.255.$([int]($_ / 256)).$($_ % 256)/32";ip=''} })
    $fixture += @{hostname='one.example';ip='1.1.1.1'}, @{hostname='two.example';ip='9.9.9.9'}
    $script:fixtureText = ConvertTo-Json -InputObject $fixture -Depth 5
    $MinimumRoutes = 1
    $script:downloads = 0
    $script:lookups = 0
    function Get-SourceText([string]$SourceValue) { $script:downloads++; return $script:fixtureText }
    function Start-DomainLookup([string]$Hostname) {
        $script:lookups++
        $completion = New-Object 'System.Threading.Tasks.TaskCompletionSource[System.Net.IPAddress[]]'
        $completion.SetResult([Net.IPAddress[]]@([Net.IPAddress]::Parse('8.8.8.8')))
        return ,$completion.Task
    }
    $path = Join-Path $testRoot 'prepared.json'
    $inputData = Get-RouteInputs 'fixture' ''
    Save-PreparedRouteInput $path 'fixture' $inputData
    $savedText = Get-Content -LiteralPath $path -Raw -Encoding UTF8
    $reused = Get-RouteInputs 'fixture' $path
    Assert-True ($script:downloads -eq 1 -and $script:lookups -eq 2) 'Installer handoff repeated network work'
    Assert-True ($reused.Text -ceq $inputData.Text -and $reused.Dns.Addresses.Count -eq 2) 'Handoff changed the validated input'
    Assert-True ((ConvertTo-UtcTimestamp $reused.Dns.Cache.updated_at) -eq (ConvertTo-UtcTimestamp $inputData.Dns.Cache.updated_at)) 'Handoff extended DNS freshness'
    # Current registry/ownership is supplied anew, never embedded in the handoff.
    $current = @{'new-manual.example'=@('7.7.7.7')}
    $plan = Get-ManagedRoutePlan $reused.List $reused.Dns $current @()
    Assert-True ((Get-DesiredSites $current @() $plan.Entries).ContainsKey('new-manual.example')) 'Handoff froze manual settings at preflight'

    Assert-Throws { Get-RouteInputs 'another-source' $path } 'Mismatched source was accepted'
    $Lite = $true
    Assert-Throws { Get-RouteInputs 'fixture' $path } 'Mismatched list mode was accepted'
    $Lite = $false
    $NoLocalSubnets = $true
    Assert-Throws { Get-RouteInputs 'fixture' $path } 'Mismatched LAN policy was accepted'
    $NoLocalSubnets = $false
    $DnsCacheHours = 0
    Assert-Throws { Get-RouteInputs 'fixture' $path } 'Mismatched DNS policy was accepted'
    $DnsCacheHours = 6
    foreach ($timestamp in @([DateTime]::UtcNow.AddMinutes(-16), [DateTime]::UtcNow.AddMinutes(1))) {
        $bad = $savedText | ConvertFrom-Json
        $bad.created_at = $timestamp.ToString('o')
        Write-JsonAtomic $path $bad
        Assert-Throws { Get-RouteInputs 'fixture' $path } 'Stale or future handoff was accepted'
    }
    $bad = $savedText | ConvertFrom-Json
    $bad.dns.addresses.'one.example' = @('10.1.2.3')
    Write-JsonAtomic $path $bad
    Assert-Throws { Get-RouteInputs 'fixture' $path } 'Private DNS from prepared input was accepted'
    $bad = $savedText | ConvertFrom-Json
    $bad.dns.addresses | Add-Member NoteProperty 'unrelated.example' @('1.1.1.1')
    Write-JsonAtomic $path $bad
    Assert-Throws { Get-RouteInputs 'fixture' $path } 'Unrelated prepared DNS domain was accepted'
    $bad = $savedText | ConvertFrom-Json
    $bad.text = '[]'
    Write-JsonAtomic $path $bad
    Assert-Throws { Get-RouteInputs 'fixture' $path } 'Prepared text bypassed list validation'
    $bad = $savedText | ConvertFrom-Json
    $bad.dns.updated_at = [DateTime]::UtcNow.AddMinutes(1).ToString('o')
    Write-JsonAtomic $path $bad
    Assert-Throws { Get-RouteInputs 'fixture' $path } 'Future DNS timestamp was accepted'

    $nearlyExpired = $savedText | ConvertFrom-Json
    $nearlyExpired.dns.updated_at = [DateTime]::UtcNow.AddHours(-6).AddMinutes(1).ToString('o')
    Write-JsonAtomic $path $nearlyExpired
    $null = Get-RouteInputs 'fixture' $path
    Assert-True ($script:downloads -eq 1 -and $script:lookups -eq 2) 'Refresh-ahead repeated DNS during the installer handoff'

    $expired = $savedText | ConvertFrom-Json
    $expired.dns.updated_at = [DateTime]::UtcNow.AddHours(-7).ToString('o')
    Write-JsonAtomic $path $expired
    $null = Get-RouteInputs 'fixture' $path
    Assert-True ($script:downloads -eq 1 -and $script:lookups -eq 4) 'Expired DNS was reused or redownloaded the prepared list'
    Write-Host 'PASS: installation reuses validated inputs, rejects invalid snapshots, and refreshes expired DNS'

    $diskCache = [ordered]@{ version=1; updated_at=[DateTime]::UtcNow.AddHours(-5).ToString('o');
        domains=@('one.example'); addresses=@{'one.example'=@('1.1.1.1')}; last_known_addresses=@{'one.example'=@('9.9.9.9')} }
    Write-JsonAtomic $DnsCachePath $diskCache
    $dns = Resolve-ManagedDomains @('one.example')
    Assert-True ($dns.Cached -and $dns.Addresses['one.example'][0] -ceq '1.1.1.1' -and $script:lookups -eq 4) 'Intervening run discarded a fresh six-hour cache'
    # A scheduled run six hours later sees a younger timestamp when the prior
    # DNS took 40 seconds. Refresh ahead of expiry instead of slipping to 12h.
    $diskCache.updated_at = [DateTime]::UtcNow.AddHours(-6).AddSeconds(40).ToString('o')
    Write-JsonAtomic $DnsCachePath $diskCache
    $dns = Resolve-ManagedDomains @('one.example')
    Assert-True (-not $dns.Cached -and $script:lookups -eq 5) 'DNS completion timestamp skipped the scheduled refresh'
    $diskCache.updated_at = [DateTime]::UtcNow.AddHours(-7).ToString('o')
    Write-JsonAtomic $DnsCachePath $diskCache
    $dns = Resolve-ManagedDomains @('one.example')
    Assert-True (-not $dns.Cached -and $script:lookups -eq 6 -and $dns.PreviousAddresses['one.example'][0] -ceq '9.9.9.9') 'Scheduled refresh lost fallback or used stale cache'
    $diskCache.updated_at = [DateTime]::UtcNow.ToString('o')
    Write-JsonAtomic $DnsCachePath $diskCache
    $DnsCacheHours = 0
    $dns = Resolve-ManagedDomains @('one.example')
    Assert-True (-not $dns.Cached -and $script:lookups -eq 7) 'Explicit cache bypass did not resolve DNS'
    Write-Host 'PASS: six-hour cache policy, scheduled refresh margin, stale fallback, and explicit cache bypass'
} finally {
    $resolved = [IO.Path]::GetFullPath($testRoot)
    $parent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($parent, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $resolved) -notlike 'amnezia-plan-test-*') { throw 'Unsafe temporary cleanup target' }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
