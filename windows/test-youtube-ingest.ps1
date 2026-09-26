# Isolated profile/protocol tests. No external network, VPN, or real registry writes.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('amnezia-ingest-test-' + [Guid]::NewGuid().ToString('N'))
$updater = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'update-amnezia-routes.ps1') -Raw -Encoding UTF8
. ([scriptblock]::Create($updater.Substring(0, $updater.IndexOf('# --- self-test')))) -StateDir $testRoot

function Assert-True([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Assert-Throws([scriptblock]$Action, [string]$Message) {
    $caught = $false
    try { & $Action | Out-Null } catch { $caught = $true }
    Assert-True $caught $Message
}
function New-FixtureList {
    return [pscustomobject]@{ Domains=@('ordinary.example'); Cidrs=@('5.255.0.0/16'); DomainAddresses=@{} }
}

try {
    $plain = Add-OptionalDirectDomains (New-FixtureList)
    Assert-True (($plain.Domains -join ',') -ceq 'ordinary.example') 'Default list added YouTube'
    $YouTubeIngestDirect = $true
    $list = Add-OptionalDirectDomains (New-FixtureList)
    $list = Add-OptionalDirectDomains $list
    Assert-True (($list.Domains -join ',') -ceq 'a.rtmps.youtube.com,b.rtmps.youtube.com,ordinary.example') 'Profile added unexpected domains or duplicates'
    $dns = [pscustomobject]@{
        Addresses=@{'a.rtmps.youtube.com'=@('8.8.8.8');'b.rtmps.youtube.com'=@('9.9.9.9')}
        PreviousAddresses=@{'a.rtmps.youtube.com'=@('8.8.4.4')}
    }
    $plan = Get-ManagedRoutePlan $list $dns @{} @()
    Assert-True (($plan.Entries -join ',') -ceq '5.255.0.0/16,8.8.8.8/32,9.9.9.9/32') 'Profile expanded beyond resolved host addresses'
    Assert-True ($plan.Entries -notcontains '8.8.4.4/32') 'Fresh DNS retained stale routes'
    $dns.Addresses.Remove('a.rtmps.youtube.com')
    $fallback = Get-ManagedRoutePlan $list $dns @{} @()
    Assert-True ($fallback.Entries -contains '8.8.4.4/32') 'DNS failure lost last known host route'
    $dns.PreviousAddresses.Clear()
    Assert-Throws { Get-ManagedRoutePlan $list $dns @{} @() } 'First-run missing DNS allowed a partial profile'
    $dns.Addresses['a.rtmps.youtube.com'] = @('127.0.0.1','10.1.2.3','::1')
    Assert-Throws { Get-ManagedRoutePlan $list $dns @{} @() } 'Private/IPv6 answers enabled the profile'
    $dns.Addresses['a.rtmps.youtube.com'] = @(1..33 | ForEach-Object { "8.8.8.$_" })
    Assert-Throws { Get-ManagedRoutePlan $list $dns @{} @() } 'Unbounded ingest DNS accepted'

    # Enabling then disabling removes only owned routes, including when a manual
    # address overlaps the profile at installation time.
    $manual = @{'8.8.8.8/32'=@(); 'manual.example'=@('1.1.1.1')}
    $owned = @(Get-OwnedEntries $manual @() $plan.Entries)
    $enabled = Get-DesiredSites $manual @() $plan.Entries
    $YouTubeIngestDirect = $false
    $offPlan = Get-ManagedRoutePlan (Add-OptionalDirectDomains (New-FixtureList)) $dns @{} @()
    $disabled = Get-DesiredSites $enabled $owned $offPlan.Entries
    Assert-True ($disabled.ContainsKey('8.8.8.8/32') -and $disabled.ContainsKey('manual.example')) 'Disabling removed manual entries'
    Assert-True (-not $disabled.ContainsKey('9.9.9.9/32')) 'Disabling retained an owned ingest address'
    Write-Host 'PASS: opt-in hosts, DNS rotation/fallback, bounded IPv4, disable preserves manual ownership'

    # Physical-interface selection must never silently choose the VPN.
    function Get-NetAdapter { return @([pscustomobject]@{ifIndex=19;Status='Up'},[pscustomobject]@{ifIndex=20;Status='Up'}) }
    function Get-NetRoute {
        return @([pscustomobject]@{InterfaceIndex=51;InterfaceAlias='VPN';RouteMetric=0},
            [pscustomobject]@{InterfaceIndex=19;InterfaceAlias='Ethernet';RouteMetric=10},
            [pscustomobject]@{InterfaceIndex=20;InterfaceAlias='Wi-Fi';RouteMetric=1})
    }
    function Get-NetIPInterface { return [pscustomobject]@{InterfaceMetric=5} }
    function Get-NetIPAddress { return [pscustomobject]@{AddressState='Preferred';SkipAsSource=$false;IPAddress='192.168.1.2'} }
    Assert-True ((Get-IngestDirectInterface).Index -eq 20) 'Did not select the best physical default route'
    $DirectInterfaceIndex = 19
    Assert-True ((Get-IngestDirectInterface).Index -eq 19) 'Explicit physical interface was ignored'
    $DirectInterfaceIndex = 51
    Assert-Throws { Get-IngestDirectInterface } 'Explicit VPN index was accepted as direct'
    $DirectInterfaceIndex = 0
    function Get-NetAdapter { return @() }
    Assert-Throws { Get-IngestDirectInterface } 'Missing physical interface fell back to VPN'
    Write-Host 'PASS: physical interface selection and explicit override'

    Initialize-IngestProbe
    Add-Type -TypeDefinition @'
using System;
using System.IO;
public sealed class IngestHandshakeFixture : Stream {
    readonly string mode;
    byte[] response;
    int offset;
    public int Written;
    public int Writes;
    public IngestHandshakeFixture(string mode) { this.mode = mode; }
    public override bool CanRead { get { return true; } }
    public override bool CanSeek { get { return false; } }
    public override bool CanWrite { get { return true; } }
    public override long Length { get { throw new NotSupportedException(); } }
    public override long Position { get { return offset; } set { throw new NotSupportedException(); } }
    public override void Flush() { }
    public override long Seek(long n, SeekOrigin origin) { throw new NotSupportedException(); }
    public override void SetLength(long n) { throw new NotSupportedException(); }
    public override void Write(byte[] buffer, int start, int count) {
        Written += count;
        Writes++;
        if (Writes == 1) {
            if (count != 1537 || buffer[start] != 3) throw new Exception("Bad C0/C1");
            response = new byte[3073];
            response[0] = (byte)(mode == "bad-version" ? 2 : 3);
            for (int i=1; i<1537; i++) response[i] = 42;
            Array.Copy(buffer, start + 1, response, 1537, 1536);
            if (mode == "bad-echo") response[3072] ^= 1;
            if (mode == "truncated") Array.Resize(ref response, 1700);
        } else {
            if (Writes != 2 || count != 1536) throw new Exception("Probe sent a publish command");
            for (int i=0; i<count; i++) if (buffer[start+i] != 42) throw new Exception("Bad C2");
        }
    }
    public override int Read(byte[] buffer, int start, int count) {
        int n = Math.Min(Math.Min(count, 73), response.Length - offset);
        Array.Copy(response, offset, buffer, start, n);
        offset += n;
        return n;
    }
}
'@
    $stream = New-Object IngestHandshakeFixture('valid')
    try {
        [AmneziaRouteSync.IngestProbe]::Handshake($stream, 4000)
        Assert-True ($stream.Writes -eq 2 -and $stream.Written -eq 3073) 'Handshake wrote unexpected application data'
    } finally { $stream.Dispose() }
    foreach ($mode in @('bad-version','bad-echo','truncated')) {
        $stream = New-Object IngestHandshakeFixture($mode)
        try { Assert-Throws { [AmneziaRouteSync.IngestProbe]::Handshake($stream, 4000) } "Accepted $mode" }
        finally { $stream.Dispose() }
    }
    Write-Host 'PASS: complete fragmented handshake, invalid version/echo and premature close; no publishing'

    # Execute the diagnostic entry point in a child: reaching the normal updater
    # or writing anything to its state directory is a failure.
    [IO.Directory]::CreateDirectory($testRoot) | Out-Null
    $engine = (Get-Process -Id $PID).Path
    foreach ($directResult in @('Failed','OK')) {
        $hooks = @'
function Invoke-YouTubeIngestCheck {
    [pscustomobject]@{Server='fixture';Address='8.8.8.8';Path='Direct';LocalAddress='';Stage='TCP';Result='DIRECT_RESULT';Detail='fixture'}
    [pscustomobject]@{Server='fixture';Address='8.8.8.8';Path='System';LocalAddress='';Stage='RTMP';Result='OK';Detail='fixture'}
}
function Get-AmneziaExePath { throw 'Diagnostic entered mutation path' }
function Read-ExceptSites { throw 'Diagnostic read the real configuration' }
'@
        $hooks = $hooks.Replace('DIRECT_RESULT', $directResult)
        $scriptPath = Join-Path $testRoot ($directResult + '.ps1')
        $instrumented = $updater.Insert($updater.IndexOf('# --- self-test'), $hooks + "`r`n")
        [IO.File]::WriteAllText($scriptPath, $instrumented, (New-Object Text.UTF8Encoding($true)))
        $state = Join-Path $testRoot 'untouched-state'
        & $engine -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $scriptPath -TestYouTubeIngest -StateDir $state > $null
        $expected = if ($directResult -eq 'OK') { 0 } else { 2 }
        Assert-True ($LASTEXITCODE -eq $expected) 'Diagnostic confused system-route reachability with direct reachability'
        Assert-True (-not (Test-Path -LiteralPath $state)) 'Read-only diagnostic wrote updater state'
    }
    Write-Host 'PASS: diagnostic entry point is read-only and fails when only the system route works'
} finally {
    $resolved = [IO.Path]::GetFullPath($testRoot)
    $parent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($parent, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $resolved) -notlike 'amnezia-ingest-test-*') { throw 'Unsafe temporary cleanup target' }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
