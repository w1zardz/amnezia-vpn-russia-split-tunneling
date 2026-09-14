# Compile and validate configuration without changing any real firewall policy.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$testDir = Join-Path ([IO.Path]::GetTempPath()) ('amnezia-app-guard-test-' + [Guid]::NewGuid().ToString('N'))
try {
    & (Join-Path $PSScriptRoot 'build-app-vpn-guard.ps1') -OutputDir $testDir
    $exe = Join-Path $testDir 'app-vpn-guard.exe'
    $config = Join-Path $testDir 'test.txt'
    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllLines($config, @('A|AmneziaVPN', "P|$exe", "P|$($exe.ToUpperInvariant())"), $encoding)
    $result = & $exe --validate-config $config
    if ($LASTEXITCODE -ne 0 -or $result -notmatch '1 program/path scopes') { throw 'Duplicate paths were not deduplicated by executable identity.' }
    [IO.File]::WriteAllLines($config, @('A|AmneziaVPN', "D|$testDir\future-app\"), $encoding)
    $result = & $exe --validate-config $config
    if ($LASTEXITCODE -ne 0 -or $result -notmatch '1 program/path scopes') { throw 'A future directory could not be protected before its creation.' }
    # Reject malformed and empty scopes before opening the filtering engine.
    foreach ($invalid in @(@('A|AmneziaVPN'), @('A|AmneziaVPN','unknown'), @("P|$exe"), @('A|AmneziaVPN', 'D|relative\path\'))) {
        [IO.File]::WriteAllLines($config, $invalid, $encoding)
        $process = Start-Process -FilePath $exe -ArgumentList @('--validate-config', ('"'+$config+'"')) `
            -WindowStyle Hidden -PassThru -Wait -RedirectStandardError (Join-Path $testDir 'error.txt')
        if ($process.ExitCode -eq 0) { throw 'Malformed policy was accepted.' }
    }
    Write-Host 'PASS: native guard builds with warnings as errors; overlapping and invalid configuration scopes verified.'
} finally {
    $resolved = [IO.Path]::GetFullPath($testDir)
    $parent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($parent,[StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $resolved) -notlike 'amnezia-app-guard-test-*') { throw 'Unsafe temporary cleanup target' }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
