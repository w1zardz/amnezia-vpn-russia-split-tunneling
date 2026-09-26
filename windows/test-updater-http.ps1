# Isolated HTTP regression tests: synthetic responses, no network or VPN changes.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http

# Load only download functions. Never execute the updater's entry point.
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'update-amnezia-routes.ps1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw ($parseErrors | Out-String) }
$names = @('New-SourceHttpClient','New-SourceHttpException','Get-SourceRetryDelay','Get-HttpsText','Get-SourceText')
foreach ($name in $names) {
    $declaration = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    if ($null -eq $declaration) { throw "Missing function: $name" }
    . ([scriptblock]::Create($declaration.Extent.Text))
}
$MaxListBytes = 64

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function New-TestResponse([int]$StatusCode = 200, [byte[]]$Body = [Text.Encoding]::UTF8.GetBytes('valid')) {
    $response = [Net.Http.HttpResponseMessage]::new([Enum]::ToObject([Net.HttpStatusCode], $StatusCode))
    $response.Content = [Net.Http.ByteArrayContent]::new($Body)
    return $response
}
function Reset-Download([object[]]$Outcomes) {
    $script:HttpOutcomes = $Outcomes
    $script:HttpAttempts = 0
    $script:DisposedClients = 0
    $script:Delays = New-Object 'System.Collections.Generic.List[int]'
}

# Keep real status handling, stream reading, decoding, cancellation and disposal;
# replace only the network client and sleeping.
function New-SourceHttpClient {
    $script:HttpAttempts++
    if ($script:HttpAttempts -gt $script:HttpOutcomes.Count) { throw 'Unexpected extra HTTP attempt' }
    $client = [pscustomobject]@{ Outcome = $script:HttpOutcomes[$script:HttpAttempts - 1] }
    $client | Add-Member ScriptMethod GetAsync {
        param($url, $completion, $token)
        if (-not $token.CanBeCanceled) { throw 'HTTP request has no cancellation token' }
        $task = New-Object 'System.Threading.Tasks.TaskCompletionSource[System.Net.Http.HttpResponseMessage]'
        if ($this.Outcome -is [Exception]) { $task.SetException($this.Outcome) }
        else { $task.SetResult($this.Outcome) }
        return $task.Task
    }
    $client | Add-Member ScriptMethod Dispose { $script:DisposedClients++ }
    return $client
}
function Start-Sleep([int]$Seconds) { $script:Delays.Add($Seconds) }
function Assert-FailedDownload([object[]]$Outcomes, [int]$Attempts, [int[]]$Delays = @()) {
    Reset-Download $Outcomes
    $caught = $null
    try { $null = Get-SourceText 'https://source.example/list.json' } catch { $caught = $_ }
    Assert-True ($null -ne $caught) 'Download unexpectedly succeeded'
    Assert-True ($script:HttpAttempts -eq $Attempts) "Wrong attempt count: $script:HttpAttempts, expected $Attempts"
    Assert-True (($script:Delays -join ',') -ceq ($Delays -join ',')) "Wrong retry delays: $($script:Delays -join ',')"
    Assert-True ($script:DisposedClients -eq $Attempts) 'An HTTP client was not disposed'
    return $caught
}

foreach ($status in @(301, 400, 401, 403, 404, 410, 422)) {
    $null = Assert-FailedDownload @((New-TestResponse $status)) 1
}
Write-Host 'PASS: permanent HTTP responses fail after one attempt without sleeping'

foreach ($status in @(408, 429, 500, 502, 503, 504, 599)) {
    Reset-Download @((New-TestResponse $status), (New-TestResponse 200))
    Assert-True ((Get-SourceText 'https://source.example/list.json') -ceq 'valid') "HTTP $status did not recover"
    Assert-True ($script:HttpAttempts -eq 2 -and ($script:Delays -join ',') -ceq '5') "HTTP $status retry mismatch"
    Assert-True ($script:DisposedClients -eq 2) 'Successful HTTP attempt leaked a client'
}
$null = Assert-FailedDownload @((New-TestResponse 503), (New-TestResponse 503), (New-TestResponse 503)) 3 @(5,10)
$null = Assert-FailedDownload @((New-TestResponse 503), (New-TestResponse 404)) 2 @(5)
Write-Host 'PASS: transient HTTP responses recover or stop at three attempts'

foreach ($seconds in @(0, 12, 3600)) {
    $response = New-TestResponse 429
    $response.Headers.RetryAfter = [Net.Http.Headers.RetryConditionHeaderValue]::new([TimeSpan]::FromSeconds($seconds))
    Reset-Download @($response, (New-TestResponse 200))
    $null = Get-SourceText 'https://source.example/list.json'
    Assert-True ($script:Delays[0] -eq [Math]::Min(30, $seconds)) "Retry-After $seconds not honored within cap"
}
$response = New-TestResponse 503
$response.Headers.RetryAfter = [Net.Http.Headers.RetryConditionHeaderValue]::new([DateTimeOffset]::UtcNow.AddHours(1))
Reset-Download @($response, (New-TestResponse 200))
$null = Get-SourceText 'https://source.example/list.json'
Assert-True ($script:Delays[0] -eq 30) 'HTTP-date Retry-After exceeded the delay cap'
$response = New-TestResponse 429
$response.Headers.RetryAfter = [Net.Http.Headers.RetryConditionHeaderValue]::new([DateTimeOffset]::UtcNow.AddMinutes(-1))
Assert-True ((Get-SourceRetryDelay (New-SourceHttpException $response 'https://source.example') 1) -eq 0) 'Past Retry-After did not become zero'
$response.Dispose()
Write-Host 'PASS: Retry-After delta/date, zero, past date and bounded server delay'

$networkFailures = @(
    [TimeoutException]::new('Timeout'),
    [Threading.Tasks.TaskCanceledException]::new('Timeout'),
    [OperationCanceledException]::new('Cancelled by request deadline'),
    [IO.IOException]::new('Connection lost while reading'),
    [Net.Sockets.SocketException]::new(10054),
    [Net.Http.HttpRequestException]::new('Connection failed'),
    [Net.WebException]::new('Name resolution', [Net.WebExceptionStatus]::NameResolutionFailure)
)
foreach ($failure in $networkFailures) {
    Reset-Download @($failure, (New-TestResponse 200))
    Assert-True ((Get-SourceText 'https://source.example/list.json') -ceq 'valid') "No recovery for $($failure.GetType().Name)"
    Assert-True ($script:HttpAttempts -eq 2 -and ($script:Delays -join ',') -ceq '5') 'Transient exception retry mismatch'
}
$timeout = Assert-FailedDownload @(
    [Threading.Tasks.TaskCanceledException]::new('Timed out'),
    [Threading.Tasks.TaskCanceledException]::new('Timed out'),
    [Threading.Tasks.TaskCanceledException]::new('Timed out')
) 3 @(5,10)
Assert-True ($timeout.Exception.Message -match '60') 'Timeout lost its useful deadline message'
Write-Host 'PASS: network/read errors and cancellation retain bounded retries and timeout context'

$permanentFailures = @(
    [Net.Http.HttpRequestException]::new('TLS', [Security.Authentication.AuthenticationException]::new('Certificate rejected')),
    [Net.Http.HttpRequestException]::new('TLS', [Net.WebException]::new('Certificate rejected', [Net.WebExceptionStatus]::TrustFailure)),
    [Net.WebException]::new('TLS rejected', [Net.WebExceptionStatus]::SecureChannelFailure),
    [ArgumentException]::new('Unsupported argument'),
    [Exception]::new('Unclassified failure')
)
foreach ($failure in $permanentFailures) { $null = Assert-FailedDownload @($failure) 1 }
# PowerShell adds wrappers to .NET method exceptions. Inner permanent causes
# must win even when the outer request exception normally permits a retry.
$nested = [Exception]::new('PowerShell wrapper', [Net.Http.HttpRequestException]::new('Request', [Security.Authentication.AuthenticationException]::new('Certificate')))
Assert-True ((Get-SourceRetryDelay $nested 1) -eq -1) 'Wrapped TLS failure retried'
Write-Host 'PASS: TLS/certificate, argument and unknown failures stop immediately'

$oversize = New-TestResponse 200 (New-Object byte[] 65)
$null = Assert-FailedDownload @($oversize) 1
$oversizeStream = New-TestResponse 200 (New-Object byte[] 65)
$oversizeStream.Content.Headers.ContentLength = 1
$null = Assert-FailedDownload @($oversizeStream) 1
$null = Assert-FailedDownload @((New-TestResponse 200 ([byte[]]@()))) 1
$null = Assert-FailedDownload @((New-TestResponse 200 ([byte[]]@(0xC3,0x28)))) 1
$unicode = 'Список: пример.рф'
Reset-Download @((New-TestResponse 200 ([Text.Encoding]::UTF8.GetBytes($unicode))))
Assert-True ((Get-SourceText 'https://source.example/list.json') -ceq $unicode) 'Valid UTF-8 was damaged'
Write-Host 'PASS: header/body size limits, empty response and invalid UTF-8 fail without retries'

foreach ($url in @('http://source.example/list.json','ftp://source.example/list.json','https://')) {
    Reset-Download @()
    $caught = $false
    try { $null = Get-SourceText $url } catch { $caught = $true }
    Assert-True ($caught -and $script:HttpAttempts -eq 0 -and $script:Delays.Count -eq 0) 'Unsupported URL reached the network or retried'
}
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('amnezia-http-test-' + [Guid]::NewGuid().ToString('N') + '.json')
try {
    [IO.File]::WriteAllText($temporary, $unicode, [Text.UTF8Encoding]::new($false))
    Assert-True ((Get-SourceText $temporary) -ceq $unicode) 'Local file source regressed'
    Assert-True ($script:HttpAttempts -eq 0) 'Local source attempted HTTP'
} finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force } }
Write-Host 'PASS: invalid/unsupported URLs make no request; local UTF-8 source still works'
Write-Host 'HTTP regression tests passed.'
