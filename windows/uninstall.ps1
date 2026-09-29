<#
.SYNOPSIS
Снимает автообновление списка RU Direct для AmneziaVPN на Windows.

.DESCRIPTION
Убирает Scheduled Task и приватные файлы из %LOCALAPPDATA%\AmneziaRouteSync.
Незавершённая routing-транзакция сначала докатывается, чтобы не оставить
Preferences AmneziaVPN в промежуточном состоянии.

Сам список в AmneziaVPN не трогается: его чистят в интерфейсе приложения.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ($env:OS -ne 'Windows_NT') { throw 'Этот uninstaller предназначен только для Windows.' }
if (-not $env:LOCALAPPDATA) { throw 'Не определён LOCALAPPDATA текущего пользователя.' }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentSid = $identity.User.Value
if ($CurrentSid -eq 'S-1-5-18') { throw 'Uninstaller нельзя запускать от SYSTEM.' }
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Запустите PowerShell от имени администратора: задачу автообновления installer регистрирует с наивысшими правами.'
}

$InstallDir = Join-Path $env:LOCALAPPDATA 'AmneziaRouteSync'
$InstalledScript = Join-Path $InstallDir 'update-amnezia-routes.ps1'
$JournalPath = Join-Path $InstallDir '.registry-transaction.json'
$TaskName = "Amnezia-Split-Route-Sync-$CurrentSid"
$PowerShellExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

$tasks = @(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
foreach ($task in $tasks) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
}
$remaining = @(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
if ($remaining.Count -ne 0) { throw 'Не удалось снять Scheduled Task; удаление остановлено.' }

if (Test-Path -LiteralPath $JournalPath -PathType Leaf) {
    if (-not (Test-Path -LiteralPath $InstalledScript -PathType Leaf)) {
        throw 'Найдена незавершённая транзакция, но updater отсутствует; удаление остановлено.'
    }
    & $PowerShellExe -NoProfile -ExecutionPolicy Bypass -File $InstalledScript -RecoverOnly
    if ($LASTEXITCODE -ne 0) { throw 'Routing recovery не завершён; файлы сохранены.' }
}
if (Test-Path -LiteralPath $JournalPath -PathType Leaf) {
    throw 'Routing recovery не завершён; файлы сохранены.'
}

$mutex = New-Object Threading.Mutex($false, "Global\Amnezia-Split-Route-Sync-$CurrentSid")
$hasLock = $false
try {
    try { $hasLock = $mutex.WaitOne(5000) } catch [Threading.AbandonedMutexException] { $hasLock = $true }
    if (-not $hasLock) { throw 'Updater ещё работает; файлы сохранены. Повторите удаление после его завершения.' }
    if (Test-Path -LiteralPath $JournalPath -PathType Leaf) { throw 'Updater оставил транзакцию; файлы сохранены. Повторите удаление для восстановления.' }
    $resolvedInstallDir = [IO.Path]::GetFullPath($InstallDir)
    $expectedParent = [IO.Path]::GetFullPath($env:LOCALAPPDATA).TrimEnd('\') + '\'
    if (-not $resolvedInstallDir.StartsWith($expectedParent, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $resolvedInstallDir) -cne 'AmneziaRouteSync') { throw 'Небезопасный путь удаления.' }
    if (Test-Path -LiteralPath $resolvedInstallDir) {
        Remove-Item -LiteralPath $resolvedInstallDir -Recurse -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $resolvedInstallDir) { throw 'Не удалось полностью удалить приватные файлы automation.' }
} finally {
    if ($hasLock) { [void]$mutex.ReleaseMutex() }
    $mutex.Dispose()
}

Write-Host 'Автоматизация удалена. Список RU Direct остался в AmneziaVPN — очистите его в интерфейсе приложения при необходимости.'
