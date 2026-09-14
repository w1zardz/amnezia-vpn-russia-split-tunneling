<#
.SYNOPSIS
Ставит автообновление списка RU Direct для AmneziaVPN на Windows.

.DESCRIPTION
Копирует updater в %LOCALAPPDATA%\AmneziaRouteSync, прогоняет self-test и dry-run
и только после успешной проверки регистрирует Scheduled Task: обновление при входе
в систему и каждые 6 часов.

Задача регистрируется с наивысшими правами: чтобы применить новый список без
перезагрузки Windows, updater отключает туннель через демон, а при сбое может
перезапустить службу AmneziaVPN-service. Поэтому и
установщик нужно запускать от имени администратора.
#>

[CmdletBinding()]
param(
    [switch]$Lite,
    [switch]$ReplaceAll,
    [switch]$NoLocalSubnets,
    [switch]$AllowVpnReconnect,
    [ValidateRange(-1, 10000)]
    [int]$ServerIndex = -1,
    [string]$Source
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ($env:OS -ne 'Windows_NT') { throw 'Этот installer предназначен только для Windows.' }
if (-not $env:LOCALAPPDATA) { throw 'Не определён LOCALAPPDATA текущего пользователя.' }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentSid = $identity.User.Value
if ($CurrentSid -eq 'S-1-5-18') { throw 'Installer нельзя запускать от SYSTEM: настройки лежат в HKCU пользователя.' }
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Запустите PowerShell от имени администратора: без этого задача не сможет перезапускать службу AmneziaVPN-service.'
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceScript = Join-Path $ScriptDir 'update-amnezia-routes.ps1'
if (-not (Test-Path -LiteralPath $SourceScript -PathType Leaf)) { throw "Не найден $SourceScript" }

$InstallDir = Join-Path $env:LOCALAPPDATA 'AmneziaRouteSync'
$InstalledScript = Join-Path $InstallDir 'update-amnezia-routes.ps1'
$TaskName = "Amnezia-Split-Route-Sync-$CurrentSid"
$PowerShellExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
if (-not (Test-Path -LiteralPath $PowerShellExe -PathType Leaf)) { throw "Не найден $PowerShellExe" }

if ($Source) {
    if ($Source -match '["\r\n]') { throw 'Источник не должен содержать кавычки или переносы строк.' }
    if (-not $Source.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) {
        $Source = (Resolve-Path -LiteralPath $Source -ErrorAction Stop).ProviderPath
    }
}
$updaterArguments = New-Object 'System.Collections.Generic.List[string]'
if ($Lite) { [void]$updaterArguments.Add('-Lite') }
if ($ReplaceAll) { [void]$updaterArguments.Add('-ReplaceAll') }
if ($NoLocalSubnets) { [void]$updaterArguments.Add('-NoLocalSubnets') }
if ($Source) { [void]$updaterArguments.Add("-Source `"$Source`"") }
if ($ServerIndex -ge 0) { [void]$updaterArguments.Add("-ServerIndex $ServerIndex") }
$updaterArgumentText = ($updaterArguments -join ' ')

$stagingDir = Join-Path $env:TEMP ("amnezia-route-stage-{0}" -f [Guid]::NewGuid().ToString('N'))
$backupDir = Join-Path $env:TEMP ("amnezia-route-backup-{0}" -f [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($stagingDir) | Out-Null
[IO.Directory]::CreateDirectory($backupDir) | Out-Null

$stagedScript = Join-Path $stagingDir 'update-amnezia-routes.ps1'
$scriptExisted = $false
$taskWasPresent = $false
$oldTaskXml = $null
$mutationStarted = $false
$installComplete = $false
$keepBackup = $false

try {
    Copy-Item -LiteralPath $SourceScript -Destination $stagedScript -Force

    & $PowerShellExe -NoProfile -ExecutionPolicy Bypass -File $stagedScript -SelfTest
    if ($LASTEXITCODE -ne 0) { throw 'Self-test updater завершился ошибкой; ничего не установлено.' }

    # Старый экземпляр не должен держать mutex и применять прежнюю политику
    # параллельно с переустановкой. Если он был прерван во время записи, сначала
    # восстанавливаем его journal, ещё до сетевых запросов и замены файлов.
    $runningTasks = @(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq 'Running' })
    if ($runningTasks.Count -gt 0) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        $stopDeadline = [DateTime]::UtcNow.AddSeconds(20)
        do {
            Start-Sleep -Milliseconds 250
            $stillRunning = (Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop).State -eq 'Running'
        } while ($stillRunning -and [DateTime]::UtcNow -lt $stopDeadline)
        if ($stillRunning) { throw 'Предыдущий updater не остановился за 20 секунд; переустановка отменена.' }
    }
    $recoveryArguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $stagedScript, '-RecoverOnly')
    if ($AllowVpnReconnect) { $recoveryArguments += '-AllowVpnReconnect' }
    & $PowerShellExe @recoveryArguments
    if ($LASTEXITCODE -ne 0) { throw 'Не удалось восстановить предыдущую транзакцию; переустановка отменена.' }

    $dryRunArguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $stagedScript, '-DryRun')
    if ($Lite) { $dryRunArguments += '-Lite' }
    if ($NoLocalSubnets) { $dryRunArguments += '-NoLocalSubnets' }
    if ($Source) { $dryRunArguments += @('-Source', $Source) }
    & $PowerShellExe @dryRunArguments
    if ($LASTEXITCODE -ne 0) { throw 'Dry-run updater завершился ошибкой; ничего не установлено.' }

    [IO.Directory]::CreateDirectory($InstallDir) | Out-Null
    $scriptExisted = Test-Path -LiteralPath $InstalledScript -PathType Leaf
    if ($scriptExisted) { Copy-Item -LiteralPath $InstalledScript -Destination (Join-Path $backupDir 'update-amnezia-routes.ps1') -Force }

    $oldTasks = @(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
    if ($oldTasks.Count -gt 1) { throw 'Task Scheduler вернул несколько задач с одним именем.' }
    if ($oldTasks.Count -eq 1) {
        $taskWasPresent = $true
        $oldTaskXml = Export-ScheduledTask -TaskName $TaskName
    }

    $mutationStarted = $true
    $temporaryTarget = Join-Path $InstallDir ".update-amnezia-routes.ps1.new.$PID"
    Copy-Item -LiteralPath $stagedScript -Destination $temporaryTarget -Force
    if ([IO.File]::Exists($InstalledScript)) { [IO.File]::Replace($temporaryTarget, $InstalledScript, [NullString]::Value) }
    else { [IO.File]::Move($temporaryTarget, $InstalledScript) }

    $taskArgumentText = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstalledScript`""
    if ($updaterArgumentText) { $taskArgumentText = "$taskArgumentText $updaterArgumentText" }
    $action = New-ScheduledTaskAction -Execute $PowerShellExe -Argument $taskArgumentText -WorkingDirectory $InstallDir
    $user = $identity.Name
    # Без задержки задача стартует одновременно с автозапуском самой AmneziaVPN и
    # перезапускает AmneziaVPN-service прямо посреди её подключения: приложение
    # остаётся в трее с бесконечным «подключением». Три минуты дают Amnezia
    # подняться и подключиться до того, как updater тронет службу.
    $logonTrigger = New-ScheduledTaskTrigger -AtLogOn -User $user
    $logonTrigger.Delay = 'PT3M'
    $triggers = @(
        $logonTrigger,
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) `
            -RepetitionInterval (New-TimeSpan -Hours 6) -RepetitionDuration (New-TimeSpan -Days 3650))
    )
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -MultipleInstances IgnoreNew `
        -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
    $task = New-ScheduledTask -Action $action -Trigger $triggers -Principal $taskPrincipal -Settings $settings `
        -Description 'Amnezia Route Sync: обновление списка RU Direct в split tunneling AmneziaVPN'
    Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null

    $registeredTasks = @(Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop)
    if ($registeredTasks.Count -ne 1) { throw 'Task Scheduler не сохранил задачу.' }

    $installComplete = $true
    # Первый запуск синхронный: установщик сообщает об успехе только после
    # применения и восстановления VPN, а ошибки не теряются в фоновой задаче.
    $initialArguments = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $InstalledScript)
    if ($Lite) { $initialArguments += '-Lite' }
    if ($ReplaceAll) { $initialArguments += '-ReplaceAll' }
    if ($NoLocalSubnets) { $initialArguments += '-NoLocalSubnets' }
    if ($Source) { $initialArguments += @('-Source', $Source) }
    if ($ServerIndex -ge 0) { $initialArguments += @('-ServerIndex', [string]$ServerIndex) }
    # One-time permission must never become a standing permission in the task.
    if ($AllowVpnReconnect) { $initialArguments += '-AllowVpnReconnect' }
    & $PowerShellExe @initialArguments
    if ($LASTEXITCODE -ne 0) {
        throw 'Скрипт и задача установлены, но первичное применение не завершилось. Исправьте ошибку выше и повторите установку; журнал восстановления сохранён, если он был создан.'
    }

    Write-Host "Установлено: $InstalledScript"
    Write-Host 'Обновление: при входе в Windows и каждые 6 часов.'
    Write-Host 'При включённом KillSwitch работающая Amnezia автоматически не переподключается: применение изменённого списка откладывается.'
    Write-Host "Статус: Get-ScheduledTask -TaskName '$TaskName'"
    Write-Host "Результат последнего запуска: Get-Content `"$InstallDir\status.json`""
} catch {
    if ($mutationStarted -and -not $installComplete) {
        try {
            $rollbackTasks = @(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
            if ($rollbackTasks.Count -ge 1) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop }
            if ($taskWasPresent -and $oldTaskXml) {
                Register-ScheduledTask -TaskName $TaskName -Xml $oldTaskXml -Force | Out-Null
            }
            if ($scriptExisted) {
                Copy-Item -LiteralPath (Join-Path $backupDir 'update-amnezia-routes.ps1') -Destination $InstalledScript -Force
            } elseif (Test-Path -LiteralPath $InstalledScript) {
                Remove-Item -LiteralPath $InstalledScript -Force
            }
            Write-Warning 'Установка не завершена; предыдущее состояние восстановлено.'
        } catch {
            $keepBackup = $true
            Write-Error "АВАРИЯ: rollback installer неполный; backup сохранён: $backupDir"
        }
    }
    throw
} finally {
    $cleanupDirs = @($stagingDir)
    if (-not $keepBackup) { $cleanupDirs += $backupDir }
    $tempParent = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\'
    foreach ($cleanupDir in $cleanupDirs) {
        $resolvedCleanup = [IO.Path]::GetFullPath($cleanupDir)
        if (-not $resolvedCleanup.StartsWith($tempParent, [StringComparison]::OrdinalIgnoreCase) -or
            (Split-Path -Leaf $resolvedCleanup) -notmatch '^amnezia-route-(stage|backup)-[0-9a-f]{32}$') {
            throw 'Небезопасный путь очистки временных файлов установщика.'
        }
        Remove-Item -LiteralPath $resolvedCleanup -Recurse -Force -ErrorAction SilentlyContinue
    }
}
