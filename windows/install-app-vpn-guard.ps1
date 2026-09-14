<#
.SYNOPSIS
Устанавливает постоянные WFP-фильтры: Claude и ChatGPT/Codex только через AmneziaWG.
.DESCRIPTION
Без -Install показывает план. При установке нужны права администратора и готовая
сборка build-app-vpn-guard.ps1. Остальные приложения и настройки Amnezia не меняются.
Покрытие относится к найденным Windows EXE. Сайты в браузере, чужие локальные
прокси и отдельные виртуальные машины этим правилом не защищены.
#>
[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Uninstall,
    [string]$AdapterAlias = 'AmneziaVPN',
    [string]$BinaryPath = (Join-Path $env:LOCALAPPDATA 'AmneziaRouteSync\app-guard-build\app-vpn-guard.exe')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$taskName = 'Amnezia-App-VPN-Guard'
$installDir = Join-Path $env:ProgramFiles 'AmneziaAppVpnGuard'
$targetExe = Join-Path $installDir 'app-vpn-guard.exe'
$configPath = Join-Path $installDir 'programs.txt'
if ($Install -and $Uninstall) { throw 'Выберите установку или удаление.' }
if ($AdapterAlias -match '[\r\n|]') { throw 'Недопустимое имя VPN-интерфейса.' }
if ($Install -or $Uninstall) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Для системных фильтров и задачи запуска нужны права администратора Windows.'
    }
}
if ($Uninstall) {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task) { Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop }
    if (-not (Test-Path -LiteralPath $targetExe)) { throw 'Не найдена установленная программа удаления фильтров.' }
    & $targetExe --remove
    if ($LASTEXITCODE -ne 0) { throw 'Удалить фильтры не удалось; файлы сохранены.' }
    if ($task) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false }
    Write-Host 'Защита этих приложений снята. Другие фильтры Windows и Amnezia сохранены.'
    return
}

$records = New-Object 'System.Collections.Generic.List[string]'
$records.Add("A|$AdapterAlias")
$packages = @(Get-AppxPackage | Where-Object { $_.Name -eq 'Claude' -or $_.Name -match '^OpenAI\.(Codex|ChatGPT)' })
foreach ($package in $packages) {
    # A path prefix covers future package versions before their first process
    # starts; scanning new EXEs after launch would leave a privacy gap.
    $packagePrefix = Join-Path (Split-Path -Parent $package.InstallLocation) ($package.Name + '_')
    $records.Add("D|$packagePrefix")
    if ($package.Name -eq 'Claude') {
        $virtualCode = Join-Path $env:LOCALAPPDATA ('Packages\' + $package.PackageFamilyName + '\LocalCache\Roaming\Claude\claude-code')
        $records.Add("D|$($virtualCode.TrimEnd('\'))\")
    }
}
foreach ($root in @(
    (Join-Path $env:APPDATA 'Claude\claude-code'),
    (Join-Path $env:LOCALAPPDATA 'OpenAI\Codex\bin'),
    (Join-Path $env:LOCALAPPDATA 'AnthropicClaude')
)) {
    $records.Add("D|$($root.TrimEnd('\'))\")
}
$processes = @(Get-Process | Where-Object { $_.ProcessName -match '^(Claude|ChatGPT|codex|codex-code-mode-host)$' })
# Updaters can unlink an EXE while its process is still running. Its native image
# identity remains usable for WFP even when the original Win32 path is gone.
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class AppVpnGuardImagePath {
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, int id);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder path, ref uint size);
    public static string Get(int id) {
        var handle=OpenProcess(0x1000, false, id);
        if(handle==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            uint size=32768; var path=new StringBuilder((int)size);
            if(!QueryFullProcessImageName(handle, 1, path, ref size)) throw new Win32Exception(Marshal.GetLastWin32Error());
            return path.ToString();
        } finally { CloseHandle(handle); }
    }
}
'@
foreach ($programPath in @($processes | ForEach-Object { [AppVpnGuardImagePath]::Get($_.Id) } | Sort-Object -Unique)) { $records.Add("N|$programPath") }
if ($records.Count -lt 2) { throw 'Не найдены установленные Claude или ChatGPT/Codex.' }
Write-Host 'Защищаемые приложения: Claude и ChatGPT/Codex, включая найденные фоновые EXE.'
Write-Host "Разрешённый VPN-интерфейс: $AdapterAlias; другие интерфейсы блокируются для этих EXE по IPv4 и IPv6."
Write-Host 'Локальные соединения внутри компьютера (loopback) сохраняются.'
Write-Host 'Постоянные фильтры сохраняются после перезагрузки и остановки наблюдателя.'
Write-Host 'Правила каталогов покрывают новые версии и новые EXE внутри этих каталогов с первого соединения.'
if (-not $Install) { $records | ForEach-Object { Write-Output $_ }; return }
if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) { throw 'Сначала выполните windows\build-app-vpn-guard.ps1.' }

# Test the actual kernel filters on the helper itself before protecting any app.
& $BinaryPath --probe $AdapterAlias
if ($LASTEXITCODE -ne 0) { throw 'Проверка блокировки в Windows не прошла; новые правила приложений не установлены.' }

[IO.Directory]::CreateDirectory($installDir) | Out-Null
# The elevated startup task must never execute user-writable code or config.
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
$inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
    $rule = New-Object Security.AccessControl.FileSystemAccessRule(
        (New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', $inheritance, 'None', 'Allow')
    $acl.AddAccessRule($rule)
}
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
    (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')), 'ReadAndExecute', $inheritance, 'None', 'Allow')))
Set-Acl -LiteralPath $installDir -AclObject $acl

$oldTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($oldTask) {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while ((Get-ScheduledTask -TaskName $taskName).State -eq 'Running' -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 200 }
    if ((Get-ScheduledTask -TaskName $taskName).State -eq 'Running') { throw 'Старый наблюдатель не остановился. Его постоянные фильтры сохранены.' }
}
if (Test-Path -LiteralPath $configPath) { Copy-Item -LiteralPath $configPath -Destination "$configPath.previous" -Force }
Copy-Item -LiteralPath $BinaryPath -Destination $targetExe -Force
Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $installDir 'install-app-vpn-guard.ps1') -Force
[IO.File]::WriteAllLines($configPath, $records, (New-Object Text.UTF8Encoding($false)))

& $targetExe --once $configPath
if ($LASTEXITCODE -ne 0) { throw 'Новые правила не применились. Предыдущая политика, если была, сохранена.' }
$action = New-ScheduledTaskAction -Execute $targetExe -Argument ('--watch "' + $configPath + '"') -WorkingDirectory $installDir
$triggers = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -AtLogOn))
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -Hidden -MultipleInstances IgnoreNew -StartWhenAvailable `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $triggers -Principal $principal -Settings $settings `
    -Description 'Claude и ChatGPT/Codex: постоянная блокировка прямых соединений вне AmneziaWG.' -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
& $targetExe --status
if ($LASTEXITCODE -ne 0) { throw 'Не удалось прочитать установленные фильтры.' }
Write-Host 'Установлено. Защита действует для каталогов приложений и найденных процессов; VPN не переподключался.'
Write-Host "Удаление: powershell -ExecutionPolicy Bypass -File `"$installDir\install-app-vpn-guard.ps1`" -Uninstall (от администратора)."
