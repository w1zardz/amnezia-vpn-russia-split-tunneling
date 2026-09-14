@echo off
chcp 65001 >nul
setlocal
set "RESULT=0"
title Российские сайты без VPN — установка для AmneziaVPN

rem Двойной клик по файлу: права администратора запрашиваются сами, дальше
rem работает windows\install.ps1. Скачанный отдельно файл сам берёт проект с GitHub.

net session >nul 2>&1
if errorlevel 1 (
    echo Запрашиваю права администратора — нажмите «Да» в окне Windows.
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

if exist "%~dp0install.ps1" (set "INSTALLER=%~dp0install.ps1" & goto run)
if exist "%~dp0windows\install.ps1" (set "INSTALLER=%~dp0windows\install.ps1" & goto run)

echo Скачиваю свежую версию с GitHub...
set "WORK=%TEMP%\amnezia-ru-direct-setup"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference = 'Stop'; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $w = $env:WORK; if (Test-Path $w) { Remove-Item $w -Recurse -Force }; New-Item -ItemType Directory $w | Out-Null; $zip = Join-Path $w 'src.zip'; Invoke-WebRequest -UseBasicParsing 'https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/archive/refs/heads/master.zip' -OutFile $zip; Expand-Archive $zip $w -Force"
if errorlevel 1 goto failed
set "INSTALLER=%WORK%\amnezia-vpn-russia-split-tunneling-master\windows\install.ps1"
if not exist "%INSTALLER%" goto failed

:run
powershell -NoProfile -ExecutionPolicy Bypass -File "%INSTALLER%"
if errorlevel 1 goto failed
echo.
echo Готово: российские сайты идут напрямую, остальное — через VPN.
echo Список обновляется сам при входе в Windows и каждые 6 часов.
goto end

:failed
set "RESULT=1"
echo.
echo Установка не удалась — причина написана выше.
echo Проверьте, что AmneziaVPN установлен и подключение в нём настроено.

:end
echo.
pause
exit /b %RESULT%
