@echo off
chcp 65001 >nul
setlocal
title Российские сайты без VPN — отключение автообновления

rem Двойной клик: снимает задачу автообновления и удаляет файлы из
rem %LOCALAPPDATA%\AmneziaRouteSync. Права администратора нужны, потому что
rem установщик регистрирует задачу с наивысшими правами. Скачанный отдельно
rem файл сам берёт windows\uninstall.ps1 с GitHub.

net session >nul 2>&1
if errorlevel 1 (
    echo Запрашиваю права администратора — нажмите «Да» в окне Windows.
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

if exist "%~dp0uninstall.ps1" (set "UNINSTALLER=%~dp0uninstall.ps1" & goto run)
if exist "%~dp0windows\uninstall.ps1" (set "UNINSTALLER=%~dp0windows\uninstall.ps1" & goto run)

echo Скачиваю свежую версию с GitHub...
set "WORK=%TEMP%\amnezia-ru-direct-uninstall"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference = 'Stop'; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $w = $env:WORK; if (Test-Path $w) { Remove-Item $w -Recurse -Force }; New-Item -ItemType Directory $w | Out-Null; $zip = Join-Path $w 'src.zip'; Invoke-WebRequest -UseBasicParsing 'https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/archive/refs/heads/master.zip' -OutFile $zip; Expand-Archive $zip $w -Force"
if errorlevel 1 goto failed
set "UNINSTALLER=%WORK%\amnezia-vpn-russia-split-tunneling-master\windows\uninstall.ps1"
if not exist "%UNINSTALLER%" goto failed

:run
powershell -NoProfile -ExecutionPolicy Bypass -File "%UNINSTALLER%"
if errorlevel 1 goto failed
echo.
echo Готово: автообновление отключено, файлы скрипта удалены.
echo Сам список остался в AmneziaVPN — при необходимости очистите его
echo в разделе «Раздельное туннелирование сайтов».
goto end

:failed
echo.
echo Отключить автообновление не удалось — причина написана выше.

:end
echo.
pause
