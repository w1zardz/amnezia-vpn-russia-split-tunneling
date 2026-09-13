#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${HOME}/Library/Application Support/AmneziaRouteSync"
LAUNCH_AGENT="${HOME}/Library/LaunchAgents/io.github.amnezia-route-sync.plist"
UPDATE_SCRIPT="${INSTALL_DIR}/update_amnezia_routes.py"
HELPER_BINARY="${INSTALL_DIR}/set-amnezia-routes"
PROTECTED_IPS_SOURCE="${SCRIPT_DIR}/../config/protected-ips.json"
PROTECTED_IPS_FILE="${INSTALL_DIR}/protected-ips.json"
STDOUT_LOG="${INSTALL_DIR}/launchd.log"
STDERR_LOG="${INSTALL_DIR}/launchd-error.log"
PENDING_PATH="${INSTALL_DIR}/.route-transaction.json"
GUI_DOMAIN="gui/${UID}"
SERVICE_TARGET="${GUI_DOMAIN}/io.github.amnezia-route-sync"
STAGING_DIR="$(mktemp -d "${TMPDIR:-/tmp}/amnezia-route-stage.XXXXXX")"
BACKUP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/amnezia-route-backup.XXXXXX")"
ROLLBACK_READY=0
INSTALL_COMPLETE=0
WAS_LOADED=0
KEEP_BACKUP=0

cleanup() {
    rm -rf -- "${STAGING_DIR}"
    if [[ "${KEEP_BACKUP}" -eq 0 ]]; then
        rm -rf -- "${BACKUP_DIR}"
    fi
}

restore_file() {
    local target="$1"
    local backup_name="$2"
    if [[ -f "${BACKUP_DIR}/${backup_name}" ]]; then
        cp -p "${BACKUP_DIR}/${backup_name}" "${target}"
    else
        rm -f -- "${target}"
    fi
}

rollback() {
    local rc="$1"
    local rollback_failed=0
    trap - ERR
    set +e
    if [[ "${ROLLBACK_READY}" -eq 1 && "${INSTALL_COMPLETE}" -eq 0 ]]; then
        if launchctl print "${SERVICE_TARGET}" >/dev/null 2>&1; then
            launchctl bootout "${SERVICE_TARGET}" >/dev/null 2>&1 || rollback_failed=1
        fi
        if launchctl print "${SERVICE_TARGET}" >/dev/null 2>&1; then
            rollback_failed=1
        fi
        if [[ "${rollback_failed}" -eq 0 ]]; then
            restore_file "${UPDATE_SCRIPT}" update_amnezia_routes.py || rollback_failed=1
            restore_file "${HELPER_BINARY}" set-amnezia-routes || rollback_failed=1
            restore_file "${PROTECTED_IPS_FILE}" protected-ips.json || rollback_failed=1
            restore_file "${LAUNCH_AGENT}" launch-agent.plist || rollback_failed=1
        fi
        if [[ "${rollback_failed}" -eq 0 && "${WAS_LOADED}" -eq 1 && -f "${LAUNCH_AGENT}" ]]; then
            launchctl bootstrap "${GUI_DOMAIN}" "${LAUNCH_AGENT}" >/dev/null 2>&1 \
                || rollback_failed=1
            launchctl print "${SERVICE_TARGET}" >/dev/null 2>&1 || rollback_failed=1
        fi
        if [[ "${rollback_failed}" -eq 0 ]]; then
            echo "Установка не завершена; предыдущая версия восстановлена" >&2
        else
            KEEP_BACKUP=1
            echo "АВАРИЯ: rollback неполный; backup сохранён: ${BACKUP_DIR}" >&2
        fi
    fi
    exit "${rc}"
}

trap 'rollback $?' ERR
trap 'rollback 130' INT
trap 'rollback 129' HUP
trap 'rollback 143' TERM
trap cleanup EXIT

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "Этот installer предназначен только для macOS" >&2
    exit 1
fi
if [[ ! -d /Applications/AmneziaVPN.app ]]; then
    echo "Не найдена /Applications/AmneziaVPN.app" >&2
    exit 1
fi
# /usr/bin/python3 — shim выбранного Xcode: после обновления Xcode он может
# существовать, но падать ещё до запуска Python. CLT запускаем напрямую.
PYTHON_BIN=""
for PYTHON_CANDIDATE in /Library/Developer/CommandLineTools/usr/bin/python3 /usr/bin/python3; do
    if [[ -x "${PYTHON_CANDIDATE}" ]] && "${PYTHON_CANDIDATE}" -c \
        'import fcntl, ipaddress, json, plistlib, sys; sys.exit(sys.version_info < (3, 9))' \
        >/dev/null 2>&1; then
        PYTHON_BIN="${PYTHON_CANDIDATE}"
        break
    fi
done
if [[ -z "${PYTHON_BIN}" ]]; then
    echo "Не найден рабочий Apple Python 3.9+ (Command Line Tools или /usr/bin/python3). Переустановите Command Line Tools." >&2
    exit 1
fi

if ! xcrun --find swiftc >/dev/null 2>&1; then
    echo "Не найден swiftc. Установите Xcode Command Line Tools: xcode-select --install" >&2
    exit 1
fi

# Полностью собираем и проверяем новую версию до изменения рабочей установки.
install -m 700 "${SCRIPT_DIR}/update_amnezia_routes.py" "${STAGING_DIR}/update_amnezia_routes.py"
# protected-ips.json необязателен: это личный список адресов, которые не должны
# попасть в маршруты мимо VPN. В публичный репозиторий он не коммитится.
if [[ -f "${PROTECTED_IPS_SOURCE}" ]]; then
    install -m 600 "${PROTECTED_IPS_SOURCE}" "${STAGING_DIR}/protected-ips.json"
fi
xcrun swiftc -warnings-as-errors -O "${SCRIPT_DIR}/set-amnezia-routes.swift" \
    -o "${STAGING_DIR}/set-amnezia-routes"
chmod 700 "${STAGING_DIR}/set-amnezia-routes"

install -m 600 "${SCRIPT_DIR}/io.github.amnezia-route-sync.plist.template" \
    "${STAGING_DIR}/launch-agent.plist"
PROGRAM_ARGUMENTS_JSON="$("${PYTHON_BIN}" -c \
    'import json,sys; print(json.dumps(sys.argv[1:]))' "${PYTHON_BIN}" "${UPDATE_SCRIPT}")"
plutil -replace ProgramArguments -json "${PROGRAM_ARGUMENTS_JSON}" \
    "${STAGING_DIR}/launch-agent.plist"
plutil -replace StandardOutPath -string "${STDOUT_LOG}" "${STAGING_DIR}/launch-agent.plist"
plutil -replace StandardErrorPath -string "${STDERR_LOG}" "${STAGING_DIR}/launch-agent.plist"
PATH_STATE_JSON="$("${PYTHON_BIN}" -c \
    'import json,sys; print(json.dumps({sys.argv[1]: True}))' "${PENDING_PATH}")"
plutil -replace KeepAlive.PathState -json "${PATH_STATE_JSON}" \
    "${STAGING_DIR}/launch-agent.plist"
plutil -lint "${STAGING_DIR}/launch-agent.plist" >/dev/null
# Тем же интерпретатором, что и LaunchAgent, а не первым python3 из PATH.
"${PYTHON_BIN}" "${STAGING_DIR}/update_amnezia_routes.py" --dry-run

mkdir -p "${INSTALL_DIR}" "$(dirname "${LAUNCH_AGENT}")"
chmod 700 "${INSTALL_DIR}"
[[ -f "${UPDATE_SCRIPT}" ]] && cp -p "${UPDATE_SCRIPT}" "${BACKUP_DIR}/update_amnezia_routes.py"
[[ -f "${HELPER_BINARY}" ]] && cp -p "${HELPER_BINARY}" "${BACKUP_DIR}/set-amnezia-routes"
[[ -f "${PROTECTED_IPS_FILE}" ]] \
    && cp -p "${PROTECTED_IPS_FILE}" "${BACKUP_DIR}/protected-ips.json"
[[ -f "${LAUNCH_AGENT}" ]] && cp -p "${LAUNCH_AGENT}" "${BACKUP_DIR}/launch-agent.plist"
if launchctl print "${SERVICE_TARGET}" >/dev/null 2>&1; then
    WAS_LOADED=1
fi
ROLLBACK_READY=1

if [[ "${WAS_LOADED}" -eq 1 ]]; then
    launchctl bootout "${SERVICE_TARGET}"
else
    launchctl bootout "${SERVICE_TARGET}" >/dev/null 2>&1 || true
fi
for _ in {1..60}; do
    if ! pgrep -f "${UPDATE_SCRIPT}" >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done
if pgrep -f "${UPDATE_SCRIPT}" >/dev/null 2>&1; then
    echo "Старый updater ещё работает; установка остановлена" >&2
    false
fi
install -m 700 "${STAGING_DIR}/update_amnezia_routes.py" "${UPDATE_SCRIPT}"
install -m 700 "${STAGING_DIR}/set-amnezia-routes" "${HELPER_BINARY}"
if [[ -f "${STAGING_DIR}/protected-ips.json" ]]; then
    install -m 600 "${STAGING_DIR}/protected-ips.json" "${PROTECTED_IPS_FILE}"
else
    rm -f -- "${PROTECTED_IPS_FILE}"
fi
install -m 600 "${STAGING_DIR}/launch-agent.plist" "${LAUNCH_AGENT}"

launchctl bootstrap "${GUI_DOMAIN}" "${LAUNCH_AGENT}"
# Bootstrap уже мог запустить RunAtLoad job. С этого момента нельзя удалять agent/helper:
# они нужны для автоматического восстановления pending-транзакции.
INSTALL_COMPLETE=1
trap - ERR
launchctl enable "${SERVICE_TARGET}"
AGENT_STATE="$(launchctl print "${SERVICE_TARGET}")"
AGENT_RUNS="$(awk '/runs =/{print $3; exit}' <<<"${AGENT_STATE}")"
if [[ "${AGENT_RUNS:-0}" -eq 0 ]] && ! grep -q 'state = running' <<<"${AGENT_STATE}"; then
    launchctl kickstart "${SERVICE_TARGET}"
fi

for _ in {1..720}; do
    AGENT_STATE="$(launchctl print "${SERVICE_TARGET}" 2>/dev/null || true)"
    AGENT_RUNS="$(awk '/runs =/{print $3; exit}' <<<"${AGENT_STATE}")"
    # launchd между spawn и стартом процесса показывает runs = 1 без state = running
    # и «last exit code = (never exited)» — это ещё не завершение.
    if [[ "${AGENT_RUNS:-0}" -ge 1 ]] && ! grep -q 'state = running' <<<"${AGENT_STATE}" \
        && grep -q 'last exit code = ' <<<"${AGENT_STATE}" \
        && ! grep -q 'never exited' <<<"${AGENT_STATE}"; then
        break
    fi
    sleep 0.5
done
AGENT_STATE="$(launchctl print "${SERVICE_TARGET}" 2>/dev/null || true)"
if grep -q 'state = running' <<<"${AGENT_STATE}"; then
    echo "Agent установлен, но первичное обновление ещё выполняется; см. ${STDERR_LOG}" >&2
    exit 1
fi
if ! grep -q 'last exit code = 0' <<<"${AGENT_STATE}"; then
    echo "Agent установлен, но первичное обновление завершилось ошибкой; см. ${STDERR_LOG}" >&2
    exit 1
fi

echo "Установлено: ${LAUNCH_AGENT}"
echo "Обновление: при входе в macOS и каждые 6 часов"
echo "Статус: launchctl print ${SERVICE_TARGET}"
echo "Новые маршруты подхвачены после безопасного перезапуска AmneziaVPN"
