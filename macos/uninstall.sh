#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="${HOME}/Library/Application Support/AmneziaRouteSync"
LAUNCH_AGENT="${HOME}/Library/LaunchAgents/io.github.amnezia-route-sync.plist"
SERVICE_TARGET="gui/${UID}/io.github.amnezia-route-sync"
UPDATE_SCRIPT="${INSTALL_DIR}/update_amnezia_routes.py"
PENDING_PATH="${INSTALL_DIR}/.route-transaction.json"
WAS_LOADED=0
REMOVAL_COMMITTED=0

restore_agent_on_failure() {
    local rc=$?
    if [[ "${REMOVAL_COMMITTED}" -eq 0 && "${WAS_LOADED}" -eq 1 && -f "${LAUNCH_AGENT}" ]]; then
        if launchctl print "${SERVICE_TARGET}" >/dev/null 2>&1; then
            return "${rc}"
        fi
        if ! launchctl bootstrap "gui/${UID}" "${LAUNCH_AGENT}" >/dev/null 2>&1 ||
            ! launchctl print "${SERVICE_TARGET}" >/dev/null 2>&1; then
            echo "Не удалось повторно загрузить прежний LaunchAgent" >&2
            rc=1
        fi
    fi
    return "${rc}"
}

trap restore_agent_on_failure EXIT

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "Этот uninstaller предназначен только для macOS" >&2
    exit 1
fi

if launchctl print "${SERVICE_TARGET}" >/dev/null 2>&1; then
    WAS_LOADED=1
fi
if [[ "${WAS_LOADED}" -eq 1 ]]; then
    launchctl bootout "${SERVICE_TARGET}"
    if launchctl print "${SERVICE_TARGET}" >/dev/null 2>&1; then
        echo "LaunchAgent остался загружен; удаление остановлено" >&2
        exit 1
    fi
fi
for _ in {1..60}; do
    if ! pgrep -f "${INSTALL_DIR}/update_amnezia_routes.py" >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done
if pgrep -f "${UPDATE_SCRIPT}" >/dev/null 2>&1; then
    echo "Updater ещё работает; удаление остановлено" >&2
    exit 1
fi
if [[ -f "${PENDING_PATH}" ]]; then
    if [[ ! -x "${UPDATE_SCRIPT}" ]]; then
        echo "Найдена незавершённая транзакция, но updater отсутствует; удаление остановлено" >&2
        exit 1
    fi
    /usr/bin/python3 "${UPDATE_SCRIPT}" --recover-only
fi
if [[ -f "${PENDING_PATH}" ]]; then
    echo "Routing recovery не завершён; файлы сохранены" >&2
    exit 1
fi

REMOVAL_COMMITTED=1
rm -f -- "${LAUNCH_AGENT}"
rm -rf -- "${INSTALL_DIR}"
if [[ -e "${LAUNCH_AGENT}" || -e "${INSTALL_DIR}" ]]; then
    echo "Не удалось полностью удалить приватные файлы automation" >&2
    exit 1
fi
SMB_CONF="${HOME}/Library/Preferences/nsmb.conf"
SMB_MARK="# amnezia-route-sync: SMB multichannel off"
if [[ -f "${SMB_CONF}" ]] && grep -Fq "${SMB_MARK}" "${SMB_CONF}"; then
    SMB_TMP="$(mktemp "${SMB_CONF}.XXXXXX")"
    awk -v mark="${SMB_MARK}" '
        $0 == mark " (section)" { header = 1; next }
        header && $0 == "[default]" { header = 0; next }
        $0 == mark { header = 0; skip = 1; next }
        skip && $0 == "mc_on=no" { skip = 0; next }
        { header = 0; skip = 0; print }' "${SMB_CONF}" >"${SMB_TMP}"
    if ! grep -Evq '^[[:space:]]*(\[default\])?[[:space:]]*$' "${SMB_TMP}"; then
        rm -f -- "${SMB_TMP}" "${SMB_CONF}"
    else
        chmod 644 "${SMB_TMP}"
        mv -f "${SMB_TMP}" "${SMB_CONF}"
    fi
fi
echo "Автоматизация удалена. Очистите managed-маршруты в интерфейсе AmneziaVPN."
