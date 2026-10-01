#!/bin/bash
# Установка в один клик для macOS: двойной щелчок по файлу открывает Терминал
# и выполняет этот скрипт. Скачанный отдельно файл сам берёт проект с GitHub.
# Тот же файл работает как однострочник: curl -fsSL <raw-url> | bash
set -Eeuo pipefail

REPO_ZIP="https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/archive/refs/heads/master.zip"
WORK=""

cleanup() {
    [[ -n "${WORK}" ]] && rm -rf -- "${WORK}"
    return 0
}
trap cleanup EXIT

pause_on_exit() {
    local rc="$1"
    if [[ "${rc}" -ne 0 ]]; then
        echo
        echo "Установка не удалась — причина написана выше."
        echo "Проверьте, что AmneziaVPN установлен и подключение в нём настроено."
    fi
    # Двойной клик: окно Терминала не должно закрыться до того, как текст прочитан.
    if [[ -t 0 ]]; then
        echo
        read -r -p "Нажмите Enter, чтобы закрыть окно. " _ || true
    fi
    exit "${rc}"
}
trap 'pause_on_exit $?' ERR
trap 'pause_on_exit 130' INT

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "Этот установщик предназначен только для macOS" >&2
    false
fi
if [[ ! -d /Applications/AmneziaVPN.app ]]; then
    echo "Не найдена /Applications/AmneziaVPN.app — сначала установите AmneziaVPN" >&2
    false
fi

# Command Line Tools дают swiftc и /usr/bin/python3, без них ставить нечего.
if ! xcrun --find swiftc >/dev/null 2>&1; then
    echo "Нужны инструменты разработчика Apple (Command Line Tools)."
    echo "Сейчас откроется окно macOS — нажмите «Установить» и дождитесь конца загрузки."
    xcode-select --install >/dev/null 2>&1 || true
    for _ in $(seq 1 360); do
        if xcrun --find swiftc >/dev/null 2>&1; then
            break
        fi
        sleep 5
    done
    if ! xcrun --find swiftc >/dev/null 2>&1; then
        echo "Command Line Tools так и не установились." >&2
        echo "Выполните в Терминале: xcode-select --install, дождитесь конца и запустите файл снова." >&2
        false
    fi
    echo "Инструменты установлены."
fi

# Файл могли запустить из распакованного проекта (macos/ или его корень) —
# тогда качать нечего.
SOURCE="${BASH_SOURCE[0]:-}"
INSTALLER=""
if [[ -n "${SOURCE}" && -f "${SOURCE}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${SOURCE}")" && pwd)"
    if [[ -f "${SCRIPT_DIR}/install.sh" ]]; then
        INSTALLER="${SCRIPT_DIR}/install.sh"
    elif [[ -f "${SCRIPT_DIR}/macos/install.sh" ]]; then
        INSTALLER="${SCRIPT_DIR}/macos/install.sh"
    fi
fi

if [[ -z "${INSTALLER}" ]]; then
    echo "Скачиваю свежую версию проекта с GitHub..."
    WORK="$(mktemp -d "${TMPDIR:-/tmp}/amnezia-ru-direct-setup.XXXXXX")"
    curl -fsSL --proto '=https' --tlsv1.2 "${REPO_ZIP}" -o "${WORK}/src.zip"
    /usr/bin/ditto -x -k "${WORK}/src.zip" "${WORK}"
    INSTALLER="${WORK}/amnezia-vpn-russia-split-tunneling-master/macos/install.sh"
    if [[ ! -f "${INSTALLER}" ]]; then
        echo "В скачанном архиве нет macos/install.sh" >&2
        false
    fi
fi

echo "Ставлю автообновление маршрутов..."
bash "${INSTALLER}"

echo
echo "Автообновление установлено. Результат проверки и применения указан выше."
echo "При работающей Amnezia изменённый список откладывается без переподключения VPN."
echo "Расписание: раз в неделю, в воскресенье в 12:00 по местному времени."
pause_on_exit 0
