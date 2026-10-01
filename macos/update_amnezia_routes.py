#!/usr/bin/env python3
"""Обновляет список RU Direct в split tunneling AmneziaVPN на macOS.

Источник — список, который собирает этот же репозиторий (tools/build_ru_direct.py)
и публикует в dist/ и в GitHub Releases. По умолчанию берётся сборка без доменов
(amnezia-ru-direct-ip.json): macOS-клиент маршрутизирует только IP, домены он
молча игнорирует, поэтому из любого источника они отбрасываются, если не задан
--with-domains. Скрипт скачивает список и проверяет его. Пока GUI или туннель
работают, применение откладывается без отключения VPN. Переподключение возможно
только с разовым --allow-vpn-reconnect. Незавершённая запись восстанавливается
из журнала.
"""

from __future__ import annotations

import argparse
import ctypes
import fcntl
import hashlib
import ipaddress
import json
import os
import plistlib
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, NamedTuple


APP_DOMAIN = "org.amneziavpn.AmneziaVPN"
APP_BUNDLE = Path("/Applications/AmneziaVPN.app")
APP_INFO_PLIST = APP_BUNDLE / "Contents/Info.plist"
SUPPORTED_APP_MAJOR = 5
PROTECTED_IPS: set[ipaddress.IPv4Address] = set()
LIST_BASE = "https://raw.githubusercontent.com/w1zardz/amnezia-vpn-russia-split-tunneling/master/dist"
# AmneziaVPN на macOS маршрутизирует split tunneling только по IP-адресам,
# домены в Conf.ExceptSites она молча игнорирует. Поэтому по умолчанию качаем
# сборку без доменов, а из любого другого источника домены отбрасываем.
LIST_FULL = f"{LIST_BASE}/amnezia-ru-direct-ip.json"
LIST_LITE = f"{LIST_BASE}/amnezia-ru-direct-lite.json"
MAX_LIST_BYTES = 4_194_304
# Шире /12 не пускаем: такая сеть означала бы «пол-интернета мимо VPN».
MIN_PREFIX_LENGTH = 12
MIN_TOTAL_ROUTES = 40
MAX_TOTAL_ROUTES = 1_500
MAX_TOTAL_ADDRESSES = 40_000_000
MIN_TOTAL_ENTRIES = 300
MAX_TOTAL_ENTRIES = 4_000
STATE_DIR = Path.home() / "Library/Application Support/AmneziaRouteSync"
PREFS_ROUTE_KEY = "Conf.ExceptSites"
PREFS_MODE_KEY = "Conf.routeMode"
PREFS_ENABLED_KEY = "Conf.sitesSplitTunnelingEnabled"
ROUTE_MODE_VPN_ALL_EXCEPT_SITES = 2
PROTECTED_IPS_FILENAME = "protected-ips.json"
PENDING_FILENAME = ".route-transaction.json"
HOSTNAME_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-.")
AMNEZIA_GUI_PROCESS = "AmneziaVPN"
AMNEZIA_TUNNEL_PROCESS = "amneziawg-go"
# Bundle identities and fallback names live together. Names never authorize a
# signal: an unverified named process or standalone CLI requires manual closure.
PROTECTED_CLIENTS = {
    "com.anthropic.claudefordesktop": frozenset({
        "Claude", "Claude Helper", "Claude Helper (GPU)",
        "Claude Helper (Plugin)", "Claude Helper (Renderer)",
    }),
    "com.openai.chat": frozenset({"ChatGPT"}),
    "com.openai.codex": frozenset({
        "ChatGPT", "Codex", "Codex (Service)", "Codex (Renderer)",
    }),
    None: frozenset({"claude"}),
}
CLIENT_CLOSE_TIMEOUT = 20.0
MAX_NODE_ARGUMENT_BYTES = 1_048_576
CLIENT_TRACKING_FILENAME = "protected-client-processes.json"
MAX_TRACKED_CLIENT_PROCESSES = 4096


class UpdateError(RuntimeError):
    pass


class UpdateDeferred(UpdateError):
    """Применение требует остановки работающей Amnezia и ожидает обслуживания."""


class SessionChanged(UpdateError):
    pass


def fetch_bytes(url: str) -> bytes:
    process = subprocess.run(
        [
            "/usr/bin/curl",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--max-filesize",
            str(MAX_LIST_BYTES),
            "--connect-timeout",
            "10",
            "--max-time",
            "30",
            "--retry",
            "2",
            "--user-agent",
            "Amnezia-Split-Route-Sync/2.0",
            url,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        message = process.stderr.decode(errors="replace").strip()
        raise UpdateError(f"не удалось скачать {url}: {message}")
    if len(process.stdout) > MAX_LIST_BYTES:
        raise UpdateError(f"{url}: ответ превышает {MAX_LIST_BYTES} байт")
    return process.stdout


def load_protected_ips(path: Path) -> None:
    """Адреса, которые никогда не должны уехать мимо VPN (например, свой сервер)."""
    global PROTECTED_IPS
    if not path.exists():
        PROTECTED_IPS = set()
        return
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UpdateError(f"не удалось прочитать {path}: {exc}") from exc
    values = document.get("protected_ips") if isinstance(document, dict) else document
    if not isinstance(values, list):
        raise UpdateError(f"{path}: ожидается список protected_ips")
    try:
        addresses = {ipaddress.ip_address(value) for value in values}
    except (TypeError, ValueError) as exc:
        raise UpdateError(f"{path}: неверный IP в protected_ips") from exc
    if any(address.version != 4 for address in addresses):
        raise UpdateError(f"{path}: protected_ips поддерживает только IPv4")
    PROTECTED_IPS = addresses


def valid_hostname(value: str) -> bool:
    if not value or len(value) > 253 or "." not in value:
        return False
    if value != value.lower() or value.startswith((".", "-")) or value.endswith((".", "-")):
        return False
    if not set(value) <= HOSTNAME_CHARACTERS:
        return False
    return all(0 < len(label) <= 63 for label in value.split("."))


def parse_import_list(payload: bytes, source: str) -> tuple[list[str], list[ipaddress.IPv4Network]]:
    """Формат импорта Amnezia: [{"hostname": "<домен или CIDR>", "ip": ""}]."""
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise UpdateError(f"{source}: список не является валидным JSON") from exc
    if not isinstance(document, list) or not document:
        raise UpdateError(f"{source}: ожидается непустой массив записей")
    domains: list[str] = []
    networks: list[ipaddress.IPv4Network] = []
    seen: set[str] = set()
    for index, entry in enumerate(document):
        if not isinstance(entry, dict):
            raise UpdateError(f"{source}: запись {index} не является объектом")
        value = entry.get("hostname")
        if not isinstance(value, str) or not value.strip():
            raise UpdateError(f"{source}: запись {index} без hostname")
        value = value.strip().lower().rstrip(".")
        if value in seen:
            continue
        seen.add(value)
        if "/" in value or value.replace(".", "").isdigit():
            try:
                network = ipaddress.ip_network(value, strict=True)
            except ValueError as exc:
                raise UpdateError(f"{source}: некорректная сеть {value!r}") from exc
            if network.version != 4:
                raise UpdateError(f"{source}: поддерживается только IPv4, получено {value!r}")
            if network.prefixlen < MIN_PREFIX_LENGTH:
                raise UpdateError(f"{source}: слишком широкая сеть {value}")
            if not network.is_global:
                raise UpdateError(f"{source}: сеть {value} не является публичной")
            networks.append(network)
            continue
        if not valid_hostname(value):
            raise UpdateError(f"{source}: некорректный домен {value!r}")
        domains.append(value)
    total = len(domains) + len(networks)
    if not MIN_TOTAL_ENTRIES <= total <= MAX_TOTAL_ENTRIES:
        raise UpdateError(
            f"{source}: {total} записей вне допустимого диапазона "
            f"{MIN_TOTAL_ENTRIES}..{MAX_TOTAL_ENTRIES}"
        )
    return sorted(set(domains)), networks


def validate_and_collapse(networks: Iterable[ipaddress.IPv4Network]) -> list[ipaddress.IPv4Network]:
    collapsed = list(ipaddress.collapse_addresses(networks))
    if not MIN_TOTAL_ROUTES <= len(collapsed) <= MAX_TOTAL_ROUTES:
        raise UpdateError(
            f"подозрительное число маршрутов: {len(collapsed)} "
            f"(допустимо {MIN_TOTAL_ROUTES}..{MAX_TOTAL_ROUTES})"
        )
    covered_addresses = sum(network.num_addresses for network in collapsed)
    if covered_addresses > MAX_TOTAL_ADDRESSES:
        raise UpdateError(f"список покрывает слишком много IPv4-адресов: {covered_addresses}")
    for network in collapsed:
        protected_inside = [ip for ip in PROTECTED_IPS if ip in network]
        if protected_inside:
            raise UpdateError("итоговый маршрут покрывает protected IP")
    return sorted(collapsed, key=lambda network: (int(network.network_address), network.prefixlen))


def merge_except_sites(
    current: dict[str, Any],
    previous_managed: Iterable[str],
    new_managed: Iterable[str],
    replace_all: bool = False,
) -> dict[str, Any]:
    if replace_all:
        merged: dict[str, Any] = {}
    else:
        previous = set(previous_managed)
        merged = {key: value for key, value in current.items() if key not in previous}
    # Amnezia дописывает в значение записи резолвнутые IP домена. Затирать их
    # пустым списком нельзя: иначе каждый запуск видел бы «список изменился»
    # и дёргал GUI с туннелем на ровном месте.
    for cidr in new_managed:
        merged[cidr] = current.get(cidr, [])
    return merged


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    file_descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(file_descriptor, "wb") as temporary_file:
            temporary_file.write(data)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.chmod(temporary_name, mode)
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def load_string_list(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UpdateError(f"не удалось прочитать state {path}: {exc}") from exc
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise UpdateError(f"неверный формат state {path}")
    return value


def export_preferences() -> tuple[bytes, dict[str, Any]]:
    process = subprocess.run(
        ["/usr/bin/defaults", "export", APP_DOMAIN, "-"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        message = process.stderr.decode(errors="replace").strip()
        raise UpdateError(f"не удалось экспортировать Preferences AmneziaVPN: {message}")
    try:
        preferences = plistlib.loads(process.stdout)
    except plistlib.InvalidFileException as exc:
        raise UpdateError("Preferences AmneziaVPN не являются валидным plist") from exc
    if not isinstance(preferences, dict):
        raise UpdateError("Preferences AmneziaVPN имеют неожиданный формат")
    return process.stdout, preferences


def protected_settings_hash(preferences: dict[str, Any]) -> str:
    protected = {key: value for key, value in preferences.items() if key.startswith("Servers.")}
    return hashlib.sha256(plistlib.dumps(protected, fmt=plistlib.FMT_BINARY)).hexdigest()


def route_state(preferences: dict[str, Any]) -> dict[str, Any]:
    sites = preferences.get(PREFS_ROUTE_KEY, {})
    if not isinstance(sites, dict):
        raise UpdateError(f"{PREFS_ROUTE_KEY} имеет неожиданный формат")
    return {
        "sites": sites,
        "mode": preferences.get(PREFS_MODE_KEY),
        "enabled": preferences.get(PREFS_ENABLED_KEY),
    }


def run_helper(helper_path: Path, state_path: Path) -> None:
    assert_protected_clients_stopped(state_path.parent)
    assert_amnezia_stopped()
    process = subprocess.run(
        [str(helper_path), "--domain", APP_DOMAIN, "--state", str(state_path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if process.returncode != 0:
        raise UpdateError(f"helper не применил routing Preferences: {process.stderr.strip()}")
    assert_protected_clients_stopped(state_path.parent)
    assert_amnezia_stopped()


def assert_amnezia_stopped() -> None:
    if process_ids(AMNEZIA_GUI_PROCESS) or process_ids(AMNEZIA_TUNNEL_PROCESS):
        raise SessionChanged(
            "AmneziaVPN запущена во время записи; запись или rollback отложены, "
            "работающее приложение не отключается"
        )


def process_ids(name: str) -> list[int]:
    process = subprocess.run(
        ["/usr/bin/pgrep", "-x", name],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if process.returncode not in (0, 1):
        raise UpdateError(f"pgrep не смог проверить процесс {name}")
    return [int(value) for value in process.stdout.split()]


def wait_for_process(name: str, running: bool, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if bool(process_ids(name)) is running:
            return True
        time.sleep(0.25)
    return bool(process_ids(name)) is running


class ClientProcess(NamedTuple):
    pid: int
    parent_pid: int
    uid: int
    command: str


def client_process_snapshot() -> dict[int, ClientProcess]:
    """Read executable names only, never prompts, tokens or command arguments."""
    try:
        result = subprocess.run(
            ["/bin/ps", "-ww", "-axo", "pid=,ppid=,uid=,comm="], check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UpdateError("не удалось проверить процессы Claude/ChatGPT") from exc
    if result.returncode != 0:
        raise UpdateError("не удалось проверить процессы Claude/ChatGPT")
    processes = {}
    try:
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            pid, parent_pid, uid, command = line.split(None, 3)
            process = ClientProcess(int(pid), int(parent_pid), int(uid), command)
            if process.pid <= 0 or process.parent_pid < 0 or process.uid < 0:
                raise ValueError("invalid process identity")
            if process.pid in processes:
                raise ValueError("duplicate process identity")
            processes[process.pid] = process
    except ValueError as exc:
        raise UpdateError("получен неверный список процессов Claude/ChatGPT") from exc
    return processes


def client_executable_path(pid: int) -> Path:
    """Verify executable identity independently of mutable process titles."""
    try:
        library = ctypes.CDLL("/usr/lib/libproc.dylib")
        function = library.proc_pidpath
        function.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        function.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(4096)
        if function(pid, buffer, len(buffer)) <= 0:
            raise ValueError("executable path unavailable")
        path = Path(os.fsdecode(buffer.value))
        if not path.is_absolute():
            raise ValueError("non-absolute executable path")
        return path.resolve()
    except (OSError, AttributeError, ValueError) as exc:
        raise UpdateError(
            "не удалось проверить executable Claude/ChatGPT; закройте клиент вручную"
        ) from exc


def client_bundle_root(path: Path) -> Path | None:
    parts = path.parts
    for index, part in enumerate(parts[:-1]):
        if part.endswith(".app") and parts[index + 1] == "Contents":
            return Path(*parts[:index + 1])
    return None


def node_process_arguments(pid: int) -> list[str]:
    """Inspect one verified Node process locally; never log its arguments."""
    try:
        library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        function = library.sysctl
        function.argtypes = [
            ctypes.POINTER(ctypes.c_int), ctypes.c_uint, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t,
        ]
        function.restype = ctypes.c_int
        query = (ctypes.c_int * 3)(1, 49, pid)  # CTL_KERN, KERN_PROCARGS2, pid
        size = ctypes.c_size_t()
        if function(query, 3, None, ctypes.byref(size), None, 0) != 0:
            raise ValueError("argument size unavailable")
        if not 4 < size.value <= MAX_NODE_ARGUMENT_BYTES:
            raise ValueError("argument buffer outside limit")
        buffer = ctypes.create_string_buffer(size.value)
        if function(query, 3, buffer, ctypes.byref(size), None, 0) != 0:
            raise ValueError("arguments unavailable")
        data = buffer.raw[:size.value]
        argc = int.from_bytes(data[:4], sys.byteorder, signed=True)
        if not 0 < argc <= 16384:
            raise ValueError("invalid argument count")
        position = data.index(b"\0", 4) + 1  # Executable path, then null padding.
        while position < len(data) and data[position] == 0:
            position += 1
        arguments = data[position:].split(b"\0", argc)
        if len(arguments) <= argc:
            raise ValueError("truncated arguments")
        return [os.fsdecode(value) for value in arguments[:argc]]
    except (OSError, AttributeError, ValueError) as exc:
        raise UpdateError(
            "не удалось проверить Node-клиент; закройте Claude CLI вручную"
        ) from exc


def node_process_directory(pid: int) -> Path:
    try:
        result = subprocess.run(
            ["/usr/sbin/lsof", "-a", "-p", str(pid), "-d", "cwd", "-Fn"],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5,
        )
        paths = [line[1:] for line in result.stdout.splitlines() if line.startswith("n")]
        if result.returncode != 0 or len(paths) != 1 or not Path(paths[0]).is_absolute():
            raise ValueError("working directory unavailable")
        return Path(paths[0])
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        raise UpdateError("не удалось проверить путь Claude CLI; закройте его вручную") from exc


def is_node_claude_cli(pid: int) -> bool:
    for argument in node_process_arguments(pid)[1:]:
        candidate = Path(argument)
        if argument.startswith("-") or candidate.name not in {"cli.js", "claude"}:
            continue
        if not candidate.is_absolute():
            candidate = node_process_directory(pid) / candidate
        candidate = candidate.resolve()
        if not (
            candidate.name == "cli.js" and candidate.parent.name == "claude-code"
            and candidate.parent.parent.name == "@anthropic-ai"
        ):
            continue
        try:
            if not candidate.is_file():
                raise ValueError("CLI entrypoint unavailable")
            with (candidate.parent / "package.json").open("rb") as source:
                package = json.load(source)
            if not isinstance(package, dict) or package.get("name") != "@anthropic-ai/claude-code":
                raise ValueError("CLI package identity mismatch")
        except (OSError, ValueError) as exc:
            raise UpdateError("не удалось проверить identity Claude CLI; закройте его вручную") from exc
        return True
    return False


def protected_client_processes(
    processes: dict[int, ClientProcess],
) -> tuple[set[str], set[int]]:
    bundle_ids: set[str] = set()
    client_pids: set[int] = set()
    names = set().union(*(values for key, values in PROTECTED_CLIENTS.items() if key))
    bundle_cache: dict[Path | None, str | None] = {}
    for process in processes.values():
        if process.uid != os.getuid():
            continue
        command = Path(process.command)
        if command.name in PROTECTED_CLIENTS[None]:
            raise UpdateError("Claude CLI работает; закройте его вручную перед обновлением")
        candidate_root = client_bundle_root(command)
        known_name = command.name in names or (
            candidate_root is not None and candidate_root.stem in names
        )
        if candidate_root is None and not known_name and command.name != "node":
            continue
        executable = client_executable_path(process.pid)
        root = client_bundle_root(executable)
        if root not in bundle_cache:
            bundle_id = None
            if root is not None:
                try:
                    with (root / "Contents/Info.plist").open("rb") as source:
                        document = plistlib.load(source)
                    if isinstance(document, dict):
                        identity = document.get("CFBundleIdentifier")
                        if isinstance(identity, str):
                            bundle_id = identity
                except (OSError, ValueError, plistlib.InvalidFileException):
                    pass
            bundle_cache[root] = bundle_id
        bundle_id = bundle_cache[root]
        if bundle_id in PROTECTED_CLIENTS and bundle_id is not None:
            bundle_ids.add(bundle_id)
            client_pids.add(process.pid)
        elif known_name:
            raise UpdateError(
                "не удалось проверить identity Claude/ChatGPT; закройте клиент вручную"
            )
        elif executable.name == "node" and is_node_claude_cli(process.pid):
            raise UpdateError("Claude CLI работает; закройте его вручную перед обновлением")
    return bundle_ids, client_pids


def client_descendants(processes: dict[int, ClientProcess], tracked: set[int]) -> set[int]:
    descendants = set(tracked)
    while True:
        added = {
            process.pid for process in processes.values()
            if process.uid == os.getuid() and process.parent_pid in descendants
        } - descendants
        if not added:
            return descendants
        descendants.update(added)


def assert_updater_outside_clients(
    processes: dict[int, ClientProcess], client_pids: set[int],
) -> None:
    pid = os.getpid()
    if pid not in processes:
        raise UpdateError("не удалось проверить родителей updater; закрытие клиентов отменено")
    visited = set()
    while pid in processes and pid not in visited:
        if pid in client_pids:
            raise UpdateError(
                "updater запущен из Claude/ChatGPT; используйте отдельный Терминал, "
                "чтобы не закрыть текущую сессию"
            )
        visited.add(pid)
        pid = processes[pid].parent_pid
    if pid in visited:
        raise UpdateError("не удалось проверить родителей updater; закрытие клиентов отменено")


def client_start_identity(pid: int) -> tuple[int, int, int]:
    class BSDInfo(ctypes.Structure):
        # macOS sys/proc_info.h: proc_bsdinfo (PROC_PIDTBSDINFO).
        _fields_ = [
            ("identity", ctypes.c_uint32 * 12), ("names", ctypes.c_char * 48),
            ("stats", ctypes.c_uint32 * 6), ("start_seconds", ctypes.c_uint64),
            ("start_microseconds", ctypes.c_uint64),
        ]
    try:
        library = ctypes.CDLL("/usr/lib/libproc.dylib")
        function = library.proc_pidinfo
        function.argtypes = [
            ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int,
        ]
        function.restype = ctypes.c_int
        info = BSDInfo()
        if function(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info)) != ctypes.sizeof(info):
            raise ValueError("process start unavailable")
        if info.identity[3] != pid or info.identity[5] != os.getuid():
            raise ValueError("process identity changed")
        return info.identity[5], info.start_seconds, info.start_microseconds
    except (OSError, AttributeError, ValueError) as exc:
        raise UpdateError("не удалось проверить время запуска дочернего процесса клиента") from exc


def live_client_tracking(
    processes: dict[int, ClientProcess], records: dict[int, tuple[int, int, int]],
) -> dict[int, tuple[int, int, int]]:
    return {
        pid: identity for pid, identity in records.items()
        if pid in processes and processes[pid].uid == os.getuid()
        and client_start_identity(pid) == identity
    }


def load_client_tracking(
    state_dir: Path, processes: dict[int, ClientProcess],
) -> dict[int, tuple[int, int, int]]:
    path = state_dir / CLIENT_TRACKING_FILENAME
    if not path.exists():
        return {}
    try:
        with path.open("rb") as source:
            payload = source.read(MAX_NODE_ARGUMENT_BYTES + 1)
        if len(payload) > MAX_NODE_ARGUMENT_BYTES:
            raise ValueError("tracking file outside limit")
        document = json.loads(payload)
        if not isinstance(document, list) or len(document) > MAX_TRACKED_CLIENT_PROCESSES:
            raise ValueError("invalid tracking records")
        records = {}
        for record in document:
            if not isinstance(record, dict) or set(record) != {"pid", "uid", "start"}:
                raise ValueError("invalid tracking identity")
            pid, uid, start = record["pid"], record["uid"], record["start"]
            if (type(pid) is not int or pid <= 0 or pid in records
                    or type(uid) is not int or uid != os.getuid()
                    or not isinstance(start, list) or len(start) != 2
                    or any(type(value) is not int or value < 0 for value in start)):
                raise ValueError("invalid tracking identity")
            records[pid] = (uid, *start)
    except (OSError, ValueError, TypeError) as exc:
        raise UpdateError("повреждён список дочерних процессов Claude/ChatGPT; обновление отменено") from exc
    return live_client_tracking(processes, records)


def save_client_tracking(
    state_dir: Path, processes: dict[int, ClientProcess],
    records: dict[int, tuple[int, int, int]], client_pids: set[int],
) -> dict[int, tuple[int, int, int]]:
    records = live_client_tracking(processes, records)
    tracked = client_descendants(processes, set(records) | client_pids)
    if len(tracked) > MAX_TRACKED_CLIENT_PROCESSES:
        raise UpdateError("слишком много дочерних процессов Claude/ChatGPT; обновление отменено")
    for pid in tracked - records.keys():
        records[pid] = client_start_identity(pid)
    path = state_dir / CLIENT_TRACKING_FILENAME
    if records:
        state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        atomic_write(path, json_bytes([
            {"pid": pid, "uid": identity[0], "start": list(identity[1:])}
            for pid, identity in sorted(records.items())
        ]))
    else:
        path.unlink(missing_ok=True)
    return records


def close_protected_clients(state_dir: Path | None = None) -> None:
    state_dir = STATE_DIR if state_dir is None else state_dir
    processes = client_process_snapshot()
    bundle_ids, client_pids = protected_client_processes(processes)
    records = load_client_tracking(state_dir, processes)
    tracked = client_descendants(processes, client_pids | set(records))
    assert_updater_outside_clients(processes, tracked)
    records = save_client_tracking(state_dir, processes, records, client_pids)
    for bundle_id in sorted(bundle_ids):
        script = (
            f'if application id "{bundle_id}" is running then '
            f'tell application id "{bundle_id}" to quit'
        )
        try:
            result = subprocess.run(
                ["/usr/bin/osascript", "-e", script], check=False,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=CLIENT_CLOSE_TIMEOUT,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise UpdateError("Claude/ChatGPT не закрылись; обновление отменено") from exc
        if result.returncode != 0:
            raise UpdateError("Claude/ChatGPT отказались закрыться; обновление отменено")
    deadline = time.monotonic() + CLIENT_CLOSE_TIMEOUT
    while True:
        processes = client_process_snapshot()
        _, remaining = protected_client_processes(processes)
        records = save_client_tracking(state_dir, processes, records, remaining)
        if not remaining and not records:
            return
        if time.monotonic() >= deadline:
            raise UpdateError(
                "Claude/ChatGPT или их дочерние процессы ещё работают; обновление отменено"
            )
        time.sleep(0.25)


def assert_protected_clients_stopped(state_dir: Path | None = None) -> None:
    state_dir = STATE_DIR if state_dir is None else state_dir
    processes = client_process_snapshot()
    _, client_pids = protected_client_processes(processes)
    if client_pids or load_client_tracking(state_dir, processes):
        raise SessionChanged(
            "Claude/ChatGPT запущены во время обновления; запись или остановка VPN отменены"
        )


class AmneziaSession(NamedTuple):
    was_running: bool
    was_connected: bool
    auto_connect: bool
    default_server_index: int


def inspect_amnezia(preferences: dict[str, Any]) -> AmneziaSession:
    gui_pids = process_ids(AMNEZIA_GUI_PROCESS)
    tunnel_running = bool(process_ids(AMNEZIA_TUNNEL_PROCESS))
    return AmneziaSession(
        was_running=bool(gui_pids),
        was_connected=tunnel_running,
        auto_connect=preferences.get("Conf.autoConnect") is True,
        default_server_index=int(preferences.get("Servers.defaultServerIndex", 0)),
    )


def session_document(session: AmneziaSession) -> dict[str, Any]:
    return {
        "was_running": session.was_running,
        "was_connected": session.was_connected,
        "auto_connect": session.auto_connect,
        "default_server_index": session.default_server_index,
    }


def load_session(value: Any) -> AmneziaSession:
    if not isinstance(value, dict):
        raise UpdateError("transaction journal не содержит Amnezia session")
    try:
        session = AmneziaSession(
            was_running=value["was_running"],
            was_connected=value["was_connected"],
            auto_connect=value["auto_connect"],
            default_server_index=value["default_server_index"],
        )
    except KeyError as exc:
        raise UpdateError("transaction journal содержит неполную Amnezia session") from exc
    if not all(isinstance(item, bool) for item in session[:3]) or not isinstance(
        session.default_server_index, int
    ):
        raise UpdateError("transaction journal содержит неверную Amnezia session")
    return session


def assert_safe_amnezia_restart(
    session: AmneziaSession, allow_vpn_reconnect: bool = False
) -> None:
    if not allow_vpn_reconnect and (session.was_running or session.was_connected):
        raise UpdateDeferred(
            "Обновление отложено: AmneziaVPN или туннель работают. "
            "Автоматическое отключение VPN запрещено. "
            "Для разового обслуживания с независимой блокировкой сети "
            "используйте --allow-vpn-reconnect."
        )


def stop_amnezia(
    session: AmneziaSession, allow_vpn_reconnect: bool = False,
    state_dir: Path | None = None,
) -> None:
    gui_pids = process_ids(AMNEZIA_GUI_PROCESS)
    tunnel_running = bool(process_ids(AMNEZIA_TUNNEL_PROCESS))
    if bool(gui_pids) != session.was_running or tunnel_running != session.was_connected:
        raise SessionChanged("состояние AmneziaVPN изменилось во время подготовки; повторите запуск")
    assert_safe_amnezia_restart(session, allow_vpn_reconnect)
    assert_protected_clients_stopped(state_dir)
    if tunnel_running and not gui_pids:
        raise UpdateError("AmneziaWG активен без GUI; безопасная запись Preferences невозможна")
    if not gui_pids:
        return

    for pid in gui_pids:
        try:
            os.kill(pid, 15)
        except ProcessLookupError:
            pass
    if not wait_for_process(AMNEZIA_GUI_PROCESS, False, 20):
        raise UpdateError("AmneziaVPN не завершилась за 20 секунд; Preferences не изменены")
    if not wait_for_process(AMNEZIA_TUNNEL_PROCESS, False, 20):
        raise UpdateError("AmneziaWG не отключился за 20 секунд; Preferences не изменены")


def relaunch_amnezia(session: AmneziaSession) -> None:
    if not session.was_running:
        return
    gui_running = bool(process_ids(AMNEZIA_GUI_PROCESS))
    tunnel_running = bool(process_ids(AMNEZIA_TUNNEL_PROCESS))
    if gui_running and (not session.was_connected or tunnel_running):
        return
    if gui_running and session.was_connected and not tunnel_running:
        raise UpdateError(
            "AmneziaVPN уже открыта без AmneziaWG-туннеля; "
            "автоматический relaunch отменён"
        )
    if gui_running:
        current_session = inspect_amnezia(export_preferences()[1])
        stop_amnezia(current_session)
    command = ["/usr/bin/open", "-a", APP_BUNDLE.stem]
    if session.was_connected and not session.auto_connect:
        command.extend(["--args", "--connect", str(session.default_server_index)])
    process = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if process.returncode != 0:
        message = process.stderr.decode(errors="replace").strip()
        raise UpdateError(f"настройки записаны, но AmneziaVPN не запустилась: {message}")
    if not wait_for_process(AMNEZIA_GUI_PROCESS, True, 20):
        raise UpdateError("настройки записаны, но процесс AmneziaVPN не появился")
    if session.was_connected and not wait_for_process(AMNEZIA_TUNNEL_PROCESS, True, 40):
        raise UpdateError("настройки записаны, но AmneziaWG не переподключился за 40 секунд")


def verify_app_version() -> str:
    try:
        with APP_INFO_PLIST.open("rb") as plist_file:
            info = plistlib.load(plist_file)
        version = str(info["CFBundleShortVersionString"])
        major = int(version.split(".", 1)[0])
    except (OSError, KeyError, ValueError, plistlib.InvalidFileException) as exc:
        raise UpdateError("не удалось определить версию AmneziaVPN") from exc
    if major != SUPPORTED_APP_MAJOR:
        raise UpdateError(
            f"AmneziaVPN {version} не поддерживается updater'ом; ожидается major {SUPPORTED_APP_MAJOR}"
        )
    return version


def apply_preferences(
    helper_path: Path,
    state_dir: Path,
    managed_path: Path,
    previous_managed: list[str],
    cidrs: list[str],
    replace_all: bool = False,
    allow_vpn_reconnect: bool = False,
) -> tuple[bool, int]:
    _, preferences = export_preferences()
    current_state = route_state(preferences)
    current_sites = current_state["sites"]
    desired_sites = merge_except_sites(current_sites, previous_managed, cidrs, replace_all)
    manual_count = len(desired_sites) - len(cidrs)
    desired_state = {
        "sites": desired_sites,
        "mode": ROUTE_MODE_VPN_ALL_EXCEPT_SITES,
        "enabled": True,
    }
    needs_change = current_state != desired_state
    if not needs_change:
        atomic_write(managed_path, json_bytes(cidrs))
        return False, manual_count

    pending_path = state_dir / PENDING_FILENAME
    session = inspect_amnezia(preferences)
    assert_safe_amnezia_restart(session, allow_vpn_reconnect)
    if session.was_running and not session.was_connected:
        raise UpdateError(
            "AmneziaVPN открыта без обнаруженного AmneziaWG-туннеля; "
            "обновление отложено до закрытия GUI или подключения AmneziaWG"
        )
    close_protected_clients(state_dir)
    atomic_write(
        pending_path,
        json_bytes({"phase": "stopping", "session": session_document(session)}),
    )
    stop_attempted = False
    route_resolved = False
    try:
        stop_attempted = True
        try:
            stop_amnezia(session, allow_vpn_reconnect, state_dir)
        except SessionChanged:
            stop_attempted = False
            pending_path.unlink()
            raise
        # После полного выхода приложение сбрасывает cached QSettings на диск.
        _, preferences = export_preferences()
        current_state = route_state(preferences)
        desired_sites = merge_except_sites(
            current_state["sites"], previous_managed, cidrs, replace_all
        )
        desired_state = {
            "sites": desired_sites,
            "mode": ROUTE_MODE_VPN_ALL_EXCEPT_SITES,
            "enabled": True,
        }
        manual_count = len(desired_sites) - len(cidrs)

        pending = {
            "phase": "writing",
            "session": session_document(session),
            "previous_managed": previous_managed,
            "desired_managed": cidrs,
            "previous_state": current_state,
            "desired_state": desired_state,
        }
        atomic_write(pending_path, json_bytes(pending))
        desired_path = state_dir / ".desired-routing-state.json"
        previous_path = state_dir / ".previous-routing-state.json"
        atomic_write(desired_path, json_bytes(desired_state))
        atomic_write(previous_path, json_bytes(current_state))
        protected_hash_before = protected_settings_hash(preferences)

        try:
            run_helper(helper_path, desired_path)
            _, verified = export_preferences()
            if route_state(verified) != desired_state:
                raise UpdateError("routing Preferences после записи не совпали с ожидаемыми")
            if protected_settings_hash(verified) != protected_hash_before:
                raise UpdateError("helper изменил защищённые настройки серверов")
            atomic_write(managed_path, json_bytes(cidrs))
            route_resolved = True
        except Exception:
            try:
                run_helper(helper_path, previous_path)
                _, rolled_back = export_preferences()
                if route_state(rolled_back) != current_state:
                    raise UpdateError("routing rollback не восстановил исходное состояние")
                if protected_settings_hash(rolled_back) != protected_hash_before:
                    raise UpdateError("routing rollback изменил защищённые настройки серверов")
                atomic_write(managed_path, json_bytes(previous_managed))
                route_resolved = True
            except Exception as rollback_error:
                raise UpdateError(
                    f"АВАРИЯ: routing rollback не удался; journal сохранён: {rollback_error}"
                ) from rollback_error
            raise
        finally:
            desired_path.unlink(missing_ok=True)
            previous_path.unlink(missing_ok=True)
    finally:
        if stop_attempted:
            relaunch_amnezia(session)
        if route_resolved:
            pending_path.unlink(missing_ok=True)

    return True, manual_count


def recover_pending_transaction(
    helper_path: Path, state_dir: Path, managed_path: Path,
    allow_vpn_reconnect: bool = False,
) -> None:
    pending_path = state_dir / PENDING_FILENAME
    if not pending_path.exists():
        return
    try:
        pending = json.loads(pending_path.read_text(encoding="utf-8"))
        phase = pending["phase"]
        saved_session = load_session(pending["session"])
    except (OSError, KeyError, json.JSONDecodeError, TypeError) as exc:
        raise UpdateError(f"повреждён transaction journal {pending_path}: {exc}") from exc
    if phase == "stopping":
        relaunch_amnezia(saved_session)
        pending_path.unlink()
        print("Восстановлена AmneziaVPN после прерванной подготовки")
        return
    if phase != "writing":
        raise UpdateError(f"transaction journal содержит неизвестную фазу {phase!r}")
    try:
        previous_managed = pending["previous_managed"]
        desired_managed = pending["desired_managed"]
        previous_state = pending["previous_state"]
        desired_state = pending["desired_state"]
    except KeyError as exc:
        raise UpdateError("transaction journal содержит неполный routing state") from exc
    if not all(isinstance(items, list) for items in (previous_managed, desired_managed)):
        raise UpdateError("transaction journal содержит неверный managed state")

    _, preferences = export_preferences()
    current_state = route_state(preferences)
    current_session = inspect_amnezia(preferences)
    if current_session.was_running and not current_session.was_connected:
        raise UpdateError(
            "Recovery отложен: AmneziaVPN открыта без обнаруженного "
            "AmneziaWG-туннеля"
        )
    if current_state == desired_state:
        atomic_write(managed_path, json_bytes(desired_managed))
        relaunch_amnezia(saved_session)
        pending_path.unlink()
        print("Восстановлен commit незавершённой routing-транзакции")
        return
    if current_state == previous_state:
        atomic_write(managed_path, json_bytes(previous_managed))
        relaunch_amnezia(saved_session)
        pending_path.unlink()
        print("Отменена незавершённая routing-транзакция")
        return

    assert_safe_amnezia_restart(current_session, allow_vpn_reconnect)
    close_protected_clients(state_dir)
    recovery_session = current_session if current_session.was_running else saved_session
    rollback_path = state_dir / ".recovery-routing-state.json"
    route_resolved = False
    stop_attempted = False
    try:
        stop_attempted = True
        try:
            stop_amnezia(current_session, allow_vpn_reconnect, state_dir)
        except SessionChanged:
            stop_attempted = False
            raise
        atomic_write(rollback_path, json_bytes(previous_state))
        run_helper(helper_path, rollback_path)
        _, verified = export_preferences()
        if route_state(verified) != previous_state:
            raise UpdateError("recovery rollback не восстановил исходный routing state")
        atomic_write(managed_path, json_bytes(previous_managed))
        route_resolved = True
        print("Выполнен rollback незавершённой routing-транзакции")
    finally:
        rollback_path.unlink(missing_ok=True)
        if stop_attempted:
            relaunch_amnezia(recovery_session)
        if route_resolved:
            pending_path.unlink(missing_ok=True)


def download_list(source: str) -> tuple[list[str], list[str]]:
    """Возвращает (домены, сети) из локального файла или по HTTPS."""
    if source.startswith("https://"):
        payload = fetch_bytes(source)
    else:
        path = Path(source).expanduser()
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise UpdateError(f"не удалось прочитать {path}: {exc}") from exc
    domains, networks = parse_import_list(payload, source)
    collapsed = validate_and_collapse(networks)
    return domains, [str(network) for network in collapsed]


# Amnezia исключает из туннеля только IPv4 (в её конфиге AllowedIPs = 0.0.0.0/0, ::/0,
# а ExceptSites разбирается регуляркой по IPv4). Значит весь IPv6 уходит в VPN всегда.
# Если у провайдера IPv6 есть, а внутри туннеля он не работает, браузер всё равно
# пробует AAAA — и сайты вроде trust.yandex.ru (платёжная форма Яндекса) виснут.
IPV6_PROBE = ("2a02:6b8::347", 443)  # trust.yandex.ru, платёжная форма Яндекса
IPV6_PROBE_TIMEOUT = 4.0


def command_output(argv: list[str], timeout: float = 5.0) -> str:
    try:
        process = subprocess.run(
            argv, check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return process.stdout.decode("utf-8", "replace")


def ipv6_default_interfaces() -> set[str]:
    """Интерфейсы, на которые смотрит дефолт IPv6 (default, ::/0, ::/1)."""
    interfaces: set[str] = set()
    for line in command_output(["/usr/sbin/netstat", "-rn", "-f", "inet6"]).splitlines():
        columns = line.split()
        if len(columns) < 4 or columns[0] not in {"default", "::/0", "::/1"}:
            continue
        # Флаг I — маршрут через link-local шлюз самого интерфейса: такие строки
        # netstat печатает для каждого спящего utun, дефолтом они не являются.
        if "I" in columns[2]:
            continue
        interfaces.add(columns[-1])
    return interfaces


def native_ipv6_devices() -> set[str]:
    """Физические интерфейсы с глобальным IPv6-адресом (2000::/3)."""
    devices: set[str] = set()
    device = ""
    for line in command_output(["/sbin/ifconfig", "-a"]).splitlines():
        if line and not line[0].isspace():
            device = line.split(":", 1)[0]
            continue
        stripped = line.strip()
        if not stripped.startswith("inet6 ") or device.startswith("utun"):
            continue
        address = stripped.split()[1].split("%", 1)[0]
        try:
            parsed = ipaddress.IPv6Address(address)
        except ValueError:
            continue
        if parsed in ipaddress.IPv6Network("2000::/3"):
            devices.add(device)
    return devices


def ipv6_reachable() -> bool:
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            probe.settimeout(IPV6_PROBE_TIMEOUT)
            probe.connect(IPV6_PROBE)
        return True
    except OSError:
        return False


def network_service_for(devices: Iterable[str]) -> str:
    """Имя сетевого сервиса («Wi-Fi») для устройства из networksetup."""
    wanted = set(devices)
    service = ""
    for line in command_output(["/usr/sbin/networksetup", "-listnetworkserviceorder"]).splitlines():
        stripped = line.strip()
        if stripped.startswith("(") and ")" in stripped and "Hardware Port" not in stripped:
            service = stripped.split(")", 1)[1].strip()
            continue
        if "Device:" in stripped:
            device = stripped.rsplit("Device:", 1)[1].strip(" )")
            if device in wanted and service:
                return service
    return "Wi-Fi"


def warn_broken_ipv6() -> None:
    """Печатает предупреждение, если IPv6 уходит в туннель и там не работает."""
    tunnels = {name for name in ipv6_default_interfaces() if name.startswith("utun")}
    if not tunnels:
        return
    devices = native_ipv6_devices()
    if not devices:
        return
    if ipv6_reachable():
        return
    service = network_service_for(devices)
    print(
        "ВНИМАНИЕ: IPv6 уходит в туннель ("
        + ", ".join(sorted(tunnels))
        + f") и там не работает: соединение с [{IPV6_PROBE[0]}]:{IPV6_PROBE[1]} не установилось.\n"
        "  Список RU Direct это не лечит: AmneziaVPN исключает из VPN только IPv4.\n"
        "  Сайты с AAAA (Яндекс Директ и его оплата, trust.yandex.ru, pay.yandex.ru, yandex.ru)\n"
        "  браузер пробует по IPv6 через VPN — страницы и платёжные формы виснут или не грузятся.\n"
        f'  Отключите IPv6 на активном сетевом сервисе:  sudo networksetup -setv6off "{service}"\n'
        f'  Вернуть обратно:                             sudo networksetup -setv6automatic "{service}"'
    )


def update(
    dry_run: bool = False,
    recover_only: bool = False,
    state_dir: Path = STATE_DIR,
    source: str = LIST_FULL,
    replace_all: bool = False,
    with_domains: bool = False,
    allow_vpn_reconnect: bool = False,
) -> int:
    if sys.platform != "darwin":
        raise UpdateError("скрипт предназначен только для macOS")
    if not APP_BUNDLE.is_dir():
        raise UpdateError(f"не найдена {APP_BUNDLE}")
    if recover_only:
        helper_path = Path(__file__).with_name("set-amnezia-routes")
        if not helper_path.is_file() or not os.access(helper_path, os.X_OK):
            raise UpdateError(f"не найден исполняемый helper {helper_path}")
        state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock_path = state_dir / "update.lock"
        with lock_path.open("a+") as lock_file:
            try:
                fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise UpdateError("другой updater ещё работает") from exc
            recover_pending_transaction(
                helper_path, state_dir, state_dir / "managed-cidrs.json", allow_vpn_reconnect
            )
        print("Recovery завершён; незавершённых routing-транзакций нет")
        return 0
    app_version = verify_app_version()
    load_protected_ips(Path(__file__).with_name(PROTECTED_IPS_FILENAME))

    warn_broken_ipv6()

    if dry_run:
        domains, cidrs = download_list(source)
        print(
            f"Проверено {len(domains)} доменов и {len(cidrs)} сетей IPv4 "
            f"для AmneziaVPN {app_version}"
        )
        if domains and not with_domains:
            print(f"Домены ({len(domains)}) в macOS не применяются: Amnezia маршрутизирует только IP")
        return 0

    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state_dir, 0o700)
    helper_path = Path(__file__).with_name("set-amnezia-routes")
    if not helper_path.is_file() or not os.access(helper_path, os.X_OK):
        raise UpdateError(f"не найден исполняемый helper {helper_path}")

    lock_path = state_dir / "update.lock"
    with lock_path.open("a+") as lock_file:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("Другой updater уже работает, пропускаю запуск")
            return 0

        managed_path = state_dir / "managed-cidrs.json"
        # Recovery не зависит от сети: сначала обязательно вернуть VPN/session.
        recover_pending_transaction(helper_path, state_dir, managed_path, allow_vpn_reconnect)
        domains, cidrs = download_list(source)
        skipped_domains = 0
        if not with_domains:
            # Мёртвый груз для macOS-клиента: только раздувает список и UI.
            skipped_domains = len(domains)
            domains = []
        entries = domains + cidrs
        print(
            f"Проверено {len(domains)} доменов и {len(cidrs)} сетей IPv4 "
            f"для AmneziaVPN {app_version}"
            + (f", пропущено доменов: {skipped_domains}" if skipped_domains else "")
        )
        previous_managed = load_string_list(managed_path)
        try:
            changed, manual_count = apply_preferences(
                helper_path, state_dir, managed_path, previous_managed, entries,
                replace_all, allow_vpn_reconnect
            )
        except UpdateDeferred as exc:
            # Не путать скачанный снимок с применённым списком или transaction journal.
            atomic_write(state_dir / "deferred-update.json", json_bytes({
                "deferred": True,
                "source": source,
                "entries": entries,
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "reason": str(exc),
            }))
            print(str(exc))
            return 0

        import_payload = [{"hostname": value, "ip": ""} for value in entries]
        atomic_write(state_dir / "amnezia-split-routes.json", json_bytes(import_payload))
        status = {
            "changed": changed,
            "source": source,
            "domain_count": len(domains),
            "domains_skipped": skipped_domains,
            "cidr_count": len(cidrs),
            "entry_count": len(entries),
            "manual_entries_preserved": manual_count,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        atomic_write(state_dir / "status.json", json_bytes(status))
        (state_dir / "deferred-update.json").unlink(missing_ok=True)

    if changed:
        print(
            f"AmneziaVPN обновлена: {len(entries)} записей, "
            f"сохранено ручных записей: {manual_count}. "
            + ("GUI и AmneziaWG перезапущены по разовому разрешению."
               if allow_vpn_reconnect else "VPN не переподключался.")
        )
    else:
        print(f"AmneziaVPN уже содержит актуальные {len(entries)} записей")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="скачать и проверить без записи")
    parser.add_argument(
        "--lite", action="store_true", help="только ядро списка вместо полного"
    )
    parser.add_argument(
        "--source",
        help="URL или путь к JSON-списку (по умолчанию dist/amnezia-ru-direct-ip.json из репозитория)",
    )
    parser.add_argument(
        "--replace-all",
        action="store_true",
        help="стереть все прежние записи Amnezia, включая ручные, и оставить только список",
    )
    parser.add_argument(
        "--with-domains",
        action="store_true",
        help="записывать и домены из списка (macOS-клиент Amnezia их игнорирует)",
    )
    parser.add_argument("--recover-only", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--allow-vpn-reconnect", action="store_true",
        help="разово разрешить переподключение VPN; требует независимой блокировки сети",
    )
    parser.add_argument("--state-dir", type=Path, default=STATE_DIR, help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    source = arguments.source or (LIST_LITE if arguments.lite else LIST_FULL)
    try:
        return update(
            dry_run=arguments.dry_run,
            recover_only=arguments.recover_only,
            state_dir=arguments.state_dir,
            source=source,
            replace_all=arguments.replace_all,
            with_domains=arguments.with_domains,
            allow_vpn_reconnect=arguments.allow_vpn_reconnect,
        )
    except UpdateError as exc:
        print(f"ОШИБКА: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
