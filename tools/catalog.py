#!/usr/bin/env python3
"""Загрузка и валидация каталога российских сервисов (data/services/*.json)."""

from __future__ import annotations

import bisect
import gzip
import io
import ipaddress
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parent.parent
SERVICES_DIR = ROOT / "data" / "services"
PREFIXES_FILE = ROOT / "data" / "prefixes.json"
EXTERNAL_FILE = ROOT / "data" / "external.json"
DOMAIN_IPS_FILE = ROOT / "data" / "domain-ips.json"
SOURCES_FILE = ROOT / "config" / "external-sources.json"
# Полный список дополнительно ограничен 3900 записями в сборщике (апдейтеры — 4000).
MAX_EXTERNAL_DOMAINS = 1500
MAX_EXTERNAL_ROOTS = 2500
# Столько IPv4 кладём в поле ips одной доменной записи.
MAX_DOMAIN_IPS = 8
MAX_TABLE_BYTES = 33_554_432
MAX_TABLE_UNPACKED_BYTES = 134_217_728
# Локальные и служебные зоны: в чужих списках встречаются, в direct им не место.
LOCAL_SUFFIXES = (
    ".arpa", ".local", ".localhost", ".lan", ".internal", ".home", ".invalid", ".test", ".example",
)

TIERS = ("core", "extended")
HOSTNAME = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
)
# Шире /12 не пускаем: такая сеть означала бы «пол-интернета мимо VPN».
MIN_PREFIXLEN = 12
MAX_PREFIXLEN = 24
MAX_ADDRESSES = 40_000_000

# Глобальные CDN/облака: их адреса не должны идти мимо VPN.
DENY_ASN = {
    13335,  # Cloudflare
    15169, 396982, 19527,  # Google
    16509, 14618, 8987,  # Amazon
    8075, 8068, 8069,  # Microsoft
    20940, 16625, 12222, 21342, 32787,  # Akamai
    54113,  # Fastly
    32934,  # Meta
    2906,  # Netflix
    13414,  # X/Twitter
    36459,  # GitHub
    14061,  # DigitalOcean
    24940,  # Hetzner
    16276,  # OVH
    63949, 20473,  # Akamai/Linode, Vultr
    60068, 9009,  # Datacamp/M247
}
# Общие хостинг-провайдеры РФ: отдельные /32 сайтов на них разрешены, но разворачивать
# такие ASN целиком через автосбор конкурентов нельзя (там живут и прокси/чужие узлы).
SHARED_HOSTING_ASN = {
    49505, 50340,  # Selectel
    197695,  # Reg.ru
    9123,  # Timeweb
    198610,  # Beget
    210644,  # Aeza
    48282,  # VDSina
    25532,  # Masterhost
    210079,  # Eurobyte
    211183,  # AdminVPS
}
# Российские anti-DDoS/скрабберы и CDN: юрлицо может быть вне РФ, но за префиксами стоят RU-сайты.
ALLOW_ASN = {
    197068, 209671, 211112, 200449,  # Qrator Labs
    51115,  # HighLoadLab (HLL / Qrator CDN)
    59796, 43298,  # StormWall / StormNetworks
    57724, 262254, 59692, 49612,  # DDoS-Guard (включая IQWeb и dCAPTCHA)
    208972, 201706,  # Servicepipe
    60922,  # Variti (антибот и защита от DDoS)
    209030,  # Kaspersky DDoS Protection
    207104,  # BI.ZONE WAF (Сбер)
    202614,  # Kinescope CDN (российский видеоплеер курсов и сервисов)
}


class CatalogError(RuntimeError):
    pass


def is_russian(asn: int, country: str, as_name: str) -> bool:
    """RU-принадлежность: страна IP, либо страна юрлица AS, либо RU anti-DDoS."""
    if asn in ALLOW_ASN:
        return True
    if country == "RU":
        return True
    # Cymru отдаёт имя вида "OZON-BANK-AS - LLC OZON BANK, RU" — хвост это страна юрлица.
    return as_name.rstrip().upper().endswith(", RU")


def http_get(url: str, max_bytes: int, timeout: int = 70) -> bytes:
    """HTTPS-загрузка через curl: только https, с потолком по размеру и времени."""
    curl = shutil.which("curl")
    if curl is None:
        raise CatalogError("нужен curl")
    per_attempt = max(15, timeout - 10)
    try:
        process = subprocess.run(
            [
                curl, "--fail", "--silent", "--show-error", "--location",
                "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2",
                "--max-filesize", str(max_bytes),
                "--connect-timeout", "10", "--max-time", str(per_attempt),
                "--retry", "3", "--retry-delay", "2",
                "--user-agent", "amnezia-split-route-sync/2.0",
                url,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=per_attempt * 4 + 15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CatalogError(f"запрос не удался: {url}") from exc
    if process.returncode != 0:
        raise CatalogError(f"HTTP-ошибка при запросе {url}: {process.stderr.decode()[:200]}")
    if len(process.stdout) > max_bytes:
        raise CatalogError(f"ответ {url} больше лимита {max_bytes} байт")
    return process.stdout


class AsnTable:
    """IP→(ASN, страна, имя AS) по диапазонам из ip2asn-v4."""

    __slots__ = ("_starts", "_rows", "announced")

    def __init__(self, rows: list[tuple[int, int, int, str, str]]) -> None:
        ordered = sorted(rows)
        self._starts = [row[0] for row in ordered]
        self._rows = ordered
        # Сколько адресов анонсирует каждый ASN — по этому размеру отличаем
        # контентную площадку от оператора связи.
        self.announced: dict[int, int] = {}
        for start, end, asn, _country, _name in ordered:
            self.announced[asn] = self.announced.get(asn, 0) + (end - start + 1)
        if any(left[1] >= right[0] for left, right in zip(ordered, ordered[1:])):
            raise CatalogError("таблица IP→ASN содержит перекрывающиеся диапазоны")

    def __len__(self) -> int:
        return len(self._rows)

    @classmethod
    def from_tsv(cls, text: str) -> "AsnTable":
        rows: list[tuple[int, int, int, str, str]] = []
        for line in text.splitlines():
            fields = line.split("\t")
            if len(fields) < 5:
                continue
            try:
                start = int(ipaddress.IPv4Address(fields[0]))
                end = int(ipaddress.IPv4Address(fields[1]))
            except (ipaddress.AddressValueError, ValueError):
                continue
            if end < start or not fields[2].isdigit():
                continue
            rows.append((start, end, int(fields[2]), fields[3].strip(), fields[4].strip()))
        if len(rows) < 100_000:
            raise CatalogError(f"таблица IP→ASN подозрительно мала: {len(rows)} строк")
        return cls(rows)

    def lookup(self, address: int) -> tuple[int, int, int, str, str] | None:
        """(начало диапазона, конец, ASN, страна, имя AS) для адреса."""
        index = bisect.bisect_right(self._starts, address) - 1
        if index < 0:
            return None
        row = self._rows[index]
        if not row[0] <= address <= row[1] or row[2] == 0:
            return None
        return row

    def covering_rows(self, network: ipaddress.IPv4Network) -> list[tuple]:
        """Все диапазоны сети; пустой результат при любом пробеле в таблице."""
        cursor, end = int(network.network_address), int(network.broadcast_address)
        index = bisect.bisect_right(self._starts, cursor) - 1
        rows = []
        while cursor <= end:
            if index < 0 or index >= len(self._rows):
                return []
            row = self._rows[index]
            if not row[0] <= cursor <= row[1] or row[2] == 0:
                return []
            rows.append(row)
            cursor = row[1] + 1
            index += 1
        return rows


def unpack_asn_table(payload: bytes) -> AsnTable:
    """ip2asn-v4.tsv или .tsv.gz → таблица, с потолком на распакованный размер."""
    if len(payload) > MAX_TABLE_UNPACKED_BYTES:
        raise CatalogError("таблица IP→ASN превышает лимит размера")
    if payload[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=io.BytesIO(payload)) as stream:
            payload = stream.read(MAX_TABLE_UNPACKED_BYTES + 1)
        if len(payload) > MAX_TABLE_UNPACKED_BYTES:
            raise CatalogError("распакованная таблица IP→ASN превышает лимит размера")
    return AsnTable.from_tsv(payload.decode("utf-8"))


def asn_table_url(path: Path = SOURCES_FILE) -> str:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CatalogError(f"{path.name}: не читается ({exc})") from exc
    table = document.get("asn_table") if isinstance(document, dict) else None
    if not isinstance(table, dict) or not isinstance(table.get("url"), str):
        raise CatalogError(f"{path.name}: нет asn_table.url")
    return table["url"]


def load_asn_table(url: str, local: Path | None = None) -> AsnTable:
    payload = local.read_bytes() if local else http_get(url, MAX_TABLE_BYTES, 120)
    return unpack_asn_table(payload)


class Service:
    __slots__ = ("id", "title", "tier", "category", "category_title", "domains", "cidrs", "notes")

    def __init__(self, **kwargs: Any) -> None:
        for name in self.__slots__:
            setattr(self, name, kwargs[name])

    def as_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__slots__}


def normalize_hostname(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise CatalogError(f"{where}: домен должен быть строкой")
    hostname = value.strip().lower().rstrip(".")
    if not HOSTNAME.fullmatch(hostname):
        try:
            hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise CatalogError(f"{where}: некорректный домен {value!r}") from exc
    if not HOSTNAME.fullmatch(hostname) or len(hostname) > 253:
        raise CatalogError(f"{where}: некорректный домен {value!r}")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return hostname
    raise CatalogError(f"{where}: {value!r} — это IP, его место в cidrs")


def parse_network(value: Any, where: str) -> ipaddress.IPv4Network:
    if not isinstance(value, str):
        raise CatalogError(f"{where}: CIDR должен быть строкой")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise CatalogError(f"{where}: некорректный CIDR {value!r}") from exc
    if network.version != 4:
        raise CatalogError(f"{where}: поддерживается только IPv4, получено {value!r}")
    if network.prefixlen < MIN_PREFIXLEN:
        raise CatalogError(f"{where}: сеть {value} слишком широкая")
    if not network.is_global:
        raise CatalogError(f"{where}: сеть {value} не является публичной")
    return network


def load_catalog(directory: Path = SERVICES_DIR) -> list[Service]:
    files = sorted(directory.glob("*.json"), key=lambda path: (len(path.name), path.name))
    if not files:
        raise CatalogError(f"каталог пуст: {directory}")
    services: list[Service] = []
    seen_ids: set[str] = set()
    for path in files:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CatalogError(f"{path.name}: не читается ({exc})") from exc
        if not isinstance(document, dict) or document.get("version") != 1:
            raise CatalogError(f"{path.name}: ожидается объект с version=1")
        category = document.get("category")
        category_title = document.get("title")
        entries = document.get("services")
        if not isinstance(category, str) or not isinstance(category_title, str):
            raise CatalogError(f"{path.name}: нет category/title")
        if not isinstance(entries, list) or not entries:
            raise CatalogError(f"{path.name}: пустой список services")
        for entry in entries:
            if not isinstance(entry, dict):
                raise CatalogError(f"{path.name}: сервис должен быть объектом")
            service_id = entry.get("id")
            title = entry.get("title")
            tier = entry.get("tier")
            where = f"{path.name}:{service_id}"
            if not isinstance(service_id, str) or not re.fullmatch(r"[a-z0-9-]{2,40}", service_id):
                raise CatalogError(f"{path.name}: некорректный id сервиса {service_id!r}")
            if service_id in seen_ids:
                raise CatalogError(f"{path.name}: дублирующийся id сервиса {service_id}")
            seen_ids.add(service_id)
            if not isinstance(title, str) or not title.strip():
                raise CatalogError(f"{where}: нет title")
            if tier not in TIERS:
                raise CatalogError(f"{where}: tier должен быть core или extended")
            domains = entry.get("domains", [])
            cidrs = entry.get("cidrs", [])
            if not isinstance(domains, list) or not isinstance(cidrs, list):
                raise CatalogError(f"{where}: domains и cidrs должны быть списками")
            if not domains and not cidrs:
                raise CatalogError(f"{where}: сервис без доменов и без CIDR")
            parsed_domains = sorted({normalize_hostname(value, where) for value in domains})
            parsed_cidrs = sorted(
                {str(parse_network(value, where)) for value in cidrs},
                key=lambda value: ipaddress.ip_network(value),
            )
            services.append(
                Service(
                    id=service_id,
                    title=title.strip(),
                    tier=tier,
                    category=category,
                    category_title=category_title,
                    domains=parsed_domains,
                    cidrs=parsed_cidrs,
                    notes=entry.get("notes", ""),
                )
            )
    return services


def catalog_domains(services: Iterable[Service], tiers: Iterable[str] = TIERS) -> list[str]:
    allowed = set(tiers)
    return sorted({
        domain
        for service in services
        if service.tier in allowed
        for domain in service.domains
    })


def domain_owner(services: Iterable[Service]) -> dict[str, list[str]]:
    owners: dict[str, list[str]] = {}
    for service in services:
        for domain in service.domains:
            owners.setdefault(domain, []).append(service.id)
    return owners


def external_domain_parent(domain: str, trusted: set[str]) -> str | None:
    """Ближайший родитель из ручного каталога; совпадение только по границе метки."""
    if domain in trusted:
        return None
    labels = domain.split(".")
    for index in range(1, len(labels) - 1):
        parent = ".".join(labels[index:])
        if parent in trusted:
            return parent
    return None


def load_external_domains(services: Iterable[Service], path: Path = EXTERNAL_FILE) -> dict[str, dict]:
    """Повторно проверяем привязку импортированных поддоменов к ручному каталогу."""
    if not path.exists():
        return {}
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("version") != 1:
        raise CatalogError(f"{path.name}: ожидается объект с version=1")
    entries = document.get("domains", {})
    if not isinstance(entries, dict) or len(entries) > MAX_EXTERNAL_DOMAINS:
        raise CatalogError(f"{path.name}: неверный список внешних доменов или превышен лимит")
    trusted = set(catalog_domains(services))
    for domain, meta in entries.items():
        if normalize_hostname(domain, path.name) != domain or not isinstance(meta, dict):
            raise CatalogError(f"{path.name}: некорректный внешний домен {domain!r}")
        parent = external_domain_parent(domain, trusted)
        if parent is None or meta.get("parent") != parent:
            raise CatalogError(f"{path.name}: {domain} не является поддоменом сервиса каталога")
        if not isinstance(meta.get("sources"), list) or not meta["sources"] or not all(
            isinstance(source, str) and source for source in meta["sources"]
        ):
            raise CatalogError(f"{path.name}: нет источников домена {domain}")
    return entries


def load_external_roots(services: Iterable[Service], path: Path = EXTERNAL_FILE) -> dict[str, dict]:
    """Корневые домены из внешних списков: вне каталога, все IP уже проверены по ASN."""
    if not path.exists():
        return {}
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("version") != 1:
        raise CatalogError(f"{path.name}: ожидается объект с version=1")
    entries = document.get("roots", {})
    if not isinstance(entries, dict) or len(entries) > MAX_EXTERNAL_ROOTS:
        raise CatalogError(f"{path.name}: неверный список корневых доменов или превышен лимит")
    trusted = set(catalog_domains(services))
    for domain, meta in entries.items():
        if normalize_hostname(domain, path.name) != domain or not isinstance(meta, dict):
            raise CatalogError(f"{path.name}: некорректный корневой домен {domain!r}")
        if domain.endswith(LOCAL_SUFFIXES):
            raise CatalogError(f"{path.name}: {domain} — локальная зона")
        # Поддомен каталога живёт в domains с привязкой к родителю, а не здесь.
        if domain in trusted or external_domain_parent(domain, trusted) is not None:
            raise CatalogError(f"{path.name}: {domain} уже покрыт каталогом")
        sources = meta.get("sources")
        if not isinstance(sources, list) or not sources or not all(
            isinstance(source, str) and source for source in sources
        ):
            raise CatalogError(f"{path.name}: нет источников корня {domain}")
        asns = meta.get("asn")
        if not isinstance(asns, list) or not asns or not all(
            isinstance(asn, int) and not isinstance(asn, bool) and asn not in DENY_ASN
            for asn in asns
        ):
            raise CatalogError(f"{path.name}: недопустимые ASN у корня {domain}")
    return entries


def load_domain_ips(path: Path = DOMAIN_IPS_FILE) -> dict[str, list[str]]:
    """Снимок A-записей доменов (tools/resolve_domains.py); нет файла — пустой."""
    if not path.exists():
        return {}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CatalogError(f"{path.name}: не читается ({exc})") from exc
    if not isinstance(document, dict) or document.get("version") != 1:
        raise CatalogError(f"{path.name}: ожидается объект с version=1")
    entries = document.get("domains")
    if not isinstance(entries, dict):
        raise CatalogError(f"{path.name}: нет объекта domains")
    result: dict[str, list[str]] = {}
    for domain, addresses in entries.items():
        if not isinstance(domain, str) or normalize_hostname(domain, path.name) != domain:
            raise CatalogError(f"{path.name}: некорректный домен {domain!r}")
        if not isinstance(addresses, list) or len(addresses) > MAX_DOMAIN_IPS:
            raise CatalogError(f"{path.name}: {domain} — ожидается список до {MAX_DOMAIN_IPS} IP")
        parsed = []
        for value in addresses:
            try:
                address = ipaddress.IPv4Address(value)
            except (ipaddress.AddressValueError, ValueError, TypeError) as exc:
                raise CatalogError(f"{path.name}: {domain} — некорректный IPv4 {value!r}") from exc
            if not address.is_global or str(address) != value:
                raise CatalogError(f"{path.name}: {domain} — {value} не публичный IPv4")
            parsed.append(value)
        if len(set(parsed)) != len(parsed):
            raise CatalogError(f"{path.name}: {domain} — повторяющиеся IP")
        result[domain] = sorted(parsed, key=ipaddress.IPv4Address)
    return result


def load_prefixes(path: Path = PREFIXES_FILE) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CatalogError(f"{path.name}: не читается ({exc})") from exc
    if not isinstance(document, dict) or document.get("version") != 1:
        raise CatalogError(f"{path.name}: ожидается объект с version=1")
    prefixes = document.get("prefixes")
    if not isinstance(prefixes, dict):
        raise CatalogError(f"{path.name}: нет объекта prefixes")
    result: dict[str, dict[str, Any]] = {}
    for value, meta in prefixes.items():
        network = parse_network(value, path.name)
        if not isinstance(meta, dict):
            raise CatalogError(f"{path.name}: метаданные {value} должны быть объектом")
        result[str(network)] = meta
    return result


def collapse(networks: Iterable[ipaddress.IPv4Network]) -> list[ipaddress.IPv4Network]:
    collapsed = sorted(
        ipaddress.collapse_addresses(list(networks)),
        key=lambda network: (int(network.network_address), network.prefixlen),
    )
    total = sum(network.num_addresses for network in collapsed)
    if total > MAX_ADDRESSES:
        raise CatalogError(f"суммарное покрытие {total} адресов превышает лимит {MAX_ADDRESSES}")
    return collapsed


def json_bytes(payload: Any) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(payload)
    temporary.replace(path)


if __name__ == "__main__":
    catalog = load_catalog()
    print(
        f"OK: {len(catalog)} сервисов, "
        f"{len(catalog_domains(catalog))} доменов, "
        f"{sum(len(service.cidrs) for service in catalog)} ручных CIDR"
    )
