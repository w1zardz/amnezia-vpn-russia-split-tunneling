#!/usr/bin/env python3
"""Обновляет data/prefixes.json: домены каталога → IP → анонсируемые BGP-префиксы.

Механика:
  1. резолвим все домены каталога (A-записи);
  2. один bulk-запрос в Team Cymru (whois.cymru.com:43) отдаёт ASN, страну
     и реальный анонсируемый префикс для каждого IP;
  3. проверяем весь диапазон по IP→ASN: страна RU и ожидаемый владелец;
     на общем хостинге оставляем /32, глобальные CDN исключаем;
  4. по желанию разворачиваем целые ASN из config/asn-expand.json через RIPEstat;
  5. только с --with-external подмешиваем проверенные внешние кандидаты;
     в обычной сборке и ежедневном workflow они отключены.

Смысл: Amnezia резолвит импортированные домены один раз, а VK/Яндекс/WB крутят
CDN — поэтому в список едут не /32 из локального DNS, а сети целиком.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import socket
import sys
import time
from datetime import date
from pathlib import Path
from typing import Iterable

import catalog
import resolve_domains

ROOT = catalog.ROOT
ASN_EXPAND_FILE = ROOT / "config" / "asn-expand.json"
CYMRU_HOST = "whois.cymru.com"
CYMRU_PORT = 43
CYMRU_CHUNK = 500
RIPESTAT_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
MAX_RIPESTAT_BYTES = 4_194_304
RIPESTAT_WORKERS = 3
MAX_CYMRU_BYTES = 4_194_304
# Курируемые ленты конкурентов (подсети сервисов и SmartCaptcha): добирают префиксы
# наших проверенных ASN из config/asn-expand.json, если RIPEstat или единичный DNS их не отдал.
# Сети вне наших ASN, провайдеры связи и зарубежные диапазоны отсекаются строго по ip2asn-v4.
COMPETITOR_SERVICE_FEEDS: tuple[tuple[str, str, str], ...] = (
    (
        "kyoresuas-standard",
        "cidr",
        "https://github.com/kyoresuas/ru-direct/releases/download/latest/ru-standard.ipv4.txt",
    ),
    (
        "lib4u-lite",
        "amnezia",
        "https://raw.githubusercontent.com/lib4u/amnezia-tunneling-ru/main/amnezia-ip-lite.json",
    ),
    (
        "opencck-russia-all",
        "amnezia",
        "https://russia.iplist.opencck.org/?format=amnezia&data=cidr4",
    ),
    (
        "mobile-whitelist-cidr",
        "cidr",
        "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/cidrwhitelist.txt",
    ),
    (
        "pincetgore-ip-list",
        "amnezia",
        "https://github.com/pincetgore/amnezia-app-ru-list/releases/download/latest/ip-list.json",
    ),
    (
        "pvd-dog-no-vpn",
        "amnezia",
        "https://raw.githubusercontent.com/pvd-dog/russia-no-vpn-list/main/russia-no-vpn-list_by_%40pvd_dog.json",
    ),
)
# Доменные ленты конкурентов: ищем новые поддомены наших курируемых сервисов
# (например новые узлы капчи, корзин WB/Ozon, шлюзов банков и Госуслуг).
COMPETITOR_SUBDOMAIN_FEEDS: tuple[tuple[str, str, str], ...] = (
    (
        "kyoresuas-domains",
        "domains",
        "https://github.com/kyoresuas/ru-direct/releases/download/latest/ru-standard.domains.txt",
    ),
    (
        "lib4u-domains",
        "amnezia",
        "https://raw.githubusercontent.com/lib4u/amnezia-tunneling-ru/main/amnezia.json",
    ),
    (
        "mobile-whitelist-domains",
        "domains",
        "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt",
    ),
    (
        "unrkn-domains",
        "domains",
        "https://raw.githubusercontent.com/UnRKN/ru-blocklist/main/ru-blocklist.txt",
    ),
)
# Источники новых сервисных/капчевых ASN у конкурентов (только малые не-провайдерские AS РФ).
COMPETITOR_ASN_CONFIGS: tuple[tuple[str, str, str], ...] = (
    (
        "runetfreedom-geoip",
        "runetfreedom",
        "https://raw.githubusercontent.com/runetfreedom/russia-blocked-geoip/main/config.json",
    ),
    (
        "kyoresuas-payments",
        "kyoresuas",
        "https://raw.githubusercontent.com/kyoresuas/ru-direct/main/config/services/payments.json",
    ),
    (
        "kyoresuas-yandex",
        "kyoresuas",
        "https://raw.githubusercontent.com/kyoresuas/ru-direct/main/config/services/yandex.json",
    ),
    (
        "kyoresuas-government",
        "kyoresuas",
        "https://raw.githubusercontent.com/kyoresuas/ru-direct/main/config/services/government.json",
    ),
    (
        "kyoresuas-social",
        "kyoresuas",
        "https://raw.githubusercontent.com/kyoresuas/ru-direct/main/config/services/social.json",
    ),
    (
        "kyoresuas-marketplaces",
        "kyoresuas",
        "https://raw.githubusercontent.com/kyoresuas/ru-direct/main/config/services/marketplaces.json",
    ),
)
MAX_AUTO_DISCOVERED_ASN_IPS = 131_072
MAX_COMPETITOR_SUBDOMAINS = 600
# Запас до лимита сборщика MAX_EFFECTIVE_ROUTES=1450 (апдейтеры macOS/Windows держат 1500),
# чтобы после добавления DNS /32 список оставался компактным (~900-1050 маршрутов) и никогда не падал.
MAX_AUTO_ROUTES = 850
TELEGRAM_SUBNETS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "91.108.56.0/22",
        "91.108.4.0/22",
        "91.108.8.0/22",
        "91.108.16.0/22",
        "91.108.12.0/22",
        "149.154.160.0/20",
        "91.105.192.0/23",
        "91.108.20.0/22",
        "185.76.151.0/24",
    )
)

# Политика по ASN и допустимая ширина сети общие с импортом внешних списков.
DENY_ASN = catalog.DENY_ASN
ALLOW_ASN = catalog.ALLOW_ASN
MIN_PREFIXLEN = catalog.MIN_PREFIXLEN
MAX_PREFIXLEN = catalog.MAX_PREFIXLEN
is_russian = catalog.is_russian


class RefreshError(RuntimeError):
    pass


def resolve_all(domains: Iterable[str], workers: int = 48) -> dict[str, list[str]]:
    domain_list = list(domains)

    def resolve_one(hostname: str) -> tuple[str, list[str]]:
        try:
            answers = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        except (socket.gaierror, UnicodeError, OSError):
            return hostname, []
        addresses = set()
        for answer in answers:
            try:
                address = ipaddress.ip_address(answer[4][0])
            except ValueError:
                continue
            if address.version == 4 and address.is_global:
                addresses.add(str(address))
        return hostname, sorted(addresses)

    result: dict[str, set[str]] = {hostname: set() for hostname in domain_list}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for hostname, addresses in executor.map(resolve_one, domain_list):
            result[hostname].update(addresses)
    # Раннер GitHub находится за рубежом: добираем российские ноды через Google ECS и Яндекс DoT.
    if domain_list:
        try:
            multi = resolve_domains.resolve_many(domain_list)
            for hostname, answer in multi.items():
                if hostname in result:
                    result[hostname].update(answer.addresses)
        except resolve_domains.ResolveError as exc:
            print(f"ПРЕДУПРЕЖДЕНИЕ: дополнительный DoH/DoT-резолв пропущен ({exc})", file=sys.stderr)
    return {hostname: sorted(values, key=ipaddress.IPv4Address) for hostname, values in result.items()}


def cymru_lookup(addresses: Iterable[str]) -> dict[str, tuple[int, str, str, str]]:
    """IP → (ASN, префикс, страна, имя AS)."""
    unique = sorted(set(addresses))
    mapping: dict[str, tuple[int, str, str, str]] = {}
    for start in range(0, len(unique), CYMRU_CHUNK):
        chunk = unique[start : start + CYMRU_CHUNK]
        query = "begin\nverbose\n" + "\n".join(chunk) + "\nend\n"
        try:
            with socket.create_connection((CYMRU_HOST, CYMRU_PORT), timeout=45) as connection:
                deadline = time.monotonic() + 60
                connection.sendall(query.encode("ascii"))
                buffer = bytearray()
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RefreshError("Team Cymru: превышен общий таймаут ответа")
                    connection.settimeout(min(45, remaining))
                    piece = connection.recv(65536)
                    if not piece:
                        break
                    buffer.extend(piece)
                    if len(buffer) > MAX_CYMRU_BYTES:
                        raise RefreshError("Team Cymru: ответ превышает лимит размера")
        except OSError as exc:
            raise RefreshError(f"Team Cymru недоступен: {exc}") from exc
        for line in buffer.decode("utf-8", "replace").splitlines():
            if "|" not in line or line.lower().startswith("bulk mode"):
                continue
            fields = [field.strip() for field in line.split("|")]
            if len(fields) < 7 or not fields[0].isdigit():
                continue
            asn = int(fields[0])
            address, prefix, country, as_name = fields[1], fields[2], fields[3], fields[6]
            if asn <= 0 or address not in chunk or not prefix or prefix == "NA":
                continue
            try:
                network = ipaddress.ip_network(prefix, strict=True)
                if network.version != 4 or ipaddress.ip_address(address) not in network:
                    continue
            except ValueError:
                continue
            previous = mapping.get(address)
            # Один IP может вернуться под несколькими ASN — берём самый узкий префикс.
            if previous is None or (
                ipaddress.ip_network(prefix).prefixlen
                > ipaddress.ip_network(previous[1]).prefixlen
            ):
                mapping[address] = (asn, prefix, country, as_name)
    return mapping


def fetch_json(url: str) -> dict:
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            payload = catalog.http_get(url, MAX_RIPESTAT_BYTES, timeout=40)
            return json.loads(payload.decode("utf-8"))
        except catalog.CatalogError as exc:
            last_error = RefreshError(str(exc))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise RefreshError(f"ответ {url} не является JSON") from exc
        if attempt < 2:
            time.sleep(2 * (attempt + 1))
    assert last_error is not None
    raise last_error


def announced_prefixes(asn: int) -> list[str]:
    document = fetch_json(RIPESTAT_URL.format(asn=asn))
    data = document.get("data") if isinstance(document, dict) else None
    entries = data.get("prefixes") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise RefreshError(f"RIPEstat вернул неожиданный ответ для AS{asn}")
    prefixes = []
    for entry in entries:
        value = entry.get("prefix") if isinstance(entry, dict) else None
        if not isinstance(value, str) or ":" in value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if MIN_PREFIXLEN <= network.prefixlen <= MAX_PREFIXLEN and network.is_global:
            prefixes.append(str(network))
    return sorted(set(prefixes))


def load_external(path: Path) -> dict[str, dict]:
    """Проверенные сети из внешних списков (см. tools/import_external.py)."""
    if not path.exists():
        return {}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RefreshError(f"{path.name}: не читается ({exc})") from exc
    if not isinstance(document, dict) or document.get("version") != 1:
        raise RefreshError(f"{path.name}: ожидается объект с version=1")
    entries = document.get("prefixes")
    if not isinstance(entries, dict):
        raise RefreshError(f"{path.name}: нет объекта prefixes")
    result: dict[str, dict] = {}
    for value, meta in entries.items():
        network = ipaddress.ip_network(value, strict=True)
        asn = meta.get("asn") if isinstance(meta, dict) else None
        if not isinstance(asn, int) or asn in DENY_ASN:
            raise RefreshError(f"{path.name}: {value} — недопустимый ASN {asn!r}")
        if network.version != 4 or not (MIN_PREFIXLEN <= network.prefixlen <= MAX_PREFIXLEN) or not network.is_global:
            raise RefreshError(f"{path.name}: {value} вне допустимого диапазона")
        if not is_russian(asn, meta.get("cc", ""), meta.get("as_name", "")):
            raise RefreshError(f"{path.name}: {value} не российская сеть")
        result[str(network)] = meta
    return result


def load_asn_expand() -> dict[int, str]:
    if not ASN_EXPAND_FILE.exists():
        return {}
    document = json.loads(ASN_EXPAND_FILE.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("version") != 1:
        raise RefreshError("config/asn-expand.json: ожидается объект с version=1")
    entries = document.get("asn", {})
    if not isinstance(entries, dict):
        raise RefreshError("config/asn-expand.json: нет объекта asn")
    result: dict[int, str] = {}
    for key, value in entries.items():
        if not str(key).isdigit() or not isinstance(value, str):
            raise RefreshError(f"config/asn-expand.json: некорректная запись {key!r}")
        number = int(key)
        if number in DENY_ASN:
            raise RefreshError(f"AS{number} в deny-листе, разворачивать нельзя")
        result[number] = value
    return result


def reviewed_ru_prefix(value: str, asn: int, table: catalog.AsnTable) -> bool:
    """Check every range, not just the first/last IP or an ASN's legal country."""
    rows = table.covering_rows(ipaddress.ip_network(value))
    return bool(rows) and all(
        record[2] == asn and is_russian(record[2], record[3], record[4])
        for record in rows
    )


def _extract_feed_networks(text: str, kind: str) -> list[ipaddress.IPv4Network]:
    candidates: list[str] = []
    if kind == "amnezia":
        document = json.loads(text)
        if not isinstance(document, list):
            return []
        for item in document:
            if not isinstance(item, dict):
                continue
            hostname = item.get("hostname")
            if isinstance(hostname, str) and ("/" in hostname or hostname.replace(".", "").isdigit()):
                candidates.append(hostname)
    else:
        for line in text.splitlines():
            value = line.split("#", 1)[0].strip()
            if value:
                candidates.append(value)
    networks: list[ipaddress.IPv4Network] = []
    for raw in candidates:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if (
            net.version == 4
            and net.is_global
            and MIN_PREFIXLEN <= net.prefixlen <= 32
            and not any(net.overlaps(tg) for tg in TELEGRAM_SUBNETS)
        ):
            networks.append(net)
    return networks


def _is_public_asn(asn: int) -> bool:
    return asn > 0 and not (64496 <= asn <= 65535 or 4200000000 <= asn <= 4294967294)


def harvest_competitor_subdomains(
    trusted_domains: Iterable[str],
    feeds: Iterable[tuple[str, str, str]] = COMPETITOR_SUBDOMAIN_FEEDS,
) -> dict[str, str]:
    """Ищет в лентах конкурентов новые поддомены наших курируемых сервисов -> {поддомен: родитель}."""
    trusted = set(trusted_domains)
    if not trusted:
        return {}
    counts: dict[str, int] = {}
    parents: dict[str, str] = {}
    for feed_id, kind, url in feeds:
        try:
            payload = catalog.http_get(url, MAX_RIPESTAT_BYTES * 2, timeout=45)
            text = payload.decode("utf-8-sig", "replace")
            if kind == "amnezia":
                doc = json.loads(text)
                candidates = [
                    item["hostname"] for item in doc
                    if isinstance(item, dict) and isinstance(item.get("hostname"), str)
                ] if isinstance(doc, list) else []
            else:
                candidates = text.splitlines()
        except (catalog.CatalogError, ValueError, OSError) as exc:
            print(f"ПРЕДУПРЕЖДЕНИЕ: лента поддоменов {feed_id} пропущена ({exc})", file=sys.stderr)
            continue
        matched = 0
        for raw in candidates:
            value = raw.split("#", 1)[0].strip()
            for prefix in ("domain:", "full:", "*."):
                if value.startswith(prefix):
                    value = value[len(prefix):]
            if not value or "/" in value:
                continue
            try:
                domain = catalog.normalize_hostname(value, feed_id)
            except catalog.CatalogError:
                continue
            parent = catalog.external_domain_parent(domain, trusted)
            if parent is None:
                continue
            parents[domain] = parent
            counts[domain] = counts.get(domain, 0) + 1
            matched += 1
        print(f"лента поддоменов {feed_id}: найдено {matched} поддоменов наших сервисов")
    ranked = sorted(parents, key=lambda d: (-counts[d], d))[:MAX_COMPETITOR_SUBDOMAINS]
    return {domain: parents[domain] for domain in ranked}


def discover_competitor_asns(
    expand: dict[int, str],
    table: catalog.AsnTable,
    configs: Iterable[tuple[str, str, str]] = COMPETITOR_ASN_CONFIGS,
) -> dict[int, str]:
    """Находит новые малые сервисные/капчевые ASN у конкурентов (строго без провайдеров и хостингов)."""
    if not any(_is_public_asn(asn) for asn in expand):
        return {}
    candidates: dict[int, str] = {}
    for cfg_id, kind, url in configs:
        try:
            payload = catalog.http_get(url, MAX_RIPESTAT_BYTES, timeout=40)
            document = json.loads(payload.decode("utf-8-sig", "replace"))
        except (catalog.CatalogError, ValueError, OSError) as exc:
            print(f"ПРЕДУПРЕЖДЕНИЕ: конфиг ASN {cfg_id} пропущен ({exc})", file=sys.stderr)
            continue
        if kind == "runetfreedom" and isinstance(document, dict):
            for item in document.get("input", []):
                wanted = (item.get("args") or {}).get("wantedList") if isinstance(item, dict) else None
                if not isinstance(wanted, dict):
                    continue
                for group_name in ("ddos-guard", "yandex"):
                    for raw_asn in wanted.get(group_name, []):
                        digits = str(raw_asn).upper().removeprefix("AS")
                        if digits.isdigit():
                            candidates.setdefault(int(digits), f"{group_name} (автосбор {cfg_id})")
        elif kind == "kyoresuas" and isinstance(document, dict):
            for service in document.get("services", []):
                if not isinstance(service, dict):
                    continue
                svc_name = str(service.get("name") or cfg_id).strip()
                for asn_item in service.get("asns") or []:
                    if isinstance(asn_item, dict) and isinstance(asn_item.get("asn"), int):
                        label = str(asn_item.get("name") or svc_name).strip()
                        candidates.setdefault(asn_item["asn"], f"{label} (автосбор)")

    accepted: dict[int, str] = {}
    for asn, label in sorted(candidates.items()):
        if asn in expand or asn in DENY_ASN or asn in catalog.SHARED_HOSTING_ASN or not _is_public_asn(asn):
            continue
        announced_ips = table.announced.get(asn, 0)
        if not (0 < announced_ips <= MAX_AUTO_DISCOVERED_ASN_IPS):
            continue
        try:
            prefs = announced_prefixes(asn)
        except RefreshError:
            continue
        if not prefs:
            continue
        valid_prefs = [
            p for p in prefs
            if reviewed_ru_prefix(p, asn, table)
            and not any(ipaddress.ip_network(p).overlaps(tg) for tg in TELEGRAM_SUBNETS)
        ]
        # Принимаем новый ASN автоматически, только если все его IPv4-анонсы чистые и российские.
        if len(valid_prefs) == len(prefs):
            accepted[asn] = label
            print(f"автооткрыт новый сервисный AS{asn} ({label}): {len(valid_prefs)} префиксов")
    return accepted


def save_asn_expand(expand: dict[int, str], path: Path = ASN_EXPAND_FILE) -> None:
    comment = (
        "ASN, которые разворачиваем целиком через RIPEstat + сверяем с курируемыми лентами конкурентов: "
        "контентные платформы, российские облака, капчи, CDN, НСПК/СБП, банки и anti-DDoS крутят адреса "
        "балансировщиков, и одного резолва домена мало (плюс разворот схлопывает сотни разрозненных /32 в "
        "компактные подсети). Операторов связи (МТС, Ростелеком, МегаФон) сюда не добавляем — их адресное "
        "пространство огромно и не нужно."
    )
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(existing, dict) and isinstance(existing.get("comment"), str):
                comment = existing["comment"]
        except (OSError, json.JSONDecodeError):
            pass
    payload = {
        "version": 1,
        "comment": comment,
        "asn": {str(asn): reason for asn, reason in sorted(expand.items())},
    }
    catalog.atomic_write(path, catalog.json_bytes(payload))


def harvest_competitor_prefixes(
    expand: dict[int, str],
    table: catalog.AsnTable,
    feeds: Iterable[tuple[str, str, str]] = COMPETITOR_SERVICE_FEEDS,
) -> dict[str, int]:
    """Добирает из курируемых лент конкурентов подсети ТОЛЬКО наших проверенных ASN."""
    public_asns = [asn for asn in expand if _is_public_asn(asn)]
    if not public_asns:
        return {}
    discovered: dict[str, int] = {}
    for feed_id, kind, url in feeds:
        try:
            payload = catalog.http_get(url, MAX_RIPESTAT_BYTES, timeout=45)
            networks = _extract_feed_networks(payload.decode("utf-8-sig", "replace"), kind)
        except (catalog.CatalogError, ValueError, OSError) as exc:
            print(f"ПРЕДУПРЕЖДЕНИЕ: лента {feed_id} пропущена ({exc})", file=sys.stderr)
            continue
        matched = 0
        for net in networks:
            rows = table.covering_rows(net)
            if not rows:
                continue
            asns = {row[2] for row in rows}
            if len(asns) != 1:
                continue
            asn = next(iter(asns))
            if asn not in expand or asn in DENY_ASN:
                continue
            prefix_str = str(net)
            if not reviewed_ru_prefix(prefix_str, asn, table):
                continue
            discovered[prefix_str] = asn
            matched += 1
        print(f"лента {feed_id}: проверено {len(networks)} сетей, совпало с нашими ASN: {matched}")
    return discovered


def enforce_route_budget(
    prefixes: dict[str, dict],
    manual_cidrs: Iterable[str],
    max_routes: int = MAX_AUTO_ROUTES,
) -> tuple[dict[str, dict], int]:
    """Гарантирует, что сжатое объединение маршрутов никогда не пробьёт потолок сборщика."""
    base_nets = [ipaddress.ip_network(c) for c in manual_cidrs]
    asn_items = [(k, v) for k, v in prefixes.items() if v.get("source") == "asn"]
    other_items = [(k, v) for k, v in prefixes.items() if v.get("source") != "asn"]
    kept: dict[str, dict] = dict(asn_items)
    covered = list(ipaddress.collapse_addresses(base_nets + [ipaddress.ip_network(k) for k, _ in asn_items]))
    coverage_index = [
        (int(net.network_address), int(net.broadcast_address)) for net in covered
    ]

    def is_covered(net: ipaddress.IPv4Network) -> bool:
        lo, hi = int(net.network_address), int(net.broadcast_address)
        return any(start <= lo and hi <= end for start, end in coverage_index)

    trimmed = 0
    current_routes = len(covered)
    for key, meta in other_items:
        net = ipaddress.ip_network(key)
        if is_covered(net):
            kept[key] = meta
            continue
        if current_routes < max_routes:
            kept[key] = meta
            current_routes += 1
        else:
            trimmed += 1
    return kept, trimmed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=catalog.PREFIXES_FILE)
    parser.add_argument("--external", type=Path, default=catalog.EXTERNAL_FILE)
    parser.add_argument("--no-expand", action="store_true", help="без разворота ASN через RIPEstat")
    parser.add_argument("--no-competitors", action="store_true", help="без добора подсетей из лент конкурентов")
    external_group = parser.add_mutually_exclusive_group()
    external_group.add_argument("--no-external", dest="no_external", action="store_true", default=True)
    external_group.add_argument("--with-external", dest="no_external", action="store_false")
    parser.add_argument("--asn-table", type=Path, help="локальный ip2asn-v4.tsv(.gz)")
    parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()

    try:
        try:
            previous_prefixes = catalog.load_prefixes(arguments.output)
        except catalog.CatalogError:
            previous_prefixes = {}

        services = catalog.load_catalog()
        base_domains = catalog.catalog_domains(services)
        external_domains = {} if arguments.no_external else catalog.load_external_domains(services, arguments.external)
        owners = dict(catalog.domain_owner(services))
        expand = {} if arguments.no_expand else load_asn_expand()
        has_public_expand = any(_is_public_asn(asn) for asn in expand)

        competitor_subdomains: dict[str, str] = {}
        if has_public_expand and not arguments.no_competitors:
            competitor_subdomains = harvest_competitor_subdomains(base_domains)
            for sub, parent in competitor_subdomains.items():
                if sub not in owners and parent in owners:
                    owners[sub] = list(owners[parent])

        domains = sorted(set(base_domains) | set(external_domains) | set(competitor_subdomains))
        print(
            f"каталог: {len(services)} сервисов, {len(base_domains)} доменов"
            + (f" (+{len(competitor_subdomains)} поддоменов у конкурентов)" if competitor_subdomains else "")
        )

        answers = resolve_all(domains)
        resolved = {domain: ips for domain, ips in answers.items() if ips}
        base_resolved = sum(1 for domain in base_domains if answers.get(domain))
        addresses = {address for ips in resolved.values() for address in ips}
        print(f"резолв: {len(resolved)}/{len(domains)} доменов, {len(addresses)} уникальных IP")
        if base_domains and base_resolved < len(base_domains) * 0.5:
            raise RefreshError("резолвится меньше половины каталога — сеть или DNS сломаны")

        cymru = cymru_lookup(addresses)
        print(f"Cymru: {len(cymru)} IP сопоставлены с BGP-префиксами")
        if addresses and len(cymru) < len(addresses) * 0.8:
            raise RefreshError("Team Cymru сопоставил меньше 80% IP — неполный снапшот не публикуется")

        table = catalog.load_asn_table(catalog.asn_table_url(), arguments.asn_table)

        if has_public_expand and not arguments.no_competitors:
            new_asns = discover_competitor_asns(expand, table)
            if new_asns:
                expand.update(new_asns)
                if not arguments.dry_run:
                    save_asn_expand(expand)
                    print(f"обновлён {ASN_EXPAND_FILE}: добавлено {len(new_asns)} новых сервисных ASN")

        prefixes: dict[str, dict] = {}
        dropped: dict[str, str] = {}
        for domain, ips in resolved.items():
            for address in ips:
                record = cymru.get(address)
                if record is None:
                    continue
                asn, prefix, country, as_name = record
                network = ipaddress.ip_network(prefix, strict=False)
                if asn in DENY_ASN:
                    dropped[prefix] = f"AS{asn} {as_name} — глобальный CDN"
                    continue
                if not is_russian(asn, country, as_name):
                    dropped[prefix] = f"AS{asn} {as_name} — страна {country}"
                    continue
                # A bank on shared hosting authorizes its IP, not every tenant
                # of that provider. Only reviewed service ASNs expand to BGP.
                if asn not in expand:
                    network = ipaddress.ip_network(address + "/32")
                if not network.is_global or not (MIN_PREFIXLEN <= network.prefixlen <= 32):
                    dropped[prefix] = f"префикс /{network.prefixlen} вне допустимого диапазона"
                    continue
                if any(network.overlaps(tg) for tg in TELEGRAM_SUBNETS):
                    dropped[str(network)] = "пересечение с подсетью Telegram"
                    continue
                if not reviewed_ru_prefix(str(network), asn, table):
                    dropped[prefix] = "весь диапазон не подтверждён как RU у этого ASN"
                    continue
                entry = prefixes.setdefault(
                    str(network),
                    {"asn": asn, "as_name": as_name, "cc": "RU", "services": [],
                     "source": "external" if domain in external_domains else "dns"},
                )
                if domain in external_domains and entry["source"] == "external":
                    entry["sources"] = sorted(set(entry.get("sources", [])) | set(external_domains[domain]["sources"]))
                for service_id in owners.get(domain, []):
                    if service_id not in entry["services"]:
                        entry["services"].append(service_id)

        def safe_announced(asn: int) -> tuple[list[str], str | None]:
            try:
                return announced_prefixes(asn), None
            except RefreshError as exc:
                return [], str(exc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=RIPESTAT_WORKERS) as executor:
            announced = dict(zip(sorted(expand), executor.map(safe_announced, sorted(expand))))

        ripestat_failures = 0
        max_ripestat_failures = max(2, len(expand) // 4)
        for asn, reason in sorted(expand.items()):
            values, error_msg = announced[asn]
            if not values:
                prev_values = sorted(
                    prev_prefix for prev_prefix, meta in previous_prefixes.items()
                    if meta.get("asn") == asn and meta.get("source") == "asn"
                    and reviewed_ru_prefix(prev_prefix, asn, table)
                )
                ripestat_failures += 1
                if prev_values and ripestat_failures <= max_ripestat_failures:
                    print(
                        f"ПРЕДУПРЕЖДЕНИЕ: RIPEstat не отдал AS{asn} ({error_msg or 'пусто'}), "
                        f"сохранены {len(prev_values)} префиксов из прошлого снимка",
                        file=sys.stderr,
                    )
                    values = prev_values
                else:
                    raise RefreshError(
                        error_msg or f"RIPEstat: у AS{asn} нет допустимых IPv4-префиксов"
                    )
            else:
                print(f"AS{asn} ({reason}): {len(values)} анонсируемых префиксов")
            for value in values:
                if any(ipaddress.ip_network(value).overlaps(tg) for tg in TELEGRAM_SUBNETS):
                    dropped[value] = "пересечение с подсетью Telegram"
                    continue
                if not reviewed_ru_prefix(value, asn, table):
                    dropped[value] = "ASN: зарубежный, смешанный или неизвестный диапазон"
                    continue
                entry = prefixes.setdefault(
                    value,
                    {"asn": asn, "as_name": reason, "cc": "RU", "services": [], "source": "asn"},
                )
                # Явно разрешённый ASN всегда входит в ядро. Новый внешний
                # поддомен не должен переименовать такой префикс в external
                # и тем самым случайно убрать его из lite.
                entry.update(asn=asn, source="asn")
                entry.pop("sources", None)

        if expand and not arguments.no_competitors:
            harvested = harvest_competitor_prefixes(expand, table)
            harvested_new = 0
            for value, asn in sorted(harvested.items(), key=lambda item: ipaddress.ip_network(item[0])):
                if value not in prefixes:
                    harvested_new += 1
                entry = prefixes.setdefault(
                    value,
                    {"asn": asn, "as_name": expand[asn], "cc": "RU", "services": [], "source": "asn"},
                )
                entry.update(asn=asn, source="asn")
                entry.pop("sources", None)
            if harvested:
                print(f"ленты конкурентов: подтверждено {len(harvested)} префиксов наших ASN (новых {harvested_new})")

        # Аддитивное сохранение вчерашних /32 из DNS ротации, которые ещё живы в RU-таблице.
        retained_dns = 0
        for prev_prefix, meta in previous_prefixes.items():
            if prev_prefix in prefixes or meta.get("source") != "dns":
                continue
            net = ipaddress.ip_network(prev_prefix)
            asn = meta.get("asn")
            if (
                net.prefixlen == 32
                and isinstance(asn, int)
                and asn not in DENY_ASN
                and not any(net.overlaps(tg) for tg in TELEGRAM_SUBNETS)
                and reviewed_ru_prefix(prev_prefix, asn, table)
            ):
                prefixes[prev_prefix] = dict(meta, cc="RU")
                retained_dns += 1
        if retained_dns:
            print(f"аддитивно сохранено прошлых /32 из ротации DNS: {retained_dns}")

        manual_cidrs = [cidr for svc in services for cidr in svc.cidrs]
        prefixes, trimmed_routes = enforce_route_budget(prefixes, manual_cidrs)
        if trimmed_routes:
            print(f"потолок маршрутов ({MAX_AUTO_ROUTES}): отсечено старых /32 сверх бюджета: {trimmed_routes}")

        external = {} if arguments.no_external else load_external(arguments.external)
        added = 0
        for value, meta in external.items():
            if value in prefixes:
                continue
            prefixes[value] = {
                "asn": meta.get("asn"),
                "as_name": meta.get("as_name", ""),
                "cc": meta.get("cc", "RU"),
                "services": [],
                "source": "external",
                "sources": meta.get("sources", []),
            }
            added += 1
        if external:
            print(f"внешние списки: {len(external)} проверенных сетей, новых {added}")

        for entry in prefixes.values():
            entry["services"] = sorted(entry["services"])

        payload = {
            "version": 1,
            "updated": date.today().isoformat(),
            "source": "Team Cymru bulk whois + RIPEstat announced-prefixes"
            + (" + внешние списки" if external else ""),
            "prefix_count": len(prefixes),
            "external_count": len(external),
            "external_domains": len(external_domains),
            "resolved_domains": len(resolved),
            "catalog_domains": len(domains),
            "prefixes": dict(
                sorted(prefixes.items(), key=lambda item: ipaddress.ip_network(item[0]))
            ),
        }
        total = sum(ipaddress.ip_network(value).num_addresses for value in prefixes)
        print(f"итого: {len(prefixes)} префиксов, {total} адресов; отброшено {len(dropped)}")
        if arguments.dry_run:
            for value, reason in sorted(dropped.items())[:20]:
                print(f"  drop {value}: {reason}")
            return 0
        catalog.atomic_write(arguments.output, catalog.json_bytes(payload))
        print(f"записан {arguments.output}")
        return 0
    except (catalog.CatalogError, RefreshError, OSError, ValueError) as exc:
        print(f"ОШИБКА: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
