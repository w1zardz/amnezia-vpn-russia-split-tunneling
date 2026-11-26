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

ROOT = catalog.ROOT
ASN_EXPAND_FILE = ROOT / "config" / "asn-expand.json"
CYMRU_HOST = "whois.cymru.com"
CYMRU_PORT = 43
CYMRU_CHUNK = 500
RIPESTAT_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
MAX_RIPESTAT_BYTES = 4_194_304
RIPESTAT_WORKERS = 3
MAX_CYMRU_BYTES = 4_194_304

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

    result: dict[str, list[str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for hostname, addresses in executor.map(resolve_one, domain_list):
            result[hostname] = addresses
    return result


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
    return bool(rows) and all(record[2] == asn and record[3] == "RU" for record in rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=catalog.PREFIXES_FILE)
    parser.add_argument("--external", type=Path, default=catalog.EXTERNAL_FILE)
    parser.add_argument("--no-expand", action="store_true", help="без разворота ASN через RIPEstat")
    external_group = parser.add_mutually_exclusive_group()
    external_group.add_argument("--no-external", dest="no_external", action="store_true", default=True)
    external_group.add_argument("--with-external", dest="no_external", action="store_false")
    parser.add_argument("--asn-table", type=Path, help="локальный ip2asn-v4.tsv(.gz)")
    parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()

    try:
        services = catalog.load_catalog()
        domains = catalog.catalog_domains(services)
        external_domains = {} if arguments.no_external else catalog.load_external_domains(services, arguments.external)
        domains = [*domains, *external_domains]
        owners = catalog.domain_owner(services)
        print(f"каталог: {len(services)} сервисов, {len(domains)} доменов")

        answers = resolve_all(domains)
        resolved = {domain: ips for domain, ips in answers.items() if ips}
        addresses = {address for ips in resolved.values() for address in ips}
        print(f"резолв: {len(resolved)}/{len(domains)} доменов, {len(addresses)} уникальных IP")
        if len(resolved) < len(domains) * 0.5:
            raise RefreshError("резолвится меньше половины каталога — сеть или DNS сломаны")

        cymru = cymru_lookup(addresses)
        print(f"Cymru: {len(cymru)} IP сопоставлены с BGP-префиксами")
        if len(cymru) < len(addresses) * 0.8:
            raise RefreshError("Team Cymru сопоставил меньше 80% IP — неполный снапшот не публикуется")

        expand = {} if arguments.no_expand else load_asn_expand()
        table = catalog.load_asn_table(catalog.asn_table_url(), arguments.asn_table)

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
                if country != "RU":
                    dropped[prefix] = f"AS{asn} {as_name} — страна {country}"
                    continue
                # A bank on shared hosting authorizes its IP, not every tenant
                # of that provider. Only reviewed service ASNs expand to BGP.
                if asn not in expand:
                    network = ipaddress.ip_network(address + "/32")
                if not network.is_global or not (MIN_PREFIXLEN <= network.prefixlen <= 32):
                    dropped[prefix] = f"префикс /{network.prefixlen} вне допустимого диапазона"
                    continue
                if not reviewed_ru_prefix(str(network), asn, table):
                    dropped[prefix] = "весь диапазон не подтверждён как RU у этого ASN"
                    continue
                entry = prefixes.setdefault(
                    str(network),
                    {"asn": asn, "as_name": as_name, "cc": country, "services": [],
                     "source": "external" if domain in external_domains else "dns"},
                )
                if domain in external_domains and entry["source"] == "external":
                    entry["sources"] = sorted(set(entry.get("sources", [])) | set(external_domains[domain]["sources"]))
                for service_id in owners.get(domain, []):
                    if service_id not in entry["services"]:
                        entry["services"].append(service_id)

        with concurrent.futures.ThreadPoolExecutor(max_workers=RIPESTAT_WORKERS) as executor:
            announced = dict(zip(sorted(expand), executor.map(announced_prefixes, sorted(expand))))
        for asn, reason in sorted(expand.items()):
            values = announced[asn]
            if not values:
                raise RefreshError(f"RIPEstat: у AS{asn} нет допустимых IPv4-префиксов")
            print(f"AS{asn} ({reason}): {len(values)} анонсируемых префиксов")
            for value in values:
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
