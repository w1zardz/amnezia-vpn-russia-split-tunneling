#!/usr/bin/env python3
"""Снимок A-записей доменов полного списка → data/domain-ips.json.

Зачем: AmneziaVPN при импорте JSON домены не резолвит. Для AmneziaWG/WireGuard,
на iOS и Android маршруты строятся только из сохранённых полей записи ips/ip,
поэтому доменная запись с пустым ip при ручном импорте не даёт ни одного
маршрута. Сборка остаётся детерминированной и офлайн: сеть трогает только этот
шаг, а tools/build_ru_direct.py лишь читает готовый снимок.

Механика:
  1. домены = ручной каталог (core + extended); внешние — только с --with-external;
  2. каждый домен спрашиваем у Google и Cloudflare по DoH (всегда) и у Яндекса
     по UDP/53 (по возможности), по два запроса на резолвер — балансировщики
     отдают разные адреса из пула;
  3. оставляем только публичные IPv4 российских ASN вне deny-листа глобальных
     CDN — проверка по той же таблице IP→ASN, что и у импорта внешних списков;
     явно заданные сети своего сервиса допускаются и при иной стране в IP→ASN;
  4. домен без свежего ответа сохраняет адреса из прошлого снимка; если свежие
     адреса получили меньше 60% доменов, DNS нас душит — файл не перезаписываем.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import http.client
import ipaddress
import json
import secrets
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse
from datetime import date
from pathlib import Path
from typing import Iterable, NamedTuple

import catalog

DOH_RESOLVERS = (
    ("dns.google", "/resolve"),
    ("cloudflare-dns.com", "/dns-query"),
)
UDP_RESOLVERS = ("77.88.8.8", "77.88.8.1")  # Яндекс.DNS
QUERIES_PER_RESOLVER = 2
TIMEOUT = 4.0
RETRIES = 2
RETRY_PAUSE = 0.3
WORKERS = 64
MAX_DOH_BYTES = 65_536
MIN_RESOLVED_SHARE = 0.6
# Столько UDP-сбоев подряд — и Яндекс считаем недоступным до конца прогона:
# без этого заблокированный порт 53 растянул бы шаг на десятки минут.
UDP_BREAKER = 200
PROBE_DOMAIN = "ya.ru"

TYPE_A, TYPE_CNAME, CLASS_IN = 1, 5, 1
NOERROR, NXDOMAIN = 0, 3
MAX_POINTER_JUMPS = 32

OK = "ok"  # есть A-записи
EMPTY = "empty"  # окончательный ответ без адресов: NXDOMAIN или нет A
FAIL = "fail"  # ни одного окончательного ответа

ACCEPT = "accept"
NOT_PUBLIC = "не публичный адрес"
NO_ROW = "адрес вне таблицы IP→ASN"
GLOBAL_CDN = "глобальный CDN или облако"
FOREIGN = "зарубежный адрес"
# Порядок важности, когда у домена несколько проблемных адресов.
REASON_ORDER = (GLOBAL_CDN, FOREIGN, NO_ROW, NOT_PUBLIC)


class ResolveError(RuntimeError):
    pass


class DnsFailure(Exception):
    """Запрос не дал окончательного ответа — можно повторить."""


class DnsMismatch(ValueError):
    """Пакет не относится к нашему запросу."""


class Answer(NamedTuple):
    status: str
    addresses: tuple[str, ...]


# --- UDP/53 -------------------------------------------------------------------


def build_query(name: str, query_id: int) -> bytes:
    """Минимальный запрос A IN с флагом рекурсии."""
    packet = bytearray(struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0))
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        if not 0 < len(raw) <= 63:
            raise ValueError(f"некорректная метка в {name!r}")
        packet += bytes([len(raw)]) + raw
    packet += b"\x00" + struct.pack("!HH", TYPE_A, CLASS_IN)
    return bytes(packet)


def read_name(payload: bytes, offset: int) -> tuple[str, int]:
    """Имя из пакета с учётом сжатия (RFC 1035 §4.1.4) → (имя, смещение за ним)."""
    labels: list[str] = []
    end: int | None = None
    jumps = 0
    while True:
        if offset >= len(payload):
            raise ValueError("имя выходит за пределы пакета")
        length = payload[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(payload):
                raise ValueError("обрезанный указатель сжатия")
            if end is None:
                end = offset + 2
            jumps += 1
            if jumps > MAX_POINTER_JUMPS:
                raise ValueError("цикл указателей сжатия")
            offset = ((length & 0x3F) << 8) | payload[offset + 1]
            continue
        if length & 0xC0:
            raise ValueError("зарезервированный тип метки")
        offset += 1
        if length == 0:
            break
        label = payload[offset:offset + length]
        if len(label) != length:
            raise ValueError("метка выходит за пределы пакета")
        labels.append(label.decode("ascii", "replace").lower())
        offset += length
    return ".".join(labels), end if end is not None else offset


def parse_dns_response(payload: bytes, query_id: int, name: str) -> tuple[int, list[str]]:
    """(RCODE, A-записи цепочки CNAME от name) из сырого ответа."""
    if len(payload) < 12:
        raise ValueError("ответ короче заголовка")
    ident, flags, qdcount, ancount, _nscount, _arcount = struct.unpack_from("!HHHHHH", payload)
    if ident != query_id or not flags & 0x8000:
        raise DnsMismatch("чужой пакет")
    if flags & 0x0200:
        raise ValueError("ответ обрезан (TC)")
    wanted = name.rstrip(".").lower()
    offset = 12
    for _ in range(qdcount):
        question, offset = read_name(payload, offset)
        if question != wanted:
            raise DnsMismatch("ответ на другой вопрос")
        offset += 4
    chain = {wanted}
    addresses: list[str] = []
    for _ in range(ancount):
        owner, offset = read_name(payload, offset)
        if offset + 10 > len(payload):
            raise ValueError("обрезанная запись ответа")
        rtype, rclass, _ttl, length = struct.unpack_from("!HHIH", payload, offset)
        start = offset + 10
        offset = start + length
        if offset > len(payload):
            raise ValueError("данные записи выходят за пределы пакета")
        if rclass != CLASS_IN or owner not in chain:
            continue
        if rtype == TYPE_CNAME:
            chain.add(read_name(payload, start)[0])
        elif rtype == TYPE_A and length == 4:
            addresses.append(str(ipaddress.IPv4Address(payload[start:offset])))
    return flags & 0x000F, addresses


def udp_query(server: str, name: str) -> tuple[int, list[str]]:
    query_id = secrets.randbelow(65536)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((server, 53))
        sock.send(build_query(name, query_id))
        deadline = time.monotonic() + TIMEOUT
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DnsFailure(f"{server}: таймаут")
            sock.settimeout(remaining)
            try:
                return parse_dns_response(sock.recv(4096), query_id, name)
            except DnsMismatch:
                continue  # запоздавший ответ на прошлый запрос — ждём свой


# --- DoH JSON -------------------------------------------------------------------

_TLS = ssl.create_default_context()
# python.org-сборка на macOS приходит без корневых сертификатов — берём системные.
# На Linux хранилище подгружается лениво из каталога, туда не лезем.
if not _TLS.get_ca_certs() and Path("/etc/ssl/cert.pem").is_file():
    _TLS.load_verify_locations("/etc/ssl/cert.pem")
_THREAD = threading.local()


def doh_query(host: str, path: str, name: str) -> tuple[int, list[str]]:
    """GET ?name=&type=A с Accept: application/dns-json; соединение живёт в потоке."""
    connections = _THREAD.__dict__.setdefault("doh", {})
    connection = connections.get(host)
    if connection is None:
        connection = http.client.HTTPSConnection(host, timeout=TIMEOUT, context=_TLS)
        connections[host] = connection
    try:
        connection.request(
            "GET",
            f"{path}?name={urllib.parse.quote(name)}&type=A",
            headers={"Accept": "application/dns-json", "User-Agent": "amnezia-split-route-sync/2.0"},
        )
        response = connection.getresponse()
        body = response.read(MAX_DOH_BYTES + 1)
        if not response.isclosed():
            raise DnsFailure(f"{host}: ответ больше {MAX_DOH_BYTES} байт")
        if response.status != 200:
            raise DnsFailure(f"{host}: HTTP {response.status}")
    except BaseException:
        connection.close()
        connections.pop(host, None)
        raise
    document = json.loads(body.decode("utf-8"))
    status = document.get("Status") if isinstance(document, dict) else None
    if not isinstance(status, int):
        raise ValueError(f"{host}: нет Status в ответе")
    addresses = []
    for record in document.get("Answer") or []:
        if isinstance(record, dict) and record.get("type") == TYPE_A:
            try:
                addresses.append(str(ipaddress.IPv4Address(record.get("data"))))
            except (ipaddress.AddressValueError, ValueError):
                continue
    return status, addresses


# --- резолв -------------------------------------------------------------------


class Resolver:
    """Один резолвер: DoH-адрес или пара UDP-серверов с автоотключением."""

    def __init__(self, label: str, doh: tuple[str, str] | None = None, udp: tuple[str, ...] = ()) -> None:
        self.label, self.doh, self.udp = label, doh, udp
        self.enabled = True
        self._failures = 0
        self._lock = threading.Lock()

    def query(self, name: str, round_: int) -> tuple[int, list[str]]:
        if self.doh:
            return doh_query(*self.doh, name)
        return udp_query(self.udp[round_ % len(self.udp)], name)

    def ask(self, name: str, round_: int) -> tuple[str, list[str]]:
        """Запрос с ретраями; NXDOMAIN окончателен и не повторяется."""
        for attempt in range(RETRIES + 1):
            if not self.enabled:
                return FAIL, []
            if attempt:
                time.sleep(RETRY_PAUSE * attempt)
            try:
                rcode, addresses = self.query(name, round_)
            except (OSError, ValueError, http.client.HTTPException, DnsFailure):
                continue
            if rcode == NOERROR:
                self._record(True)
                return (OK if addresses else EMPTY), addresses
            if rcode == NXDOMAIN:
                self._record(True)
                return EMPTY, []
        self._record(False)
        return FAIL, []

    def _record(self, success: bool) -> None:
        if self.doh:
            return
        with self._lock:
            self._failures = 0 if success else self._failures + 1
            if self._failures >= UDP_BREAKER and self.enabled:
                self.enabled = False
                print(f"ПРЕДУПРЕЖДЕНИЕ: {self.label} не отвечает, дальше без него", file=sys.stderr)

    def resolve(self, name: str) -> Answer:
        statuses: list[str] = []
        addresses: set[str] = set()
        for round_ in range(QUERIES_PER_RESOLVER):
            status, found = self.ask(name, round_)
            statuses.append(status)
            addresses.update(found)
            # Второй запрос нужен ради ротации пула; при отказе DoH он бессмыслен,
            # а у Яндекса второй адрес — другой сервер, его стоит спросить.
            if status == EMPTY or (status == FAIL and self.doh):
                break
        return merge_answers(Answer(status, tuple(addresses)) for status in statuses)


def merge_answers(answers: Iterable[Answer]) -> Answer:
    """Объединение ответов: адреса суммируются, окончательность — если хоть один ответил."""
    addresses: set[str] = set()
    definitive = False
    for answer in answers:
        addresses.update(answer.addresses)
        definitive = definitive or answer.status != FAIL
    ordered = tuple(sorted(addresses, key=ipaddress.IPv4Address))
    if ordered:
        return Answer(OK, ordered)
    return Answer(EMPTY if definitive else FAIL, ())


def default_resolvers() -> list[Resolver]:
    return [
        *(Resolver(f"DoH {host}", doh=(host, path)) for host, path in DOH_RESOLVERS),
        Resolver("Яндекс UDP/53", udp=UDP_RESOLVERS),
    ]


def resolve_many(domains: Iterable[str], workers: int = WORKERS) -> dict[str, Answer]:
    """Все домены у всех доступных резолверов; без DoH работать не с чем."""
    names = sorted(set(domains))
    resolvers = default_resolvers()
    for resolver in resolvers:
        # Проба на заведомо живом домене: недоступный резолвер иначе съел бы
        # по 12 секунд таймаутов на каждый домен.
        if resolver.ask(PROBE_DOMAIN, 0)[0] == FAIL:
            resolver.enabled = False
            print(f"ПРЕДУПРЕЖДЕНИЕ: {resolver.label} недоступен, пропускаю", file=sys.stderr)
    if not any(resolver.enabled for resolver in resolvers if resolver.doh):
        raise ResolveError("ни один DoH-резолвер не отвечает")
    active = [resolver for resolver in resolvers if resolver.enabled]
    tasks = [(name, resolver) for name in names for resolver in active]
    partial: dict[str, list[Answer]] = {name: [] for name in names}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for (name, _resolver), answer in zip(
            tasks, executor.map(lambda task: task[1].resolve(task[0]), tasks)
        ):
            partial[name].append(answer)
    return {name: merge_answers(answers) for name, answers in partial.items()}


# --- фильтр адресов -------------------------------------------------------------


def address_verdict(address: str, table: catalog.AsnTable) -> tuple[str, tuple | None]:
    """ACCEPT, если IPv4 публичный, российский и не в сети глобального CDN."""
    try:
        parsed = ipaddress.IPv4Address(address)
    except (ipaddress.AddressValueError, ValueError):
        return NOT_PUBLIC, None
    if not parsed.is_global:
        return NOT_PUBLIC, None
    record = table.lookup(int(parsed))
    if record is None:
        return NO_ROW, None
    if record[2] in catalog.DENY_ASN:
        return GLOBAL_CDN, record
    if record[3] != "RU":
        return FOREIGN, record
    return ACCEPT, record


def ru_addresses(
    addresses: Iterable[str], table: catalog.AsnTable,
    manual_networks: Iterable[ipaddress.IPv4Network] = (),
) -> list[str]:
    # A reviewed service CIDR already goes direct in every export. Keep its DNS
    # labels even when the anti-DDoS provider is registered abroad. This does
    # not allow other addresses of that ASN or bypass the public/CDN checks.
    networks = tuple(manual_networks)
    accepted = set()
    for address in addresses:
        verdict = address_verdict(address, table)[0]
        if verdict == ACCEPT or (
            verdict in (FOREIGN, NO_ROW)
            and any(ipaddress.IPv4Address(address) in network for network in networks)
        ):
            accepted.add(address)
    return sorted(accepted, key=ipaddress.IPv4Address)[: catalog.MAX_DOMAIN_IPS]


def manual_domain_networks(services: Iterable[catalog.Service]) -> dict[str, list[ipaddress.IPv4Network]]:
    result: dict[str, list[ipaddress.IPv4Network]] = {}
    for service in services:
        networks = [ipaddress.IPv4Network(value) for value in service.cidrs]
        for domain in service.domains:
            result.setdefault(domain, []).extend(networks)
    return result


def full_list_domains(services: list[catalog.Service], with_external: bool = False) -> list[str]:
    """Те же домены, что попадают в полный список: каталог, поддомены, корни."""
    if not with_external:
        return catalog.catalog_domains(services)
    return sorted(
        set(catalog.catalog_domains(services))
        | set(catalog.load_external_domains(services))
        | set(catalog.load_external_roots(services))
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=catalog.DOMAIN_IPS_FILE)
    parser.add_argument("--asn-table", type=Path, help="локальный ip2asn-v4.tsv(.gz) вместо загрузки")
    external_group = parser.add_mutually_exclusive_group()
    external_group.add_argument("--no-external", dest="with_external", action="store_false", default=False)
    external_group.add_argument("--with-external", dest="with_external", action="store_true")
    parser.add_argument("--limit", type=int, help="только первые N доменов — для отладки")
    parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()

    try:
        if arguments.limit is not None and arguments.limit < 1:
            raise ResolveError("--limit должен быть положительным")
        services = catalog.load_catalog()
        manual_networks = manual_domain_networks(services)
        domains = full_list_domains(services, arguments.with_external)
        if arguments.limit:
            domains = domains[: arguments.limit]
        try:
            previous = catalog.load_domain_ips(arguments.output)
        except catalog.CatalogError as exc:
            print(f"ПРЕДУПРЕЖДЕНИЕ: прошлый снимок не читается, начинаю с нуля ({exc})", file=sys.stderr)
            previous = {}
        table_url = catalog.asn_table_url()
        table = catalog.load_asn_table(table_url, arguments.asn_table)
        print(f"доменов: {len(domains)}; таблица IP→ASN: {len(table)} диапазонов")

        started = time.monotonic()
        answers = resolve_many(domains)
        resolved = sum(1 for domain in domains if answers[domain].addresses)
        print(f"свежие адреса: {resolved}/{len(domains)} доменов за {time.monotonic() - started:.0f} с")
        if resolved < len(domains) * MIN_RESOLVED_SHARE:
            raise ResolveError(
                f"свежие адреса получили меньше {MIN_RESOLVED_SHARE:.0%} доменов — "
                "DNS режет запросы, прошлый снимок оставлен как есть"
            )

        result: dict[str, list[str]] = {}
        stale = 0
        for domain in domains:
            answer = answers[domain]
            if answer.status == FAIL:
                # Резолверы промолчали — держим прошлые адреса, но и их сверяем с таблицей.
                kept = ru_addresses(previous.get(domain, []), table, manual_networks.get(domain, ()))
                if kept:
                    result[domain] = kept
                    stale += 1
                continue
            accepted = ru_addresses(answer.addresses, table, manual_networks.get(domain, ()))
            if accepted:
                result[domain] = accepted
        print(
            f"с разрешёнными IPv4: {len(result)} доменов (из прошлого снимка {stale}); "
            f"адресов {sum(len(values) for values in result.values())}"
        )

        payload = {
            "version": 1,
            "updated": date.today().isoformat(),
            "asn_table": table_url,
            "resolved": resolved,
            "total": len(domains),
            "domains": dict(sorted(result.items())),
        }
        if arguments.dry_run:
            return 0
        catalog.atomic_write(arguments.output, catalog.json_bytes(payload))
        print(f"записан {arguments.output}")
        return 0
    except (catalog.CatalogError, ResolveError, OSError, ValueError, EOFError) as exc:
        print(f"ОШИБКА: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
