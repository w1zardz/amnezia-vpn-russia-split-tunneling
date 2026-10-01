#!/usr/bin/env python3
"""Собирает готовые списки RU Direct из каталога сервисов и снапшота BGP-префиксов.

На выходе (каталог dist/):
  amnezia-ru-direct.json       — полный список для импорта в AmneziaVPN (домены + сети)
  amnezia-ru-direct-lite.json  — только ядро: самые популярные сервисы
  ru-direct-domains.txt        — домены построчно
  ru-direct-ipv4.txt           — сети построчно (для скриптов и macOS-синка)
  happ-ru-direct.json          — фрагмент профиля маршрутизации Happ
  manifest.json                — счётчики, sha256, разбивка по сервисам
  RELEASE_NOTES.md             — что вошло в сборку, по категориям

Доменные записи несут снимок IPv4 из data/domain-ips.json (tools/resolve_domains.py):
Amnezia при импорте JSON домены не резолвит, AmneziaWG и мобильные клиенты строят
маршруты только из полей ips/ip. Сама сборка сеть не трогает.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import sys
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any, Iterable

import catalog
import refresh_prefixes

ROOT = catalog.ROOT
DIST = ROOT / "dist"
# Amnezia переваривает несколько тысяч записей, но UI начинает подтормаживать —
# держим потолок, чтобы список оставался быстрым.
MAX_ENTRIES = 4_000
# 4000 зашито в уже установленные апдейтеры (MAX_TOTAL_ENTRIES / $MaximumEntries):
# список больше просто перестанет у них применяться. Полный список держим с запасом.
MAX_FULL_ENTRIES = 3_900
MIN_ENTRIES = 300
# Столько же маршрутов принимают установленные апдейтеры Windows и macOS
# ($MaximumRoutes / MAX_TOTAL_ROUTES). Список, который они отвергнут, нельзя
# публиковать: у пользователя обновление просто перестанет применяться.
MAX_ROUTES = 1_500
MAX_EFFECTIVE_ROUTES = 1_000


def curated_prefixes(prefixes: dict[str, dict], reviewed: set[int]) -> dict[str, dict]:
    """Published routes come from reviewed service ASNs or individual RU hosts.

    Old snapshots may contain whole shared-hosting networks learned from a
    single DNS answer. Only their validated host addresses belong in the list.
    """
    return {
        value: meta for value, meta in prefixes.items()
        if meta.get("source") != "external" and meta.get("cc") == "RU"
        and (meta.get("asn") in reviewed or ipaddress.ip_network(value).prefixlen == 32)
    }


def snapshot_routes(domains: Iterable[str], cidrs: Iterable[str], ips: dict[str, list[str]]) -> list[str]:
    networks = [ipaddress.ip_network(value) for value in cidrs]
    networks.extend(ipaddress.ip_network(ip) for domain in domains for ip in ips.get(domain, []))
    return [str(network) for network in ipaddress.collapse_addresses(networks)]


class BuildError(RuntimeError):
    pass


def import_entries(
    domains: Iterable[str], cidrs: Iterable[str] = (), ips: dict[str, list[str]] | None = None
) -> list[dict[str, Any]]:
    """Записи импорта Amnezia. С ips домен несёт снимок адресов, иначе ip пустой."""
    entries: list[dict[str, Any]] = []
    for domain in domains:
        if ips is None:
            entries.append({"hostname": domain, "ip": ""})
            continue
        addresses = ips.get(domain, [])
        entries.append({"hostname": domain, "ips": addresses, "ip": addresses[0] if addresses else ""})
    entries.extend({"hostname": value, "ip": ""} for value in cidrs)
    return entries


def rank_external(entries: dict[str, dict]) -> list[str]:
    """Больше источников — выше; при равенстве по алфавиту, чтобы обрезка была детерминированной."""
    return sorted(entries, key=lambda domain: (-len(entries[domain].get("sources", [])), domain))


def fit_full_list(
    base_domains: list[str],
    cidrs: list[str],
    external_domains: dict[str, dict],
    roots: dict[str, dict],
    limit: int = MAX_FULL_ENTRIES,
) -> tuple[list[str], list[str], list[str], int, int]:
    """Сперва поддомены каталога, затем корни — пока полный список не упрётся в потолок.

    → (домены, принятые поддомены, принятые корни, срезано поддоменов, срезано корней)
    """
    present = set(base_domains)
    room = limit - len(present) - len(cidrs)
    if room < 0:
        raise BuildError(f"полный список без внешних доменов уже {len(present) + len(cidrs)} записей — больше {limit}")
    subdomains = [domain for domain in rank_external(external_domains) if domain not in present]
    kept_subdomains = subdomains[:room]
    present.update(kept_subdomains)
    room -= len(kept_subdomains)
    candidates = [domain for domain in rank_external(roots) if domain not in present]
    kept_roots = candidates[:room]
    present.update(kept_roots)
    return (
        sorted(present), kept_subdomains, kept_roots,
        len(subdomains) - len(kept_subdomains), len(candidates) - len(kept_roots),
    )


def sort_networks(values: Iterable[str]) -> list[str]:
    return [
        str(network)
        for network in sorted(
            {ipaddress.ip_network(value) for value in values},
            key=lambda item: (int(item.network_address), item.prefixlen),
        )
    ]


def route_metrics(domains: Iterable[str], cidrs: Iterable[str], ips: dict[str, list[str]]) -> dict[str, int]:
    """Count actual routes, including repeated DNS answers, not just JSON rows."""
    networks = [ipaddress.ip_network(value) for value in cidrs]
    networks.extend(ipaddress.ip_network(ip) for domain in domains for ip in ips.get(domain, []))
    compacted = list(ipaddress.collapse_addresses(networks))
    return {
        "candidates": len(networks),
        "unique": len(set(networks)),
        "compacted": len(compacted),
        "redundant": len(networks) - len(compacted),
    }


def load_personal(path: Path) -> tuple[list[str], list[str], list[str]]:
    """Личный довесок: {"domains": [...], "cidrs": [...], "protected_ips": [...]}."""
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise BuildError(f"{path}: ожидается объект JSON")
    domains = sorted({
        catalog.normalize_hostname(value, str(path))
        for value in document.get("domains", [])
    })
    cidrs = sort_networks(
        str(catalog.parse_network(value, str(path))) for value in document.get("cidrs", [])
    )
    protected = [str(ipaddress.ip_address(value)) for value in document.get("protected_ips", [])]
    return domains, cidrs, protected


def build(
    services: list[catalog.Service],
    prefixes: dict[str, dict[str, Any]],
    tiers: tuple[str, ...],
    extra_domains: Iterable[str] = (),
    extra_cidrs: Iterable[str] = (),
) -> tuple[list[str], list[str]]:
    allowed_ids = {service.id for service in services if service.tier in tiers}
    domains = sorted({
        domain
        for service in services
        if service.id in allowed_ids
        for domain in service.domains
    } | set(extra_domains))
    networks = [
        ipaddress.ip_network(value)
        for service in services
        if service.id in allowed_ids
        for value in service.cidrs
    ]
    for value, meta in prefixes.items():
        owners = meta.get("services") or []
        source = meta.get("source")
        if source == "external":
            # Сети из внешних списков углубляют покрытие, но в lite не идут:
            # он существует ровно ради короткого списка для слабых устройств.
            if "extended" in tiers:
                networks.append(ipaddress.ip_network(value))
            continue
        # Префиксы из разворота ASN не привязаны к конкретному сервису — они всегда в ядре.
        if source == "asn" or not owners or any(owner in allowed_ids for owner in owners):
            networks.append(ipaddress.ip_network(value))
    networks.extend(ipaddress.ip_network(value) for value in extra_cidrs)
    collapsed = [str(network) for network in catalog.collapse(networks)]
    return domains, collapsed


def guard(
    domains: list[str], cidrs: list[str], protected: Iterable[str], label: str, limit: int = MAX_ENTRIES
) -> None:
    total = len(domains) + len(cidrs)
    if not MIN_ENTRIES <= total <= min(limit, MAX_ENTRIES):
        raise BuildError(f"{label}: {total} записей вне допустимого диапазона")
    if len(cidrs) > MAX_ROUTES:
        raise BuildError(
            f"{label}: {len(cidrs)} сетей — апдейтеры принимают не больше {MAX_ROUTES}. "
            "Сузь внешние источники (tools/import_external.py --limit)"
        )
    networks = [ipaddress.ip_network(value) for value in cidrs]
    for value in protected:
        address = ipaddress.ip_address(value)
        if any(address in network for network in networks):
            raise BuildError(f"{label}: список накрывает защищённый IP {value}")


NON_ROUTABLE = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
)


def invert_networks(cidrs: list[str]) -> list[str]:
    """0.0.0.0/0 минус российские сети и приватные диапазоны.

    Результат кладётся в AllowedIPs конфига WireGuard/AmneziaWG: туннель просто
    не забирает эти адреса, поэтому раздельное туннелирование работает даже там,
    где клиент такой функции не даёт.
    """
    exclude = list(
        ipaddress.collapse_addresses(
            [ipaddress.ip_network(value) for value in cidrs]
            + [ipaddress.ip_network(value) for value in NON_ROUTABLE]
        )
    )
    remaining = [ipaddress.ip_network("0.0.0.0/0")]
    for network in exclude:
        following: list[ipaddress.IPv4Network] = []
        for current in remaining:
            if network.subnet_of(current):
                following.extend(current.address_exclude(network))
            elif not current.overlaps(network):
                following.append(current)
        remaining = following
    return [str(network) for network in ipaddress.collapse_addresses(remaining)]


REPO_URL = "https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling"
# Значки категорий каталога (поле category в data/services/*.json). Порядок словаря —
# порядок строк в таблице релиза; новая категория без записи встанет в конец со значком 📁.
CATEGORY_ICONS = {
    "gov": "🏛️",
    "banks": "🏦",
    "market": "🛒",
    "vk": "💬",
    "yandex": "🔍",
    "media": "🎬",
    "travel": "🚆",
    "telecom": "📱",
    "delivery": "🚚",
    "health": "🏥",
    "edu": "🎓",
    "gaming": "🎮",
    "cloud": "☁️",
    "misc": "🧩",
}


def plural(value: int, one: str, few: str, many: str) -> str:
    """«1 домен», «3 домена», «11 доменов» — число вместе со словом."""
    tail = value % 100
    if 11 <= tail <= 14:
        word = many
    elif value % 10 == 1:
        word = one
    elif 2 <= value % 10 <= 4:
        word = few
    else:
        word = many
    return f"{value} {word}"


def spaced(value: int) -> str:
    return f"{value:,}".replace(",", " ")


def category_rows(services: list[catalog.Service]) -> list[tuple[str, str, list[catalog.Service], int]]:
    """(значок, название, сервисы, уникальных доменов) по категориям каталога."""
    grouped: dict[str, list[catalog.Service]] = {}
    titles: dict[str, str] = {}
    for service in services:
        grouped.setdefault(service.category, []).append(service)
        titles.setdefault(service.category, service.category_title)
    order = [category for category in CATEGORY_ICONS if category in grouped]
    order += [category for category in grouped if category not in CATEGORY_ICONS]
    return [
        (
            CATEGORY_ICONS.get(category, "📁"),
            titles[category],
            grouped[category],
            len({domain for service in grouped[category] for domain in service.domains}),
        )
        for category in order
    ]


def release_notes(
    services: list[catalog.Service], counts: dict[str, Any], sources: dict[str, int] | None = None
) -> str:
    sources = sources or {}
    catalog_domains = len({domain for service in services for domain in service.domains})
    in_catalog = counts["domains"] - counts.get("external_domains", 0) - counts.get("external_roots", 0)
    lines = [
        f"## 📊 RU Direct — сборка {counts['built']}",
        "",
        f"**{plural(counts['services'], 'сервис', 'сервиса', 'сервисов')}** · "
        f"**{plural(counts['domains'], 'домен', 'домена', 'доменов')}** · "
        f"**{plural(counts['cidrs'], 'сеть', 'сети', 'сетей')}** IPv4 · "
        f"покрытие **{spaced(counts['addresses'])}** адресов",
        "",
        "При включённом режиме исключений адреса из списка идут напрямую, остальной трафик — через VPN.",
        "",
        "### Установка скриптом на Windows и macOS",
        "",
        f"**Windows:** [install-windows.bat]({REPO_URL}/releases/latest/download/install-windows.bat). "
        f"**macOS:** [install-macos.zip]({REPO_URL}/releases/latest/download/install-macos.zip), "
        "распакуйте и запустите `install-macos.command`.",
        "Скрипт сам добавляет список и обновляет его каждые 6 часов, сохраняя ручные записи. "
        "При изменении списка VPN переподключается. Для своего сервера подписка Premium не нужна. "
        f"[Пошаговая установка]({REPO_URL}#установка-скрипта-с-автообновлением).",
        "",
        "### Состав файлов, которые используют скрипты",
        "",
        "| Файл | Записей | Доменов | Сетей IPv4 |",
        "|---|---:|---:|---:|",
        f"| **`amnezia-ru-direct.json`** — полный | {counts['entries']} | {counts['domains']} | {counts['cidrs']} |",
        f"| **`amnezia-ru-direct-ip.json`** — только сети | {counts['ip_entries']} | — | {counts['ip_entries']} |",
        f"| `amnezia-ru-direct-lite.json` — ключевые сервисы | {counts['lite_entries']} "
        f"| {counts['lite_domains']} | {counts['lite_cidrs']} |",
        f"| `wg-allowed-ips.txt` — строка `AllowedIPs` "
        f"| {plural(counts['allowed_ips'], 'префикс', 'префикса', 'префиксов')} | — | — |",
        "",
        "## 📦 Что вошло",
        "",
        "| Категория | Сервисы | Доменов |",
        "|---|---|---:|",
    ]
    rows = category_rows(services)
    for icon, title, entries, domain_count in rows:
        names = " · ".join(
            f"**{service.title}**" if service.tier == "core" else service.title
            for service in entries
        ).replace("|", "\\|")
        lines.append(f"| {icon} **{title}** | {names} | {domain_count} |")
    lines += [
        f"| **Итого: {plural(len(rows), 'категория', 'категории', 'категорий')}** "
        f"| {plural(counts['services'], 'сервис', 'сервиса', 'сервисов')}, "
        f"из них {counts['core_services']} ключевых | **{catalog_domains}** |",
        "",
        "Жирным — ключевые сервисы: они входят и в полный список, и в lite. "
        "Итог по доменам — без повторов между категориями.",
        "",
    ]
    if counts.get("external_domains") or counts.get("external_roots"):
        dropped = [
            plural(counts[key], *words)
            for key, words in (
                ("external_domains_dropped", ("поддомен", "поддомена", "поддоменов")),
                ("external_roots_dropped", ("корневой домен", "корневых домена", "корневых доменов")),
            )
            if counts.get(key)
        ]
        lines += [
            f"Доменов в полном списке — **{counts['domains']}**: {in_catalog} из каталога, "
            f"**{counts.get('external_domains', 0)}** новых поддоменов сервисов каталога и "
            f"**{counts.get('external_roots', 0)}** корневых доменов вне каталога из внешних списков — "
            "только тех, у которых все IPv4 российские. В lite внешние домены не входят."
            + (
                f" Ещё {' и '.join(dropped)} не влезли в потолок {MAX_FULL_ENTRIES} записей."
                if dropped
                else ""
            ),
            "",
        ]
    lines += [
        "## 🔗 Источники",
        "",
        "| Источник | Что даёт | В этой сборке |",
        "|---|---|---:|",
        f"| 📚 [Ручной каталог]({REPO_URL}/tree/master/data/services) | сервисы и их домены по категориям "
        f"| {plural(counts['services'], 'сервис', 'сервиса', 'сервисов')} · "
        f"{plural(catalog_domains, 'домен', 'домена', 'доменов')} |",
    ]
    if sources.get("dns"):
        lines.append(
            "| 🔎 DNS каталога → BGP (Team Cymru) | анонсируемые сети, где сейчас живут домены сервисов "
            f"| {plural(sources['dns'], 'префикс', 'префикса', 'префиксов')} |"
        )
    if sources.get("asn"):
        lines.append(
            "| 🛰️ ASN контентных площадок (RIPEstat) | все анонсы сетей VK, Яндекса, маркетплейсов, банков "
            f"| {plural(sources['asn'], 'префикс', 'префикса', 'префиксов')} |"
        )
    if sources.get("lists"):
        label = f"🧩 Внешние списки — {plural(sources['lists'], 'источник', 'источника', 'источников')}"
        external_rows = [
            ("сети, прошедшие проверку по таблице IP→ASN", sources.get("external", 0),
             ("префикс", "префикса", "префиксов")),
            ("новые поддомены сервисов каталога", counts.get("external_domains", 0),
             ("домен", "домена", "доменов")),
            ("корневые домены, у которых все IPv4 российские", counts.get("external_roots", 0),
             ("домен", "домена", "доменов")),
        ]
        for index, (what, value, words) in enumerate(external_rows):
            lines.append(f"| {label if index == 0 else ''} | {what} | {plural(value, *words)} |")
    lines += [
        "",
        f"Сети всех слоёв объединяются и схлопываются: префиксов в снимке BGP — {counts['prefix_snapshot']}, "
        f"сетей IPv4 в полном списке — **{counts['cidrs']}**. Автоматический сбор отсекает зарубежные адреса "
        "и глобальные CDN; явно проверенные ручные исключения сервисов сохраняются. "
        f"Что принято из каждого внешнего источника и почему остальное отсеяно — "
        f"[data/external-report.md]({REPO_URL}/blob/master/data/external-report.md).",
        "",
        "<details>",
        "<summary><b>📱 Ручной импорт на Android, iPhone, iPad и Linux — подробно</b></summary>",
        "",
        "### Сначала проверьте подключение",
        "",
        "**Amnezia Free: импорт этого JSON не включит раздельное туннелирование по IP.** "
        "Для этого сценария на серверах Amnezia нужна действующая подписка **Amnezia Premium**. "
        "Наши списки и скрипты не включают Premium и не снимают ограничение Free.",
        "",
        "**Свой сервер (Amnezia Self-hosted): Premium покупать не требуется**, "
        "но подключение должно поддерживать раздельное туннелирование по IP. "
        "Бесплатное приложение AmneziaVPN и подключение Amnezia Free — разные вещи. "
        "Основание: [инструкция Amnezia](https://docs.amnezia.org/ru/documentation/instructions/vpn-split-tunneling/) "
        "и [условия Self-hosted](https://amnezia.org/ru/self-hosted). Сверено 8 сентября 2026 года.",
        "",
        "### Какой файл качать",
        "",
        "| Файл | Кому нужен | Импорт в Amnezia |",
        "|---|---|:---:|",
        "| **`amnezia-ru-direct.json`** | источник Windows-скрипта: домены с IP + сети | ✅ |",
        f"| **`amnezia-ru-direct-ip.json`** | Android, iPhone, iPad и Linux — ручной импорт: "
        f"только готовые сети IPv4 ({counts['ip_entries']}), не зависит от преобразования доменных записей "
        "в IP самим клиентом. Наш macOS-updater берёт его по умолчанию. Подходит и для Windows/Android | ✅ |",
        f"| `amnezia-ru-direct-lite.json` | только ключевые сервисы: "
        f"{plural(counts['lite_entries'], 'запись', 'записи', 'записей')} вместо {counts['entries']}, "
        "только самые популярные сервисы. Бери его, если список тормозит интерфейс Amnezia | ✅ |",
        "| `wg-allowed-ips.txt` | 🔧 клиент не умеет split tunneling — строка для конфига WireGuard/AmneziaWG | — |",
        "| `ru-direct-domains.txt` | свои скрипты, AdGuard Home, dnsmasq | — |",
        "| `ru-direct-ipv4.txt` | роутеры, ipset, свой роутинг | — |",
        "| `happ-ru-direct.json` | профиль маршрутизации Happ | — |",
        "| `manifest.json` | счётчики и SHA-256 | — |",
        "",
        "Остальные файлы для импорта в Amnezia **не нужны** — они для скриптов, Happ и роутеров.",
        "",
        *(
            [
                f"Доменные записи несут снимок IPv4 на день сборки (поля `ips` и `ip`): "
                f"адреса есть у **{counts['domains_with_ips']}** из {counts['domains']} доменов "
                f"полного списка и у {counts['lite_domains_with_ips']} из {counts['lite_domains']} в lite, "
                "проверенные адреса каталога, включая явно заданные /32 общих CDN. "
                "Amnezia при импорте домены не резолвит, поэтому без этого "
                "снимка доменная запись не дала бы маршрута в AmneziaWG и на мобильных клиентах. "
                "Адреса между сборками меняются; в полном списке для Windows их регулярно "
                "обновляет наш updater.",
            ]
            if counts.get("domains_with_ips")
            else [
                "Один импорт доменов не обеспечивает обновление их IPv4. "
                "В полном списке для Windows текущие адреса регулярно заполняет наш updater.",
            ]
        ),
        "",
        f"`wg-allowed-ips.txt` — готовая строка `AllowedIPs` из {counts['allowed_ips']} префиксов: весь IPv4 "
        "минус российские сети и приватные диапазоны. Вставляется в секцию `[Peer]` "
        "конфига WireGuard или AmneziaWG вместо `0.0.0.0/0`. Нужны рабочий доступ к серверу "
        "и клиент с возможностью редактирования `AllowedIPs`. Для своего конфига Premium "
        "не требуется; этот файл не снимает ограничения подключения Amnezia Free.",
        "",
        "### Как импортировать",
        "",
        "Сначала выберите совместимое подключение: Premium с активной подпиской или свой сервер. "
        "Убедитесь, что раздельное туннелирование сайтов доступно.",
        "",
        "AmneziaVPN → **Настройки → Раздельное туннелирование сайтов** → "
        "«Адреса из списка не должны открываться через VPN» → включить функцию → ⋮ → "
        "**Добавить импортированные сайты к существующим** → выбрать JSON → **переподключить VPN**. "
        "Пункт «Заменить список с сайтами» удаляет прежние записи; для сохранения своих записей его не используйте.",
        "",
        "На iPhone сначала сохрани файл в «Файлы» (Safari → «Загрузить»), потом выбирай его оттуда.",
        "",
        "Успешный импорт подтверждает чтение файла, а не работу маршрутов. "
        "Для проверки откройте [yandex.ru/internet](https://yandex.ru/internet): "
        "при применившемся исключении он покажет IP обычного интернет-подключения. "
        "Это проверка одного соединения. За пределами России список не создаёт российский IP.",
        "",
        "</details>",
        "",
        "---",
        "",
        "Не хочешь возиться с импортом — тот же роутинг в один тап есть у "
        "[MATRIX VPN](https://mtrxvpn.com/happ-ru-direct): профиль ставится по ссылке "
        "`happ://` и обновляется сам.",
        "",
    ]
    return "\n".join(lines)


def count_external_lists(path: Path = catalog.EXTERNAL_FILE) -> int:
    """Сколько внешних источников дошло до последнего импорта (data/external.json)."""
    if not path.exists():
        return 0
    document = json.loads(path.read_text(encoding="utf-8"))
    listed = document.get("sources") if isinstance(document, dict) else None
    return len(listed) if isinstance(listed, dict) else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DIST)
    parser.add_argument("--personal", type=Path, help="личный довесок, в публичный репозиторий не коммитится")
    external_group = parser.add_mutually_exclusive_group()
    external_group.add_argument("--no-external", dest="no_external", action="store_true", default=True,
                                help="только ручной каталог (по умолчанию)")
    external_group.add_argument("--with-external", dest="no_external", action="store_false",
                                help="экспериментальная сборка с внешними кандидатами; не для релиза")
    parser.add_argument("--no-ips", action="store_true", help="доменные записи без снимка IPv4 (ip пустой)")
    parser.add_argument("--domain-ips", type=Path, default=catalog.DOMAIN_IPS_FILE)
    parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()

    try:
        services = catalog.load_catalog()
        prefixes = catalog.load_prefixes()
        if not prefixes:
            raise BuildError("нет data/prefixes.json — сначала запусти tools/refresh_prefixes.py")
        external_domains = {} if arguments.no_external else catalog.load_external_domains(services)
        external_roots = {} if arguments.no_external else catalog.load_external_roots(services)
        if arguments.no_external:
            prefixes = curated_prefixes(prefixes, set(refresh_prefixes.load_asn_expand()))
        # Нет снимка — доменные записи как раньше, с пустым ip; лишние домены снимка не нужны.
        domain_ips = (
            None if arguments.no_ips or not arguments.domain_ips.exists()
            else catalog.load_domain_ips(arguments.domain_ips)
        )

        personal_domains: list[str] = []
        personal_cidrs: list[str] = []
        protected: list[str] = []
        if arguments.personal:
            personal_domains, personal_cidrs, protected = load_personal(arguments.personal)

        base_domains, full_cidrs = build(
            services, prefixes, ("core", "extended"), personal_domains, personal_cidrs
        )
        full_domains, kept_subdomains, kept_roots, subdomains_dropped, roots_dropped = fit_full_list(
            base_domains, full_cidrs, external_domains, external_roots
        )
        lite_domains, lite_cidrs = build(
            services, prefixes, ("core",), personal_domains, personal_cidrs
        )
        # Shared hosting contributes exact validated A records, never its whole
        # BGP prefix. Every client, including the IP-only/macOS importer, gets
        # the same compact union of routes.
        full_cidrs = snapshot_routes(full_domains, full_cidrs, domain_ips or {})
        lite_cidrs = snapshot_routes(lite_domains, lite_cidrs, domain_ips or {})
        guard(full_domains, full_cidrs, protected, "полный список", MAX_FULL_ENTRIES)
        guard(lite_domains, lite_cidrs, protected, "lite-список")

        full_entries = import_entries(full_domains, full_cidrs, domain_ips)
        lite_entries = import_entries(lite_domains, lite_cidrs, domain_ips)
        # Экспорт готовых сетей не зависит от DNS-обработки доменных записей клиентом.
        ip_entries = import_entries((), full_cidrs)
        with_ips = domain_ips or {}
        routing = {
            "full": route_metrics(full_domains, full_cidrs, with_ips),
            "lite": route_metrics(lite_domains, lite_cidrs, with_ips),
        }
        for label, metrics in routing.items():
            route_limit = MAX_EFFECTIVE_ROUTES if arguments.no_external else 2_000
            if metrics["compacted"] > route_limit:
                raise BuildError(f"{label}: после DNS {metrics['compacted']} маршрутов, лимит {route_limit}")
        allowed_ips = invert_networks(full_cidrs)
        happ = {
            "DirectSites": [f"domain:{domain}" for domain in full_domains],
            "DirectIp": full_cidrs,
        }
        addresses = sum(ipaddress.ip_network(value).num_addresses for value in full_cidrs)
        counts = {
            "built": date.today().isoformat(),
            "selection_policy": "reviewed-catalog" if arguments.no_external else "experimental-external",
            "services": len(services),
            "core_services": sum(1 for service in services if service.tier == "core"),
            "domains": len(full_domains),
            "cidrs": len(full_cidrs),
            "addresses": addresses,
            "entries": len(full_entries),
            "lite_domains": len(lite_domains),
            "lite_cidrs": len(lite_cidrs),
            "lite_entries": len(lite_entries),
            "ip_entries": len(ip_entries),
            "routing": routing,
            "allowed_ips": len(allowed_ips),
            "prefix_snapshot": len(prefixes),
            "personal_domains": len(personal_domains),
            "personal_cidrs": len(personal_cidrs),
            "external_domains": len(kept_subdomains),
            "external_domains_dropped": subdomains_dropped,
            "external_roots": len(kept_roots),
            "external_roots_dropped": roots_dropped,
            "domains_with_ips": sum(1 for domain in full_domains if with_ips.get(domain)),
            "lite_domains_with_ips": sum(1 for domain in lite_domains if with_ips.get(domain)),
        }

        if arguments.dry_run:
            print(json.dumps(counts, ensure_ascii=False, indent=2))
            return 0

        outputs: dict[str, bytes] = {
            "amnezia-ru-direct.json": catalog.json_bytes(full_entries),
            "amnezia-ru-direct-lite.json": catalog.json_bytes(lite_entries),
            "amnezia-ru-direct-ip.json": catalog.json_bytes(ip_entries),
            "ru-direct-domains.txt": ("\n".join(full_domains) + "\n").encode("utf-8"),
            "ru-direct-ipv4.txt": ("\n".join(full_cidrs) + "\n").encode("utf-8"),
            "wg-allowed-ips.txt": ("AllowedIPs = " + ", ".join(allowed_ips) + "\n").encode("utf-8"),
            "happ-ru-direct.json": catalog.json_bytes(happ),
        }
        counts["sha256"] = {
            name: hashlib.sha256(payload).hexdigest() for name, payload in outputs.items()
        }
        outputs["manifest.json"] = catalog.json_bytes(counts)
        # Разбивка снимка по слоям — только для таблицы «Источники» в описании релиза.
        sources = dict(Counter(meta.get("source") for meta in prefixes.values()))
        sources["lists"] = 0 if arguments.no_external else count_external_lists()
        outputs["RELEASE_NOTES.md"] = release_notes(services, counts, sources).encode("utf-8")
        for name, payload in outputs.items():
            catalog.atomic_write(arguments.output_dir / name, payload)

        print(
            f"собрано: {counts['entries']} записей "
            f"({counts['domains']} доменов + {counts['cidrs']} сетей), "
            f"lite — {counts['lite_entries']}"
        )
        if arguments.personal:
            print(
                f"личный довесок: {counts['personal_domains']} доменов, "
                f"{counts['personal_cidrs']} сетей"
            )
        return 0
    except (catalog.CatalogError, refresh_prefixes.RefreshError, BuildError, OSError, json.JSONDecodeError) as exc:
        print(f"ОШИБКА: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
