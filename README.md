# Amnezia VPN: российские сайты напрямую, остальное через VPN

[![Сборка](https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/actions/workflows/release.yml/badge.svg)](https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/actions/workflows/release.yml)
[![Обновлено](https://img.shields.io/github/last-commit/w1zardz/amnezia-vpn-russia-split-tunneling?label=обновлено&color=brightgreen)](https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/releases/latest)
[![Звёзды](https://img.shields.io/github/stars/w1zardz/amnezia-vpn-russia-split-tunneling?style=flat)](https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/stargazers)

Готовые списки российских сайтов и сетей IPv4 для **раздельного туннелирования в AmneziaVPN**.
Банки, Госуслуги, Ozon, Wildberries, Avito, Яндекс и VK идут через обычное подключение;
остальной трафик остаётся в VPN. Подходит для уже настроенного **своего сервера или Amnezia Premium**.

- **Windows и macOS:** установщик и еженедельная проверка обновлений, с сохранением ваших ручных правил.
- **Android, iPhone, iPad и Linux:** скачайте JSON и импортируйте через интерфейс AmneziaVPN.
- **Проверенный каталог:** ежедневная сборка, до 1000 публичных маршрутов после объединения сетей и IP из DNS. Точные числа — в [manifest.json](dist/manifest.json).

**Помогло? Поставьте ⭐ Star вверху страницы — так вы поддержите развитие проекта.**

<a id="быстрый-старт"></a>
<a id="установка-скрипта-с-автообновлением"></a>

## Скачать и настроить

| Устройство | Скачать | Что делать |
|---|---|---|
| **Windows 10/11** | [Установщик .bat](https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/releases/latest/download/install-windows.bat) | Запустите и подтвердите запрос администратора. [Пошагово](docs/guide.md#-windows--в-один-клик) |
| **macOS 14+** | [Установщик .zip](https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/releases/latest/download/install-macos.zip) | Распакуйте → правой кнопкой по `install-macos.command` → «Открыть». [Пошагово](docs/guide.md#-macos--в-один-клик) |
| **Android / iPhone / iPad** | [Список IPv4 .json](https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/releases/latest/download/amnezia-ru-direct-ip.json) | [Ручной импорт — 4 шага ниже](#ручной-импорт-json) |
| **Linux** | [Список IPv4 .json](https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/releases/latest/download/amnezia-ru-direct-ip.json) | [Ручной импорт](#ручной-импорт-json) или [свой роутинг](docs/guide.md#-linux) |

**Перед запуском установщика:** скрипты меняют исключения AmneziaVPN.
При работающем окне Amnezia или туннеле применение откладывается; VPN автоматически не отключается.
Перед реальным применением скрипт штатно закрывает **Claude и ChatGPT**; если закрытие не удалось, отменяет применение.
После обновления эти приложения не запускаются. **Claude CLI завершите вручную.**
Подробности и ограничения — [приватность](docs/ip-privacy.md).

Установленный скрипт проверяет список **по воскресеньям в 12:00 местного времени**.
Для применения изменённого списка GUI и туннель Amnezia должны быть закрыты.
[Установка через Терминал/PowerShell](docs/guide.md#установка-скрипта-с-автообновлением) · [Удаление автообновления](docs/guide.md#отключение-автообновления).

<a id="ручной-импорт-json"></a>

## Android, iPhone, iPad и ручной импорт

1. Скачайте [**amnezia-ru-direct-ip.json**](https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/releases/latest/download/amnezia-ru-direct-ip.json).
2. В AmneziaVPN откройте **Настройки → Подключение → Раздельное туннелирование сайтов**.
3. Выберите **«Адреса из списка НЕ должны использовать VPN»**. Откройте **⋮ → Импорт** и выберите **добавление к существующим** — так сохранятся ваши записи. Замена списка удалит прежние записи.
4. Включите раздельное туннелирование сайтов и **переподключите VPN вручную**. Перед переподключением закройте приложения, которым нельзя выходить в интернет без VPN.

**Выбранные сайты видят IP вашего обычного подключения.** Это намеренный обход VPN.
Список не создаёт российский IP за границей и не гарантирует покрытие каждого адреса сервиса.
Нужна функция раздельного туннелирования по IP: **свой сервер или Premium; Amnezia Free её не поддерживает**.
[Инструкция по платформам](docs/guide.md#-iphone-ipad-и-android) · [Документация Amnezia](https://docs.amnezia.org/ru/documentation/instructions/vpn-split-tunneling/).

<details>
<summary>Показать анимированную инструкцию</summary>

![Ручной импорт списка IPv4 в AmneziaVPN: скачать JSON, выбрать исключения, добавить записи и переподключить VPN](docs/media/split-tunneling-demo.gif)

Пошаговая памятка; названия пунктов могут отличаться между версиями клиента. [Видео MP4](docs/media/split-tunneling-demo.mp4).

</details>

## Что отличает этот проект

| Возможность | Как работает |
|---|---|
| Автоматизация на компьютере | Windows/macOS проверяют список раз в неделю; работающая Amnezia откладывает применение |
| Ваши записи сохраняются | Скрипты обновляют свою управляемую часть; пользовательские записи вне неё остаются |
| Ограничение числа маршрутов | Сборка останавливается при превышении 1000 публичных маршрутов; есть [lite для слабых устройств](https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/releases/latest/download/amnezia-ru-direct-lite.json) |
| Проверяемые источники | [Ручной каталог сервисов](data/services/), проверки страны и владельца для автоматически собранных сетей; внешние списки не входят в автоматические релизы |
| Форматы для других клиентов | Списки доменов, CIDR, фрагмент Happ и строка `AllowedIPs` для собственного конфига WireGuard/AmneziaWG |

В каталоге: **банки и платежи · Госуслуги · маркетплейсы · VK и Mail.ru · Яндекс · кино и медиа · транспорт · связь · доставка · медицина · образование · игры**.
Полный состав текущей сборки — в [описании релиза](https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/releases/latest) и [каталоге](data/services/).

## Другие файлы и клиенты

| Файл | Назначение |
|---|---|
| [amnezia-ru-direct.json](https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/releases/latest/download/amnezia-ru-direct.json) | Домены с IP и сети; источник Windows-скрипта |
| [amnezia-ru-direct-ip.json](https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/releases/latest/download/amnezia-ru-direct-ip.json) | Сети IPv4; macOS и ручной импорт |
| [amnezia-ru-direct-lite.json](https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/releases/latest/download/amnezia-ru-direct-lite.json) | Основные сервисы для слабых устройств |
| [ru-direct-domains.txt](https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/releases/latest/download/ru-direct-domains.txt) | Домены построчно: Xray, AdGuard, свои правила |
| [ru-direct-ipv4.txt](https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/releases/latest/download/ru-direct-ipv4.txt) | Сети IPv4 в CIDR |
| [happ-ru-direct.json](https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/releases/latest/download/happ-ru-direct.json) | Фрагмент routing-профиля Happ; [как использовать](docs/guide.md#-happ-xray-роутеры) |
| [wg-allowed-ips.txt](https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/releases/latest/download/wg-allowed-ips.txt) | Строка `AllowedIPs` для собственного конфига; [инструкция](docs/guide.md#-клиент-не-умеет-split-tunneling--правим-allowedips) |

Постоянные ссылки `releases/latest/download/…` всегда ведут на свежую сборку. [Все файлы и контрольные суммы](dist/manifest.json).

<a id="совместимость"></a>

## Частые вопросы

**Нужна ли подписка?** Для своего сервера — нет. Подключение Amnezia Premium поддерживается; Amnezia Free не поддерживает раздельное туннелирование по IP. Скрипт и JSON эту функцию не включают.

**Это работает с AmneziaWG?** С протоколом AmneziaWG внутри AmneziaVPN — да. Отдельный клиент AmneziaWG скрипты не настраивают; для собственного конфига есть `AllowedIPs`.

**Если сайт всё ещё идёт через VPN?** Проверьте режим исключений, включение функции, переподключение и версию клиента. Адрес сервиса может отсутствовать в списке. [Диагностика](docs/guide.md#почему-не-работает-раздельное-туннелирование-в-amnezia).

**А IPv6 и защита IP?** Эти списки — IPv4. Обновлятор не обеспечивает постоянную блокировку доступа без VPN. [IPv6](docs/guide.md#у-меня-есть-ipv6--российские-сайты-тормозят-или-не-грузится-оплата-что-делать) · [KillSwitch на Windows](docs/windows-killswitch.md) · [Защита IP](docs/ip-privacy.md).

## Помочь проекту

- **Поставьте ⭐ Star**, если список пригодился. Новые сборки появляются в [Releases](https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/releases/latest).
- Нашли отсутствующий сайт или проблему? [Создайте issue](https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/issues/new): укажите ОС, версию AmneziaVPN, режим и домен. **Не прикладывайте VPN-ключи, профили или приватные адреса.**
- Добавить сервис: [формат каталога и команды сборки](docs/guide.md#свои-домены-и-сети). Общие вопросы — в [Discussions](https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling/discussions).

[Подробная инструкция и FAQ](docs/guide.md) · [Источники данных](NOTICE.md) · [Сообщить об уязвимости](SECURITY.md) · [Лицензия MIT](LICENSE).

Проект независимый, не связан с Amnezia. Результат зависит от клиента, сети и адресов сервиса.

<a id="отключение-автообновления"></a>
<a id="windows--полностью-автоматически"></a>
<a id="macos--полностью-автоматически"></a>
<a id="-macos--в-один-клик"></a>

**Старые ссылки на разделы:** [Windows](docs/guide.md#windows--полностью-автоматически) · [macOS](docs/guide.md#macos--полностью-автоматически) · [Удаление](docs/guide.md#отключение-автообновления) · [Установка macOS](docs/guide.md#-macos--в-один-клик).
