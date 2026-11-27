# CLAUDE.md — amnezia-split-route-sync

> Ревизия 28.11.2026. Единые правила разработки и проверок для ИИ-агентов.

## 1. Публичный статус репозитория и приватность (КРИТИЧНО)

- Это **публичный** open-source репозиторий (`w1zardz/amnezia-vpn-russia-split-tunneling`).
- ⛔ **Никогда не добавлять в файлы репозитория и сообщения коммитов:** приватные IP серверов, внутренние домены, ключи, токены, UUID, URI подписок, абсолютные домашние пути ОС, дампы/логи и локальный `config/protected-ips.json`.
- Любая правка обязана проходить `python3 tools/privacy_scan.py` (запускается первым шагом в `.github/workflows/validate.yml`).

## 2. Архитектура и инварианты сборки

- **Источники и сборка (`data/`, `config/`, `tools/`, `dist/`):**
  - `data/services/*.json` — курируемый каталог российских сервисов; `config/asn-expand.json` и `config/external-sources.json` — правила расширения подсетей и внешних списков.
  - Сборка `python3 tools/build_ru_direct.py` формирует артефакты в `dist/` (`amnezia-ru-direct.json`, `amnezia-ru-direct-ip.json`, `amnezia-ru-direct-lite.json`, `ru-direct-domains.txt`, `ru-direct-ipv4.txt`, `happ-ru-direct.json`, `wg-allowed-ips.txt`, `manifest.json`).
  - Жёсткий потолок основной сборки — **до 1000 публичных маршрутов**; закоммиченные файлы в `dist/` обязаны побайтово совпадать с результатом `tools/build_ru_direct.py` (иначе упадёт CI `validate.yml`).
- **Windows (`windows/*.ps1`):**
  - ⛔ **Все файлы `windows/*.ps1` обязаны сохраняться в UTF-8 с BOM (`\xef\xbb\xbf`)** — без BOM Windows PowerShell 5.1 читает кириллицу как ANSI и ломает парсинг (проверяется в CI).
- **macOS (`macos/`):**
  - Обновлятор `macos/update_amnezia_routes.py`, нативный помощник `macos/set-amnezia-routes.swift`, скрипты установки `macos/install.sh`, `macos/install-macos.command`, `macos/uninstall.sh`.
- **Безопасность применения у пользователя:**
  - При открытом окне или активном туннеле AmneziaVPN автообновление откладывается (туннель сам не рвётся); ручные записи пользователя вне управляемого блока сохраняются.

## 3. Обязательные проверки перед коммитом

```bash
python3 tools/privacy_scan.py
python3 -m unittest discover -s tools -p test_collectors.py
python3 -m unittest discover -s macos -p test_updater.py
python3 tools/catalog.py
bash -n macos/install.sh macos/uninstall.sh macos/install-macos.command
```

Если менялись `data/`, `config/` или `tools/build_ru_direct.py` — пересобрать `dist/` и убедиться, что `diff` чист.

## 4. Git и публикация

- Ежедневный workflow обновляет `data/` и `dist/` напрямую в `origin/master` — перед началом работы на чистом дереве выполнять `git fetch origin && git merge --ff-only origin/master`.
- Работать в ветке `master` (без лишних веток и PR, если не запрошено явно).
- После прохождения проверок сразу выполнять `git commit` и `git push origin master` без вопросов и только по явным своим путям (`git add -- <пути> && git commit -m "Суть изменения" -- <пути> && git push origin master`), автор `w1zardz`, на русском, без AI-атрибуции.

---

## 5. Известные технические решения (не откатывать)

### 🐢 ИНЦИДЕНТ 2026-11-09: общая папка ПК копировалась через VPN (~1 МБ/с)

Симптом: Finder копировал 35 ГБ с SMB-шары ПК (`\\192.168.1.133\Videos`) «около 5 часов», хотя раньше всё летало. ПК по кабелю 1 Гбит/с, Mac на Wi-Fi 648 Мбит/с, маршрут ПК → Mac через Ethernet, диск ПК 3–9 ГБ/с.

Как ловили:
- голый TCP ПК → Mac (`TcpClient` → `nc`/python): **24,9 МБ/с** — сеть цела;
- SMB-чтение той же шары: **0,5–1 МБ/с** — тормозит именно SMB;
- `smbutil multichannel -m` показал активный канал `utun6 → 10.8.1.1` (адрес ПК внутри туннеля Amnezia), а не `en0 → 192.168.1.133`.

Корень: ПК и Mac подключены к одному серверу Amnezia и видят друг друга в подсети туннеля. Windows объявляет адаптер AmneziaVPN (WireGuard) как **100 Гбит/с**, SMB multichannel на Mac выбирает самый быстрый интерфейс → трафик локальной сети уходит на VPN-сервер и обратно.

Фикс (коммит `a9016e6`), не откатывать:
- macOS `install.sh`: `mc_on=no` в `~/Library/Preferences/nsmb.conf` (без sudo), строки с маркером `# amnezia-route-sync: SMB multichannel off`; заданный пользователем `mc_on` не трогаем; `uninstall.sh` снимает только свои строки.
- Windows `install.ps1`: `Set-SmbServerConfiguration`/`Set-SmbClientConfiguration -EnableMultiChannel $false`, прежние значения → `smb-multichannel.json`, `uninstall.ps1` их возвращает.
- Отвязка `ms_server` от адаптера туннеля НЕ годится: Amnezia пересоздаёт адаптер при каждом подключении, привязка возвращается.
- После изменения сетевые диски нужно подключить заново: настройка действует на новые сессии.
