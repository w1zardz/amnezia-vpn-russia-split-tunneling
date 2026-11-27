# AGENTS.md — amnezia-split-route-sync

> Ревизия 28.11.2026. Правила проекта и инварианты сборки ведутся в [CLAUDE.md](CLAUDE.md).

## Перед работой

1. Прочитать [CLAUDE.md](CLAUDE.md): репозиторий **публичный** (`tools/privacy_scan.py` обязателен), все `windows/*.ps1` — строго в UTF-8 с BOM, `dist/*` обязаны совпадать с выводом `tools/build_ru_direct.py`.
2. Перед правками на чистом дереве подтянуть ежедневное автообновление списков: `git fetch origin && git merge --ff-only origin/master`.
3. Делегированные воркеры работают только в указанных путях и не выполняют `git commit` / `git push`; публикацию проверенных путей в `origin/master` делает основной агент.
