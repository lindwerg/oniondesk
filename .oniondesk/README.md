# OnionDesk macOS native V5 R4 — provenance

Локальный derivative от commit `59bf58813c5f19384b56e01ede130666ef845a72`. Статус: `LOCAL_ONLY_NOT_UPLOADED`. Состав корня: приложение и единственное руководство; metadata скрыта в `.oniondesk/`.

## Native R4

Launcher читает source worker как недоверенные bytes и создаёт независимую exclusive private-копию. Он проверяет закреплённый SHA, закрывает writable FD, задаёт 0555 и применяет неизменный WorkerExecutableGuard. Worker получает ровно `--source-root` и путь Bundle transport pool. Исходный bundle и его предки не chmod; embedded manifest, engine.Restore, cache guards и Core entrypoint сохранены. Cancel/Quit ждут завершения подготовки и очистки недоставленной копии.

Все 556 transport pointers и guide pointer совпадают с base commit. Изменены только launcher, worker, CodeResources и эти два provenance-файла. Сборка выполнена из точных 51 исходников в нейтральном реальном build tree; новые native blobs проверены на отсутствие private HOME/account/compiler path literals.

## Соответствующие исходники и GPL

Собственные native launcher и worker/engine распространяются на условиях GNU GPL v3. Точный текст: `licenses/OnionDesk-GPLv3.txt`.

Полный R4 privacy-fixed source addendum: [oniondesk-macos-r4-privacy-source-20261017.tar.gz](https://github.com/lindwerg/oniondesk/releases/download/preview-2026.10.16-v5/oniondesk-macos-r4-privacy-source-20261017.tar.gz).

SHA-256: `c4a4f4e0bd6166363b4883e81aedbb5e3081621bf7a529c43c3f331b1d6ae360`; 1673190 байт. Он содержит все 51 configured source file, tests, build recipe, pins, icon/PkgInfo и GPL. Плановый обычный asset приватного Release `preview-2026.10.16-v5` загружает root отдельно. Приложение по этой ссылке ничего не скачивает.

Неизменённые компоненты, notices и 50 Debian source packages: [базовый source archive](https://github.com/lindwerg/oniondesk/releases/download/preview-2026.10.16-v5/oniondesk-native-bootstrap-source-20261017.tar.gz), SHA-256 `72be43a42e70f0eda28ee5246855eb631e38d5b9abf81d1c599ac9c11081fedf`. Source addendum не включает весь runtime/Core. Исходники Core находятся в [приватной main-ветке](https://github.com/lindwerg/oniondesk/tree/main); доступ к приватным материалам требует прав к репозиторию. Лицензии отдельных payload-компонентов сохраняются в их notices.

## Границы проверки

Strict/deep codesign локального native candidate — PASS. Root сообщил PASS холодного GUI mode-fixture с исходными директориями 0775 и data-файлами 0664: подготовка, первый экран Core, Next action и Quit собственного Core. Это локальный тест. Новая remote full ZIP/TAR загрузка для данного R4 ref пока не проверена; Gatekeeper/notarization не заявляются. Запись о дефекте default extraction R3 сохранена в прежних proof без изменений.

Локальный `git archive` здесь проверяется как pointer-only. Никаких network/push/upload/GUI в ходе этой Git-подготовки не выполнялось.
