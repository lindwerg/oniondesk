# OnionDesk native V5 — сведения для разработчика

Платформа: `linux-x64`. Локальная подготовка: `LOCAL_ONLY_NOT_UPLOADED`.
В корне находятся приложение и единственное руководство. Скрытые ресурсы нужны для автономного восстановления; перемещайте комплект целиком.

## Лицензия и соответствующие исходники

Оболочки OnionDesk и bootstrap engine распространяются на условиях GNU GPL v3. Текст находится в `licenses/OnionDesk-GPLv3.txt`. Компоненты runtime/Core сохраняют собственные лицензии и notices в восстановленном payload; в Linux лицензии частных библиотек также лежат в `bootstrap/licenses/`, а рецепт — в `bootstrap/BUILD-AND-LICENSES.md`.

Соответствующие исходники bootstrap: [https://github.com/lindwerg/oniondesk/releases/download/preview-2026.10.16-v5/oniondesk-native-bootstrap-source-20261017.tar.gz](https://github.com/lindwerg/oniondesk/releases/download/preview-2026.10.16-v5/oniondesk-native-bootstrap-source-20261017.tar.gz)

SHA-256: `72be43a42e70f0eda28ee5246855eb631e38d5b9abf81d1c599ac9c11081fedf`. Это обычный asset приватного Release. Для доступа нужны права к репозиторию. Архив охватывает engine, оболочки, producer, настроенные manifests и build recipes; исходники всего runtime/Core и третьих сторон в этот bootstrap-архив не входят. Ссылка — сведения о распространении исходников, приложение её не загружает.

## Локальная Git-проверка

Транспортные blobs и руководство представлены каноническими Git LFS pointers. Обычный `git archive` в этой проверке содержит pointers. Удалённые refs, expanded ZIP/TAR и загрузка пользователем здесь не проверялись. Windows GUI/UAC и Linux Tor ARM64 этой сборкой не подтверждаются.
