# OnionDesk Linux R4 — сведения о поставке

Платформа: `linux-x64`. Статус новой derivative-ветки: `LOCAL_ONLY_NOT_UPLOADED`.
В корне находятся native ELF и единственное руководство. Скрытая `.oniondesk/` содержит прежние498 Core blobs, manifest, notices и metadata; перемещайте комплект целиком.

Static stage0 содержит70 проверяемых mini inputs, восстанавливает GTK CUI/worker/64 libraries/fonts в отдельный owner-only `OnionDesk-Native-UI-R4`, затем запускает private CUI. Внешние executable worker/bootstrap libraries в этой поставке не нужны. Core contract и cache `OnionDesk-Offline` сохранены. Приложение не скачивает runtime и не использует shell launcher.

## Source и notices

Полный R4 source addendum: https://github.com/lindwerg/oniondesk/releases/download/preview-2026.10.16-v5/oniondesk-linux-r4-source-20261017.tar.gz
SHA256: `ba98510e06ae5a58aa9dc4bf46197cbcb854895c7fa74a1b5ebc53e8c83611e6`; 59825135 bytes; local prepared ordinary asset, ещё не загружен этой задачей. Включены296 frozen inputs, обе configured mini production copies со всеми70 binary inputs, Go/C/producer source, tests, воспроизводимые recipes, GPLv3 и third-party notices.

Неизменный base source с50 Debian packages: https://github.com/lindwerg/oniondesk/releases/download/preview-2026.10.16-v5/oniondesk-native-bootstrap-source-20261017.tar.gz
SHA256: `72be43a42e70f0eda28ee5246855eb631e38d5b9abf81d1c599ac9c11081fedf`.
Собственный код GPLv3: `licenses/OnionDesk-GPLv3.txt`; Debian notices: `bootstrap/licenses/`; Go notices: `licenses/go1.26.2/`. Core сохраняет собственные лицензии/notices; его source-reference — https://github.com/lindwerg/oniondesk/tree/main. Ссылки служат для распространения исходников и автоматически приложением не открываются.

## Границы проверки

Новый Git tree локально проверяется как pointer-only derivative от `88041c8548d0a38b483fb2eb9642466b9b3721cb`: все499 LFS pointers byte/OID/mode-identical. Новый remote ZIP/TAR не скачивался, ref/asset не публиковались. Root native cold/warm/window/Cancel/Quit QA этой embedded сборки пока pending; PASS предыдущих версий к ней не переносится.

Git mode metadata не выдаётся за измеренные права после распаковки: GitHub archive/extractor может дать dirs0775/data0664. R4 рассчитан на data-only внешний pool и strict private cache; фактическая проверка извлечения/GUI остаётся root gate. Неизбежная ранняя ошибка показывает trusted system zenity/kdialog при наличии, иначе фиксированный stderr; универсальный OS-dialog не обещается.
