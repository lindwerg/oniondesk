# Лицензии поставки OnionDesk

Обновлено: **2026-10-17**.

Оригинальный код OnionDesk — [GNU GPL версии 3](../LICENSE), `GPL-3.0-only`. Сторонние компоненты сохраняют собственные условия. [Полный перечень прав, уведомлений и исходных архивов](../docs/LICENSES.md).

В ZIP текущего R5 тексты лицензий и source references находятся в скрытой папке `.oniondesk/LICENSES`. Сохраняйте распакованный комплект целиком. На Mac ресурсы запуска находятся внутри `OnionDesk.app`; внешний runtime-пул рядом с ним не требуется.

Для соответствующих исходников нужны:

- [Исходники R5](https://github.com/lindwerg/oniondesk/releases/download/runtime-data-2026.10.17-v6/oniondesk-r5-corresponding-source-20261017.tar.gz), [SOURCES.json](https://github.com/lindwerg/oniondesk/releases/download/runtime-data-2026.10.17-v6/SOURCES.json) и [SHA256SUMS](https://github.com/lindwerg/oniondesk/releases/download/runtime-data-2026.10.17-v6/SHA256SUMS).
- [Неизменённые базовые исходники и 50 пакетов Debian](https://github.com/lindwerg/oniondesk/releases/download/preview-2026.10.16-v5/oniondesk-native-bootstrap-source-20261017.tar.gz).
- [Неизменённое дополнение Linux R4](https://github.com/lindwerg/oniondesk/releases/download/preview-2026.10.16-v5/oniondesk-linux-r4-source-20261017.tar.gz).
- [Исходники Core V5 в main](https://github.com/lindwerg/oniondesk/tree/main).

Архив R5 содержит код нативных загрузчиков, транспорта и producer с build-инструкциями и входными ресурсами. Большие runtime-объекты, компиляторы и SDK в него не включены. Точные хеши и границы состава приведены в [документе о лицензиях](../docs/LICENSES.md).

- [Monero](Monero/LICENSE) · [источники](Monero/SOURCE.txt).
- [Android SDK](Android/GOOGLE-ANDROID-SDK-LICENSE.txt) · [источники Android/Tor](Android/SOURCES.txt).
- [Tor Browser](Android/TOR-BROWSER-LICENSE.html).
- [JetBrains Mono](../client/ui/fonts/OFL.txt) · [происхождение шрифтов](../client/ui/fonts/SOURCE.json).
