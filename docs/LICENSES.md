# Права и сторонние компоненты

Обновлено: **2026-10-17**.

Оригинальный код OnionDesk распространяется по **GNU GPL версии 3** (`GPL-3.0-only`): [полный текст лицензии](../LICENSE). Это разрешает использование, изменение и распространение кода с соблюдением GPLv3, включая предоставление соответствующих исходников при распространении изменённых бинарных версий. Решение принято владельцем проекта. 17 октября 2026 года владелец отдельно разрешил публичный доступ: репозиторий открыт для просмотра, скачивания и распространения с соблюдением лицензий.

## Исходники текущей поставки R5

Исходники оригинального Core V5 находятся в [ветке main](https://github.com/lindwerg/oniondesk/tree/main). Интерфейс и Core сохранены; R5 меняет нативный запуск и доставку runtime.

- [Архив соответствующих исходников R5](https://github.com/lindwerg/oniondesk/releases/download/runtime-data-2026.10.17-v6/oniondesk-r5-corresponding-source-20261017.tar.gz): **65 981 280 bytes**, SHA-256 `5e81d984cfc54b43ea5c1a065ba4c923dceb1abb0fe2d582062988742754d52e`.
- [SOURCES.json](https://github.com/lindwerg/oniondesk/releases/download/runtime-data-2026.10.17-v6/SOURCES.json) — точное соответствие исходных путей, размеров, режимов и SHA-256; [SHA256SUMS](https://github.com/lindwerg/oniondesk/releases/download/runtime-data-2026.10.17-v6/SHA256SUMS) — контрольные суммы опубликованных архивов.
- В архиве сохранены точные исходники Mac, Windows, Linux, общего транспорта и producer, build-инструкции, 18 локально замкнутых Go-модулей, настоящие входные ресурсы Linux и 176 notices для двух архитектур. Проверка 820 файлов и независимые general/Python review завершились успешно.
- Компиляторы и SDK, 866 больших runtime-объектов и две части данных в этот исходный архив не входят. Полный офлайн-запуск без предварительной загрузки runtime не заявляется. Точные требования сборки перечислены в `BUILDING.md` внутри архива.

Архив R5, `SOURCES.json` и `SHA256SUMS` повторно скачаны из публичного Release без авторизации; размеры и SHA-256 совпали. Исходный архив R5 **не заменяет** необходимые неизменённые сторонние исходники:

| Состав | Архив и контрольная сумма |
|---|---|
| Базовые bootstrap, engine, producer и 50 исходных пакетов Debian | [Исходники](https://github.com/lindwerg/oniondesk/releases/download/preview-2026.10.16-v5/oniondesk-native-bootstrap-source-20261017.tar.gz) · [SHA256SUMS](https://github.com/lindwerg/oniondesk/releases/download/preview-2026.10.16-v5/oniondesk-native-bootstrap-source-20261017.SHA256SUMS); SHA-256 архива `72be43a42e70f0eda28ee5246855eb631e38d5b9abf81d1c599ac9c11081fedf` |
| Неизменённые Linux runtime и исходники R4 | [Дополнение Linux R4](https://github.com/lindwerg/oniondesk/releases/download/preview-2026.10.16-v5/oniondesk-linux-r4-source-20261017.tar.gz) · [SHA-256](https://github.com/lindwerg/oniondesk/releases/download/preview-2026.10.16-v5/oniondesk-linux-r4-source-20261017.tar.gz.sha256); SHA-256 архива `ba98510e06ae5a58aa9dc4bf46197cbcb854895c7fa74a1b5ebc53e8c83611e6` |
| Историческое исправление приватности Mac R4 | [Дополнение Mac R4](https://github.com/lindwerg/oniondesk/releases/download/preview-2026.10.16-v5/oniondesk-macos-r4-privacy-source-20261017.tar.gz) · [SHA-256](https://github.com/lindwerg/oniondesk/releases/download/preview-2026.10.16-v5/oniondesk-macos-r4-privacy-source-20261017.tar.gz.sha256) |

Эти архивы остаются доступными обычными Release-вложениями. Новая поставка сохраняет тексты лицензий и source references в `.oniondesk/LICENSES`. Это проверка состава и ссылок на соответствующие исходники; полная юридическая сертификация всех сторонних файлов не заявляется.

## Сторонние компоненты

Лицензия нашего кода не заменяет лицензии сторонних компонентов, иллюстраций, шрифтов и других материалов. Существующие уведомления об авторских правах и условиях использования сохраняются. Для D-Bus и соответствующих частей AT-SPI в поставке Linux используется совместимая ветвь **GPL-2.0-or-later**, а не альтернативная AFL.

Выпуски с частными динамическими библиотеками Linux должны предоставлять соответствующие исходные пакеты Debian, упаковочный рецепт, тексты лицензий и уведомления рядом с бинарными файлами. Пользователь вправе заменить совместимые динамические библиотеки для собственного использования и отладки таких изменений. Базовый исходный архив относится к bootstrap и его библиотекам; полный комплект соответствующих исходников использует перечисленные выше архивы и исходники Core в main. Проверка замены библиотек ещё не завершена.

Это программное обеспечение частично основано на работе **FreeType Team**.

Сторонние компоненты сохраняют свои условия и attribution:

- [Monero: LICENSE](../LICENSES/Monero/LICENSE) и [источники](../LICENSES/Monero/SOURCE.txt).
- [Google Android SDK terms](../LICENSES/Android/GOOGLE-ANDROID-SDK-LICENSE.txt), оригинальные component NOTICE для платформ и [источники Android/Tor](../LICENSES/Android/SOURCES.txt).
- [Tor Browser component licenses](../LICENSES/Android/TOR-BROWSER-LICENSE.html).
- [JetBrains Mono OFL](../client/ui/fonts/OFL.txt), [источники и точные хеши шрифтов](../client/ui/fonts/SOURCE.json).

Большие оригинальные архивы не находятся в Git. Их внутренние лицензии и notices должны сохраняться в релизном payload. Для GnuPG, PyInstaller, Python, системных библиотек и остальных бинарных зависимостей сборщик должен включить соответствующие license/source сведения; существующие сборщики содержат часть такой процедуры. Отсутствие бинарника в этом экспорте не отменяет обязанностей при его последующем распространении.

Происхождение имеющихся иллюстраций и персонажа этим экспортом не переопределяется. Перед расширением распространения права проверяются владельцем проекта отдельно. Изображения в README служат демонстрацией и не являются фактами испытаний.
