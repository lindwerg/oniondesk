# Контракт подготовки Tails USB

Актуально: 15 октября 2026.

`system_info()` возвращает JSON-словарь с `platform`, `architecture`,
`supported`, `tails_can_boot_here`, `boot_message`, `verifier_available`,
`verifier_message`, `minimum_usb_bytes`, `download_notice`.
На Apple Silicon подготовка доступна, загрузка Tails на этом Mac — нет.

`list_usb_disks()` возвращает список `{id, name, size_bytes, identity, platform}`.
`id` — непрозрачный токен выбранного безопасного USB-диска внутри процесса.
Пути устройств и неподходящие диски в интерфейс не выдаются. Носители без
аппаратного серийного номера не предлагаются. Пустой список допустим.

`download_verified_image(progress_cb, cancel_event)` возвращает
`{path, sha256, version, size_bytes, verified: true}`. Путь информационный:
функция записи использует только внутренний результат текущей загрузки.
GnuPG обязательна: встроенная в bundle либо уже установленная. Подпись
проверяется в изолированном keyring с закреплённым первичным ключом Tails.
Сначала `offline_bundle.prepare_tails()` ищет официальный подписанный IMG
Tails 7.15 в общей папке `OnionDesk-Data`. Каталог программы закрепляет
пути, размеры и SHA-256 образа, подписи и ключа; manifest не может изменить
эти значения. Файлы копируются в защищённый кэш и проходят проверку подписи
без Интернета. Повреждённая или устаревшая найденная папка вызывает отказ;
сетевая загрузка допускается только при отсутствии офлайн-папки.
Контрольная сумма из HTTPS latest.json — дополнительная проверка, не замена подписи.
При сетевой загрузке ключ обновляется с сайта, но смена первичного fingerprint
требует обновления программы. Версии ниже 7.15 и ниже уже проверенной локально
версии запрещены в обоих вариантах.

`write_verified_image(selection, typed_confirmation, progress_cb, cancel_event)`
принимает `selection` как объект из списка либо его строковый `id`.
`typed_confirmation` должно в точности равняться `СТЕРЕТЬ`.
Возвращает `{verified: true, sha256, bytes_written, version, name}` только после
синхронизации устройства и полного чтения записанной области с проверкой SHA-256.
Запись напрямую заменяет таблицу разделов. Это новая установка с потерей данных
и существующего Persistent Storage; отдельное форматирование не выполняется.
Не обещается безопасное уничтожение прежних данных вне записанного образа.

Прогресс всегда имеет `{stage, message, percent}`; для скачивания/записи/чтения
добавляются `bytes_done`, `bytes_total`. `percent` может быть `null`.
Стадии: `offline`, `tor`, `metadata`, `download`, `signature`, `verified`, `source`, `admin`,
`unmount`, `write`, `flush`, `readback`, `complete`.
Ошибки: `USBError` (подкласс RuntimeError), отмена — `USBCancelled` (USBError).
Все сообщения предназначены для пользователя и написаны по-русски.

Источник хранится в `client/data/tails` при запуске Python-исходников, либо
в пользовательском кэше `OnionDesk/tails` у самостоятельного приложения.
Перед записью источник заново хешируется. Помощник с правами администратора
создаёт защищённую временную копию, ещё раз проверяет SHA и подпись и повторно
сверяет аппаратный идентификатор/размер/USB-шину диска. На Linux применяется
эксклюзивное открытие устройства, Windows блокирует тома перед размонтированием;
macOS выполняет обычное `unmountDisk` без принудительного отключения.
Системные/загрузочные/swap-диски, диски с программой или образом и сложные
контейнеры не допускаются. Отмена обрабатывается между блоками 1 МиБ; зависший
драйвер ОС может задержать её. Прерванную флешку необходимо записать заново.

Системные права: Windows UAC, macOS стандартное окно администратора, Linux
polkit `pkexec` в графическом сеансе. Приложение не собирает пароли ОС.
Самостоятельное приложение запускает тот же бинарный файл с аргументами
`--usb-privileged <request.json>`; entry point должен вызвать
`usb_privileged.main(sys.argv[2:])` до открытия пользовательского интерфейса.
Встроенный GnuPG размещается в `sys._MEIPASS/tools/gpg/bin/gpg` (на Unix); переменная `ONIONDESK_GPG` принимается только для пути внутри этой
папки. В Unix внешний GnuPG в помощнике запускается с правами исходного
пользователя. Доступ к собственной программе и папке кэша предполагает
доверенную исходную ОС; аппаратную совместимость доказывает реальная загрузка.

При отсутствии офлайн-папки образ выбирается по текущему официальному latest.json. Официальный HTTPS
redirector download.tails.net выбирает HTTPS-зеркало, допускается только
указанный им файл образа; дальнейшие перенаправления зеркала запрещены.
DNS проверяется на публичные адреса, соединение закрепляется за проверенным
IP с исходным SNI и проверкой TLS hostname. Все загрузки выполняются только через проверенный локальный Tor на 9150/9050.
DNS назначения также разрешается через Tor (SOCKS RESOLVE 0xF0); системный
DNS не используется. При отсутствии Tor операция останавливается без прямого
fallback. Проверяются публичные адреса и сертификат исходного имени сайта.

Первичные источники, проверены 15 октября 2026:

- https://tails.net/install/download/ — текущий USB-образ 7.15 и подпись.
- https://tails.net/install/v2/Tails/amd64/stable/latest.json — версия, размер, URL, SHA-256.
- https://tails.net/torrents/files/tails-amd64-7.15.img.sig — текущая подпись.
- https://tails.net/tails-signing.key — обновления закреплённого ключа.
- https://tails.net/doc/about/openpgp_keys/index.en.html — primary fingerprint `A490D0F4D311A4153E2BB7CADBB802B258ACD84F`.
- https://tails.net/contribute/design/download_verification/ — модель проверки загрузок.
- https://tails.net/doc/about/requirements/ — x86-64, Apple Silicon не поддерживается.
- https://github.com/gpg/gnupg/blob/master/doc/DETAILS — формат статусов GOODSIG/VALIDSIG.
- https://learn.microsoft.com/en-us/powershell/module/storage/get-disk — перечисление USB-дисков.
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew — raw physical disks.
- https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_lock_volume — блокировка тома.
- https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/disk.h — macOS device ioctls.
- Локальные справочники macOS `diskutil(8)`/`ioreg(8)` — plist, external physical и unmountDisk.
- https://man7.org/linux/man-pages/man8/lsblk.8.html — явные JSON-колонки и дерево устройств.
- https://urllib3.readthedocs.io/en/stable/advanced-usage.html — потоковое HTTPS и SNI при закреплённом IP.

Проверки USB engine работают с моками и временными обычными файлами.
Официальный IMG Tails 7.15 с подписью подготовлен в офлайн-комплекте;
загрузка Tails испытана в лабораторной VM. Это не подтверждает запись
реального USB, Windows UAC/raw I/O, размонтирование физического носителя
или загрузку на конкретном устройстве. Актуальные результаты и ограничения —
в [CHECKS.md](../CHECKS.md).

На Windows GPG из установленного OnionDesk либо GnuPG/Gpg4win выбирается только из KnownFolders системным API и после проверки
владельца, ACL и отсутствия reparse points у файла и предков. PATH, ProgramFiles
из окружения и bundled GPG не используются. На Unix в привилегированном
помощнике проверка подписи запускается с user/group исходного пользователя.
Проверки используют безопасные имитации; реальные Windows ACL/UAC,
администраторские окна и запись физической флешки не проверялись.
