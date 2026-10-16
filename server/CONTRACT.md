# Серверная часть OnionDesk

Актуально: 16 октября 2026.

Подготовлена для отдельного свежего физического сервера Debian 13 amd64: доступный `/dev/kvm`, 4 CPU, 8 GiB RAM (Linux обычно сообщает немного меньше), 50 GiB свободного места. Установщик не предназначен для Debian 12, macOS и существующего production-сервера. Лабораторные VM испытаны в QEMU TCG на Mac ARM64; это не испытание физического Debian/KVM.

## Установка и согласие

Из корня полного комплекта:

```sh
sudo bash server/install.sh --check
sudo bash server/install.sh --yes-licenses --tor-mode public-obfs4
```

`--check` только читает свойства host. Вторую команду выполняйте после прочтения [лицензии Whonix](https://www.whonix.org/wiki/License_Agreement) и [условий использования](https://www.whonix.org/wiki/Terms_of_Service). Без `--yes-licenses` установщик просит явное подтверждение до изменений. Локальный launcher по умолчанию передаёт `public-obfs4`: один комплектный публичный obfs4-мост настраивается отдельно для host Tor и Gateway, без прямого fallback. Shell-установщик требует явный выбор режима или спрашивает его в терминале. Совместимые режимы: `wizard` оставляет выбор Tor/bridges Gateway в GUI; `direct` явно разрешает Gateway подключаться к публичному Tor (`DisableNetwork 0`). В этих двух режимах host Tor использует публичную сеть Tor. Доступность любого маршрута зависит от сети; публичный мост не гарантирует обход блокировок или анонимность.

Полный официальный архив всегда проходит SHA-512 и OpenPGP-проверку, в том числе с `--archive /path/image.xz --signature /path/image.xz.asc`. Без `--signature` требуется соседний файл `image.xz.asc`. Закреплён выпуск **18.2.1.9**, fingerprint **916B8D99C38EAF5E8ADC7A2A8D66066A2EEACCDA**. При ошибке проверки импорт не выполняется.

Повторная установка поверх `/opt/oniondesk`, `/var/lib/oniondesk`, `/etc/oniondesk`, собственного каталога дисков или существующих одноимённых VM отвергается. Не удаляйте эти каталоги для обхода проверки: при частичной ошибке сначала выясните её причину. Установщик не удаляет диски, snapshots или чужие домены.

## Автоматическая первая настройка гостя

`first_boot.py stage` работает с выключенными приватными копиями проверенных vendor-дисков. После явного принятия условий он сверяет реализацию штатного `setup-dist` marker и создаёт `/var/cache/setup-dist/status-files/setup-dist.done` в обоих гостях. Для Workstation дополнительно проверяются обычный USER entry по умолчанию, единственный точный title `PERSISTENT Mode | SYSMAINT Session | system maintenance tasks`, kernel args и штатная поддержка однократного `next_entry`. Неизвестная структура или уже занятый `next_entry` останавливает установку.

В vendor `grubenv` записывается только одноразовый `next_entry` на SYSMAINT. Устанавливается `oniondesk-first-boot.service`: oneshot после штатных SYSMAINT target/service, только при `boot-role=sysmaint` и отсутствии `/var/lib/oniondesk/setup.complete`. Скрипт `/usr/local/sbin/oniondesk-workstation-setup` проверяет существующий `user-sysmaint-split`, ждёт подтверждения Tor из Workstation через API Tor Project, затем устанавливает `telegram-desktop` из `trixie-backports`, `qemu-guest-agent`, `mat2` и `zenity` из Debian. После проверки компонентов он создаёт root:0600 `setup.complete` и штатно выключает Workstation. Постоянный GRUB default и разделение ролей сохраняются.

В режимах `public-obfs4` и `direct` установщик сам вызывает `control.sh first-setup`. В режиме `wizard` сначала подключите Gateway через Anon Connection Wizard, затем выполните `sudo /opt/oniondesk/server/control.sh first-setup`. Наблюдатель `first_boot.py finish` ждёт штатного выключения, проверяет guest marker на выключенном диске, запускает обычный USER и требует полный текущий аудит host и отчёт QGA. Состояние root:0600 `first-boot.pending` переходит в `first-boot.complete` только после успеха. После прерывания наблюдение можно повторить; уже загрузившийся после перезагрузки USER принимается только по полному текущему отчёту. Таймаут или ошибка сохраняет VM и не объявляет готовность.

Ручной выбор SYSMAINT и запуск `sudo /usr/local/sbin/oniondesk-workstation-setup` через **System Maintenance Panel → Open Terminal** остаются средством диагностики неуспешной подготовки после остановки автоматического задания и выяснения причины. Не запускайте ручной setup одновременно с автоматическим. Проверяйте Gateway, `control.sh diagnostics` и журнал `oniondesk-first-boot.service` в госте; не запускайте второй установщик поверх частичного состояния.

Вход в Telegram и подтверждение номера/кода выполняет пользователь. Данные Telegram сохраняются на диске Workstation между выключениями и перезагрузками. Установленный Telegram не подтверждает регистрацию, оплату номера или доставку SMS.

Ни host installation, ни наличие работающей VM сами по себе не означают готовность Telegram. `control.sh status` сначала проверяет текущую изоляцию host, затем объявляет готовность только после успешной установки, текущей проверки Tor и подтверждения обычной USER загрузки внутри Workstation через guest agent. USER требует установленного split, отсутствия maintenance boot role, успешного `sysmaint-boot.service`, неактивного maintenance target и активного графического target. При недоступности agent или любой проверки готовность не подтверждается.

## Управление и закрытие SSH

`control.sh` без аргументов открывает меню. Доступны `status`, `start`, `stop`, `update`, `credentials`, `first-setup`, `diagnostics`, `auto-cleaner`. Выключение использует только штатный `virsh shutdown`; если VM не отвечает, её оставляют работающей и сообщают ошибку, без принудительного удаления/`destroy`.

## Автоматическая очистка копий

SYSMAINT-установка добавляет `guest-auto-cleaner.py` и глобально включает пользовательский `oniondesk-auto-cleaner.service`. Служба запускается только для `user` в обычном USER-сеансе. QGA-readiness теперь требует шесть условий, включая текущее состояние этой службы. `control.sh auto-cleaner` сначала проверяет изоляцию host и затем возвращает ограниченный отчёт без имён и путей пользовательских файлов.

Наблюдение ограничено `~/Downloads` и одним уровнем `~/Downloads/Telegram Desktop`. После стабилизации файла создаётся проверенная `mat2` копия в `~/OnionDesk-Clean`; исходник не удаляется и ничего автоматически не отправляется. Символические ссылки, hardlink, чужие/чрезмерные/неподдерживаемые файлы не обрабатываются. Временный вход парсера хранится вне выходной папки, в приватном `~/.oniondesk-processing`. Соответствие исходников и копий находится только в `~/.local/state/oniondesk/auto-clean/Соответствия файлов.txt` с правами 0600. Отчёт содержит счётчики и ограниченные признаки состояния. При исчерпании лимитов, сбое записи отчёта или отсутствии USER-сеанса готовность не объявляется. Очистка метаданных не удаляет сведения из видимого содержимого и не гарантирует отсутствие всех следов.

`credentials` показывает `login`, `password`, `totp_secret`, `otpauth_uri` только в терминале администратора и проверяет root:0600 у `/etc/oniondesk/credentials.json`. Секреты не печатаются при установке. Сохраняйте их в менеджере паролей.

SSH сохраняется после установки. Прежде чем его отключать, реально проверьте onion-вход с паролем и TOTP, оба рабочих стола и доступ к консоли провайдера. Затем:

```sh
sudo /opt/oniondesk/server/seal.sh --onion-confirmed --provider-console-confirmed --confirm-disable-ssh
```

Этот отдельный шаг проверяет текущую готовность Workstation и защищённые websocket маршруты через onion, затем отключает только SSH services/sockets. Он не удаляет и не заменяет firewall. Восстановление из консоли провайдера: `systemctl enable --now ssh.service`.

## Контракт компонентов

| Компонент | Значение |
|---|---|
| Установленные файлы | `/opt/oniondesk/server`, `/opt/oniondesk/frontend` |
| Собственное состояние | `/var/lib/oniondesk` root:0711 для прохода auth service; staging root:0700, `auth` oniondesk-auth:0700; `/etc/oniondesk` root:0700 |
| Диски | `/var/lib/libvirt/images/oniondesk/gateway.qcow2`, `workstation.qcow2`; только non-root libvirt-qemu |
| Libvirt | `qemu:///system`, VM `oniondesk-gateway`, `oniondesk-workstation` |
| Внешняя сеть GW | Официальный `interface type=user`, `backend=passt` |
| Внутренняя сеть | Официальные UDP 127.0.0.1:5577 ↔ 127.0.0.1:6688; у WS нет внешнего интерфейса |
| VNC | GW 127.0.0.1:5901, WS 127.0.0.1:5902; server-side QEMU display |
| Websockify | GW 127.0.0.1:16081, WS 127.0.0.1:16082 |
| noVNC | Host `/usr/share/novnc`; в гостях VNC/noVNC не устанавливаются |
| Nginx/auth | 127.0.0.1:18080 / 127.0.0.1:18081; frontend hook получает один v3 `.onion` hostname |
| Tor ingress | Onion TCP 80 → 127.0.0.1:18080; `/var/lib/tor/oniondesk/hostname` |
| Проверка host Tor | Приватные UNIX socket `/run/tor/control` и cookie `/run/tor/control.authcookie`, оба Tor:0600; TCP ControlPort не открывается |
| Первое обслуживание WS | Vendor `grubenv next_entry` → `oniondesk-first-boot.service` → штатное выключение → USER/QGA |
| GUI URL | `/novnc/vnc.html?autoconnect=1&resize=scale&path=ws/workstation` либо `ws/gateway` |
| Auth gate smoke check | `/ws/gateway`, `/ws/workstation` без cookie: HTTP 401 или redirect к login; не WebSocket 101 |

Installer маскирует `nginx.service`, `tor.service` и `tor@default.service` до первого `apt-get update`: default Debian site не открывает публичный HTTP, а новый Tor не стартует до настройки выбранного маршрута. `host_tor.py` проверяет формат bridge-конфига, настраивает onion ingress и приватный Control socket с cookie authentication. После перезапуска Tor проверяются PID/UID peer через `SO_PEERCRED`, тип/владелец/0600 socket и cookie, текущие `DisableNetwork`/`UseBridges`, bootstrap 100% и установленная цепочка. Только после этого создаётся frontend через `frontend/install-auth.sh HOSTNAME.onion`, проверяется Nginx и снимается его mask. Frontend hook не должен сам стартовать Nginx во время mask. При ошибке службы могут остаться masked; SSH сохраняется.

Серверные службы запускают VM при загрузке host. Изменения штатного XML ограничены собственным именем VM, `volume → file`, удалением CPU pinning, loopback VNC вместо SPICE и добавлением канала QGA в WS. Runtime uid QEMU проверяется после запуска. Перед записью guest files проверяются реальные role markers, accounts, GRUB/sysmaint target, boot script и vendor setup marker; при несовпадении контрактов установка останавливается без угадывания GRUB IDs.

`sudo python3 -B /opt/oniondesk/server/runtime-audit.py --json` — read-only аудит текущего host. Ответ: `{"ok": true|false, "checks": [{"id": "…", "ok": true|false, "detail": "…"}]}`; exit 0 означает прохождение, 1 — отказ проверки, 2 — недоступность самого аудита. Проверяются inactive/live XML обеих VM, точная GW passt/WS UDP топология, UID QEMU, шесть реальных TCP listeners на IPv4 `127.0.0.1` и два UDP endpoint с владельцами PID/UID, текущие systemd services/cgroup и права секретов. Секреты, XML и onion hostname не выводятся. Аудит не исправляет настройки и не меняет чужие службы.

Перед каждым запуском VM проверяются определения и уже работающие VM, после запуска — live XML/VNC/UDP. Полный аудит проходит после запуска прокси, перед готовностью и перед созданием root:0600 `/var/lib/oniondesk/host-installed`. Этот marker подтверждает только установку host; Telegram/Tor/USER подтверждаются отдельно завершением first-setup и текущим `control.sh status`. Это проверки в моменты действий/статуса, а не непрерывный мониторинг и не замена изоляции Whonix.

## Выполненные проверки и ограничения

Автоматические проверки покрывают preflight, официальный XML и отказ при лишнем NIC/QEMU namespace/DTD/неверном пути, OpenPGP/SHA-512, SYSMAINT guards, system libvirt, readiness Tor/USER, runtime listeners/владельцев/службы, fail-closed подготовку GRUB/setup marker и приватный host Tor Control. Актуальные результаты и ограничения приведены в [CHECKS.md](../CHECKS.md); этот контракт описывает требуемое поведение, а не общий PASS.

Официальный архив Whonix 18.2.1.9 скачан и криптографически проверен. Предыдущая лабораторная проверка с ручной подготовкой подтвердила Tor, Telegram, обычный USER и QGA. Отдельный чистый автоматический цикл в TCG завершён: однократный SYSMAINT, установка, штатное выключение, обычный USER и текущий положительный QGA/HTTPS Tor. Ручных запусков установщика или переключения роли внутри гостя не было; ввод для чтения журнала отмечен в исходных лабораторных материалах. В этот экспорт включены только точечно просмотренные PNG встроенной помощи с [точным списком хешей](../docs/GUIDE-IMAGE-MANIFEST.json); необработанные provenance-файлы в Git не переносятся. Прежние результаты не подменяют новый прогон экспортированного дерева. QEMU TCG с лабораторной сетью не подтверждает физический Debian/KVM, production passt, host reboot или полную серверную установку. Они требуют отдельного испытания. Комплект не обещает полную анонимность или безопасное стирание данных.

Первичные источники: [официальная KVM инструкция](https://www.whonix.org/wiki/KVM), [ключ Whonix](https://www.whonix.org/wiki/Main/Project_Signing_Key), [Sysmaint](https://www.whonix.org/wiki/Sysmaint), [Telegram в Whonix](https://www.whonix.org/wiki/Telegram), [libvirt XML](https://libvirt.org/formatdomain.html), [libguestfs](https://libguestfs.org/guestfish.1.html), [Debian QGA](https://packages.debian.org/trixie/qemu-guest-agent).
