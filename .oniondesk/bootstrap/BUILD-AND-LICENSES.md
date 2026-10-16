# Linux native bootstrap

Небольшой GTK 3 launcher для x64 и ARM64 с русским окном, progress, «Отмена»,
«Повторить» и понятной ошибкой. Палитра navy/gold, approved hacker icon. Конечный
пользователь извлекает архив и запускает корневой ELF; Python, shell launcher,
менеджер пакетов и установленный GTK для этого не требуются. Системные glibc
**2.36+**, kernel, X11/Wayland desktop и штатная политика запуска ELF остаются
платформенными требованиями. Открытие браузера исходным клиентом сохраняется.

Это исходники оболочки и build recipe. Checked-in `generated_release.h` намеренно
`OD_CONFIGURED=0`: без root integration программа сообщает об отсутствии готовой
сборки и не запускает worker. Наличие исходников и host fixture PASS не означает
готовность пользовательского Linux-дистрибутива.

## Доставка

```text
OnionDesk-Linux-x64                  # или OnionDesk-Linux-ARM64; native GTK ELF
.oniondesk-worker                    # root sibling; reviewed static Go worker
.oniondesk/
  transport/blobs/<sha256>           # frozen flat pool; root supplies it later
  bootstrap/
    lib/*.so*                        # full GTK/GLib/etc closure for this arch
    hacker-mark.png                   # exact approved PNG, SHA below
    fonts/{DejaVuSans,DejaVuSans-Bold}.ttf
    fonts.conf
    modules/                         # empty, external modules disabled
    licenses/                        # per Debian package copyright + licenses
    runtime-lock.json                # exact final hashes, versions/provenance
```

Worker обязан находиться **рядом с корневым launcher**, поскольку существующий
worker получает pool как `executable parent/.oniondesk/transport/blobs`. Оболочка
не изменяет worker/engine/payload. Original shim восстанавливается в private
`<user cache>/OnionDesk-Offline/<pinned manifest>/ready-<32hex>/payload` и запускается
по точному абсолютному пути, без аргументов, с cwd = payload. Внешние JSON,
CLI/URL/environment command overrides, shell, browser-open в bootstrap отсутствуют.

Компилятор закрепляет distribution, manifest SHA256, original entrypoint,
entrypoint SHA256/размер/ELF machine и SHA256 точного Go worker. Build-only generator
проверяет manifest общим reviewed `engine.ParseManifest` с **явно переданным ранее
утверждённым digest**. Вычисление hash произвольного внешнего manifest само по себе
не устанавливает доверие. Подлинность пакета обеспечивается утверждённым каналом
доставки; отдельные новые signing keys этим wrapper не вводятся.

## IPC, запуск и отмена

Worker получает ноль аргументов и dedicated stdin/stdout pipes. Максимальный event
вместе с LF — 16 KiB; stdout постоянно дренируется nonblocking, не более 64 KiB за
main-loop dispatch и 64 MiB на попытку. Parser принимает только известные поля,
один JSON object на строку, известные event/phase, UTF-8, uint counters <= 16 GiB;
duplicate/unknown keys, overflow, partial final line, лишние строки после terminal
event отклоняются. Raw worker message и stderr не показываются пользователю.

Корректный terminal `error` — допустимый исход worker, а не нарушение протокола.
После чистого EOF оболочка показывает локализованную ошибку по принятому `code`
(например, `integrity`), независимо от порядка stdout EOF и child exit. Флаг
`session.failed` обозначает только некорректный протокол/поток; отсутствие READY
самостоятельно запрещает launch после `error`, в том числе при ошибочном exit 0.

Launch gate требует одновременно validated READY, полный stdout EOF, exit code 0,
отсутствие принятой отмены/закрытия, exact pinned cache layout и manifest. Затем
повторно открываются без directory symlinks private owner-only cache directories,
проверяются receipt, regular independent 0755 original ELF, его architecture,
размер и SHA256. Полная payload verification остаётся обязанностью pinned worker.
Угрозы от злонамеренного процесса того же UID или administrator за пределами
этой границы: filesystem проверки не выдают за атомарную защиту от такого процесса.

При отмене/закрытии main-context state сразу запрещает запуск. Единственная строка
в stdin — `{"type":"cancel"}\n`, затем pipe закрывается; EOF также означает cancel.
SIGPIPE игнорируется, запись неблокирующая. По истечении 2 s незавершённый child
получает SIGTERM, после 3 s — SIGKILL; сохранённый PID не используется после reap.
После terminal line допускается 10 s до exit; после exit — 3 s до EOF и ограниченная
остановка reader. Retry доступен только после exit+EOF и создаёт новые pipes/state.
Финализированный cache оболочка никогда автоматически не удаляет.

Непрерываемая короткая проверка original ELF и сам OS spawn выполняются в одном
main-context callback. Перед spawn состояние становится launching, кнопка
отключается; ранее **принятая** отмена всегда блокирует этот переход. Уже переданный
OS spawn request неотзываем. Протокольные и файловые фикстуры не запускают Core.

## Сборка для root

Pinned multiarch base подтверждён существующим v5 build recipe:
`python:3.12.13-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2`.
`Dockerfile` устанавливает **build-time** GTK SDK и инструменты в отдельный builder;
ничего из этого не устанавливается на пользовательский Linux. Debian package
versions могут получить security updates: готовая closure фиксируется exact
SHA256 и Debian source/binary versions в `runtime-lock.json`, который root сохраняет
как immutable build proof. Побитовая воспроизводимость по одному base digest не
заявляется. Не использовать неизвестный mutable toolchain tag как provenance.

1. Root собирает **точный reviewed engine/worker** с embedded frozen manifest для
   каждой архитектуры; worker static, Go 1.26.2, CGO=0. Worker не запускать на этом
   шаге. Его full ELF bytes будут закреплены в header.
2. На host с Go 1.26.2 получить новый header, передав независимо утверждённый SHA
   manifest. Output должен ещё не существовать:

```sh
cd wrappers/linux/tools
go test ./...
go run . -manifest /absolute/reviewed/manifest-linux-x64.json \
  -expected-digest APPROVED_MANIFEST_SHA256 \
  -worker /absolute/linux-x64-out/.oniondesk-worker \
  -output /absolute/linux-x64-out/release.h
```

Для ARM64 — exact ARM64 manifest/worker и другой output directory. Генератор
проверяет исходное имя `OnionDesk-Linux-ARM64` и ELF machine 183; x64 —
`OnionDesk-Linux-x64` и 62. Header дополнительно запрещает компиляцию под другую
архитектуру. Нельзя собирать обе архитектуры с одним перезаписываемым header.

3. Root строит отдельный builder для `linux/amd64` и `linux/arm64` из этого Dockerfile.
   Например, из `wrappers/linux`, с `$LINUX_OUT` = absolute fresh architecture output:

```sh
docker build --platform linux/amd64 -t oniondesk-native-gtk-bookworm:amd64 .
docker run --platform linux/amd64 --rm --network none \
  -v "$PWD":/src:ro -v "$LINUX_OUT":/out \
  oniondesk-native-gtk-bookworm:amd64 /bin/sh -ec '
    cp -R /src /tmp/native-ui
    cd /tmp/native-ui
    make clean
    make test
    make package-test
    make RELEASE_HEADER=/out/release.h
    make build/png-probe
    ./build/png-probe assets/hacker-mark.png
    python3 tools/package-runtime.py --binary build/OnionDesk \
      --worker /out/.oniondesk-worker --header /out/release.h --output /out/candidate
  '
```

Повторить с platform `linux/arm64`, tag `:arm64`, отдельным `$LINUX_OUT`. Эти команды
не выполнялись Linux subagent. `make test` — только малые synthetic fixtures;
`png-probe` — non-GUI decode approved PNG с loader modules отключёнными, без worker.
При отсутствии builtin PNG probe должен завершиться ошибкой: не полагаться на
случайный host pixbuf loader. Build helper Python остаётся только в builder;
в candidate нет Python/shell executable bootstrap или scripts.

Native launcher имеет DT_RPATH `$ORIGIN/.oniondesk/bootstrap/lib`; каждая copied
shared library — `$ORIGIN`. Полная DT_NEEDED closure копируется без symlinks,
под точным именем DT_NEEDED, даже если basename resolved файла содержит другую
версию. Одинаковое loader name с разными resolved paths отклоняется; разные loader
names получают независимые regular files. Closure ограничена 256 libraries,
512 MiB суммарно, 128 MiB на library и 8192 pending dependency records.
glibc/loader остаются системными с baseline 2.36. GTK IM/GIO external modules и
pixbuf module cache отключены; рендеринг использует private fontconfig+DejaVu.
Оригинальный Core получает сохранённое environment, без bootstrap GTK overrides.

Перед `gtk_init_check()` bootstrap устанавливает `GDK_GL=disable`, **после**
`g_get_environ()`. Простое GTK3-окно не использует GL context; это предотвращает
автоматическую GLX/Mesa/LLVM-загрузку через libepoxy вне private closure.
Worker и original Core получают полный исходный snapshot: отсутствующий `GDK_GL`
остаётся отсутствующим, пользовательское непустое или пустое значение сохраняется.
`GDK_BACKEND` не задаётся; проверка Wayland остаётся отдельным платформенным gate.
Исходники GTK 3.24.38 подтверждают разбор `disable` как `GDK_GL_DISABLE` до
GLX probing. Root A/B smoke прежнего ARM64 candidate со внешним `GDK_GL=disable`
подтвердил читаемое X11-окно, 64 private shared libraries и только 5 системных
glibc libraries. Этот smoke обосновывает правку, но **не заменяет пересборку и
проверку нового ELF** на обеих архитектурах без внешней установки переменной.

4. До выпуска root проверяет на минимальном Debian 12 runtime **без установленного
   GTK и без сети**: library resolution только из private closure кроме glibc,
   startup window/icon/font, cancel, window close, missing/corrupt blob, retry,
   repeat cached run, exact original shim launch и обе архитектуры. Сборка и lock
   ещё не доказывают такой smoke. Затем добавить approved flat pool и руководство,
   проверить executable bits после archive/extract. Не запускать original Core
   в обычном builder без согласованной QA-среды.

## Проверки и provenance

Host `make test` и `make sanitize` проверяют bounded JSON, UTF-8/duplicate/overflow,
paths, READY/EOF/exit ordering, cancel-before-ready, terminal duplication, partial
line, wrong ELF arch/size/modes, symlink/hardlink/FIFO, private cache и receipt.
Regression fixture компилирует настоящий stdout callback из `src/stdout_ready.inc`
с mock read/close без GTK. Последовательность 1 byte + 4096-byte chunks и другие
нерегулярные порции с EINTR подтверждают максимум 65536 bytes за dispatch: последний
read ограничен оставшимся budget, callback возвращает управление перед следующей
порцией, сохраняя возможность принять отмену и обработать таймеры.
`tests/environment_test.c` выполняет точную production-последовательность из
`src/bootstrap_environment.inc` с libc-адаптерами GLib без GTK. Три исходных
состояния `GDK_GL` (отсутствует, задано пользователем, пусто) проверяют bootstrap
`disable`, неизменность полного snapshot и шесть synthetic `execve` child targets
с этим snapshot, по два на состояние. Реальные worker/Core не запускаются.
Прежняя последовательность без override и мутация с override до snapshot должны
завершать fixture контролируемой ошибкой 77.
`tests/worker_events_test.c` компилирует настоящие production callbacks из
`src/worker_events.inc` и reader из `src/stdout_ready.inc` с теми же parser/session,
заменяя только GTK/GLib UI и не относящиеся к проверке OS-вызовы. 29 cases включают
9 progress + `error integrity` из прямого запуска точного ARM64 worker на
повреждённом blob, три порядка child exit (до данных, после terminal до EOF,
после EOF), chunks 1/7/4096 bytes и запрет launch после error даже с exit 0.
Неполная строка, лишнее событие после terminal, malformed record и отсутствие
terminal по-прежнему дают protocol error. Synthetic READY проверяет gate
READY+EOF+exit 0+no cancel с mock launch target; настоящие filesystem/ELF launch
проверки и Core этим тестом не выполняются. Исходный NDJSON сохранён без изменений
в `tests/fixtures/worker-corrupt-integrity.ndjson` (926 bytes, SHA256
`69e4f6bc86c540c0a620e30a277bd5d770915efbd8596695ff0705e14db01425`);
provenance — root QA `integration/linux-runtime-qa/arm64-r2-worker-direct-corrupt.ndjson`.
Прежний parser с `failed=true` при принятии корректного ERROR должен завершать
новую callback fixture контролируемой ошибкой 77.
`tools/go test ./...` проверяет генерацию обеих архитектур и отрицательные cases.
`make package-test` проверяет exact loader name при несовпадении с basename,
коллизии и независимость aliases, transitive dependencies, system exclusion и
caps на маленьких synthetic files; ldd, GTK и реальные worker не запускаются.
На host macOS отсутствуют GTK SDK/pkg-config: native GTK build, Linux runtime
closure, actual worker/Core и визуальное окно здесь **NOT_VERIFIED**.

Approved icon copied read-only from
`work/release-refresh-20261016/v5-build/candidates/OnionDesk.app/Contents/Resources/assets/hacker-mark.png`:
1508723 bytes, SHA256 `37f3423b5ff9773e7327de160f0ab86605df0fd025a71f22543318577f6a0b4c`.
Launcher закрепляет exact PNG hash и не считает отсутствие иконки готовым пакетом.

Packager копирует Debian copyright notices для каждой bundled library и DejaVu,
а также common license texts. Lock содержит exact source package/version и ссылки
на исходники Debian. **До фактической раздачи root должен закрыть применимые
source-redistribution/LGPL obligations**: сохранить corresponding source packages
и notices для точных версий, разрешённый механизм предоставления исходников и
возможность замены динамических LGPL libraries. `source_redistribution_review`
намеренно остаётся REQUIRED_BEFORE_RELEASE; наличие URL не выдаётся за исполнение
всех обязательств. Source packages нужны только build/release archive, не runtime.

## Лицензия собственного bootstrap и notices

Собственный исходный код этого Linux bootstrap распространяется по **GNU General
Public License, version 3** (`GPL-3.0-only`), согласно решению владельца проекта.
Полный неизменённый текст — в `LICENSE`. Вы можете распространять и изменять этот
код на условиях GPLv3; программа предоставляется без каких-либо гарантий, включая
гарантии товарной пригодности и пригодности для конкретной цели. Подробнее — в
полном тексте лицензии. Этот выбор относится к собственному коду оболочки;
upstream-компоненты и их copyright/license notices сохраняют свои условия.

Для bundled `libdbus-1-3` используется разрешённая его notice альтернатива
`GPL-2+` с выбором GPLv3; отдельный выбор AFL-2.1 для этой поставки не требуется.
Полный Debian notice, включая условия Expat/Tcl-BSDish и иных включённых частей,
сохраняется. Для используемой FreeType 2.12.1 сохраняется FTL notice и credit:

> Portions of this software are copyright © 1996-2022 The FreeType Project
> (www.freetype.org). All rights reserved.

Packager уже копирует Debian notices, common license texts (включая GPL-3) и этот
README как `BUILD-AND-LICENSES.md`; дополнительных лицензий или source archives
в runtime он не загружает. Root добавляет собственный GPL-3 `LICENSE` и полный
corresponding-source bundle точных версий к выпуску отдельно. Наличие этого notice
не закрывает оставшийся root gate `source_redistribution_review` автоматически.

Первичные API references:
[GLib child watch](https://docs.gtk.org/glib/func.child_watch_add.html),
[private pipe spawn](https://docs.gtk.org/glib/func.spawn_async_with_pipes.html),
[spawn flags](https://docs.gtk.org/glib/flags.SpawnFlags.html),
[Unix FD source](https://docs.gtk.org/glib-unix/func.fd_add.html),
[GTK3 progress](https://docs.gtk.org/gtk3/method.ProgressBar.set_fraction.html),
[GTK 3.24.38 GDK GL flags and pre-parse](https://github.com/GNOME/gtk/blob/3.24.38/gdk/gdk.c#L129-L138),
[GTK 3.24.38 X11 GL initialization](https://github.com/GNOME/gtk/blob/3.24.38/gdk/x11/gdkglcontext-x11.c#L784-L805),
[GdkPixbuf 2.42.10 builtin PNG/loader implementation](https://raw.githubusercontent.com/GNOME/gdk-pixbuf/2.42.10/gdk-pixbuf/gdk-pixbuf-io.c).
