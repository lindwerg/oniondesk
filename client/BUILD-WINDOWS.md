# Сборка приложения Windows x64 разработчиком

Этот рецепт предназначен для сборки из checkout. Наличие исходников и
успешная упаковка не подтверждают готовность нового выпуска. Поддерживаемая
цель — Windows 10/11 x64; запуск, UAC и запись USB нужно проверять на настоящей
Windows. Wine пригоден для упаковки и ограниченных smoke-проверок.

Приложение собирается в `Windows/OnionDesk/OnionDesk.exe` в режиме `onedir`
с Python, Paramiko, Requests и SOCKS внутри. Папка `_internal` рядом с `.exe`
является частью приложения. Интерфейс открывается в обычном браузере,
WebView2 не нужен. Listener слушает только `127.0.0.1`, случайный код запуска
передаётся браузеру во фрагменте URL.

Нужен установленный Windows CPython x64; исходный рецепт использовал CPython
3.13.16 и PyInstaller 6.22.3. Сборщик отклоняет Python другой ОС и 32-битный
интерпретатор. Для проверки версии выполните `python --version` до создания
окружения. Из корня checkout в PowerShell:

```powershell
python -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r client\requirements.txt PyInstaller==6.22.3
$buildRoot = "$(Get-Location)-build"
& .\.venv\Scripts\python.exe client\build-windows.py --work-dir "$buildRoot\windows" --output-dir Windows
```

Промежуточная папка должна быть новой пустой папкой либо предыдущей папкой
этого сборщика с его маркером. Команда, логи и отчёт записываются в
`<checkout>-build/windows`. Полный граф Windows Python-зависимостей здесь не
зафиксирован. В checkout нужны `assets`, `client/ui`, `server`, `frontend` и
`screenshots/real`. В приложение включаются только эти ресурсы и код клиента;
`client/data`, ключи и кэш не читаются и не упаковываются.

Установщик отдельно размещает приложение и GnuPG в защищённой папке
`Program Files\OnionDesk`. Он запрашивает системное разрешение Windows и не
запускает пользовательский мастер с правами администратора. Для записи USB
приложение вызывает отдельное повышение прав. Установщик не перезаписывает
существующую установку: сначала её нужно удалить штатным способом. DLL
привилегированного helper загружаются из защищённой установки.

Для установщика подготовьте проверенную Windows-дистрибуцию GnuPG с
`bin/gpg.exe`, её DLL, лицензиями и сведениями об источнике, лицензии остальных
компонентов и полный публичный `OnionDesk-Data` по каталогам клиента.
Исходный рецепт использовал GnuPG Windows 2.5.24 с проверенной OpenPGP-подписью
производителя. Эти файлы не скачиваются приведёнными командами.

В отдельной Linux-среде сборки нужны Python 3.11+, NSIS 3.11+ и
`x86_64-w64-mingw32-gcc`. После подготовки Windows-приложения и указанных папок
из корня checkout:

```sh
build_root="$(pwd)-build"
APP_DIR="$PWD/Windows/OnionDesk" \
GPG_DIR="$build_root/windows-gpg" \
LICENSE_DIR="$build_root/windows-licenses" \
DATA_DIR="$PWD/OnionDesk-Data" \
SETUP_WORK="$build_root/windows-setup" \
OUTPUT_EXE="$PWD/Windows/OnionDesk-Setup.exe" \
  sh client/build-windows-setup.sh
```

Обёртка проверяет публичные файлы, создаёт список для NSIS и компилирует
проверяющий модуль SHA-256. Прямого вызова `makensis` только с папками
приложения и GnuPG недостаточно: обязательны также сгенерированные
`DATA_INCLUDE` и `DATA_VERIFIER`. Полученный установщик при запуске ожидает
рядом полный проверенный набор `.oniondesk/OnionDesk-Data`. Этот рецепт не
создаёт доставляемый архив с этим набором; его подготовка и проверка полного
дистрибутива — отдельный этап.

Коммерческая подпись Authenticode этим рецептом не создаётся. Перед выпуском
нужно отдельно проверить интерфейс, Host/код запуска, штатный выход,
проверку подписей GnuPG, ранний USB-helper, UAC и запись USB на Windows.
Проверки под Wine не заменяют эти проверки.

Справочные материалы: [PyInstaller](https://pyinstaller.org/en/stable/usage.html#supporting-multiple-operating-systems),
[встраиваемый Python](https://docs.python.org/3.13/using/windows.html#the-embeddable-package),
[разрешения NSIS](https://nsis.sourceforge.io/Reference/RequestExecutionLevel).
