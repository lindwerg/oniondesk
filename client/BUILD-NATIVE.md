# Сборка приложения для Mac разработчиком

Рецепт рассчитан на Mac с Apple Silicon и macOS 15 или новее. Сборщик
отклоняет другие ОС и архитектуры. Это инструкция повторной сборки из checkout;
готовность нового выпуска определяется отдельными проверками результата.
Для Windows и Linux см. `BUILD-WINDOWS.md` и `BUILD-LINUX.md`.

Нужны Python 3.11+ ARM64, инструменты macOS `file`, `otool`,
`install_name_tool`, `codesign` и установленный Homebrew GnuPG вместе с
`gpgconf`. Сборщик принимает GnuPG только из `/opt/homebrew/Cellar` и собирает
его зависимости из того же Homebrew. Исходный рецепт использовал GnuPG
2.5.19, PyInstaller 6.22.3 и pywebview 6.2.1. Полный граф macOS Python- и
Homebrew-зависимостей здесь не зафиксирован; другой GnuPG может изменить
минимальную версию macOS и состав библиотек.

В checkout должны находиться полные `assets`, `client/ui`, `server`,
`frontend`, `screenshots/real` и публичный набор `OnionDesk-Data`,
соответствующий каталогам клиента. Большие публичные файлы подготавливаются
отдельно и проверяются сборщиком по размеру и SHA-256. Сборщик не скачивает
недостающие файлы. `client/data`, пользовательские ключи и кэш в приложение
не включаются.

Из корня checkout с уже установленными Python ARM64 и Homebrew GnuPG:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r client/requirements.txt \
  PyInstaller==6.22.3 pywebview==6.2.1
build_root="$(pwd)-build"
.venv/bin/python client/build-native.py \
  --work-dir "$build_root/native" \
  --tools-dir "$build_root/native-gpg" \
  --gpg /opt/homebrew/bin/gpg \
  --output-app "$build_root/OnionDesk.app"
```

Промежуточные папки должны быть новыми пустыми папками либо предыдущими
папками сборщика с его маркером. Выходной путь `.app` должен быть свободен;
для повторного результата выберите новый `--output-app`. Без этого флага
сборщик создаёт `OnionDesk.app` в корне checkout и также сохраняет уже
существующее приложение. `--prepare-only` подготавливает и проверяет только
переносимый GnuPG, без сборки `.app` и без подготовки `OnionDesk-Data`.

Команда PyInstaller сохраняется в `<checkout>-build/native/build-command.json`,
логи и `evidence.json` — в той же папке. Python, WebKit-окно и GnuPG включаются
в результат; получателю не требуется устанавливать Python или Homebrew.
GnuPG и его библиотеки переносятся с `@loader_path`, подписываются ad-hoc и
проверяются на внешние ссылки Homebrew. Лицензии, формулы, исходные
URL/SHA-256 и хеши бинарников помещаются в
`Contents/Resources/tools/gpg` (допустимы внутренние ссылки на Frameworks).
Такие ссылки нужно сохранять при архивировании `.app`.

Автоматические проверки сборщика охватывают GnuPG, корректную подпись малого
искусственного файла и отказ после его изменения, подпись `.app`, внешние
библиотеки и ранний frozen helper с несуществующим запросом. Эти проверки не
открывают GUI, не вызывают системное окно администратора и не записывают USB.
Они не подтверждают визуальную работу WebKit, системное повышение прав или
запись USB; эти сценарии нужно проверить отдельно на целевом Mac.

Приложение имеет только локальную подпись ad-hoc. Developer ID и notarization
этот рецепт не выполняет. Готовая Intel Mac сборка не заявляется. Tor Browser
по-прежнему нужен для сетевых операций; подготовленная Tails-флешка
загружается на совместимом Intel/AMD x86-64, а не на Apple Silicon.
