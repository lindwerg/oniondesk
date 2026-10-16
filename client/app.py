#!/usr/bin/env python3
"""Loopback-only guided desktop setup; secrets and authorization live in memory."""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
import json
import mimetypes
import os
from pathlib import Path
import re
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
import webbrowser

if getattr(sys, "frozen", False):
    KIT = Path(sys._MEIPASS)
    CLIENT = KIT / "client"
else:
    CLIENT = Path(__file__).resolve().parent
    KIT = CLIENT.parent
UI = CLIENT / "ui"
MAX_BODY = 16_384
NATIVE_ACCESS_MESSAGE = "Проверяю установочные файлы приложения…"
ONION = re.compile(r"(?:https?://)?[a-z2-7]{56}\.onion(?:/)?")
AUDIT_LABELS = {
    "vm.active-list": "Список запущенных рабочих систем",
    "oniondesk-gateway.inactive-xml": "Сохранённая сеть Gateway",
    "oniondesk-gateway.live-xml": "Текущая сеть Gateway",
    "oniondesk-gateway.owner": "Права процесса Gateway",
    "oniondesk-workstation.inactive-xml": "Сохранённая сеть Workstation",
    "oniondesk-workstation.live-xml": "Текущая сеть Workstation",
    "oniondesk-workstation.owner": "Права процесса Workstation",
    "tor@default.service": "Служба Tor на сервере",
    "nginx.service": "Страница входа",
    "oniondesk-auth.service": "Проверка пароля и кода входа",
    "oniondesk-vms.service": "Служба запуска рабочих систем",
    "oniondesk-websockify-gateway.service": "Передача экрана Gateway",
    "oniondesk-websockify-workstation.service": "Передача экрана Workstation",
    "private./etc/oniondesk": "Папка данных входа",
    "private./var/lib/oniondesk": "Папка состояния сервера",
    "private./etc/oniondesk/credentials.json": "Доступ к карточке входа",
    "private./etc/oniondesk/auth.json": "Доступ к настройкам авторизации",
    "tcp.snapshot": "Чтение открытых сетевых портов",
    "tcp.no-public-bindings": "Запрет прямого доступа к служебным портам",
    "tcp.5901": "Внутренний экран Gateway",
    "tcp.5902": "Внутренний экран Workstation",
    "tcp.16081": "Внутренний канал Gateway",
    "tcp.16082": "Внутренний канал Workstation",
    "tcp.18080": "Внутренняя страница кабинета",
    "tcp.18081": "Внутренняя проверка входа",
    "udp.snapshot": "Чтение внутренних сетевых каналов",
    "udp.6688": "Частная сеть со стороны Gateway",
    "udp.5577": "Частная сеть со стороны Workstation",
    "audit.internal": "Выполнение проверки сервера",
}
ASSETS = {"/": UI / "index.html", "/index.html": UI / "index.html",
          "/app.js": UI / "app.js", "/style.css": UI / "style.css",
          "/favicon.svg": UI / "favicon.svg",
          "/assets/hacker-mark.png": KIT / "assets" / "hacker-mark.png",
          "/fonts/JetBrainsMono-Regular.ttf": UI / "fonts" / "JetBrainsMono-Regular.ttf",
          "/fonts/JetBrainsMono-Bold.ttf": UI / "fonts" / "JetBrainsMono-Bold.ttf",
          "/assets/agent-cover.png": KIT / "assets" / "agent-cover.png"}
for _name in ("01-device", "02-usb", "03-purchase", "04-setup", "05-access", "06-daily"):
    ASSETS[f"/assets/steps/{_name}.png"] = KIT / "assets" / "steps" / f"{_name}.png"
for _goal, _count in enumerate((2, 4, 3, 10, 6, 3, 7, 3, 4, 6, 3, 6, 5, 3)):
    for _step in range(1, _count + 1):
        _name = f"g{_goal:02d}-s{_step:02d}.png"
        ASSETS["/assets/microsteps/" + _name] = KIT / "assets" / "microsteps" / _name

GUIDE_SHOTS = {
    "tor-first-connect": ("tor-macos/00-first-connect.png", "Настоящий первый запуск подготовленного Tor Browser 15.0.25 на Mac. Встроенные мосты уже настроены; нажмите Connect."),
    "tor-browser-ready": ("tor-macos/01-browser-ready.png", "Настоящий результат первого подключения подготовленной копии на Mac. После обычного Connect проверка самого мастера подтвердила Tor через HTTPS."),
    "tails-preparing": ("tails-first-boot-preparing.png", "Первый запуск Tails с виртуального USB. Настоящий кадр Tails 7.15; это ещё не готовый рабочий стол."),
    "tails-boot": ("tails-emulator-usb-boot-menu.png", "Настоящее меню загрузки виртуальной машины. На вашем компьютере названия и клавиши могут отличаться."),
    "tails-welcome": ("tails-welcome-russian.png", "Настоящее приветствие Tails 7.15 на русском в виртуальной машине. Выберите язык и нажмите «Запуск Tails»."),
    "tails-network": ("tails-desktop-network.png", "Настоящий рабочий стол Tails 7.15. В проверке использовалось виртуальное проводное подключение; Wi-Fi на физическом устройстве не проверялся."),
    "tails-tor": ("tails-tor-connection-options.png", "Настоящий мастер подключения Tor в Tails 7.15. Само открытие этого окна ещё не подтверждает соединение."),
    "tails-tor-auto": ("tails-tor-connection-auto.png", "Настоящий выбор автоматического подключения в Tails 7.15. Дождитесь отдельного подтверждения соединения."),
    "tails-tor-bridge": ("tails-tor-custom-obfs4.png", "Настоящий ввод официального публичного obfs4-моста в Tails 7.15. После ввода нажмите Connect и дождитесь результата."),
    "tails-tor-success": ("tails-tor-connected.png", "Настоящее успешное подключение Tails 7.15 через мост. В этой же системе проверочный HTTPS-запрос вернул 200 и IsTor=true. Это проверка сетевого маршрута, а не гарантия анонимности."),
    "tails-tor-failure": ("tails-tor-direct-failed-bridges-pending.png", "Фактический результат испытания: прямое соединение Tor заблокировано, Tails пробует штатные мосты. Успешный вход в Tor Browser этим кадром не подтверждён."),
    "tails-about": ("tails-about-version.png", "Настоящее окно версии испытанной системы: Tails 7.15. Кадры сняты с официального проверенного образа."),
    "whonix-gateway": ("whonix/06-gateway-tor-bootstrap.png", "Настоящий Gateway Whonix 18.2.1.9 после подключения через obfs4. Отдельный строгий HTTPS-запрос подтвердил IsTor=true. Это эмуляция, не испытание арендованного сервера с KVM."),
    "whonix-grub": ("whonix/27-auto-workstation-maintenance.png", "Настоящая автоматическая загрузка SYSMAINT без выбора в меню; роль загрузки ядра подтверждена."),
    "whonix-maintenance": ("whonix/28-auto-workstation-setup.png", "Реальная панель SYSMAINT во время фоновой автоматической установки; пользователь установку не запускал."),
    "whonix-terminal": ("whonix/30-auto-setup-readonly-status.png", "Диагностическое чтение журнала автоматической службы; для обычной установки терминал не требуется."),
    "whonix-telegram": ("whonix/32-auto-telegram-launch.png", "Настоящий экран приветствия Telegram в USER-режиме Whonix после автоматической установки. Запуск подтверждён; регистрация аккаунта и получение SMS этим кадром не подтверждаются."),
    "whonix-metadata": ("whonix/33-auto-clean-files.png", "Настоящий диалог очистки файлов внутри Whonix после автоматической установки. Сам выбор файла ещё не подтверждает очистку его содержимого."),
    "provider-privex": ("providers/privex-order-form.png", "Реальная форма Privex: псевдоним явно разрешён; нужны почта, имя сервера и назначение. Debian 13 доступен. Заказ не отправлялся, оборудование и счёт не оплачены."),
    "provider-privex-xmr": ("providers/privex-xmr-terms.png", "Действующие опубликованные условия Privex включают XMR. Наличие этого пункта не заменяет проверку валюты в вашем окончательном счёте."),
    "provider-nice-registration": ("providers/nicevps-registration.png", "Реальная форма NiceVPS: имя аккаунта, почта, пароль и CAPTCHA. Аккаунт не создавался; отсутствие паспортной проверки после заказа не подтверждено."),
    "provider-nice-payment": ("providers/nicevps-monero-payment.png", "Реальная таблица NiceVPS: XMR, четыре подтверждения, Phone Verification — NO verification. Это формулировка о телефоне, не гарантия отсутствия любых проверок личности."),
    "provider-nice-config": ("providers/nicevps-config.png", "Реальная конфигурация NiceVPS DEDI E3. Список мест размещения оказался пустым, поэтому возможность заказа этого сервера не подтверждена."),
    "crypton-api": ("providers/crypton-api-docs.png", "Настоящая документация Crypton API. Бесплатен доступ к API; номера и SMS оплачиваются отдельно. Ключ API может открывать сообщения и требует защиты как пароль."),
    "metadata-picker": ("metadata/01-select-file.png", "Реальный выбор файла в очистителе, испытанном на Debian 13. Использован тестовый файл; интерфейс Whonix проверяется отдельно."),
    "metadata-result": ("metadata/02-clean-result.png", "Реальный результат очистки тестового файла в Debian 13. Исходник сохранён; содержимое фотографии или документа не обезличивается."),
}
for _relative, _caption in GUIDE_SHOTS.values():
    ASSETS["/screens/real/" + _relative] = KIT / "screenshots" / "real" / _relative


def guide_shots():
    """Only captured, shipped frames; never invent an image for a missing step."""
    shots = {}
    root = KIT / "screenshots" / "real"
    for key, (relative, caption) in GUIDE_SHOTS.items():
        source = root / relative
        if source.is_file() and not source.is_symlink() and source.resolve().is_relative_to(root.resolve()):
            shots[key] = {"url": "/screens/real/" + relative, "alt": caption, "caption": caption}
    return {"shots": shots}


def open_system_browser(url):
    """System browsers must use their own libraries, not a frozen Linux bundle."""
    if not (sys.platform.startswith("linux") and getattr(sys, "frozen", False)):
        return webbrowser.open(url)
    previous = os.environ.get("LD_LIBRARY_PATH")
    original = os.environ.get("LD_LIBRARY_PATH_ORIG")
    try:
        if original is None:
            os.environ.pop("LD_LIBRARY_PATH", None)
        else:
            os.environ["LD_LIBRARY_PATH"] = original
        return webbrowser.open(url)
    finally:
        if previous is None:
            os.environ.pop("LD_LIBRARY_PATH", None)
        else:
            os.environ["LD_LIBRARY_PATH"] = previous


def load_usb():
    import usb_tails
    return usb_tails


def load_engine():
    import launcher
    launcher.KIT = KIT
    return launcher


def load_offline():
    import offline_bundle
    return offline_bundle


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Повторяющиеся поля запроса запрещены.")
        result[key] = value
    return result


def clean_message(value):
    # Runtime logs never expose the onion access URL. Passwords are never logged.
    return ONION.sub("[адрес в карточке доступа]", str(value))[:2000]


class Desk:
    def __init__(self, usb=None, engine=None, offline=None, wallets=None, phones=None):
        self.nonce = secrets.token_urlsafe(32)
        self.usb = usb
        self.engine = engine
        self.offline = offline
        self.wallets = wallets
        self.phones = phones
        self.lock = threading.RLock()
        self.job = None
        self.cancel_event = None
        self.remote = None
        self.credentials = None
        self.tor_verified = False
        self.server_installed = False
        self.guest_ready = False
        self.safety_checked = False
        self.safety_ok = False
        self.safety_report = ""
        self.last_status = ""
        self.auto_cleaner = None
        self.usb_verified = False
        self.usb_written = False
        self.closed = False
        self.closing = False
        self._close_prepared = False
        self.native_access_pending = False
        self.seq = 0

    def usb_engine(self):
        if self.usb is None:
            self.usb = load_usb()
        return self.usb

    def network_engine(self):
        if self.engine is None:
            self.engine = load_engine()
        return self.engine

    def offline_engine(self):
        if self.offline is None:
            self.offline = load_offline()
        return self.offline

    def wallet_manager(self):
        # The initial state request and secret-forget request can arrive together.
        # Keep one controller responsible for all vaults and pending secrets.
        with self.lock:
            if self.wallets is None:
                if self.closed or self.closing:
                    raise ValueError("Приложение завершает работу.")
                from wallet_controller import WalletController
                self.wallets = WalletController()
            return self.wallets

    def phone_manager(self):
        with self.lock:
            if self.closed or self.closing:
                raise ValueError("Приложение завершает работу.")
            if self.phones is None:
                from phone_usb import PhoneUSBController
                self.phones = PhoneUSBController()
            return self.phones

    def phone_status(self):
        with self.lock:
            manager = self.phones
        if manager is not None:
            return manager.state()
        from phone_usb import status
        return status()

    def state(self):
        usb = self.usb_engine()
        info = usb.system_info()
        with self.lock:
            pending = self.native_access_pending
        if pending:
            # Polling must remain responsive while the main thread asks macOS
            # for folder consent. Wallet presence reads the same manifest too.
            offline = {"available": False, "tails_available": False, "tor_available": False,
                       "tails_version": "", "tor_version": "", "access_pending": True,
                       "message": NATIVE_ACCESS_MESSAGE}
            wallet = {"available": False, "workspace_open": False, "pending_seed": False,
                      "vaults": [], "message": NATIVE_ACCESS_MESSAGE}
            phone = {"available": False, "session_open": False, "cleanup_required": False,
                     "devices": [], "tor_ready": False, "message": NATIVE_ACCESS_MESSAGE}
            feather = {"available": False, "prepared": False, "running": False,
                       "workspace_open": False, "version": "", "checked_on": "",
                       "message": NATIVE_ACCESS_MESSAGE}
        else:
            offline = self.offline_engine().status()
            manager = self.wallet_manager()
            wallet = manager.state()
            if hasattr(manager, "feather_state"):
                feather = manager.feather_state()
            else:
                import feather_bundle
                feather = feather_bundle.status()
            phone = self.phone_status()
        with self.lock:
            return {"system": info, "offline": offline, "wallet": wallet, "phone": phone, "feather": feather,
                    "closing": self.closing, "job": self.job,
                    "tor_verified": self.tor_verified,
                    "server_connected": self.remote is not None,
                    "server_installed": self.server_installed,
                    "guest_ready": self.guest_ready, "status": self.last_status,
                    "safety_checked": self.safety_checked, "safety_ok": self.safety_ok,
                    "safety_report": self.safety_report,
                    "auto_cleaner": self.auto_cleaner,
                    "has_credentials": self.credentials is not None,
                    "usb_verified": self.usb_verified, "usb_written": self.usb_written}

    def emit(self, progress):
        if isinstance(progress, str):
            progress = {"message": progress}
        with self.lock:
            if not self.job:
                return
            message = clean_message(progress.get("message", "Выполняется…"))
            percent = progress.get("percent")
            if isinstance(percent, (int, float)) and not isinstance(percent, bool):
                self.job["percent"] = max(0, min(100, percent))
            self.job["message"] = message
            self.job["events"] = (self.job["events"] + [message])[-20:]

    def start_job(self, kind, target, cancellable=False):
        with self.lock:
            if self.closed or self.closing:
                raise ValueError("Приложение завершает работу.")
            if self.job and self.job["state"] == "running":
                raise ValueError("Дождитесь завершения текущей операции.")
            # A new accepted operation must not retain evidence from a past success.
            reset = {
                "usb-download": ("usb_verified", "usb_written"),
                "usb-write": ("usb_written",),
                "server-status": ("guest_ready",),
                "server-start": ("guest_ready",),
                "tor-check": ("tor_verified",),
                "tor-start": ("tor_verified",),
                "server-connect": ("tor_verified", "guest_ready"),
                "server-audit": ("guest_ready",),
                "server-resume": ("guest_ready", "server_installed"),
                "server-install": ("guest_ready", "server_installed"),
            }
            for flag in reset.get(kind, ()):
                setattr(self, flag, False)
            if kind in ("server-connect", "server-status", "server-start", "server-audit", "server-install", "server-resume", "server-auto-cleaner"):
                self.safety_checked = False
                self.safety_ok = False
                self.safety_report = ""
                self.auto_cleaner = None
            self.seq += 1
            job = {"id": self.seq, "kind": kind, "state": "running",
                        "percent": None, "message": "Начинаю…", "events": [],
                        "cancellable": cancellable}
            self.job = job
            event = threading.Event()
            self.cancel_event = event

        def work():
            try:
                target(event)
                with self.lock:
                    job["state"] = "done"
                    job["percent"] = 100
                    if not job["events"]:
                        job["message"] = "Готово."
            except Exception as error:
                # No tracebacks, request bodies, URLs, passwords, or remote keys in logs.
                with self.lock:
                    job["state"] = "cancelled" if event.is_set() else "error"
                    job["message"] = clean_message(error)
            finally:
                with self.lock:
                    job["cancellable"] = False
        threading.Thread(target=work, daemon=True, name="desk-operation").start()
        return {"started": True, "job_id": self.seq}

    def _remote_required(self):
        with self.lock:
            if self.remote is None:
                raise ValueError("Сначала подключитесь к компьютеру в аренде на этапе «Установить сервер».")
            return self.remote

    def _phone_dispatch(self, action, data):
        schemas = {"list": set(), "install": {"device_id"}, "close": set()}
        if action not in schemas:
            raise LookupError("Неизвестное действие телефона.")
        if set(data) != schemas[action]:
            raise ValueError("Телефон выбирается только из списка; команды и пути не принимаются.")
        if action == "install" and (not isinstance(data["device_id"], str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", data["device_id"])):
            raise ValueError("Выберите телефон из обновлённого списка.")

        def operate(_event):
            manager = self.phone_manager()
            if action == "list":
                manager.list_devices(self.emit)
            elif action == "install":
                manager.install(data["device_id"], self.emit)
            else:
                manager.close()
                self.emit("Подключение для установки завершено. На телефоне отключите отладку USB и отзовите разрешение этого компьютера.")
        return self.start_job("phone-" + action, operate)

    def _wallet_dispatch(self, action, data):
        schemas = {'create': {'password'}, 'unlock': {'vault_id', 'password'},
                   'reveal': {'wallet_id', 'password'}, 'seed': set(),
                   'confirm': {'wallet_id', 'challenge', 'answers'}, 'forget': set(), 'lock': set()}
        if action not in schemas:
            raise LookupError('Неизвестное действие кошелька.')
        if set(data) != schemas[action]:
            raise ValueError('Некорректные поля кошелька. Сеть и пути задаёт только программа.')
        with self.lock:
            if self.closed:
                raise ValueError('Приложение завершает работу.')
            if action != 'forget' and self.job and self.job['state'] == 'running':
                raise ValueError('Дождитесь завершения текущей операции.')
        if action == 'forget':
            with self.lock:
                manager = self.wallets
            if manager is not None:
                manager.forget()
            return {'forgotten': True}
        manager = self.wallet_manager()
        if action == 'seed':
            return manager.take_seed()
        if action == 'confirm':
            if not isinstance(data['answers'], list) or len(data['answers']) != 3 or any(
                    not isinstance(word, str) or not re.fullmatch(r'[A-Za-z]{1,32}', word) for word in data['answers']):
                raise ValueError('Введите три слова из сохранённой фразы.')
            if not isinstance(data['wallet_id'], str) or not isinstance(data['challenge'], str):
                raise ValueError('Повторно откройте проверку резервной копии.')
            operation = lambda: manager.confirm_backup(data['wallet_id'], data['challenge'], data['answers'])
            message = 'Резервная копия кошелька подтверждена. Слова скрыты.'
        elif action == 'lock':
            operation = manager.close
            message = 'Рабочее хранилище кошелька закрыто.'
        else:
            password = data.pop('password')
            if not isinstance(password, str) or not 12 <= len(password) <= 256 or '\0' in password:
                raise ValueError('Выберите пароль кошелька от 12 до 256 символов.')
            if action == 'create':
                operation = lambda: manager.create(password, self.emit)
                message = 'Кошелёк создан в защищённом хранилище. Теперь сохраните фразу восстановления.'
            else:
                key = 'vault_id' if action == 'unlock' else 'wallet_id'
                if not isinstance(data[key], str) or not 1 <= len(data[key]) <= 100:
                    raise ValueError('Выберите своё хранилище и кошелёк из списка.')
                operation = (lambda: manager.unlock(data[key], password, self.emit)) if action == 'unlock' else (
                    lambda: manager.reveal(data[key], password, self.emit))
                message = 'Хранилище открыто.' if action == 'unlock' else 'Фраза подготовлена для просмотра; нажмите «Показать слова».'
        def run_wallet(_event):
            from wallet_engine import WalletError
            try:
                operation()
            except WalletError:
                raise
            except Exception:
                raise RuntimeError('Операция кошелька не завершилась. Данные и секреты не выводятся; проверьте состояние хранилища.') from None
            self.emit({'message': message, 'percent': 100})
        return self.start_job('wallet-' + action, run_wallet)

    def _feather_dispatch(self, action: str, data: dict[str, object]) -> dict[str, object]:
        if action not in {"prepare", "launch", "connect", "stop"}:
            raise LookupError("Неизвестное действие Feather.")
        if data:
            raise ValueError("Feather использует только проверенные файлы и открытое хранилище. Параметры не принимаются.")
        manager = self.wallet_manager()
        def operate(_event):
            if action == "prepare":
                manager.prepare_feather(self.emit)
            elif action == "launch":
                manager.launch_feather(self.emit)
            elif action == "connect":
                manager.connect_feather(self.emit)
            else:
                manager.stop_feather()
                self.emit({"stage": "feather", "message": "Сеанс Feather завершён.", "percent": 100})
        return self.start_job("feather-" + action, operate)

    def dispatch(self, path, data):
        if not isinstance(data, dict):
            raise ValueError("Ожидается объект JSON.")
        with self.lock:
            if (self.closed or self.closing) and path not in {"/api/wallet/forget", "/api/secrets/clear"}:
                raise ValueError("Приложение завершает работу.")
            if self.native_access_pending and path not in {
                    "/api/secrets/clear", "/api/wallet/forget", "/api/job/cancel"}:
                raise ValueError(NATIVE_ACCESS_MESSAGE)
        if path.startswith('/api/wallet/'):
            return self._wallet_dispatch(path.removeprefix('/api/wallet/'), data)
        if path.startswith('/api/phone/'):
            return self._phone_dispatch(path.removeprefix('/api/phone/'), data)
        if path.startswith('/api/feather/'):
            return self._feather_dispatch(path.removeprefix('/api/feather/'), data)
        if path == "/api/usb/download":
            def download(event):
                self.usb_engine().download_verified_image(self.emit, event)
                with self.lock:
                    self.usb_verified = True
                self.emit({"message": "Tails скачан. Подпись проверена; можно записать флешку.", "percent": 100})
            return self.start_job("usb-download", download, True)
        if path == "/api/usb/write":
            selection = data.get("selection")
            confirmation = data.get("confirmation")
            if not isinstance(selection, str) or not selection or len(selection) > 512:
                raise ValueError("Выберите флешку из обновлённого списка.")
            if confirmation != "СТЕРЕТЬ":
                raise ValueError("Для записи введите ровно СТЕРЕТЬ. Все данные выбранной флешки будут удалены.")
            def write(event):
                self.usb_engine().write_verified_image(selection, confirmation, self.emit, event)
                with self.lock:
                    self.usb_written = True
                self.emit({"message": "Флешка записана и проверена. Извлеките её безопасно.", "percent": 100})
            return self.start_job("usb-write", write, False)
        if path == "/api/tor/check":
            def check(_event):
                self.emit("Проверяю защищённое соединение через Tor Browser…")
                self.network_engine().find_tor_proxy()
                with self.lock:
                    self.tor_verified = True
                self.emit("Tor подтверждён сейчас. При подключении к серверу проверю его ещё раз.")
            return self.start_job("tor-check", check)
        if path == "/api/tor/start":
            def launch(_event):
                self.emit("Проверяю подпись официального Tor Browser из комплекта…")
                result = self.offline_engine().prepare_tor(self.emit)
                if not isinstance(result, dict) or not isinstance(result.get("message"), str) or not 1 <= len(result["message"]) <= 2000:
                    raise RuntimeError("Tor Browser не подтвердил подготовку. Проверьте комплект и повторите.")
                self.emit(result["message"])
            return self.start_job("tor-start", launch)
        if path == "/api/server/connect":
            engine = self.network_engine()
            host = engine.validate_host(data.get("host", ""))
            expected = engine.validate_fingerprint(data.get("fingerprint", ""))
            password = data.get("password")
            if not isinstance(password, str) or not 1 <= len(password) <= 1024:
                raise ValueError("Введите первоначальный пароль root из панели или письма провайдера.")
            def connect(_event):
                client = None
                # A failed switch must never leave the previous machine selected.
                with self.lock:
                    old = self.remote
                    self.remote = None
                    self.credentials = None
                    self.server_installed = False
                    self.last_status = ""
                if old:
                    old.close()
                try:
                    self.emit("Проверяю Tor. Подключаюсь и сверяю отпечаток компьютера…")
                    port = engine.find_tor_proxy()
                    client = engine.connect(host, password, expected, port)
                    # No arbitrary command API: only a fixed Debian/privilege check.
                    engine.run(client, 'test "$(id -u)" = 0 && . /etc/os-release && test "$ID" = debian && test "$VERSION_ID" = 13')
                    with self.lock:
                        self.remote = client
                        client = None
                        self.tor_verified = True
                        self.guest_ready = False
                        self.last_status = ""
                        self.server_installed = False
                        self.credentials = None
                    self.emit("Соединение подтверждено: Tor, совпавший SSH-ключ и Debian 13. Можно начать настройку.")
                except Exception:
                    if client:
                        client.close()
                    raise RuntimeError("Подключение не удалось. Проверьте Tor Browser, IP, пароль root и SHA256 из консоли; также нужен Debian 13. Прямого подключения нет.") from None
            return self.start_job("server-connect", connect)
        if path == "/api/server/install":
            if data.get("licenses") is not True or data.get("fresh_server") is not True:
                raise ValueError("Подтвердите условия Whonix и использование отдельного свежего сервера.")
            remote = self._remote_required()
            def install(_event):
                values = self.network_engine().install(remote, self.emit)
                self._set_credentials(values)
                with self.lock:
                    self.server_installed = True
                self.emit("Компьютер настроен. Далее нужен первый вход в Whonix; готовность Telegram ещё не подтверждена.")
            return self.start_job("server-install", install)
        if path == "/api/server/credentials":
            remote = self._remote_required()
            def recover(_event):
                values = self.network_engine().read_credentials(remote, require_complete=True)
                self._set_credentials(values)
                with self.lock:
                    self.server_installed = True
                    self.guest_ready = False
                self.emit("Карточка получена с вашего сервера. Она доступна только в этом запуске приложения.")
            return self.start_job("server-credentials", recover)
        if path == "/api/server/resume":
            remote = self._remote_required()
            def resume(_event):
                values = self.network_engine().resume_install(remote, self.emit)
                self._set_credentials(values)
                with self.lock:
                    self.server_installed = True
                self.emit("Наблюдение восстановлено; установка завершилась. Пройдите первый вход и проверку готовности.")
            return self.start_job("server-resume", resume)
        if path == "/api/server/action":
            action = data.get("action")
            commands = {"status": "sudo /opt/oniondesk/server/control.sh status",
                        "start": "sudo /opt/oniondesk/server/control.sh start",
                        "auto-cleaner": "sudo /opt/oniondesk/server/control.sh auto-cleaner",
                        "audit": "python3 -B /opt/oniondesk/server/runtime-audit.py --json || [ \"$?\" -eq 1 ]"}
            if action not in commands:
                raise ValueError("Неизвестное действие.")
            remote = self._remote_required()
            def operate(_event):
                if action == "status" and not self._audit_remote(remote):
                    self.emit("Проверка обнаружила проблему изоляции или службы. Готовность заблокирована; смотрите отчёт проверки.")
                    return
                output = self.network_engine().run(remote, commands[action], timeout=180)
                if action == "audit":
                    self._set_safety_report(output)
                    self.emit("Проверка изоляции завершена. " + ("Проверенные ограничения соблюдены сейчас." if self.safety_ok else "Обнаружена проблема; рабочий стол нельзя считать безопасно настроенным."))
                elif action == "auto-cleaner":
                    self._set_auto_cleaner(output)
                    self.emit("Автоочистка загрузок работает. Готовые копии находятся в папке OnionDesk-Clean на удалённом рабочем столе."
                              if self.auto_cleaner["auto_cleaner"] else "Автоочистка пока не подтверждена. Проверьте состояние удалённого рабочего стола.")
                elif action == "status":
                    with self.lock:
                        self.guest_ready = any(line.startswith("ГОТОВО: Telegram") for line in output.splitlines())
                        self.last_status = clean_message(output)
                    self.emit("Проверка завершена. " + ("Telegram установлен; Tor в Workstation подтверждён сейчас." if self.guest_ready else "Готовность пока не подтверждена. Завершите первый вход в Whonix и повторите проверку."))
                else:
                    with self.lock:
                        self.guest_ready = False
                    self.emit("Запуск запрошен. Подождите немного и проверьте готовность отдельно.")
            return self.start_job("server-" + action, operate)
        if path == "/api/job/cancel":
            with self.lock:
                if not self.job or self.job["state"] != "running" or not self.job["cancellable"]:
                    raise ValueError("Эту операцию нельзя остановить здесь.")
                self.cancel_event.set()
            return {"cancel_requested": True}
        if path == "/api/secrets/clear":
            with self.lock:
                self.credentials = None
            return {"cleared": True}
        raise LookupError("Неизвестное действие.")

    def _set_auto_cleaner(self, output):
        with self.lock:
            self.auto_cleaner = None
        try:
            if not isinstance(output, str) or len(output) > 10_000:
                raise ValueError
            value = json.loads(output)
            flags = {"installed", "enabled", "running", "user_session", "auto_cleaner"}
            if not isinstance(value, dict) or set(value) != flags | {"report"}:
                raise ValueError
            if any(type(value[key]) is not bool for key in flags):
                raise ValueError
            details = value["report"]
            if details is not None:
                counts = {"pending", "processing", "cleaned", "failed", "unsupported", "downloading"}
                limits = {"watch_error", "scan_limited", "capacity_reached"}
                if not isinstance(details, dict) or set(details) != counts | limits | {"last_result", "updated_at"}:
                    raise ValueError
                if any(type(details[key]) is not int or not 0 <= details[key] < 2 ** 31 for key in counts):
                    raise ValueError
                if any(type(details[key]) is not bool for key in limits):
                    raise ValueError
                if details["last_result"] not in {"waiting", "processing", "cleaned", "failed", "unsupported", "changed"}:
                    raise ValueError
                if not isinstance(details["updated_at"], str) or not re.fullmatch(r"[0-9T:+.Z-]{19,40}", details["updated_at"]):
                    raise ValueError
            expected = (all(value[key] for key in flags - {"auto_cleaner"})
                        and details is not None and not details["watch_error"])
            if value["auto_cleaner"] != expected:
                raise ValueError
        except (ValueError, TypeError, KeyError, RecursionError):
            raise RuntimeError("Сервер не подтвердил состояние автоочистки. Предыдущее успешное состояние сброшено.") from None
        with self.lock:
            self.auto_cleaner = value

    def _audit_remote(self, remote):
        output = self.network_engine().run(remote,
            'python3 -B /opt/oniondesk/server/runtime-audit.py --json || [ "$?" -eq 1 ]', timeout=180)
        self._set_safety_report(output)
        return self.safety_ok

    def _set_safety_report(self, output):
        try:
            report = json.loads(output)
            checks = report["checks"]
            if type(report["ok"]) is not bool or not isinstance(checks, list) or not 1 <= len(checks) <= 32:
                raise ValueError
            lines = []
            for item in checks:
                if not isinstance(item, dict) or type(item.get("ok")) is not bool:
                    raise ValueError
                if not isinstance(item.get("id"), str) or not isinstance(item.get("detail"), str):
                    raise ValueError
                label = AUDIT_LABELS.get(item["id"], "Проверка сервера")
                lines.append(("✓ " if item["ok"] else "✕ ") + label + ": " + clean_message(item["detail"])[:500])
            if report["ok"] != all(item["ok"] for item in checks):
                raise ValueError
        except (ValueError, KeyError, TypeError, RecursionError):
            raise RuntimeError("Сервер не прислал корректный отчёт изоляции. Готовность не подтверждена.") from None
        with self.lock:
            self.safety_checked = True
            self.safety_ok = report["ok"]
            self.safety_report = "\n".join(lines)
            if not self.safety_ok:
                self.guest_ready = False

    def access_note(self):
        with self.lock:
            if self.credentials is None:
                raise ValueError("Сначала получите карточку доступа на шаге 4.")
            url = self.credentials["url"]
        return {"filename": "OnionDesk-Tails.txt", "text": (
            "ONIONDESK · ПЕРЕХОД В TAILS\n\nАдрес вашего кабинета:\n" + url + "\n\n"
            "Это адрес частного кабинета. Не публикуйте и не отправляйте его посторонним.\n"
            "В памятке нет паролей, имени входа, ключа кодов или данных Telegram.\n\n"
            "ДО ПЕРЕЗАГРУЗКИ\n"
            "1. Отдельно сохраните имя входа, пароль и ключ кодов из карточки в менеджер паролей или зашифрованное хранилище.\n"
            "2. Перенесите эту памятку на второй носитель или запишите адрес на бумаге. Не изменяйте установочный образ Tails.\n"
            "3. Проверьте, что можете прочитать адрес и получить код аутентификатора после перезагрузки.\n\n"
            "В TAILS\n"
            "4. Загрузите совместимый Intel/AMD компьютер с флешки, подключите сеть и дождитесь подключения Tor.\n"
            "5. Откройте памятку через Файлы. Скопируйте адрес в Tor Browser. Unsafe Browser для кабинета не используйте.\n"
            "6. Введите имя, пароль и текущий код аутентификатора. Откройте Workstation в USER Session.\n"
            "7. Для следующих входов сохраните onion-адрес в закладки. По желанию включите Tor Browser Bookmarks в зашифрованном Persistent Storage.\n\n"
            "Мастер в Tails устанавливать не требуется. Личные аккаунты и раскрытые вами сведения могут связать действия с вами даже через Tor.\n"
        )}

    def _set_credentials(self, values):
        if not isinstance(values, dict):
            raise RuntimeError("Неизвестный формат карточки доступа.")
        url = values.get("url", "")
        if not isinstance(url, str) or not re.fullmatch(r"http://[a-z2-7]{56}\.onion/", url):
            raise RuntimeError("Неизвестный адрес доступа.")
        for key in ("login", "password", "totp_secret", "otpauth_uri"):
            if not isinstance(values.get(key), str) or not 1 <= len(values[key]) <= 2048:
                raise RuntimeError("Карточка доступа неполная.")
        with self.lock:
            self.credentials = {key: values[key] for key in ("url", "login", "password", "totp_secret", "otpauth_uri")}

    def close_wallet(self):
        if self.wallets is not None:
            self.wallets.close()

    def close_phone(self):
        if self.phones is not None:
            self.phones.close()

    def prepare_close(self):
        with self.lock:
            if self.closed or self._close_prepared:
                return
            if self.closing or (self.job and self.job["state"] == "running"):
                raise RuntimeError("Дождитесь завершения текущей операции.")
            # Admit no new worker or controller until all protected stores close.
            self.closing = True
        try:
            self.close_phone()
            self.close_wallet()
        except BaseException:
            with self.lock:
                self.closing = False
            raise
        with self.lock:
            self._close_prepared = True

    def close(self):
        self.prepare_close()
        with self.lock:
            self.closed = True
            self.credentials = None
            remote, self.remote = self.remote, None
        if remote:
            remote.close()


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, desk, port=0):
        self.desk = desk
        super().__init__(("127.0.0.1", port), Handler)
        self.origin = f"http://127.0.0.1:{self.server_port}"
        self.host = f"127.0.0.1:{self.server_port}"
        self.on_quit = None

    def handle_error(self, request, client_address):
        # The standard handler would print sensitive request context on stderr.
        pass


class Handler(BaseHTTPRequestHandler):
    server_version = "LocalDesk"

    def log_message(self, format, *args):
        pass

    def headers_ok(self, api=False, mutation=False):
        if self.headers.get_all("Host", []) != [self.server.host]:
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin != self.server.origin:
            return False
        if mutation and origin != self.server.origin:
            return False
        site = self.headers.get("Sec-Fetch-Site")
        if site is not None and site not in ("same-origin", "none"):
            return False
        if api:
            token = self.headers.get("X-App-Nonce", "")
            if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token) or not secrets.compare_digest(token, self.server.desk.nonce):
                return False
        return True

    def respond(self, status, body, content_type="application/json; charset=utf-8"):
        payload = json.dumps(body, ensure_ascii=False).encode() if isinstance(body, dict) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        path = urlsplit(self.path)
        api = path.path.startswith("/api/")
        if path.query or path.fragment or not self.headers_ok(api=api):
            self.respond(403, {"error": "Доступ разрешён только локальному приложению. Перезапустите приложение, если потерян код запуска."})
            return
        try:
            if path.path == "/api/state":
                self.respond(200, self.server.desk.state())
            elif path.path == "/api/usb/disks":
                self.respond(200, {"disks": self.server.desk.usb_engine().list_usb_disks()})
            elif path.path == "/api/secrets":
                with self.server.desk.lock:
                    card = self.server.desk.credentials
                    if card is None:
                        raise ValueError("Карточка ещё не получена или уже скрыта. Получите её с сервера на шаге 4.")
                    self.respond(200, {"credentials": card})
            elif path.path == "/api/access-note":
                self.respond(200, self.server.desk.access_note())
            elif path.path == "/api/guide-shots":
                self.respond(200, guide_shots())
            elif path.path == "/api/wallet/list":
                with self.server.desk.lock:
                    if self.server.desk.native_access_pending:
                        raise ValueError(NATIVE_ACCESS_MESSAGE)
                self.respond(200, self.server.desk.wallet_manager().list_wallets())
            elif path.path in ASSETS:
                source = ASSETS[path.path]
                if not source.is_file():
                    self.respond(404, {"error": "Файл интерфейса недоступен."})
                    return
                content_type = mimetypes.guess_type(str(source))[0] or "application/octet-stream"
                self.respond(200, source.read_bytes(), content_type)
            else:
                self.respond(404, {"error": "Страница не найдена."})
        except (ValueError, RuntimeError) as error:
            self.respond(400, {"error": clean_message(error)})
        except Exception:
            self.respond(500, {"error": "Не удалось выполнить проверку. Повторите действие; при необходимости перезапустите приложение."})

    def do_POST(self):
        path = urlsplit(self.path)
        if path.query or path.fragment or not path.path.startswith("/api/") or not self.headers_ok(api=True, mutation=True):
            self.respond(403, {"error": "Запрос отклонён. Откройте приложение через его значок."})
            return
        if self.headers.get("Transfer-Encoding") is not None or self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
            self.respond(415, {"error": "Ожидается JSON."})
            return
        lengths = self.headers.get_all("Content-Length", [])
        try:
            if len(lengths) != 1:
                raise ValueError
            length = int(lengths[0])
            if length < 0 or length > MAX_BODY:
                self.respond(413, {"error": "Слишком большой запрос."})
                return
            self.connection.settimeout(10)
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError
            data = json.loads(body, object_pairs_hook=unique_object)
            if not isinstance(data, dict):
                raise ValueError
        except (ValueError, UnicodeError, TimeoutError, RecursionError):
            self.respond(400, {"error": "Некорректный запрос."})
            return
        if path.path == "/api/quit":
            with self.server.desk.lock:
                running = self.server.desk.job and self.server.desk.job["state"] == "running"
            if running:
                self.respond(409, {"error": "Сначала дождитесь завершения операции. Запись флешки и установку нельзя прерывать закрытием приложения."})
                return
            try:
                self.server.desk.close()
            except RuntimeError:
                self.respond(409, {"error": "Не удалось завершить USB-подключение или закрыть защищённое хранилище. Закройте использующие его файлы и повторите выход."})
                return
            self.respond(200, {"closed": True})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            if self.server.on_quit:
                threading.Thread(target=self.server.on_quit, daemon=True).start()
            return
        try:
            result = self.server.desk.dispatch(path.path, data)
            self.respond(200, result)
        except LookupError as error:
            self.respond(404, {"error": str(error)})
        except (ValueError, RuntimeError) as error:
            self.respond(400, {"error": clean_message(error)})
        except Exception:
            self.respond(500, {"error": "Операция не началась. Проверьте введённые данные и повторите."})

    def do_OPTIONS(self):
        self.respond(405, {"error": "Метод запрещён."})


@contextmanager
def native_data_access(desk):
    """Verify app resources directly; obtain consent for legacy external kits."""
    if sys.platform != "darwin":
        yield
        return
    offline = desk.offline_engine()
    root = offline._find_root()
    if root is None:
        yield
        return
    root = Path(root).absolute()
    embedded = root == offline._embedded_data_root()
    # Installed kits in Applications do not need a protected-folder prompt.
    # Never exempt an alias or a redirected ancestor from the ordinary checks.
    applications = (Path("/Applications"), Path.home() / "Applications")
    if not embedded and root.resolve() == root and any(root.is_relative_to(folder) for folder in applications):
        yield
        return

    from AppKit import NSAlert, NSApplication, NSModalResponseOK, NSOpenPanel
    from Foundation import NSURL

    NSApplication.sharedApplication().activateIgnoringOtherApps_(True)

    def abort(message):
        alert = NSAlert.alloc().init()
        alert.setMessageText_("Запуск OnionDesk отменён")
        alert.setInformativeText_(message)
        alert.addButtonWithTitle_("Закрыть")
        alert.runModal()
        raise SystemExit(1)

    if embedded:
        try:
            offline._check_manifest(root)
        except (offline.OfflineError, OSError) as error:
            abort(clean_message(error))
        yield
        return

    panel = NSOpenPanel.openPanel()
    panel.setTitle_("Доступ к файлам OnionDesk")
    panel.setMessage_("Откройте папку OnionDesk-Data из этого комплекта. Мастеру нужен доступ к установочным файлам в этой папке.")
    panel.setPrompt_("Открыть")
    panel.setCanChooseDirectories_(True)
    panel.setCanChooseFiles_(False)
    panel.setAllowsMultipleSelection_(False)
    panel.setCanCreateDirectories_(False)
    panel.setResolvesAliases_(False)
    panel.setDirectoryURL_(NSURL.fileURLWithPath_(str(root)))
    if panel.runModal() != NSModalResponseOK:
        abort("Доступ к папке OnionDesk-Data не предоставлен. Чтобы продолжить, запустите OnionDesk снова и откройте указанную папку.")
    selected = panel.URL()
    if selected is None or not selected.isFileURL() or Path(selected.path()).absolute() != root or root.name != "OnionDesk-Data":
        abort("Выбрана другая папка. Запустите OnionDesk снова и откройте именно папку OnionDesk-Data из этого комплекта: " + str(root))
    # A non-sandboxed open-panel URL may have no explicit security scope. The
    # selection still grants folder consent; reading the pinned manifest below
    # remains mandatory. Retain the selected URL for the entire native session.
    scoped = selected.startAccessingSecurityScopedResource()
    try:
        try:
            offline._check_manifest(root)
        except (offline.OfflineError, OSError) as error:
            abort(clean_message(error))
        yield
    finally:
        if scoped:
            selected.stopAccessingSecurityScopedResource()


def native_window(server, desk, launch, webview):
    """Optional packaged WebKit window. No Python API is exposed to the page."""
    mac_access = sys.platform == "darwin"
    if mac_access:
        from PyObjCTools import AppHelper
    with desk.lock:
        desk.native_access_pending = mac_access
    webview.settings["ALLOW_DOWNLOADS"] = False
    webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = False
    window = webview.create_window("OnionDesk · первое задание", launch,
                                   width=1260, height=850, min_size=(680, 560),
                                   text_select=True, background_color="#f1f0e8")
    data_access = ExitStack()
    session_open = True
    access_scheduled = False

    def grant_access():
        # AppHelper dispatches this callback on Cocoa's main thread. Both scope
        # entry and ExitStack.close run there, never in a webview event worker.
        with desk.lock:
            if not session_open or desk.closed:
                return
        try:
            data_access.enter_context(native_data_access(desk))
        except SystemExit:
            window.destroy()
        except Exception:
            from AppKit import NSAlert
            alert = NSAlert.alloc().init()
            alert.setMessageText_("Не удалось открыть файлы OnionDesk")
            alert.setInformativeText_("Запустите OnionDesk снова и откройте папку OnionDesk-Data из полного комплекта.")
            alert.addButtonWithTitle_("Закрыть")
            alert.runModal()
            window.destroy()
        else:
            with desk.lock:
                if not desk.closed:
                    desk.native_access_pending = False

    def loaded():
        nonlocal access_scheduled
        with desk.lock:
            if access_scheduled or not session_open or desk.closed:
                return
            access_scheduled = True
        AppHelper.callAfter(grant_access)

    def closing():
        with desk.lock:
            running = desk.job and desk.job["state"] == "running"
        if running:
            window.evaluate_js("document.getElementById('notice').textContent='Дождитесь завершения операции перед закрытием приложения.';document.getElementById('notice').hidden=false;")
            return False
        try:
            desk.prepare_close()
        except RuntimeError:
            window.evaluate_js("document.getElementById('notice').textContent='Не удалось завершить USB-подключение или закрыть защищённое хранилище. Повторите выход после закрытия его файлов.';document.getElementById('notice').hidden=false;")
            return False
    def closed():
        desk.close()
        server.shutdown()
    window.events.closing += closing
    window.events.closed += closed
    if mac_access:
        window.events.loaded += loaded
    server.on_quit = window.destroy
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        webview.start(debug=False, private_mode=True)
    finally:
        with desk.lock:
            session_open = False
            if mac_access:
                desk.native_access_pending = True
        data_access.close()


def main():
    # Native privilege helper dispatch must occur before any GUI or listener.
    if len(sys.argv) > 1 and sys.argv[1] == "--usb-privileged":
        import usb_privileged
        raise SystemExit(usb_privileged.main(sys.argv[2:]))
    parser = argparse.ArgumentParser(description="Локальный мастер OnionDesk")
    parser.add_argument("--no-browser", action="store_true", help="не открывать браузер автоматически")
    parser.add_argument("--native", action="store_true", help="использовать встроенное окно, если установлен pywebview")
    parser.add_argument("--port", type=int, default=0)
    options = parser.parse_args()
    desk = Desk()
    server = LocalServer(desk, options.port)
    launch = server.origin + "/#" + desk.nonce
    try:
        if not options.no_browser and (options.native or getattr(sys, "frozen", False)):
            try:
                import webview as native_webview
            except ImportError:
                if options.native:
                    raise RuntimeError("Для встроенного окна нужен pywebview. Запустите обычный мастер без --native.") from None
            else:
                native_window(server, desk, launch, native_webview)
                return
        if not options.no_browser:
            open_system_browser(launch)
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        desk.close()
        server.server_close()


if __name__ == "__main__":
    main()
