#!/usr/bin/env python3
"""Read-only live probe via the dedicated Workstation guest-agent channel."""
import base64
import json
import subprocess
import sys
import time


def agent(command):
    result = subprocess.run(["virsh", "--connect", "qemu:///system", "qemu-agent-command", "oniondesk-workstation", "--timeout", "5", json.dumps(command)], capture_output=True, text=True, timeout=8)
    if result.returncode:
        raise RuntimeError("Guest agent ещё недоступен: завершите первичную установку в SYSMAINT.")
    response = json.loads(result.stdout)
    if "error" in response:
        raise RuntimeError("Guest agent отклонил запрос состояния.")
    return response["return"]


def main(arguments=()):
    auto_only = list(arguments) == ["--auto-cleaner"]
    if arguments and not auto_only:
        return 2
    task = agent({"execute": "guest-exec", "arguments": {"path": "/usr/bin/python3", "arg": ["-B", "/usr/local/lib/oniondesk/workstation-status.py"] + (["--auto-cleaner"] if auto_only else []), "capture-output": True}})
    deadline = time.monotonic() + 110
    while time.monotonic() < deadline:
        status = agent({"execute": "guest-exec-status", "arguments": {"pid": task["pid"]}})
        if status.get("exited"):
            if status.get("exitcode") != 0:
                raise RuntimeError("Гостевая проверка завершилась ошибкой.")
            encoded = status.get("out-data", "")
            if not isinstance(encoded, str) or len(encoded) > 16384:
                raise RuntimeError("Гостевая проверка превысила допустимый размер отчёта.")
            report = json.loads(base64.b64decode(encoded, validate=True))
            if not isinstance(report, dict):
                raise RuntimeError("Гостевая проверка вернула неизвестный формат.")
            if auto_only:
                required = {"installed", "enabled", "running", "user_session", "auto_cleaner", "report"}
                if not isinstance(report, dict) or set(report) != required:
                    raise RuntimeError("Гостевая проверка вернула неизвестный формат.")
                for key in required - {"report"}:
                    if type(report[key]) is not bool:
                        raise RuntimeError("Гостевая проверка вернула неверный статус.")
                details = report["report"]
                if details is not None:
                    keys = {"pending", "processing", "cleaned", "failed", "unsupported", "downloading",
                            "watch_error", "scan_limited", "capacity_reached", "last_result", "updated_at"}
                    if not isinstance(details, dict) or set(details) != keys:
                        raise RuntimeError("Гостевой отчёт имеет неизвестный формат.")
                    for key in ("pending", "processing", "cleaned", "failed", "unsupported", "downloading"):
                        if type(details[key]) is not int or not 0 <= details[key] <= 2 ** 31 - 1:
                            raise RuntimeError("Гостевой отчёт имеет неверные счётчики.")
                    for key in ("watch_error", "scan_limited", "capacity_reached"):
                        if type(details[key]) is not bool:
                            raise RuntimeError("Гостевой отчёт имеет неверный статус.")
                    if (details["last_result"] not in {"waiting", "processing", "cleaned", "failed", "unsupported", "changed"}
                            or not isinstance(details["updated_at"], str) or len(details["updated_at"]) > 40):
                        raise RuntimeError("Гостевой отчёт имеет неверный результат.")
                print(json.dumps(report, ensure_ascii=True))
                return 0
            required = {"setup_complete", "telegram", "agent_installed", "user_session", "tor", "auto_cleaner", "checked_at"}
            if not required <= report.keys():
                raise RuntimeError("Гостевая проверка вернула неизвестный формат.")
            if all(report[key] is True for key in ("setup_complete", "telegram", "agent_installed", "user_session", "tor", "auto_cleaner")):
                print("ГОТОВО: Telegram установлен; USER session, Tor и работа автоочистки в Workstation подтверждены сейчас.")
                print("Проверено: " + str(report["checked_at"]))
                return 0
            print("НЕ ГОТОВО: " + json.dumps(report, ensure_ascii=False))
            return 1
        time.sleep(2)
    raise RuntimeError("Гостевая проверка не завершилась вовремя; готовность не подтверждена.")


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)

