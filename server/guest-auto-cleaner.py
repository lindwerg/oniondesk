#!/usr/bin/python3
"""Bounded USER-only automatic cleaned copies of fixed Workstation downloads.

Only report.json is read by the guest readiness probe. Filenames and the mapping
from originals to verified copies stay in private guest-local history.json.
"""
from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import pwd
import secrets
import signal
import stat
import sys
import tempfile
import time

POLL_SECONDS = 2
STABLE_SECONDS = 6
MAX_ENTRIES = 1024
MAX_COPIES = 1024
MAX_SCAN = 2048
MAX_STATE = 2 * 1024 * 1024
MAX_REPORT = 4096
MAX_COUNT = 2 ** 31 - 1
WATCHES = ("Downloads", "Downloads/Telegram Desktop")
TEMP_SUFFIXES = (".part", ".partial", ".crdownload", ".download", ".tmp")
COUNTS = ("pending", "processing", "cleaned", "failed", "unsupported", "downloading")
RESULTS = {"waiting", "processing", "cleaned", "failed", "unsupported", "changed"}
INSTALLED_HELPER = Path("/usr/local/lib/oniondesk/auto-cleaner.py")
INSTALLED_UNIT = Path("/etc/systemd/user/oniondesk-auto-cleaner.service")


class SafetyError(Exception):
    """An unsafe local path/state stops the service without disclosing its name."""


def signature(info):
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_uid, info.st_nlink]


def private_directory(parent, name):
    path = parent / name
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise SafetyError("unsafe private directory")
    return path


def state_directory(home):
    # Existing XDG parents may be 0755 but must belong to USER and not be writable
    # by other users. Reject every symlink rather than resolving it elsewhere.
    parent = home
    for name in (".local", "state"):
        candidate = parent / name
        try:
            candidate.mkdir(mode=0o700)
        except FileExistsError:
            pass
        info = candidate.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o022):
            raise SafetyError("unsafe state parent")
        parent = candidate
    return private_directory(private_directory(parent, "oniondesk"), "auto-clean")


def read_private_json(path, owner, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as incoming:
        info = os.fstat(incoming.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > maximum):
            raise SafetyError("unsafe state file")
        content = incoming.read(maximum + 1)
    if len(content) > maximum:
        raise SafetyError("oversized state file")
    return json.loads(content)


def atomic_private_write(path, encoded):
    # Never replace a link or an untrusted pre-existing state object.
    try:
        info = path.lstat()
    except FileNotFoundError:
        pass
    else:
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
            raise SafetyError("unsafe state file")
    if len(encoded) > MAX_STATE:
        raise SafetyError("oversized state")
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".state-", delete=False) as output:
        temporary = Path(output.name)
        try:
            os.fchmod(output.fileno(), 0o600)
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def encoded_json(value):
    return (json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")


def atomic_private_json(path, value):
    atomic_private_write(path, encoded_json(value))


def process_identity(pid):
    """Bind health to this live process, including Linux PID reuse protection."""
    proc = Path("/proc") / str(pid)
    info = proc.stat()
    fields = (proc / "stat").read_text().rsplit(") ", 1)[1].split()
    command = (proc / "cmdline").read_bytes().split(b"\0")
    if fields[0] == "Z" or len(fields) < 20:
        raise SafetyError("process not running")
    return info.st_uid, fields[19], command


def safe_public_report(home, owner, pid):
    # QGA runs as root. Do not follow even user-controlled links while reading
    # health; the private mapping is never read or exported by this function.
    directory = home
    for name in (".local", "state", "oniondesk", "auto-clean"):
        directory /= name
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022):
            raise SafetyError("unsafe report parent")
    value = read_private_json(directory / "report.json", owner, MAX_REPORT)
    if not isinstance(value, dict) or value.get("version") != 1 or value.get("pid") != pid:
        raise SafetyError("unexpected report")
    uid, start, command = process_identity(pid)
    if (uid != owner or value.get("uid") != owner or value.get("start_ticks") != start
            or os.fsencode(str(INSTALLED_HELPER)) not in command or b"--watch" not in command):
        raise SafetyError("report process mismatch")
    updated = value.get("updated_unix")
    if not isinstance(updated, (float, int)) or not 0 <= time.time() - updated <= 120:
        raise SafetyError("stale report")
    report = {}
    for key in COUNTS:
        number = value.get(key)
        if type(number) is not int or not 0 <= number <= MAX_COUNT:
            raise SafetyError("invalid count")
        report[key] = number
    for key in ("watch_error", "scan_limited", "capacity_reached"):
        if type(value.get(key)) is not bool:
            raise SafetyError("invalid report flag")
        report[key] = value[key]
    if value.get("last_result") not in RESULTS:
        raise SafetyError("invalid result")
    report["last_result"] = value["last_result"]
    report["updated_at"] = datetime.fromtimestamp(updated, timezone.utc).isoformat()
    return report


class Watcher:
    def __init__(self, home, engine, *, clock=time.monotonic):
        self.home = Path(home)
        info = self.home.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022):
            raise SafetyError("unsafe home")
        self.engine = engine
        self.clock = clock
        self.state_dir = state_directory(self.home)
        lock_path = self.state_dir / "watch.lock"
        self.lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        info = os.fstat(self.lock_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
            self.close()
            raise SafetyError("unsafe lock")
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.entries = self._load_history()
            self._history_dirty = not (self.state_dir / "history.json").exists()
            self._capacity_stopped = False
            self._storage_stopped = False
            self._mapping_dirty = bool(self.copies)
            self.last_result = "waiting"
            self.live = {"downloading": 0, "watch_error": False, "scan_limited": False, "capacity_reached": False}
            self.start_ticks = process_identity(os.getpid())[1] if sys.platform == "linux" else "test"
            self._download_directory()
            self._write_report()
        except BaseException:
            self.close()
            raise

    def _download_directory(self):
        # The user-facing watch list is fixed. No command-line path accepts user
        # input and no recursive search or host filesystem transport is used.
        root = self.home / "Downloads"
        try:
            root.mkdir(mode=0o700)
        except FileExistsError:
            pass
        with self._directory_fd("Downloads") as fd:
            try:
                os.mkdir("Telegram Desktop", mode=0o700, dir_fd=fd)
            except FileExistsError:
                pass

    def close(self):
        if getattr(self, "lock_fd", None) is not None:
            os.close(self.lock_fd)
            self.lock_fd = None

    def _load_history(self):
        self.copies = {}
        path = self.state_dir / "history.json"
        try:
            saved = read_private_json(path, os.getuid(), MAX_STATE)
        except FileNotFoundError:
            return {}
        if not isinstance(saved, dict) or saved.get("version") != 1 or not isinstance(saved.get("entries"), dict):
            raise SafetyError("invalid history")
        entries = saved["entries"]
        copies = saved.get("copies", {})
        if (not isinstance(copies, dict) or len(copies) > MAX_COPIES
                or any(not isinstance(name, str) or Path(name).name != name or not name.startswith("file-")
                       or not isinstance(source, str) or source not in entries for name, source in copies.items())):
            raise SafetyError("invalid copy mappings")
        self.copies = copies
        if len(entries) > MAX_ENTRIES:
            raise SafetyError("history capacity")
        for key, value in entries.items():
            parts = key.split("/")
            if (len(parts) not in (2, 3) or "/".join(parts[:-1]) not in WATCHES
                    or parts[-1] in ("", ".", "..") or not isinstance(value, dict)
                    or value.get("status") not in {"pending", "cleaned", "failed", "unsupported"}
                    or not isinstance(value.get("signature"), list) or len(value["signature"]) != 8
                    or any(type(x) is not int for x in value["signature"])):
                raise SafetyError("invalid history entry")
            output = value.get("output")
            if output is not None and (not isinstance(output, str) or Path(output).name != output
                                       or not output.startswith("file-")):
                raise SafetyError("invalid output mapping")
            value["stable_since"] = self.clock()
        return entries

    def _directory_fd(self, relative):
        # Holding parent fds prevents a rename/symlink swap of Downloads or its
        # Telegram directory from making the cleaner traverse an arbitrary path.
        class Directory:
            def __enter__(nested):
                nested.fds = []
                try:
                    fd = os.open(self.home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    nested.fds.append(fd)
                    for part in relative.split("/"):
                        fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                        nested.fds.append(fd)
                        info = os.fstat(fd)
                        if info.st_uid != os.getuid() or info.st_mode & 0o022:
                            raise SafetyError("unsafe download directory")
                    return fd
                except BaseException:
                    nested.__exit__(None, None, None)
                    raise

            def __exit__(nested, *_):
                for fd in reversed(nested.fds):
                    os.close(fd)
        return Directory()

    def report(self):
        report = {key: 0 for key in COUNTS}
        for entry in self.entries.values():
            report[entry["status"]] += 1
        report.update(self.live)
        report["last_result"] = self.last_result
        return report

    def _write_report(self):
        report = self.report()
        report.update(version=1, pid=os.getpid(), uid=os.getuid(), start_ticks=self.start_ticks,
                      updated_unix=time.time())
        atomic_private_json(self.state_dir / "report.json", report)

    def _copy_list_bytes(self, copies=None):
        lines = ["Соответствия оригиналов и проверенных копий OnionDesk.",
                 "Оригиналы сохранены. Для отправки выбирайте указанную копию.",
                 "Этот локальный список содержит исходные имена; не отправляйте его.", ""]
        for name, source in (self.copies if copies is None else copies).items():
            # ASCII JSON escaping is reversible even for Linux surrogate-escaped
            # byte names; control characters cannot insert fake mapping rows.
            lines.append(json.dumps(source, ensure_ascii=True) + " → " + name)
        return ("\n".join(lines) + "\n").encode("utf-8")

    def _write_copy_list(self):
        # Original filenames stay outside the folder users may share wholesale.
        atomic_private_write(self.state_dir / "Соответствия файлов.txt", self._copy_list_bytes())

    def _history_bytes(self, *, entries=None, copies=None):
        saved = {key: {k: v for k, v in value.items() if k != "stable_since"}
                 for key, value in (self.entries if entries is None else entries).items()}
        return encoded_json({"version": 1, "entries": saved,
                             "copies": self.copies if copies is None else copies})

    def _can_complete(self, key, entry):
        # The engine always publishes file-<24 hex>.<supported extension>. Budget
        # the complete prospective durable success BEFORE starting its parser.
        suffix = Path(key).suffix.lower()
        suffix = ".jpg" if suffix == ".jpeg" else suffix
        name = "file-" + secrets.token_hex(12) + suffix
        while name in self.copies:
            name = "file-" + secrets.token_hex(12) + suffix
        entries = dict(self.entries)
        entries[key] = {**entry, "status": "cleaned", "output": name}
        copies = {**self.copies, name: key}
        return (len(self._history_bytes(entries=entries, copies=copies)) <= MAX_STATE
                and len(self._copy_list_bytes(copies)) <= MAX_STATE)

    def _save_history(self):
        if self._history_dirty:
            atomic_private_write(self.state_dir / "history.json", self._history_bytes())
            self._history_dirty = False

    def _save(self):
        self._save_history()
        if self._mapping_dirty:
            try:
                self._write_copy_list()
                self._mapping_dirty = False
            except (OSError, SafetyError):
                # A committed, verified output remains tracked even if this
                # secondary private display cannot be refreshed (e.g. disk full).
                self.live["watch_error"] = True
        self._write_report()

    def _discard_output(self, output, identity):
        # Roll back ONLY this attempt's newly created inode. Never remove another
        # file that replaced its path or any previously tracked verified copy.
        if output is None or identity is None:
            return
        try:
            info = output.lstat()
        except FileNotFoundError:
            return
        if (output.parent != self.home / "OnionDesk-Clean" or output.name in self.copies
                or (info.st_dev, info.st_ino) != identity or info.st_uid != os.getuid()
                or not stat.S_ISREG(info.st_mode)):
            raise SafetyError("output rollback identity mismatch")
        output.unlink()

    def _observe(self, key, info):
        observed = signature(info)
        previous = self.entries.get(key)
        if previous and previous["signature"] == observed:
            return previous
        if not previous and len(self.entries) >= MAX_ENTRIES:
            self.live["capacity_reached"] = True
            return None
        suffix = Path(key).suffix.lower()
        if suffix not in self.engine.TYPES:
            status = "unsupported"
        elif (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
              or not 0 < info.st_size <= self.engine.MAX_INPUT):
            status = "failed"
        else:
            status = "pending"
        entry = {"signature": observed, "status": status, "stable_since": self.clock()}
        self.entries[key] = entry
        if len(self._history_bytes()) > MAX_STATE:
            if previous is None:
                del self.entries[key]
            else:
                self.entries[key] = previous
            self._capacity_stopped = True
            self.live["capacity_reached"] = True
            return None
        self._history_dirty = True
        if status != "pending":
            self.last_result = status
        return entry

    def scan(self):
        self.live = {"downloading": 0, "watch_error": self._storage_stopped, "scan_limited": False,
                     "capacity_reached": self._capacity_stopped}
        handled = False
        for relative in WATCHES:
            try:
                with self._directory_fd(relative) as directory_fd, os.scandir(directory_fd) as listing:
                    seen = set()
                    complete = True
                    for index, item in enumerate(listing):
                        if index >= MAX_SCAN:
                            self.live["scan_limited"] = True
                            complete = False
                            break
                        info = item.stat(follow_symlinks=False)
                        # Ordinary child directories are outside the fixed scope.
                        if stat.S_ISDIR(info.st_mode):
                            continue
                        if item.name.lower().endswith(TEMP_SUFFIXES):
                            self.live["downloading"] = min(MAX_COUNT, self.live["downloading"] + 1)
                            continue
                        key = relative + "/" + item.name
                        seen.add(key)
                        entry = self._observe(key, info)
                        if (entry is None or entry["status"] != "pending" or handled
                                or self.clock() - entry["stable_since"] < STABLE_SECONDS):
                            continue
                        if self._storage_stopped or self._capacity_stopped:
                            continue
                        if len(self.copies) >= MAX_COPIES or not self._can_complete(key, entry):
                            self._capacity_stopped = True
                            self.live["capacity_reached"] = True
                            continue
                        handled = True  # At most one bounded mat2 worker per pass.
                        # Persist a fail-closed checkpoint before parsing. If the
                        # final success commit fails or the process dies, restart
                        # will not repeat this unchanged signature indefinitely.
                        entry["status"] = "failed"
                        checkpoint = dict(entry)
                        self._history_dirty = True
                        try:
                            self._save_history()
                        except (OSError, SafetyError):
                            self._storage_stopped = True
                            self.live["watch_error"] = True
                            continue
                        entry["status"] = "processing"
                        self.last_result = "processing"
                        output, identity = None, None
                        report_written = False
                        try:
                            self._write_report()
                            report_written = True
                            output = self.engine.clean_file(Path(item.name), self.home, source_dir_fd=directory_fd)
                            output_info = output.lstat()
                            if (output.parent != self.home / "OnionDesk-Clean" or output.name in self.copies
                                    or output_info.st_uid != os.getuid() or not stat.S_ISREG(output_info.st_mode)):
                                raise SafetyError("unexpected output")
                            identity = (output_info.st_dev, output_info.st_ino)
                            after = os.stat(item.name, dir_fd=directory_fd, follow_symlinks=False)
                            if signature(after) != checkpoint["signature"]:
                                self._discard_output(output, identity)
                                output, identity = None, None
                                entry.clear()
                                entry.update(checkpoint)
                                self._observe(key, after)
                                self.last_result = "changed"
                                self._save_history()
                            else:
                                entry.update(status="cleaned", output=output.name)
                                self.copies[output.name] = key
                                self._history_dirty = True
                                try:
                                    self._save_history()
                                except BaseException:
                                    # The output is not a committed success yet.
                                    del self.copies[output.name]
                                    raise
                                # The durable source-to-copy mapping now exists.
                                # A later report/display write cannot invalidate it.
                                output, identity = None, None
                                self._mapping_dirty = True
                                self.last_result = "cleaned"
                        except BaseException as failure:
                            if not report_written:
                                self._storage_stopped = True
                                self.live["watch_error"] = True
                            # Restore fail-closed state before any cleanup that
                            # could itself encounter an I/O/permission failure.
                            # Exception text may contain metadata; never log it.
                            entry.clear()
                            entry.update(checkpoint)
                            self.entries[key] = entry
                            self._history_dirty = True
                            self.last_result = "failed"
                            try:
                                self._discard_output(output, identity)
                            except (OSError, SafetyError):
                                self._storage_stopped = True
                                self.live["watch_error"] = True
                            try:
                                self._save_history()
                            except (OSError, SafetyError):
                                self._storage_stopped = True
                                self.live["watch_error"] = True
                            if not isinstance(failure, Exception):
                                raise
                        self._save()
                    if complete:
                        for key, entry in self.entries.items():
                            if (str(Path(key).parent) == relative and key not in seen
                                    and entry["status"] == "pending"):
                                entry["status"] = "failed"
                                self._history_dirty = True
                                self.last_result = "failed"
            except (OSError, SafetyError):
                self.live["watch_error"] = True
        self._save()


def load_engine():
    location = Path(__file__).with_name("clean-files.py")
    if not location.is_file():
        location = Path(__file__).with_name("guest-clean-files.py")
    spec = importlib.util.spec_from_file_location("oniondesk_metadata_engine", location)
    engine = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(engine)
    return engine


def main():
    os.umask(0o077)
    if sys.argv[1:] != ["--watch"]:
        return 2
    account = pwd.getpwuid(os.getuid())
    parameters = Path("/proc/cmdline").read_text().split()
    roles = [value for value in parameters if value.startswith("boot-role=")]
    if (os.geteuid() == 0 or account.pw_name != "user" or roles not in ([], ["boot-role=user"])
            or "systemd.unit=sysmaint-boot.target" in parameters or any("remove-sysmaint" in x for x in parameters)):
        return 1
    stop = False

    def stopping(*_):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGTERM, stopping)
    signal.signal(signal.SIGINT, stopping)
    watcher = Watcher(Path(account.pw_dir), load_engine())
    try:
        while not stop:
            watcher.scan()
            for _ in range(POLL_SECONDS * 5):
                if stop:
                    break
                time.sleep(0.2)
    finally:
        watcher.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        # systemd receives a failure code; no private data enters the journal.
        raise SystemExit(1)
