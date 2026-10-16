"""Prepare only the official pinned wallet RPC from the local distribution.

No downloads, arbitrary archives, user supplied executable paths, daemon or
mining executables are supported. Source filesystem and GPG discovery reuse the
launcher boundaries; Monero assets have their own compiled catalog.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
import platform
import secrets
import shutil
import stat
import subprocess
import tarfile
import tempfile
import threading
import zipfile

import offline_bundle as offline
import usb_tails as usb
import wallet_catalog as catalog
from wallet_engine import (Network, OfflineWalletEngine, WalletError,
                           _private_directory, _private_file, default_wallet_root)

_PREPARE_LOCK = threading.Lock()
_MAX_MEMBERS = 128
_MAX_UNCOMPRESSED = 600 * 1024**2


def _platform_key():
    system, machine = platform.system(), platform.machine().lower()
    if system == "Darwin" and machine in {"arm64", "aarch64"}:
        return "macos-arm64"
    if system == "Windows" and machine in {"amd64", "x86_64"}:
        return "windows-x64"
    if system == "Linux" and machine in {"amd64", "x86_64"}:
        return "linux-x64"
    if system == "Linux" and machine in {"arm64", "aarch64"}:
        return "linux-arm64"
    raise WalletError("В комплекте нет Monero RPC для этой системы.")


def status():
    try:
        key = _platform_key()
        root = offline._find_root()
        available = root is not None and all((root / item["path"]).is_file()
                                             for item in (catalog.HASHES, catalog.KEY, catalog.PLATFORMS[key]))
        return {"available": available, "version": catalog.VERSION,
                "message": "Официальный Monero RPC есть в комплекте." if available else "Файлы Monero не найдены. Нужен полный комплект."}
    except (OSError, WalletError):
        return {"available": False, "version": catalog.VERSION, "message": "Monero RPC недоступен для этой системы."}


def _cache_root():
    return default_wallet_root().parent / "monero-rpc"


def _copy_asset(root, record, target):
    copied, digest = 0, hashlib.sha256()
    try:
        with offline._open_regular(root, record["path"], record["size_bytes"]) as source:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as output:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    copied += len(chunk)
                    if copied > record["size_bytes"]:
                        raise WalletError("Размер файла Monero изменился во время проверки.")
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
        if copied != record["size_bytes"] or not secrets.compare_digest(digest.hexdigest(), record["sha256"]):
            raise WalletError("Контрольная сумма файла Monero не совпала. Запуск запрещён.")
    except (OSError, offline.OfflineError):
        raise WalletError("Файлы Monero повреждены или недоступны. Распакуйте полный комплект заново.") from None


def _valid_signature(output):
    rows = [line.split()[1:] for line in output.splitlines() if line.startswith("[GNUPG:] ")]
    rejected = {"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY", "NODATA", "FAILURE"}
    signatures = [row[1:] for row in rows if row and row[0] == "VALIDSIG"]
    return (not any(row and row[0] in rejected for row in rows)
            and any(row and row[0] == "GOODSIG" for row in rows)
            and len(signatures) == 1 and len(signatures[0]) >= 10
            and signatures[0][9] == catalog.PUBLISHER_FINGERPRINT
            and signatures[0][7] in {"8", "9", "10", "11"})


def _verify_hashes(hashes, key, record):
    gpg = usb._find_gpg()
    if not gpg:
        raise WalletError("Нет GnuPG для проверки подписи Monero. Нужен полный комплект.")
    short = None if os.name == "nt" else ("/private/tmp" if platform.system() == "Darwin" else "/tmp")
    with tempfile.TemporaryDirectory(prefix="monero-gpg-", dir=short) as home:
        os.chmod(home, 0o700)
        base = [gpg, "--no-options", "--homedir", home, "--batch", "--no-tty", "--no-autostart",
                "--no-auto-key-retrieve", "--auto-key-locate", "clear"]

        def execute(arguments):
            try:
                return subprocess.run(base + arguments, capture_output=True, timeout=45, check=False)
            except (OSError, subprocess.TimeoutExpired):
                raise WalletError("Не удалось проверить подпись Monero. Запуск запрещён.") from None

        shown = execute(["--with-colons", "--import-options", "show-only", "--import", str(key)])
        primary, waiting = [], False
        for line in shown.stdout.decode("utf-8", "replace").splitlines():
            fields = line.split(":")
            if fields[0] == "pub":
                waiting = True
            elif fields[0] == "fpr" and waiting and len(fields) > 9:
                primary.append(fields[9])
                waiting = False
        if shown.returncode or primary != [catalog.PUBLISHER_FINGERPRINT]:
            raise WalletError("Ключ Monero не совпал с закреплённым ключом binaryFate.")
        if execute(["--import", str(key)]).returncode:
            raise WalletError("Не удалось прочитать ключ Monero.")
        checked = execute(["--status-fd", "1", "--verify", str(hashes)])
        if checked.returncode or not _valid_signature(checked.stdout.decode("utf-8", "replace")):
            raise WalletError("Подпись списка SHA-256 Monero не прошла проверку.")
    expected = f"{record['sha256']}  {PurePosixPath(record['path']).name}"
    if hashes.read_text(encoding="ascii").splitlines().count(expected) != 1:
        raise WalletError("Подписанный список не содержит ожидаемый архив Monero.")


def _extract_rpc(archive_path, record, target):
    """Read exactly one fixed regular member; never unpack archive paths."""
    try:
        expected = record["rpc_member"]
        if PurePosixPath(expected).is_absolute() or ".." in PurePosixPath(expected).parts:
            raise WalletError("Недопустимый путь Monero RPC в каталоге.")
        if archive_path.suffix == ".zip":
            with zipfile.ZipFile(archive_path) as archive:
                members = archive.infolist()
                matches = [item for item in members if item.filename == expected]
                if len(members) > _MAX_MEMBERS or sum(item.file_size for item in members) > _MAX_UNCOMPRESSED or len(matches) != 1:
                    raise WalletError("Неожиданная структура архива Monero.")
                item = matches[0]
                kind = stat.S_IFMT(item.external_attr >> 16)
                if item.is_dir() or kind not in (0, stat.S_IFREG) or item.file_size != record["rpc_bytes"]:
                    raise WalletError("Неверный тип или размер Monero RPC.")
                with archive.open(item) as source:
                    _write_rpc(source, record, target)
        else:
            with tarfile.open(archive_path, "r:bz2") as archive:
                matches, count, total = [], 0, 0
                for item in archive:
                    count += 1
                    total += item.size
                    if count > _MAX_MEMBERS or total > _MAX_UNCOMPRESSED:
                        raise WalletError("Архив Monero превышает разрешённые пределы.")
                    if item.name == expected:
                        matches.append(item)
                if len(matches) != 1 or not matches[0].isfile() or matches[0].size != record["rpc_bytes"]:
                    raise WalletError("В архиве нет единственного ожидаемого Monero RPC.")
                with archive.extractfile(matches[0]) as source:
                    _write_rpc(source, record, target)
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile, RuntimeError):
        raise WalletError("Не удалось безопасно прочитать архив Monero.") from None


def _write_rpc(source, record, target):
    copied, digest = 0, hashlib.sha256()
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            copied += len(chunk)
            if copied > record["rpc_bytes"]:
                raise WalletError("Размер Monero RPC превышен.")
            digest.update(chunk)
            output.write(chunk)
        output.flush()
        os.fsync(output.fileno())
    if copied != record["rpc_bytes"] or not secrets.compare_digest(digest.hexdigest(), record["rpc_sha256"]):
        raise WalletError("Контрольная сумма Monero RPC не совпала. Запуск запрещён.")
    os.chmod(target, 0o700)


def prepare_engine(*, network=Network.MAINNET, wallet_root=None):
    """UI entry point. Platform, paths, executable and trust pins stay in code."""
    with _PREPARE_LOCK:
        record = catalog.PLATFORMS[_platform_key()]
        root = offline._find_root()
        if root is None:
            raise WalletError("Файлы Monero не найдены. Нужен полный комплект.")
        cache = _cache_root()
        _private_directory(cache)
        install = cache / (catalog.VERSION + "-" + _platform_key())
        _private_directory(install)
        binary = install / PurePosixPath(record["rpc_member"]).name
        with tempfile.TemporaryDirectory(prefix=".prepare-", dir=cache) as temporary:
            work = Path(temporary)
            files = {}
            for name, item in (("hashes", catalog.HASHES), ("key", catalog.KEY)):
                files[name] = work / PurePosixPath(item["path"]).name
                _copy_asset(root, item, files[name])
            _verify_hashes(files["hashes"], files["key"], record)
            engine = OfflineWalletEngine(binary, record["rpc_sha256"], network=network, wallet_root=wallet_root)
            if binary.exists() or binary.is_symlink():
                _private_file(binary)
                engine._verify_binary()
                return engine
            archive = work / PurePosixPath(record["path"]).name
            _copy_asset(root, record, archive)
            prepared = work / binary.name
            _extract_rpc(archive, record, prepared)
            os.replace(prepared, binary)
            _private_file(binary)
            engine._verify_binary()
            return engine
