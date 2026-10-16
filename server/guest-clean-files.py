#!/usr/bin/python3
"""Create checked metadata-cleaned copies in the Workstation user session.

Debian 13 mat2 0.13.5 API: parser_factory.get_parser -> (parser, MIME),
remove_all -> bool, output_filename, get_meta -> dict. Parsing runs only in a
bounded child, including its initial format checks and final metadata check.
This is metadata removal, not a content anonymiser or a malware sandbox.
"""

from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import resource
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
from urllib.parse import unquote
import xml.etree.ElementTree as ET
import zipfile

MAX_INPUT = 50 * 1024 * 1024
MAX_OUTPUT = 100 * 1024 * 1024
MAX_MEMBERS = 1000
WORKER_TIMEOUT = 70
NEUTRAL_TIME = 946684800  # 2000-01-01, never copied from the original.
TYPES = {
    ".jpg": ("image/jpeg", b"\xff\xd8\xff"),
    ".jpeg": ("image/jpeg", b"\xff\xd8\xff"),
    ".png": ("image/png", b"\x89PNG\r\n\x1a\n"),
    ".pdf": ("application/pdf", b"%PDF-"),
    ".docx": (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        b"PK\x03\x04",
    ),
}
NESTED_SUFFIXES = {
    ".zip", ".tar", ".tgz", ".tbz", ".tbz2", ".txz", ".gz", ".bz2", ".xz",
    ".7z", ".rar", ".epub", ".doc", ".xls", ".ppt", ".docx", ".xlsx", ".pptx",
    ".docm", ".xlsm", ".pptm", ".odt", ".ods", ".odp", ".bin",
}
LIMITATION = (
    "Удалены стандартные метаданные, которые поддерживает mat2; повторная проверка пройдена. "
    "Это не гарантия отсутствия всех скрытых данных. Имена и лица в содержимом, водяные знаки, "
    "учётные записи и следы в системе не очищаются. PDF станет изображением страниц; "
    "качество и функции документов могут измениться. Оригинал сохранён. "
    "Проверьте копию перед отправкой и выбирайте для отправки именно её."
)


class CleaningError(Exception):
    """An unsuccessful cleaning never publishes an output file."""


def _regular_info(path: Path, maximum: int, *, dir_fd: int | None = None) -> os.stat_result:
    info = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
            or not 0 < info.st_size <= maximum):
        raise CleaningError("Нужен обычный непустой файл допустимого размера (до 50 МиБ).")
    return info


def _copy_source(source: Path, destination: Path, *, source_dir_fd: int | None = None) -> None:
    # O_NONBLOCK prevents a swapped FIFO/device from blocking before fstat.
    before = _regular_info(source, MAX_INPUT, dir_fd=source_dir_fd)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    noatime = getattr(os, "O_NOATIME", 0) if before.st_uid == os.getuid() else 0
    fd = os.open(source, flags | noatime, dir_fd=source_dir_fd)
    with os.fdopen(fd, "rb") as incoming:
        opened = os.fstat(incoming.fileno())
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.getuid() or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
            raise CleaningError("Файл изменился во время выбора; выберите его заново.")
        with destination.open("xb") as outgoing:
            total = 0
            while chunk := incoming.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_INPUT:
                    raise CleaningError("Файл превышает предел 50 МиБ.")
                outgoing.write(chunk)
        after = os.fstat(incoming.fileno())
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns, opened.st_nlink) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_nlink):
            raise CleaningError("Файл изменился во время копирования; повторите выбор.")


def _check_docx(path: Path) -> None:
    # Bound expansion before libmat2 extracts this ZIP-based format.
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        names = [member.filename for member in members]
        if len(members) > MAX_MEMBERS or len(set(names)) != len(names):
            raise CleaningError("DOCX содержит слишком много или повторяющиеся части.")
        if not {"[Content_Types].xml", "word/document.xml"}.issubset(names):
            raise CleaningError("Файл не является поддерживаемым DOCX.")
        if sum(member.file_size for member in members) > MAX_OUTPUT:
            raise CleaningError("Распакованный DOCX превышает предел 100 МиБ.")
        for member in members:
            name = PurePosixPath(member.filename)
            mode = member.external_attr >> 16
            if (member.flag_bits & 1 or name.is_absolute() or ".." in name.parts
                    or "\\" in member.filename or stat.S_ISLNK(mode)
                    or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR))):
                raise CleaningError("Зашифрованный DOCX или небезопасные части не поддерживаются.")
            lower_name = name.as_posix().casefold()
            if (lower_name == "word/embeddings" or lower_name.startswith("word/embeddings/")
                    or name.suffix.casefold() in NESTED_SUFFIXES):
                raise CleaningError("DOCX с вложенными документами, архивами или объектами не поддерживается.")
            if not member.is_dir():
                # No recursive archive parser may receive a nested container.
                # is_zipfile also detects ZIPs with a prepended image/SFX header;
                # it reads only this bounded outer member, never nested contents.
                with archive.open(member) as part:
                    header = part.read(8)
                    if (header.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08",
                                           b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", b"\x1f\x8b",
                                           b"BZh", b"\xfd7zXZ\x00", b"7z\xbc\xaf\x27\x1c", b"Rar!"))
                            or zipfile.is_zipfile(part)):
                        raise CleaningError("DOCX с вложенными документами, архивами или объектами не поддерживается.")
            if member.filename.endswith(".rels"):
                for relation in ET.fromstring(archive.read(member)):
                    if relation.get("Type", "").casefold().rsplit("/", 1)[-1] in {"oleobject", "package"}:
                        raise CleaningError("DOCX с вложенными документами, архивами или объектами не поддерживается.")
                    if relation.get("TargetMode") == "External":
                        raise CleaningError("DOCX с внешними ссылками не поддерживается; сохраните локальную версию без них.")
                    target = _docx_target(member.filename, relation.get("Target", ""))
                    if target not in names:
                        raise CleaningError("DOCX содержит ссылку на отсутствующую часть.")


def _docx_target(relation_name: str, target: str) -> str:
    target = unquote(target.partition("#")[0])
    base = posixpath.dirname(posixpath.dirname(relation_name))
    result = posixpath.normpath(target.lstrip("/") if target.startswith("/") else posixpath.join(base, target))
    if not target or result.startswith("../") or result == ".." or "\\" in result:
        raise CleaningError("DOCX содержит небезопасную ссылку.")
    return result


def _repair_docx_relationships(path: Path) -> None:
    # Debian mat2 0.13.5 misses ../customXml targets when pruning relations.
    # Remove only references to parts already deleted by upstream cleaning.
    replacement = path.with_name("repaired.docx")
    with zipfile.ZipFile(path) as incoming, zipfile.ZipFile(replacement, "w") as outgoing:
        names = set(incoming.namelist())
        for member in incoming.infolist():
            data = incoming.read(member)
            if member.filename.endswith(".rels") or member.filename == "[Content_Types].xml":
                tree = ET.fromstring(data)
                changed = False
                for item in list(tree):
                    if member.filename.endswith(".rels"):
                        target = _docx_target(member.filename, item.get("Target", ""))
                    elif "PartName" in item.attrib:
                        target = unquote(item.attrib["PartName"].lstrip("/"))
                    else:
                        continue
                    if target not in names:
                        tree.remove(item)
                        changed = True
                if changed:
                    data = ET.tostring(tree, encoding="utf-8", xml_declaration=True)
            outgoing.writestr(member, data)
    replacement.replace(path)


def _check_format(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix not in TYPES:
        raise CleaningError("Поддерживаются только JPEG, PNG, PDF и DOCX до 50 МиБ.")
    with path.open("rb") as stream:
        if not stream.read(8).startswith(TYPES[suffix][1]):
            raise CleaningError("Содержимое файла не соответствует его формату.")
    if suffix == ".docx":
        _check_docx(path)
    return TYPES[suffix][0]


def _verify_meta(metadata: dict, mime: str) -> None:
    remaining = dict(metadata)
    if mime == "application/pdf":
        # mat2/Poppler returns format plus -1 for explicitly removed dates.
        # All other fields, dates and versions must still fail closed.
        for key, expected in (("format", "PDF-1.5"), ("creation-date", -1), ("mod-date", -1)):
            if remaining.get(key) == expected:
                del remaining[key]
    if remaining:
        raise CleaningError("Проверка обнаружила оставшиеся метаданные; копия не сохранена.")


def _worker(path: Path) -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (45, 45))
    resource.setrlimit(resource.RLIMIT_AS, (1024 ** 3, 1024 ** 3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT, MAX_OUTPUT))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_NPROC, (256, 256))
    _regular_info(path, MAX_INPUT)
    expected_mime = _check_format(path)
    from libmat2 import parser_factory

    parser, mime = parser_factory.get_parser(str(path))
    if parser is None or mime != expected_mime:
        raise CleaningError("mat2 не подтвердил поддержку формата.")
    # Keep upstream thorough cleaning, sandbox and unknown-member ABORT defaults.
    if parser.remove_all() is not True:
        raise CleaningError("mat2 не завершил очистку; копия не сохранена.")
    output = Path(parser.output_filename)
    _regular_info(output, MAX_OUTPUT)
    if path.suffix == ".docx":
        _repair_docx_relationships(output)
    _check_format(output)
    verifier, checked_mime = parser_factory.get_parser(str(output))
    if verifier is None or checked_mime != expected_mime:
        raise CleaningError("Не удалось заново открыть очищенную копию.")
    _verify_meta(verifier.get_meta(), checked_mime)
    print(json.dumps({"output": output.name}))


def _run_worker(staged: Path, timeout: int = WORKER_TIMEOUT) -> Path:
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8",
                   "HOME": str(staged.parent), "TMPDIR": str(staged.parent)}
    # No unbounded stdout/stderr pipe: parser output is limited on disk by RLIMIT_FSIZE.
    with tempfile.TemporaryFile(dir=staged.parent) as stdout, tempfile.TemporaryFile(dir=staged.parent) as stderr:
        process = subprocess.Popen(
            [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--worker", str(staged)],
            cwd=staged.parent, env=environment, stdout=stdout, stderr=stderr, start_new_session=True,
        )
        try:
            status = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise CleaningError("Очистка превысила лимит времени; копия не сохранена.") from error
        finally:
            # Also end any external parser descendants left after an error or timeout.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        if status != 0:
            raise CleaningError("Очистка или проверка mat2 не удалась. Копия не сохранена; оригинал доступен.")
        stdout.seek(0)
        try:
            result = json.loads(stdout.read(4096))
            name = result["output"]
            if name != staged.stem + ".cleaned" + staged.suffix:
                raise ValueError
        except (ValueError, KeyError, TypeError) as error:
            raise CleaningError("Очистка не вернула подтверждённый результат.") from error
    return staged.parent / name


def clean_file(source: Path, home: Path | None = None, *, source_dir_fd: int | None = None) -> Path:
    source = Path(source)
    if source_dir_fd is None:
        source = Path(os.path.abspath(source))
    elif source.name != str(source) or source.name in ("", ".", ".."):
        raise CleaningError("Небезопасное имя входного файла.")
    if source.suffix.lower() not in TYPES:
        raise CleaningError("Поддерживаются только JPEG, PNG, PDF и DOCX до 50 МиБ.")
    _regular_info(source, MAX_INPUT, dir_fd=source_dir_fd)
    home = (home or Path.home()).resolve(strict=True)
    output_dir = home / "OnionDesk-Clean"
    try:
        output_dir.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = output_dir.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise CleaningError("Папка OnionDesk-Clean должна быть личной папкой владельца с правами 700.")
    # Raw staging must never appear beside copies a person may select to send.
    processing_root = home / ".oniondesk-processing"
    try:
        processing_root.mkdir(mode=0o700)
    except FileExistsError:
        pass
    processing_info = processing_root.lstat()
    if (not stat.S_ISDIR(processing_info.st_mode) or processing_info.st_uid != os.getuid()
            or stat.S_IMODE(processing_info.st_mode) != 0o700):
        raise CleaningError("Не удалось открыть личную временную папку обработки.")
    with tempfile.TemporaryDirectory(prefix=".processing-", dir=processing_root) as temporary:
        staged = Path(temporary) / ("input" + source.suffix.lower())
        _copy_source(source, staged, source_dir_fd=source_dir_fd)
        cleaned = _run_worker(staged)
        _regular_info(cleaned, MAX_OUTPUT)
        output = output_dir / ("file-" + secrets.token_hex(12) + (".jpg" if source.suffix.lower() == ".jpeg" else source.suffix.lower()))
        try:
            # Exclusive creation also avoids overwriting any previous clean file.
            with cleaned.open("rb") as incoming, output.open("xb") as outgoing:
                os.fchmod(outgoing.fileno(), 0o600)
                while chunk := incoming.read(1024 * 1024):
                    outgoing.write(chunk)
                outgoing.flush()
                os.fsync(outgoing.fileno())
            os.utime(output, (NEUTRAL_TIME, NEUTRAL_TIME), follow_symlinks=False)
        except BaseException:
            output.unlink(missing_ok=True)
            raise
    return output


def _dialog(kind: str, text: str) -> None:
    subprocess.run(["/usr/bin/zenity", kind, "--no-markup", "--title=Очистить данные файла",
                    "--width=560", "--text=" + text], check=False)


def main() -> int:
    os.umask(0o077)
    if os.geteuid() == 0:
        print("Запускайте очистку из обычной USER session без sudo.", file=sys.stderr)
        return 1
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        try:
            _worker(Path(sys.argv[2]))
            return 0
        except Exception:
            # Parser errors can contain original metadata; never persist/display them.
            return 1
    if len(sys.argv) != 1:
        return 2
    try:
        selected = subprocess.run(
            ["/usr/bin/zenity", "--file-selection", "--title=Выберите JPEG, PNG, PDF или DOCX",
             "--file-filter=Поддерживаемые файлы | *.jpg *.jpeg *.png *.pdf *.docx"],
            capture_output=True, check=False,
        )
        if selected.returncode == 1:
            return 0
        if selected.returncode != 0:
            raise CleaningError("Не удалось открыть выбор файла.")
        output = clean_file(Path(os.fsdecode(selected.stdout.removesuffix(b"\n"))))
        _dialog("--info", "Готовая копия: " + str(output) + "\n\n" + LIMITATION)
        return 0
    except (CleaningError, OSError) as error:
        message = str(error) if isinstance(error, CleaningError) else "Не удалось прочитать файл или записать копию."
        _dialog("--error", message)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
