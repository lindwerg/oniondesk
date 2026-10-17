#!/usr/bin/env python3
"""Cold native R5 lifecycle on a fresh public GitHub-hosted runner only.

Native app output, browser URLs, process arguments and filesystem state remain
private. Public proof contains fixed-schema facts and cropped owned-window PNGs.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit
import unicodedata
import uuid
import zipfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
EVIDENCE = REPO / "native-r5-evidence"
MAX_EVIDENCE = 8 * 1024 * 1024
EVIDENCE_NAMES = {"status.json", "cleanup.json", "native-prepare.png",
                  "native-installer.png", "core-first-action.png", "arm-gate.png", "browser-diagnostic.cms"}
BOOL_FIELDS = {"public_github_hosted_runner", "synthetic_profile", "starter_verified", "source_pool_absent",
               "cold_cache", "native_preparation_window_seen", "ready_receipt_verified", "ordinary_installer_completed",
               "ordinary_uninstaller_completed", "core_browser_fallback_seen", "headed_ui", "first_device_action_completed",
               "browser_sandbox_enabled", "unsupported_arm_tor_browser_gate_respected", "ui_quit_completed",
               "sandbox_renderer_flags_checked", "linux_renderer_seccomp_enabled",
               "tooling_mount_nosuid", "sandbox_helper_mount_nosuid", "linux_sandbox_diagnostics_positive",
               "system_chrome_exists", "system_chrome_symlink", "system_chrome_regular", "system_chrome_root_owned",
               "system_chrome_group_writable", "system_chrome_other_writable", "browser_diagnostic_encrypted",
               "system_chrome_permissions_hardened", "browser_architecture_matches",
               "native_launcher_alive", "probe_source_verified", "probe_exact_go_version", "probe_unsafe_error",
               "probe_download_progress_seen", "probe_deadline_reached", "probe_restore_lock_exists",
               "token_owner_equals_user", "token_owner_is_admin", "token_elevated", "cache_owner_is_user",
               "cache_owner_is_admin", "cache_dacl_protected", "manifest_child_exists", "manifest_child_owner_is_user",
               "manifest_child_owner_is_admin", "manifest_child_dacl_protected", "probe_diagnostic_complete",
               "cache_exists",
               "core_listener_closed", "owned_resources_only", "exact_process_identities_only", "owned_processes_stopped",
               "private_cache_and_profile_removed"}
COUNT_FIELDS = {"restored_files_verified", "online_blobs_verified", "online_parts_verified"}
BROWSER_FAILURE_REASONS = {"display_unavailable", "sandbox_helper_misconfigured", "sandbox_unavailable",
                           "user_namespace_rejected", "shared_library_missing", "executable_missing",
                           "permission_denied", "socket_path_too_long", "sandbox_diagnostics_failed", "unclassified_browser_launch_failure"}
PHASES = {"initialize", "download_release_asset", "headed_sandboxed_browser", "native_cold_download_and_restore",
          "independent_restore_verification", "ordinary_nsis_install", "ordinary_nsis_uninstall", "core_first_action",
          "core_ui_quit", "complete", "browser_sandbox_diagnostics", "browser_attestation", "browser_launch", "browser_sandbox_check",
          "windows_cache_diagnostic"}
NATIVE_ERRORS = {
    "Пакет установки ещё не готов. Получите готовый пакет OnionDesk у издателя.": "not_configured",
    "Недостаточно места на системном диске. Освободите место и повторите подготовку.": "space",
    "Файлы не прошли проверку целостности. Повторите подготовку или получите новый пакет.": "integrity",
    "Не удалось безопасно подготовить файлы. Проверьте доступ к пользовательскому кэшу и повторите попытку.": "unsafe_cache",
    "Не удалось подготовить установку. Повторите попытку. Если ошибка сохранится, получите новый пакет.": "preparation_failed",
}
PINS = json.loads((HERE / "pins.json").read_text(encoding="utf-8"))
SHA = re.compile(r"[0-9a-f]{64}")
TRUSTED_ERROR_CODES = {
    'BrowserELFArchitectureMismatch',
    'BrowserSandboxDisabled',
    'BrowserTemporaryPathTooLong',
    'CIInterrupted',
    'CheckoutSHAMismatch',
    'ChromiumSandboxHelperRequired',
    'CleanupLinkedWindowsClaim',
    'CleanupMarkerMismatch',
    'CleanupOwnershipMismatch',
    'ColdDownloadRequiresAbsentPool',
    'ColdRestoreIncomplete',
    'ContractDistributionMismatch',
    'ContractPinMismatch',
    'CoreListenerSurvivedQuit',
    'CoreSystemBrowserRequestRequired',
    'DiagnosticDERInvalid',
    'DiagnosticRecipientIdentityInvalid',
    'DiagnosticRecipientPinMismatch',
    'DiagnosticRecipientRSARequired',
    'EncryptedDiagnosticProfileMismatch',
    'EncryptedDiagnosticSizeLimit',
    'ExistingWindowsInstallationOrCache',
    'ExistingWindowsRegistration',
    'ExistingWindowsShortcut',
    'ExpectedRunDistributionOrCleanup',
    'FreshPublicRunnerRequired',
    'InstalledCoreRequired',
    'KnownFolderUnavailable',
    'NativePreparationExitedBeforeReady',
    'NativePreparationTerminalError',
    'NativePreparationWindowNotProven',
    'NativeWindowGeometry',
    'OnlineBlobMismatch',
    'OnlinePartReceiptMismatch',
    'OnlinePoolSetMismatch',
    'OrdinaryNSISIncomplete',
    'OrdinaryUninstallLeftInstallation',
    'OwnedBrowserRendererRequired',
    'OwnedNativeWindowRequired',
    'OwnedProcessCleanupIncomplete',
    'PositiveSandboxDiagnosticsRequired',
    'ProbeExactGoVersionRequired',
    'ProbeExecutionIncomplete',
    'ProbeFrozenSourceMismatch',
    'ProbeSourceArchiveMismatch',
    'ProbeSourceCatalogMismatch',
    'PublicEvidenceBudgetExceeded',
    'PublicEvidenceField',
    'PublicEvidenceSchema',
    'ReadyGenerationCount',
    'ReadyReceiptMismatch',
    'ReleaseAssetPinMismatch',
    'ReleaseAssetPinRequired',
    'ReleaseAssetTooLarge',
    'RendererSeccompRequired',
    'RestoredDirectoryMismatch',
    'RestoredFileMismatch',
    'RestoredLinkMismatch',
    'RestoredModeMismatch',
    'SandboxHelperAlreadyExists',
    'SandboxHelperCleanupIncomplete',
    'SandboxHelperMissing',
    'SandboxHelperMountRejectsSetuid',
    'SandboxOwnershipMismatch',
    'StarterEntryCount',
    'StarterExecutableMismatch',
    'StarterNotExecutable',
    'StateAlreadyExists',
    'SystemChromePermissionsUnsafe',
    'TrustedSystemChromeRequired',
    'UnexpectedCoreBrowserRequest',
    'UnexpectedEvidenceImage',
    'UnexpectedNSISFinish',
    'UnexpectedPublicEvidence',
    'UnexpectedRestoredEntry',
    'UnexpectedZipPermissions',
    'UnsafeBrowserToolingPath',
    'UnsafeSandboxHelperIdentity',
    'UnsafeSandboxHelperPin',
    'UnsafeSandboxOwnershipRecord',
    'UnsafeStatePath',
    'UnsafeZipComponent',
    'UnsafeZipEntry',
    'UnsafeZipName',
    'WindowsDiagnosticRunnerRequired',
    'ZipBudgetExceeded',
    'ZipTypeMismatch',
}
DIAGNOSTIC_CERT_SHA256 = "b023aa189fd017bba34f426e4b9af9fe3b3ebafd4138bec9771b315b3893132b"


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".new")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def safe_member(name):
    """One portable relative name; reject Windows aliases on every platform."""
    if not name or len(name) > 512 or "\\" in name or ":" in name or any(unicodedata.category(c).startswith("C") for c in name):
        raise ValueError("UnsafeZipName")
    value = name.removesuffix("/")
    parts = value.split("/")
    reserved = {"con", "prn", "aux", "nul", *("com" + str(i) for i in range(1, 10)),
                *("lpt" + str(i) for i in range(1, 10))}
    if any(p in {"", ".", ".."} or p.endswith((" ", ".")) or
           p.split(".")[0].casefold() in reserved for p in parts):
        raise ValueError("UnsafeZipComponent")
    return PurePosixPath(value)


def extract_zip(archive, destination):
    """Validate the complete central directory before writing any member."""
    with zipfile.ZipFile(archive) as source:
        members = source.infolist()
        if len(members) > 3000 or sum(item.file_size for item in members) > 160 * 1024 * 1024:
            raise ValueError("ZipBudgetExceeded")
        names = set()
        for item in members:
            relative = safe_member(item.filename)
            name = str(relative).casefold()
            mode = item.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if name in names or kind not in {0, stat.S_IFREG, stat.S_IFDIR} or item.flag_bits & 1:
                raise ValueError("UnsafeZipEntry")
            if bool(kind == stat.S_IFDIR) != item.is_dir() and kind != 0:
                raise ValueError("ZipTypeMismatch")
            if os.name != "nt" and not item.is_dir() and mode & 0o777 not in {0o644, 0o755}:
                raise ValueError("UnexpectedZipPermissions")
            names.add(name)
        for item in members:
            target = destination.joinpath(*safe_member(item.filename).parts)
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
            else:
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with source.open(item) as incoming, target.open("xb") as outgoing:
                    shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
                if os.name != "nt":
                    mode = (item.external_attr >> 16) & 0o777
                    if mode not in {0o644, 0o755}:
                        raise ValueError("UnexpectedZipPermissions")
                    target.chmod(mode)


def verify_contract(distribution):
    pin = PINS["distributions"][distribution]
    path = HERE / "contracts" / (distribution + ".json")
    if digest(path) != pin["manifest_sha256"] or digest(HERE / "contracts/index.json") != PINS["index_sha256"]:
        raise ValueError("ContractPinMismatch")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    index = json.loads((HERE / "contracts/index.json").read_text(encoding="utf-8"))
    if manifest["distribution"] != distribution or index["release"] != PINS["release"]:
        raise ValueError("ContractDistributionMismatch")
    for item in manifest["files"] + manifest["directories"] + manifest["symlinks"]:
        safe_member(item["path"])
    return pin, manifest, index


def verify_payload(payload, manifest):
    for item in manifest["files"]:
        path = payload.joinpath(*safe_member(item["path"]).parts)
        if path.is_symlink() or not path.is_file() or path.stat().st_size != item["bytes"] or digest(path) != item["sha256"]:
            raise ValueError("RestoredFileMismatch")
        if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) != item["mode"]:
            raise ValueError("RestoredModeMismatch")
    for item in manifest["directories"]:
        path = payload.joinpath(*safe_member(item["path"]).parts)
        if path.is_symlink() or not path.is_dir():
            raise ValueError("RestoredDirectoryMismatch")
    for item in manifest["symlinks"]:
        path = payload.joinpath(*safe_member(item["path"]).parts)
        if not path.is_symlink() or os.readlink(path) != item["target"]:
            raise ValueError("RestoredLinkMismatch")
    expected = {item["path"] for group in ("files", "directories", "symlinks") for item in manifest[group]}
    if {p.relative_to(payload).as_posix() for p in payload.rglob("*")} != expected:
        raise ValueError("UnexpectedRestoredEntry")


def seal_evidence():
    EVIDENCE.mkdir(exist_ok=True)
    files = list(EVIDENCE.iterdir())
    if any(p.name not in EVIDENCE_NAMES or p.is_symlink() or not p.is_file() for p in files):
        raise ValueError("UnexpectedPublicEvidence")
    if sum(p.stat().st_size for p in files) > MAX_EVIDENCE:
        raise ValueError("PublicEvidenceBudgetExceeded")
    for path in files:
        if path.suffix == ".json":
            validate_public_json(json.loads(path.read_text(encoding="utf-8")))
        elif path.name == "browser-diagnostic.cms":
            if path.stat().st_size > 128 * 1024:
                raise ValueError("EncryptedDiagnosticSizeLimit")
            validate_encrypted_diagnostic(path.read_bytes())
        else:
            from PIL import Image
            with Image.open(path) as image:
                if image.format != "PNG" or not (0 < image.width <= 1280 and 0 < image.height <= 900):
                    raise ValueError("UnexpectedEvidenceImage")
                image.verify()


def validate_public_json(value):
    if not isinstance(value, dict) or len(value) > 50:
        raise ValueError("PublicEvidenceSchema")
    for key, item in value.items():
        if key in BOOL_FIELDS:
            valid = type(item) is bool
        elif key in COUNT_FIELDS:
            valid = type(item) is int and 0 <= item <= 10000
        elif key in {"asset_sha256", "starter_sha256", "manifest_sha256", "index_sha256"}:
            valid = isinstance(item, str) and bool(SHA.fullmatch(item))
        elif key == "source_commit":
            valid = isinstance(item, str) and bool(re.fullmatch(r"[0-9a-f]{40}", item))
        elif key == "distribution":
            valid = isinstance(item, str) and item in PINS["distributions"]
        elif key == "release":
            valid = item == PINS["release"]
        elif key == "phase":
            valid = isinstance(item, str) and item in PHASES
        elif key == "result":
            valid = item in {"RUNNING", "PASS", "PASS_PREPARATION_UI_ARM_GATE", "FAIL_OR_INCOMPLETE", "WINDOWS_CACHE_DIAGNOSTIC_ONLY"}
        elif key == "error_class":
            valid = isinstance(item, str) and bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,80}", item))
        elif key in {"error_code", "diagnostic_error_code"}:
            valid = isinstance(item, str) and item in TRUSTED_ERROR_CODES
        elif key == "diagnostic_error_class":
            valid = isinstance(item, str) and bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,80}", item))
        elif key == "browser_failure_reason":
            valid = isinstance(item, str) and item in BROWSER_FAILURE_REASONS
        elif key == "browser_failure_signal":
            valid = isinstance(item, str) and item in {"SIGABRT", "SIGTRAP", "SIGSEGV", "SIGILL", "SIGBUS", "SIGKILL", "SIGTERM"}
        elif key == "linux_sandbox_layer1":
            valid = isinstance(item, str) and item in {"SUID", "Namespace"}
        elif key == "browser_engine":
            valid = isinstance(item, str) and item in {"system_google_chrome", "pinned_chromium"}
        elif key == "browser_version":
            valid = isinstance(item, str) and bool(re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,8}){2,3}", item))
        elif key == "browser_elf_machine":
            valid = type(item) is int and 0 <= item <= 65535
        elif key == "browser_socket_path_max_bytes":
            valid = type(item) is int and 0 < item <= 100
        elif key == "native_error_code":
            valid = isinstance(item, str) and item in set(NATIVE_ERRORS.values())
        elif key == "probe_error_kind":
            valid = isinstance(item, str) and item in {"owned_handle_owner_dacl", "root_owner_dacl", "ancestor_acl", "other", "none"}
        elif key == "progress_blob_files":
            valid = type(item) is int and 0 <= item <= 1000
        elif key == "progress_blob_bytes":
            valid = type(item) is int and 0 <= item <= 16 * 1024**3
        else:
            valid = False
        if not valid:
            raise ValueError("PublicEvidenceField")


def browser_failure_facts(error):
    """Match fixed upstream signatures in memory; never publish exception text."""
    message = str(error).casefold()
    signatures = [
        ("socket_path_too_long", ("socket path too long",)),
        ("display_unavailable", ("missing x server or $display", "cannot open display", "unable to open x display")),
        ("sandbox_helper_misconfigured", ("suid sandbox helper binary was found, but is not configured correctly", "setuid sandbox provides api version")),
        ("sandbox_unavailable", ("no usable sandbox", "running as root without --no-sandbox")),
        ("user_namespace_rejected", ("failed to move to new namespace", "failed to unshare", "user namespace is not permitted")),
        ("shared_library_missing", ("error while loading shared libraries", "host system is missing dependencies")),
        ("executable_missing", ("executable doesn't exist", "executable does not exist", "failed to launch chromium because executable")),
        ("permission_denied", ("permission denied",)),
    ]
    result = {"browser_failure_reason": next((name for name, literals in signatures if any(value in message for value in literals)),
                                             "unclassified_browser_launch_failure")}
    match = re.search(r"signal=(sigabrt|sigtrap|sigsegv|sigill|sigbus|sigkill|sigterm)\b", message)
    if match:
        result["browser_failure_signal"] = match[1].upper()
    return result


def classify_native_error(texts):
    return next((NATIVE_ERRORS[value.strip()] for value in texts if value.strip() in NATIVE_ERRORS), None)


def trusted_error_facts(error):
    if type(error) in {RuntimeError, ValueError, TimeoutError, OSError, InterruptedError} and \
            len(error.args) == 1 and isinstance(error.args[0], str) and error.args[0] in TRUSTED_ERROR_CODES:
        return {"error_code": error.args[0]}
    return {}


def der_fields(data):
    """Read bounded, definite, minimally encoded DER TLVs without recursion."""
    fields, offset = [], 0
    while offset < len(data):
        start = offset
        if len(fields) >= 32 or offset + 2 > len(data):
            raise ValueError("DiagnosticDERInvalid")
        tag, size = data[offset], data[offset + 1]
        offset += 2
        if tag == 0 or tag & 31 == 31:
            raise ValueError("DiagnosticDERInvalid")
        if size & 128:
            count = size & 127
            if count not in {1, 2, 3} or offset + count > len(data) or data[offset] == 0:
                raise ValueError("DiagnosticDERInvalid")
            size = int.from_bytes(data[offset:offset + count], "big")
            offset += count
            if size < 128:
                raise ValueError("DiagnosticDERInvalid")
        end = offset + size
        if end > len(data):
            raise ValueError("DiagnosticDERInvalid")
        fields.append((tag, data[offset:end], data[start:end]))
        offset = end
    return fields


def der_one(data, tag):
    fields = der_fields(data)
    if len(fields) != 1 or fields[0][0] != tag:
        raise ValueError("DiagnosticDERInvalid")
    return fields[0][1]


def diagnostic_recipient_identifier():
    certificate = HERE / "diagnostic-recipient.pem"
    if certificate.is_symlink() or digest(certificate) != DIAGNOSTIC_CERT_SHA256:
        raise ValueError("DiagnosticRecipientPinMismatch")
    raw = subprocess.run(["openssl", "x509", "-in", str(certificate), "-outform", "DER"],
                         check=True, capture_output=True, timeout=20).stdout
    certificate_fields = der_fields(der_one(raw, 0x30))
    if len(certificate_fields) != 3 or certificate_fields[0][0] != 0x30:
        raise ValueError("DiagnosticRecipientIdentityInvalid")
    tbs = der_fields(certificate_fields[0][1])
    if tbs and tbs[0][0] == 0xA0:
        tbs = tbs[1:]
    if len(tbs) < 6 or tbs[0][0] != 2 or tbs[2][0] != 0x30 or tbs[5][0] != 0x30:
        raise ValueError("DiagnosticRecipientIdentityInvalid")
    # The pinned certificate also binds the exact RSA public key. Check its
    # algorithm and modulus size, rather than trusting a caller's recipient ID.
    spki = der_fields(tbs[5][1])
    rsa_algorithm = bytes.fromhex("06092a864886f70d0101010500")
    if len(spki) != 2 or spki[0][:2] != (0x30, rsa_algorithm) or spki[1][0] != 3 or not spki[1][1].startswith(b"\0"):
        raise ValueError("DiagnosticRecipientIdentityInvalid")
    rsa = der_fields(der_one(spki[1][1][1:], 0x30))
    if len(rsa) != 2 or rsa[0][0] != 2 or rsa[1][0] != 2 or int.from_bytes(rsa[0][1], "big").bit_length() != 3072:
        raise ValueError("DiagnosticRecipientIdentityInvalid")
    return tbs[2][2], tbs[0][2]


def validate_encrypted_diagnostic(data):
    """Accept only our RFC 5652 RSA/AES-256-CBC EnvelopedData profile.

    Exact TLV consumption rejects appended plaintext. No Data, SignedData,
    optional attributes, additional recipients, or alternate ciphers are allowed.
    """
    content = der_fields(der_one(data, 0x30))
    enveloped_oid = bytes.fromhex("2a864886f70d010703")
    data_oid = bytes.fromhex("2a864886f70d010701")
    rsa_algorithm = bytes.fromhex("06092a864886f70d0101010500")
    aes256_oid = bytes.fromhex("60864801650304012a")
    if len(content) != 2 or content[0][:2] != (6, enveloped_oid) or content[1][0] != 0xA0:
        raise ValueError("EncryptedDiagnosticProfileMismatch")
    envelope = der_fields(der_one(content[1][1], 0x30))
    if len(envelope) != 3 or envelope[0][:2] != (2, b"\0") or envelope[1][0] != 0x31 or envelope[2][0] != 0x30:
        raise ValueError("EncryptedDiagnosticProfileMismatch")
    recipient = der_fields(der_one(envelope[1][1], 0x30))
    if len(recipient) != 4 or recipient[0][:2] != (2, b"\0") or recipient[1][0] != 0x30 or \
            recipient[2][:2] != (0x30, rsa_algorithm) or recipient[3][0] != 4 or len(recipient[3][1]) != 384:
        raise ValueError("EncryptedDiagnosticProfileMismatch")
    identifier = der_fields(recipient[1][1])
    issuer, serial = diagnostic_recipient_identifier()
    if len(identifier) != 2 or identifier[0][2] != issuer or identifier[1][2] != serial:
        raise ValueError("EncryptedDiagnosticProfileMismatch")
    encrypted = der_fields(envelope[2][1])
    if len(encrypted) != 3 or encrypted[0][:2] != (6, data_oid) or encrypted[1][0] != 0x30 or encrypted[2][0] != 0x80:
        raise ValueError("EncryptedDiagnosticProfileMismatch")
    algorithm = der_fields(encrypted[1][1])
    if len(algorithm) != 2 or algorithm[0][:2] != (6, aes256_oid) or algorithm[1][0] != 4 or len(algorithm[1][1]) != 16:
        raise ValueError("EncryptedDiagnosticProfileMismatch")
    if not encrypted[2][1] or len(encrypted[2][1]) % 16 or len(encrypted[2][1]) > 64 * 1024 + 16:
        raise ValueError("EncryptedDiagnosticProfileMismatch")


def encrypt_browser_diagnostic(error, phase):
    """Send bounded raw diagnostics only to the root's pinned public recipient."""
    certificate = HERE / "diagnostic-recipient.pem"
    if certificate.is_symlink() or digest(certificate) != DIAGNOSTIC_CERT_SHA256:
        raise ValueError("DiagnosticRecipientPinMismatch")
    checked = subprocess.run(["openssl", "x509", "-in", str(certificate), "-noout", "-text"],
                             check=True, capture_output=True, text=True, encoding="utf-8", timeout=20).stdout
    if "Public Key Algorithm: rsaEncryption" not in checked or not re.search(r"Public-Key:\s*\(3072 bit\)", checked):
        raise ValueError("DiagnosticRecipientRSARequired")
    plaintext = bounded_browser_diagnostic(error, phase)
    encrypted = subprocess.run(["openssl", "cms", "-encrypt", "-aes-256-cbc", "-binary", "-outform", "DER", str(certificate)],
                               input=plaintext, check=True, capture_output=True, timeout=20).stdout
    if not encrypted or len(encrypted) > 128 * 1024:
        raise ValueError("EncryptedDiagnosticSizeLimit")
    (EVIDENCE / "browser-diagnostic.cms").write_bytes(encrypted)


def bounded_browser_diagnostic(error, phase):
    payload = ("phase=" + phase + "\nexception=" + type(error).__name__ + "\n" + str(error)).encode(
        "utf-8", errors="backslashreplace")
    limit = 64 * 1024
    if len(payload) <= limit:
        return payload
    marker = b"\n[bounded diagnostic: middle omitted]\n"
    first = (limit - len(marker)) // 2
    last = limit - first - len(marker)
    return payload[:first].decode("utf-8", errors="ignore").encode("utf-8") + marker + \
        payload[-last:].decode("utf-8", errors="ignore").encode("utf-8")


def system_chrome_attestation(executable):
    facts = {"system_chrome_exists": executable.exists(), "system_chrome_symlink": executable.is_symlink(),
             "system_chrome_regular": False, "system_chrome_root_owned": False,
             "system_chrome_group_writable": False, "system_chrome_other_writable": False}
    if facts["system_chrome_exists"]:
        info = executable.stat()
        facts.update({"system_chrome_regular": stat.S_ISREG(info.st_mode), "system_chrome_root_owned": info.st_uid == 0,
                      "system_chrome_group_writable": bool(info.st_mode & 0o020),
                      "system_chrome_other_writable": bool(info.st_mode & 0o002)})
    return facts


def browser_elf_machine(executable):
    with executable.open("rb") as source:
        header = source.read(64)
    if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
        return 0
    return int.from_bytes(header[18:20], "little")


def browser_socket_path_max_bytes(temporary):
    # Pinned Chromium uses 24/28-byte vendor+random directory names. Reserve
    # 40 bytes, plus both separators and SingletonSocket, below Linux sun_path.
    return len(os.fsencode(temporary)) + 1 + 40 + 1 + len(b"SingletonSocket")


def create_harness_root(owner):
    parent = Path(os.environ["RUNNER_TEMP"])
    if os.name == "nt":
        return Path(tempfile.mkdtemp(prefix="oniondesk-native-" + owner + "-", dir=parent))
    if browser_socket_path_max_bytes(parent / "od-xxxxxxxx" / "t") > 100:
        parent = Path("/tmp")
    root = Path(tempfile.mkdtemp(prefix="od-", dir=parent))
    if browser_socket_path_max_bytes(root / "t") > 100:
        root.rmdir()  # This just-created directory is still empty.
        raise RuntimeError("BrowserTemporaryPathTooLong")
    return root


def positive_linux_sandbox_layer(rows):
    if rows.get("Layer 1 Sandbox") not in {"SUID", "Namespace"} or any(
        rows.get(key) != "Yes" for key in ("PID namespaces", "Network namespaces", "Seccomp-BPF sandbox")
    ):
        raise RuntimeError("PositiveSandboxDiagnosticsRequired")
    return rows["Layer 1 Sandbox"]


def private_state_path():
    path = Path(os.environ["CI_STATE_FILE"])
    if path.parent.resolve() != Path(os.environ["RUNNER_TEMP"]).resolve() or not re.fullmatch(
        r"oniondesk-native-[0-9]+-[0-9]+-(windows-x64|linux-x64|linux-arm64)\.json", path.name
    ):
        raise ValueError("UnsafeStatePath")
    return path


def local_app_data():
    import ctypes
    folder = (ctypes.c_ubyte * 16).from_buffer_copy(uuid.UUID("f1b32785-6fba-4fcf-9d55-7b8e7f157091").bytes_le)
    result = ctypes.c_void_p()
    if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(folder), 0, None, ctypes.byref(result)) != 0:
        raise OSError("KnownFolderUnavailable")
    try:
        return Path(ctypes.wstring_at(result))
    finally:
        ctypes.windll.ole32.CoTaskMemFree(result)


def windows_claims():
    return [local_app_data() / "OnionDesk-Offline", Path(os.environ["ProgramFiles"]) / "OnionDesk"]


def process_identity(process):
    return {"pid": process.pid, "created": process.create_time()}


def same_process(identity):
    import psutil
    try:
        process = psutil.Process(identity["pid"])
        return process if process.create_time() == identity["created"] else None
    except psutil.NoSuchProcess:
        return None


class Harness:
    def __init__(self, distribution):
        import psutil
        self.distribution = distribution
        self.pin, self.manifest, self.index = verify_contract(distribution)
        required = {"CI_PUBLIC_REPOSITORY": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                    "RUNNER_OS": self.pin["runner_os"], "RUNNER_ARCH": self.pin["runner_arch"],
                    "GITHUB_REPOSITORY": "lindwerg/oniondesk"}
        if any(os.environ.get(k) != v for k, v in required.items()):
            raise RuntimeError("FreshPublicRunnerRequired")
        source = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, check=True, capture_output=True, text=True, encoding="utf-8", timeout=10).stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{40}", source) or source != os.environ.get("GITHUB_SHA"):
            raise RuntimeError("CheckoutSHAMismatch")
        if not SHA.fullmatch(self.pin["zip_sha256"]):
            raise ValueError("ReleaseAssetPinRequired")
        self.state_path = private_state_path()
        if self.state_path.exists():
            raise RuntimeError("StateAlreadyExists")
        self.owner = uuid.uuid4().hex
        self.root = create_harness_root(self.owner)
        self.root.chmod(0o700)
        (self.root / ".owner").write_text(self.owner, encoding="utf-8")
        self.state = {"owner": self.owner, "root": str(self.root), "processes": [], "windows_claimed": False}
        self.facts = {"distribution": distribution, "result": "RUNNING", "phase": "initialize",
                      "public_github_hosted_runner": True, "release": PINS["release"],
                      "index_sha256": PINS["index_sha256"], "manifest_sha256": self.pin["manifest_sha256"],
                      "source_commit": os.environ["GITHUB_SHA"], "synthetic_profile": True}
        self.save()
        temporary = self.root / ("temp" if os.name == "nt" else "t")
        temporary.mkdir(mode=0o700)
        if os.name != "nt":
            self.facts["browser_socket_path_max_bytes"] = browser_socket_path_max_bytes(temporary)
            self.save()
        if os.name == "nt":
            import winreg
            for path in windows_claims():
                if path.exists() or path.is_symlink():
                    raise RuntimeError("ExistingWindowsInstallationOrCache")
            for key in (r"Software\OnionDesk", r"Software\Microsoft\Windows\CurrentVersion\Uninstall\OnionDesk"):
                try:
                    handle = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
                except FileNotFoundError:
                    continue
                handle.Close()
                raise RuntimeError("ExistingWindowsRegistration")
            for path in windows_shortcuts():
                if path.exists() or path.is_symlink():
                    raise RuntimeError("ExistingWindowsShortcut")
            self.state["windows_claimed"] = True
            self.save()
        for relative in ("home", "package", "cache", "home/AppData/Local", "home/AppData/Roaming"):
            (self.root / relative).mkdir(parents=True, exist_ok=True, mode=0o700)
        keys = {"PATH", "SystemRoot", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "ProgramFiles", "PROGRAMFILES",
                "ProgramFiles(x86)", "CommonProgramFiles", "PUBLIC", "ALLUSERSPROFILE", "PROGRAMDATA",
                "DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "LANG", "LC_ALL"}
        self.environment = {k: v for k, v in os.environ.items() if k in keys}
        self.environment.update({"HOME": str(self.root / "home"), "USERPROFILE": str(self.root / "home"),
            "APPDATA": str(self.root / "home/AppData/Roaming"), "LOCALAPPDATA": str(self.root / "home/AppData/Local"),
            "TMPDIR": str(temporary), "TMP": str(temporary), "TEMP": str(temporary),
            "XDG_CACHE_HOME": str(self.root / "cache"), "XDG_CONFIG_HOME": str(self.root / "home/.config"),
            "ONIONDESK_CI_OWNED_ROOT": str(self.root), "ONIONDESK_CI_BROWSER_REQUEST": str(self.root / "browser-request"),
            "BROWSER": '"' + sys.executable + '" "' + str(HERE / "browser_dispatch.py") + '" %s'})
        if os.name != "nt":
            sandbox = Path(os.environ["CI_CHROME_SANDBOX"])
            validate_sandbox_helper(sandbox, os.environ["CI_CHROME_SANDBOX_SHA256"])
            self.facts["tooling_mount_nosuid"] = bool(os.statvfs(browser_tooling_path()).f_flag & os.ST_NOSUID)
            self.facts["sandbox_helper_mount_nosuid"] = bool(os.statvfs(sandbox.parent).f_flag & os.ST_NOSUID)
            self.save()
            if self.facts["sandbox_helper_mount_nosuid"]:
                raise RuntimeError("SandboxHelperMountRejectsSetuid")
            self.environment["CHROME_DEVEL_SANDBOX"] = str(sandbox)
        self.cache = windows_claims()[0] if os.name == "nt" else self.root / "cache/OnionDesk-Offline"
        self.package = self.root / "package"
        self.started = time.time()
        self.self_process = psutil.Process()

    def save(self):
        write_json(self.state_path, self.state)
        write_json(EVIDENCE / "status.json", self.facts)

    def phase(self, value):
        self.facts["phase"] = value
        self.save()
        print("Native R5: " + value, flush=True)

    def remember(self, process):
        import psutil
        try:
            identity = process_identity(process)
            if identity not in self.state["processes"]:
                self.state["processes"].append(identity)
                self.save()
        except psutil.NoSuchProcess:
            pass

    def discover(self):
        """Persist exact identities before any cleanup; no name-based kill."""
        import psutil
        for process in self.self_process.children(recursive=True):
            self.remember(process)
        owned = [self.root] + (windows_claims() if os.name == "nt" and self.state["windows_claimed"] else [])
        for process in psutil.process_iter(["exe", "create_time"]):
            try:
                if process.info["exe"] and process.info["create_time"] >= self.started and any(
                    Path(process.info["exe"]).is_relative_to(root) for root in owned
                ):
                    self.remember(process)
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue

    def spawn(self, executable, environment=None):
        import psutil
        process = subprocess.Popen([str(executable)], cwd=executable.parent, env=environment or self.environment,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.remember(psutil.Process(process.pid))
        return process

    def download(self):
        self.phase("download_release_asset")
        url = "https://github.com/lindwerg/oniondesk/releases/download/" + PINS["release"] + "/" + self.pin["asset"]
        target = self.root / "starter.zip"
        with urllib.request.urlopen(url, timeout=120) as response, target.open("xb") as output:
            size = 0
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > 128 * 1024 * 1024:
                    raise ValueError("ReleaseAssetTooLarge")
                output.write(chunk)
        if digest(target) != self.pin["zip_sha256"]:
            raise ValueError("ReleaseAssetPinMismatch")
        extract_zip(target, self.package)
        entries = list(self.package.rglob(self.pin["entry"]))
        if len(entries) != 1:
            raise ValueError("StarterEntryCount")
        self.entry = entries[0]
        self.package = self.entry.parent
        if self.entry.stat().st_size != self.pin["entry_bytes"] or digest(self.entry) != self.pin["entry_sha256"]:
            raise ValueError("StarterExecutableMismatch")
        if os.name != "nt" and stat.S_IMODE(self.entry.stat().st_mode) != 0o755:
            raise ValueError("StarterNotExecutable")
        source = self.package / ".oniondesk/transport/blobs"
        if source.exists() or source.is_symlink():
            raise ValueError("ColdDownloadRequiresAbsentPool")
        (self.package / ".oniondesk/transport").mkdir(parents=True, exist_ok=True, mode=0o700)
        self.facts.update({"asset_sha256": self.pin["zip_sha256"], "starter_sha256": self.pin["entry_sha256"],
                           "starter_verified": True, "source_pool_absent": True, "cold_cache": not self.cache.exists()})
        self.save()

    def payload(self):
        namespace = self.cache / self.pin["manifest_sha256"]
        candidates = [p for p in namespace.glob("ready-*") if re.fullmatch(r"ready-[0-9a-f]{32}", p.name)]
        if not candidates:
            return None
        if len(candidates) != 1 or candidates[0].is_symlink():
            raise ValueError("ReadyGenerationCount")
        generation = candidates[0]
        if json.loads((generation / "receipt.json").read_text(encoding="utf-8")) != {"schema": 1, "manifest": self.pin["manifest_sha256"]}:
            raise ValueError("ReadyReceiptMismatch")
        return generation / "payload"

    def verify_restore(self, payload):
        self.phase("independent_restore_verification")
        verify_payload(payload, self.manifest)
        online = self.cache / "online-r5" if os.name == "nt" else self.root / "cache/OnionDesk-Online-R5"
        namespace = online / ("r5-" + PINS["index_sha256"] + "-" + self.distribution + "-" + self.pin["manifest_sha256"])
        for i, part in enumerate(self.index["parts"]):
            if (namespace / ("part-" + str(i) + ".ok")).read_text(encoding="utf-8") != part["sha256"] + "\n":
                raise ValueError("OnlinePartReceiptMismatch")
        pool = namespace / "pool"
        if {p.name for p in pool.iterdir()} != {b["sha256"] for b in self.manifest["blobs"]}:
            raise ValueError("OnlinePoolSetMismatch")
        for blob in self.manifest["blobs"]:
            path = pool / blob["sha256"]
            if path.is_symlink() or path.stat().st_size != blob["bytes"] or digest(path) != blob["sha256"]:
                raise ValueError("OnlineBlobMismatch")
        self.facts.update({"restored_files_verified": len(self.manifest["files"]),
                           "online_blobs_verified": len(self.manifest["blobs"]),
                           "online_parts_verified": len(self.index["parts"]), "ready_receipt_verified": True})
        self.save()

    def screenshot(self, image, name):
        image.thumbnail((1280, 900))
        image.convert("RGB").save(EVIDENCE / name, format="PNG", optimize=True)
        seal_evidence()

    def native_snapshot(self):
        self.discover()
        if os.name == "nt":
            window = self.nsis_window(required=False, installer=False)
            if window:
                self.screenshot(window.capture_as_image(), "native-prepare.png")
                self.facts["native_preparation_window_seen"] = True
                self.save()
                return True
        else:
            from PIL import ImageGrab
            result = subprocess.run(["xdotool", "search", "--onlyvisible", "--name", "^OnionDesk$"],
                                    capture_output=True, text=True, encoding="utf-8", timeout=10)
            for window in result.stdout.split():
                pid = subprocess.run(["xdotool", "getwindowpid", window], capture_output=True, text=True, encoding="utf-8", timeout=10)
                if not pid.stdout.strip().isdigit() or int(pid.stdout) not in {i["pid"] for i in self.state["processes"]}:
                    continue
                geometry = subprocess.run(["xdotool", "getwindowgeometry", "--shell", window],
                                          check=True, capture_output=True, text=True, encoding="utf-8", timeout=10)
                values = dict(line.split("=", 1) for line in geometry.stdout.splitlines() if "=" in line)
                x, y, width, height = (int(values[k]) for k in ("X", "Y", "WIDTH", "HEIGHT"))
                if not (0 <= x < 1280 and 0 <= y < 900 and 100 <= width <= 1280 and 100 <= height <= 900):
                    raise ValueError("NativeWindowGeometry")
                self.screenshot(ImageGrab.grab(bbox=(x, y, x + width, y + height)), "native-prepare.png")
                self.facts["native_preparation_window_seen"] = True
                self.save()
                return True
        return False

    def nsis_window(self, required=True, installer=True):
        from pywinauto import Desktop
        self.discover()
        owned = {i["pid"] for i in self.state["processes"] if same_process(i)}
        windows = [w for w in Desktop(backend="win32").windows(title_re=".*OnionDesk.*", visible_only=True)
                   if w.process_id() in owned and (not installer or w.class_name() == "#32770")]
        if len(windows) > 1:
            windows = [w for w in windows if w.class_name() == "#32770"]
        if windows:
            return windows[0]
        if required:
            raise RuntimeError("OwnedNativeWindowRequired")
        return None

    def native_terminal_error(self):
        window = self.nsis_window(required=False, installer=False)
        if window:
            return classify_native_error([child.window_text() for child in window.children() if child.class_name() == "Static"])
        return None

    def cache_progress(self, launcher):
        online = self.cache / "online-r5"
        namespace = online / ("r5-" + PINS["index_sha256"] + "-" + self.distribution + "-" + self.pin["manifest_sha256"])
        expected = {item["sha256"]: item["bytes"] for item in self.manifest["blobs"]}
        sizes = [path.stat().st_size for path in (namespace / "pool").glob("*") if path.name in expected and
                 path.is_file() and not path.is_symlink() and path.stat().st_size == expected[path.name]]
        self.facts.update({"native_launcher_alive": launcher.poll() is None,
                           "progress_blob_files": len(sizes), "progress_blob_bytes": sum(sizes)})
        self.save()
        print("Native R5 progress: " + json.dumps({key: self.facts[key] for key in
              ("native_launcher_alive", "progress_blob_files", "progress_blob_bytes")}), flush=True)

    def drive_nsis(self, uninstall=False):
        self.phase("ordinary_nsis_uninstall" if uninstall else "ordinary_nsis_install")
        deadline = time.monotonic() + 600
        advanced = False
        while time.monotonic() < deadline:
            window = self.nsis_window(required=False)
            if window:
                buttons = [b for b in window.children() if b.class_name() == "Button" and b.control_id() == 1]
                if buttons and buttons[0].is_enabled():
                    button = buttons[0]
                    caption = button.window_text().replace("&", "").strip()
                    if any(value in caption for value in ("Готово", "Закрыть")):
                        if not advanced:
                            raise RuntimeError("UnexpectedNSISFinish")
                        if not uninstall:
                            self.screenshot(window.capture_as_image(), "native-installer.png")
                        button.click_input()
                        self.facts["ordinary_uninstaller_completed" if uninstall else "ordinary_installer_completed"] = True
                        self.save()
                        return
                    if not advanced and any(value in caption for value in ("Далее", "Установить", "Удалить")):
                        button.click_input()
                        advanced = True
            time.sleep(0.5)
        raise TimeoutError("OrdinaryNSISIncomplete")

    def wait_native_restore(self):
        self.phase("native_cold_download_and_restore")
        # The wrapper uses Windows' Known Folder API. Keep its actual ephemeral
        # runner profile stable, while Core and the browser get our private profile.
        wrapper_environment = dict(self.environment)
        if os.name == "nt":
            wrapper_environment.update({k: os.environ[k] for k in ("USERPROFILE", "LOCALAPPDATA", "APPDATA")})
        launcher = self.spawn(self.entry, wrapper_environment)
        deadline = time.monotonic() + 2400
        snapshot = False
        progress_due = time.monotonic()
        while time.monotonic() < deadline:
            if not snapshot:
                snapshot = self.native_snapshot()
            payload = self.payload()
            if payload:
                self.verify_restore(payload)
                if not snapshot:
                    raise RuntimeError("NativePreparationWindowNotProven")
                if os.name == "nt":
                    self.drive_nsis()
                    core = windows_claims()[1] / "OnionDesk.exe"
                    if not core.is_file() or core.is_symlink():
                        raise RuntimeError("InstalledCoreRequired")
                    self.spawn(core)
                return
            if os.name == "nt":
                error = self.native_terminal_error()
                if error:
                    self.facts["native_error_code"] = error
                    self.native_snapshot()
                    self.save()
                    raise RuntimeError("NativePreparationTerminalError")
                if launcher.poll() is not None:
                    self.facts["native_launcher_alive"] = False
                    self.save()
                    raise RuntimeError("NativePreparationExitedBeforeReady")
                if time.monotonic() >= progress_due:
                    self.cache_progress(launcher)
                    progress_due = time.monotonic() + 60
            self.discover()
            time.sleep(0.5)
        raise TimeoutError("ColdRestoreIncomplete")

    def core_flow(self, context):
        from playwright.sync_api import expect
        self.phase("core_first_action")
        request = self.root / "browser-request"
        deadline = time.monotonic() + 180
        while not request.exists() and time.monotonic() < deadline:
            self.discover()
            time.sleep(0.2)
        if not request.is_file() or request.is_symlink() or request.stat().st_size > 512:
            raise RuntimeError("CoreSystemBrowserRequestRequired")
        url = request.read_text(encoding="utf-8")
        if not re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}/#[A-Za-z0-9_-]{32,128}", url):
            raise ValueError("UnexpectedCoreBrowserRequest")
        page = context.new_page()
        page.goto(url, wait_until="domcontentloaded", timeout=60000)
        expect(page.locator("#heading-0")).to_be_visible(timeout=60000)
        expect(page.locator("#device-name")).not_to_have_text("Определяю устройство…", timeout=60000)
        page.locator('[data-page="0"] [data-inner-next]').click()
        expect(page.locator("#action-heading-0-1")).to_be_visible()
        expected = "Windows" if os.name == "nt" else "Linux"
        expect(page.locator("#device-name")).to_contain_text(expected)
        self.verify_browser_sandbox()
        page.screenshot(path=str(EVIDENCE / "core-first-action.png"))
        self.facts.update({"core_browser_fallback_seen": True, "headed_ui": True,
                           "first_device_action_completed": True, "browser_sandbox_enabled": True})
        if self.distribution == "linux-arm64":
            page.locator('[data-page="0"] [data-go="1"]').click()
            page.locator('[data-page="1"] [data-inner-next]').click()
            expect(page.locator("#launch-tor")).to_be_visible()
            expect(page.locator("#launch-tor")).to_be_disabled()
            expect(page.locator("#bundle-state")).to_contain_text("Для этой архитектуры официальный стабильный Tor Browser")
            page.screenshot(path=str(EVIDENCE / "arm-gate.png"))
            self.facts["unsupported_arm_tor_browser_gate_respected"] = True
        self.phase("core_ui_quit")
        page.locator("#quit").click()
        expect(page.locator("#quit")).to_be_disabled(timeout=30000)
        self.facts["ui_quit_completed"] = True
        self.save()
        self.wait_core_listener_closed(url)

    def verify_browser_sandbox(self):
        import psutil
        self.discover()
        renderers = []
        for identity in self.state["processes"]:
            process = same_process(identity)
            if not process:
                continue
            try:
                arguments = process.cmdline()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if "--type=renderer" in arguments:
                if {"--no-sandbox", "--disable-setuid-sandbox"} & set(arguments):
                    raise RuntimeError("BrowserSandboxDisabled")
                renderers.append(process.pid)
        if not renderers:
            raise RuntimeError("OwnedBrowserRendererRequired")
        self.facts["sandbox_renderer_flags_checked"] = True
        if os.name != "nt":
            for pid in renderers:
                fields = dict(line.split(":", 1) for line in Path("/proc", str(pid), "status").read_text(encoding="utf-8").splitlines() if ":" in line)
                if fields.get("Seccomp", "").strip() != "2":
                    raise RuntimeError("RendererSeccompRequired")
            self.facts["linux_renderer_seccomp_enabled"] = True

    def wait_core_listener_closed(self, url):
        # A genuine Quit must close the owned loopback listener, not just a tab.
        port = urlsplit(url).port
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    pass
            except ConnectionRefusedError:
                self.facts["core_listener_closed"] = True
                break
            except (OSError, TimeoutError):
                pass
            time.sleep(0.2)
        if not self.facts.get("core_listener_closed"):
            raise RuntimeError("CoreListenerSurvivedQuit")
        self.save()

    def run(self):
        from playwright.sync_api import sync_playwright
        self.download()
        self.phase("browser_attestation")
        with sync_playwright() as playwright:
            context = None
            try:
                options = {}
                self.facts["browser_engine"] = "pinned_chromium"
                executable = Path(playwright.chromium.executable_path)
                if self.distribution == "linux-x64":
                    executable = Path("/opt/google/chrome/chrome")
                    self.facts["browser_engine"] = "system_google_chrome"
                    facts = system_chrome_attestation(executable)
                    self.facts.update(facts)
                    self.save()
                    if not all(facts[key] for key in ("system_chrome_exists", "system_chrome_regular", "system_chrome_root_owned")) or any(
                        facts[key] for key in ("system_chrome_symlink", "system_chrome_group_writable", "system_chrome_other_writable")
                    ):
                        raise RuntimeError("TrustedSystemChromeRequired")
                    options["executable_path"] = str(executable)
                    self.facts["system_chrome_permissions_hardened"] = os.environ.get("CI_SYSTEM_CHROME_HARDENED") == "true"
                if os.name != "nt":
                    machine = browser_elf_machine(executable)
                    self.facts.update({"browser_elf_machine": machine,
                                       "browser_architecture_matches": machine == (183 if self.distribution == "linux-arm64" else 62)})
                    self.save()
                    if not self.facts["browser_architecture_matches"]:
                        raise RuntimeError("BrowserELFArchitectureMismatch")
                    # Upstream diagnostic logging stays inside the bounded,
                    # recipient-encrypted exception capture on launch failure.
                    options["args"] = ["--enable-logging=stderr", "--v=1"]
                self.phase("browser_launch")
                context = playwright.chromium.launch_persistent_context(str(self.root / "browser-profile"),
                    headless=False, chromium_sandbox=True, viewport={"width": 1200, "height": 820},
                    env=self.environment, accept_downloads=False, **options)
                if context.browser is not None:
                    self.facts["browser_version"] = context.browser.version
                self.save()
                if os.name != "nt":
                    self.phase("browser_sandbox_check")
                    self.linux_sandbox_diagnostics(context)
                self.discover()
                self.wait_native_restore()
                self.core_flow(context)
            except Exception as error:
                if self.facts["phase"] in {"browser_attestation", "browser_launch", "browser_sandbox_check"}:
                    self.facts.update(trusted_error_facts(error))
                    if self.facts["phase"] == "browser_launch":
                        self.facts.update(browser_failure_facts(error))
                    elif self.facts["phase"] == "browser_sandbox_check":
                        self.facts["browser_failure_reason"] = "sandbox_diagnostics_failed"
                    try:
                        encrypt_browser_diagnostic(error, self.facts["phase"])
                        self.facts["browser_diagnostic_encrypted"] = True
                    except Exception as diagnostic_error:
                        self.facts["browser_diagnostic_encrypted"] = False
                        self.facts["diagnostic_error_class"] = type(diagnostic_error).__name__
                        code = trusted_error_facts(diagnostic_error).get("error_code")
                        if code:
                            self.facts["diagnostic_error_code"] = code
                    self.save()
                raise
            finally:
                self.discover()
                if context:
                    context.close()
        if os.name == "nt":
            self.spawn(windows_claims()[1] / "Uninstall.exe")
            self.drive_nsis(uninstall=True)
            if windows_claims()[1].exists():
                raise RuntimeError("OrdinaryUninstallLeftInstallation")
        self.facts.update({"phase": "complete", "result": "PASS_PREPARATION_UI_ARM_GATE" if self.distribution == "linux-arm64" else "PASS"})
        self.save()

    def linux_sandbox_diagnostics(self, context):
        from playwright.sync_api import expect
        page = context.new_page()
        try:
            page.goto("chrome://sandbox", wait_until="domcontentloaded", timeout=30000)
            expect(page.locator("#evaluation")).to_have_text("You are adequately sandboxed.", timeout=30000)
            rows = page.locator("#sandbox-status tr").evaluate_all(
                "rows => Object.fromEntries(rows.map(row => [row.cells[0].textContent, row.cells[1].textContent]))")
            layer = positive_linux_sandbox_layer(rows)
            self.facts.update({"linux_sandbox_diagnostics_positive": True,
                               "linux_sandbox_layer1": layer, "browser_sandbox_enabled": True})
            self.save()
        finally:
            page.close()


def windows_shortcuts():
    public = Path(os.environ["PUBLIC"])
    program_data = Path(os.environ["ProgramData"])
    return [public / "Desktop/OnionDesk.lnk", program_data / "Microsoft/Windows/Start Menu/Programs/OnionDesk"]


def browser_tooling_path():
    target = Path(os.environ["PLAYWRIGHT_BROWSERS_PATH"])
    if target.parent.resolve() != Path(os.environ["RUNNER_TEMP"]).resolve() or not re.fullmatch(
        r"oniondesk-native-browsers-[0-9]+-[0-9]+", target.name
    ) or target.is_symlink():
        raise ValueError("UnsafeBrowserToolingPath")
    return target


def sandbox_helper_path():
    suffix = os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    if not re.fullmatch(r"[0-9]+-[0-9]+", suffix):
        raise ValueError("UnsafeSandboxHelperIdentity")
    return Path("/usr/local/sbin") / ("oniondesk-native-" + suffix + "-sandbox")


def validate_sandbox_helper(path, expected):
    if path != sandbox_helper_path() or not SHA.fullmatch(expected):
        raise ValueError("UnsafeSandboxHelperPin")
    parent, info = path.parent.stat(), path.stat()
    if path.is_symlink() or path.parent.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or \
            stat.S_IMODE(info.st_mode) != 0o4755 or parent.st_uid != 0 or parent.st_mode & 0o022 or digest(path) != expected:
        raise RuntimeError("ChromiumSandboxHelperRequired")


def cleanup_browser_tooling():
    tooling = browser_tooling_path()
    owner = tooling / "sandbox-owner.json"
    if owner.exists():
        if owner.is_symlink() or not owner.is_file() or owner.stat().st_size > 1024:
            raise ValueError("UnsafeSandboxOwnershipRecord")
        record = json.loads(owner.read_text(encoding="utf-8"))
        if set(record) != {"sha256", "target"} or record["target"] != str(sandbox_helper_path()):
            raise ValueError("SandboxOwnershipMismatch")
        target = sandbox_helper_path()
        if target.exists() or target.is_symlink():
            validate_sandbox_helper(target, record["sha256"])
            subprocess.run(["sudo", "--non-interactive", "rm", "--", str(target)], check=True, capture_output=True, timeout=20)
        if target.exists() or target.is_symlink():
            raise RuntimeError("SandboxHelperCleanupIncomplete")
    if tooling.exists():
        shutil.rmtree(tooling)


def harden_system_chrome_permissions():
    """Tighten only known root-owned Chrome paths on the ephemeral CI VM."""
    executable = Path("/opt/google/chrome/chrome")
    parents = [Path("/opt"), Path("/opt/google"), executable.parent]
    paths = [*parents, executable]
    for path in paths:
        info = path.lstat()
        expected_type = stat.S_ISREG if path == executable else stat.S_ISDIR
        if info.st_uid != 0 or not expected_type(info.st_mode):
            raise RuntimeError("SystemChromePermissionsUnsafe")
    # Lock the parent directories before the executable, then re-attest all
    # paths. The launch guard remains unchanged and still rejects writable code.
    for group in (parents, [executable]):
        subprocess.run(["sudo", "--non-interactive", "chmod", "0755", "--", *(str(path) for path in group)],
                       check=True, capture_output=True, timeout=20)
    for path in paths:
        info = path.lstat()
        expected_type = stat.S_ISREG if path == executable else stat.S_ISDIR
        if info.st_uid != 0 or not expected_type(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o755:
            raise RuntimeError("SystemChromePermissionsUnsafe")


def provision():
    """Normal sandbox provisioning; never alter AppArmor, sysctls or TLS."""
    distribution = os.environ.get("CI_DISTRIBUTION")
    if distribution not in PINS["distributions"]:
        raise RuntimeError("FreshPublicRunnerRequired")
    pin = PINS["distributions"][distribution]
    required = {"CI_PUBLIC_REPOSITORY": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": pin["runner_os"], "RUNNER_ARCH": pin["runner_arch"], "GITHUB_REPOSITORY": "lindwerg/oniondesk"}
    if any(os.environ.get(key) != value for key, value in required.items()):
        raise RuntimeError("FreshPublicRunnerRequired")
    browser_tooling_path()
    commands = []
    if os.name != "nt":
        commands.extend([["sudo", "apt-get", "update", "-qq"], ["sudo", "apt-get", "install", "-y", "-qq", "xvfb", "xauth", "xdotool"]])
    commands.append([sys.executable, "-m", "playwright", "install", "--with-deps", "chromium"])
    for command in commands:
        subprocess.run(command, check=True, capture_output=True, timeout=900)
    if distribution == "linux-x64":
        harden_system_chrome_permissions()
        with Path(os.environ["GITHUB_ENV"]).open("a", encoding="utf-8") as output:
            output.write("CI_SYSTEM_CHROME_HARDENED=true\n")
    if os.name != "nt":
        from playwright.sync_api import sync_playwright
        with sync_playwright() as playwright:
            source = Path(playwright.chromium.executable_path).with_name("chrome_sandbox")
        if not source.is_relative_to(browser_tooling_path()) or not source.is_file() or source.is_symlink():
            raise ValueError("SandboxHelperMissing")
        sandbox = sandbox_helper_path()
        if sandbox.exists() or sandbox.is_symlink():
            raise RuntimeError("SandboxHelperAlreadyExists")
        expected = digest(source)
        # Record ownership before the normal root-owned helper installation, so
        # cleanup can recover from interruption before GITHUB_ENV is written.
        write_json(browser_tooling_path() / "sandbox-owner.json", {"target": str(sandbox), "sha256": expected})
        subprocess.run(["sudo", "--non-interactive", "install", "-o", "root", "-g", "root", "-m", "4755", "--", str(source), str(sandbox)],
                       check=True, capture_output=True, timeout=20)
        validate_sandbox_helper(sandbox, expected)
        with Path(os.environ["GITHUB_ENV"]).open("a", encoding="utf-8") as output:
            output.write("CI_CHROME_SANDBOX=" + str(sandbox) + "\n")
            output.write("CI_CHROME_SANDBOX_SHA256=" + expected + "\n")
    print("Native R5: browser tooling provisioned with browser sandbox enabled", flush=True)


def cleanup():
    path = private_state_path()
    if not path.exists():
        cleanup_browser_tooling()
        seal_evidence()
        return
    import psutil
    state = json.loads(path.read_text(encoding="utf-8"))
    owner = state["owner"]
    root = Path(state["root"])
    legacy_root = root.parent.resolve() == path.parent.resolve() and root.name.startswith("oniondesk-native-" + owner + "-")
    short_root = os.name != "nt" and root.parent.resolve() in {path.parent.resolve(), Path("/tmp").resolve()} and \
        bool(re.fullmatch(r"od-[a-z0-9_]{8}", root.name))
    if not re.fullmatch(r"[0-9a-f]{32}", owner) or not (legacy_root or short_root):
        raise ValueError("CleanupOwnershipMismatch")
    if root.is_symlink() or (root / ".owner").is_symlink() or (root / ".owner").read_text(encoding="utf-8") != owner:
        raise ValueError("CleanupMarkerMismatch")
    # Stop only persisted PID + creation-time pairs. Never kill by process name.
    survivors = []
    for identity in reversed(state["processes"]):
        process = same_process(identity)
        if process:
            try:
                process.terminate()
                survivors.append(process)
            except psutil.NoSuchProcess:
                pass
    _, alive = psutil.wait_procs(survivors, timeout=5)
    for process in alive:
        identity = process_identity(process)
        if identity in state["processes"] and same_process(identity):
            process.kill()
    _, alive = psutil.wait_procs(alive, timeout=5)
    if alive:
        raise RuntimeError("OwnedProcessCleanupIncomplete")
    if os.name == "nt" and state["windows_claimed"]:
        import winreg
        for key in (r"Software\OnionDesk", r"Software\Microsoft\Windows\CurrentVersion\Uninstall\OnionDesk"):
            try:
                winreg.DeleteKeyEx(winreg.HKEY_LOCAL_MACHINE, key, winreg.KEY_WOW64_64KEY, 0)
            except FileNotFoundError:
                pass
        for item in windows_shortcuts() + windows_claims():
            if item.is_symlink():
                raise ValueError("CleanupLinkedWindowsClaim")
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink(missing_ok=True)
    cleanup_browser_tooling()
    shutil.rmtree(root)
    path.unlink()
    write_json(EVIDENCE / "cleanup.json", {"owned_resources_only": True, "exact_process_identities_only": True,
                                          "owned_processes_stopped": True, "private_cache_and_profile_removed": True})
    seal_evidence()


def main():
    if sys.argv[1:] == ["diagnose-windows"]:
        from windows_cache_debug import run_diagnostic
        return run_diagnostic(sys.modules[__name__])
    if sys.argv[1:] == ["seal"]:
        seal_evidence()
        return 0
    if sys.argv[1:] == ["provision"]:
        provision()
        return 0
    if sys.argv[1:] == ["cleanup"]:
        cleanup()
        return 0
    if len(sys.argv) != 3 or sys.argv[1] != "run" or sys.argv[2] not in PINS["distributions"]:
        raise ValueError("ExpectedRunDistributionOrCleanup")
    harness = None
    failed = False
    try:
        harness = Harness(sys.argv[2])
        harness.run()
    except Exception as error:
        failed = True
        record_failure(error, harness)
    finally:
        try:
            cleanup()
        except Exception as error:
            record_failure(error, harness)
            raise
    return int(failed)


def record_failure(error, harness=None):
    facts = {"result": "FAIL_OR_INCOMPLETE", "error_class": type(error).__name__, **trusted_error_facts(error)}
    if harness:
        harness.facts.update(facts)
        harness.save()
    else:
        write_json(EVIDENCE / "status.json", {"phase": "initialize", **facts})


def interrupted(_signal, _frame):
    raise InterruptedError("CIInterrupted")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    try:
        raise SystemExit(main())
    except Exception as error:
        # Exception strings can contain nonce URLs, commands and private paths.
        code = trusted_error_facts(error).get("error_code")
        print("Native R5 stopped: " + type(error).__name__ + (" [" + code + "]" if code else ""), file=sys.stderr)
        raise SystemExit(1)
