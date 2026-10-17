"""Pinned, bounded CMS envelope boundary shared with reviewed native CI."""
import hashlib
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent
DIAGNOSTIC_CERT_SHA256 = "b023aa189fd017bba34f426e4b9af9fe3b3ebafd4138bec9771b315b3893132b"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    if not data or len(data) > 128 * 1024:
        raise ValueError("EncryptedDiagnosticSizeLimit")
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


def encrypt_diagnostic(data, target):
    """Only bounded ciphertext leaves private process memory."""
    if not isinstance(data, bytes) or not data:
        return False
    certificate = HERE / "diagnostic-recipient.pem"
    diagnostic_recipient_identifier()
    encrypted = subprocess.run(["openssl", "cms", "-encrypt", "-aes-256-cbc", "-binary",
                                "-outform", "DER", str(certificate)], input=data[-64 * 1024:],
                               check=True, capture_output=True, timeout=20).stdout
    if not encrypted or len(encrypted) > 128 * 1024:
        raise ValueError("EncryptedDiagnosticSizeLimit")
    validate_encrypted_diagnostic(encrypted)
    target.write_bytes(encrypted)
    return True


class PrivateDiagnostic:
    """A single bounded private buffer; save encrypts it before any write."""
    def __init__(self):
        self.data = bytearray()

    def add(self, label, data):
        self.data.extend(b"\n[" + label.encode("ascii") + b"]\n" + data[-64 * 1024:])
        del self.data[:-64 * 1024]

    def save(self, target):
        return encrypt_diagnostic(bytes(self.data), target)


def passt_denials(data):
    """Only passt AppArmor denial records from a bounded host kernel query."""
    identity = re.compile(rb'\b(?:comm="passt(?:\.avx2)?"|profile="(?:/usr/bin/)?passt(?:\.avx2)?")')
    return b"\n".join(line for line in data.splitlines()
                      if b'apparmor="DENIED"' in line and identity.search(line))[-32 * 1024:]


def collect_host_security(target):
    """Read host policy/audit evidence; never load, unload or alter a policy."""
    private = PrivateDiagnostic()
    denied = b""
    probes = (
        ("kernel_passt_denials", ["sudo", "-n", "journalctl", "--dmesg", "--no-pager", "--output=cat", "--lines=500"]),
        ("loaded_profiles", ["sudo", "-n", "cat", "/sys/kernel/security/apparmor/profiles"]),
        ("host_passt_profile", ["sudo", "-n", "cat", "/etc/apparmor.d/usr.bin.passt"]),
        ("host_passt_abstraction", ["sudo", "-n", "cat", "/etc/apparmor.d/abstractions/passt"]),
    )
    for label, arguments in probes:
        try:
            response = subprocess.run(arguments, capture_output=True, timeout=20)
            data = response.stdout
            if label == "kernel_passt_denials":
                data = denied = passt_denials(data)
            elif label == "loaded_profiles":
                data = b"\n".join(line for line in data.splitlines() if b"passt" in line or b"libvirt" in line)
            private.add(label, b"exit=" + str(response.returncode).encode("ascii") + b"\n" + data[-12 * 1024:])
        except (OSError, subprocess.SubprocessError):
            private.add(label, b"probe_unavailable")
    return {"encrypted_host_security_diagnostic_saved": private.save(target),
            "host_kernel_passt_apparmor_denial_observed": bool(denied)}


def collect_container_security(private):
    """Read packaged policy and the actual daemon label into encrypted inputs."""
    for label, filename in (
        ("container_passt_profile", "/etc/apparmor.d/usr.bin.passt"),
        ("container_passt_abstraction", "/etc/apparmor.d/abstractions/passt"),
        ("container_libvirt_policy", "/etc/apparmor.d/abstractions/libvirt-qemu"),
        ("container_current_label", "/proc/self/attr/current"),
    ):
        try:
            private.add(label, Path(filename).read_bytes()[-8 * 1024:])
        except OSError:
            private.add(label, b"probe_unavailable")
    try:
        response = subprocess.run(["systemctl", "show", "libvirtd.service", "--property=MainPID", "--value"],
                                  capture_output=True, timeout=10)
        pid = response.stdout.strip()
        if response.returncode == 0 and re.fullmatch(rb"[1-9][0-9]{0,9}", pid):
            private.add("libvirtd_current_label", Path("/proc", pid.decode("ascii"), "attr/current").read_bytes())
        versions = subprocess.run(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n",
                                   "passt", "libvirt-daemon-driver-qemu", "apparmor"], capture_output=True, timeout=10)
        private.add("container_package_versions", versions.stdout[-4096:])
    except (OSError, subprocess.SubprocessError):
        private.add("container_security_runtime", b"probe_unavailable")

