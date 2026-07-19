import hashlib
import json
import re
import sqlite3
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import BACKUP_FORMAT_VERSION
from .paths import backup_dir


REQUIRED_FILES = {"metadata.json", "manifest.json", "checksums.sha256"}
ARCHIVE_SUFFIX = ".nsbackup"
ARCHIVE_NAME_PATTERN = re.compile(r"^NetSpecter-Vault-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6}\.nsbackup$")


@dataclass
class VerificationResult:
    ok: bool
    detail: str


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_member_names(tar):
    names = []
    for member in tar.getmembers():
        name = member.name
        path = Path(name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"unsafe archive path: {name}")
        if member.isdir():
            continue
        names.append(name)
    return names


def load_json(path):
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def read_checksums(path):
    expected = {}
    for line in Path(path).read_text().splitlines():
        if not line.strip():
            continue
        digest, rel = line.split(None, 1)
        expected[rel.strip()] = digest
    return expected


def sqlite_integrity(path):
    if not Path(path).exists():
        return True, "no database in backup"
    con = sqlite3.connect(str(path), timeout=30)
    try:
        rows = con.execute("PRAGMA integrity_check").fetchall()
    finally:
        con.close()
    ok = len(rows) == 1 and str(rows[0][0]).lower() == "ok"
    return ok, "ok" if ok else "; ".join(str(row[0]) for row in rows)


def valid_backup_archive_name(archive_name):
    filename = str(archive_name or "").strip()
    if filename != Path(filename).name or not ARCHIVE_NAME_PATTERN.fullmatch(filename):
        raise ValueError("archive path must be a NetSpecter backup archive")
    return filename


def resolve_backup_archive_path(archive_name, safe_root=None):
    filename = valid_backup_archive_name(archive_name)
    root = Path(safe_root) if safe_root else backup_dir()
    for path in root.glob(f"*{ARCHIVE_SUFFIX}"):
        if path.name == filename:
            return path
    return None


def _verify_backup_path(archive_path, max_archive_bytes=None):
    archive_path = Path(archive_path)
    if not archive_path.exists():
        return VerificationResult(False, "archive does not exist")
    size = archive_path.stat().st_size
    if size <= 0:
        return VerificationResult(False, "archive is empty")
    if max_archive_bytes is not None and size > max_archive_bytes:
        return VerificationResult(False, "archive exceeds configured maximum size")

    try:
        with tempfile.TemporaryDirectory(prefix="netspecter-vault-verify-") as tmp:
            tmp_path = Path(tmp)
            with tarfile.open(archive_path, "r:gz") as tar:
                names = set(safe_member_names(tar))
                missing = REQUIRED_FILES - names
                if missing:
                    return VerificationResult(False, f"archive missing required files: {', '.join(sorted(missing))}")
                tar.extractall(tmp_path)

            metadata = load_json(tmp_path / "metadata.json")
            manifest = load_json(tmp_path / "manifest.json")
            if int(metadata.get("backup_format_version", -1)) != BACKUP_FORMAT_VERSION:
                return VerificationResult(False, "unsupported backup format version")
            for key in ("hostname", "created_at", "database_format", "included_components", "architecture"):
                if key not in metadata:
                    return VerificationResult(False, f"metadata missing {key}")
            if int(manifest.get("backup_format_version", -1)) != BACKUP_FORMAT_VERSION:
                return VerificationResult(False, "manifest version mismatch")

            expected = read_checksums(tmp_path / "checksums.sha256")
            manifest_paths = {item["path"] for item in manifest.get("files", [])}
            if manifest_paths != set(expected):
                return VerificationResult(False, "manifest and checksum file list differ")
            for rel, digest in expected.items():
                target = tmp_path / rel
                if not target.exists():
                    return VerificationResult(False, f"missing archived file: {rel}")
                if sha256_file(target) != digest:
                    return VerificationResult(False, f"checksum mismatch: {rel}")

            db_path = tmp_path / "var" / "lib" / "netspecter" / "netspecter.db"
            ok, detail = sqlite_integrity(db_path)
            if not ok:
                return VerificationResult(False, f"database integrity failed: {detail}")
    except Exception as error:
        return VerificationResult(False, str(error))

    return VerificationResult(True, "backup verified")


def verify_backup(archive_name, max_archive_bytes=None, safe_root=None):
    try:
        archive_path = resolve_backup_archive_path(archive_name, safe_root=safe_root)
    except ValueError as error:
        return VerificationResult(False, str(error))
    if archive_path is None:
        return VerificationResult(False, "archive does not exist")
    return _verify_backup_path(archive_path, max_archive_bytes=max_archive_bytes)

