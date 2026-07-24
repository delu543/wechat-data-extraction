from __future__ import annotations

import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from live_tools.wechat_safe_snapshot import (
    CONFIG_FILENAME,
    CONTACT_REL,
    KEYS_FILENAME,
    PAGE_SIZE,
    RESOURCE_REL,
    RESERVED_BYTES,
    FileFingerprint,
    OnlineSnapshotUnavailable,
    SnapshotError,
    acquire_online_wal_locks,
    apfs_clone_file_atomic,
    copy_stable_file_atomic,
    derive_account_ref_from_db_base,
    find_wechat_holders,
    inspect_sidecar,
    materialize_copied_database_with_wal,
    normalize_database_request,
    normalize_database_requests,
    parse_lsof_records,
    resolve_source,
    scan_copied_wal_for_replay,
    snapshot_and_decrypt,
    validate_copied_wal_logically_empty,
    validate_db_base,
    validate_private_output_root,
    _argument_parser,
    _resolve_cli_db_base,
    _wal_checksum_words,
)


def _sqlite_library() -> ctypes.CDLL:
    candidates = (
        "/usr/lib/libsqlite3.dylib",
        "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0",
        "/usr/lib/aarch64-linux-gnu/libsqlite3.so.0",
        "libsqlite3.so.0",
    )
    last: OSError | None = None
    for candidate in candidates:
        try:
            return ctypes.CDLL(candidate)
        except OSError as exc:
            last = exc
    assert last is not None
    raise last


def _create_reserved_sqlite(path: Path, statements: str) -> None:
    """Create a real SQLite fixture whose pages reserve the WeChat 80 bytes."""

    library = _sqlite_library()
    library.sqlite3_open_v2.argtypes = [
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_int,
        ctypes.c_char_p,
    ]
    library.sqlite3_open_v2.restype = ctypes.c_int
    library.sqlite3_file_control.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_void_p,
    ]
    library.sqlite3_file_control.restype = ctypes.c_int
    library.sqlite3_exec.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_char_p),
    ]
    library.sqlite3_exec.restype = ctypes.c_int
    library.sqlite3_close.argtypes = [ctypes.c_void_p]
    library.sqlite3_close.restype = ctypes.c_int
    library.sqlite3_free.argtypes = [ctypes.c_void_p]

    database = ctypes.c_void_p()
    flags = 0x00000002 | 0x00000004  # SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE
    rc = library.sqlite3_open_v2(os.fsencode(path), ctypes.byref(database), flags, None)
    if rc != 0:
        raise AssertionError(f"sqlite3_open_v2 failed: {rc}")
    try:
        reserve = ctypes.c_int(RESERVED_BYTES)
        rc = library.sqlite3_file_control(
            database, b"main", 38, ctypes.byref(reserve)
        )  # SQLITE_FCNTL_RESERVE_BYTES
        if rc != 0:
            raise AssertionError(f"SQLITE_FCNTL_RESERVE_BYTES failed: {rc}")

        error = ctypes.c_char_p()
        sql = (
            "PRAGMA page_size=4096; VACUUM; " + statements
        ).encode("utf-8")
        rc = library.sqlite3_exec(database, sql, None, None, ctypes.byref(error))
        if rc != 0:
            message = error.value.decode("utf-8", errors="replace") if error.value else str(rc)
            if error:
                library.sqlite3_free(error)
            raise AssertionError(f"sqlite3_exec failed: {message}")
    finally:
        library.sqlite3_close(database)

    raw = path.read_bytes()
    if raw[16:18] != PAGE_SIZE.to_bytes(2, "big") or raw[20] != RESERVED_BYTES:
        raise AssertionError("fixture SQLite did not persist the requested page layout")
    for offset in range(0, len(raw), PAGE_SIZE):
        if any(raw[offset + PAGE_SIZE - RESERVED_BYTES : offset + PAGE_SIZE]):
            raise AssertionError("fixture SQLite reserve area is unexpectedly nonzero")


def _encrypt_wechat_fixture(
    plain: Path,
    encrypted: Path,
    key: bytes,
    *,
    salt: bytes | None = None,
) -> None:
    from Crypto.Cipher import AES

    source = plain.read_bytes()
    if not source or len(source) % PAGE_SIZE:
        raise AssertionError("plain SQLite fixture must contain complete pages")
    database_salt = salt or hashlib.sha256(b"fixture-salt").digest()[:16]
    if len(database_salt) != 16:
        raise AssertionError("fixture database salt must be exactly 16 bytes")
    result = bytearray()
    encrypted_end = PAGE_SIZE - RESERVED_BYTES
    for index in range(0, len(source), PAGE_SIZE):
        page_number = index // PAGE_SIZE + 1
        page = source[index : index + PAGE_SIZE]
        start = 16 if page_number == 1 else 0
        iv = hashlib.sha256(f"fixture-iv-{page_number}".encode()).digest()[:16]
        output = bytearray(PAGE_SIZE)
        if page_number == 1:
            output[:16] = database_salt
        output[start:encrypted_end] = AES.new(key, AES.MODE_CBC, iv).encrypt(
            page[start:encrypted_end]
        )
        output[encrypted_end : encrypted_end + 16] = iv
        result.extend(output)
    encrypted.parent.mkdir(parents=True, exist_ok=True)
    encrypted.write_bytes(result)


def _write_logical_empty_wal_sidecars(
    database: Path,
    *,
    first_frame_uses_current_salt: bool = False,
) -> None:
    """Create checksummed WAL/SHM with mxFrame=0 and a preallocated slot."""

    salt = bytes.fromhex("1020304050607080")
    prefix = struct.pack(
        ">IIII", 0x377F0682, 3_007_000, PAGE_SIZE, 7
    ) + salt
    wal_checksum = _wal_checksum_words(prefix, "little")
    wal_header = prefix + struct.pack(">II", *wal_checksum)
    frame_salt = salt if first_frame_uses_current_salt else bytes.fromhex(
        "90a0b0c0d0e0f001"
    )
    frame_header = struct.pack(">II", 1, 0) + frame_salt + bytes(8)
    Path(str(database) + "-wal").write_bytes(
        wal_header + frame_header + bytes(PAGE_SIZE)
    )

    index = bytearray(48)
    index[0:4] = (3_007_000).to_bytes(4, sys.byteorder)
    index[8:12] = (1).to_bytes(4, sys.byteorder)
    index[12] = 1
    index[13] = 0
    index[14:16] = PAGE_SIZE.to_bytes(2, sys.byteorder)
    index[16:20] = (0).to_bytes(4, sys.byteorder)
    index[20:24] = (2).to_bytes(4, sys.byteorder)
    index[32:40] = salt
    index_checksum = _wal_checksum_words(bytes(index[:40]), sys.byteorder)
    index[40:44] = index_checksum[0].to_bytes(4, sys.byteorder)
    index[44:48] = index_checksum[1].to_bytes(4, sys.byteorder)
    Path(str(database) + "-shm").write_bytes(
        bytes(index) * 2 + bytes(32 * 1024 - 96)
    )


def _encrypted_pages(path: Path) -> list[tuple[int, bytes]]:
    raw = path.read_bytes()
    if not raw or len(raw) % PAGE_SIZE:
        raise AssertionError("encrypted fixture must contain complete pages")
    return [
        (offset // PAGE_SIZE + 1, raw[offset : offset + PAGE_SIZE])
        for offset in range(0, len(raw), PAGE_SIZE)
    ]


def _write_wal_transactions(
    database: Path,
    transactions: list[tuple[list[tuple[int, bytes]], int | None]],
) -> int:
    """Write checksum-valid encrypted WAL frames for committed/uncommitted txns."""

    salt = bytes.fromhex("1122334455667788")
    prefix = struct.pack(
        ">IIII", 0x377F0682, 3_007_000, PAGE_SIZE, 9
    ) + salt
    rolling = _wal_checksum_words(prefix, "little")
    result = bytearray(prefix + struct.pack(">II", *rolling))
    frame_count = 0
    for pages, committed_pages in transactions:
        if not pages:
            raise AssertionError("transaction must contain at least one page")
        for index, (page_number, page) in enumerate(pages):
            if len(page) != PAGE_SIZE:
                raise AssertionError("WAL fixture page must be complete")
            database_pages = (
                int(committed_pages or 0)
                if committed_pages is not None and index == len(pages) - 1
                else 0
            )
            frame_prefix = struct.pack(">II", page_number, database_pages)
            rolling = _wal_checksum_words(
                frame_prefix + page,
                "little",
                rolling,
            )
            result.extend(
                frame_prefix
                + salt
                + struct.pack(">II", *rolling)
                + page
            )
            frame_count += 1
    Path(str(database) + "-wal").write_bytes(result)
    return frame_count


def _write_active_wal_shm(
    database: Path,
    *,
    max_frame: int,
    database_pages: int,
    n_backfill: int = 0,
) -> None:
    """Create a valid 32KiB WalIndexHdr anchor for an existing fixture WAL."""

    wal = Path(str(database) + "-wal").read_bytes()
    frame_bytes = 24 + PAGE_SIZE
    complete_frames = max(0, (len(wal) - 32) // frame_bytes)
    if not 0 < max_frame <= complete_frames:
        raise AssertionError("active SHM fixture needs an existing committed frame")
    frame_header = 32 + (max_frame - 1) * frame_bytes
    frame_checksum = (
        int.from_bytes(wal[frame_header + 16 : frame_header + 20], "big"),
        int.from_bytes(wal[frame_header + 20 : frame_header + 24], "big"),
    )
    index = bytearray(48)
    index[0:4] = (3_007_000).to_bytes(4, sys.byteorder)
    index[8:12] = (1).to_bytes(4, sys.byteorder)
    index[12] = 1
    index[13] = int.from_bytes(wal[0:4], "big") & 1
    index[14:16] = PAGE_SIZE.to_bytes(2, sys.byteorder)
    index[16:20] = max_frame.to_bytes(4, sys.byteorder)
    index[20:24] = database_pages.to_bytes(4, sys.byteorder)
    index[24:28] = frame_checksum[0].to_bytes(4, sys.byteorder)
    index[28:32] = frame_checksum[1].to_bytes(4, sys.byteorder)
    index[32:40] = wal[16:24]
    index_checksum = _wal_checksum_words(bytes(index[:40]), sys.byteorder)
    index[40:44] = index_checksum[0].to_bytes(4, sys.byteorder)
    index[44:48] = index_checksum[1].to_bytes(4, sys.byteorder)
    shm = bytearray(32 * 1024)
    shm[:48] = index
    shm[48:96] = index
    shm[96:100] = n_backfill.to_bytes(4, sys.byteorder)
    Path(str(database) + "-shm").write_bytes(shm)


class SafeSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.xwechat_root = self.root / "xwechat_files"
        self.xwechat_root.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_cli_accepts_redacted_account_ref_without_a_database_path(self) -> None:
        base = self._db_base()
        salt = bytes.fromhex("00112233445566778899aabbccddeeff")
        (base / CONTACT_REL).write_bytes(salt + bytes(PAGE_SIZE - len(salt)))
        account_ref = derive_account_ref_from_db_base(base)
        parsed = _argument_parser().parse_args(
            [
                "--account-ref",
                account_ref,
                "--output-root",
                str(self.root / "output"),
                "--database",
                "contact",
            ]
        )
        with mock.patch(
            "live_tools.wechat_key_init.resolve_account_ref", return_value=base
        ):
            self.assertEqual(
                _resolve_cli_db_base(parsed, xwechat_root=self.xwechat_root),
                base,
            )

        parsed.account_ref = "account-0123456789ab"
        with mock.patch(
            "live_tools.wechat_key_init.resolve_account_ref", return_value=base
        ), self.assertRaisesRegex(SnapshotError, "contact salt"):
            _resolve_cli_db_base(parsed, xwechat_root=self.xwechat_root)

        missing = argparse.Namespace(account_ref=None, db_base=None)
        with self.assertRaises(SnapshotError):
            _resolve_cli_db_base(missing)

    def test_cli_online_flag_is_explicit(self) -> None:
        parsed = _argument_parser().parse_args(
            [
                "--db-base",
                "/private/example/db_storage",
                "--output-root",
                "/private/example/output",
                "--database",
                "contact",
                "--online",
            ]
        )
        self.assertTrue(parsed.online)

    def _db_base(self, account_name: str = "account_fixture") -> Path:
        base = self.xwechat_root / account_name / "db_storage"
        (base / "contact").mkdir(parents=True)
        (base / "message").mkdir()
        return base

    def _create_encrypted_contact(
        self,
        base: Path,
        *,
        key: bytes,
        salt: bytes,
        fixture_name: str,
    ) -> str:
        plain = self.root / "plain" / f"{fixture_name}.db"
        plain.parent.mkdir(exist_ok=True)
        _create_reserved_sqlite(
            plain,
            "CREATE TABLE contact(id INTEGER, username TEXT); "
            f"INSERT INTO contact VALUES(1, '{fixture_name}');",
        )
        _encrypt_wechat_fixture(plain, base / CONTACT_REL, key, salt=salt)
        return derive_account_ref_from_db_base(base)

    def _private_state_root(self) -> Path:
        private_root = self.root / "private-state"
        private_root.mkdir(mode=0o700, exist_ok=True)
        os.chmod(private_root, 0o700)
        return private_root

    def _write_private_json(self, path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(path.parent, 0o700)
        path.write_text(json.dumps(value), encoding="utf-8")
        os.chmod(path, 0o600)

    def _write_schema2_account_state(
        self,
        *,
        private_root: Path,
        account_ref: str,
        base: Path,
        key_hex: str,
    ) -> Path:
        account_dir = private_root / "accounts" / account_ref
        account_dir.mkdir(parents=True, mode=0o700)
        os.chmod(private_root / "accounts", 0o700)
        os.chmod(account_dir, 0o700)
        keys_file = account_dir / KEYS_FILENAME
        self._write_private_json(keys_file, {"contact": key_hex})
        salt_fingerprint = hashlib.sha256(
            (base / CONTACT_REL).read_bytes()[:16]
        ).hexdigest()
        self._write_private_json(
            account_dir / CONFIG_FILENAME,
            {
                "schema_version": 2,
                "initialized_at": "2026-07-22T00:00:00Z",
                "account_ref": account_ref,
                "db_base_path": str(base),
                "keys_file": str(keys_file),
                "targets": {"contact": CONTACT_REL},
                "salt_fingerprints": {"contact": salt_fingerprint},
            },
        )
        return keys_file

    def _write_schema1_root_state(
        self,
        *,
        private_root: Path,
        base: Path,
        key_hex: str,
    ) -> Path:
        keys_file = private_root / KEYS_FILENAME
        self._write_private_json(keys_file, {"contact": key_hex})
        self._write_private_json(
            private_root / CONFIG_FILENAME,
            {
                "schema_version": 1,
                "db_base_path": str(base),
                "keys_file": str(keys_file),
                "targets": {"contact": CONTACT_REL},
            },
        )
        return keys_file

    def _private_output(self) -> Path:
        output = self.root / "private-output"
        output.mkdir(mode=0o700, exist_ok=True)
        os.chmod(output, 0o700)
        return output

    def test_database_allowlist_rejects_traversal_and_noncanonical_shards(self) -> None:
        self.assertEqual(normalize_database_request("contact"), CONTACT_REL)
        self.assertEqual(
            normalize_database_request("message_2"), "message/message_2.db"
        )
        self.assertEqual(
            normalize_database_request("message/media_3.db"), "message/media_3.db"
        )
        self.assertEqual(
            normalize_database_request("message_resource"), RESOURCE_REL
        )
        self.assertEqual(
            normalize_database_request(RESOURCE_REL), RESOURCE_REL
        )
        for value in (
            "../contact/contact.db",
            "/tmp/message_0.db",
            "message/message_00.db",
            "message/message_fts.db",
            "session/session.db",
            "message\\message_0.db",
        ):
            with self.subTest(value=value), self.assertRaises(SnapshotError):
                normalize_database_request(value)
        with self.assertRaisesRegex(SnapshotError, "重复"):
            normalize_database_requests(["message_0", "message/message_0.db"])

    def test_validation_rejects_symlink_source_and_public_output_root(self) -> None:
        base = self._db_base()
        target = base / "contact/contact.db"
        real = self.root / "real.db"
        real.write_bytes(b"x" * PAGE_SIZE)
        target.symlink_to(real)
        validated = validate_db_base(base, xwechat_root=self.xwechat_root)
        with self.assertRaisesRegex(SnapshotError, "符号链接"):
            resolve_source(validated, "contact")

        public = self.root / "public-output"
        public.mkdir(mode=0o755)
        os.chmod(public, 0o755)
        with self.assertRaisesRegex(SnapshotError, "0700"):
            validate_private_output_root(public)

    def test_db_base_outside_exact_xwechat_account_boundary_is_rejected(self) -> None:
        outside = self.root / "outside" / "account_fixture" / "db_storage"
        (outside / "contact").mkdir(parents=True)
        (outside / "message").mkdir()
        with self.assertRaisesRegex(SnapshotError, "严格位于"):
            validate_db_base(outside, xwechat_root=self.xwechat_root)

    def test_lsof_parser_and_wechat_filter_are_testable(self) -> None:
        raw = "\n".join(
            (
                "p101",
                "cWeChat",
                "n/private/a.db",
                "n/private/a.db-wal",
                "p202",
                "cpython",
                "n/private/a.db",
            )
        )
        records = parse_lsof_records(raw)
        self.assertEqual(
            [(item.pid, item.command) for item in records],
            [(101, "WeChat"), (202, "python")],
        )

        def runner(*args, **kwargs):
            return subprocess.CompletedProcess(args[0], 0, raw, "")

        holders = find_wechat_holders([Path("/private/a.db")], runner=runner)
        self.assertEqual(len(holders), 1)
        self.assertEqual(holders[0].pid, 101)

    def test_nonempty_wal_is_literal_size_gate(self) -> None:
        database = self.root / "message_0.db"
        database.write_bytes(b"x" * PAGE_SIZE)
        wal = Path(str(database) + "-wal")
        wal.write_bytes(b"")
        self.assertEqual(inspect_sidecar(database, "-wal").status, "zero")
        wal.write_bytes(b"\x00" * (4 * 1024 * 1024))
        with self.assertRaisesRegex(SnapshotError, "非空 WAL"):
            inspect_sidecar(database, "-wal")

    def test_logically_empty_preallocated_wal_has_strong_shm_gate(self) -> None:
        database = self.root / "message_0.db"
        database.write_bytes(b"x" * PAGE_SIZE)
        _write_logical_empty_wal_sidecars(database)
        report = validate_copied_wal_logically_empty(
            Path(str(database) + "-wal"),
            Path(str(database) + "-shm"),
        )
        self.assertEqual(report["status"], "logical_empty_preallocated")
        self.assertEqual(report["wal_frames_applied"], 0)
        self.assertEqual(report["shm"]["mx_frame"], 0)
        self.assertNotIn("1020304050607080", json.dumps(report))

        _write_logical_empty_wal_sidecars(
            database, first_frame_uses_current_salt=True
        )
        with self.assertRaisesRegex(SnapshotError, "首个 WAL frame"):
            validate_copied_wal_logically_empty(
                Path(str(database) + "-wal"),
                Path(str(database) + "-shm"),
            )

    def test_committed_wal_is_replayed_and_uncommitted_tail_is_ignored(self) -> None:
        base = self._db_base("wal_replay")
        key = bytes([0x71]) * 32
        salt = bytes.fromhex("00112233445566778899aabbccddeeff")
        plain_root = self.root / "wal-plain"
        plain_root.mkdir()
        base_plain = plain_root / "base.db"
        committed_plain = plain_root / "committed.db"
        uncommitted_plain = plain_root / "uncommitted.db"
        _create_reserved_sqlite(
            base_plain,
            "CREATE TABLE contact(id INTEGER, username TEXT); "
            "INSERT INTO contact VALUES(1, 'base');",
        )
        _create_reserved_sqlite(
            committed_plain,
            "CREATE TABLE contact(id INTEGER, username TEXT); "
            "INSERT INTO contact VALUES(1, 'base'); "
            "INSERT INTO contact VALUES(2, 'committed'); "
            "CREATE TABLE growth(payload BLOB); "
            "INSERT INTO growth VALUES(zeroblob(20000));",
        )
        _create_reserved_sqlite(
            uncommitted_plain,
            "CREATE TABLE contact(id INTEGER, username TEXT); "
            "INSERT INTO contact VALUES(1, 'base'); "
            "INSERT INTO contact VALUES(2, 'committed'); "
            "INSERT INTO contact VALUES(3, 'uncommitted');",
        )
        encrypted = base / CONTACT_REL
        committed_encrypted = self.root / "committed-encrypted.db"
        uncommitted_encrypted = self.root / "uncommitted-encrypted.db"
        _encrypt_wechat_fixture(base_plain, encrypted, key, salt=salt)
        _encrypt_wechat_fixture(
            committed_plain, committed_encrypted, key, salt=salt
        )
        _encrypt_wechat_fixture(
            uncommitted_plain, uncommitted_encrypted, key, salt=salt
        )
        committed_pages = _encrypted_pages(committed_encrypted)
        uncommitted_pages = _encrypted_pages(uncommitted_encrypted)
        frame_count = _write_wal_transactions(
            encrypted,
            [
                (committed_pages, len(committed_pages)),
                (uncommitted_pages, None),
            ],
        )

        key_file = self.root / "wal-keys.json"
        key_file.write_text(json.dumps({"contact": key.hex()}), encoding="utf-8")
        os.chmod(key_file, 0o600)
        report = snapshot_and_decrypt(
            db_base=base,
            output_root=self._private_output(),
            keys_file=key_file,
            databases=["contact"],
            holder_probe=lambda paths: [],
            xwechat_root=self.xwechat_root,
        )
        record = report["records"][0]
        self.assertEqual(record["wal_gate"], "committed_frames")
        self.assertEqual(record["wal_validation"]["commit_count"], 1)
        self.assertEqual(
            record["wal_validation"]["ignored_uncommitted_frames"],
            len(uncommitted_pages),
        )
        self.assertEqual(record["wal_validation"]["valid_frames"], frame_count)
        decrypted = (
            Path(report["run_directory"]) / "decrypted" / CONTACT_REL
        )
        with sqlite3.connect(decrypted) as connection:
            rows = connection.execute(
                "SELECT id, username FROM contact ORDER BY id"
            ).fetchall()
            self.assertEqual(rows, [(1, "base"), (2, "committed")])
            self.assertEqual(connection.execute("PRAGMA quick_check").fetchone()[0], "ok")
        manifest = Path(report["manifest_path"]).read_text(encoding="utf-8")
        self.assertNotIn(key.hex(), manifest)
        self.assertNotIn(salt.hex(), manifest)
        self.assertFalse(report["safety"]["page_hmac_verified"])

    def test_online_snapshot_uses_locked_anchor_and_skips_holder_gate(self) -> None:
        base = self._db_base("online_replay")
        key = bytes([0x72]) * 32
        salt = bytes.fromhex("00112233445566778899aabbccddeeff")
        plain_root = self.root / "online-plain"
        plain_root.mkdir()
        base_plain = plain_root / "base.db"
        committed_plain = plain_root / "committed.db"
        _create_reserved_sqlite(
            base_plain,
            "CREATE TABLE contact(id INTEGER, username TEXT); "
            "INSERT INTO contact VALUES(1, 'base');",
        )
        _create_reserved_sqlite(
            committed_plain,
            "CREATE TABLE contact(id INTEGER, username TEXT); "
            "INSERT INTO contact VALUES(1, 'base'); "
            "INSERT INTO contact VALUES(2, 'online');",
        )
        encrypted = base / CONTACT_REL
        committed_encrypted = self.root / "online-committed-encrypted.db"
        _encrypt_wechat_fixture(base_plain, encrypted, key, salt=salt)
        _encrypt_wechat_fixture(
            committed_plain,
            committed_encrypted,
            key,
            salt=salt,
        )
        committed_pages = _encrypted_pages(committed_encrypted)
        commit_frame_count = len(committed_pages)
        total_frame_count = _write_wal_transactions(
            encrypted,
            [
                (committed_pages, len(committed_pages)),
                (committed_pages[:1], None),
            ],
        )
        _write_active_wal_shm(
            encrypted,
            max_frame=commit_frame_count,
            database_pages=len(committed_pages),
        )
        shm_path = Path(str(encrypted) + "-shm")
        shm_path.write_bytes(shm_path.read_bytes() + bytes(32 * 1024))
        key_file = self.root / "online-keys.json"
        key_file.write_text(json.dumps({"contact": key.hex()}), encoding="utf-8")
        os.chmod(key_file, 0o600)
        clone_calls: list[Path] = []

        def fixture_cloner(
            source: Path,
            destination: Path,
            expected: FileFingerprint,
        ) -> dict[str, object]:
            clone_calls.append(source)
            return {
                **copy_stable_file_atomic(source, destination, expected),
                "clone_method": "fixture_atomic_copy",
            }

        def forbidden_holder_probe(paths: object) -> object:
            raise AssertionError("online snapshot must not require WeChat to exit")

        report = snapshot_and_decrypt(
            db_base=base,
            output_root=self._private_output(),
            keys_file=key_file,
            databases=["contact"],
            holder_probe=forbidden_holder_probe,
            xwechat_root=self.xwechat_root,
            online=True,
            online_cloner=fixture_cloner,
        )
        record = report["records"][0]
        self.assertEqual(
            report["safety"]["snapshot_mode"],
            "online_sqlite_shm_coordinated_apfs_clone",
        )
        self.assertEqual(
            report["safety"]["wechat_holder_check"],
            "not_required_online_sqlite_coordination_locks",
        )
        self.assertEqual(
            record["online_wal_anchor"]["mx_frame"],
            commit_frame_count,
        )
        self.assertEqual(
            record["wal_validation"]["last_commit_frame"],
            commit_frame_count,
        )
        self.assertEqual(
            record["wal_validation"]["valid_frames"],
            total_frame_count,
        )
        self.assertEqual(
            record["wal_validation"]["ignored_uncommitted_frames"],
            1,
        )
        self.assertEqual(record["shm_state"], "locked_live_index_not_copied")
        self.assertEqual(len(clone_calls), 2)
        run = Path(report["run_directory"])
        self.assertFalse(Path(str(run / "encrypted" / CONTACT_REL) + "-shm").exists())
        with sqlite3.connect(run / "decrypted" / CONTACT_REL) as connection:
            rows = connection.execute(
                "SELECT id, username FROM contact ORDER BY id"
            ).fetchall()
        self.assertEqual(rows, [(1, "base"), (2, "online")])

    @unittest.skipUnless(
        sys.platform == "darwin" and hasattr(fcntl, "F_OFD_SETLK"),
        "Darwin OFD lock semantics",
    )
    def test_online_ofd_lock_survives_unrelated_close_and_releases(self) -> None:
        base = self._db_base("ofd_lock")
        database = base / CONTACT_REL
        database.write_bytes(bytes(PAGE_SIZE))
        shm = Path(str(database) + "-shm")
        shm.write_bytes(bytes(32 * 1024))
        fingerprint = FileFingerprint.from_stat(database.lstat())
        locks = acquire_online_wal_locks(
            {CONTACT_REL: (database, fingerprint)},
            timeout_seconds=0,
        )
        unrelated = os.open(shm, os.O_RDONLY)
        os.close(unrelated)
        probe = (
            "import fcntl,os,sys\n"
            "fd=os.open(sys.argv[1],os.O_RDWR)\n"
            "try:\n"
            "  try:\n"
            "    fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB,3,120,os.SEEK_SET)\n"
            "  except OSError:\n"
            "    print('busy')\n"
            "  else:\n"
            "    print('acquired')\n"
            "    fcntl.lockf(fd,fcntl.LOCK_UN,3,120,os.SEEK_SET)\n"
            "finally:\n"
            "  os.close(fd)\n"
        )
        held = subprocess.run(
            [sys.executable, "-c", probe, str(shm)],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(held.stdout.strip(), "busy")
        locks.release()
        released = subprocess.run(
            [sys.executable, "-c", probe, str(shm)],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(released.stdout.strip(), "acquired")

    def test_online_snapshot_rejects_shm_wal_commit_mismatch(self) -> None:
        base = self._db_base("online_mismatch")
        key = bytes([0x73]) * 32
        salt = bytes.fromhex("102132435465768798a9bacbdcedfe0f")
        plain = self.root / "online-mismatch.db"
        _create_reserved_sqlite(
            plain,
            "CREATE TABLE contact(id INTEGER, username TEXT); "
            "INSERT INTO contact VALUES(1, 'fixture');",
        )
        encrypted = base / CONTACT_REL
        _encrypt_wechat_fixture(plain, encrypted, key, salt=salt)
        pages = _encrypted_pages(encrypted)
        frame_count = _write_wal_transactions(
            encrypted,
            [(pages, len(pages))],
        )
        _write_active_wal_shm(
            encrypted,
            max_frame=frame_count,
            database_pages=len(pages) + 1,
        )
        key_file = self.root / "online-mismatch-keys.json"
        key_file.write_text(json.dumps({"contact": key.hex()}), encoding="utf-8")
        os.chmod(key_file, 0o600)
        output = self._private_output()
        with self.assertRaisesRegex(
            OnlineSnapshotUnavailable,
            "数据库页数与在线 SHM 不一致",
        ):
            snapshot_and_decrypt(
                db_base=base,
                output_root=output,
                keys_file=key_file,
                databases=["contact"],
                holder_probe=lambda paths: [],
                xwechat_root=self.xwechat_root,
                online=True,
                online_cloner=copy_stable_file_atomic,
            )
        self.assertFalse(list(output.glob("**/manifest.json")))

    def test_online_lock_failure_creates_no_run(self) -> None:
        base = self._db_base("online_lock_failure")
        key = bytes([0x74]) * 32
        self._create_encrypted_contact(
            base,
            key=key,
            salt=bytes.fromhex("11223344556677889900aabbccddeeff"),
            fixture_name="online-lock-failure",
        )
        key_file = self.root / "online-lock-failure-keys.json"
        key_file.write_text(json.dumps({"contact": key.hex()}), encoding="utf-8")
        os.chmod(key_file, 0o600)
        output = self._private_output()
        with mock.patch(
            "live_tools.wechat_safe_snapshot.acquire_online_wal_locks",
            side_effect=OnlineSnapshotUnavailable("fixture lock busy"),
        ):
            with self.assertRaisesRegex(
                OnlineSnapshotUnavailable,
                "fixture lock busy",
            ):
                snapshot_and_decrypt(
                    db_base=base,
                    output_root=output,
                    keys_file=key_file,
                    databases=["contact"],
                    holder_probe=lambda paths: [],
                    xwechat_root=self.xwechat_root,
                    online=True,
                    online_cloner=copy_stable_file_atomic,
                )
        self.assertFalse(list(output.glob("**/run-*")))

    def test_current_generation_wal_checksum_corruption_is_rejected(self) -> None:
        database = self.root / "checksum.db"
        database.write_bytes(os.urandom(PAGE_SIZE * 2))
        frame_page = os.urandom(PAGE_SIZE)
        _write_wal_transactions(
            database,
            [([(2, frame_page)], 2)],
        )
        wal = Path(str(database) + "-wal")
        raw = bytearray(wal.read_bytes())
        raw[32 + 24 + 127] ^= 0x01
        wal.write_bytes(raw)
        with self.assertRaisesRegex(SnapshotError, "frame checksum"):
            scan_copied_wal_for_replay(wal, database_pages=2)
        destination = self._private_output() / "corrupt.db"
        with self.assertRaisesRegex(SnapshotError, "frame checksum"):
            materialize_copied_database_with_wal(
                database,
                wal,
                destination,
            )
        self.assertFalse(destination.exists())

    def test_stream_copy_is_private_atomic_and_detects_changed_source(self) -> None:
        source = self.root / "source.db"
        source.write_bytes(os.urandom(PAGE_SIZE * 2))
        expected = FileFingerprint.from_stat(source.lstat())
        destination = self._private_output() / "snapshot/source.db"
        report = copy_stable_file_atomic(source, destination, expected)
        self.assertEqual(report["bytes"], PAGE_SIZE * 2)
        self.assertEqual(report["sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
        self.assertFalse(list(destination.parent.glob("*.partial")))

        source.write_bytes(source.read_bytes() + b"changed")
        with self.assertRaisesRegex(SnapshotError, "发生变化"):
            copy_stable_file_atomic(
                source, self._private_output() / "snapshot/changed.db", expected
            )

    @unittest.skipUnless(sys.platform == "darwin", "APFS clone is macOS-only")
    def test_apfs_clone_is_private_and_byte_exact(self) -> None:
        source = self.root / "clone-source.db"
        source.write_bytes(os.urandom(PAGE_SIZE * 2))
        expected = FileFingerprint.from_stat(source.lstat())
        destination = self._private_output() / "clone/output.db"
        report = apfs_clone_file_atomic(source, destination, expected)
        self.assertEqual(report["clone_method"], "apfs_fclonefileat")
        self.assertEqual(destination.read_bytes(), source.read_bytes())
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)

    def test_cross_account_and_wrong_key_fail_before_any_run_directory(self) -> None:
        base_a = self._db_base("account_a")
        base_b = self._db_base("account_b")
        key_a = bytes([0x31]) * 32
        key_b = bytes([0x42]) * 32
        ref_a = self._create_encrypted_contact(
            base_a,
            key=key_a,
            salt=bytes.fromhex("00112233445566778899aabbccddeeff"),
            fixture_name="account-a",
        )
        ref_b = self._create_encrypted_contact(
            base_b,
            key=key_b,
            salt=bytes.fromhex("ffeeddccbbaa99887766554433221100"),
            fixture_name="account-b",
        )
        self.assertNotEqual(ref_a, ref_b)

        state_root = self._private_state_root()
        legacy_keys = state_root / KEYS_FILENAME
        legacy_config = state_root / CONFIG_FILENAME
        self._write_private_json(legacy_keys, {"contact": key_a.hex()})
        self._write_private_json(
            legacy_config,
            {
                "schema_version": 1,
                "db_base_path": str(base_a),
                "keys_file": str(legacy_keys),
                "targets": {"contact": CONTACT_REL},
            },
        )
        output = self._private_output()

        with self.assertRaisesRegex(SnapshotError, "另一个微信账号"):
            snapshot_and_decrypt(
                db_base=base_b,
                output_root=output,
                keys_file=legacy_keys,
                databases=["contact"],
                holder_probe=lambda paths: [],
                xwechat_root=self.xwechat_root,
                account_ref=ref_b,
                private_root=state_root,
            )
        self.assertFalse(list(output.glob("**/run-*")))

        # Even a configuration accidentally rewritten for B cannot make A's
        # actual key material pass the first-page proof.
        self._write_private_json(
            legacy_config,
            {
                "schema_version": 1,
                "db_base_path": str(base_b),
                "keys_file": str(legacy_keys),
                "targets": {"contact": CONTACT_REL},
            },
        )
        with self.assertRaisesRegex(SnapshotError, "密钥与目标数据库不匹配"):
            snapshot_and_decrypt(
                db_base=base_b,
                output_root=output,
                keys_file=legacy_keys,
                databases=["contact"],
                holder_probe=lambda paths: [],
                xwechat_root=self.xwechat_root,
                account_ref=ref_b,
                private_root=state_root,
            )
        self.assertFalse(list(output.glob("**/run-*")))

        external = self.root / "external-state"
        external.mkdir(mode=0o700)
        external_keys = external / KEYS_FILENAME
        self._write_private_json(external_keys, {"contact": key_b.hex()})
        self._write_private_json(
            external / CONFIG_FILENAME,
            {
                "schema_version": 2,
                "account_ref": ref_b,
                "db_base_path": str(base_b),
                "keys_file": str(external_keys),
                "targets": {"contact": CONTACT_REL},
                "salt_fingerprints": {
                    "contact": hashlib.sha256(
                        (base_b / CONTACT_REL).read_bytes()[:16]
                    ).hexdigest()
                },
            },
        )
        with self.assertRaisesRegex(SnapshotError, "scoped keys-file"):
            snapshot_and_decrypt(
                db_base=base_b,
                output_root=output,
                keys_file=external_keys,
                databases=["contact"],
                holder_probe=lambda paths: [],
                xwechat_root=self.xwechat_root,
                account_ref=ref_b,
                private_root=state_root,
            )
        self.assertFalse(list(output.glob("**/run-*")))

    def test_strict_snapshot_is_account_scoped_and_manifest_is_redacted(self) -> None:
        base = self._db_base("account_scoped")
        key = bytes([0x53]) * 32
        salt = bytes.fromhex("102132435465768798a9bacbdcedfe0f")
        account_ref = self._create_encrypted_contact(
            base,
            key=key,
            salt=salt,
            fixture_name="account-scoped",
        )
        state_root = self._private_state_root()
        keys_file = self._write_schema2_account_state(
            private_root=state_root,
            account_ref=account_ref,
            base=base,
            key_hex=key.hex(),
        )
        output = self._private_output()
        legacy_run = output / "run-legacy-untouched"
        legacy_run.mkdir(mode=0o700)

        report = snapshot_and_decrypt(
            db_base=base,
            output_root=output,
            keys_file=None,
            databases=["contact"],
            holder_probe=lambda paths: [],
            xwechat_root=self.xwechat_root,
            account_ref=account_ref,
            private_root=state_root,
        )

        run = Path(report["run_directory"])
        self.assertEqual(run.parent, output / account_ref)
        self.assertTrue(legacy_run.is_dir())
        self.assertEqual(report["schema_version"], 2)
        self.assertEqual(
            report["account_binding"],
            {
                "mode": "strict_account_ref",
                "account_ref": account_ref,
                "contact_salt_reference": "matched",
                "key_binding": "schema2_scoped_config",
                "config_schema_version": 2,
                "requested_key_first_page_validation": "passed_before_run_creation",
                "output_scope": "account_ref",
            },
        )
        manifest_text = Path(report["manifest_path"]).read_text(encoding="utf-8")
        self.assertNotIn(str(base), manifest_text)
        self.assertNotIn(str(keys_file), manifest_text)
        self.assertNotIn(key.hex(), manifest_text)
        self.assertNotIn(salt.hex(), manifest_text)

    def test_missing_scoped_keys_automatically_uses_exact_schema1_legacy_state(
        self,
    ) -> None:
        base = self._db_base("legacy_auto_account")
        key = bytes([0x61]) * 32
        account_ref = self._create_encrypted_contact(
            base,
            key=key,
            salt=bytes.fromhex("ab01cd23ef4567891032547698badcfe"),
            fixture_name="legacy-auto-account",
        )
        state_root = self._private_state_root()
        self._write_schema1_root_state(
            private_root=state_root,
            base=base,
            key_hex=key.hex(),
        )

        report = snapshot_and_decrypt(
            db_base=base,
            output_root=self._private_output(),
            keys_file=None,
            databases=["contact"],
            holder_probe=lambda paths: [],
            xwechat_root=self.xwechat_root,
            account_ref=account_ref,
            private_root=state_root,
        )

        self.assertEqual(
            report["account_binding"]["key_binding"],
            "legacy_schema1_exact_path",
        )
        self.assertEqual(
            report["account_binding"]["config_schema_version"],
            1,
        )

    def test_scoped_keys_take_priority_over_valid_schema1_legacy_state(self) -> None:
        base = self._db_base("scoped_priority_account")
        key = bytes([0x62]) * 32
        account_ref = self._create_encrypted_contact(
            base,
            key=key,
            salt=bytes.fromhex("bc12de34f056789a21436587a9cbed0f"),
            fixture_name="scoped-priority-account",
        )
        state_root = self._private_state_root()
        self._write_schema1_root_state(
            private_root=state_root,
            base=base,
            key_hex=key.hex(),
        )
        self._write_schema2_account_state(
            private_root=state_root,
            account_ref=account_ref,
            base=base,
            key_hex=key.hex(),
        )

        report = snapshot_and_decrypt(
            db_base=base,
            output_root=self._private_output(),
            keys_file=None,
            databases=["contact"],
            holder_probe=lambda paths: [],
            xwechat_root=self.xwechat_root,
            account_ref=account_ref,
            private_root=state_root,
        )

        self.assertEqual(
            report["account_binding"]["key_binding"],
            "schema2_scoped_config",
        )
        self.assertEqual(
            report["account_binding"]["config_schema_version"],
            2,
        )

    def test_invalid_existing_scoped_keys_never_fall_back_to_legacy(self) -> None:
        base = self._db_base("invalid_scoped_account")
        key = bytes([0x63]) * 32
        account_ref = self._create_encrypted_contact(
            base,
            key=key,
            salt=bytes.fromhex("cd23ef45016789ab32547698badcfe10"),
            fixture_name="invalid-scoped-account",
        )
        state_root = self._private_state_root()
        self._write_schema1_root_state(
            private_root=state_root,
            base=base,
            key_hex=key.hex(),
        )
        scoped_keys = (
            state_root / "accounts" / account_ref / KEYS_FILENAME
        )
        scoped_keys.parent.mkdir(parents=True, mode=0o700)
        os.chmod(state_root / "accounts", 0o700)
        os.chmod(scoped_keys.parent, 0o700)
        scoped_keys.write_text("{not-json", encoding="utf-8")
        os.chmod(scoped_keys, 0o600)
        output = self._private_output()

        with self.assertRaisesRegex(SnapshotError, "keys-file 不是有效"):
            snapshot_and_decrypt(
                db_base=base,
                output_root=output,
                keys_file=None,
                databases=["contact"],
                holder_probe=lambda paths: [],
                xwechat_root=self.xwechat_root,
                account_ref=account_ref,
                private_root=state_root,
            )

        self.assertFalse(list(output.glob("**/run-*")))

    def test_automatic_legacy_candidate_without_sibling_config_fails(self) -> None:
        base = self._db_base("legacy_missing_config_account")
        key = bytes([0x65]) * 32
        account_ref = self._create_encrypted_contact(
            base,
            key=key,
            salt=bytes.fromhex("de34f05612789abc436587a9cbed0f21"),
            fixture_name="legacy-missing-config-account",
        )
        state_root = self._private_state_root()
        self._write_private_json(
            state_root / KEYS_FILENAME,
            {"contact": key.hex()},
        )
        output = self._private_output()

        with self.assertRaisesRegex(
            SnapshotError,
            "非默认 keys-file 缺少 sibling local-vault.json",
        ):
            snapshot_and_decrypt(
                db_base=base,
                output_root=output,
                keys_file=None,
                databases=["contact"],
                holder_probe=lambda paths: [],
                xwechat_root=self.xwechat_root,
                account_ref=account_ref,
                private_root=state_root,
            )

        self.assertFalse(list(output.glob("**/run-*")))

    def test_root_schema1_legacy_binding_remains_read_only_compatible(self) -> None:
        base = self._db_base("legacy_account")
        key = bytes([0x64]) * 32
        account_ref = self._create_encrypted_contact(
            base,
            key=key,
            salt=bytes.fromhex("abcdef0123456789fedcba9876543210"),
            fixture_name="legacy-account",
        )
        state_root = self._private_state_root()
        keys_file = state_root / KEYS_FILENAME
        config_file = state_root / CONFIG_FILENAME
        self._write_private_json(keys_file, {"contact": key.hex()})
        legacy_config = {
            "schema_version": 1,
            "db_base_path": str(base),
            "keys_file": str(keys_file),
            "targets": {"contact": CONTACT_REL},
        }
        self._write_private_json(config_file, legacy_config)

        report = snapshot_and_decrypt(
            db_base=base,
            output_root=self._private_output(),
            keys_file=keys_file,
            databases=["contact"],
            holder_probe=lambda paths: [],
            xwechat_root=self.xwechat_root,
            account_ref=account_ref,
            private_root=state_root,
        )
        self.assertEqual(
            report["account_binding"]["key_binding"],
            "legacy_schema1_exact_path",
        )
        self.assertEqual(json.loads(config_file.read_text()), legacy_config)

    def test_full_snapshot_decrypt_and_manifest_have_no_keys_or_source_paths(self) -> None:
        base = self._db_base()
        fixtures = {
            "contact": (
                "contact/contact.db",
                "CREATE TABLE contact(id INTEGER, username TEXT); "
                "INSERT INTO contact VALUES(1, 'fixture');",
            ),
            "message_0": (
                "message/message_0.db",
                "CREATE TABLE Msg_fixture(server_id INTEGER); "
                "INSERT INTO Msg_fixture VALUES(42);",
            ),
            "media_0": (
                "message/media_0.db",
                "CREATE TABLE VoiceInfo(svr_id INTEGER, voice_data BLOB); "
                "INSERT INTO VoiceInfo VALUES(42, X'0102');",
            ),
            "message_resource": (
                RESOURCE_REL,
                "CREATE TABLE MessageResourceInfo(local_id INTEGER, "
                "packed_info_data BLOB); "
                "INSERT INTO MessageResourceInfo VALUES(42, X'0102');",
            ),
        }
        keys: dict[str, str] = {}
        for index, (alias, (relative, statements)) in enumerate(fixtures.items(), start=1):
            key = bytes([index]) * 32
            keys[alias] = key.hex()
            plain = self.root / "plain" / f"{alias}.db"
            plain.parent.mkdir(exist_ok=True)
            _create_reserved_sqlite(plain, statements)
            _encrypt_wechat_fixture(plain, base / relative, key)
            if alias == "message_0":
                _write_logical_empty_wal_sidecars(base / relative)

        key_file = self.root / "keys.json"
        key_file.write_text(json.dumps(keys), encoding="utf-8")
        os.chmod(key_file, 0o600)
        output = self._private_output()
        report = snapshot_and_decrypt(
            db_base=base,
            output_root=output,
            keys_file=key_file,
            databases=["contact", "message_0", "media_0", "message_resource"],
            holder_probe=lambda paths: [],
            xwechat_root=self.xwechat_root,
        )
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["database_count"], 4)
        self.assertFalse(report["safety"]["page_hmac_verified"])

        manifest_path = Path(report["manifest_path"])
        manifest_text = manifest_path.read_text(encoding="utf-8")
        self.assertNotIn(str(base), manifest_text)
        self.assertNotIn(str(key_file), manifest_text)
        for key_hex in keys.values():
            self.assertNotIn(key_hex, manifest_text)
        self.assertEqual(stat.S_IMODE(manifest_path.stat().st_mode), 0o600)

        run = Path(report["run_directory"])
        message_record = next(
            item for item in report["records"]
            if item["database"] == "message/message_0.db"
        )
        self.assertEqual(message_record["wal_gate"], "logical_empty_preallocated")
        self.assertEqual(message_record["wal_validation"]["wal_frames_applied"], 0)
        self.assertTrue(
            (run / "encrypted/message/message_0.db-wal").is_file()
        )
        self.assertTrue(
            (run / "encrypted/message/message_0.db-shm").is_file()
        )
        for _, (relative, _) in fixtures.items():
            encrypted = run / "encrypted" / relative
            decrypted = run / "decrypted" / relative
            self.assertTrue(encrypted.is_file())
            self.assertTrue(decrypted.is_file())
            self.assertEqual(stat.S_IMODE(encrypted.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(decrypted.stat().st_mode), 0o600)
            with sqlite3.connect(decrypted) as connection:
                self.assertEqual(connection.execute("PRAGMA quick_check").fetchone()[0], "ok")

    def test_expected_table_gate_prevents_plaintext_publication(self) -> None:
        base = self._db_base()
        key = bytes([9]) * 32
        plain = self.root / "wrong-contact.db"
        _create_reserved_sqlite(plain, "CREATE TABLE wrong_table(id INTEGER);")
        _encrypt_wechat_fixture(plain, base / CONTACT_REL, key)
        key_file = self.root / "keys.json"
        key_file.write_text(json.dumps({"contact": key.hex()}), encoding="utf-8")
        os.chmod(key_file, 0o600)
        output = self._private_output()
        with self.assertRaisesRegex(SnapshotError, "预期表"):
            snapshot_and_decrypt(
                db_base=base,
                output_root=output,
                keys_file=key_file,
                databases=["contact"],
                holder_probe=lambda paths: [],
                xwechat_root=self.xwechat_root,
            )
        runs = list(output.glob("run-*"))
        self.assertEqual(len(runs), 1)
        self.assertFalse((runs[0] / "decrypted/contact/contact.db").exists())


if __name__ == "__main__":
    unittest.main()
