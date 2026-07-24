from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest

from direct_vault.direct_voice_vault import VaultError
from content_vault.attachment_resolver import (
    copy_verified_file,
    resolve_regular_file,
    resolve_sticker,
    safe_basename,
)


class AttachmentResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.account = self.base / "account"
        self.account.mkdir()
        self.timestamp = 1_704_067_200  # 2024-01-01 in Asia/Shanghai or nearby.

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_safe_basename_rejects_traversal(self) -> None:
        for value in ("../x", "a/b", "a\\b", "\x00bad", ".."):
            with self.assertRaises(VaultError):
                safe_basename(value)

    def test_file_requires_hash_evidence_for_resolved(self) -> None:
        directory = self.account / "msg/file/2024-01"
        directory.mkdir(parents=True)
        payload = b"fixture-file"
        source = directory / "report.pdf"
        source.write_bytes(payload)
        metadata = resolve_regular_file(
            self.account, self.timestamp, "report.pdf", expected_size=len(payload)
        )
        self.assertEqual(metadata.status, "metadata_only")
        resolved = resolve_regular_file(
            self.account,
            self.timestamp,
            "report.pdf",
            expected_size=len(payload),
            expected_md5=hashlib.md5(payload).hexdigest(),
        )
        self.assertEqual(resolved.status, "resolved")
        self.assertEqual(resolved.source, source.resolve())

    def test_sticker_exact_md5_and_magic(self) -> None:
        payload = b"GIF89a" + b"fixture-sticker"
        md5_value = hashlib.md5(payload).hexdigest()
        directory = self.account / "business/emoticon/Persist/aa"
        directory.mkdir(parents=True)
        (directory / md5_value).write_bytes(payload)
        resolved = resolve_sticker(self.account, self.timestamp, md5_value)
        self.assertEqual(resolved.status, "resolved")
        self.assertEqual(resolved.metadata["format"], "gif")

    def test_symlink_is_not_accepted(self) -> None:
        outside = self.base / "outside"
        outside.write_bytes(b"outside")
        directory = self.account / "msg/file/2024-01"
        directory.mkdir(parents=True)
        (directory / "link.txt").symlink_to(outside)
        result = resolve_regular_file(self.account, self.timestamp, "link.txt")
        self.assertEqual(result.status, "missing")

    def test_verified_copy_has_private_mode_and_hash(self) -> None:
        source = self.base / "source.bin"
        payload = b"copy-me"
        source.write_bytes(payload)
        destination = self.base / "out/copy.bin"
        report = copy_verified_file(
            source, destination, hashlib.sha256(payload).hexdigest()
        )
        self.assertEqual(report["byte_count"], len(payload))
        self.assertEqual(destination.read_bytes(), payload)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
