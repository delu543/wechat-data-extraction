from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from content_vault.profile import (
    ACCOUNT_PROFILE_SCHEMA_VERSION,
    MAX_ACCOUNT_PROFILES,
    MAX_PROFILE_BYTES,
    ProfileError,
    list_account_profile_refs,
    load_account_profile,
    load_profile,
    write_account_profile,
    write_profile,
)


class ProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / "private" / "profile.json"
        self.profiles_dir = self.root / "private" / "profiles"
        self.account_ref = "account-0123456789ab"
        self.profile = {
            "schema_version": 1,
            "vault_dir": "/private/vault",
            "account_root": "/private/account",
            "swift_bin": None,
        }
        self.account_profile = {
            "schema_version": ACCOUNT_PROFILE_SCHEMA_VERSION,
            "account_ref": self.account_ref,
            "vault_dir": "/private/vault",
            "account_root": "/private/account",
            "swift_bin": None,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _raw_profile(self, value: object, *, mode: int = 0o600) -> Path:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path.write_text(json.dumps(value), encoding="utf-8")
        self.path.chmod(mode)
        return self.path

    def _raw_account_profile(
        self,
        value: object,
        *,
        account_ref: str | None = None,
        mode: int = 0o600,
    ) -> Path:
        selected = account_ref or self.account_ref
        self.profiles_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.profiles_dir.chmod(0o700)
        path = self.profiles_dir / f"{selected}.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        path.chmod(mode)
        return path

    def test_round_trip_is_private_and_atomic(self) -> None:
        result = write_profile(self.profile, self.path)

        self.assertEqual(result, self.path)
        self.assertEqual(load_profile(self.path), self.profile)
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(list(self.path.parent.glob("*.partial")), [])

    def test_swift_binary_accepts_an_absolute_path(self) -> None:
        expected = dict(self.profile, swift_bin="/usr/bin/swift")
        write_profile(expected, self.path)
        self.assertEqual(load_profile(self.path), expected)

    def test_existing_regular_profile_is_replaced(self) -> None:
        write_profile(self.profile, self.path)
        updated = dict(self.profile, vault_dir="/new/vault")
        write_profile(updated, self.path)
        self.assertEqual(load_profile(self.path), updated)

    def test_invalid_profile_does_not_create_parent(self) -> None:
        invalid = dict(self.profile, vault_dir="relative/path")
        with self.assertRaises(ProfileError):
            write_profile(invalid, self.path)
        self.assertFalse(self.path.parent.exists())

    def test_rejects_missing_extra_and_credential_fields(self) -> None:
        cases = [
            {key: value for key, value in self.profile.items() if key != "swift_bin"},
            dict(self.profile, extra="value"),
            dict(self.profile, key="do-not-store"),
            dict(self.profile, secret="do-not-store"),
            dict(self.profile, token="do-not-store"),
        ]
        for case in cases:
            with self.subTest(fields=tuple(case)):
                with self.assertRaises(ProfileError):
                    write_profile(case, self.path)

    def test_rejects_wrong_schema_and_non_absolute_paths(self) -> None:
        cases = [
            dict(self.profile, schema_version=2),
            dict(self.profile, schema_version=True),
            dict(self.profile, vault_dir="vault"),
            dict(self.profile, account_root="../account"),
            dict(self.profile, swift_bin="bin/swift"),
            dict(self.profile, swift_bin=7),
        ]
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(ProfileError):
                    write_profile(case, self.path)

    def test_load_rejects_extra_or_credential_fields(self) -> None:
        for field in ("extra", "key", "secret", "token"):
            with self.subTest(field=field):
                self._raw_profile(dict(self.profile, **{field: "hidden"}))
                with self.assertRaises(ProfileError):
                    load_profile(self.path)

    def test_load_rejects_duplicate_json_fields(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True)
        self.path.write_text(
            '{"schema_version":1,"schema_version":1,'
            '"vault_dir":"/v","account_root":"/a","swift_bin":null}',
            encoding="utf-8",
        )
        self.path.chmod(0o600)
        with self.assertRaises(ProfileError):
            load_profile(self.path)

    def test_load_rejects_symlink(self) -> None:
        source = self.root / "source.json"
        source.write_text(json.dumps(self.profile), encoding="utf-8")
        source.chmod(0o600)
        self.path.parent.mkdir(mode=0o700, parents=True)
        self.path.symlink_to(source)
        with self.assertRaises(ProfileError):
            load_profile(self.path)

    def test_write_does_not_replace_symlink(self) -> None:
        source = self.root / "source.json"
        source.write_text("sentinel", encoding="utf-8")
        self.path.parent.mkdir(mode=0o700, parents=True)
        self.path.symlink_to(source)

        with self.assertRaises(ProfileError):
            write_profile(self.profile, self.path)
        self.assertTrue(self.path.is_symlink())
        self.assertEqual(source.read_text(encoding="utf-8"), "sentinel")

    def test_write_rejects_symlink_parent(self) -> None:
        actual = self.root / "actual"
        actual.mkdir(mode=0o700)
        linked = self.root / "linked"
        linked.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(ProfileError):
            write_profile(self.profile, linked / "profile.json")
        self.assertFalse((actual / "profile.json").exists())

    def test_load_rejects_group_other_execute_and_special_permissions(self) -> None:
        # macOS silently clears setuid/setgid on ordinary test files, while the
        # sticky bit is preserved and still exercises rejection of special
        # permission bits.
        for mode in (0o640, 0o604, 0o700, 0o1600):
            with self.subTest(mode=oct(mode)):
                self._raw_profile(self.profile, mode=mode)
                with self.assertRaises(ProfileError):
                    load_profile(self.path)

    def test_load_accepts_read_only_0400_profile(self) -> None:
        self._raw_profile(self.profile, mode=0o400)
        self.assertEqual(load_profile(self.path), self.profile)

    def test_load_rejects_oversized_file(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True)
        self.path.write_bytes(b"x" * (MAX_PROFILE_BYTES + 1))
        self.path.chmod(0o600)
        with self.assertRaises(ProfileError):
            load_profile(self.path)

    def test_default_path_uses_private_application_support_location(self) -> None:
        fake_home = self.root / "home"
        fake_home.mkdir()
        expected = (
            fake_home
            / "Library"
            / "Application Support"
            / "WeChatLocalExport"
            / "profile.json"
        )
        with mock.patch("content_vault.profile.Path.home", return_value=fake_home):
            self.assertEqual(write_profile(self.profile), expected)
            self.assertEqual(load_profile(), self.profile)

    def test_account_profiles_round_trip_independently_and_list_refs(self) -> None:
        second_ref = "account-1123456789ab"
        second_profile = dict(
            self.account_profile,
            account_ref=second_ref,
            vault_dir="/private/second-vault",
            account_root="/private/second-account",
        )

        first_path = write_account_profile(
            self.account_ref, self.account_profile, self.profiles_dir
        )
        second_path = write_account_profile(
            second_ref, second_profile, self.profiles_dir
        )

        self.assertEqual(
            first_path, self.profiles_dir / f"{self.account_ref}.json"
        )
        self.assertEqual(load_account_profile(self.account_ref, self.profiles_dir), self.account_profile)
        self.assertEqual(load_account_profile(second_ref, self.profiles_dir), second_profile)
        self.assertEqual(
            list_account_profile_refs(self.profiles_dir),
            (self.account_ref, second_ref),
        )
        self.assertEqual(stat.S_IMODE(self.profiles_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(first_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(second_path.stat().st_mode), 0o600)

    def test_account_profile_update_is_atomic_and_does_not_touch_other_account(self) -> None:
        second_ref = "account-1123456789ab"
        second_profile = dict(self.account_profile, account_ref=second_ref)
        write_account_profile(self.account_ref, self.account_profile, self.profiles_dir)
        second_path = write_account_profile(second_ref, second_profile, self.profiles_dir)
        second_before = second_path.read_bytes()

        updated = dict(self.account_profile, vault_dir="/private/refreshed-vault")
        write_account_profile(self.account_ref, updated, self.profiles_dir)

        self.assertEqual(load_account_profile(self.account_ref, self.profiles_dir), updated)
        self.assertEqual(second_path.read_bytes(), second_before)
        self.assertEqual(list(self.profiles_dir.glob("*.partial")), [])

    def test_account_profile_write_never_overwrites_legacy_profile(self) -> None:
        legacy_path = write_profile(self.profile, self.path)
        legacy_before = legacy_path.read_bytes()
        legacy_inode = legacy_path.stat().st_ino

        write_account_profile(
            self.account_ref, self.account_profile, self.profiles_dir
        )

        self.assertEqual(legacy_path.read_bytes(), legacy_before)
        self.assertEqual(legacy_path.stat().st_ino, legacy_inode)
        self.assertEqual(load_profile(legacy_path), self.profile)

    def test_account_profile_does_not_implicitly_fall_back_to_legacy(self) -> None:
        write_profile(self.profile, self.path)
        with self.assertRaises(ProfileError):
            load_account_profile(self.account_ref, self.profiles_dir)
        self.assertEqual(list_account_profile_refs(self.profiles_dir), ())

    def test_account_profile_rejects_invalid_reference_and_mismatched_payload(self) -> None:
        invalid_refs = (
            "account-0123456789AB",
            "account-0123456789a",
            "../account-0123456789ab",
            "account-0123456789ab/extra",
            "",
        )
        for account_ref in invalid_refs:
            with self.subTest(account_ref=account_ref):
                with self.assertRaises(ProfileError):
                    write_account_profile(
                        account_ref, self.account_profile, self.profiles_dir
                    )
        self.assertFalse(self.profiles_dir.exists())

        mismatched = dict(
            self.account_profile, account_ref="account-1123456789ab"
        )
        with self.assertRaises(ProfileError):
            write_account_profile(
                self.account_ref, mismatched, self.profiles_dir
            )

    def test_account_profile_rejects_wrong_schema_paths_and_credential_fields(self) -> None:
        cases = (
            dict(self.account_profile, schema_version=1),
            dict(self.account_profile, schema_version=True),
            dict(self.account_profile, vault_dir="relative/vault"),
            dict(self.account_profile, account_root="../account"),
            dict(self.account_profile, swift_bin="relative/bin"),
            dict(self.account_profile, key="do-not-store"),
            dict(self.account_profile, secret="do-not-store"),
            dict(self.account_profile, token="do-not-store"),
        )
        for value in cases:
            with self.subTest(fields=tuple(value)):
                with self.assertRaises(ProfileError):
                    write_account_profile(
                        self.account_ref, value, self.profiles_dir
                    )

    def test_account_profile_load_binds_filename_and_payload_reference(self) -> None:
        mismatched = dict(
            self.account_profile, account_ref="account-1123456789ab"
        )
        self._raw_account_profile(mismatched)
        with self.assertRaises(ProfileError):
            load_account_profile(self.account_ref, self.profiles_dir)

    def test_account_registry_rejects_symlink_and_unsupported_entries(self) -> None:
        actual = self.root / "actual-profiles"
        actual.mkdir(mode=0o700)
        self.profiles_dir.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.profiles_dir.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(ProfileError):
            write_account_profile(
                self.account_ref, self.account_profile, self.profiles_dir
            )
        self.assertEqual(list(actual.iterdir()), [])

        self.profiles_dir.unlink()
        self.profiles_dir.mkdir(mode=0o700)
        (self.profiles_dir / "unexpected.txt").write_text("sentinel", encoding="utf-8")
        (self.profiles_dir / "unexpected.txt").chmod(0o600)
        with self.assertRaises(ProfileError):
            list_account_profile_refs(self.profiles_dir)
        with self.assertRaises(ProfileError):
            write_account_profile(
                self.account_ref, self.account_profile, self.profiles_dir
            )

    def test_account_registry_rejects_public_modes_and_symlink_entries(self) -> None:
        self._raw_account_profile(self.account_profile)
        self.profiles_dir.chmod(0o755)
        with self.assertRaises(ProfileError):
            load_account_profile(self.account_ref, self.profiles_dir)

        self.profiles_dir.chmod(0o700)
        target = self.profiles_dir / f"{self.account_ref}.json"
        target.unlink()
        source = self.root / "source-account-profile.json"
        source.write_text(json.dumps(self.account_profile), encoding="utf-8")
        source.chmod(0o600)
        target.symlink_to(source)
        with self.assertRaises(ProfileError):
            load_account_profile(self.account_ref, self.profiles_dir)

    def test_account_registry_enforces_profile_count_bound(self) -> None:
        self.profiles_dir.mkdir(mode=0o700, parents=True)
        for index in range(MAX_ACCOUNT_PROFILES):
            account_ref = f"account-{index:012x}"
            value = dict(self.account_profile, account_ref=account_ref)
            path = self.profiles_dir / f"{account_ref}.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            path.chmod(0o600)

        overflow_ref = f"account-{MAX_ACCOUNT_PROFILES:012x}"
        with self.assertRaises(ProfileError):
            write_account_profile(
                overflow_ref,
                dict(self.account_profile, account_ref=overflow_ref),
                self.profiles_dir,
            )
        self.assertFalse((self.profiles_dir / f"{overflow_ref}.json").exists())

    def test_default_account_registry_is_separate_from_legacy_profile(self) -> None:
        fake_home = self.root / "home"
        fake_home.mkdir()
        expected = (
            fake_home
            / "Library"
            / "Application Support"
            / "WeChatLocalExport"
            / "profiles"
            / f"{self.account_ref}.json"
        )
        with mock.patch("content_vault.profile.Path.home", return_value=fake_home):
            self.assertEqual(
                write_account_profile(self.account_ref, self.account_profile),
                expected,
            )
            self.assertEqual(load_account_profile(self.account_ref), self.account_profile)
            self.assertFalse(expected.parent.parent.joinpath("profile.json").exists())

    def test_default_account_registry_repairs_owned_support_root_mode(self) -> None:
        fake_home = self.root / "home"
        support_root = (
            fake_home
            / "Library"
            / "Application Support"
            / "WeChatLocalExport"
        )
        support_root.mkdir(mode=0o755, parents=True)
        support_root.chmod(0o755)

        with mock.patch("content_vault.profile.Path.home", return_value=fake_home):
            result = write_account_profile(self.account_ref, self.account_profile)

        self.assertEqual(
            result,
            support_root / "profiles" / f"{self.account_ref}.json",
        )
        self.assertEqual(stat.S_IMODE(support_root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(result.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(result.stat().st_mode), 0o600)

    def test_custom_registry_does_not_repair_public_support_root(self) -> None:
        support_root = self.root / "caller-managed-support"
        profiles_dir = support_root / "profiles"
        support_root.mkdir(mode=0o755)
        support_root.chmod(0o755)

        with self.assertRaisesRegex(
            ProfileError, "profile registry permissions must not exceed 0700"
        ):
            write_account_profile(
                self.account_ref,
                self.account_profile,
                profiles_dir,
            )

        self.assertEqual(stat.S_IMODE(support_root.stat().st_mode), 0o755)
        self.assertFalse(profiles_dir.exists())

    def test_default_account_registry_rejects_symlink_support_root(self) -> None:
        fake_home = self.root / "home"
        application_support = fake_home / "Library" / "Application Support"
        application_support.mkdir(parents=True)
        actual = self.root / "actual-support"
        actual.mkdir(mode=0o755)
        support_root = application_support / "WeChatLocalExport"
        support_root.symlink_to(actual, target_is_directory=True)

        with mock.patch("content_vault.profile.Path.home", return_value=fake_home):
            with self.assertRaisesRegex(
                ProfileError, "profile parent must be a non-symlink directory"
            ):
                write_account_profile(self.account_ref, self.account_profile)

        self.assertTrue(support_root.is_symlink())
        self.assertEqual(stat.S_IMODE(actual.stat().st_mode), 0o755)
        self.assertEqual(list(actual.iterdir()), [])

    def test_default_account_profile_read_does_not_repair_permissions(self) -> None:
        fake_home = self.root / "home"
        support_root = (
            fake_home
            / "Library"
            / "Application Support"
            / "WeChatLocalExport"
        )
        profiles_dir = support_root / "profiles"
        with mock.patch("content_vault.profile.Path.home", return_value=fake_home):
            write_account_profile(self.account_ref, self.account_profile)

        support_root.chmod(0o755)
        with mock.patch("content_vault.profile.Path.home", return_value=fake_home):
            with self.assertRaisesRegex(
                ProfileError, "profile registry permissions must not exceed 0700"
            ):
                load_account_profile(self.account_ref)

        self.assertEqual(stat.S_IMODE(support_root.stat().st_mode), 0o755)
        self.assertTrue(profiles_dir.is_dir())


if __name__ == "__main__":
    unittest.main()
