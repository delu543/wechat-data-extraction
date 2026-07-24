from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INSTALLER = PROJECT_ROOT / "scripts" / "setup_key_init_tools.sh"
REQUIREMENTS = PROJECT_ROOT / "scripts" / "requirements-key-init.txt"


class SetupKeyInitToolsTests(unittest.TestCase):
    def _new_home(self, root: Path) -> Path:
        home = root / "home"
        home.mkdir(mode=0o700)
        return home

    def _run_installer(self, home: Path) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["HOME"] = str(home)
        return subprocess.run(
            ["/bin/zsh", str(INSTALLER)],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

    def test_requirements_are_binary_only_hash_pinned_for_supported_macos(self) -> None:
        text = REQUIREMENTS.read_text(encoding="utf-8")
        self.assertIn("frida==17.16.4", text)
        self.assertIn("pycryptodome==3.23.0", text)
        self.assertIn("typing-extensions==4.16.0", text)
        self.assertEqual(text.count("--hash=sha256:"), 5)
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("--require-hashes", installer)
        self.assertIn("--only-binary=:all:", installer)
        self.assertIn("--isolated", installer)
        self.assertIn("--index-url https://pypi.org/simple", installer)
        self.assertIn("--no-deps", installer)
        self.assertIn("--no-cache-dir", installer)
        self.assertNotIn('"frida==17.16.4"', installer)

    def test_installer_rejects_symlinked_support_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="key-init-symlink-test.") as temporary:
            root = Path(temporary)
            home = self._new_home(root)
            target = root / "target"
            target.mkdir(mode=0o700)
            (home / "Library").symlink_to(target, target_is_directory=True)
            result = self._run_installer(home)
            self.assertEqual(result.returncode, 2)
            self.assertIn("symbolic-link support-directory ancestor", result.stderr)

    def test_installer_rejects_wide_private_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="key-init-mode-test.") as temporary:
            home = self._new_home(Path(temporary))
            library = home / "Library"
            app_support = library / "Application Support"
            product = app_support / "WeChatLocalExport"
            private = product / "key-init-tools"
            library.mkdir(mode=0o700)
            app_support.mkdir(mode=0o700)
            product.mkdir(mode=0o700)
            private.mkdir(mode=0o755)
            result = self._run_installer(home)
            self.assertEqual(result.returncode, 2)
            self.assertIn("must have mode 0700", result.stderr)

    def test_installer_refuses_existing_environment_before_install(self) -> None:
        with tempfile.TemporaryDirectory(prefix="key-init-existing-test.") as temporary:
            home = self._new_home(Path(temporary))
            library = home / "Library"
            app_support = library / "Application Support"
            product = app_support / "WeChatLocalExport"
            private = product / "key-init-tools"
            environment = private / "python"
            library.mkdir(mode=0o700)
            app_support.mkdir(mode=0o700)
            product.mkdir(mode=0o700)
            private.mkdir(mode=0o700)
            environment.mkdir(mode=0o700)
            result = self._run_installer(home)
            self.assertEqual(result.returncode, 2)
            self.assertIn("refusing to overwrite", result.stderr)

    def test_installer_uses_exclusive_atomic_publish_and_exact_cleanup(self) -> None:
        text = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("umask 077", text)
        self.assertIn("renamex_np", text)
        self.assertIn("RENAME_EXCL = 0x00000004", text)
        self.assertIn('"$TASK_SUPPORT_ROOT"/.python.install.*', text)
        self.assertNotIn('rm -rf -- "$TASK_SUPPORT_ROOT"', text)


if __name__ == "__main__":
    unittest.main()
