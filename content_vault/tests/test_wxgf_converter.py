from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from content_vault.wxgf_converter import (
    WXGFConversionError,
    convert_wxgf_to_jpeg,
    discover_ffmpeg,
    find_annex_b_start,
)


class WXGFConverterTests(unittest.TestCase):
    def test_annex_b_start_supports_three_and_four_byte_markers(self) -> None:
        self.assertEqual(find_annex_b_start(b"wxgf-meta\x00\x00\x00\x01nal"), 9)
        self.assertEqual(find_annex_b_start(b"wxgf\x00\x00\x01nal"), 4)
        with self.assertRaises(WXGFConversionError):
            find_annex_b_start(b"wxgf-no-stream")

    def test_converter_uses_argv_and_validates_jpeg(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "ffmpeg"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o700)

            def fake_run(arguments, **kwargs):
                self.assertIsInstance(arguments, list)
                Path(arguments[-1]).write_bytes(b"\xff\xd8\xff\xe0\xff\xd9")

                class Result:
                    returncode = 0
                    stdout = ""
                    stderr = ""

                return Result()

            with patch("content_vault.wxgf_converter.subprocess.run", side_effect=fake_run):
                jpeg = convert_wxgf_to_jpeg(
                    b"wxgf-metadata\x00\x00\x00\x01hevc", ffmpeg_bin=executable
                )
            self.assertEqual(jpeg, b"\xff\xd8\xff\xe0\xff\xd9")

    def test_invalid_input_is_rejected_before_running_a_tool(self) -> None:
        with self.assertRaises(WXGFConversionError):
            convert_wxgf_to_jpeg(b"not-wxgf")

    def test_discovery_never_trusts_an_ffmpeg_from_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "ffmpeg"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o700)
            with patch.dict(sys.modules, {"imageio_ffmpeg": None}):
                with patch.dict(os.environ, {"PATH": temporary}):
                    self.assertIsNone(discover_ffmpeg())


if __name__ == "__main__":
    unittest.main()
