"""Convert a decrypted wxgf HEVC payload into one validated JPEG frame."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import tempfile
from typing import Optional, Union

from content_vault.image_crypto import ImageDecodeError, detect_image_format


MAX_WXGF_BYTES = 512 * 1024 * 1024
MAX_FFMPEG_OUTPUT_CHARS = 4_000


class WXGFConversionError(ImageDecodeError):
    pass


def find_annex_b_start(data: bytes) -> int:
    positions = [
        position
        for marker in (b"\x00\x00\x00\x01", b"\x00\x00\x01")
        if (position := data.find(marker)) >= 0
    ]
    if not positions:
        raise WXGFConversionError("wxgf payload does not contain an Annex-B HEVC stream")
    return min(positions)


def discover_ffmpeg() -> Optional[Path]:
    candidates: list[Path] = []
    try:
        import imageio_ffmpeg  # type: ignore[import-not-found]

        candidates.append(Path(imageio_ffmpeg.get_ffmpeg_exe()))
    except (ImportError, ModuleNotFoundError, RuntimeError, OSError):
        pass
    for candidate in candidates:
        try:
            resolved = candidate.expanduser().resolve(strict=True)
            info = resolved.stat()
        except OSError:
            continue
        if stat.S_ISREG(info.st_mode) and os.access(resolved, os.X_OK):
            return resolved
    return None


def convert_wxgf_to_jpeg(
    data: bytes,
    *,
    ffmpeg_bin: Optional[Union[str, Path]] = None,
    timeout_seconds: int = 30,
) -> bytes:
    if not isinstance(data, bytes) or not data.startswith(b"wxgf"):
        raise WXGFConversionError("input is not a decrypted wxgf payload")
    if len(data) <= 4 or len(data) > MAX_WXGF_BYTES:
        raise WXGFConversionError("wxgf payload size is outside the safe range")
    start = find_annex_b_start(data)
    if ffmpeg_bin is None:
        executable = discover_ffmpeg()
    else:
        requested = Path(ffmpeg_bin).expanduser()
        try:
            executable = requested.resolve(strict=True)
            info = executable.stat()
        except OSError as error:
            raise WXGFConversionError("ffmpeg helper is unavailable") from error
        if not stat.S_ISREG(info.st_mode) or not os.access(executable, os.X_OK):
            raise WXGFConversionError("ffmpeg helper is not executable")
    if executable is None:
        raise WXGFConversionError(
            "wxgf conversion requires imageio-ffmpeg; run scripts/setup_content_tools.sh"
        )

    with tempfile.TemporaryDirectory(prefix="wechat-wxgf-") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        hevc_path = root / "frame.h265"
        jpeg_path = root / "frame.jpg"
        with hevc_path.open("xb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(data[start:])
            handle.flush()
            os.fsync(handle.fileno())
        try:
            completed = subprocess.run(
                [
                    str(executable),
                    "-nostdin",
                    "-hide_banner",
                    "-v",
                    "error",
                    "-f",
                    "hevc",
                    "-i",
                    str(hevc_path),
                    "-map",
                    "0:v:0",
                    "-frames:v",
                    "1",
                    "-y",
                    str(jpeg_path),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise WXGFConversionError("wxgf frame conversion did not complete") from error
        if completed.returncode != 0 or not jpeg_path.is_file():
            detail = (completed.stderr or completed.stdout or "no diagnostic output").strip()
            if len(detail) > MAX_FFMPEG_OUTPUT_CHARS:
                detail = detail[-MAX_FFMPEG_OUTPUT_CHARS:]
            raise WXGFConversionError(f"wxgf frame conversion failed: {detail}")
        jpeg = jpeg_path.read_bytes()
        try:
            image_format = detect_image_format(jpeg)
        except ImageDecodeError as error:
            raise WXGFConversionError("wxgf converter output is not a valid image") from error
        if image_format != "jpg":
            raise WXGFConversionError("wxgf converter did not output JPEG")
        return jpeg


__all__ = [
    "WXGFConversionError",
    "convert_wxgf_to_jpeg",
    "discover_ffmpeg",
    "find_annex_b_start",
]
