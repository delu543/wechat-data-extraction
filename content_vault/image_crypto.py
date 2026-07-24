"""Strict, side-effect-free helpers for locating and decoding WeChat images.

The module deliberately does not acquire, print, or persist any key.  Callers
provide key material in memory and decide where (or whether) decoded bytes are
written.  ``wxgf`` payloads are identified but are not converted here.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
from typing import Iterable, Optional, Tuple, Union


BytesLike = Union[bytes, bytearray, memoryview]
PathLike = Union[str, os.PathLike]

PACKED_INFO_MD5_MARKER = b"\x12\x22\x0a\x20"
V1_MAGIC = b"\x07\x08V1\x08\x07"
V2_MAGIC = b"\x07\x08V2\x08\x07"
V1_AES_KEY = b"cfcd208495d565ef"

_HEX_32_RE = re.compile(rb"(?<![0-9A-Fa-f])([0-9A-Fa-f]{32})(?![0-9A-Fa-f])")
_HEX_32_TEXT_RE = re.compile(r"^[0-9A-Fa-f]{32}$")
_MONTH_RE = re.compile(r"^\d{4}-\d{2}$")
_HEADER_SIZE = 15
_AES_BLOCK_SIZE = 16


class ImageCryptoError(Exception):
    """Base error for this module."""


class ImageCandidateError(ImageCryptoError):
    """A candidate image path could not be resolved safely."""


class ImageCandidateNotFoundError(ImageCandidateError):
    """No exact image candidate exists under the requested chat root."""


class ImageCandidateAmbiguityError(ImageCandidateError):
    """Highest-quality candidates disagree byte-for-byte."""


class UnsafeImagePathError(ImageCandidateError):
    """A symlink, path escape, race, or non-regular file was encountered."""


class ImageDecodeError(ImageCryptoError):
    """An encrypted image payload is malformed or cannot be decoded."""


class UnsupportedImageFormatError(ImageDecodeError):
    """Decoded bytes do not form one of the supported image formats."""


class CryptoDependencyError(ImageDecodeError):
    """AES decoding was requested without its optional dependency."""


# Short aliases make the exception names convenient for API consumers while
# retaining the more explicit class names above.
ImageCandidateAmbiguity = ImageCandidateAmbiguityError
ImageCandidateNotFound = ImageCandidateNotFoundError


@dataclass(frozen=True)
class ImageCandidateResolution:
    """The deterministic result of exact candidate resolution.

    ``duplicate_paths`` contains other candidates at the selected quality with
    the same SHA-256. ``lower_quality_paths`` is informational only and never
    makes a higher-quality result ambiguous.
    """

    path: Path
    quality: str
    sha256: str
    duplicate_paths: Tuple[Path, ...] = ()
    lower_quality_paths: Tuple[Path, ...] = ()

    @property
    def duplicates(self) -> Tuple[Path, ...]:
        """Compatibility/readability alias for ``duplicate_paths``."""

        return self.duplicate_paths


ResolvedImageCandidate = ImageCandidateResolution


@dataclass(frozen=True)
class DecodedImage:
    """Decoded bytes plus their validated format and decoder path."""

    data: bytes
    format: str
    decoder: str

    @property
    def is_wxgf(self) -> bool:
        """Whether conversion must be delegated to a wxgf-aware integration."""

        return self.format == "wxgf"


def _as_bytes(value: BytesLike, *, field: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    raise TypeError("{} must be bytes-like".format(field))


def _ordered_unique(values: Iterable[str]) -> Tuple[str, ...]:
    seen = set()
    result = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return tuple(result)


def extract_packed_info_md5_candidates(blob: Optional[BytesLike]) -> Tuple[str, ...]:
    """Return every distinct 32-hex image identifier in encounter order.

    Protobuf-framed values (``12 22 0a 20`` + 32 ASCII hex bytes) are
    authoritative.  Boundary-checked fallback scanning is used only when no
    valid framed value exists.  Results are normalized to lowercase.
    """

    if blob is None:
        return ()
    packed = _as_bytes(blob, field="packed_info")
    if not packed:
        return ()

    marked = []
    cursor = 0
    while True:
        marker_at = packed.find(PACKED_INFO_MD5_MARKER, cursor)
        if marker_at < 0:
            break
        start = marker_at + len(PACKED_INFO_MD5_MARKER)
        candidate = packed[start : start + 32]
        if len(candidate) == 32 and _HEX_32_RE.fullmatch(candidate):
            marked.append(candidate.decode("ascii").lower())
        cursor = marker_at + 1

    if marked:
        return _ordered_unique(marked)

    fallback = (
        match.group(1).decode("ascii").lower()
        for match in _HEX_32_RE.finditer(packed)
    )
    return _ordered_unique(fallback)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _lexists(path: Path) -> bool:
    return os.path.lexists(os.fspath(path))


def _sha256_regular_file(path: Path) -> str:
    """Hash one exact regular file without following a final symlink."""

    try:
        before = os.lstat(os.fspath(path))
    except OSError as exc:
        raise UnsafeImagePathError("candidate cannot be inspected: {}".format(path)) from exc
    if not stat.S_ISREG(before.st_mode):
        raise UnsafeImagePathError("candidate is not a regular file: {}".format(path))

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(os.fspath(path), flags)
    except OSError as exc:
        raise UnsafeImagePathError("candidate cannot be opened safely: {}".format(path)) from exc

    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise UnsafeImagePathError("candidate is not a regular file: {}".format(path))
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise UnsafeImagePathError("candidate changed while it was opened: {}".format(path))
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)

    try:
        after = os.lstat(os.fspath(path))
    except OSError as exc:
        raise UnsafeImagePathError("candidate changed while it was hashed: {}".format(path)) from exc
    if (before.st_dev, before.st_ino, before.st_size) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
    ):
        raise UnsafeImagePathError("candidate changed while it was hashed: {}".format(path))
    return digest.hexdigest()


def resolve_image_candidate(
    chat_root: PathLike,
    image_md5: str,
    *,
    month: Optional[str] = None,
) -> ImageCandidateResolution:
    """Resolve one exact ``<YYYY-MM>/Img/<md5>{,_h,_t}.dat`` candidate.

    Quality order is ``full`` > ``high`` > ``thumbnail``.  Every candidate at
    the winning quality is SHA-256 compared: identical duplicates are accepted
    deterministically, while differing bytes fail closed as ambiguous.
    """

    if not isinstance(image_md5, str) or not _HEX_32_TEXT_RE.fullmatch(image_md5):
        raise ImageCandidateError("image_md5 must contain exactly 32 hexadecimal characters")
    normalized_md5 = image_md5.lower()
    if month is not None and (not isinstance(month, str) or not _MONTH_RE.fullmatch(month)):
        raise ImageCandidateError("month must use the YYYY-MM form")

    requested_root = Path(chat_root).expanduser().absolute()
    if requested_root.is_symlink():
        raise UnsafeImagePathError("chat root must not be a symlink: {}".format(requested_root))
    if not requested_root.exists() or not requested_root.is_dir():
        raise ImageCandidateError("chat root is not a directory: {}".format(requested_root))
    try:
        root = requested_root.resolve(strict=True)
    except OSError as exc:
        raise ImageCandidateError("chat root cannot be resolved: {}".format(requested_root)) from exc

    qualities = (
        ("full", "{}.dat".format(normalized_md5)),
        ("high", "{}_h.dat".format(normalized_md5)),
        ("thumbnail", "{}_t.dat".format(normalized_md5)),
    )
    found = {quality: [] for quality, _ in qualities}

    try:
        month_entries = sorted(root.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        raise ImageCandidateError("chat root cannot be listed: {}".format(root)) from exc

    for month_path in month_entries:
        if not _MONTH_RE.fullmatch(month_path.name):
            continue
        if month is not None and month_path.name != month:
            continue
        if month_path.is_symlink():
            raise UnsafeImagePathError("month directory must not be a symlink: {}".format(month_path))
        if not month_path.is_dir():
            continue

        image_dir = month_path / "Img"
        if not _lexists(image_dir):
            continue
        if image_dir.is_symlink():
            raise UnsafeImagePathError("Img directory must not be a symlink: {}".format(image_dir))
        if not image_dir.is_dir():
            raise UnsafeImagePathError("Img path is not a directory: {}".format(image_dir))

        for quality, filename in qualities:
            candidate = image_dir / filename
            if not _lexists(candidate):
                continue
            if candidate.is_symlink():
                raise UnsafeImagePathError("candidate must not be a symlink: {}".format(candidate))
            try:
                resolved = candidate.resolve(strict=True)
            except OSError as exc:
                raise UnsafeImagePathError("candidate cannot be resolved: {}".format(candidate)) from exc
            if not _is_within(resolved, root):
                raise UnsafeImagePathError("candidate escapes the chat root: {}".format(candidate))
            digest = _sha256_regular_file(candidate)
            found[quality].append((candidate, digest))

    selected_quality = None
    for quality, _ in qualities:
        if found[quality]:
            selected_quality = quality
            break
    if selected_quality is None:
        suffix = " in {}".format(month) if month is not None else ""
        raise ImageCandidateNotFoundError(
            "no exact image candidate for {}{} under {}".format(normalized_md5, suffix, root)
        )

    selected = sorted(found[selected_quality], key=lambda item: os.fspath(item[0]))
    hashes = {digest for _, digest in selected}
    if len(hashes) != 1:
        paths = ", ".join(os.fspath(path) for path, _ in selected)
        raise ImageCandidateAmbiguityError(
            "highest-quality candidates contain different bytes: {}".format(paths)
        )

    chosen_path, chosen_hash = selected[0]
    duplicate_paths = tuple(path for path, _ in selected[1:])
    selected_index = tuple(quality for quality, _ in qualities).index(selected_quality)
    lower_quality_paths = tuple(
        path
        for quality, _ in qualities[selected_index + 1 :]
        for path, _digest in sorted(found[quality], key=lambda item: os.fspath(item[0]))
    )
    return ImageCandidateResolution(
        path=chosen_path,
        quality=selected_quality,
        sha256=chosen_hash,
        duplicate_paths=duplicate_paths,
        lower_quality_paths=lower_quality_paths,
    )


def detect_image_format(data: BytesLike) -> str:
    """Validate and return ``jpg/png/gif/webp/tif/bmp/wxgf``.

    This is intentionally stricter than a header-only extension guess.  A
    malformed or unknown payload is rejected instead of being reported as a
    successful generic ``bin`` file.
    """

    payload = _as_bytes(data, field="image data")

    if payload.startswith(b"\xff\xd8\xff"):
        if len(payload) >= 5 and payload.endswith(b"\xff\xd9"):
            return "jpg"
        raise UnsupportedImageFormatError("JPEG payload is missing its end marker")

    if payload.startswith(b"\x89PNG\r\n\x1a\n"):
        png_end = b"\x00\x00\x00\x00IEND\xaeB\x60\x82"
        if len(payload) >= len(b"\x89PNG\r\n\x1a\n") + len(png_end) and payload.endswith(png_end):
            return "png"
        raise UnsupportedImageFormatError("PNG payload is missing a valid IEND trailer")

    if payload.startswith((b"GIF87a", b"GIF89a")):
        if len(payload) >= 7 and payload.endswith(b";"):
            return "gif"
        raise UnsupportedImageFormatError("GIF payload is missing its trailer")

    if payload.startswith(b"RIFF"):
        if len(payload) < 12 or payload[8:12] != b"WEBP":
            raise UnsupportedImageFormatError("RIFF payload is not WEBP")
        declared_size = struct.unpack_from("<I", payload, 4)[0] + 8
        if declared_size != len(payload):
            raise UnsupportedImageFormatError("WEBP RIFF size does not match the payload")
        return "webp"

    if payload.startswith((b"II*\x00", b"MM\x00*")):
        if len(payload) < 8:
            raise UnsupportedImageFormatError("TIFF payload is shorter than its header")
        byte_order = "<" if payload.startswith(b"II") else ">"
        first_ifd = struct.unpack_from(byte_order + "I", payload, 4)[0]
        if first_ifd != 0 and first_ifd + 2 > len(payload):
            raise UnsupportedImageFormatError("TIFF first IFD points outside the payload")
        return "tif"

    if payload.startswith(b"BM"):
        if len(payload) < 14:
            raise UnsupportedImageFormatError("BMP payload is shorter than its file header")
        declared_size = struct.unpack_from("<I", payload, 2)[0]
        pixel_offset = struct.unpack_from("<I", payload, 10)[0]
        if declared_size != len(payload):
            raise UnsupportedImageFormatError("BMP declared size does not match the payload")
        if pixel_offset < 14 or pixel_offset > len(payload):
            raise UnsupportedImageFormatError("BMP pixel offset is outside the payload")
        return "bmp"

    if payload.startswith(b"wxgf"):
        return "wxgf"

    raise UnsupportedImageFormatError("decoded payload is not a supported image format")


def _load_aes():
    try:
        from Crypto.Cipher import AES  # type: ignore
    except (ImportError, ModuleNotFoundError) as exc:
        raise CryptoDependencyError(
            "PyCryptodome is required for WeChat V1/V2 image decoding; "
            "install it with: python3 -m pip install pycryptodome"
        ) from exc
    return AES


def _coerce_aes_key(aes_key: Optional[Union[str, BytesLike]]) -> bytes:
    if aes_key is None:
        raise ImageDecodeError("a 16-byte AES key is required for a V2 image")
    if isinstance(aes_key, str):
        try:
            key = aes_key.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ImageDecodeError("the V2 AES key must contain exactly 16 ASCII bytes") from exc
    else:
        key = _as_bytes(aes_key, field="aes_key")
    if len(key) != _AES_BLOCK_SIZE:
        raise ImageDecodeError("the V2 AES key must contain exactly 16 bytes")
    return key


def _coerce_xor_key(xor_key: Optional[Union[int, BytesLike]]) -> int:
    if isinstance(xor_key, int) and not isinstance(xor_key, bool):
        if 0 <= xor_key <= 0xFF:
            return xor_key
    elif isinstance(xor_key, (bytes, bytearray, memoryview)):
        key_bytes = bytes(xor_key)
        if len(key_bytes) == 1:
            return key_bytes[0]
    raise ImageDecodeError("xor_key must be an integer from 0 through 255 or one byte")


def _strict_pkcs7_unpad(padded: bytes) -> bytes:
    if not padded or len(padded) % _AES_BLOCK_SIZE:
        raise ImageDecodeError("AES plaintext is not block aligned")
    padding_size = padded[-1]
    if padding_size < 1 or padding_size > _AES_BLOCK_SIZE:
        raise ImageDecodeError("AES plaintext has invalid PKCS#7 padding")
    if padded[-padding_size:] != bytes([padding_size]) * padding_size:
        raise ImageDecodeError("AES plaintext has invalid PKCS#7 padding")
    return padded[:-padding_size]


def _decode_versioned(
    payload: bytes,
    *,
    aes_key: Optional[Union[str, BytesLike]],
    xor_key: Optional[Union[int, BytesLike]],
) -> DecodedImage:
    if len(payload) < _HEADER_SIZE:
        raise ImageDecodeError("V1/V2 image is shorter than its 15-byte header")

    magic = payload[:6]
    aes_size, xor_size = struct.unpack_from("<II", payload, 6)
    aligned_aes_size = aes_size + (_AES_BLOCK_SIZE - (aes_size % _AES_BLOCK_SIZE))
    aes_start = _HEADER_SIZE
    aes_end = aes_start + aligned_aes_size
    if aligned_aes_size < _AES_BLOCK_SIZE or aligned_aes_size % _AES_BLOCK_SIZE:
        raise ImageDecodeError("V1/V2 AES segment has an invalid aligned size")
    if aes_end > len(payload):
        raise ImageDecodeError("V1/V2 AES segment extends beyond the payload")
    if xor_size > len(payload) - aes_end:
        raise ImageDecodeError("V1/V2 XOR segment overlaps the AES segment")
    xor_start = len(payload) - xor_size
    if xor_start < aes_end:
        raise ImageDecodeError("V1/V2 segment boundaries overlap")

    key = V1_AES_KEY if magic == V1_MAGIC else _coerce_aes_key(aes_key)
    AES = _load_aes()
    try:
        padded_plaintext = AES.new(key, AES.MODE_ECB).decrypt(payload[aes_start:aes_end])
    except (ValueError, TypeError, KeyError) as exc:
        raise ImageDecodeError("V1/V2 AES segment could not be decrypted") from exc
    aes_plaintext = _strict_pkcs7_unpad(padded_plaintext)
    if len(aes_plaintext) != aes_size:
        raise ImageDecodeError("V1/V2 AES size does not match the unpadded plaintext")

    raw_middle = payload[aes_end:xor_start]
    if xor_size:
        xor_byte = _coerce_xor_key(xor_key)
        xor_plaintext = bytes(value ^ xor_byte for value in payload[xor_start:])
    else:
        xor_plaintext = b""
    decoded = aes_plaintext + raw_middle + xor_plaintext
    image_format = detect_image_format(decoded)
    return DecodedImage(
        data=decoded,
        format=image_format,
        decoder="v1" if magic == V1_MAGIC else "v2",
    )


_LEGACY_SIGNATURES = (
    b"\xff\xd8\xff",
    b"\x89PNG\r\n\x1a\n",
    b"GIF87a",
    b"GIF89a",
    b"RIFF",
    b"II*\x00",
    b"MM\x00*",
    b"BM",
    b"wxgf",
)


def _decode_legacy_xor(payload: bytes) -> DecodedImage:
    if not payload:
        raise ImageDecodeError("legacy image payload is empty")

    candidates = []
    tried_keys = set()
    for signature in _LEGACY_SIGNATURES:
        if len(payload) < len(signature):
            continue
        xor_byte = payload[0] ^ signature[0]
        if xor_byte in tried_keys:
            continue
        tried_keys.add(xor_byte)
        decoded = bytes(value ^ xor_byte for value in payload)
        try:
            image_format = detect_image_format(decoded)
        except UnsupportedImageFormatError:
            continue
        candidates.append((decoded, image_format))

    unique_candidates = []
    seen = set()
    for decoded, image_format in candidates:
        identity = (decoded, image_format)
        if identity not in seen:
            seen.add(identity)
            unique_candidates.append(identity)
    if not unique_candidates:
        raise ImageDecodeError(
            "legacy XOR key could not be inferred from a validated image signature"
        )
    if len(unique_candidates) != 1:
        raise ImageDecodeError("legacy XOR payload matches more than one validated format")
    decoded, image_format = unique_candidates[0]
    return DecodedImage(data=decoded, format=image_format, decoder="legacy-xor")


def decode_image_dat(
    data: BytesLike,
    *,
    aes_key: Optional[Union[str, BytesLike]] = None,
    xor_key: Optional[Union[int, BytesLike]] = None,
) -> DecodedImage:
    """Decode one in-memory WeChat ``.dat`` payload.

    Legacy payloads infer their one-byte XOR key from validated image
    signatures. V1 uses WeChat's fixed AES key; V2 requires ``aes_key``. V1/V2
    XOR tails require ``xor_key`` only when their declared tail is non-empty.
    The function performs no filesystem writes and never logs key material.
    """

    payload = _as_bytes(data, field="image .dat data")
    if payload.startswith((V1_MAGIC, V2_MAGIC)):
        return _decode_versioned(payload, aes_key=aes_key, xor_key=xor_key)
    return _decode_legacy_xor(payload)


__all__ = [
    "CryptoDependencyError",
    "DecodedImage",
    "ImageCandidateAmbiguity",
    "ImageCandidateAmbiguityError",
    "ImageCandidateError",
    "ImageCandidateNotFound",
    "ImageCandidateNotFoundError",
    "ImageCandidateResolution",
    "ImageCryptoError",
    "ImageDecodeError",
    "ResolvedImageCandidate",
    "UnsupportedImageFormatError",
    "UnsafeImagePathError",
    "V1_AES_KEY",
    "V1_MAGIC",
    "V2_MAGIC",
    "decode_image_dat",
    "detect_image_format",
    "extract_packed_info_md5_candidates",
    "resolve_image_candidate",
]
