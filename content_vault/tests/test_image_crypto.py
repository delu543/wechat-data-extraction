import hashlib
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

try:
    from Crypto.Cipher import AES
except ImportError:  # The production module must still support legacy XOR.
    AES = None

from content_vault import image_crypto


MD5 = "0123456789abcdef0123456789abcdef"
OTHER_MD5 = "fedcba9876543210fedcba9876543210"


def jpeg_bytes(body=b"jpeg-body"):
    return b"\xff\xd8\xff\xe0" + body + b"\xff\xd9"


def png_bytes(body=b"png-body"):
    return (
        b"\x89PNG\r\n\x1a\n"
        + body
        + b"\x00\x00\x00\x00IEND\xaeB\x60\x82"
    )


def gif_bytes(body=b"gif-body"):
    return b"GIF89a" + body + b";"


def webp_bytes(body=b"webp-body"):
    payload = b"WEBP" + body
    return b"RIFF" + struct.pack("<I", len(payload)) + payload


def tif_bytes(body=b"tif-body"):
    return b"II*\x00" + struct.pack("<I", 0) + body


def bmp_bytes(body=b"bmp-body"):
    size = 14 + len(body)
    return b"BM" + struct.pack("<I", size) + b"\x00" * 4 + struct.pack("<I", 14) + body


def wxgf_bytes(body=b"opaque-wxgf-payload"):
    return b"wxgf" + body


def xor_encrypt(payload, key):
    return bytes(value ^ key for value in payload)


def build_versioned(payload, *, magic, key, xor_key, aes_size=16, xor_size=5):
    if AES is None:
        raise unittest.SkipTest("PyCryptodome is unavailable")
    if aes_size > len(payload) or xor_size > len(payload) - aes_size:
        raise ValueError("fixture segment sizes overlap")
    aes_plain = payload[:aes_size]
    padding_size = 16 - (len(aes_plain) % 16)
    padded = aes_plain + bytes([padding_size]) * padding_size
    aes_ciphertext = AES.new(key, AES.MODE_ECB).encrypt(padded)
    raw = payload[aes_size : len(payload) - xor_size] if xor_size else payload[aes_size:]
    tail = xor_encrypt(payload[len(payload) - xor_size :], xor_key) if xor_size else b""
    header = magic + struct.pack("<II", aes_size, xor_size) + b"\x00"
    return header + aes_ciphertext + raw + tail


class PackedInfoTests(unittest.TestCase):
    def test_marker_candidates_are_all_returned_normalized_and_deduplicated(self):
        first = MD5.upper().encode("ascii")
        second = OTHER_MD5.encode("ascii")
        packed = (
            b"prefix"
            + image_crypto.PACKED_INFO_MD5_MARKER
            + first
            + b"middle"
            + image_crypto.PACKED_INFO_MD5_MARKER
            + second
            + image_crypto.PACKED_INFO_MD5_MARKER
            + first
        )
        self.assertEqual(
            image_crypto.extract_packed_info_md5_candidates(packed),
            (MD5, OTHER_MD5),
        )

    def test_marker_candidates_take_priority_over_fallback_text(self):
        packed = (
            OTHER_MD5.encode("ascii")
            + b"|"
            + image_crypto.PACKED_INFO_MD5_MARKER
            + MD5.encode("ascii")
        )
        self.assertEqual(image_crypto.extract_packed_info_md5_candidates(packed), (MD5,))

    def test_fallback_requires_exact_hex_boundaries(self):
        packed = (
            b"z"
            + MD5.upper().encode("ascii")
            + b"z|"
            + b"a" * 33
            + b"|"
            + OTHER_MD5.encode("ascii")
            + b"f"
        )
        self.assertEqual(image_crypto.extract_packed_info_md5_candidates(packed), (MD5,))

    def test_empty_blob_has_no_candidates(self):
        self.assertEqual(image_crypto.extract_packed_info_md5_candidates(None), ())
        self.assertEqual(image_crypto.extract_packed_info_md5_candidates(b""), ())


class CandidateResolutionTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name) / "chat"
        self.root.mkdir()

    def tearDown(self):
        self.temp_dir.cleanup()

    def make_candidate(self, month, filename, data):
        image_dir = self.root / month / "Img"
        image_dir.mkdir(parents=True, exist_ok=True)
        path = image_dir / filename
        path.write_bytes(data)
        return path

    def test_quality_order_is_full_then_high_then_thumbnail(self):
        thumbnail = self.make_candidate("2026-06", MD5 + "_t.dat", b"thumbnail")
        high = self.make_candidate("2026-07", MD5 + "_h.dat", b"high")
        full = self.make_candidate("2026-05", MD5 + ".dat", b"full")
        result = image_crypto.resolve_image_candidate(self.root, MD5.upper())
        self.assertEqual(result.path, full.resolve())
        self.assertEqual(result.quality, "full")
        self.assertEqual(result.sha256, hashlib.sha256(b"full").hexdigest())
        self.assertEqual(result.lower_quality_paths, (high.resolve(), thumbnail.resolve()))

    def test_same_quality_same_sha_is_a_deterministic_duplicate(self):
        first = self.make_candidate("2026-01", MD5 + ".dat", b"same")
        second = self.make_candidate("2026-02", MD5 + ".dat", b"same")
        result = image_crypto.resolve_image_candidate(self.root, MD5)
        self.assertEqual(result.path, first.resolve())
        self.assertEqual(result.duplicate_paths, (second.resolve(),))

    def test_same_quality_different_sha_is_ambiguous(self):
        self.make_candidate("2026-01", MD5 + "_h.dat", b"one")
        self.make_candidate("2026-02", MD5 + "_h.dat", b"two")
        with self.assertRaises(image_crypto.ImageCandidateAmbiguityError):
            image_crypto.resolve_image_candidate(self.root, MD5)

    def test_lower_quality_disagreement_does_not_make_full_ambiguous(self):
        full = self.make_candidate("2026-03", MD5 + ".dat", b"winner")
        self.make_candidate("2026-01", MD5 + "_h.dat", b"one")
        self.make_candidate("2026-02", MD5 + "_h.dat", b"two")
        result = image_crypto.resolve_image_candidate(self.root, MD5)
        self.assertEqual(result.path, full.resolve())

    def test_month_filter_is_exact(self):
        self.make_candidate("2026-06", MD5 + ".dat", b"older")
        expected = self.make_candidate("2026-07", MD5 + ".dat", b"target")
        result = image_crypto.resolve_image_candidate(self.root, MD5, month="2026-07")
        self.assertEqual(result.path, expected.resolve())

    def test_prefix_glob_is_not_accepted(self):
        self.make_candidate("2026-07", MD5 + "-extra.dat", b"wrong")
        with self.assertRaises(image_crypto.ImageCandidateNotFoundError):
            image_crypto.resolve_image_candidate(self.root, MD5)

    def test_symlink_candidate_is_rejected(self):
        outside = Path(self.temp_dir.name) / "outside.dat"
        outside.write_bytes(b"outside")
        candidate = self.root / "2026-07" / "Img" / (MD5 + ".dat")
        candidate.parent.mkdir(parents=True)
        candidate.symlink_to(outside)
        with self.assertRaises(image_crypto.UnsafeImagePathError):
            image_crypto.resolve_image_candidate(self.root, MD5)

    def test_symlink_img_directory_path_escape_is_rejected(self):
        outside = Path(self.temp_dir.name) / "outside"
        outside.mkdir()
        (outside / (MD5 + ".dat")).write_bytes(b"outside")
        month = self.root / "2026-07"
        month.mkdir()
        (month / "Img").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(image_crypto.UnsafeImagePathError):
            image_crypto.resolve_image_candidate(self.root, MD5)

    def test_symlink_chat_root_is_rejected(self):
        link = Path(self.temp_dir.name) / "chat-link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(image_crypto.UnsafeImagePathError):
            image_crypto.resolve_image_candidate(link, MD5)

    def test_invalid_identifier_and_month_are_rejected(self):
        with self.assertRaises(image_crypto.ImageCandidateError):
            image_crypto.resolve_image_candidate(self.root, "../not-an-md5")
        with self.assertRaises(image_crypto.ImageCandidateError):
            image_crypto.resolve_image_candidate(self.root, MD5, month="2026/07")


class FormatAndLegacyDecodeTests(unittest.TestCase):
    def test_every_supported_standard_format_round_trips_legacy_xor(self):
        fixtures = {
            "jpg": jpeg_bytes(),
            "png": png_bytes(),
            "gif": gif_bytes(),
            "webp": webp_bytes(),
            "tif": tif_bytes(),
            "bmp": bmp_bytes(),
        }
        for expected_format, plain in fixtures.items():
            with self.subTest(expected_format):
                decoded = image_crypto.decode_image_dat(xor_encrypt(plain, 0xA7))
                self.assertEqual(decoded.data, plain)
                self.assertEqual(decoded.format, expected_format)
                self.assertEqual(decoded.decoder, "legacy-xor")

    def test_wxgf_is_returned_for_integration_without_conversion(self):
        plain = wxgf_bytes()
        decoded = image_crypto.decode_image_dat(xor_encrypt(plain, 0x39))
        self.assertEqual(decoded.data, plain)
        self.assertEqual(decoded.format, "wxgf")
        self.assertTrue(decoded.is_wxgf)

    def test_malformed_known_headers_and_unknown_bin_are_rejected(self):
        malformed = (
            b"\xff\xd8\xff-no-end",
            b"\x89PNG\r\n\x1a\n-no-iend",
            b"GIF89a-no-trailer",
            b"RIFF\x00\x00\x00\x00WEBP",
            b"BM-too-short",
            b"ordinary unknown bytes",
        )
        for payload in malformed:
            with self.subTest(payload=payload[:8]):
                with self.assertRaises(image_crypto.UnsupportedImageFormatError):
                    image_crypto.detect_image_format(payload)
        with self.assertRaises(image_crypto.ImageDecodeError):
            image_crypto.decode_image_dat(b"this must never become a successful bin")


@unittest.skipIf(AES is None, "PyCryptodome is unavailable")
class VersionedDecodeTests(unittest.TestCase):
    def test_v2_decodes_aes_raw_and_xor_segments(self):
        plain = jpeg_bytes(b"A" * 30)
        key = b"0123456789abcdef"
        encrypted = build_versioned(
            plain,
            magic=image_crypto.V2_MAGIC,
            key=key,
            xor_key=0x6B,
            aes_size=16,
            xor_size=7,
        )
        # Exactly 16 plaintext bytes must produce two encrypted blocks because
        # WeChat uses a full PKCS#7 padding block in this case.
        self.assertEqual(len(encrypted[15 : 15 + 32]), 32)
        decoded = image_crypto.decode_image_dat(encrypted, aes_key=key, xor_key=0x6B)
        self.assertEqual(decoded, image_crypto.DecodedImage(plain, "jpg", "v2"))

    def test_v1_uses_fixed_aes_key_and_supplied_xor_tail_key(self):
        plain = png_bytes(b"B" * 30)
        encrypted = build_versioned(
            plain,
            magic=image_crypto.V1_MAGIC,
            key=image_crypto.V1_AES_KEY,
            xor_key=0x24,
            aes_size=17,
            xor_size=9,
        )
        decoded = image_crypto.decode_image_dat(
            encrypted,
            aes_key=b"ignored-for-v1!",
            xor_key=b"\x24",
        )
        self.assertEqual(decoded.data, plain)
        self.assertEqual(decoded.format, "png")
        self.assertEqual(decoded.decoder, "v1")

    def test_versioned_wxgf_is_identified_but_not_converted(self):
        plain = wxgf_bytes(b"C" * 30)
        key = b"0123456789abcdef"
        encrypted = build_versioned(
            plain,
            magic=image_crypto.V2_MAGIC,
            key=key,
            xor_key=0x51,
            aes_size=16,
            xor_size=5,
        )
        decoded = image_crypto.decode_image_dat(encrypted, aes_key=key, xor_key=0x51)
        self.assertEqual(decoded.format, "wxgf")
        self.assertEqual(decoded.data, plain)

    def test_v2_requires_exact_key_and_nonempty_tail_requires_xor_key(self):
        plain = jpeg_bytes(b"D" * 30)
        key = b"0123456789abcdef"
        encrypted = build_versioned(
            plain,
            magic=image_crypto.V2_MAGIC,
            key=key,
            xor_key=0x11,
            aes_size=16,
            xor_size=4,
        )
        with self.assertRaises(image_crypto.ImageDecodeError):
            image_crypto.decode_image_dat(encrypted, xor_key=0x11)
        with self.assertRaises(image_crypto.ImageDecodeError):
            image_crypto.decode_image_dat(encrypted, aes_key=b"too-short", xor_key=0x11)
        with self.assertRaises(image_crypto.ImageDecodeError):
            image_crypto.decode_image_dat(encrypted, aes_key=key)

    def test_zero_length_xor_tail_does_not_require_xor_key(self):
        plain = gif_bytes(b"E" * 30)
        key = b"0123456789abcdef"
        encrypted = build_versioned(
            plain,
            magic=image_crypto.V2_MAGIC,
            key=key,
            xor_key=0x00,
            aes_size=16,
            xor_size=0,
        )
        decoded = image_crypto.decode_image_dat(encrypted, aes_key=key)
        self.assertEqual(decoded.data, plain)

    def test_malformed_segment_bounds_and_padding_are_rejected(self):
        key = b"0123456789abcdef"
        beyond = image_crypto.V2_MAGIC + struct.pack("<II", 100, 0) + b"\x00" + b"X" * 16
        with self.assertRaises(image_crypto.ImageDecodeError):
            image_crypto.decode_image_dat(beyond, aes_key=key)

        overlap = image_crypto.V2_MAGIC + struct.pack("<II", 1, 1) + b"\x00" + b"X" * 16
        with self.assertRaises(image_crypto.ImageDecodeError):
            image_crypto.decode_image_dat(overlap, aes_key=key, xor_key=0x01)

        bad_plain_block = b"A" * 16
        bad_ciphertext = AES.new(key, AES.MODE_ECB).encrypt(bad_plain_block)
        bad_padding = image_crypto.V2_MAGIC + struct.pack("<II", 1, 0) + b"\x00" + bad_ciphertext
        with self.assertRaises(image_crypto.ImageDecodeError):
            image_crypto.decode_image_dat(bad_padding, aes_key=key)

    def test_valid_encryption_with_unknown_plaintext_is_not_bin_success(self):
        plain = b"not-an-image-payload-with-enough-bytes"
        key = b"0123456789abcdef"
        encrypted = build_versioned(
            plain,
            magic=image_crypto.V2_MAGIC,
            key=key,
            xor_key=0x77,
            aes_size=16,
            xor_size=4,
        )
        with self.assertRaises(image_crypto.UnsupportedImageFormatError):
            image_crypto.decode_image_dat(encrypted, aes_key=key, xor_key=0x77)

    def test_crypto_dependency_error_is_actionable(self):
        plain = jpeg_bytes(b"F" * 30)
        key = b"0123456789abcdef"
        encrypted = build_versioned(
            plain,
            magic=image_crypto.V2_MAGIC,
            key=key,
            xor_key=0x32,
            aes_size=16,
            xor_size=2,
        )
        real_import = __import__

        def block_crypto(name, *args, **kwargs):
            if name == "Crypto.Cipher" or name.startswith("Crypto.Cipher."):
                raise ImportError("synthetic missing dependency")
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=block_crypto):
            with self.assertRaises(image_crypto.CryptoDependencyError) as caught:
                image_crypto.decode_image_dat(encrypted, aes_key=key, xor_key=0x32)
        self.assertIn("python3 -m pip install pycryptodome", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
