"""Atomic export of a frozen content plan into a readable local archive."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import html
from importlib import metadata as importlib_metadata
import json
import os
from pathlib import Path
import re
import select
import shutil
import stat
import struct
import subprocess
import tempfile
import time
from typing import Any, Optional, Union

from content_vault.attachment_resolver import (
    AssetResolution,
    copy_verified_file,
    resolve_regular_file,
    resolve_sticker,
)
from content_vault.image_crypto import (
    ImageCandidateAmbiguityError,
    ImageCandidateError,
    ImageCandidateNotFoundError,
    ImageDecodeError,
    UnsafeImagePathError,
    V1_MAGIC,
    V2_MAGIC,
    decode_image_dat,
    resolve_image_candidate,
)
from content_vault.scanner import load_content_plan, verify_plan_sources
from content_vault.wxgf_converter import WXGFConversionError, convert_wxgf_to_jpeg
from direct_vault.direct_voice_vault import (
    DIRECT_VOICE_MAX_DURATION_MILLISECONDS,
    DIRECT_VOICE_MIN_DURATION_MILLISECONDS,
    PCM_BYTES_PER_SAMPLE,
    PCM_SAMPLE_RATE,
    PLAN_SCHEMA_VERSION,
    SILK_PACKET_MILLISECONDS,
    VaultError,
    _canonical_json,
    _default_silk_decoder,
    _ensure_output_outside_vault,
    _is_relative_to,
    _load_extract_manifest,
    _plan_digest,
    _require_plain_file,
    _sha256_bytes,
    _sha256_file,
    _validate_pcm,
    _write_json_private,
    decode as decode_voices,
    extract as extract_voices,
)


ARCHIVE_SCHEMA_VERSION = 1
VOICE_MP4_ONLY_SCHEMA_VERSION = 2
MAX_IMAGE_DAT_BYTES = 512 * 1024 * 1024
KVCOMM_KEY_RE = re.compile(r"^key_(\d+)_.+\.statistic$", re.IGNORECASE)
FATAL_ASSET_STATES = {"metadata_only", "missing", "ambiguous", "corrupt", "unsupported"}
VOICE_MP4_GAP_MILLISECONDS = 300
VOICE_MP4_STREAM_TIMEOUT_SECONDS = 900
VOICE_MP4_STOP_GRACE_SECONDS = 5
VOICE_MP4_DURATION_TOLERANCE_MILLISECONDS = 550
VOICE_PCM_WRITE_CHUNK_BYTES = 64 * 1024
MAX_FFMPEG_AUDIT_CHARACTERS = 4_000


def _private_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("xb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _private_text(path: Path, value: str) -> None:
    _private_write(path, value.encode("utf-8"))


def _validate_account_root(value: Union[str, Path]) -> Path:
    requested = Path(value).expanduser()
    if requested.is_symlink():
        raise VaultError("微信账号目录不能是符号链接")
    account = requested.resolve()
    if not account.is_dir() or not (account / "msg").is_dir():
        raise VaultError(f"微信账号目录无效：{account}")
    return account


def _read_stable(path: Path, expected_sha256: str) -> bytes:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise VaultError("图片候选不再是普通文件")
    if before.st_size <= 0 or before.st_size > MAX_IMAGE_DAT_BYTES:
        raise VaultError("图片候选大小超出安全范围")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise VaultError("图片候选在打开时发生变化")
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
            digest.update(chunk)
    finally:
        os.close(descriptor)
    after = path.lstat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise VaultError("图片候选在读取过程中发生变化")
    if digest.hexdigest() != expected_sha256:
        raise VaultError("图片候选 SHA-256 与扫描结果不一致")
    return b"".join(chunks)


def _account_name_candidates(account: Path) -> list[str]:
    name = account.name
    values = [name]
    if name.lower().startswith("wxid_"):
        match = re.match(r"^(wxid_[^_]+)", name, re.IGNORECASE)
        if match and match.group(1) != name:
            values.append(match.group(1))
    else:
        match = re.match(r"^(.+)_([A-Za-z0-9]{4})$", name)
        if match:
            values.append(match.group(1))
    return list(dict.fromkeys(values))


def _image_key_candidates(account: Path) -> list[tuple[bytes, int]]:
    documents = account.parent.parent
    roots = [
        documents / "app_data/net/kvcomm",
        documents.parent / "app_data/net/kvcomm",
    ]
    uins: set[int] = set()
    for root in roots:
        if root.is_symlink() or not root.is_dir():
            continue
        try:
            for entry in root.iterdir():
                match = KVCOMM_KEY_RE.fullmatch(entry.name)
                if not match:
                    continue
                value = int(match.group(1))
                if 0 < value <= 0xFFFFFFFF:
                    uins.add(value)
        except OSError:
            continue
    result: list[tuple[bytes, int]] = []
    for account_name in _account_name_candidates(account):
        for uin in sorted(uins):
            aes_key = hashlib.md5(f"{uin}{account_name}".encode("utf-8")).hexdigest()[:16]
            result.append((aes_key.encode("ascii"), uin & 0xFF))
    return list(dict.fromkeys(result))


def _decode_image(data: bytes, account: Path) -> tuple[bytes, str, str, int]:
    if not data.startswith((V1_MAGIC, V2_MAGIC)):
        decoded = decode_image_dat(data)
        return decoded.data, decoded.format, decoded.decoder, 0
    candidates = _image_key_candidates(account)
    # A V1 record with no XOR tail does not need a per-account key.
    if data.startswith(V1_MAGIC) and len(data) >= 14 and struct.unpack_from("<I", data, 10)[0] == 0:
        candidates = [(b"0" * 16, 0), *candidates]
    if not candidates:
        raise VaultError("图片密钥不可用：未找到与该账号匹配的 kvcomm 候选")
    decoded_by_hash: dict[str, tuple[bytes, str, str]] = {}
    for aes_key, xor_key in candidates:
        try:
            decoded = decode_image_dat(data, aes_key=aes_key, xor_key=xor_key)
        except ImageDecodeError:
            continue
        digest = hashlib.sha256(decoded.data).hexdigest()
        decoded_by_hash[digest] = (decoded.data, decoded.format, decoded.decoder)
    if not decoded_by_hash:
        raise VaultError("图片密钥候选均未通过完整格式校验")
    if len(decoded_by_hash) != 1:
        raise VaultError("图片密钥候选产生多个有效结果，拒绝猜测")
    decoded_data, image_format, decoder = next(iter(decoded_by_hash.values()))
    return decoded_data, image_format, decoder, len(candidates)


def _asset_id(message: dict[str, Any], kind: str) -> str:
    return "asset:v1:sha256:" + _sha256_bytes(
        _canonical_json({"message_id": message["message_id"], "kind": kind})
    )


def _record_issue(
    issues: list[dict[str, Any]], message: dict[str, Any], status: str, detail: str
) -> None:
    issues.append(
        {
            "sequence": message["sequence"],
            "message_id": message["message_id"],
            "kind": message["kind"],
            "status": status,
            "detail": detail,
        }
    )


def _export_image(
    message: dict[str, Any], account: Path, staging: Path
) -> dict[str, Any]:
    asset_id = _asset_id(message, "image")
    candidates = message.get("payload", {}).get("resource_md5_candidates") or []
    if len(candidates) == 0:
        return {"asset_id": asset_id, "kind": "image", "status": "missing", "reason": "missing_metadata"}
    if len(candidates) != 1:
        return {
            "asset_id": asset_id,
            "kind": "image",
            "status": "ambiguous",
            "reason": "multiple_resource_md5_candidates",
            "candidate_count": len(candidates),
        }
    resource_md5 = str(candidates[0]).lower()
    chat_hash = hashlib.md5(message["_chat_id"].encode("utf-8")).hexdigest()
    chat_root = account / "msg" / "attach" / chat_hash
    if not chat_root.exists():
        return {
            "asset_id": asset_id,
            "kind": "image",
            "status": "missing",
            "reason": "chat_attachment_root_missing",
        }
    month = datetime.fromtimestamp(message["create_time"]).strftime("%Y-%m")
    try:
        try:
            resolution = resolve_image_candidate(chat_root, resource_md5, month=month)
        except ImageCandidateNotFoundError:
            # Older caches can be filed in an adjacent month due to delayed
            # download or a timezone boundary. The fallback still searches
            # only this exact chat hash and exact filename variants.
            resolution = resolve_image_candidate(chat_root, resource_md5)
    except ImageCandidateNotFoundError:
        return {"asset_id": asset_id, "kind": "image", "status": "missing", "reason": "attachment_missing"}
    except ImageCandidateAmbiguityError:
        return {"asset_id": asset_id, "kind": "image", "status": "ambiguous", "reason": "attachment_ambiguous"}
    except (ImageCandidateError, UnsafeImagePathError) as error:
        return {"asset_id": asset_id, "kind": "image", "status": "corrupt", "reason": type(error).__name__}
    try:
        encrypted = _read_stable(resolution.path, resolution.sha256)
        decoded, image_format, decoder, key_candidates = _decode_image(encrypted, account)
    except (ImageDecodeError, VaultError, OSError) as error:
        reason = "key_unavailable" if "密钥" in str(error) else "decode_failed"
        return {"asset_id": asset_id, "kind": "image", "status": "corrupt", "reason": reason}
    if image_format == "wxgf":
        try:
            decoded = convert_wxgf_to_jpeg(decoded)
            image_format = "jpg"
            decoder += "+wxgf-hevc"
        except WXGFConversionError:
            return {
                "asset_id": asset_id,
                "kind": "image",
                "status": "unsupported",
                "reason": "wxgf_converter_unavailable_or_failed",
            }
    output_name = f"{message['sequence']:06d}-{resource_md5}.{image_format}"
    relative = Path("media/images") / output_name
    _private_write(staging / relative, decoded)
    return {
        "asset_id": asset_id,
        "kind": "image",
        "status": "resolved",
        "relative_path": str(relative),
        "resource_md5": resource_md5,
        "quality": resolution.quality,
        "thumbnail_only": resolution.quality == "thumbnail",
        "encrypted_sha256": resolution.sha256,
        "decoder": decoder,
        "format": image_format,
        "byte_count": len(decoded),
        "sha256": hashlib.sha256(decoded).hexdigest(),
        "duplicate_identical": bool(resolution.duplicate_paths),
        "key_candidate_count": key_candidates,
    }


def _payload_int(payload: dict[str, Any], *names: str) -> Optional[int]:
    for name in names:
        value = payload.get(name)
        if value in (None, ""):
            continue
        try:
            result = int(value)
        except (TypeError, ValueError):
            continue
        if result >= 0:
            return result
    return None


def _export_file(message: dict[str, Any], account: Path, staging: Path) -> dict[str, Any]:
    asset_id = _asset_id(message, "file")
    payload = message.get("payload", {})
    filename = payload.get("filename") or payload.get("title")
    if not isinstance(filename, str) or not filename.strip():
        return {"asset_id": asset_id, "kind": "file", "status": "missing", "reason": "filename_missing"}
    expected_md5 = payload.get("md5")
    try:
        resolution = resolve_regular_file(
            account,
            message["create_time"],
            filename,
            expected_size=_payload_int(
                payload, "byte_size", "size", "total_bytes", "totallen"
            ),
            expected_md5=expected_md5 if isinstance(expected_md5, str) else None,
        )
    except VaultError:
        return {
            "asset_id": asset_id,
            "kind": "file",
            "status": "corrupt",
            "reason": "unsafe_or_invalid_metadata",
        }
    asset = {"asset_id": asset_id, "kind": "file", "status": resolution.status, **resolution.metadata}
    if resolution.status != "resolved" or resolution.source is None:
        return asset
    output_name = f"{message['sequence']:06d}-{resolution.metadata['filename']}"
    relative = Path("media/files") / output_name
    copy_verified_file(resolution.source, staging / relative, resolution.metadata["sha256"])
    asset["relative_path"] = str(relative)
    return asset


def _export_sticker(message: dict[str, Any], account: Path, staging: Path) -> dict[str, Any]:
    asset_id = _asset_id(message, "sticker")
    expected_md5 = message.get("payload", {}).get("md5")
    if not isinstance(expected_md5, str) or not expected_md5:
        return {"asset_id": asset_id, "kind": "sticker", "status": "missing", "reason": "md5_missing"}
    try:
        resolution = resolve_sticker(account, message["create_time"], expected_md5)
    except VaultError:
        return {
            "asset_id": asset_id,
            "kind": "sticker",
            "status": "corrupt",
            "reason": "unsafe_or_invalid_metadata",
        }
    asset = {"asset_id": asset_id, "kind": "sticker", "status": resolution.status, **resolution.metadata}
    if resolution.source is None:
        return asset
    extension = str(resolution.metadata.get("format") or "bin")
    relative = Path("media/stickers") / f"{message['sequence']:06d}-{expected_md5}.{extension}"
    copy_verified_file(resolution.source, staging / relative, resolution.metadata["sha256"])
    asset["relative_path"] = str(relative)
    return asset


def _voice_subplan(plan: dict[str, Any], messages: list[dict[str, Any]]) -> dict[str, Any]:
    voice_rows: list[dict[str, Any]] = []
    for sequence, message in enumerate((item for item in messages if item["kind"] == "voice"), 1):
        duration = _payload_int(message.get("payload", {}), "duration_ms")
        source = message["source_ref"]
        voice_rows.append(
            {
                "source_db": source["source_db"],
                "source_table": source["source_table"],
                "local_id": source["local_id"],
                "server_id": source["server_id"],
                "create_time": message["create_time"],
                "duration_ms": duration,
                "sequence": sequence,
            }
        )
    voice_plan: dict[str, Any] = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "mode": "decrypted-vault-read-only",
        "chat": deepcopy(plan["chat"]),
        "time_range": deepcopy(plan["time_range"]),
        "expected_count": len(voice_rows),
        "voice_count": len(voice_rows),
        "message_table": plan["message_table"],
        "voices": voice_rows,
    }
    voice_plan["plan_digest"] = _plan_digest(voice_plan)
    return voice_plan


def _ffmpeg_duration_milliseconds(output: str) -> int:
    matches = re.findall(
        r"time=(\d+):(\d+):(\d+(?:\.\d+)?)",
        output,
    )
    if not matches:
        matches = re.findall(
            r"Duration:\s*(\d+):(\d+):(\d+(?:\.\d+)?)",
            output,
        )
    if not matches:
        raise VaultError("ffmpeg 未返回可验证的 MP4 时长")
    return max(
        int(
            round(
                (
                    int(hours) * 3_600
                    + int(minutes) * 60
                    + float(seconds)
                )
                * 1_000
            )
        )
        for hours, minutes, seconds in matches
    )


def _ffmpeg_container_duration_milliseconds(output: str) -> int:
    matches = re.findall(
        r"Duration:\s*(\d+):(\d+):(\d+(?:\.\d+)?)",
        output,
    )
    if not matches:
        raise VaultError("ffmpeg 未返回可验证的 MP4 容器时长")
    return max(
        int(
            round(
                (
                    int(hours) * 3_600
                    + int(minutes) * 60
                    + float(seconds)
                )
                * 1_000
            )
        )
        for hours, minutes, seconds in matches
    )


def _ffmpeg_input_codecs(output: str) -> tuple[str, str]:
    input_section = output.split("Stream mapping:", 1)[0]
    streams = re.findall(
        r"^\s*Stream #0:\d+(?:\[[^\]]+\])?(?:\([^)]+\))?:\s*"
        r"(Video|Audio|Subtitle|Data|Attachment):\s*([^,\s]+)",
        input_section,
        flags=re.MULTILINE,
    )
    if len(streams) != 2:
        raise VaultError("ffmpeg 最终 MP4 必须且只能包含一条音轨和一条视频轨")
    video = [codec.casefold() for kind, codec in streams if kind == "Video"]
    audio = [codec.casefold() for kind, codec in streams if kind == "Audio"]
    if video != ["h264"] or audio != ["aac"]:
        raise VaultError("ffmpeg 最终 MP4 编码必须是 H.264 + AAC")
    return video[0], audio[0]


def _resolve_local_ffmpeg() -> tuple[Path, str, str]:
    try:
        import imageio_ffmpeg  # type: ignore[import-not-found]

        configured = os.environ.get("IMAGEIO_FFMPEG_EXE")
        if configured:
            raw = Path(configured).expanduser()
        else:
            package_root = Path(imageio_ffmpeg.__file__).resolve().parent
            candidates = sorted(
                path
                for path in (package_root / "binaries").glob("ffmpeg-*")
                if path.is_file() and not path.is_symlink()
            )
            if len(candidates) != 1:
                raise VaultError("imageio-ffmpeg 未提供唯一的本机离线编码器")
            raw = candidates[0]
        if raw.is_symlink():
            raise VaultError("本地 ffmpeg 编码器不能是符号链接")
        ffmpeg = raw.resolve(strict=True)
        version = importlib_metadata.version("imageio-ffmpeg").strip()
    except VaultError:
        raise
    except (ImportError, OSError, RuntimeError) as error:
        raise VaultError("无法定位本地 ffmpeg MP4 编码器") from error
    if not ffmpeg.is_file() or not os.access(ffmpeg, os.X_OK):
        raise VaultError("本地 ffmpeg MP4 编码器不可执行")
    if (
        not version
        or len(version) > 100
        or any(ord(character) < 32 for character in version)
    ):
        raise VaultError("本地 imageio-ffmpeg 包版本信息无效")
    return ffmpeg, version, _sha256_file(ffmpeg)


def _bounded_ffmpeg_log(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            size = path.stat().st_size
            handle.seek(max(0, size - 16_000))
            value = handle.read().decode("utf-8", errors="replace").strip()
    except OSError:
        return ""
    return value[-MAX_FFMPEG_AUDIT_CHARACTERS:]


def _stop_ffmpeg_process(process: subprocess.Popen[bytes]) -> None:
    stdin = process.stdin
    if stdin is not None and not stdin.closed:
        try:
            stdin.close()
        except OSError:
            pass
    if process.poll() is not None:
        return
    try:
        process.terminate()
    except OSError:
        pass
    try:
        process.wait(timeout=VOICE_MP4_STOP_GRACE_SECONDS)
        return
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        process.kill()
    except OSError:
        pass
    try:
        process.wait(timeout=VOICE_MP4_STOP_GRACE_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _write_ffmpeg_stdin(
    process: subprocess.Popen[bytes],
    data: bytes,
    deadline: float,
) -> None:
    stdin = process.stdin
    if stdin is None or stdin.closed:
        raise BrokenPipeError("ffmpeg stdin 不可用")
    descriptor = stdin.fileno()
    os.set_blocking(descriptor, False)
    remaining = memoryview(data)
    while remaining:
        if process.poll() is not None:
            raise BrokenPipeError("ffmpeg 在 PCM 输入完成前退出")
        timeout = deadline - time.monotonic()
        if timeout <= 0:
            raise subprocess.TimeoutExpired(
                "ffmpeg-stream",
                VOICE_MP4_STREAM_TIMEOUT_SECONDS,
            )
        try:
            _, writable, _ = select.select(
                [],
                [descriptor],
                [],
                min(timeout, 0.25),
            )
        except OSError as error:
            raise BrokenPipeError("无法等待 ffmpeg PCM 输入") from error
        if not writable:
            continue
        try:
            written = os.write(
                descriptor,
                remaining[:VOICE_PCM_WRITE_CHUNK_BYTES],
            )
        except BlockingIOError:
            continue
        except OSError as error:
            raise BrokenPipeError("ffmpeg PCM 输入管道断开") from error
        if written <= 0:
            raise BrokenPipeError("ffmpeg PCM 输入未取得进展")
        remaining = remaining[written:]


def _probe_streamed_voice_mp4(
    ffmpeg: Path,
    output_path: Path,
    expected_duration_milliseconds: int,
) -> dict[str, Any]:
    try:
        probe = subprocess.run(
            [
                str(ffmpeg),
                "-nostdin",
                "-hide_banner",
                "-i",
                str(output_path),
                "-map",
                "0:v:0",
                "-map",
                "0:a:0",
                "-f",
                "null",
                "-",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=VOICE_MP4_STREAM_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise VaultError("ffmpeg 最终 MP4 完整解码校验超时") from error
    except OSError as error:
        raise VaultError("无法运行 ffmpeg 最终 MP4 校验") from error
    output = (probe.stderr or "") + "\n" + (probe.stdout or "")
    if probe.returncode != 0:
        raise VaultError(
            "ffmpeg 最终 MP4 音视频解码校验失败："
            + output.strip()[-MAX_FFMPEG_AUDIT_CHARACTERS:]
        )
    video_codec, audio_codec = _ffmpeg_input_codecs(output)
    decoded_duration = _ffmpeg_duration_milliseconds(output)
    container_duration = _ffmpeg_container_duration_milliseconds(output)
    tolerance = VOICE_MP4_DURATION_TOLERANCE_MILLISECONDS
    if abs(decoded_duration - expected_duration_milliseconds) > tolerance:
        raise VaultError(
            "ffmpeg 最终 MP4 解码时长与 PCM 样本不一致"
            f"（PCM {expected_duration_milliseconds}ms，"
            f"解码 {decoded_duration}ms，容差 {tolerance}ms）"
        )
    if abs(container_duration - expected_duration_milliseconds) > tolerance:
        raise VaultError(
            "ffmpeg 最终 MP4 容器时长与 PCM 样本不一致"
            f"（PCM {expected_duration_milliseconds}ms，"
            f"容器 {container_duration}ms，容差 {tolerance}ms）"
        )
    return {
        "duration_ms": decoded_duration,
        "container_duration_ms": container_duration,
        "video_codec": video_codec,
        "audio_codec": audio_codec,
        "duration_tolerance_ms": tolerance,
    }


def _stream_voice_pcm_to_mp4(
    extract_dir: Path,
    extract_report: dict[str, Any],
    messages: list[dict[str, Any]],
    output_path: Path,
    *,
    title: str,
    expected_chat_id: str,
    expected_source_plan_digest: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    (
        extract,
        source_manifest,
        source_manifest_hash,
        source_plan_digest,
        chat,
        _time_range,
        voices,
    ) = _load_extract_manifest(extract_dir)
    extracted_items = extract_report.get("voices")
    if (
        source_plan_digest != expected_source_plan_digest
        or extract_report.get("source_plan_digest") != expected_source_plan_digest
        or chat.get("chat_id") != expected_chat_id
        or not isinstance(extracted_items, list)
        or len(extracted_items) != len(voices)
        or len(voices) != len(messages)
    ):
        raise VaultError("MP4-only SILK 提取记录与确认计划不一致")
    prepared: list[
        tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]
    ] = []
    for sequence, (message, voice, extracted) in enumerate(
        zip(messages, voices, extracted_items),
        1,
    ):
        if not isinstance(extracted, dict):
            raise VaultError(f"第 {sequence} 条流式语音提取记录无效")
        binding = extracted.get("chat_binding")
        packet_count = extracted.get("packet_count")
        if (
            voice.get("sequence") != sequence
            or extracted.get("sequence") != sequence
            or str(voice.get("server_id")) != str(extracted.get("server_id"))
            or str(voice.get("server_id"))
            != str(message.get("source_ref", {}).get("server_id"))
            or voice.get("sha256") != extracted.get("sha256")
            or voice.get("sha256")
            != extracted.get("source_voice_data_sha256")
            or voice.get("byte_count") != extracted.get("byte_count")
            or voice.get("frame_duration_ms")
            != extracted.get("frame_duration_ms")
            or voice.get("expected_duration_ms")
            != extracted.get("expected_duration_ms")
            or voice.get("expected_duration_ms")
            != _payload_int(message.get("payload", {}), "duration_ms")
            or type(packet_count) is not int
            or packet_count <= 0
            or packet_count * SILK_PACKET_MILLISECONDS
            != voice.get("frame_duration_ms")
        ):
            raise VaultError(f"第 {sequence} 条流式语音身份、哈希或帧字段不一致")
        if (
            not isinstance(binding, dict)
            or binding.get("status") != "verified"
            or binding.get("mapped_chat_id") != expected_chat_id
        ):
            raise VaultError(f"第 {sequence} 条流式语音聊天绑定无效")
        prepared.append((message, voice, extracted, binding))
    if output_path.exists() or output_path.is_symlink():
        raise VaultError("MP4-only ffmpeg 输出已存在，拒绝覆盖")

    ffmpeg, ffmpeg_package_version, ffmpeg_hash = _resolve_local_ffmpeg()
    output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    pcm_root = output_path.parent / ".voice-pcm"
    if pcm_root.exists() or pcm_root.is_symlink():
        raise VaultError("MP4-only PCM 临时目录已存在")
    pcm_root.mkdir(mode=0o700)
    stderr_path = output_path.parent / ".voice-ffmpeg.stderr"
    if stderr_path.exists() or stderr_path.is_symlink():
        raise VaultError("MP4-only ffmpeg 日志路径已存在")

    arguments = [
        str(ffmpeg),
        "-nostdin",
        "-hide_banner",
        "-loglevel",
        "error",
        "-f",
        "lavfi",
        "-i",
        "color=c=0x111827:s=1280x720:r=2",
        "-f",
        "s16le",
        "-ar",
        str(PCM_SAMPLE_RATE),
        "-ac",
        "1",
        "-i",
        "pipe:0",
        "-map",
        "0:v:0",
        "-map",
        "1:a:0",
        "-c:v",
        "libx264",
        "-preset",
        "veryfast",
        "-tune",
        "stillimage",
        "-pix_fmt",
        "yuv420p",
        "-c:a",
        "aac",
        "-b:a",
        "96000",
        "-ar",
        "48000",
        "-ac",
        "1",
        "-shortest",
        "-movflags",
        "+faststart",
        "-metadata",
        f"title={title}",
        "-n",
        str(output_path),
    ]
    process: Optional[subprocess.Popen[bytes]] = None
    failure: Optional[BaseException] = None
    evidence: list[dict[str, Any]] = []
    stream_hash = hashlib.sha256()
    total_samples = 0
    gap_samples = PCM_SAMPLE_RATE * VOICE_MP4_GAP_MILLISECONDS // 1_000
    gap_bytes = bytes(gap_samples * PCM_BYTES_PER_SAMPLE)
    deadline = time.monotonic() + VOICE_MP4_STREAM_TIMEOUT_SECONDS
    try:
        with stderr_path.open("xb") as stderr_handle:
            os.fchmod(stderr_handle.fileno(), 0o600)
            process = subprocess.Popen(
                arguments,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=stderr_handle,
                bufsize=0,
            )
            if process.stdin is None:
                raise VaultError("ffmpeg 未提供可写 PCM 输入")

            for sequence, (message, voice, extracted, binding) in enumerate(
                prepared,
                1,
            ):
                source = voice["source"]
                _require_plain_file(source, f"第 {sequence} 条 SILK")
                if (
                    source.stat().st_size != voice["byte_count"]
                    or _sha256_file(source) != voice["sha256"]
                ):
                    raise VaultError(f"第 {sequence} 条 SILK 在解码前发生变化")
                pcm_path = pcm_root / f"{sequence:04d}.pcm"
                try:
                    with pcm_path.open("xb") as pcm_handle:
                        os.fchmod(pcm_handle.fileno(), 0o600)
                    previous_umask = os.umask(0o077)
                    try:
                        _default_silk_decoder(source, pcm_path, PCM_SAMPLE_RATE)
                    finally:
                        os.umask(previous_umask)
                    _require_plain_file(pcm_path, f"第 {sequence} 条解码 PCM")
                    os.chmod(pcm_path, 0o600)
                    decoded_duration = _validate_pcm(
                        pcm_path,
                        voice["expected_duration_ms"],
                        voice["frame_duration_ms"],
                    )
                    if (
                        source.stat().st_size != voice["byte_count"]
                        or _sha256_file(source) != voice["sha256"]
                    ):
                        raise VaultError(f"第 {sequence} 条 SILK 在解码过程中发生变化")

                    pcm_byte_count = pcm_path.stat().st_size
                    pcm_sample_count = pcm_byte_count // PCM_BYTES_PER_SAMPLE
                    pcm_hash = _sha256_file(pcm_path)
                    start_sample = total_samples
                    with pcm_path.open("rb") as pcm_handle:
                        while True:
                            chunk = pcm_handle.read(VOICE_PCM_WRITE_CHUNK_BYTES)
                            if not chunk:
                                break
                            _write_ffmpeg_stdin(process, chunk, deadline)
                            stream_hash.update(chunk)
                    total_samples += pcm_sample_count
                    gap_after = gap_samples if sequence < len(voices) else 0
                    evidence.append(
                        {
                            "asset_id": _asset_id(message, "voice"),
                            "kind": "voice",
                            "status": "resolved",
                            "server_id": str(voice["server_id"]),
                            "voice_sequence": sequence,
                            "duration_ms": voice["expected_duration_ms"],
                            "frame_duration_ms": voice["frame_duration_ms"],
                            "packet_count": extracted["packet_count"],
                            "source_voice_data_sha256": voice["sha256"],
                            "chat_binding": deepcopy(binding),
                            "decoded_pcm_sha256": pcm_hash,
                            "decoded_pcm_byte_count": pcm_byte_count,
                            "decoded_pcm_sample_count": pcm_sample_count,
                            "decoded_pcm_duration_ms": decoded_duration,
                            "pcm_start_sample": start_sample,
                            "pcm_end_sample": total_samples,
                            "gap_after_samples": gap_after,
                        }
                    )
                    if gap_after:
                        _write_ffmpeg_stdin(process, gap_bytes, deadline)
                        stream_hash.update(gap_bytes)
                        total_samples += gap_after
                finally:
                    pcm_path.unlink(missing_ok=True)

            if _sha256_file(source_manifest) != source_manifest_hash:
                raise VaultError("SILK 提取清单在流式解码过程中发生变化")
            process.stdin.close()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(
                    arguments,
                    VOICE_MP4_STREAM_TIMEOUT_SECONDS,
                )
            returncode = process.wait(timeout=remaining)
            stderr_handle.flush()
            if returncode != 0:
                raise VaultError(
                    "ffmpeg 流式 MP4 编码失败："
                    + (_bounded_ffmpeg_log(stderr_path) or f"exit={returncode}")
                )
    except BaseException as error:
        failure = error
        if process is not None:
            _stop_ffmpeg_process(process)
    finally:
        shutil.rmtree(pcm_root, ignore_errors=True)

    stderr_detail = _bounded_ffmpeg_log(stderr_path)
    stderr_path.unlink(missing_ok=True)
    if failure is not None:
        output_path.unlink(missing_ok=True)
        if isinstance(failure, VaultError):
            raise failure
        if isinstance(failure, subprocess.TimeoutExpired):
            raise VaultError("ffmpeg 流式 MP4 编码超时") from failure
        if isinstance(failure, (BrokenPipeError, OSError)):
            detail = f"：{stderr_detail}" if stderr_detail else ""
            raise VaultError(f"ffmpeg 流式 PCM 输入失败{detail}") from failure
        raise failure

    try:
        _require_plain_file(output_path, "MP4-only 最终 MP4")
        if output_path.stat().st_size <= 0:
            raise VaultError("MP4-only 最终 MP4 为空")
        os.chmod(output_path, 0o600)
        expected_duration = int(round(total_samples * 1_000 / PCM_SAMPLE_RATE))
        inspection = _probe_streamed_voice_mp4(
            ffmpeg,
            output_path,
            expected_duration,
        )
    except BaseException:
        output_path.unlink(missing_ok=True)
        raise

    return evidence, {
        "relative_path": "media/voice.mp4",
        "sha256": _sha256_file(output_path),
        "byte_count": output_path.stat().st_size,
        "item_count": len(evidence),
        "source_extract_plan_digest": source_plan_digest,
        "duration_ms": inspection["duration_ms"],
        "container_duration_ms": inspection["container_duration_ms"],
        "duration_tolerance_ms": inspection["duration_tolerance_ms"],
        "audio_codec": inspection["audio_codec"],
        "video_codec": inspection["video_codec"],
        "encoder": "local-imageio-ffmpeg-stream",
        "ffmpeg_package_version": ffmpeg_package_version,
        "ffmpeg_binary_sha256": ffmpeg_hash,
        "pcm_sample_rate": PCM_SAMPLE_RATE,
        "pcm_channels": 1,
        "pcm_sample_format": "s16le",
        "pcm_stream_sha256": stream_hash.hexdigest(),
        "pcm_total_samples": total_samples,
        "pcm_total_bytes": total_samples * PCM_BYTES_PER_SAMPLE,
        "gap_milliseconds": VOICE_MP4_GAP_MILLISECONDS,
        "gap_samples": gap_samples,
    }


def _export_voices_mp4_only_fast(
    vault: Path,
    plan: dict[str, Any],
    messages: list[dict[str, Any]],
    staging: Path,
    title: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    voice_plan = _voice_subplan(plan, messages)
    if (
        not voice_plan["voices"]
        or any(item["duration_ms"] is None for item in voice_plan["voices"])
    ):
        raise VaultError("MP4-only 语音缺少可验证的时长元数据")
    plan_path = staging / ".voice-plan.json"
    _write_json_private(plan_path, voice_plan, vault=None)
    silk_dir = staging / "media/voices-silk"
    try:
        extract_report = extract_voices(vault, plan_path, silk_dir)
        return _stream_voice_pcm_to_mp4(
            silk_dir,
            extract_report,
            messages,
            staging / "media/voice.mp4",
            title=title,
            expected_chat_id=plan["chat"]["chat_id"],
            expected_source_plan_digest=voice_plan["plan_digest"],
        )
    finally:
        plan_path.unlink(missing_ok=True)


def _assemble_direct_with_ffmpeg(
    manifest_path: Path,
    output_path: Path,
    *,
    title: str,
    gap_milliseconds: int = 300,
) -> dict[str, Any]:
    """Strict local fallback when this macOS cannot encode with AVFoundation."""

    if gap_milliseconds < 0 or gap_milliseconds > 5_000:
        raise VaultError("ffmpeg 语音间隔超出安全范围")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VaultError("ffmpeg 直连清单不可读") from error
    items = manifest.get("items") if isinstance(manifest, dict) else None
    expected_count = manifest.get("expected_count") if isinstance(manifest, dict) else None
    if (
        not isinstance(items, list)
        or not items
        or expected_count != len(items)
    ):
        raise VaultError("ffmpeg 直连清单条数无效")
    sources: list[Path] = []
    durations: list[int] = []
    seen_servers: set[str] = set()
    for sequence, item in enumerate(items, 1):
        if not isinstance(item, dict) or item.get("sequence") != sequence:
            raise VaultError("ffmpeg 直连清单 sequence 无效")
        server_id = str(item.get("server_id") or "")
        relative = item.get("source_path")
        duration = item.get("expected_duration_milliseconds")
        expected_hash = item.get("sha256")
        if (
            not server_id.isdigit()
            or server_id == "0"
            or server_id in seen_servers
            or not isinstance(relative, str)
            or Path(relative).name != relative
            or Path(relative).suffix.casefold() != ".m4a"
            or type(duration) is not int
            or not DIRECT_VOICE_MIN_DURATION_MILLISECONDS
            <= duration
            <= DIRECT_VOICE_MAX_DURATION_MILLISECONDS
            or not re.fullmatch(r"[0-9a-f]{64}", str(expected_hash or ""))
        ):
            raise VaultError("ffmpeg 直连清单条目无效")
        source = manifest_path.parent / relative
        if (
            source.is_symlink()
            or not source.is_file()
            or source.resolve().parent != manifest_path.parent.resolve()
            or _sha256_file(source) != expected_hash
        ):
            raise VaultError(f"ffmpeg 第 {sequence} 条 M4A 未通过哈希验证")
        seen_servers.add(server_id)
        sources.append(source)
        durations.append(duration)
    expected_duration = sum(durations) + gap_milliseconds * (len(items) - 1)

    try:
        import imageio_ffmpeg  # type: ignore[import-not-found]

        ffmpeg = Path(imageio_ffmpeg.get_ffmpeg_exe()).resolve(strict=True)
    except (ImportError, OSError, RuntimeError) as error:
        raise VaultError("无法定位本地 ffmpeg MP4 编码器") from error
    if ffmpeg.is_symlink() or not ffmpeg.is_file() or not os.access(ffmpeg, os.X_OK):
        raise VaultError("本地 ffmpeg MP4 编码器不可执行")
    if output_path.exists() or output_path.is_symlink():
        raise VaultError("ffmpeg MP4 输出已存在，拒绝覆盖")

    arguments = [
        str(ffmpeg),
        "-nostdin",
        "-hide_banner",
        "-loglevel",
        "error",
        "-f",
        "lavfi",
        "-i",
        (
            "color=c=0x111827:s=1280x720:r=2:"
            f"d={expected_duration / 1_000:.3f}"
        ),
    ]
    for source in sources:
        arguments.extend(["-i", str(source)])
    filters: list[str] = []
    concat_inputs: list[str] = []
    for index in range(len(sources)):
        input_index = index + 1
        filters.append(
            f"[{input_index}:a]"
            "aresample=48000,"
            "aformat=sample_fmts=fltp:sample_rates=48000:channel_layouts=mono,"
            f"asetpts=PTS-STARTPTS[a{index}]"
        )
        concat_inputs.append(f"[a{index}]")
        if index + 1 < len(sources) and gap_milliseconds:
            gap_seconds = gap_milliseconds / 1_000
            filters.append(
                "anullsrc=channel_layout=mono:sample_rate=48000:"
                f"d={gap_seconds:.3f}[g{index}]"
            )
            concat_inputs.append(f"[g{index}]")
    filters.append(
        "".join(concat_inputs)
        + f"concat=n={len(concat_inputs)}:v=0:a=1[aout]"
    )
    arguments.extend(
        [
            "-filter_complex",
            ";".join(filters),
            "-map",
            "0:v:0",
            "-map",
            "[aout]",
            "-c:v",
            "libx264",
            "-preset",
            "veryfast",
            "-tune",
            "stillimage",
            "-pix_fmt",
            "yuv420p",
            "-c:a",
            "aac",
            "-b:a",
            "96000",
            "-shortest",
            "-movflags",
            "+faststart",
            "-metadata",
            f"title={title}",
            "-t",
            f"{expected_duration / 1_000:.3f}",
            "-n",
            str(output_path),
        ]
    )
    try:
        completed = subprocess.run(
            arguments,
            capture_output=True,
            text=True,
            check=False,
            timeout=900,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VaultError("无法完成本地 ffmpeg MP4 合并") from error
    if completed.returncode != 0 or not output_path.is_file():
        detail = (completed.stderr or completed.stdout or "无错误输出").strip()[-4000:]
        raise VaultError(f"ffmpeg 语音 MP4 合并失败：{detail}")
    os.chmod(output_path, 0o600)

    probe = subprocess.run(
        [
            str(ffmpeg),
            "-nostdin",
            "-hide_banner",
            "-i",
            str(output_path),
            "-map",
            "0:v:0",
            "-map",
            "0:a:0",
            "-f",
            "null",
            "-",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=900,
    )
    if probe.returncode != 0:
        raise VaultError("ffmpeg 最终 MP4 音视频解码校验失败")
    probe_output = (probe.stderr or "") + "\n" + (probe.stdout or "")
    actual_duration = _ffmpeg_duration_milliseconds(probe_output)
    container_duration = _ffmpeg_container_duration_milliseconds(probe_output)
    tolerance = max(1_000, int(expected_duration * 0.02))
    if abs(actual_duration - expected_duration) > tolerance:
        raise VaultError(
            "ffmpeg 最终 MP4 时长与逐条语音清单不一致"
            f"（清单 {expected_duration}ms，成品 {actual_duration}ms，"
            f"容差 {tolerance}ms）"
        )
    if abs(container_duration - expected_duration) > tolerance:
        raise VaultError(
            "ffmpeg 最终 MP4 容器时长与逐条语音清单不一致"
            f"（清单 {expected_duration}ms，容器 {container_duration}ms，"
            f"容差 {tolerance}ms）"
        )
    return {
        "output": str(output_path.resolve()),
        "itemCount": len(items),
        "durationMilliseconds": actual_duration,
        "fileSize": output_path.stat().st_size,
        "sha256": _sha256_file(output_path),
        "encoder": "local-imageio-ffmpeg",
    }


def _export_voices(
    vault: Path,
    plan: dict[str, Any],
    messages: list[dict[str, Any]],
    staging: Path,
    swift_bin: Optional[Union[str, Path]],
    title: str,
) -> tuple[list[dict[str, Any]], Optional[dict[str, Any]]]:
    voice_messages = [item for item in messages if item["kind"] == "voice"]
    if not voice_messages:
        return [], None
    if swift_bin is None:
        return (
            [
                {
                    "asset_id": _asset_id(message, "voice"),
                    "kind": "voice",
                    "status": "unsupported",
                    "reason": "voice_decoder_unavailable",
                }
                for message in voice_messages
            ],
            None,
        )
    swift = Path(swift_bin).expanduser().resolve()
    if swift.is_symlink() or not swift.is_file() or not os.access(swift, os.X_OK):
        raise VaultError("Swift 语音工具不存在或不可执行")
    voice_plan = _voice_subplan(plan, messages)
    if any(item["duration_ms"] is None for item in voice_plan["voices"]):
        return (
            [
                {
                    "asset_id": _asset_id(message, "voice"),
                    "kind": "voice",
                    "status": "corrupt",
                    "reason": "duration_metadata_missing",
                }
                for message in voice_messages
            ],
            None,
        )
    plan_path = staging / ".voice-plan.json"
    _write_json_private(plan_path, voice_plan, vault=None)
    silk_dir = staging / "media/voices-silk"
    extract_report = extract_voices(vault, plan_path, silk_dir)
    m4a_dir = staging / "media/voices"
    decode_report = decode_voices(silk_dir, m4a_dir, swift, title)
    mp4_path = staging / "media/voice.mp4"
    completed = subprocess.run(
        [str(swift), "assemble-direct", "--manifest", decode_report["manifest"], "--output", str(mp4_path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=900,
    )
    if completed.returncode != 0 or not mp4_path.is_file():
        detail = (completed.stderr or completed.stdout or "无错误输出").strip()[-4000:]
        known_encoder_failure = (
            "Cannot Encode" in detail
            or (
                "1718449215" in detail
                and "avfaudio" in detail.casefold()
            )
        )
        if not known_encoder_failure:
            raise VaultError(f"语音 MP4 合并失败：{detail}")
        if mp4_path.is_symlink():
            raise VaultError("Swift 失败后出现不安全的 MP4 路径")
        mp4_path.unlink(missing_ok=True)
        _assemble_direct_with_ffmpeg(
            Path(decode_report["manifest"]),
            mp4_path,
            title=title,
        )
    os.chmod(mp4_path, 0o600)
    direct_manifest = json.loads(Path(decode_report["manifest"]).read_text(encoding="utf-8"))
    assets: list[dict[str, Any]] = []
    direct_items = direct_manifest.get("items")
    extract_items = extract_report.get("voices")
    if not isinstance(direct_items, list) or not isinstance(extract_items, list):
        raise VaultError("语音流水线缺少逐条验证记录")
    by_server = {str(item.get("server_id")): item for item in direct_items}
    extracted_by_server = {
        str(item.get("server_id")): item for item in extract_items
    }
    if (
        len(by_server) != len(direct_items)
        or len(extracted_by_server) != len(extract_items)
        or set(by_server) != set(extracted_by_server)
        or len(by_server) != len(voice_messages)
    ):
        raise VaultError("语音流水线逐条记录缺失、重复或不一致")
    for message in voice_messages:
        server_id = message["source_ref"]["server_id"]
        if server_id not in by_server or server_id not in extracted_by_server:
            raise VaultError(f"语音流水线缺少 server_id={server_id} 的验证记录")
        item = by_server[server_id]
        extracted = extracted_by_server[server_id]
        relative = Path("media/voices") / item["source_path"]
        assets.append(
            {
                "asset_id": _asset_id(message, "voice"),
                "kind": "voice",
                "status": "resolved",
                "server_id": server_id,
                "voice_sequence": item["sequence"],
                "relative_path": str(relative),
                "format": "m4a",
                "duration_ms": item["expected_duration_milliseconds"],
                "sha256": item["sha256"],
                "byte_count": (staging / relative).stat().st_size,
                "source_voice_data_sha256": extracted[
                    "source_voice_data_sha256"
                ],
                "frame_duration_ms": extracted["frame_duration_ms"],
                "packet_count": extracted["packet_count"],
                "chat_binding": deepcopy(extracted["chat_binding"]),
            }
        )
    mp4_asset = {
        "relative_path": "media/voice.mp4",
        "sha256": _sha256_file(mp4_path),
        "byte_count": mp4_path.stat().st_size,
        "item_count": len(assets),
        "source_extract_plan_digest": extract_report["source_plan_digest"],
    }
    plan_path.unlink(missing_ok=True)
    return assets, mp4_asset


def _message_summary(message: dict[str, Any]) -> str:
    payload = message.get("payload", {})
    for key in ("text", "title", "description", "label", "filename", "raw"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if key == "raw" and isinstance(value, dict):
            preview = value.get("preview")
            if isinstance(preview, str) and preview.strip():
                return preview.strip()
    return f"[{message['kind']}]"


def _render_markdown(messages: list[dict[str, Any]], assets: list[dict[str, Any]], title: str) -> str:
    by_id = {item["asset_id"]: item for item in assets}
    lines = [f"# {title}", "", "本归档由本地只读快照生成；视频正文未导出。", ""]
    for message in messages:
        sender = html.escape(str(message.get("sender_id") or "未知发送者"))
        lines.append(f"## {message['sequence']}. {message['time_iso8601']} · {sender}")
        lines.append("")
        lines.append(html.escape(_message_summary(message)))
        for asset_id in message.get("asset_ids", []):
            asset = by_id.get(asset_id)
            if not asset:
                continue
            relative = asset.get("relative_path")
            if relative and asset["status"] == "resolved":
                if asset["kind"] in {"image", "sticker"}:
                    lines.append(f"![{asset['kind']}]({relative})")
                else:
                    lines.append(f"[{asset['kind']}]({relative})")
            else:
                lines.append(f"`{asset['kind']}: {asset['status']}`")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _render_html(messages: list[dict[str, Any]], assets: list[dict[str, Any]], title: str) -> str:
    by_id = {item["asset_id"]: item for item in assets}
    cards: list[str] = []
    for message in messages:
        body = [f"<p>{html.escape(_message_summary(message))}</p>"]
        for asset_id in message.get("asset_ids", []):
            asset = by_id.get(asset_id)
            if not asset:
                continue
            relative = html.escape(str(asset.get("relative_path") or ""), quote=True)
            if relative and asset["status"] == "resolved" and asset["kind"] in {"image", "sticker"}:
                body.append(f'<img loading="lazy" src="{relative}" alt="{asset["kind"]}">')
            elif relative and asset["status"] == "resolved" and asset["kind"] == "voice":
                body.append(f'<audio controls preload="none" src="{relative}"></audio>')
            elif relative and asset["status"] == "resolved":
                body.append(f'<a href="{relative}">打开 {asset["kind"]}</a>')
            else:
                body.append(f'<code>{html.escape(asset["kind"])}: {html.escape(asset["status"])}</code>')
        sender = html.escape(str(message.get("sender_id") or "未知发送者"))
        timestamp = html.escape(message["time_iso8601"])
        cards.append(f'<article><header>{message["sequence"]}. {timestamp} · {sender}</header>{"".join(body)}</article>')
    safe_title = html.escape(title)
    return (
        "<!doctype html><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">"
        f"<title>{safe_title}</title><style>body{{max-width:860px;margin:2rem auto;padding:0 1rem;"
        "font:16px/1.55 -apple-system,sans-serif;background:#f5f5f5;color:#222}}article{background:white;"
        "padding:1rem;margin:1rem 0;border-radius:12px}header{color:#666;font-size:.9rem}img{max-width:100%;"
        "max-height:640px}audio{width:100%}code{color:#a33}</style>"
        f"<h1>{safe_title}</h1><p>本地只读归档；视频正文未导出。</p>{''.join(cards)}"
    )


def _verify_staged_archive(
    staging: Path,
    manifest: dict[str, Any],
    messages: list[dict[str, Any]],
) -> dict[str, Any]:
    """Re-read staged output and verify every published hash before rename."""

    root = staging.resolve(strict=True)
    try:
        disk_manifest = json.loads((staging / "manifest.json").read_text(encoding="utf-8"))
        disk_messages = json.loads((staging / "messages.json").read_text(encoding="utf-8"))
        disk_jsonl = [
            json.loads(line)
            for line in (staging / "messages.jsonl").read_text(encoding="utf-8").splitlines()
            if line
        ]
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VaultError("暂存归档无法重新读取验证") from error
    if disk_manifest != manifest:
        raise VaultError("暂存 manifest 与内存结果不一致")
    if disk_messages != messages or disk_jsonl != messages:
        raise VaultError("暂存消息文件与确认计划不一致")

    summary = manifest.get("summary")
    issues = manifest.get("issues")
    if not isinstance(summary, dict) or summary.get("message_count") != len(messages):
        raise VaultError("暂存 manifest 消息数量不一致")
    if not isinstance(issues, list) or summary.get("issue_count") != len(issues):
        raise VaultError("暂存 manifest 问题数量不一致")
    if manifest.get("mode") == "strict" and issues:
        raise VaultError("严格归档不得包含未确认问题")

    integrity = manifest.get("integrity")
    if not isinstance(integrity, dict):
        raise VaultError("暂存 manifest 缺少完整性摘要")
    unsigned = deepcopy(manifest)
    unsigned.pop("integrity", None)
    manifest_hash = _sha256_bytes(_canonical_json(unsigned))
    if integrity.get("canonical_manifest_sha256") != manifest_hash:
        raise VaultError("暂存 manifest 完整性摘要不匹配")

    assets = manifest.get("assets")
    if not isinstance(assets, list):
        raise VaultError("暂存 manifest 资源列表无效")
    asset_ids: set[str] = set()
    asset_by_id: dict[str, dict[str, Any]] = {}
    published_paths: set[Path] = set()
    resolved_count = 0

    def verify_hashed_file(record: dict[str, Any], description: str) -> None:
        nonlocal resolved_count
        relative_value = record.get("relative_path")
        expected_hash = record.get("sha256")
        expected_bytes = record.get("byte_count")
        if (
            not isinstance(relative_value, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_hash or "")
            or type(expected_bytes) is not int
            or expected_bytes < 0
        ):
            raise VaultError(f"{description}缺少路径或 SHA-256")
        relative = Path(relative_value)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or relative_value != relative.as_posix()
        ):
            raise VaultError(f"{description}路径无效或重复")
        candidate = staging / relative
        if candidate.is_symlink() or not candidate.is_file():
            raise VaultError(f"{description}文件缺失或不安全")
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise VaultError(f"{description}文件无法安全解析") from error
        if not _is_relative_to(resolved, root):
            raise VaultError(f"{description}路径逃逸")
        if resolved in published_paths:
            raise VaultError(f"{description}路径无效或重复")
        if _sha256_file(resolved) != expected_hash:
            raise VaultError(f"{description}发布前哈希不一致")
        if resolved.stat().st_size != expected_bytes:
            raise VaultError(f"{description}发布前大小不一致")
        published_paths.add(resolved)
        resolved_count += 1

    for asset in assets:
        if not isinstance(asset, dict):
            raise VaultError("暂存 manifest 包含无效资源记录")
        asset_id = asset.get("asset_id")
        if not isinstance(asset_id, str) or asset_id in asset_ids:
            raise VaultError("暂存 manifest 资源 ID 缺失或重复")
        asset_ids.add(asset_id)
        asset_by_id[asset_id] = asset
        if asset.get("status") == "resolved" or "relative_path" in asset:
            verify_hashed_file(asset, "已解决资源")

    referenced_counts = {asset_id: 0 for asset_id in asset_ids}
    message_ids: set[str] = set()
    sequences: set[int] = set()
    for message in messages:
        message_id = message.get("message_id")
        sequence = message.get("sequence")
        if (
            not isinstance(message_id, str)
            or message_id in message_ids
            or type(sequence) is not int
            or sequence in sequences
        ):
            raise VaultError("暂存消息 ID 或序号缺失或重复")
        message_ids.add(message_id)
        sequences.add(sequence)
        references = message.get("asset_ids")
        if not isinstance(references, list) or any(
            not isinstance(asset_id, str) or asset_id not in asset_ids
            for asset_id in references
        ):
            raise VaultError("消息引用了不存在的资源")
        if len(references) != len(set(references)):
            raise VaultError("消息包含重复资源引用")
        for asset_id in references:
            asset = asset_by_id[asset_id]
            kind = asset.get("kind")
            if (
                not isinstance(kind, str)
                or kind != message.get("kind")
                or asset_id != _asset_id(message, kind)
            ):
                raise VaultError("消息与资源身份不一致")
            referenced_counts[asset_id] += 1
    if any(count != 1 for count in referenced_counts.values()):
        raise VaultError("资源必须且只能被一条消息引用")

    actual_kind_counts: dict[str, int] = {}
    for message in messages:
        kind = message.get("kind")
        if not isinstance(kind, str):
            raise VaultError("暂存消息类型无效")
        actual_kind_counts[kind] = actual_kind_counts.get(kind, 0) + 1
    actual_status_counts: dict[str, int] = {}
    for asset in assets:
        status = asset.get("status")
        if not isinstance(status, str):
            raise VaultError("暂存资源状态无效")
        actual_status_counts[status] = actual_status_counts.get(status, 0) + 1
    if summary.get("counts_by_kind") != dict(sorted(actual_kind_counts.items())):
        raise VaultError("暂存 manifest 消息类型统计不一致")
    if summary.get("asset_status_counts") != dict(sorted(actual_status_counts.items())):
        raise VaultError("暂存 manifest 资源状态统计不一致")

    expected_issues: set[tuple[int, str, str, str]] = set()
    for message in messages:
        for asset_id in message["asset_ids"]:
            asset = asset_by_id[asset_id]
            if asset["status"] in FATAL_ASSET_STATES:
                expected_issues.add(
                    (
                        message["sequence"],
                        message["message_id"],
                        message["kind"],
                        asset["status"],
                    )
                )
    actual_issues: set[tuple[int, str, str, str]] = set()
    for issue in issues:
        if not isinstance(issue, dict):
            raise VaultError("暂存 manifest 问题记录无效")
        identity = (
            issue.get("sequence"),
            issue.get("message_id"),
            issue.get("kind"),
            issue.get("status"),
        )
        if identity in actual_issues:
            raise VaultError("暂存 manifest 包含重复问题记录")
        actual_issues.add(identity)
    if actual_issues != expected_issues:
        raise VaultError("暂存 manifest 问题记录与未解决资源不一致")

    voice_mp4 = manifest.get("voice_mp4")
    if voice_mp4 is not None:
        if not isinstance(voice_mp4, dict):
            raise VaultError("语音 MP4 记录无效")
        verify_hashed_file(voice_mp4, "语音 MP4")

    for relative in ("chat.md", "index.html"):
        path = staging / relative
        if path.is_symlink() or not path.is_file():
            raise VaultError("暂存归档缺少可读入口")
    return {
        "status": "verified-before-atomic-publish",
        "message_count": len(messages),
        "resolved_file_count": resolved_count,
        "manifest_sha256": manifest_hash,
    }


def _voice_mp4_only_source_fingerprint_digest(plan: dict[str, Any]) -> str:
    fingerprints = plan.get("source_databases")
    if not isinstance(fingerprints, list) or not fingerprints:
        raise VaultError("内容计划缺少源数据库指纹")
    return _sha256_bytes(_canonical_json(fingerprints))


def _require_voice_mp4_only_plan(plan: dict[str, Any]) -> None:
    messages = plan.get("messages")
    selection = plan.get("selection")
    if (
        not isinstance(messages, list)
        or not messages
        or not isinstance(selection, dict)
        or selection.get("types") != ["voice"]
        or plan.get("counts_by_kind") != {"voice": len(messages)}
        or any(
            not isinstance(message, dict) or message.get("kind") != "voice"
            for message in messages
        )
    ):
        raise VaultError(
            "--voice-mp4-only 只接受扫描时明确仅选择 voice 的非空计划"
        )


def _voice_mp4_only_items(
    plan: dict[str, Any],
    messages: list[dict[str, Any]],
    assets: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if len(assets) != len(messages):
        raise VaultError("MP4-only 语音条数与确认计划不一致")
    by_server: dict[str, dict[str, Any]] = {}
    for asset in assets:
        server_id = str(asset.get("server_id") or "")
        if not server_id or server_id == "0" or server_id in by_server:
            raise VaultError("MP4-only 语音 server_id 缺失或重复")
        by_server[server_id] = asset

    result: list[dict[str, Any]] = []
    expected_start_sample = 0
    expected_gap_samples = (
        PCM_SAMPLE_RATE * VOICE_MP4_GAP_MILLISECONDS // 1_000
    )
    for sequence, message in enumerate(messages, 1):
        server_id = str(message.get("source_ref", {}).get("server_id") or "")
        asset = by_server.get(server_id)
        duration_ms = _payload_int(message.get("payload", {}), "duration_ms")
        if (
            asset is None
            or asset.get("asset_id") != _asset_id(message, "voice")
            or asset.get("kind") != "voice"
            or asset.get("status") != "resolved"
            or asset.get("voice_sequence") != sequence
            or duration_ms is None
            or asset.get("duration_ms") != duration_ms
        ):
            raise VaultError(f"第 {sequence} 条语音未通过 MP4-only 身份或时长校验")

        chat_binding = asset.get("chat_binding")
        if (
            not isinstance(chat_binding, dict)
            or chat_binding.get("status") != "verified"
            or chat_binding.get("mapped_chat_id") != plan["chat"]["chat_id"]
        ):
            raise VaultError(f"第 {sequence} 条语音无法验证属于确认的聊天")

        source_hash = asset.get("source_voice_data_sha256")
        decoded_hash = asset.get("decoded_pcm_sha256")
        decoded_bytes = asset.get("decoded_pcm_byte_count")
        decoded_samples = asset.get("decoded_pcm_sample_count")
        decoded_duration = asset.get("decoded_pcm_duration_ms")
        start_sample = asset.get("pcm_start_sample")
        end_sample = asset.get("pcm_end_sample")
        gap_after = asset.get("gap_after_samples")
        frame_duration_ms = asset.get("frame_duration_ms")
        packet_count = asset.get("packet_count")
        required_gap = expected_gap_samples if sequence < len(messages) else 0
        if (
            not re.fullmatch(r"[0-9a-f]{64}", source_hash or "")
            or not re.fullmatch(r"[0-9a-f]{64}", decoded_hash or "")
            or type(decoded_bytes) is not int
            or decoded_bytes <= 0
            or type(decoded_samples) is not int
            or decoded_samples <= 0
            or decoded_bytes != decoded_samples * PCM_BYTES_PER_SAMPLE
            or type(decoded_duration) is not int
            or decoded_duration
            != int(round(decoded_samples * 1_000 / PCM_SAMPLE_RATE))
            or type(start_sample) is not int
            or start_sample < 0
            or type(end_sample) is not int
            or end_sample <= start_sample
            or type(gap_after) is not int
            or gap_after < 0
            or start_sample != expected_start_sample
            or end_sample != start_sample + decoded_samples
            or gap_after != required_gap
            or type(frame_duration_ms) is not int
            or frame_duration_ms <= 0
            or type(packet_count) is not int
            or packet_count <= 0
        ):
            raise VaultError(f"第 {sequence} 条语音缺少完整的逐条验证证据")

        result.append(
            {
                "sequence": sequence,
                "message_id": message["message_id"],
                "server_id": server_id,
                "create_time": message["create_time"],
                "expected_duration_ms": duration_ms,
                "frame_duration_ms": frame_duration_ms,
                "packet_count": packet_count,
                "source_voice_data_sha256": source_hash,
                "decoded_pcm_sha256": decoded_hash,
                "decoded_pcm_byte_count": decoded_bytes,
                "decoded_pcm_sample_count": decoded_samples,
                "decoded_pcm_duration_ms": decoded_duration,
                "pcm_start_sample": start_sample,
                "pcm_end_sample": end_sample,
                "gap_after_samples": gap_after,
                "chat_binding": "verified",
            }
        )
        expected_start_sample = end_sample + gap_after
    if set(by_server) != {item["server_id"] for item in result}:
        raise VaultError("MP4-only 语音验证记录包含计划外条目")
    return result


def _verify_staged_voice_mp4_only(
    staging: Path,
    manifest: dict[str, Any],
    plan: dict[str, Any],
) -> dict[str, Any]:
    """Verify the two-file MP4-only publication before its atomic rename."""

    expected_names = {"manifest.json", "voice.mp4"}
    try:
        entries = list(staging.iterdir())
        disk_manifest = json.loads(
            (staging / "manifest.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VaultError("MP4-only 暂存结果无法重新读取验证") from error
    if (
        {entry.name for entry in entries} != expected_names
        or any(entry.is_symlink() or not entry.is_file() for entry in entries)
    ):
        raise VaultError("MP4-only 最终目录必须且只能包含 MP4 与 manifest")
    if disk_manifest != manifest:
        raise VaultError("MP4-only 暂存 manifest 与内存结果不一致")
    if (
        manifest.get("schema") != "wechat-local-voice-mp4-export"
        or manifest.get("schema_version") != VOICE_MP4_ONLY_SCHEMA_VERSION
        or manifest.get("mode") != "strict"
        or manifest.get("output_mode") != "voice-mp4-only"
        or manifest.get("issues") != []
        or manifest.get("source_plan_digest") != plan["plan_digest"]
        or manifest.get("source_database_fingerprint_digest")
        != _voice_mp4_only_source_fingerprint_digest(plan)
    ):
        raise VaultError("MP4-only manifest 来源、模式或严格状态不一致")

    messages = plan["messages"]
    summary = manifest.get("summary")
    voices = manifest.get("voices")
    if (
        not isinstance(summary, dict)
        or summary.get("message_count") != len(messages)
        or summary.get("voice_count") != len(messages)
        or summary.get("issue_count") != 0
        or not isinstance(voices, list)
        or len(voices) != len(messages)
    ):
        raise VaultError("MP4-only manifest 条数不一致")

    seen_messages: set[str] = set()
    seen_servers: set[str] = set()
    expected_start_sample = 0
    expected_gap_samples = (
        PCM_SAMPLE_RATE * VOICE_MP4_GAP_MILLISECONDS // 1_000
    )
    for sequence, (message, voice) in enumerate(zip(messages, voices), 1):
        if not isinstance(voice, dict):
            raise VaultError("MP4-only manifest 包含无效语音记录")
        duration_ms = _payload_int(message.get("payload", {}), "duration_ms")
        server_id = str(message.get("source_ref", {}).get("server_id") or "")
        message_id = message.get("message_id")
        if (
            voice.get("sequence") != sequence
            or voice.get("message_id") != message_id
            or voice.get("server_id") != server_id
            or voice.get("create_time") != message.get("create_time")
            or voice.get("expected_duration_ms") != duration_ms
            or voice.get("chat_binding") != "verified"
            or not isinstance(message_id, str)
            or message_id in seen_messages
            or server_id in seen_servers
        ):
            raise VaultError("MP4-only manifest 语音身份、顺序或聊天绑定不一致")
        for field in ("source_voice_data_sha256", "decoded_pcm_sha256"):
            if not re.fullmatch(r"[0-9a-f]{64}", str(voice.get(field) or "")):
                raise VaultError("MP4-only manifest 逐条哈希无效")
        for field in (
            "frame_duration_ms",
            "packet_count",
            "decoded_pcm_byte_count",
            "decoded_pcm_sample_count",
            "decoded_pcm_duration_ms",
            "pcm_end_sample",
        ):
            if type(voice.get(field)) is not int or voice[field] <= 0:
                raise VaultError("MP4-only manifest 逐条校验数据无效")
        start_sample = voice.get("pcm_start_sample")
        end_sample = voice["pcm_end_sample"]
        sample_count = voice["decoded_pcm_sample_count"]
        gap_after = voice.get("gap_after_samples")
        required_gap = expected_gap_samples if sequence < len(messages) else 0
        if (
            type(start_sample) is not int
            or start_sample < 0
            or type(gap_after) is not int
            or gap_after < 0
            or start_sample != expected_start_sample
            or end_sample != start_sample + sample_count
            or voice["decoded_pcm_byte_count"]
            != sample_count * PCM_BYTES_PER_SAMPLE
            or voice["decoded_pcm_duration_ms"]
            != int(round(sample_count * 1_000 / PCM_SAMPLE_RATE))
            or gap_after != required_gap
        ):
            raise VaultError("MP4-only manifest PCM 顺序、样本或间隔无效")
        expected_start_sample = end_sample + gap_after
        seen_messages.add(message_id)
        seen_servers.add(server_id)

    mp4 = manifest.get("voice_mp4")
    expected_duration = int(
        round(expected_start_sample * 1_000 / PCM_SAMPLE_RATE)
    )
    if (
        not isinstance(mp4, dict)
        or mp4.get("relative_path") != "voice.mp4"
        or mp4.get("item_count") != len(messages)
        or not re.fullmatch(r"[0-9a-f]{64}", str(mp4.get("sha256") or ""))
        or not re.fullmatch(
            r"[0-9a-f]{64}",
            str(mp4.get("pcm_stream_sha256") or ""),
        )
        or not re.fullmatch(
            r"[0-9a-f]{64}",
            str(mp4.get("ffmpeg_binary_sha256") or ""),
        )
        or type(mp4.get("byte_count")) is not int
        or mp4["byte_count"] <= 0
        or type(mp4.get("duration_ms")) is not int
        or mp4["duration_ms"] <= 0
        or type(mp4.get("container_duration_ms")) is not int
        or mp4["container_duration_ms"] <= 0
        or mp4.get("duration_tolerance_ms")
        != VOICE_MP4_DURATION_TOLERANCE_MILLISECONDS
        or abs(mp4["duration_ms"] - expected_duration)
        > VOICE_MP4_DURATION_TOLERANCE_MILLISECONDS
        or abs(mp4["container_duration_ms"] - expected_duration)
        > VOICE_MP4_DURATION_TOLERANCE_MILLISECONDS
        or mp4.get("audio_codec") != "aac"
        or mp4.get("video_codec") != "h264"
        or mp4.get("encoder") != "local-imageio-ffmpeg-stream"
        or not isinstance(mp4.get("ffmpeg_package_version"), str)
        or not mp4["ffmpeg_package_version"]
        or len(mp4["ffmpeg_package_version"]) > 100
        or mp4.get("pcm_sample_rate") != PCM_SAMPLE_RATE
        or mp4.get("pcm_channels") != 1
        or mp4.get("pcm_sample_format") != "s16le"
        or mp4.get("pcm_total_samples") != expected_start_sample
        or mp4.get("pcm_total_bytes")
        != expected_start_sample * PCM_BYTES_PER_SAMPLE
        or mp4.get("gap_milliseconds") != VOICE_MP4_GAP_MILLISECONDS
        or mp4.get("gap_samples") != expected_gap_samples
        or mp4.get("source_extract_plan_digest")
        != _voice_subplan(plan, messages)["plan_digest"]
    ):
        raise VaultError("MP4-only manifest 的最终 MP4 记录无效")
    mp4_path = staging / "voice.mp4"
    if (
        _sha256_file(mp4_path) != mp4["sha256"]
        or mp4_path.stat().st_size != mp4["byte_count"]
    ):
        raise VaultError("MP4-only 最终 MP4 哈希或大小不一致")

    integrity = manifest.get("integrity")
    if not isinstance(integrity, dict):
        raise VaultError("MP4-only manifest 缺少完整性摘要")
    unsigned = deepcopy(manifest)
    unsigned.pop("integrity", None)
    manifest_hash = _sha256_bytes(_canonical_json(unsigned))
    if integrity.get("canonical_manifest_sha256") != manifest_hash:
        raise VaultError("MP4-only manifest 完整性摘要不匹配")
    return {
        "status": "verified-before-atomic-publish",
        "message_count": len(messages),
        "resolved_file_count": 1,
        "manifest_sha256": manifest_hash,
    }


def export_archive(
    vault_dir: Union[str, Path],
    account_root: Union[str, Path],
    plan_path: Union[str, Path],
    approve_digest: str,
    output_dir: Union[str, Path],
    *,
    swift_bin: Optional[Union[str, Path]] = None,
    title: Optional[str] = None,
    allow_partial: bool = False,
    voice_mp4_only: bool = False,
) -> dict[str, Any]:
    plan = load_content_plan(plan_path)
    if approve_digest != plan["plan_digest"]:
        raise VaultError("--approve-digest 与扫描计划不一致")
    if voice_mp4_only and allow_partial:
        raise VaultError("--voice-mp4-only 不允许 --allow-partial")
    if voice_mp4_only:
        _require_voice_mp4_only_plan(plan)
    vault = verify_plan_sources(vault_dir, plan)
    account = _validate_account_root(account_root)
    raw_output = Path(output_dir).expanduser()
    if raw_output.is_symlink():
        raise VaultError("输出目录不能是符号链接")
    output = _ensure_output_outside_vault(raw_output, vault)
    if output.exists():
        raise VaultError(f"输出目录已存在，拒绝覆盖：{output}")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}-", dir=output.parent))
    os.chmod(staging, 0o700)
    messages = deepcopy(plan["messages"])
    for message in messages:
        message["_chat_id"] = plan["chat"]["chat_id"]
        message["asset_ids"] = []
    assets: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    clean_title = (title or f"{plan['chat']['display_name']} 微信归档").strip()
    if (
        not clean_title
        or len(clean_title) > 200
        or any(ord(character) < 32 for character in clean_title)
    ):
        raise VaultError("标题必须是 1...200 个不含控制字符的可见字符")
    try:
        if voice_mp4_only:
            voice_assets, voice_mp4 = _export_voices_mp4_only_fast(
                vault, plan, messages, staging, clean_title
            )
            voice_items = _voice_mp4_only_items(
                plan, messages, voice_assets
            )
            if (
                voice_mp4.get("relative_path") != "media/voice.mp4"
                or voice_mp4.get("item_count") != len(messages)
            ):
                raise VaultError("MP4-only 最终 MP4 条数或路径不一致")
            source_mp4 = staging / "media/voice.mp4"
            if (
                source_mp4.is_symlink()
                or not source_mp4.is_file()
                or _sha256_file(source_mp4) != voice_mp4.get("sha256")
                or source_mp4.stat().st_size != voice_mp4.get("byte_count")
            ):
                raise VaultError("MP4-only 最终 MP4 未通过发布前校验")
            final_mp4 = staging / "voice.mp4"
            os.replace(source_mp4, final_mp4)
            media_staging = staging / "media"
            if media_staging.is_symlink() or not media_staging.is_dir():
                raise VaultError("MP4-only 中间媒体目录无效")
            shutil.rmtree(media_staging)

            compact_manifest: dict[str, Any] = {
                "schema": "wechat-local-voice-mp4-export",
                "schema_version": VOICE_MP4_ONLY_SCHEMA_VERSION,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "source_plan_digest": plan["plan_digest"],
                "source_database_fingerprint_digest": (
                    _voice_mp4_only_source_fingerprint_digest(plan)
                ),
                "mode": "strict",
                "output_mode": "voice-mp4-only",
                "network_policy": "offline",
                "selection": {
                    "display_name": plan["chat"]["display_name"],
                    "kind": plan["chat"]["kind"],
                    "time_range": plan["time_range"],
                    "types": ["voice"],
                },
                "summary": {
                    "message_count": len(messages),
                    "voice_count": len(messages),
                    "issue_count": 0,
                },
                "voice_mp4": {
                    **voice_mp4,
                    "relative_path": "voice.mp4",
                },
                "voices": voice_items,
                "issues": [],
            }
            compact_manifest["integrity"] = {
                "canonical_manifest_sha256": _sha256_bytes(
                    _canonical_json(compact_manifest)
                )
            }
            _write_json_private(
                staging / "manifest.json", compact_manifest, vault=None
            )
            for path in staging.iterdir():
                if path.is_symlink() or not path.is_file():
                    raise VaultError("MP4-only 临时输出包含非普通文件")
                os.chmod(path, 0o600)
            verification = _verify_staged_voice_mp4_only(
                staging, compact_manifest, plan
            )
            staging.rename(output)
            return {
                "output_dir": str(output),
                "mp4": str(output / "voice.mp4"),
                "manifest": str(output / "manifest.json"),
                "output_mode": "voice-mp4-only",
                "message_count": len(messages),
                "asset_count": 1,
                "issue_count": 0,
                "plan_digest": plan["plan_digest"],
                "verification": verification,
            }

        for message in messages:
            asset: Optional[dict[str, Any]] = None
            if message["kind"] == "image":
                asset = _export_image(message, account, staging)
            elif message["kind"] == "file":
                asset = _export_file(message, account, staging)
            elif message["kind"] == "sticker":
                asset = _export_sticker(message, account, staging)
            elif message["kind"] == "video":
                asset = {
                    "asset_id": _asset_id(message, "video"),
                    "kind": "video",
                    "status": "excluded_by_policy",
                }
            if asset:
                assets.append(asset)
                message["asset_ids"].append(asset["asset_id"])
                if asset["status"] in FATAL_ASSET_STATES:
                    _record_issue(issues, message, asset["status"], str(asset.get("reason") or "asset_unresolved"))

        try:
            voice_assets, voice_mp4 = _export_voices(
                vault, plan, messages, staging, swift_bin, clean_title
            )
        except VaultError as error:
            if not allow_partial:
                raise
            for relative in (
                ".voice-plan.json",
                "media/voices-silk",
                "media/voices",
                "media/voice.mp4",
            ):
                target = staging / relative
                if target.is_dir():
                    shutil.rmtree(target, ignore_errors=True)
                else:
                    target.unlink(missing_ok=True)
            voice_mp4 = None
            voice_assets = [
                {
                    "asset_id": _asset_id(message, "voice"),
                    "kind": "voice",
                    "status": "corrupt",
                    "reason": "voice_pipeline_failed",
                    "detail": str(error)[:500],
                }
                for message in messages
                if message["kind"] == "voice"
            ]
        voice_by_server = {asset.get("server_id"): asset for asset in voice_assets}
        unresolved_voice = iter([item for item in voice_assets if "server_id" not in item])
        for message in (item for item in messages if item["kind"] == "voice"):
            asset = voice_by_server.get(message["source_ref"]["server_id"])
            if asset is None:
                asset = next(unresolved_voice)
            assets.append(asset)
            message["asset_ids"].append(asset["asset_id"])
            if asset["status"] in FATAL_ASSET_STATES:
                _record_issue(issues, message, asset["status"], str(asset.get("reason") or "voice_unresolved"))

        if issues and not allow_partial:
            counts: dict[str, int] = {}
            for issue in issues:
                counts[issue["status"]] = counts.get(issue["status"], 0) + 1
            summary = ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))
            bounded = "; ".join(
                "#{sequence}:{kind}:{status}:{detail}".format(**issue)
                for issue in issues[:20]
            )
            remainder = len(issues) - 20
            if remainder > 0:
                bounded += f"; 另有 {remainder} 项"
            raise VaultError(
                f"严格导出发现未解决媒体（{summary}；{bounded}）；"
                "未发布任何归档。用户查看这些序号和原因后，才可另行确认 --allow-partial"
            )

        for message in messages:
            message.pop("_chat_id", None)
        status_counts: dict[str, int] = {}
        for asset in assets:
            status_counts[asset["status"]] = status_counts.get(asset["status"], 0) + 1
        manifest: dict[str, Any] = {
            "schema": "wechat-local-chat-export",
            "schema_version": ARCHIVE_SCHEMA_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_plan_digest": plan["plan_digest"],
            "mode": "partial-explicit" if allow_partial else "strict",
            "network_policy": "offline",
            "video_policy": "exclude_body",
            "selection": {
                "display_name": plan["chat"]["display_name"],
                "kind": plan["chat"]["kind"],
                "time_range": plan["time_range"],
            },
            "summary": {
                "message_count": len(messages),
                "counts_by_kind": plan["counts_by_kind"],
                "asset_status_counts": dict(sorted(status_counts.items())),
                "issue_count": len(issues),
            },
            "voice_mp4": voice_mp4,
            "assets": assets,
            "issues": issues,
        }
        manifest["integrity"] = {
            "canonical_manifest_sha256": _sha256_bytes(_canonical_json(manifest))
        }
        _write_json_private(staging / "manifest.json", manifest, vault=None)
        _write_json_private(staging / "messages.json", messages, vault=None)
        jsonl = "".join(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n" for item in messages)
        _private_text(staging / "messages.jsonl", jsonl)
        _private_text(staging / "chat.md", _render_markdown(messages, assets, clean_title))
        _private_text(staging / "index.html", _render_html(messages, assets, clean_title))
        for path in staging.rglob("*"):
            if path.is_symlink():
                raise VaultError("临时输出中出现符号链接")
            if path.is_file():
                os.chmod(path, 0o600)
            elif path.is_dir():
                os.chmod(path, 0o700)
        verification = _verify_staged_archive(staging, manifest, messages)
        staging.rename(output)
        return {
            "output_dir": str(output),
            "manifest": str(output / "manifest.json"),
            "message_count": len(messages),
            "asset_count": len(assets),
            "issue_count": len(issues),
            "plan_digest": plan["plan_digest"],
            "verification": verification,
        }
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
