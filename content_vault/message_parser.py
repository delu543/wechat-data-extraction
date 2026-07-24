"""Bounded, loss-aware parsing of already-decoded WeChat message content.

This module deliberately has no database, filesystem, network, key, or media
side effects.  Every input message produces exactly one JSON-safe dictionary.
Unsupported or malformed content is represented as a redacted raw fallback
instead of being discarded.
"""

from __future__ import annotations

from hashlib import sha256
from html import unescape
import re
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlsplit, urlunsplit
from xml.etree import ElementTree as ET


SCHEMA_VERSION = 1
MAX_XML_BYTES = 512 * 1024
MAX_XML_ELEMENTS = 2_048
MAX_XML_DEPTH = 48
MAX_XML_ATTRIBUTES = 64
MAX_RAW_PREVIEW_CHARS = 8_192
MAX_FIELD_CHARS = 16_384
MAX_FORWARDED_ITEMS = 512
_XML_FEED_CHARS = 8_192

_MD5_RE = re.compile(r"[0-9a-fA-F]{32}\Z")
_STRICT_SENDER_RE = re.compile(r"(?:wxid|gh)_[A-Za-z0-9_-]{3,128}\Z")
_LEGACY_SENDER_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{2,127}\Z")
_SENSITIVE_FIELD_NAMES = (
    "aeskey",
    "aes_key",
    "authkey",
    "auth_key",
    "signature",
    "token",
    "encfilekey",
    "filekey",
    "cdnkey",
    "cdnthumbaeskey",
    "cdnthumbkey",
    "cdnattachaeskey",
    "cdnvideoaeskey",
    "cdnmidimgaeskey",
    "cdnmidimgkey",
)
_SENSITIVE_FIELD_PATTERN = "|".join(
    re.escape(item) for item in _SENSITIVE_FIELD_NAMES
)
_SENSITIVE_QUOTED_ATTRIBUTE_RE = re.compile(
    rf"(?is)(\b(?:{_SENSITIVE_FIELD_PATTERN})\s*=\s*)([\"'])(.*?)(\2)"
)
_SENSITIVE_UNQUOTED_ATTRIBUTE_RE = re.compile(
    rf"(?is)((?:\s|<)(?:{_SENSITIVE_FIELD_PATTERN})\s*=\s*)(?![\"'])([^\s>]+)"
)
_SENSITIVE_ELEMENT_RE = re.compile(
    rf"(?is)(<\s*({_SENSITIVE_FIELD_PATTERN})\b[^>]*>)(.*?)(</\s*\2\s*>)"
)
_SENSITIVE_UNCLOSED_ELEMENT_RE = re.compile(
    rf"(?is)(<\s*(?:{_SENSITIVE_FIELD_PATTERN})\b[^>]*>)([^<]*)"
)
_SENSITIVE_TEXT_ASSIGNMENT_RE = re.compile(
    rf"(?i)(\b(?:{_SENSITIVE_FIELD_PATTERN})\s*[:=]\s*)([^\s<>&]+)"
)
_URL_RE = re.compile(r"(?i)https?://[^\s<>\"']+")

_KIND_BY_BASE_TYPE = {
    1: "text",
    3: "image",
    34: "voice",
    42: "contact_card",
    43: "video",
    47: "sticker",
    48: "location",
    49: "app_message",
    50: "call",
    10000: "system",
    10002: "system",
}


class XMLBoundaryError(ValueError):
    """Raised when XML violates a deterministic parser safety bound."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _BoundedTreeBuilder:
    def __init__(
        self,
        *,
        max_elements: int,
        max_depth: int,
        max_attributes: int,
    ) -> None:
        self._builder = ET.TreeBuilder()
        self._max_elements = max_elements
        self._max_depth = max_depth
        self._max_attributes = max_attributes
        self._elements = 0
        self._depth = 0

    def start(self, tag: str, attributes: dict[str, str]) -> ET.Element:
        self._elements += 1
        self._depth += 1
        if self._elements > self._max_elements:
            raise XMLBoundaryError("xml_element_limit")
        if self._depth > self._max_depth:
            raise XMLBoundaryError("xml_depth_limit")
        if len(attributes) > self._max_attributes:
            raise XMLBoundaryError("xml_attribute_limit")
        return self._builder.start(tag, attributes)

    def end(self, tag: str) -> ET.Element:
        result = self._builder.end(tag)
        self._depth -= 1
        return result

    def data(self, data: str) -> None:
        self._builder.data(data)

    def comment(self, text: str) -> None:
        # Comments carry no typed message fields and are intentionally omitted.
        return None

    def pi(self, target: str, text: str | None = None) -> None:
        # Processing instructions are not part of the message schema.
        return None

    def doctype(self, name: str, pubid: str | None, system: str | None) -> None:
        raise XMLBoundaryError("unsafe_xml_declaration")

    def close(self) -> ET.Element:
        return self._builder.close()


def parse_xml_bounded(
    text: str,
    *,
    max_bytes: int = MAX_XML_BYTES,
    max_elements: int = MAX_XML_ELEMENTS,
    max_depth: int = MAX_XML_DEPTH,
    max_attributes: int = MAX_XML_ATTRIBUTES,
) -> ET.Element:
    """Parse XML after enforcing byte, entity, node, depth, and attribute bounds."""

    if not isinstance(text, str) or not text.strip():
        raise XMLBoundaryError("empty_xml")
    try:
        byte_count = len(text.encode("utf-8", errors="surrogatepass"))
    except (UnicodeError, ValueError) as error:
        raise XMLBoundaryError("invalid_xml_text") from error
    if byte_count > max_bytes:
        raise XMLBoundaryError("xml_byte_limit")
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, flags=re.IGNORECASE):
        raise XMLBoundaryError("unsafe_xml_declaration")

    target = _BoundedTreeBuilder(
        max_elements=max_elements,
        max_depth=max_depth,
        max_attributes=max_attributes,
    )
    parser = ET.XMLParser(target=target)
    for offset in range(0, len(text), _XML_FEED_CHARS):
        parser.feed(text[offset : offset + _XML_FEED_CHARS])
    root = parser.close()
    if not isinstance(root, ET.Element):
        raise XMLBoundaryError("empty_xml")
    return root


def split_local_type(local_type: int) -> tuple[int, int]:
    """Return ``(low32_base_type, high32_flags)`` for signed or unsigned input."""

    value = int(local_type)
    return value & 0xFFFFFFFF, (value >> 32) & 0xFFFFFFFF


def classify_local_type(local_type: int) -> str:
    """Classify a message from only the low 32 bits of ``local_type``."""

    try:
        base_type, _ = split_local_type(local_type)
    except (TypeError, ValueError, OverflowError):
        return "unknown"
    return _KIND_BY_BASE_TYPE.get(base_type, "unknown")


def _safe_sender_candidate(value: str) -> bool:
    return bool(
        value
        and len(value) <= 256
        and "@chatroom" not in value
        and not any(character.isspace() or ord(character) < 32 for character in value)
        and all(character not in value for character in ("<", ">", "/", "\\"))
    )


def split_group_sender_prefix(
    content: str,
    *,
    is_group: bool,
    expected_sender_id: str = "",
) -> tuple[str, str]:
    """Safely consume ``sender_id:\n`` only for a verified group-message prefix.

    Without an expected sender ID, only the strict ``wxid_``/``gh_`` internal
    forms are accepted.  This prevents ordinary user text such as
    ``heading:\nbody`` from being mistaken for sender metadata.
    """

    if not is_group or not isinstance(content, str):
        return "", content
    boundary = content.find(":\n", 0, 259)
    if boundary <= 0:
        return "", content
    candidate = content[:boundary]
    if not _safe_sender_candidate(candidate):
        return "", content

    expected = str(expected_sender_id or "").strip()
    expected_is_named_account = bool(expected and not expected.isdecimal())
    if expected_is_named_account:
        accepted = candidate == expected
    elif expected.isdecimal():
        # WeChat 4.x can expose real_sender_id as a numeric Name2Id row while
        # the content prefix still uses an older ASCII account name.
        accepted = bool(
            _STRICT_SENDER_RE.fullmatch(candidate)
            or _LEGACY_SENDER_RE.fullmatch(candidate)
        )
    else:
        accepted = bool(_STRICT_SENDER_RE.fullmatch(candidate))
    if not accepted:
        return "", content
    return candidate, content[boundary + 2 :]


def _local_name(tag: Any) -> str:
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1].lower()


def _first_element(root: ET.Element, *names: str) -> ET.Element | None:
    wanted = {name.lower() for name in names}
    for element in root.iter():
        if _local_name(element.tag) in wanted:
            return element
    return None


def _element_text(element: ET.Element | None) -> str:
    if element is None:
        return ""
    return "".join(element.itertext()).strip()


def _direct_child_text(element: ET.Element | None, *names: str) -> str:
    if element is None:
        return ""
    wanted = {name.lower() for name in names}
    for child in list(element):
        if _local_name(child.tag) in wanted:
            value = _element_text(child)
            if value:
                return value
    return ""


def _first_text(root: ET.Element, *names: str) -> str:
    return _element_text(_first_element(root, *names))


def _attribute(element: ET.Element | None, *names: str) -> str:
    if element is None:
        return ""
    wanted = {name.lower() for name in names}
    for key, value in element.attrib.items():
        if _local_name(key) in wanted:
            return str(value).strip()
    return ""


def _attribute_or_text(element: ET.Element, *names: str) -> str:
    return _attribute(element, *names) or _first_text(element, *names)


def _nonnegative_int(value: str) -> int | None:
    value = str(value or "").strip()
    if not value or not re.fullmatch(r"\d+", value):
        return None
    result = int(value)
    return result if result >= 0 else None


def _normalized_md5(value: str) -> str | None:
    value = str(value or "").strip()
    return value.lower() if _MD5_RE.fullmatch(value) else None


def _sensitive_query_key(key: str) -> bool:
    normalized = unescape(key).split(";")[-1].strip().lower().replace("_", "-")
    exact = {
        "access-token",
        "aeskey",
        "auth",
        "auth-key",
        "credential",
        "encfilekey",
        "expires",
        "filekey",
        "key",
        "policy",
        "sig",
        "signature",
        "token",
        "wssecret",
        "wstime",
    }
    return (
        normalized in exact
        or normalized.startswith("x-amz-")
        or normalized.startswith("x-oss-")
        or normalized.startswith("q-sign-")
        or normalized.endswith("-signature")
    )


def _sanitize_url(value: str) -> tuple[str, bool]:
    value = str(value or "").strip()
    if not value:
        return "", False
    decoded = unescape(value)
    try:
        parts = urlsplit(decoded)
        query = parse_qsl(parts.query, keep_blank_values=True)
        fragment_query = parse_qsl(parts.fragment, keep_blank_values=True)
        path_parameters = []
        for segment in parts.path.split(";")[1:]:
            if "=" in segment:
                path_parameters.append(tuple(segment.split("=", 1)))
        has_sensitive = any(
            _sensitive_query_key(key)
            for key, _ in (*query, *fragment_query, *path_parameters)
        )
        has_userinfo = parts.username is not None or parts.password is not None
        if has_sensitive or has_userinfo:
            safe_path = parts.path.split(";", 1)[0]
            safe_netloc = parts.hostname or ""
            if parts.port is not None:
                safe_netloc += f":{parts.port}"
            return urlunsplit((parts.scheme, safe_netloc, safe_path, "", "")), True
    except (TypeError, ValueError, UnicodeError):
        if re.search(
            r"(?i)(?:[?&#;])(?:token|signature|sig|auth_?key|aeskey|encfilekey|filekey)=",
            decoded,
        ):
            return "[signed-url-redacted]", True
    return value, False


def _sanitize_raw_text(text: str) -> str:
    def replace_quoted(match: re.Match[str]) -> str:
        return f"{match.group(1)}{match.group(2)}[redacted]{match.group(2)}"

    def replace_element(match: re.Match[str]) -> str:
        return f"{match.group(1)}[redacted]{match.group(4)}"

    redacted = _SENSITIVE_QUOTED_ATTRIBUTE_RE.sub(replace_quoted, text)
    redacted = _SENSITIVE_UNQUOTED_ATTRIBUTE_RE.sub(r"\1[redacted]", redacted)
    redacted = _SENSITIVE_ELEMENT_RE.sub(replace_element, redacted)
    redacted = _SENSITIVE_UNCLOSED_ELEMENT_RE.sub(r"\1[redacted]", redacted)
    redacted = _SENSITIVE_TEXT_ASSIGNMENT_RE.sub(r"\1[redacted]", redacted)

    def replace_url(match: re.Match[str]) -> str:
        url, was_redacted = _sanitize_url(match.group(0))
        return url if was_redacted else match.group(0)

    return _URL_RE.sub(replace_url, redacted)


def _sanitize_field(value: str) -> str:
    """Bound and redact a field that may contain text, a URL, or a page path."""

    text = str(value or "")[:MAX_FIELD_CHARS]
    sanitized = _sanitize_raw_text(text)
    url_value, redacted = _sanitize_url(sanitized)
    return url_value if redacted else sanitized


def _has_sensitive_xml_data(text: str) -> bool:
    if re.search(
        rf"(?i)(?:<\s*(?:{_SENSITIVE_FIELD_PATTERN})\b|\b(?:{_SENSITIVE_FIELD_PATTERN})\s*=)",
        text,
    ):
        return True
    for match in _URL_RE.finditer(text):
        _, was_redacted = _sanitize_url(match.group(0))
        if was_redacted:
            return True
    return False


def _raw_payload(text: str) -> dict[str, Any]:
    # Only the preview is persisted, so sanitize a bounded prefix rather than
    # running several regular-expression passes over an arbitrarily large row.
    preview_source = text[: MAX_RAW_PREVIEW_CHARS * 2]
    safe_text = _sanitize_raw_text(preview_source)
    return {
        "raw": {
            "preview": safe_text[:MAX_RAW_PREVIEW_CHARS],
            "preview_truncated": len(safe_text) > MAX_RAW_PREVIEW_CHARS,
            "char_count": len(text),
            "sha256": sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest(),
        }
    }


def _try_parse_xml(text: str) -> tuple[ET.Element | None, str | None]:
    try:
        return parse_xml_bounded(text), None
    except XMLBoundaryError as error:
        return None, error.code
    except (ET.ParseError, UnicodeError, ValueError):
        return None, "malformed_xml"
    except Exception:
        return None, "xml_parse_error"


def _xml_target_or_issue(
    root: ET.Element, name: str, issues: list[str]
) -> ET.Element | None:
    target = _first_element(root, name)
    if target is None:
        issues.append(f"missing_{name}_element")
    return target


def _parse_image(root: ET.Element, issues: list[str]) -> dict[str, Any]:
    image = _first_element(root, "img")
    if image is None:
        image = root
    md5_text = _attribute_or_text(image, "md5", "filemd5")
    md5 = _normalized_md5(md5_text)
    if md5_text and md5 is None:
        issues.append("invalid_image_md5")
    if not md5:
        issues.append("image_md5_missing")
    return {
        "md5": md5,
        "byte_size": _nonnegative_int(_attribute_or_text(image, "length", "size")),
    }


def _parse_voice(root: ET.Element, issues: list[str]) -> dict[str, Any]:
    voice = _xml_target_or_issue(root, "voicemsg", issues)
    if voice is None:
        return {}
    duration_text = _attribute_or_text(voice, "voicelength")
    duration_ms = _nonnegative_int(duration_text)
    if duration_text and duration_ms is None:
        issues.append("invalid_voice_duration")
    if duration_ms is None:
        issues.append("voice_duration_missing")
    return {
        "duration_ms": duration_ms,
        "byte_size": _nonnegative_int(_attribute_or_text(voice, "length")),
        "format": _attribute_or_text(voice, "voiceformat") or None,
    }


def _parse_contact_card(root: ET.Element, issues: list[str]) -> dict[str, Any]:
    card = _first_element(root, "msg", "contact", "card")
    if card is None:
        issues.append("missing_contact_element")
        return {}
    username = _attribute_or_text(card, "username", "user_name")
    nickname = _attribute_or_text(card, "nickname", "nick_name")
    if not username and not nickname:
        issues.append("contact_identity_missing")
    return {
        "username": _sanitize_field(username) or None,
        "nickname": _sanitize_field(nickname) or None,
        "alias": _sanitize_field(_attribute_or_text(card, "alias")) or None,
        "remark": _sanitize_field(_attribute_or_text(card, "remark", "remarkname")) or None,
        "province": _sanitize_field(_attribute_or_text(card, "province")) or None,
        "city": _sanitize_field(_attribute_or_text(card, "city")) or None,
    }


def _parse_video(root: ET.Element, issues: list[str]) -> dict[str, Any]:
    video = _first_element(root, "videomsg", "video")
    if video is None:
        issues.append("missing_video_element")
        return {"body_exported": False}
    return {
        "body_exported": False,
        "duration_seconds": _nonnegative_int(
            _attribute_or_text(video, "playlength", "duration")
        ),
        "byte_size": _nonnegative_int(_attribute_or_text(video, "length", "size")),
        "width": _nonnegative_int(_attribute_or_text(video, "width")),
        "height": _nonnegative_int(_attribute_or_text(video, "height")),
    }


def _parse_sticker(root: ET.Element, issues: list[str]) -> dict[str, Any]:
    emoji = _xml_target_or_issue(root, "emoji", issues)
    if emoji is None:
        return {}
    md5_text = _attribute_or_text(emoji, "md5")
    md5 = _normalized_md5(md5_text)
    if md5_text and md5 is None:
        issues.append("invalid_sticker_md5")
    if not md5:
        issues.append("sticker_md5_missing")
    return {
        "md5": md5,
        "product_id": _sanitize_field(_attribute_or_text(emoji, "productid", "product_id")) or None,
        "width": _nonnegative_int(_attribute_or_text(emoji, "width")),
        "height": _nonnegative_int(_attribute_or_text(emoji, "height")),
    }


def _parse_location(root: ET.Element, issues: list[str]) -> dict[str, Any]:
    location = _xml_target_or_issue(root, "location", issues)
    if location is None:
        return {}
    latitude = _attribute_or_text(location, "x", "latitude", "lat")
    longitude = _attribute_or_text(location, "y", "longitude", "lng", "lon")
    if not latitude or not longitude:
        issues.append("location_coordinates_missing")
    return {
        "latitude": latitude or None,
        "longitude": longitude or None,
        "scale": _attribute_or_text(location, "scale") or None,
        "label": _sanitize_field(_attribute_or_text(location, "label")) or None,
        "poi_name": _sanitize_field(_attribute_or_text(location, "poiname", "poi_name")) or None,
    }


def _system_text(root: ET.Element) -> str:
    for name in ("replacemsg", "plain", "content", "title"):
        value = _first_text(root, name)
        if value:
            return value
    return " ".join(part.strip() for part in root.itertext() if part.strip()).strip()


def _parse_system(root: ET.Element, issues: list[str]) -> dict[str, Any]:
    text = _system_text(root)
    if not text:
        issues.append("system_text_missing")
    return {
        "text": _sanitize_raw_text(text),
        "system_type": _attribute(root, "type") or _first_text(root, "type") or None,
    }


def _parse_call(root: ET.Element, issues: list[str]) -> dict[str, Any]:
    call = _first_element(root, "voipmsg", "voipinvitemsg", "call")
    if call is None:
        call = root
    return {
        "call_type": _attribute_or_text(call, "type", "room_type") or None,
        "duration_seconds": _nonnegative_int(
            _attribute_or_text(call, "duration", "durationseconds")
        ),
        "text": _sanitize_raw_text(_first_text(call, "content", "msg")) or None,
    }


def _app_title_description(appmsg: ET.Element) -> tuple[str, str]:
    return (
        _sanitize_field(_direct_child_text(appmsg, "title")),
        _sanitize_field(_direct_child_text(appmsg, "des", "description")),
    )


def _parse_forwarded_record(
    appmsg: ET.Element,
    title: str,
    description: str,
    issues: list[str],
) -> tuple[dict[str, Any], str]:
    record_text = _direct_child_text(appmsg, "recorditem", "record_item")
    if not record_text:
        issues.append("forwarded_record_missing")
        return {"title": title or None, "description": description or None, "items": []}, "partial"
    nested, error = _try_parse_xml(unescape(record_text))
    if nested is None:
        issues.append(error or "malformed_forwarded_record")
        payload = {"title": title or None, "description": description or None, "items": []}
        payload.update(_raw_payload(record_text))
        return payload, "raw_fallback"

    items: list[dict[str, Any]] = []
    data_items = [
        element for element in nested.iter() if _local_name(element.tag) == "dataitem"
    ]
    if len(data_items) > MAX_FORWARDED_ITEMS:
        issues.append("forwarded_item_limit")
        data_items = data_items[:MAX_FORWARDED_ITEMS]
    for element in data_items:
        data_type = _nonnegative_int(_attribute(element, "datatype", "data_type"))
        item = {
            "data_type": data_type,
            "data_id": _sanitize_field(_attribute(element, "dataid", "data_id")) or None,
            "source_name": _sanitize_field(_direct_child_text(element, "sourcename")) or None,
            "source_time": _sanitize_field(_direct_child_text(element, "sourcetime")) or None,
            "title": _sanitize_field(_direct_child_text(element, "datatitle", "title")) or None,
            "description": _sanitize_field(_direct_child_text(element, "datadesc", "description")) or None,
        }
        items.append(item)
    if not items:
        issues.append("forwarded_items_missing")
    return {
        "title": title or None,
        "description": description or None,
        "item_count": len(items),
        "items": items,
    }, "parsed" if items else "partial"


def _parse_app_message(
    root: ET.Element,
    raw_text: str,
    issues: list[str],
) -> tuple[str, dict[str, Any], str, int | None]:
    appmsg = _first_element(root, "appmsg")
    if appmsg is None:
        issues.append("missing_appmsg_element")
        return "app_message", _raw_payload(raw_text), "raw_fallback", None

    app_type_text = _direct_child_text(appmsg, "type")
    app_type = _nonnegative_int(app_type_text)
    if app_type_text and app_type is None:
        issues.append("invalid_app_type")
    title, description = _app_title_description(appmsg)

    if app_type == 5:
        url, redacted = _sanitize_url(_direct_child_text(appmsg, "url"))
        if redacted:
            issues.append("signed_url_query_removed")
        return (
            "link",
            {"title": title or None, "description": description or None, "url": url or None},
            "parsed",
            app_type,
        )

    if app_type in {33, 36, 44}:
        info = _first_element(appmsg, "weappinfo", "weapp_info")
        app_id = _attribute(appmsg, "appid")
        if info is not None:
            app_id = _direct_child_text(info, "appid", "app_id") or app_id
        return (
            "mini_program",
            {
                "title": title or None,
                "description": description or None,
                "app_id": _sanitize_field(app_id) or None,
                "username": _sanitize_field(_direct_child_text(info, "username")) or None,
                "page_path": _sanitize_field(_direct_child_text(info, "pagepath", "page_path")) or None,
                "app_name": _sanitize_field(_direct_child_text(info, "appservicetype", "appname")) or None,
            },
            "parsed",
            app_type,
        )

    if app_type == 19:
        forwarded, status = _parse_forwarded_record(
            appmsg, title, description, issues
        )
        return "forwarded_record", forwarded, status, app_type

    if app_type == 6:
        attach = _first_element(appmsg, "appattach", "attachment")
        source = attach if attach is not None else appmsg
        file_title = title or _sanitize_field(
            _direct_child_text(source, "filename", "file_name")
        )
        size_text = _direct_child_text(source, "totallen", "size", "file_size")
        md5_text = _direct_child_text(source, "filemd5", "md5")
        size = _nonnegative_int(size_text)
        md5 = _normalized_md5(md5_text)
        if not file_title:
            issues.append("file_title_missing")
        if size_text and size is None:
            issues.append("invalid_file_size")
        if md5_text and md5 is None:
            issues.append("invalid_file_md5")
        return (
            "file",
            {
                "title": file_title or None,
                "description": description or None,
                "byte_size": size,
                "md5": md5,
            },
            "parsed",
            app_type,
        )

    if app_type == 57:
        refer = _first_element(appmsg, "refermsg", "refer_msg")
        if refer is None:
            issues.append("quote_reference_missing")
        return (
            "quote",
            {
                "text": title or description or None,
                "reference": {
                    "message_type": _nonnegative_int(_direct_child_text(refer, "type")),
                    "server_id": _direct_child_text(refer, "svrid", "server_id") or None,
                    "sender_id": _sanitize_field(_direct_child_text(refer, "fromusr", "sender_id")) or None,
                    "chat_id": _sanitize_field(_direct_child_text(refer, "chatusr", "chat_id")) or None,
                    "display_name": _sanitize_field(_direct_child_text(refer, "displayname")) or None,
                    "content": _sanitize_raw_text(_direct_child_text(refer, "content")) or None,
                },
            },
            "parsed",
            app_type,
        )

    issues.append("unsupported_app_type")
    payload = {
        "app_type": app_type,
        "title": title or None,
        "description": description or None,
    }
    payload.update(_raw_payload(raw_text))
    return "app_message", payload, "raw_fallback", app_type


def _xml_message_result(
    base_type: int,
    kind: str,
    content: str,
    issues: list[str],
) -> tuple[str, dict[str, Any], str, int | None]:
    root, xml_error = _try_parse_xml(content)
    if root is None:
        issues.append(xml_error or "malformed_xml")
        status = "excluded_by_policy" if base_type == 43 else "raw_fallback"
        if base_type == 43:
            issues.append("video_body_excluded")
        return kind, _raw_payload(content), status, None

    if _has_sensitive_xml_data(content):
        issues.append("sensitive_xml_fields_omitted")

    if base_type == 3:
        return kind, _parse_image(root, issues), "parsed", None
    if base_type == 34:
        return kind, _parse_voice(root, issues), "parsed", None
    if base_type == 42:
        return kind, _parse_contact_card(root, issues), "parsed", None
    if base_type == 43:
        issues.append("video_body_excluded")
        return kind, _parse_video(root, issues), "excluded_by_policy", None
    if base_type == 47:
        return kind, _parse_sticker(root, issues), "parsed", None
    if base_type == 48:
        return kind, _parse_location(root, issues), "parsed", None
    if base_type == 49:
        return _parse_app_message(root, content, issues)
    if base_type in {10000, 10002}:
        return kind, _parse_system(root, issues), "parsed", None
    if base_type == 50:
        return kind, _parse_call(root, issues), "parsed", None
    issues.append("unsupported_xml_message_type")
    return kind, _raw_payload(content), "raw_fallback", None


def _coerce_content(content: str, issues: list[str]) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, (bytes, bytearray, memoryview)):
        issues.append("content_decoded_from_bytes")
        return bytes(content).decode("utf-8", errors="replace")
    if content is None:
        issues.append("content_was_none")
        return ""
    try:
        issues.append("content_coerced_to_text")
        return str(content)
    except Exception:
        issues.append("content_unrepresentable")
        return "[unrepresentable content]"


def parse_message(
    local_type: int,
    content: str,
    *,
    is_group: bool,
    real_sender_id: str = "",
) -> dict[str, Any]:
    """Parse one message into a stable, JSON-safe, loss-aware dictionary.

    The signature is intentionally row-agnostic so database readers can keep
    their own immutable ordering and identity fields.  This function never
    deduplicates and never returns ``None``.
    """

    issues: list[str] = []
    content_text = _coerce_content(content, issues)
    try:
        raw_type = int(local_type)
        base_type, flags_hi32 = split_local_type(raw_type)
    except (TypeError, ValueError, OverflowError):
        raw_type = 0
        base_type = 0
        flags_hi32 = 0
        issues.append("invalid_local_type")

    try:
        sender_from_row = str(real_sender_id or "").strip()
    except Exception:
        sender_from_row = ""
        issues.append("invalid_real_sender_id")
    prefix_sender, body = split_group_sender_prefix(
        content_text,
        is_group=bool(is_group),
        expected_sender_id=sender_from_row,
    )
    sender_id = prefix_sender or sender_from_row
    kind = _KIND_BY_BASE_TYPE.get(base_type, "unknown")
    status = "parsed"
    app_type: int | None = None

    try:
        if base_type == 1:
            payload: dict[str, Any] = {"text": body}
        elif base_type in {10000, 10002} and not body.lstrip().startswith("<"):
            payload = {"text": body, "system_type": "recall" if base_type == 10002 else None}
        elif base_type == 50 and not body.lstrip().startswith("<"):
            payload = {"text": body or None, "call_type": None, "duration_seconds": None}
        elif base_type in _KIND_BY_BASE_TYPE:
            kind, payload, status, app_type = _xml_message_result(
                base_type, kind, body, issues
            )
        else:
            status = "raw_fallback"
            issues.append("unsupported_message_type")
            payload = _raw_payload(body)
        if status == "parsed" and any(
            issue.startswith(("missing_", "invalid_")) for issue in issues
        ):
            status = "partial"
    except Exception:
        # Parsing a damaged individual row must not remove it from the export.
        status = "excluded_by_policy" if base_type == 43 else "raw_fallback"
        if base_type == 43 and "video_body_excluded" not in issues:
            issues.append("video_body_excluded")
        issues.append("parser_internal_error")
        payload = _raw_payload(body)

    return {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "payload": payload,
        "parse": {
            "status": status,
            "issues": list(dict.fromkeys(issues)),
            "content_sha256": sha256(
                content_text.encode("utf-8", errors="surrogatepass")
            ).hexdigest(),
            "sender_prefix_consumed": bool(prefix_sender),
        },
        "sender_id": sender_id,
        "local_type": {
            "raw": raw_type,
            "base": base_type,
            "flags_hi32": flags_hi32,
            "app_type": app_type,
        },
    }


def parse_messages(
    messages: Iterable[tuple[int, str]],
    *,
    is_group: bool,
    real_sender_id: str = "",
) -> list[dict[str, Any]]:
    """Parse every input occurrence in order; identical messages stay distinct."""

    return [
        parse_message(
            local_type,
            content,
            is_group=is_group,
            real_sender_id=real_sender_id,
        )
        for local_type, content in messages
    ]
