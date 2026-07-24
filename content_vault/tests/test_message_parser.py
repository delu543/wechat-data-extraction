from __future__ import annotations

import json
import unittest

from content_vault.message_parser import (
    XMLBoundaryError,
    classify_local_type,
    parse_message,
    parse_messages,
    parse_xml_bounded,
    split_group_sender_prefix,
    split_local_type,
)


MD5 = "0123456789abcdef0123456789abcdef"


class MessageParserTests(unittest.TestCase):
    def assert_json_safe(self, value: object) -> str:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)

    def test_group_sender_prefix_is_strict_and_direct_messages_are_untouched(self) -> None:
        sender, body = split_group_sender_prefix(
            "wxid_member_123:\n正文", is_group=True
        )
        self.assertEqual((sender, body), ("wxid_member_123", "正文"))

        self.assertEqual(
            split_group_sender_prefix("标题:\n正文", is_group=True),
            ("", "标题:\n正文"),
        )
        self.assertEqual(
            split_group_sender_prefix("wxid_member_123:\n正文", is_group=False),
            ("", "wxid_member_123:\n正文"),
        )
        self.assertEqual(
            split_group_sender_prefix(
                "custom_user:\n正文",
                is_group=True,
                expected_sender_id="custom_user",
            ),
            ("custom_user", "正文"),
        )
        self.assertEqual(
            split_group_sender_prefix(
                "legacy01:\n正文", is_group=True, expected_sender_id="7"
            ),
            ("legacy01", "正文"),
        )

    def test_high_32_bits_are_flags_and_low_32_bits_control_kind(self) -> None:
        local_type = (0xA5A5 << 32) | 34
        self.assertEqual(split_local_type(local_type), (34, 0xA5A5))
        self.assertEqual(classify_local_type(local_type), "voice")
        result = parse_message(
            local_type,
            '<msg><voicemsg voicelength="52000" length="321"/></msg>',
            is_group=False,
        )
        self.assertEqual(result["kind"], "voice")
        self.assertEqual(result["local_type"]["flags_hi32"], 0xA5A5)
        self.assertEqual(result["payload"]["duration_ms"], 52000)

    def test_text_and_system_messages(self) -> None:
        text = parse_message(
            1,
            "wxid_member_123:\n同一段文字",
            is_group=True,
            real_sender_id="7",
        )
        self.assertEqual(text["sender_id"], "wxid_member_123")
        self.assertEqual(text["payload"], {"text": "同一段文字"})
        self.assertTrue(text["parse"]["sender_prefix_consumed"])

        system = parse_message(10000, "你邀请了成员", is_group=True)
        self.assertEqual(system["kind"], "system")
        self.assertEqual(system["payload"]["text"], "你邀请了成员")

        recall = parse_message(
            10002,
            "<sysmsg type='revokemsg'><revokemsg><replacemsg>撤回了一条消息</replacemsg></revokemsg></sysmsg>",
            is_group=False,
        )
        self.assertEqual(recall["payload"]["text"], "撤回了一条消息")

    def test_contact_and_location(self) -> None:
        card = parse_message(
            42,
            "<msg username='wxid_friend' nickname='朋友' alias='friend-id' province='广东' city='深圳'/>",
            is_group=False,
        )
        self.assertEqual(card["kind"], "contact_card")
        self.assertEqual(card["payload"]["username"], "wxid_friend")
        self.assertEqual(card["payload"]["nickname"], "朋友")

        location = parse_message(
            48,
            "<msg><location x='22.5431' y='114.0579' scale='16' label='深圳' poiname='测试点'/></msg>",
            is_group=False,
        )
        self.assertEqual(location["kind"], "location")
        self.assertEqual(location["payload"]["latitude"], "22.5431")
        self.assertEqual(location["payload"]["longitude"], "114.0579")

    def test_image_metadata_does_not_persist_delivery_secrets(self) -> None:
        image = parse_message(
            3,
            f"<msg><img md5='{MD5}' length='2048' aeskey='image-key' "
            "cdnmidimgurl='https://cdn.test/i?signature=image-sign'/></msg>",
            is_group=False,
        )
        self.assertEqual(image["kind"], "image")
        self.assertEqual(image["payload"]["md5"], MD5)
        self.assertEqual(image["payload"]["byte_size"], 2048)
        serialized = self.assert_json_safe(image)
        self.assertNotIn("image-key", serialized)
        self.assertNotIn("image-sign", serialized)

    def test_link_and_mini_program(self) -> None:
        link = parse_message(
            49,
            "<msg><appmsg><title>链接标题</title><des>摘要</des><type>5</type>"
            "<url>https://example.test/article?id=3&amp;token=do-not-store</url>"
            "</appmsg></msg>",
            is_group=False,
        )
        self.assertEqual(link["kind"], "link")
        self.assertEqual(link["payload"]["url"], "https://example.test/article")
        self.assertIn("signed_url_query_removed", link["parse"]["issues"])
        self.assertNotIn("do-not-store", self.assert_json_safe(link))

        mini = parse_message(
            49,
            "<msg><appmsg appid='outer-app'><title>小程序</title><type>33</type>"
            "<weappinfo><appid>mini-app</appid><username>gh_demo</username>"
            "<pagepath>pages/home?id=1</pagepath></weappinfo></appmsg></msg>",
            is_group=False,
        )
        self.assertEqual(mini["kind"], "mini_program")
        self.assertEqual(mini["payload"]["app_id"], "mini-app")
        self.assertEqual(mini["payload"]["page_path"], "pages/home?id=1")

    def test_sensitive_values_are_redacted_from_all_structured_fields(self) -> None:
        unknown = parse_message(
            49,
            "<msg><appmsg><title>aeskey=title-secret</title><des>"
            "https://example.test/a;token=path-secret#signature=fragment-secret"
            "</des><type>999</type><cdnthumbaeskey>thumb-secret</cdnthumbaeskey>"
            "</appmsg></msg>",
            is_group=False,
        )
        serialized = self.assert_json_safe(unknown)
        for secret in ("title-secret", "path-secret", "fragment-secret", "thumb-secret"):
            self.assertNotIn(secret, serialized)

        mini = parse_message(
            49,
            "<msg><appmsg><title>mini</title><type>33</type><weappinfo>"
            "<pagepath>pages/home;token=page-secret#signature=fragment</pagepath>"
            "</weappinfo></appmsg></msg>",
            is_group=False,
        )
        mini_json = self.assert_json_safe(mini)
        self.assertNotIn("page-secret", mini_json)
        self.assertNotIn("#signature", mini_json)

    def test_forwarded_record_type_19_is_structured_and_bounded(self) -> None:
        nested = (
            "<recordinfo><datalist><dataitem datatype='1' dataid='item-1'>"
            "<sourcename>发送者</sourcename><sourcetime>2026-07-20 10:00</sourcetime>"
            "<datatitle>标题</datatitle><datadesc>正文</datadesc>"
            "</dataitem></datalist></recordinfo>"
        )
        result = parse_message(
            49,
            f"<msg><appmsg><title>合并记录</title><type>19</type>"
            f"<recorditem><![CDATA[{nested}]]></recorditem></appmsg></msg>",
            is_group=False,
        )
        self.assertEqual(result["kind"], "forwarded_record")
        self.assertEqual(result["payload"]["item_count"], 1)
        self.assertEqual(result["payload"]["items"][0]["description"], "正文")
        self.assertEqual(result["parse"]["status"], "parsed")

    def test_type49_file_extracts_only_safe_resolution_metadata(self) -> None:
        result = parse_message(
            49,
            "<msg><appmsg><title>材料.pdf</title><type>6</type><appattach>"
            f"<totallen>4096</totallen><filemd5>{MD5.upper()}</filemd5>"
            "<aeskey>top-secret-aes</aeskey>"
            "<cdnattachurl>https://cdn.example.test/file?signature=secret-signature</cdnattachurl>"
            "</appattach></appmsg></msg>",
            is_group=False,
        )
        self.assertEqual(result["kind"], "file")
        self.assertEqual(result["payload"]["title"], "材料.pdf")
        self.assertEqual(result["payload"]["byte_size"], 4096)
        self.assertEqual(result["payload"]["md5"], MD5)
        serialized = self.assert_json_safe(result)
        self.assertNotIn("top-secret-aes", serialized)
        self.assertNotIn("secret-signature", serialized)
        self.assertIn("sensitive_xml_fields_omitted", result["parse"]["issues"])

    def test_quote_extracts_reference_without_secret_xml_fields(self) -> None:
        quote = parse_message(
            49,
            "<msg><appmsg><title>我的回复</title><type>57</type><refermsg>"
            "<type>1</type><svrid>9988</svrid><fromusr>wxid_original</fromusr>"
            "<displayname>原发送者</displayname><content>被引用的正文</content>"
            "</refermsg></appmsg></msg>",
            is_group=True,
        )
        self.assertEqual(quote["kind"], "quote")
        self.assertEqual(quote["payload"]["text"], "我的回复")
        self.assertEqual(quote["payload"]["reference"]["server_id"], "9988")
        self.assertEqual(quote["payload"]["reference"]["content"], "被引用的正文")

    def test_sticker_md5_voice_metadata_and_video_exclusion(self) -> None:
        sticker = parse_message(
            47,
            "<msg><emoji md5='0123456789ABCDEF0123456789ABCDEF' width='120' height='80' "
            "aeskey='sticker-key' cdnurl='https://cdn.test/e?token=sticker-token'/></msg>",
            is_group=False,
        )
        self.assertEqual(sticker["kind"], "sticker")
        self.assertEqual(sticker["payload"]["md5"], MD5)
        sticker_json = self.assert_json_safe(sticker)
        self.assertNotIn("sticker-key", sticker_json)
        self.assertNotIn("sticker-token", sticker_json)

        video = parse_message(
            43,
            "<msg><videomsg playlength='61' length='9000' width='1080' height='1920' "
            "aeskey='video-key' cdnvideourl='https://cdn.test/v?signature=video-sign'/></msg>",
            is_group=False,
        )
        self.assertEqual(video["kind"], "video")
        self.assertEqual(video["parse"]["status"], "excluded_by_policy")
        self.assertFalse(video["payload"]["body_exported"])
        self.assertEqual(video["payload"]["duration_seconds"], 61)
        video_json = self.assert_json_safe(video)
        self.assertNotIn("video-key", video_json)
        self.assertNotIn("video-sign", video_json)

    def test_unknown_type_is_a_json_safe_raw_fallback(self) -> None:
        result = parse_message(987654, "未知但必须保留", is_group=False)
        self.assertEqual(result["kind"], "unknown")
        self.assertEqual(result["parse"]["status"], "raw_fallback")
        self.assertEqual(result["payload"]["raw"]["preview"], "未知但必须保留")
        self.assert_json_safe(result)

    def test_identical_legitimate_messages_are_not_deduplicated(self) -> None:
        results = parse_messages(
            [(1, "完全相同"), (1, "完全相同")],
            is_group=False,
        )
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0], results[1])

    def test_malformed_xml_falls_back_and_redacts_secrets(self) -> None:
        malformed = (
            "<msg><emoji md5='0123456789abcdef0123456789abcdef' "
            "aeskey='raw-aes-secret' "
            "cdnurl='https://cdn.test/e?token=raw-url-secret'>"
        )
        result = parse_message(47, malformed, is_group=False)
        self.assertEqual(result["kind"], "sticker")
        self.assertEqual(result["parse"]["status"], "raw_fallback")
        self.assertIn("malformed_xml", result["parse"]["issues"])
        serialized = self.assert_json_safe(result)
        self.assertNotIn("raw-aes-secret", serialized)
        self.assertNotIn("raw-url-secret", serialized)
        self.assertEqual(len(result["payload"]["raw"]["sha256"]), 64)

    def test_entity_declarations_and_deep_xml_are_rejected_before_use(self) -> None:
        malicious = (
            "<!DOCTYPE msg [<!ENTITY x 'expanded'>]>"
            f"<msg><emoji md5='{MD5}'>&x;</emoji></msg>"
        )
        result = parse_message(47, malicious, is_group=False)
        self.assertEqual(result["parse"]["status"], "raw_fallback")
        self.assertIn("unsafe_xml_declaration", result["parse"]["issues"])

        deep = "<a>" * 4 + "x" + "</a>" * 4
        with self.assertRaises(XMLBoundaryError) as raised:
            parse_xml_bounded(deep, max_depth=3)
        self.assertEqual(raised.exception.code, "xml_depth_limit")


if __name__ == "__main__":
    unittest.main()
