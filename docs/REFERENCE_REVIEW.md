# 对 yichen-wechat-local-vault 的复核结论

复核对象：<https://github.com/mcncarl/yichen-skills/tree/main/yichen-wechat-local-vault>

## 可以复用的思路

- 从 Mac 微信 4.x 的 `contact.db` 与 `message_*.db` 解析精确聊天 ID、消息表、时间和消息类型。
- 使用 `local_type & 0xffffffff == 34` 识别语音消息。
- 将数据库解密结果放进独立的本机私有 vault，再以只读方式查询。

## 不能直接复用的结论

- 该仓库的语音分支只读取 `voicelength` 并输出时长占位，没有导出真实音频字节。
- 它没有查询 `VoiceInfo.voice_data`，`--media` 也不处理语音消息。
- 原解密脚本不合并 WAL/SHM，也不验证页 HMAC；不能把“脚本运行成功”当成最新消息零遗漏证明。
- 原密钥流程会复制并临时重签微信，再用 Frida 捕获 PBKDF2 材料。它是一次侵入性初始化，不应在没有用户单独确认时自动运行。
- 当前机器安装路径是 `/Applications/微信.app`，而参考脚本写死 `/Applications/WeChat.app`，不能原样执行。

## 本项目补上的语音链路

公开实现给出了 Mac 微信 4.x 的精确关联：

```text
message/message_*.db / Msg_<md5(chat_id)>.server_id
  == message/media_*.db / VoiceInfo.svr_id
  -> VoiceInfo.voice_data
```

本项目因此枚举所有 `message/media_*.db`，要求每条 `server_id` 全局唯一命中一行，必要时再用
`VoiceInfo.chat_name_id -> Name2Id.user_name` 复核聊天归属。原始 BLOB 按字节保存，验证腾讯
SILK 标识、帧数、数据库时长和 SHA-256，随后用 `pilk` 解码到临时 PCM，再由 Swift/
AVFoundation 编码 AAC 并合成 H.264 + AAC MP4。

相关独立实现：

- 精确消息 ID 到 `VoiceInfo` 映射：<https://github.com/tzwkb/wechat-decrypt/blob/82909766d310a2e03ffaceab208dcce62c094db1/scripts/common/transcribe_db.py>
- SILK BLOB 解码：<https://github.com/tzwkb/wechat-decrypt/blob/82909766d310a2e03ffaceab208dcce62c094db1/scripts/common/voice_decode.py>
- 独立的 `VoiceInfo` 查询：<https://github.com/hkhere/WeChatMsg/blob/9457ecdad74826ebede9a040b1d86d986c968f1e/wxManager/db_v4/media.py>
- `pilk`：<https://github.com/foyoux/pilk>

## 收藏夹方案

收藏可以帮助定位和整理消息，但参考仓库只把收藏/语音变成索引或文本占位，并没有证明收藏后
能得到可直接合并的标准音频文件。因此收藏不作为主链路；数据库中的 `VoiceInfo.voice_data`
才是当前有源码交叉证据的直接音频来源。

## 当前边界

代码和合成夹具已验证；当前机器也已完成一次性密钥初始化、冻结快照和真实语音端到端
导出：33 条语音全部唯一关联、解码并合并为 MP4，统一归档计划共 34 条消息且严格导出
无缺失。这个证据只证明当前机器及该微信 4.x schema，不等于跨电脑或未来微信版本兼容。
若某条 `voice_data` 本机确实不存在，只报告该条并由用户决定是否定点触发下载，不把整批
自动退回实时录制。
