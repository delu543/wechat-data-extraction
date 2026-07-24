# Direct Voice Vault

这是首选的本地只读路径：从一份**已经解密且同一时点一致的 Mac 微信 4.x vault
快照**中提取语音，不按语音总时长逐条播放。它不负责获取密钥或解密数据库，不 Hook、
注入、重签或修改微信，不控制界面，也不会写入源数据库。

vault 至少应包含联系人、`message/message_*.db` 和 `message/media_*.db`。请把明文
快照与输出放在不受云同步的私有目录，目录权限建议为 `0700`；不要放进项目、Git 仓库
或共享目录，也不要直接对仍在变化的微信数据目录运行。

消息按精确聊天名/ID（私聊或群聊）与时间筛选，语音类型为 `local_type & 0xffffffff == 34`。提取时只接受：

```text
message/message_*.db / Msg_<md5(chat_id)>.server_id
    == message/media_*.db / VoiceInfo.svr_id
```

必须全局唯一命中一行 `VoiceInfo.voice_data`。计划内重复的非零 `server_id`、缺失、多行、
`server_id=0`、SILK 魔数或帧时长不符都会停止，不按修改时间、目录顺序或相近时长猜文件。
若同一个媒体库同时具备 `VoiceInfo.chat_name_id` 与 `Name2Id.user_name`，还会要求该语音
明确属于目标聊天，并把验证状态写进清单。

## 使用流程

先构建 Swift 工具并安装独立的本地解码依赖：

```bash
./scripts/build.sh
./scripts/setup_direct_tools.sh
```

然后依次执行 `doctor → plan → extract → decode → assemble`。每一步都应先核对输出的
聊天名/ID、时间、条数、顺序和失败项，再进入下一步。

```bash
./scripts/direct.sh doctor \
  --vault-dir "/path/to/decrypted/current"

./scripts/direct.sh plan \
  --vault-dir "/path/to/decrypted/current" \
  --chat "群名" \
  --start "2026-07-21 09:00" \
  --end "2026-07-21 10:00" \
  --expected 36 \
  --output "/private/path/voice-plan.json"

./scripts/direct.sh extract \
  --vault-dir "/path/to/decrypted/current" \
  --plan "/private/path/voice-plan.json" \
  --output-dir "/private/path/extracted-silk"

./scripts/direct.sh decode \
  --extract-dir "/private/path/extracted-silk" \
  --output-dir "/private/path/decoded-m4a" \
  --swift-bin "$PWD/.build/release/wechat-voice-mp4"

.build/release/wechat-voice-mp4 assemble-direct \
  --manifest "/private/path/decoded-m4a/direct-manifest.json" \
  --output "/private/path/微信群语音.mp4"
```

`extract` 输出按消息顺序编号的腾讯 SILK_V3 文件和带 SHA-256 的 `manifest.json`。
`VoiceInfo.voice_data` 会逐字节原样保存，包括微信可选的首字节 `0x02`；清单中的 `sha256`
就是输出文件的哈希。`decode` 只把通过清单与哈希复核的 SILK 解码为临时 PCM，再调用
Swift 工具输出 M4A 和 `direct-manifest.json`；临时 PCM 不应保留。最后由
`assemble-direct` 重新校验来源并生成 H.264 + AAC MP4。

## 缺失与安全边界

- `server_id=0`、计划中重复 ID、无匹配、多行匹配、空 BLOB、SILK 标识或时长异常均会停止，不会跳过或猜测。
- 若只有个别 `VoiceInfo.voice_data` 缺失，应只在微信里定点打开/播放对应消息以促使下载，再制作新快照并重跑；当前工具不会自动点击或下载。
- 本模块本身不包含密钥发现、Frida、注入、重签、数据库写入、微信输入或消息发送能力；一次性初始化位于独立的 `live_tools` 安全边界。
- 明文数据库、SILK、PCM、M4A、MP4 和清单都可能包含私人内容；请自行控制保存位置和删除周期。

## 当前验证状态

`doctor/plan/extract/decode/assemble` 已通过合成 fixture 与媒体自检，也已在一份真实的
冻结微信 vault 上严格验证：计划中的 33 条语音全部通过唯一 `server_id == svr_id`
关联、SILK 解码、逐条 M4A 和最终 MP4 合并，缺失与歧义为 0。这个证据证明当前机器和
该微信 4.x schema 可用，不等于所有微信版本或其他电脑已经兼容。

测试：

```bash
/usr/bin/python3 -m unittest -v direct_vault.tests.test_direct_voice_vault
./scripts/direct_self_test.sh
```
