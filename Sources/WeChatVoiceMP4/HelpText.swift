enum HelpText {
    static let value = #"""
    wechat-voice-mp4 — 微信语音安全采集与 MP4 合并

    首选数据库直取入口：scripts/direct.sh（doctor → plan → extract → decode），
    本二进制负责 PCM→M4A 与最终 MP4；以下 UI 命令是缺失 BLOB 时的兜底。

    命令：
      doctor
        检查微信、屏幕与系统音频录制、辅助功能权限。

      init-task --chat <群名> --start <时间> --end <时间>
                --expected <准确条数> [--task-dir <目录>]
        创建任务。时间格式：yyyy-MM-dd HH:mm[:ss]；时间边界由用户人工定位。

      dry-run --task <任务目录>
              [--message-region x,y,w,h] [--save-screenshot]
              [--pages <1...30> --allow-scroll]
        默认只扫描当前微信窗口；区域使用 0...1 归一化坐标且必须位于硬安全区。
        多页模式只做有界滚动，不点击、不输入；批准前必须保存每屏截图并核对。
        多页还要求每条语音节点有稳定且唯一的 per-message AXIdentifier；否则失败关闭。
        截图属于本地敏感明文，其 SHA-256 会进入冻结计划。

      approve --task <任务目录> --confirm-chat <群名> --count <条数>
              --confirm-first <首条锚点> --confirm-last <末条锚点>
              --confirm-all-voice
        冻结群名、时间、窗口、区域、完整候选及首尾锚点，仍不会点击。

      capture --task <任务目录> --arm [--max-items <条数>] [--probe-cache]
              [--ack-interrupted <targetID>]
        正式采集。权限须就绪，并已完成 dry-run/approve。
        ack 前必须人工确认中断语音已停止；工具绝不自动重试点击。

      assemble --task <任务目录> [--gap-ms 300] [--output <文件.mp4>]
        只使用已验证片段生成 MP4；gap-ms 范围 0...5000，拒绝覆盖已有文件。

      pcm-to-m4a --input <16-bit-le.pcm> --output <文件.m4a>
                 [--sample-rate 24000] [--expected-ms <数据库时长>]
        把 SILK 解码器产生的单声道 PCM 转成 AAC/M4A，并校验时长。

      assemble-direct --manifest <direct-manifest.json> --output <文件.mp4>
                      [--gap-ms 300]
        合并直读数据库得到的音频。逐条验证 sequence、serverID、SHA-256 和数据库时长。

      self-test --output <文件.mp4>
        不使用微信，生成两段模拟音频并验证完整 MP4 管线。

      verify-core
        不使用微信，运行参数、状态机、缓存、持久化和安全门单元验证。

      inspect-task --task <任务目录>
        查看任务和运行状态。

      cache-roots
        列出只读缓存探针目录。

    安全约束：
      - 工具不包含键盘输入、粘贴或发送消息能力。
      - 正式采集只允许消息区域单次左键和有界滚动。
      - 聊天标题、干跑清单或权限不一致时立即停止。
      - 应用音频覆盖整个微信进程；采集前必须开启勿扰并关闭微信其他声音。
    """#
}
