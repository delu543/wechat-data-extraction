# WeChat Local Export：安装、升级与卸载

## 当前交付状态

这是一个 **Plugin-ready 的源码开发包**，不是已经签名、公证的消费级 Mac 产品。

当前交付有两个 ZIP：

- `wechat-local-export-source-kit-0.2.0-dev.7.zip`：当前可运行的完整源码套件，包含
  Plugin、统一导出后端、初始化/快照工具、Swift 工程、测试和文档；源码开发用户应选它。
- `wechat-local-export-plugin-0.2.0-dev.7.zip`：只含对话层和薄客户端，供未来已安装签名
  Companion 的电脑使用；它本身不能解密或导出聊天，也不会偷偷内置密钥工具。

因此，在签名 Companion 发布前，不要让普通用户只安装 Plugin ZIP 后误以为已经具备完整
导出能力。当前最简单的可用路径是解压 source kit，运行一次显式 setup，然后只通过对话
使用 Skill。

公开 GitHub 仓库的推荐入口是在完整源码根目录运行：

```bash
./scripts/codex_bootstrap.sh doctor
./scripts/codex_bootstrap.sh install
```

或者在 Codex 打开仓库后说“帮我安装并检查微信数据提取项目”。根目录 `AGENTS.md` 会指导
Codex 先做只读检查，再运行同一个幂等安装器。仅打开仓库不会静默执行代码；普通 bootstrap
也不会安装初始化依赖、捕获密钥或创建明文快照。

- 已包含两个 Codex Skill、Plugin manifest、受限薄客户端、源码开发后端和静态校验。
- 源码开发后端复用本项目的统一只读内容 vault，可导出文字、结构化消息、图片、语音、普通文件和可验证的本地表情；视频仅保留元数据。
- 尚未随包交付 Developer ID 签名、公证、通用架构的 `WeChat Local Export.app`。
- 当前开发初始化仍会把验证后的数据库密钥保存为本机私有 `0600` 文件；产品发行版必须迁移到 macOS Keychain。
- 本包没有远程 MCP、遥测、上传或后台网络服务。

不要把“Plugin 已安装”误认为“签名 Companion 已安装”，也不要把源码测试结果描述成跨电脑产品验证。

## 支持边界

- macOS + Mac 微信 4.x。
- 当前源码工具的 Swift 构建目标与依赖以项目根目录的 `Package.swift` 和脚本为准。
- 必须只处理当前用户有权访问的本机微信数据。
- 微信本机没有保存的附件不能凭消息索引恢复。
- 数据库 schema、微信版本或 WAL 状态不受支持时必须安全停止。

## 方式一：本地 Skill 开发安装

Codex 当前的用户级 Skill 目录是 `$HOME/.agents/skills`。在完整项目根目录执行：

```bash
mkdir -p "$HOME/.agents/skills"
ln -s "$(pwd)/portable_skill/skills/wechat-local-export" \
  "$HOME/.agents/skills/wechat-local-export"
ln -s "$(pwd)/portable_skill/skills/wechat-local-export-setup" \
  "$HOME/.agents/skills/wechat-local-export-setup"
```

这两个 Skill 会引用完整项目中的源码开发后端，因此不要只复制单个 Skill 目录。Codex 通常会自动发现新 Skill；若没有出现，请重启 Codex。

使用方式：

```text
把“示例讨论群”周一上午的文字、图片、语音、文件和表情归档，先扫描数量，不要直接导出。
```

也可以只说“导出示例讨论群昨天 20:00 到 21:00 的语音”。系统只把明确选择的类型写入
冻结计划；只有用户说“全部”时才归档区间内所有可解析消息。macOS 语音输入可直接把这句
话转成文字，Skill 本身不申请麦克风权限。

如果用户在同一个请求里明确说“直接导出成 MP4”，Skill 会调用单个
`direct-voice-mp4` 高层命令完成 doctor、在线扫描和严格 MP4-only 导出；普通用户不再
需要在命令之间传递 plan、digest 或条数。名称不精确、同名、零条或能力检查失败仍会停止。

需要初始化时必须显式调用：

```text
$wechat-local-export-setup
```

`wechat-local-export-setup` 已关闭隐式触发。普通导出 Skill 不得替用户自动进入初始化。

## 方式二：本地 Plugin 开发安装

本目录自带本地 marketplace。使用绝对路径添加：

```bash
codex plugin marketplace add "$(pwd)/portable_skill"
codex plugin add wechat-local-export@wechat-local-export-local
```

也可以在 ChatGPT/Codex 桌面应用的 Plugins 页面从该本地 marketplace 安装。安装或更新后若未生效，请重启桌面应用。

## 方式三：以后通过 Git marketplace 分发

发行仓库需要把本 Plugin 放在稳定目录，并提供 `.agents/plugins/marketplace.json`。用户侧流程应固定到版本标签，而不是浮动分支：

```bash
codex plugin marketplace add owner/repository --ref v1.0.0
codex plugin add wechat-local-export@marketplace-name
```

公开发行前还必须完成：

1. Developer ID 签名与 Apple notarization。
2. arm64/x86_64 支持矩阵和干净 Mac 验证。
3. Keychain 密钥存储与迁移。
4. 隐私政策、服务条款、支持渠道与第三方依赖许可证审查。
5. 不同 macOS、微信版本、账号数量、当前会话切换和数据库 schema 的兼容测试。

## 源码开发后端准备

在完整项目根目录运行现有测试和构建脚本：

```bash
./scripts/test.sh
./scripts/build.sh
./scripts/setup_content_tools.sh
```

只有显式进入 `$wechat-local-export-setup` 且只读诊断确认缺少初始化依赖时，才在用户同意
下载 pinned 依赖后运行：

```bash
./scripts/setup_key_init_tools.sh
```

它把 Frida、PyCryptodome 与 Python 3.9 兼容层装在独立私有环境中，不进入普通导出环境，
也不等于用户已经同意抓取密钥。

薄客户端按以下顺序查找后端：

1. 仅在 `WECHAT_LOCAL_EXPORT_ALLOW_UNVERIFIED_HELPER=1` 时采用开发者显式设置的
   `WECHAT_LOCAL_EXPORT_HELPER`；
2. 稳定安装位置中的未来 Companion helper；
3. 完整项目中的 `portable_skill/scripts/dev_backend.py`。

第 1 项只能用于源码开发。正式发行客户端必须固定 Companion 路径并校验 Developer ID、
Team ID、designated requirement 和协议版本，不能信任 `PATH` 中的同名程序或 helper
自报的 `signed_companion`。

源码开发后端的普通当前账号路径会在精确定位聊天后在线协调并刷新最小数据库集合；
官方微信可以保持打开。显式传入 `vault_dir` 的开发/恢复路径仍只接受已经解密、冻结且
不含 WAL/SHM 的 vault，并需要与该快照对应的微信账号媒体根目录。两种路径都不会读取
或打印数据库密钥，也不会自动执行一次性密钥初始化。

setup 完成后会在当前用户私有的 WeChat Local Export 支持目录中写入账号级 profile
registry。每个条目只保存该账号已验证的 vault、账号媒体目录和可选媒体 helper 路径，
文件权限为 `0600`，不含数据库密钥、聊天内容或导出授权。`doctor`、`scan`、`export`
和受限的 `direct-voice-mp4` 每次先只读唯一绑定当前官方微信会话，再自动使用匹配条目；
普通用户不需要提供数据库路径，也不会因为切换账号而沿用上一个账号的 profile。

### 多账号日常使用

1. 在官方微信登录这次要导出的账号，并打开任意聊天。
2. 该账号第一次使用时，显式调用 `$wechat-local-export-setup`。
3. 以后保持官方微信打开即可；正常对话扫描/导出前，Skill 会重新核对当前会话和账号级
   profile，在旧快照中精确定位聊天后在线刷新所需的最小数据库集合。
4. 换到另一个账号后，如果它尚未 setup，普通导出只会提示显式进入 setup，不会自动
   抓取密钥。

日常群聊筛选、定时摘要和普通导出不要求退出微信。只有在线协调安全失败且重试仍不能
完成时，退出微信才作为一次恢复步骤。

电脑里曾经登录过的账号目录不会作为选项展示。当前会话绑定不能依赖数据库更新时间、
大小、目录顺序或“最近使用”猜测。若只读检查得到零个、多个或不稳定的绑定，用户应
登录目标账号、打开任意聊天并把官方微信窗口置前后重试；仍无法唯一绑定时必须停止。
窗口置前只是重试动作，不是账号证据，也不是密钥捕获授权。

## 权限

macOS Full Disk Access 与 Codex 自身的沙箱权限是两层不同的权限。

### 当前源码开发模式

当前代码由 Terminal、Codex 或其子进程运行。若系统拒绝读取微信容器，需要用户亲自在：

```text
系统设置 → 隐私与安全性 → 完全磁盘访问权限
```

为实际运行源码的宿主应用授权，然后完全退出并重新打开该宿主。脚本只能检测权限或打开设置页面，不能替用户打开授权开关。

### 未来产品模式

应只给签名的 `WeChat Local Export.app` 授予 Full Disk Access，让 Codex 保持工作区级权限。Companion 内部仍必须把可读源路径限制在微信容器，不能因为获得系统权限就暴露任意文件读取能力。

数据库直取不需要屏幕录制、辅助功能或麦克风权限。本 Plugin 不应请求这些权限。

## 安全使用流程

1. `doctor` 只读检查环境、后端、vault 和受支持能力。
2. 如果需要初始化，普通导出 Skill 只提示用户显式进入 setup Skill。
3. setup 先运行只读 `setup-doctor`，只接受当前官方微信进程能够唯一证明的账号，不显示
   历史账号目录，也不要求用户寻找微信数据库路径；再用内部保留的脱敏 `account-ref`
   做 `dry-scan`，显示数据库类别和依赖状态，并保留绑定本次范围的 digest。
4. 当前账号第一次明确同意后，才可正常退出官方微信并进行该账号的一次性密钥初始化；
   捕获会再次校验 Mac 微信 4.x、固定腾讯签名、数据库持有状态及 dry-scan digest。自动
   账号绑定、依赖安装或另一个账号的授权都不能代替这次同意。
5. 临时副本正常退出并完成有界 cleanup 后，setup 必须第二次征得用户同意，才可创建并
   保留私有明文快照。密钥捕获同意不能代替快照保留同意。
6. setup 保存该账号不含密钥的本机 profile；以后用户只需登录相应账号并说聊天、时间和
   类型。换号后只允许使用与当前会话匹配的 profile。
7. `scan` 将自然语言解析后的聊天、绝对时间和明确选择的类型写入私有 JSON 请求；用户
   没说明内容类型时先用日常语言追问，绝不默认 `all`。
8. 名称不是唯一精确匹配时，Skill 只展示有界候选并等待选择，不自动选群，也不启动
   在线刷新。
9. 唯一精确聊天确定后，普通当前账号路径在线刷新所需数据库、验证新 vault，再生成
   计划；公开状态只显示 `snapshot_mode: online`，不显示路径、密钥或数据库细节。
10. Skill 显示精确聊天、绝对时间、类型数量和首末时间。
11. 默认由用户确认数量后，Skill 在内部用 plan digest 执行 `export`，不要求用户查看或
    复制摘要。同一请求明确要求直接导出纯语音 MP4 时，非空、无歧义扫描可直接进入严格
    MP4-only 导出；Skill 使用 `direct-voice-mp4` 在一个高层调用中完成 doctor、在线
    scan 和同一计划 export。这不授权部分导出或改变账号、群和时间。内部临时 plan 在
    成功、零条、歧义或失败时均做精确清理，请求文件留给 Skill 做最终有界清理。
12. 严格导出在发布前验证媒体；失败时不留半成品，按消息序号报告原因。只有用户另行
    接受后才可重跑部分归档。成功后检查 manifest、条数、哈希和失败项。

不要把密钥、Keychain 内容、原始 PBKDF 行、登录凭据或聊天正文放进命令行、环境变量、日志或对话消息。

## 升级

### 本地 Skill 符号链接

更新完整项目后，符号链接会自动指向新文件。先运行：

```bash
python3 portable_skill/scripts/validate_package.py
python3 -m unittest discover -s portable_skill/tests -v
```

然后重启 Codex。不要在一次导出任务中途升级。

### Plugin marketplace

先刷新 marketplace：

```bash
codex plugin marketplace upgrade marketplace-name
codex plugin add wechat-local-export@marketplace-name
```

如果当前 Codex 版本要求先移除旧缓存，再由用户明确执行 remove/add。升级不得自动删除任务数据或密钥。`doctor` 必须在新版本第一次导出前重新运行。

## 卸载

移除 Plugin：

```bash
codex plugin remove wechat-local-export@marketplace-name
```

本地 Skill 安装只应删除这两个明确的符号链接，不要递归删除 `$HOME/.agents/skills`。

Plugin 卸载与私人数据清理必须分开：

- 移除 Skill/Plugin 不自动删除 Companion。
- 移除 Companion 不自动删除导出文件。
- 删除任务快照、中间明文和数据库密钥必须分别确认。
- 产品发行版应通过 Companion UI 提供“任务数据”“Keychain 密钥”“完整卸载”三个独立操作。

当前源码开发密钥和运行目录只可使用项目现有的、带所有权校验的 cleanup 流程。不要手工对宽泛目录运行递归删除。

## 静态校验

```bash
python3 portable_skill/scripts/validate_package.py
python3 -m unittest discover -s portable_skill/tests -v
```

校验覆盖：

- setup Skill 必须禁止隐式调用；
- 普通 export Skill 必须允许自然语言触发；
- Plugin manifest 和 marketplace 路径有效；
- 薄客户端只接受 `doctor`、`scan`、`export`、`direct-voice-mp4` 四个高层命令；
- 薄客户端不接受密钥、口令或 token 参数；
- 包内没有具体用户名路径、私钥块或 shell 注入入口。
