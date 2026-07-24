import ApplicationServices
import AppKit
import CoreGraphics
import Foundation

struct DoctorCheck: Codable, Sendable {
    let name: String
    let passed: Bool
    let required: Bool
    let detail: String
}

struct DoctorReport: Codable, Sendable {
    let generatedAt: Date
    let checks: [DoctorCheck]

    var readyForDryRun: Bool {
        checks.filter(\.required).allSatisfy(\.passed)
    }
}

enum Doctor {
    static func run() -> DoctorReport {
        let fileManager = FileManager.default
        let home = fileManager.homeDirectoryForCurrentUser
        let dataRoot = home.appendingPathComponent(
            "Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files",
            isDirectory: true
        )

        let applicationCandidates = [
            "/Applications/微信.app",
            "/Applications/WeChat.app",
            "/Applications/Weixin.app"
        ]
        let foundApplication = NSWorkspace.shared.urlForApplication(
            withBundleIdentifier: "com.tencent.xinWeChat"
        )?.path ?? applicationCandidates.first {
            fileManager.fileExists(atPath: $0)
        }

        let checks = [
            DoctorCheck(
                name: "wechat_application",
                passed: foundApplication != nil,
                required: true,
                detail: foundApplication ?? "未在标准位置找到微信应用"
            ),
            DoctorCheck(
                name: "wechat_data_readable",
                passed: fileManager.isReadableFile(atPath: dataRoot.path),
                required: false,
                detail: dataRoot.path
            ),
            DoctorCheck(
                name: "screen_and_system_audio_permission",
                passed: CGPreflightScreenCaptureAccess(),
                required: true,
                detail: "系统设置 > 隐私与安全性 > 屏幕与系统音频录制"
            ),
            DoctorCheck(
                name: "accessibility_permission",
                passed: AXIsProcessTrusted(),
                required: true,
                detail: "系统设置 > 隐私与安全性 > 辅助功能"
            ),
            DoctorCheck(
                name: "post_event_permission",
                passed: CGPreflightPostEventAccess(),
                required: true,
                detail: "受限鼠标点击所需；不会生成键盘事件"
            ),
            DoctorCheck(
                name: "ffmpeg_optional",
                passed: executableExists("ffmpeg"),
                required: false,
                detail: "可选；默认使用 AVFoundation"
            )
        ]

        return DoctorReport(generatedAt: Date(), checks: checks)
    }

    private static func executableExists(_ name: String) -> Bool {
        let paths = ProcessInfo.processInfo.environment["PATH"]?.split(separator: ":") ?? []
        return paths.contains { path in
            FileManager.default.isExecutableFile(
                atPath: URL(fileURLWithPath: String(path)).appendingPathComponent(name).path
            )
        }
    }
}
