import Darwin
import Foundation

@_silgen_name("flock")
private func systemFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

final class TaskExecutionLock: @unchecked Sendable {
    private let stateLock = NSLock()
    private var descriptor: Int32

    convenience init(taskRoot: URL, operation: String) throws {
        try self.init(
            lockURL: taskRoot.appendingPathComponent(".wechat-voice-mp4.lock"),
            conflictMessage: "同一任务已有操作在运行；拒绝并发执行 \(operation)"
        )
    }

    static func acquireWeChatControl(operation: String) throws -> TaskExecutionLock {
        let url = URL(fileURLWithPath: "/tmp", isDirectory: true)
            .appendingPathComponent(
                "wechat-voice-mp4-ui-\(Darwin.getuid()).lock",
                isDirectory: false
            )
        return try TaskExecutionLock(
            lockURL: url,
            conflictMessage: "另一个任务正在控制微信窗口/音频；拒绝并发执行 \(operation)"
        )
    }

    private init(lockURL url: URL, conflictMessage: String) throws {
        let fileDescriptor = url.path.withCString {
            Darwin.open($0, O_CREAT | O_RDWR | O_NOFOLLOW, mode_t(0o600))
        }
        guard fileDescriptor >= 0 else {
            throw VoiceMP4Error.unavailable("无法创建任务锁：\(url.path)")
        }
        guard systemFlock(fileDescriptor, LOCK_EX | LOCK_NB) == 0 else {
            Darwin.close(fileDescriptor)
            throw VoiceMP4Error.safetyViolation(conflictMessage)
        }
        descriptor = fileDescriptor
    }

    func release() {
        stateLock.withLock {
            guard descriptor >= 0 else { return }
            _ = systemFlock(descriptor, LOCK_UN)
            _ = Darwin.close(descriptor)
            descriptor = -1
        }
    }

    deinit { release() }
}
