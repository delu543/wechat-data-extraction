import ApplicationServices
import AppKit
import CoreGraphics
import Foundation
import ScreenCaptureKit

final class MacWeChatWindowProvider: WindowSnapshotProviding, @unchecked Sendable {
    func currentWeChatWindow() async throws -> WindowSnapshot {
        guard CGPreflightScreenCaptureAccess() else {
            throw VoiceMP4Error.unavailable(
                "缺少屏幕与系统音频录制权限；请先运行 doctor 并在系统设置中授权"
            )
        }

        let content = try await SCShareableContent.excludingDesktopWindows(
            true,
            onScreenWindowsOnly: true
        )
        let application = try selectWeChatApplication(from: content)

        let windows = content.windows.filter {
            $0.owningApplication?.processID == application.processID
                && $0.isOnScreen
                && $0.frame.width >= 480
                && $0.frame.height >= 360
        }
        guard windows.count == 1, let window = windows.first else {
            throw VoiceMP4Error.safetyViolation(
                "必须只保留一个可见微信主窗口；当前检测到 \(windows.count) 个"
            )
        }

        let filter = SCContentFilter(desktopIndependentWindow: window)
        let configuration = SCStreamConfiguration()
        let scale = max(Double(filter.pointPixelScale), 1)
        configuration.width = max(Int(window.frame.width * scale), 2)
        configuration.height = max(Int(window.frame.height * scale), 2)
        configuration.showsCursor = false
        configuration.ignoreShadowsSingleWindow = true

        let image = try await SCScreenshotManager.captureImage(
            contentFilter: filter,
            configuration: configuration
        )
        // This timestamp represents the pixels, not the later OCR completion.
        let capturedAt = Date()
        let axContext = AXWindowContext(processIdentifier: application.processID)
        let detectedTitle = try? ChatHeaderRecognizer.detect(in: image)
        let windowTitle = normalizedUsefulTitle(window.title)
        let title = detectedTitle ?? windowTitle ?? axContext.focusedWindowTitle
        let frontmostBundle = NSWorkspace.shared.frontmostApplication?.bundleIdentifier
        let modalState = axContext.modalState

        return WindowSnapshot(
            bundleIdentifier: application.bundleIdentifier,
            foregroundBundleIdentifier: frontmostBundle,
            processIdentifier: application.processID,
            windowID: window.windowID,
            title: title,
            frame: window.frame,
            image: image,
            pointPixelScale: scale,
            focusedRole: axContext.focusedRole,
            modalStateKnown: modalState.known,
            hasModalWindow: modalState.hasModal,
            capturedAt: capturedAt
        )
    }

    private func area(_ rect: CGRect) -> CGFloat {
        rect.width * rect.height
    }

    private func normalizedUsefulTitle(_ title: String?) -> String? {
        guard let title = title?.trimmingCharacters(in: .whitespacesAndNewlines),
              !title.isEmpty,
              title != "微信",
              title.caseInsensitiveCompare("WeChat") != .orderedSame else { return nil }
        return title
    }

    private func selectWeChatApplication(
        from content: SCShareableContent
    ) throws -> SCRunningApplication {
        var matches: [SCRunningApplication] = []
        for application in content.applications {
            let identifier = application.bundleIdentifier
            if identifier == "com.tencent.xinWeChat" || identifier == "com.tencent.WeChat" {
                matches.append(application)
            }
        }
        guard matches.count == 1, let application = matches.first else {
            throw VoiceMP4Error.safetyViolation(
                "必须只运行一个微信实例；当前检测到 \(matches.count) 个"
            )
        }
        return application
    }
}

enum MacBoundWindowPixelCapture {
    static func capture(binding: BoundWindowIdentity) async throws -> CGImage {
        guard CGPreflightScreenCaptureAccess() else {
            throw VoiceMP4Error.unavailable("缺少屏幕与系统音频录制权限")
        }
        try MacRuntimeSafetyGuard.validate(binding: binding)
        let content = try await SCShareableContent.excludingDesktopWindows(
            true,
            onScreenWindowsOnly: true
        )
        let applications = content.applications.filter {
            $0.bundleIdentifier == binding.bundleIdentifier
                && $0.processID == binding.processIdentifier
        }
        guard applications.count == 1 else {
            throw VoiceMP4Error.safetyViolation("点击前无法唯一确认绑定的微信进程")
        }
        let windows = content.windows.filter {
            $0.windowID == binding.windowID
                && $0.owningApplication?.processID == binding.processIdentifier
                && $0.isOnScreen
        }
        guard windows.count == 1, let window = windows.first,
              framesMatch(window.frame, binding.frame.cgRect) else {
            throw VoiceMP4Error.safetyViolation("点击前无法唯一确认绑定的微信窗口")
        }
        let filter = SCContentFilter(desktopIndependentWindow: window)
        let scale = max(Double(filter.pointPixelScale), 1)
        guard abs(scale - binding.pointPixelScale) <= 0.01 else {
            throw VoiceMP4Error.safetyViolation("点击前窗口像素缩放发生变化")
        }
        let configuration = SCStreamConfiguration()
        configuration.width = max(Int(window.frame.width * scale), 2)
        configuration.height = max(Int(window.frame.height * scale), 2)
        configuration.showsCursor = false
        configuration.ignoreShadowsSingleWindow = true
        return try await SCScreenshotManager.captureImage(
            contentFilter: filter,
            configuration: configuration
        )
    }

    private static func framesMatch(_ lhs: CGRect, _ rhs: CGRect) -> Bool {
        abs(lhs.origin.x - rhs.origin.x) <= 0.75
            && abs(lhs.origin.y - rhs.origin.y) <= 0.75
            && abs(lhs.width - rhs.width) <= 0.75
            && abs(lhs.height - rhs.height) <= 0.75
    }
}

struct AXWindowContext {
    let processIdentifier: pid_t

    private var application: AXUIElement {
        AXUIElementCreateApplication(processIdentifier)
    }

    var focusedWindowTitle: String? {
        guard let window: AXUIElement = value(application, kAXFocusedWindowAttribute) else {
            return nil
        }
        return value(window, kAXTitleAttribute)
    }

    var focusedRole: String? {
        guard let element: AXUIElement = value(application, kAXFocusedUIElementAttribute) else {
            return nil
        }
        return value(element, kAXRoleAttribute)
    }

    var modalState: (known: Bool, hasModal: Bool) {
        guard let windows: [AXUIElement] = value(application, kAXWindowsAttribute) else {
            return (false, true)
        }
        guard windows.count == 1, let window = windows.first,
              let modal: Bool = value(window, kAXModalAttribute) else {
            return (windows.count > 1, true)
        }
        return (true, modal)
    }

    private func value<T>(_ element: AXUIElement, _ attribute: String) -> T? {
        var raw: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, attribute as CFString, &raw) == .success else {
            return nil
        }
        return raw as? T
    }
}

enum MacRuntimeSafetyGuard {
    static func validate(binding: BoundWindowIdentity) throws {
        guard let frontmost = NSWorkspace.shared.frontmostApplication,
              frontmost.bundleIdentifier == binding.bundleIdentifier,
              frontmost.processIdentifier == binding.processIdentifier else {
            throw VoiceMP4Error.safetyViolation("微信实例不再是前台应用")
        }
        guard let info = currentWindowInfo(windowID: binding.windowID),
              let owner = info[kCGWindowOwnerPID as String] as? NSNumber,
              owner.int32Value == binding.processIdentifier,
              let layer = info[kCGWindowLayer as String] as? NSNumber,
              layer.intValue == 0,
              let onScreen = info[kCGWindowIsOnscreen as String] as? NSNumber,
              onScreen.boolValue,
              let rawBounds = info[kCGWindowBounds as String] as? [String: Any],
              let currentFrame = CGRect(
                dictionaryRepresentation: rawBounds as CFDictionary
              ) else {
            throw VoiceMP4Error.safetyViolation("绑定的微信窗口已消失或被替换")
        }
        guard framesMatch(binding.frame.cgRect, currentFrame) else {
            throw VoiceMP4Error.safetyViolation("微信窗口在采集期间移动或缩放")
        }
        let context = AXWindowContext(processIdentifier: binding.processIdentifier)
        let modal = context.modalState
        guard modal.known, !modal.hasModal else {
            throw VoiceMP4Error.safetyViolation("无法排除微信弹窗、附加窗口或模态状态")
        }
        guard let role = context.focusedRole else {
            throw VoiceMP4Error.safetyViolation("无法确认微信当前焦点控件")
        }
        if role.localizedCaseInsensitiveContains("text")
            || role == "AXMenu"
            || role == "AXMenuItem" {
            throw VoiceMP4Error.safetyViolation("焦点进入了输入或菜单控件")
        }
    }

    private static func currentWindowInfo(windowID: CGWindowID) -> [String: Any]? {
        guard let raw = CGWindowListCopyWindowInfo(.optionIncludingWindow, windowID) as? [[String: Any]] else {
            return nil
        }
        return raw.first
    }

    private static func framesMatch(_ lhs: CGRect, _ rhs: CGRect) -> Bool {
        abs(lhs.origin.x - rhs.origin.x) <= 0.75
            && abs(lhs.origin.y - rhs.origin.y) <= 0.75
            && abs(lhs.width - rhs.width) <= 0.75
            && abs(lhs.height - rhs.height) <= 0.75
    }
}

enum ChatTitleMatcher {
    static func matches(observed: String?, expected: String) -> Bool {
        guard let observed else { return false }
        return normalize(observed) == normalize(expected)
    }

    static func normalize(_ value: String) -> String {
        value
            .replacingOccurrences(of: "（", with: "(")
            .replacingOccurrences(of: "）", with: ")")
            .split(whereSeparator: \Character.isWhitespace)
            .joined()
    }
}
