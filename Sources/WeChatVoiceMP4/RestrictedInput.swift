import ApplicationServices
import CoreGraphics
import Foundation

struct MacRestrictedInputDriver: RestrictedInputDriving, Sendable {
    func clickVoiceBubble(
        in snapshot: WindowSnapshot,
        candidate: ScannedVoiceCandidate,
        target: VoiceTarget,
        messageRegion: NormalizedRect,
        expectedChatTitle: String,
        binding: BoundWindowIdentity
    ) async throws {
        let rect = candidate.rect
        guard AXIsProcessTrusted(), CGPreflightPostEventAccess() else {
            throw VoiceMP4Error.unavailable("辅助功能或输入监控权限未就绪")
        }
        guard MessageRegionPolicy.containsHardBounds(rect) else {
            throw VoiceMP4Error.safetyViolation("拒绝点击消息区硬边界以外的坐标")
        }
        guard Date().timeIntervalSince(snapshot.capturedAt) <= 2.5 else {
            throw VoiceMP4Error.safetyViolation("点击授权截图已过期")
        }
        guard binding.matches(snapshot) else {
            throw VoiceMP4Error.safetyViolation("点击授权截图不属于已批准的微信窗口")
        }
        guard ChatTitleMatcher.matches(observed: snapshot.title, expected: expectedChatTitle) else {
            throw VoiceMP4Error.safetyViolation("点击前聊天标题复核失败")
        }
        try MacRuntimeSafetyGuard.validate(binding: binding)
        try verifyNoRecentUserInput()
        let point = screenPoint(snapshot: snapshot, rect: rect)
        guard let approvedAXSignature = target.axSemanticSignature else {
            throw VoiceMP4Error.safetyViolation("冻结目标缺少严格 AX 语音语义签名")
        }
        let initialEvidence = try MacAXHitInspector.inspect(
            point: point,
            processIdentifier: snapshot.processIdentifier,
            windowID: snapshot.windowID
        )
        guard initialEvidence.isStrictVoiceTarget,
              initialEvidence.signature == approvedAXSignature,
              target.axOccurrenceIdentifier == nil
                || initialEvidence.occurrenceIdentifier == target.axOccurrenceIdentifier else {
            throw VoiceMP4Error.safetyViolation("点击候选的 AX 语音语义或播放动作已变化")
        }
        guard candidate.durationMilliseconds == target.expectedDurationMilliseconds,
              candidate.fingerprint == target.contextFingerprint else {
            throw VoiceMP4Error.safetyViolation("点击候选不再属于冻结目标")
        }
        let freshImage = try await MacBoundWindowPixelCapture.capture(binding: binding)
        let freshFingerprint = CandidateVisualFingerprint.make(
            image: freshImage,
            candidateRect: rect,
            region: messageRegion,
            durationMilliseconds: target.expectedDurationMilliseconds
        )
        guard freshFingerprint == target.contextFingerprint else {
            throw VoiceMP4Error.safetyViolation("点击前最后一帧与批准的语音行不一致")
        }
        let finalEvidence = try MacAXHitInspector.inspect(
            point: point,
            processIdentifier: snapshot.processIdentifier,
            windowID: snapshot.windowID
        )
        guard finalEvidence.isStrictVoiceTarget,
              finalEvidence.signature == approvedAXSignature,
              target.axOccurrenceIdentifier == nil
                || finalEvidence.occurrenceIdentifier == target.axOccurrenceIdentifier else {
            throw VoiceMP4Error.safetyViolation("最后点击门禁无法证明目标是原语音播放控件")
        }
        try MacRuntimeSafetyGuard.validate(binding: binding)
        try verifyNoRecentUserInput()

        guard let source = CGEventSource(stateID: .privateState) else {
            throw VoiceMP4Error.unavailable("无法创建私有鼠标事件源")
        }
        guard let down = CGEvent(
            mouseEventSource: source,
            mouseType: .leftMouseDown,
            mouseCursorPosition: point,
            mouseButton: .left
        ), let up = CGEvent(
            mouseEventSource: source,
            mouseType: .leftMouseUp,
            mouseCursorPosition: point,
            mouseButton: .left
        ) else {
            throw VoiceMP4Error.unavailable("无法创建受限鼠标事件")
        }
        down.flags = []
        up.flags = []
        var postedUp = false
        down.postToPid(snapshot.processIdentifier)
        defer {
            if !postedUp { up.postToPid(snapshot.processIdentifier) }
        }
        try? await Task.sleep(for: .milliseconds(75))
        up.postToPid(snapshot.processIdentifier)
        postedUp = true
    }

    func scrollMessageList(
        in snapshot: WindowSnapshot,
        deltaLines: Int32
    ) async throws {
        guard (-8...8).contains(deltaLines), deltaLines != 0 else {
            throw VoiceMP4Error.safetyViolation("单次滚动必须介于 -8...8 行且不能为 0")
        }
        guard AXIsProcessTrusted(), CGPreflightPostEventAccess() else {
            throw VoiceMP4Error.unavailable("辅助功能或输入监控权限未就绪")
        }
        guard Date().timeIntervalSince(snapshot.capturedAt) <= 2.5 else {
            throw VoiceMP4Error.safetyViolation("滚动授权截图已过期")
        }
        try MacRuntimeSafetyGuard.validate(binding: BoundWindowIdentity(snapshot: snapshot))
        try verifyNoRecentUserInput()
        let location = CGPoint(
            x: snapshot.frame.minX + MessageRegionPolicy.hardBounds.x * snapshot.frame.width
                + MessageRegionPolicy.hardBounds.width * snapshot.frame.width / 2,
            y: snapshot.frame.minY + MessageRegionPolicy.hardBounds.y * snapshot.frame.height
                + MessageRegionPolicy.hardBounds.height * snapshot.frame.height / 2
        )
        let evidence = try MacAXHitInspector.inspect(
            point: location,
            processIdentifier: snapshot.processIdentifier,
            windowID: snapshot.windowID
        )
        guard evidence.hasMessageListAncestor, evidence.forbiddenRole == nil else {
            throw VoiceMP4Error.safetyViolation("滚动点不在可证明的消息列表内")
        }
        guard let source = CGEventSource(stateID: .privateState) else {
            throw VoiceMP4Error.unavailable("无法创建私有滚动事件源")
        }
        guard let event = CGEvent(
            scrollWheelEvent2Source: source,
            units: .line,
            wheelCount: 1,
            wheel1: deltaLines,
            wheel2: 0,
            wheel3: 0
        ) else {
            throw VoiceMP4Error.unavailable("无法创建受限滚动事件")
        }
        event.flags = []
        event.location = location
        event.postToPid(snapshot.processIdentifier)
        try? await Task.sleep(for: .milliseconds(450))
    }

    private func screenPoint(snapshot: WindowSnapshot, rect: NormalizedRect) -> CGPoint {
        CGPoint(
            x: snapshot.frame.minX + (rect.x + rect.width / 2) * snapshot.frame.width,
            y: snapshot.frame.minY + (rect.y + rect.height / 2) * snapshot.frame.height
        )
    }

    private func verifyNoRecentUserInput() throws {
        let flags = CGEventSource.flagsState(.combinedSessionState)
        let modifiers: CGEventFlags = [.maskShift, .maskControl, .maskAlternate, .maskCommand,
                                       .maskSecondaryFn]
        guard flags.intersection(modifiers).isEmpty else {
            throw VoiceMP4Error.safetyViolation("检测到用户正在按修饰键")
        }
        let keyboardAge = [CGEventType.keyDown, .keyUp].map {
            CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: $0)
        }.min() ?? .infinity
        let mouseAge = CGEventSource.secondsSinceLastEventType(
            .combinedSessionState,
            eventType: .mouseMoved
        )
        let interactionAge = [
            CGEventType.leftMouseDown, .leftMouseUp, .rightMouseDown, .rightMouseUp,
            .otherMouseDown, .otherMouseUp, .leftMouseDragged, .rightMouseDragged,
            .otherMouseDragged, .scrollWheel
        ].map {
            CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: $0)
        }.min() ?? .infinity
        guard keyboardAge >= 0.8, mouseAge >= 0.35, interactionAge >= 0.6 else {
            throw VoiceMP4Error.safetyViolation("检测到近期人工键盘、点击、滚轮或鼠标移动")
        }
    }
}
