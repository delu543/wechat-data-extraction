import Foundation

enum CapturePhase: String, Codable, Sendable {
    case preflight
    case bindChat
    case plan
    case seekFirst
    case locateNext
    case armClick
    case clickOnce
    case waitStart
    case capturing
    case waitEnd
    case validateSegment
    case commit
    case advance
    case reconcile
    case finalVerify
    case pausedByInterference
    case finished
}

struct SafetySnapshot: Sendable {
    let foregroundBundleIdentifier: String?
    let observedChatTitle: String?
    let focusedRole: String?
    let targetRect: NormalizedRect?
    let messageRegion: NormalizedRect?
    let modalStateKnown: Bool
    let hasModalWindow: Bool
    let audioCaptureReady: Bool
    let applicationAudioQuiet: Bool
    let playbackActive: Bool
}

struct SafetyDecision: Equatable, Sendable {
    let allowed: Bool
    let reasons: [String]
}

enum SafetyGate {
    static let supportedBundleIdentifiers = Set([
        "com.tencent.xinWeChat",
        "com.tencent.WeChat"
    ])

    static func mayClick(snapshot: SafetySnapshot, expectedChatTitle: String) -> SafetyDecision {
        var reasons: [String] = []

        guard let bundle = snapshot.foregroundBundleIdentifier,
              supportedBundleIdentifiers.contains(bundle) else {
            reasons.append("前台应用不是受支持的微信")
            return SafetyDecision(allowed: false, reasons: reasons)
        }
        if !ChatTitleMatcher.matches(
            observed: snapshot.observedChatTitle,
            expected: expectedChatTitle
        ) {
            reasons.append("聊天标题与任务不一致")
        }
        if !snapshot.modalStateKnown {
            reasons.append("无法确认微信弹窗状态")
        }
        if snapshot.hasModalWindow {
            reasons.append("存在弹窗或模态窗口")
        }
        if snapshot.focusedRole == nil {
            reasons.append("无法确认微信当前焦点控件")
        } else if snapshot.focusedRole?.localizedCaseInsensitiveContains("text") == true {
            reasons.append("焦点位于文本输入控件")
        }
        if snapshot.playbackActive {
            reasons.append("已有语音正在播放")
        }
        if !snapshot.audioCaptureReady {
            reasons.append("应用音频捕获尚未就绪")
        }
        if !snapshot.applicationAudioQuiet {
            reasons.append("微信应用音频不是静默状态")
        }
        guard let target = snapshot.targetRect, target.isInsideUnitSquare,
              let region = snapshot.messageRegion,
              MessageRegionPolicy.validate(region) else {
            reasons.append("目标或消息区域无效")
            return SafetyDecision(allowed: false, reasons: reasons)
        }
        if !contains(region, target) {
            reasons.append("目标不在消息列表安全区域内")
        }
        if !MessageRegionPolicy.containsHardBounds(target) {
            reasons.append("目标越过消息区硬安全边界")
        }

        return SafetyDecision(allowed: reasons.isEmpty, reasons: reasons)
    }

    private static func contains(_ outer: NormalizedRect, _ inner: NormalizedRect) -> Bool {
        inner.x >= outer.x
            && inner.y >= outer.y
            && inner.x + inner.width <= outer.x + outer.width
            && inner.y + inner.height <= outer.y + outer.height
    }
}

struct ClickNonce: Equatable, Sendable {
    let targetID: String
    let issuedAt: Date
    private(set) var consumedAt: Date?

    var isUsable: Bool { consumedAt == nil }

    mutating func consume(now: Date = Date()) throws {
        guard consumedAt == nil else {
            throw VoiceMP4Error.safetyViolation("同一目标的点击许可已使用")
        }
        consumedAt = now
    }
}

struct CaptureStateMachine: Sendable {
    private(set) var phase: CapturePhase = .preflight
    private(set) var currentTargetID: String?
    private(set) var clickNonce: ClickNonce?

    mutating func transition(to next: CapturePhase) throws {
        guard allowedTransitions[phase, default: []].contains(next) else {
            throw VoiceMP4Error.safetyViolation("非法状态迁移：\(phase.rawValue) → \(next.rawValue)")
        }
        phase = next
    }

    mutating func arm(targetID: String) throws {
        guard phase == .armClick else {
            throw VoiceMP4Error.safetyViolation("只有 armClick 阶段可以创建点击许可")
        }
        currentTargetID = targetID
        clickNonce = ClickNonce(targetID: targetID, issuedAt: Date(), consumedAt: nil)
    }

    mutating func consumeClick() throws {
        guard phase == .clickOnce, var nonce = clickNonce else {
            throw VoiceMP4Error.safetyViolation("当前没有可用点击许可")
        }
        try nonce.consume()
        clickNonce = nonce
    }

    mutating func pause() {
        phase = .pausedByInterference
        clickNonce = nil
    }

    private var allowedTransitions: [CapturePhase: Set<CapturePhase>] {
        [
            .preflight: [.bindChat, .pausedByInterference],
            .bindChat: [.plan, .pausedByInterference],
            .plan: [.seekFirst, .pausedByInterference],
            .seekFirst: [.locateNext, .pausedByInterference],
            .locateNext: [.armClick, .reconcile, .pausedByInterference],
            .armClick: [.clickOnce, .pausedByInterference],
            .clickOnce: [.waitStart, .pausedByInterference],
            .waitStart: [.capturing, .locateNext, .pausedByInterference],
            .capturing: [.waitEnd, .pausedByInterference],
            .waitEnd: [.validateSegment, .pausedByInterference],
            .validateSegment: [.commit, .locateNext, .pausedByInterference],
            .commit: [.advance, .pausedByInterference],
            .advance: [.locateNext, .pausedByInterference],
            .reconcile: [.finalVerify, .pausedByInterference],
            .finalVerify: [.finished, .pausedByInterference],
            .pausedByInterference: [.bindChat],
            .finished: []
        ]
    }
}
