import CoreGraphics
import Foundation

struct WindowSnapshot: @unchecked Sendable {
    let bundleIdentifier: String
    let foregroundBundleIdentifier: String?
    let processIdentifier: pid_t
    let windowID: CGWindowID
    let title: String?
    let frame: CGRect
    let image: CGImage
    let pointPixelScale: Double
    let focusedRole: String?
    let modalStateKnown: Bool
    let hasModalWindow: Bool
    let capturedAt: Date
}

struct ScannedVoiceCandidate: Equatable, Sendable {
    let sequenceInViewport: Int
    let durationMilliseconds: Int
    let senderLabel: String?
    let timestampLabel: String?
    let rect: NormalizedRect
    let confidence: Double
    let fingerprint: String
    let axSemanticSignature: String?
    let axSemanticDigest: String?
    let axOccurrenceIdentifier: String?

    init(
        sequenceInViewport: Int,
        durationMilliseconds: Int,
        senderLabel: String?,
        timestampLabel: String?,
        rect: NormalizedRect,
        confidence: Double,
        fingerprint: String,
        axSemanticSignature: String? = nil,
        axSemanticDigest: String? = nil,
        axOccurrenceIdentifier: String? = nil
    ) {
        self.sequenceInViewport = sequenceInViewport
        self.durationMilliseconds = durationMilliseconds
        self.senderLabel = senderLabel
        self.timestampLabel = timestampLabel
        self.rect = rect
        self.confidence = confidence
        self.fingerprint = fingerprint
        self.axSemanticSignature = axSemanticSignature
        self.axSemanticDigest = axSemanticDigest
        self.axOccurrenceIdentifier = axOccurrenceIdentifier
    }
}

protocol WindowSnapshotProviding: Sendable {
    func currentWeChatWindow() async throws -> WindowSnapshot
}

protocol VoiceCandidateScanning: Sendable {
    func scan(_ snapshot: WindowSnapshot, within region: NormalizedRect) async throws
        -> [ScannedVoiceCandidate]
}

protocol RestrictedInputDriving: Sendable {
    func clickVoiceBubble(
        in snapshot: WindowSnapshot,
        candidate: ScannedVoiceCandidate,
        target: VoiceTarget,
        messageRegion: NormalizedRect,
        expectedChatTitle: String,
        binding: BoundWindowIdentity
    ) async throws
    func scrollMessageList(in snapshot: WindowSnapshot, deltaLines: Int32) async throws
}

protocol ApplicationAudioCapturing: Sendable {
    var isReady: Bool { get async }
    var isQuiet: Bool { get async }
    func beginSegment(outputURL: URL) async throws
    func endSegment() async throws -> URL
    func cancelSegment() async
}

protocol MediaAssembling: Sendable {
    func assemble(
        segments: [URL],
        gapMilliseconds: Int,
        title: String,
        outputURL: URL
    ) async throws
}
