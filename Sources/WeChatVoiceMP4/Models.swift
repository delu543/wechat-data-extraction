import CoreGraphics
import Foundation

enum VoiceMP4Error: LocalizedError {
    case invalidArguments(String)
    case safetyViolation(String)
    case unavailable(String)
    case validation(String)

    var errorDescription: String? {
        switch self {
        case .invalidArguments(let message),
             .safetyViolation(let message),
             .unavailable(let message),
             .validation(let message):
            return message
        }
    }
}

struct NormalizedRect: Codable, Equatable, Sendable {
    var x: Double
    var y: Double
    var width: Double
    var height: Double

    static let zero = NormalizedRect(x: 0, y: 0, width: 0, height: 0)

    var isInsideUnitSquare: Bool {
        x >= 0 && y >= 0 && width > 0 && height > 0
            && x + width <= 1 && y + height <= 1
    }
}

enum VoiceTargetStatus: String, Codable, Sendable {
    case planned
    case located
    case cacheCaptured
    case audioCaptured
    case validated
    case failed
}

struct VoiceTarget: Codable, Equatable, Identifiable, Sendable {
    var id: String
    var sequence: Int
    var viewportIndex: Int
    var detectionConfidence: Double
    var senderLabel: String?
    var observedTimestampLabel: String?
    var messageTime: Date?
    var expectedDurationMilliseconds: Int
    var bubbleRect: NormalizedRect?
    var contextFingerprint: String?
    var axRolePath: [String]
    var axSemanticHints: [String]
    var axSemanticSignature: String?
    var axSemanticDigest: String?
    var axOccurrenceIdentifier: String?
    var axVoiceSemanticConfirmed: Bool
    var status: VoiceTargetStatus

    init(
        id: String = UUID().uuidString,
        sequence: Int,
        viewportIndex: Int = 0,
        detectionConfidence: Double = 1,
        senderLabel: String? = nil,
        observedTimestampLabel: String? = nil,
        messageTime: Date? = nil,
        expectedDurationMilliseconds: Int,
        bubbleRect: NormalizedRect? = nil,
        contextFingerprint: String? = nil,
        axRolePath: [String] = [],
        axSemanticHints: [String] = [],
        axSemanticSignature: String? = nil,
        axSemanticDigest: String? = nil,
        axOccurrenceIdentifier: String? = nil,
        axVoiceSemanticConfirmed: Bool = false,
        status: VoiceTargetStatus = .planned
    ) {
        self.id = id
        self.sequence = sequence
        self.viewportIndex = viewportIndex
        self.detectionConfidence = detectionConfidence
        self.senderLabel = senderLabel
        self.observedTimestampLabel = observedTimestampLabel
        self.messageTime = messageTime
        self.expectedDurationMilliseconds = expectedDurationMilliseconds
        self.bubbleRect = bubbleRect
        self.contextFingerprint = contextFingerprint
        self.axRolePath = axRolePath
        self.axSemanticHints = axSemanticHints
        self.axSemanticSignature = axSemanticSignature
        self.axSemanticDigest = axSemanticDigest
        self.axOccurrenceIdentifier = axOccurrenceIdentifier
        self.axVoiceSemanticConfirmed = axVoiceSemanticConfirmed
        self.status = status
    }
}

struct WindowFrame: Codable, Equatable, Sendable {
    var x: Double
    var y: Double
    var width: Double
    var height: Double

    init(x: Double, y: Double, width: Double, height: Double) {
        self.x = x
        self.y = y
        self.width = width
        self.height = height
    }

    init(_ rect: CGRect) {
        x = rect.origin.x
        y = rect.origin.y
        width = rect.width
        height = rect.height
    }

    var cgRect: CGRect { CGRect(x: x, y: y, width: width, height: height) }
}

struct BoundWindowIdentity: Codable, Equatable, Sendable {
    var bundleIdentifier: String
    var processIdentifier: Int32
    var windowID: UInt32
    var frame: WindowFrame
    var pointPixelScale: Double

    init(
        bundleIdentifier: String,
        processIdentifier: Int32,
        windowID: UInt32,
        frame: WindowFrame,
        pointPixelScale: Double
    ) {
        self.bundleIdentifier = bundleIdentifier
        self.processIdentifier = processIdentifier
        self.windowID = windowID
        self.frame = frame
        self.pointPixelScale = pointPixelScale
    }

    init(snapshot: WindowSnapshot) {
        bundleIdentifier = snapshot.bundleIdentifier
        processIdentifier = snapshot.processIdentifier
        windowID = snapshot.windowID
        frame = WindowFrame(snapshot.frame)
        pointPixelScale = snapshot.pointPixelScale
    }

    func matches(_ snapshot: WindowSnapshot, tolerance: Double = 0.75) -> Bool {
        bundleIdentifier == snapshot.bundleIdentifier
            && processIdentifier == snapshot.processIdentifier
            && windowID == snapshot.windowID
            && abs(frame.x - snapshot.frame.origin.x) <= tolerance
            && abs(frame.y - snapshot.frame.origin.y) <= tolerance
            && abs(frame.width - snapshot.frame.width) <= tolerance
            && abs(frame.height - snapshot.frame.height) <= tolerance
            && abs(pointPixelScale - snapshot.pointPixelScale) <= 0.01
    }
}

struct CaptureApproval: Codable, Equatable, Sendable {
    var chatTitle: String
    var approvedCandidateCount: Int
    var allCandidatesConfirmedAsVoice: Bool
    var approvedAt: Date
    var frozenPlanDigest: String
}

/// Only immutable, user-approved fields belong in the frozen digest. Runtime
/// progress such as `VoiceTarget.status` is intentionally excluded.
struct FrozenVoiceTarget: Codable, Equatable, Sendable {
    var id: String
    var sequence: Int
    var viewportIndex: Int
    var detectionConfidence: Double
    var senderLabel: String?
    var observedTimestampLabel: String?
    var messageTime: Date?
    var expectedDurationMilliseconds: Int
    var bubbleRect: NormalizedRect?
    var contextFingerprint: String?
    var axRolePath: [String]
    var axSemanticHints: [String]
    var axSemanticSignature: String?
    var axSemanticDigest: String?
    var axOccurrenceIdentifier: String?
    var axVoiceSemanticConfirmed: Bool

    init(_ target: VoiceTarget) {
        id = target.id
        sequence = target.sequence
        viewportIndex = target.viewportIndex
        detectionConfidence = target.detectionConfidence
        senderLabel = target.senderLabel
        observedTimestampLabel = target.observedTimestampLabel
        messageTime = target.messageTime
        expectedDurationMilliseconds = target.expectedDurationMilliseconds
        bubbleRect = target.bubbleRect
        contextFingerprint = target.contextFingerprint
        axRolePath = target.axRolePath
        axSemanticHints = target.axSemanticHints
        axSemanticSignature = target.axSemanticSignature
        axSemanticDigest = target.axSemanticDigest
        axOccurrenceIdentifier = target.axOccurrenceIdentifier
        axVoiceSemanticConfirmed = target.axVoiceSemanticConfirmed
    }
}

struct ViewportCandidateAnchor: Codable, Equatable, Sendable {
    var durationMilliseconds: Int
    var rect: NormalizedRect
    var fingerprint: String
    var axSemanticDigest: String? = nil
    var axOccurrenceIdentifier: String? = nil
}

struct ViewportPlan: Codable, Equatable, Sendable {
    var viewportIndex: Int
    var overlapWithPrevious: Int
    var candidates: [ViewportCandidateAnchor]
}

struct DiagnosticScreenshotRecord: Codable, Equatable, Sendable {
    var viewportIndex: Int
    var relativePath: String
    var sha256: String
}

struct FrozenCapturePlan: Codable, Equatable, Sendable {
    var schemaVersion: Int
    var taskID: String
    var chatTitle: String
    var startTime: Date
    var endTime: Date
    var expectedCount: Int
    var strictMode: Bool
    var messageRegion: NormalizedRect
    var boundWindow: BoundWindowIdentity
    var scannerVersion: String
    var targets: [FrozenVoiceTarget]
    var viewportPlans: [ViewportPlan]
    var diagnosticScreenshots: [DiagnosticScreenshotRecord]
    var firstVisualAnchor: String
    var lastVisualAnchor: String
}

struct CaptureTask: Codable, Equatable, Identifiable, Sendable {
    static let schemaVersion = 6

    var schemaVersion: Int
    var id: String
    var chatTitle: String
    var startTime: Date
    var endTime: Date
    var expectedCount: Int?
    var strictMode: Bool
    var messageRegion: NormalizedRect?
    var boundWindow: BoundWindowIdentity?
    var scannerVersion: String?
    var createdAt: Date
    var approval: CaptureApproval?
    var targets: [VoiceTarget]
    var viewportPlans: [ViewportPlan]
    var diagnosticScreenshots: [DiagnosticScreenshotRecord]
    var outputDirectory: String

    init(
        id: String = UUID().uuidString,
        chatTitle: String,
        startTime: Date,
        endTime: Date,
        expectedCount: Int?,
        strictMode: Bool = true,
        outputDirectory: String
    ) {
        self.schemaVersion = Self.schemaVersion
        self.id = id
        self.chatTitle = chatTitle
        self.startTime = startTime
        self.endTime = endTime
        self.expectedCount = expectedCount
        self.strictMode = strictMode
        self.messageRegion = nil
        self.boundWindow = nil
        self.scannerVersion = nil
        self.createdAt = Date()
        self.approval = nil
        self.targets = []
        self.viewportPlans = []
        self.diagnosticScreenshots = []
        self.outputDirectory = outputDirectory
    }

    func frozenPlan() throws -> FrozenCapturePlan {
        // Reject malformed task JSON before using values in dropFirst/ranges.
        guard schemaVersion == Self.schemaVersion,
              strictMode,
              expectedCount != nil,
              messageRegion != nil,
              boundWindow != nil,
              scannerVersion != nil,
              !targets.isEmpty,
              !viewportPlans.isEmpty,
              viewportPlans.first?.overlapWithPrevious == 0,
              viewportPlans.allSatisfy({ !$0.candidates.isEmpty }),
              viewportPlans.dropFirst().allSatisfy({ plan in
                  plan.overlapWithPrevious > 0
                      && plan.overlapWithPrevious < plan.candidates.count
              }) else {
            throw VoiceMP4Error.validation("任务结构损坏或尚未完成安全干跑")
        }
        let flattenedViewportCandidates: [(Int, ViewportCandidateAnchor)] = viewportPlans.flatMap {
            plan in
            plan.candidates.dropFirst(plan.overlapWithPrevious).map {
                (plan.viewportIndex, $0)
            }
        }
        let targetsMatchViewportPrefix = targets.count <= flattenedViewportCandidates.count
            && zip(targets, flattenedViewportCandidates.prefix(targets.count)).allSatisfy {
                target, entry in
                target.viewportIndex == entry.0
                    && target.expectedDurationMilliseconds == entry.1.durationMilliseconds
                    && target.bubbleRect == entry.1.rect
                    && target.contextFingerprint == entry.1.fingerprint
                    && target.axSemanticDigest == entry.1.axSemanticDigest
                    && target.axOccurrenceIdentifier == entry.1.axOccurrenceIdentifier
            }
        let viewportOverlapsAreUnique = viewportPlans.indices.dropFirst().allSatisfy { index in
            let previous = viewportPlans[index - 1].candidates
            let current = viewportPlans[index].candidates
            let limit = min(previous.count, current.count)
            let matches = (1...limit).filter { length in
                zip(previous.suffix(length), current.prefix(length)).allSatisfy { lhs, rhs in
                    guard let lhsID = lhs.axOccurrenceIdentifier,
                          let rhsID = rhs.axOccurrenceIdentifier,
                          let lhsSemantic = lhs.axSemanticDigest,
                          let rhsSemantic = rhs.axSemanticDigest else { return false }
                    return lhsID == rhsID
                        && lhs.durationMilliseconds == rhs.durationMilliseconds
                        && lhs.fingerprint == rhs.fingerprint
                        && lhsSemantic == rhsSemantic
                }
            }
            return matches == [viewportPlans[index].overlapWithPrevious]
        }
        let multiPageOccurrenceIdentitiesAreValid: Bool
        if viewportPlans.count > 1 {
            let identitiesByPage = viewportPlans.map {
                $0.candidates.compactMap(\.axOccurrenceIdentifier)
            }
            let semanticDigestsByPage = viewportPlans.map {
                $0.candidates.compactMap(\.axSemanticDigest)
            }
            let completeAndUniqueWithinPages = zip(viewportPlans, identitiesByPage)
                .allSatisfy { plan, identities in
                    identities.count == plan.candidates.count
                        && Set(identities).count == identities.count
                }
            let completeSemanticEvidence = zip(viewportPlans, semanticDigestsByPage)
                .allSatisfy { plan, digests in
                    digests.count == plan.candidates.count
                        && digests.allSatisfy { !$0.isEmpty }
                }
            let flattenedNewIdentities = viewportPlans.flatMap { plan in
                plan.candidates.dropFirst(plan.overlapWithPrevious)
                    .compactMap(\.axOccurrenceIdentifier)
            }
            let expectedFlattenedCount = viewportPlans.reduce(0) { partial, plan in
                partial + plan.candidates.count - plan.overlapWithPrevious
            }
            multiPageOccurrenceIdentitiesAreValid = completeAndUniqueWithinPages
                && completeSemanticEvidence
                && flattenedNewIdentities.count == expectedFlattenedCount
                && Set(flattenedNewIdentities).count == flattenedNewIdentities.count
        } else {
            multiPageOccurrenceIdentitiesAreValid = true
        }
        guard schemaVersion == Self.schemaVersion,
              strictMode,
              let expectedCount,
              expectedCount > 0,
              expectedCount == targets.count,
              let messageRegion,
              let boundWindow,
              let scannerVersion,
              !targets.isEmpty,
              !viewportPlans.isEmpty,
              viewportPlans.map(\.viewportIndex) == Array(0..<viewportPlans.count),
              viewportPlans.first?.overlapWithPrevious == 0,
              viewportPlans.dropFirst().allSatisfy({ plan in
                plan.overlapWithPrevious > 0
                    && plan.overlapWithPrevious < plan.candidates.count
              }),
              viewportPlans.allSatisfy({ plan in
                !plan.candidates.isEmpty
                    && plan.candidates.allSatisfy({ anchor in
                        (1_000...60_000).contains(anchor.durationMilliseconds)
                            && !anchor.fingerprint.isEmpty
                            && MessageRegionPolicy.contains(messageRegion, anchor.rect)
                            && MessageRegionPolicy.containsHardBounds(anchor.rect)
                    })
              }),
              Set(diagnosticScreenshots.map(\.viewportIndex))
                == Set(viewportPlans.map(\.viewportIndex)),
              diagnosticScreenshots.count == viewportPlans.count,
              Set(diagnosticScreenshots.map(\.relativePath)).count
                == diagnosticScreenshots.count,
              diagnosticScreenshots.allSatisfy({
                !$0.relativePath.isEmpty && !$0.sha256.isEmpty
              }),
              targetsMatchViewportPrefix,
              viewportOverlapsAreUnique,
              multiPageOccurrenceIdentitiesAreValid,
              Set(targets.map(\.id)).count == targets.count,
              targets.map(\.sequence) == Array(1...targets.count),
              zip(targets, targets.dropFirst()).allSatisfy({ pair in
                pair.0.viewportIndex <= pair.1.viewportIndex
              }),
              targets.allSatisfy({ target in
                guard viewportPlans.indices.contains(target.viewportIndex),
                      target.detectionConfidence >= CandidateIdentityPolicy.minimumConfidence,
                      (1_000...60_000).contains(target.expectedDurationMilliseconds),
                      let rect = target.bubbleRect,
                      let fingerprint = target.contextFingerprint,
                      !fingerprint.isEmpty,
                      let axSignature = target.axSemanticSignature,
                      !axSignature.isEmpty,
                      let axSemanticDigest = target.axSemanticDigest,
                      !axSemanticDigest.isEmpty else { return false }
                return MessageRegionPolicy.contains(messageRegion, rect)
                    && MessageRegionPolicy.containsHardBounds(rect)
              }),
              targets.allSatisfy({
                $0.axVoiceSemanticConfirmed && $0.axSemanticSignature != nil
              }),
              let firstVisualAnchor = targets.first?.contextFingerprint,
              let lastVisualAnchor = targets.last?.contextFingerprint else {
            throw VoiceMP4Error.validation(
                "任务还不能冻结：需要完整候选锚点，且每条都必须通过 AX 语音语义与播放动作验证"
            )
        }
        return FrozenCapturePlan(
            schemaVersion: schemaVersion,
            taskID: id,
            chatTitle: chatTitle,
            startTime: startTime,
            endTime: endTime,
            expectedCount: expectedCount,
            strictMode: strictMode,
            messageRegion: messageRegion,
            boundWindow: boundWindow,
            scannerVersion: scannerVersion,
            targets: targets.map(FrozenVoiceTarget.init),
            viewportPlans: viewportPlans,
            diagnosticScreenshots: diagnosticScreenshots,
            firstVisualAnchor: firstVisualAnchor,
            lastVisualAnchor: lastVisualAnchor
        )
    }
}

enum SegmentSource: String, Codable, Sendable {
    case cache
    case applicationAudio
    case synthetic
}

struct SegmentRecord: Codable, Equatable, Identifiable, Sendable {
    var id: String
    var targetID: String
    var sequence: Int
    var source: SegmentSource
    var relativePath: String
    var expectedDurationMilliseconds: Int
    var actualDurationMilliseconds: Int?
    var sha256: String?
    var validated: Bool
    var failureReason: String?
}

struct RuntimeState: Codable, Equatable, Sendable {
    var taskID: String
    var approvedPlanDigest: String?
    var startedAt: Date?
    var updatedAt: Date
    var completedTargetIDs: [String]
    var failedTargetIDs: [String]
    var segments: [SegmentRecord]
    var inFlight: InFlightRecord?
    var finalMP4RelativePath: String?

    static func empty(taskID: String) -> RuntimeState {
        RuntimeState(
            taskID: taskID,
            approvedPlanDigest: nil,
            startedAt: nil,
            updatedAt: Date(),
            completedTargetIDs: [],
            failedTargetIDs: [],
            segments: [],
            inFlight: nil,
            finalMP4RelativePath: nil
        )
    }
}

enum InFlightStage: String, Codable, Sendable {
    case intentPersisted
    case clicked
    case capturing
    case uncertain
}

struct InFlightRecord: Codable, Equatable, Sendable {
    var targetID: String
    var sequence: Int
    var stage: InFlightStage
    var initiatedAt: Date
}

struct AuditEvent: Codable, Sendable {
    var timestamp: Date
    var taskID: String
    var targetID: String?
    var kind: String
    var message: String
    var metadata: [String: String]
}
