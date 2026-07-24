import Foundation

enum MessageRegionPolicy {
    static let hardBounds = NormalizedRect(x: 0.27, y: 0.09, width: 0.71, height: 0.66)

    static func validate(_ region: NormalizedRect) -> Bool {
        region.isInsideUnitSquare
            && region.width >= 0.25
            && region.height >= 0.25
            && contains(hardBounds, region)
    }

    static func containsHardBounds(_ target: NormalizedRect) -> Bool {
        target.isInsideUnitSquare && contains(hardBounds, target)
    }

    static func contains(_ outer: NormalizedRect, _ inner: NormalizedRect) -> Bool {
        inner.x >= outer.x
            && inner.y >= outer.y
            && inner.x + inner.width <= outer.x + outer.width
            && inner.y + inner.height <= outer.y + outer.height
    }
}

enum ViewportOverlap {
    static func uniqueCount(
        previous: [ScannedVoiceCandidate],
        current: [ScannedVoiceCandidate]
    ) throws -> Int {
        let previousIDs = previous.compactMap(\.axOccurrenceIdentifier)
        let currentIDs = current.compactMap(\.axOccurrenceIdentifier)
        guard previousIDs.count == previous.count,
              currentIDs.count == current.count else {
            throw VoiceMP4Error.safetyViolation(
                "跨页需要每个可点击语音节点提供稳定 AXIdentifier"
            )
        }
        guard Set(previousIDs).count == previousIDs.count,
              Set(currentIDs).count == currentIDs.count else {
            throw VoiceMP4Error.safetyViolation(
                "同一屏出现重复 AXIdentifier；可能是通用控件 ID，禁止跨页"
            )
        }
        guard previous.allSatisfy({ $0.axSemanticDigest?.isEmpty == false }),
              current.allSatisfy({ $0.axSemanticDigest?.isEmpty == false }) else {
            throw VoiceMP4Error.safetyViolation("跨页候选缺少稳定 AX 语义摘要")
        }
        let matches = matchingCounts(previous: previous, current: current)
        guard matches.count == 1, let overlap = matches.first else {
            if matches.isEmpty {
                throw VoiceMP4Error.safetyViolation("页间没有可验证重叠")
            }
            throw VoiceMP4Error.safetyViolation(
                "页间重叠存在多个解释 \(matches.sorted())；重复外观语音不能自动去重"
            )
        }
        return overlap
    }

    static func matchingCounts(
        previous: [ScannedVoiceCandidate],
        current: [ScannedVoiceCandidate]
    ) -> [Int] {
        let limit = min(previous.count, current.count)
        guard limit > 0 else { return [] }
        var matches: [Int] = []
        for length in stride(from: limit, through: 1, by: -1) {
            let previousSuffix = previous.suffix(length)
            let currentPrefix = current.prefix(length)
            let isMatch = zip(previousSuffix, currentPrefix).allSatisfy { lhs, rhs in
                lhs.axOccurrenceIdentifier == rhs.axOccurrenceIdentifier
                    && lhs.durationMilliseconds == rhs.durationMilliseconds
                    && lhs.axSemanticDigest == rhs.axSemanticDigest
                    && lhs.fingerprint == rhs.fingerprint
            }
            if isMatch { matches.append(length) }
        }
        return matches
    }
}

enum CandidateIdentityPolicy {
    static let minimumConfidence = 0.55
    static let maximumCenterDrift = 0.018

    static func matches(_ candidate: ScannedVoiceCandidate, target: VoiceTarget) -> Bool {
        guard candidate.confidence >= minimumConfidence,
              candidate.durationMilliseconds == target.expectedDurationMilliseconds,
              candidate.axSemanticSignature == target.axSemanticSignature,
              candidate.axSemanticDigest == target.axSemanticDigest,
              let planned = target.bubbleRect,
              centerDistance(candidate.rect, planned) <= maximumCenterDrift else { return false }
        if let occurrence = target.axOccurrenceIdentifier {
            return candidate.axOccurrenceIdentifier == occurrence
        }
        return candidate.fingerprint == target.contextFingerprint
    }

    private static func centerDistance(_ lhs: NormalizedRect, _ rhs: NormalizedRect) -> Double {
        let dx = lhs.x + lhs.width / 2 - rhs.x - rhs.width / 2
        let dy = lhs.y + lhs.height / 2 - rhs.y - rhs.height / 2
        return sqrt(dx * dx + dy * dy)
    }
}

enum VoiceSegmentDurationPolicy {
    /// WeChat displays whole seconds. A valid capture must retain almost the
    /// entire displayed duration, while allowing for display rounding and the
    /// deliberately preserved boundary padding.
    static func matches(expectedMilliseconds: Int, actualMilliseconds: Int?) -> Bool {
        guard expectedMilliseconds > 0, let actualMilliseconds else { return false }
        let minimum = max(600, expectedMilliseconds - 1_000)
        let maximum = expectedMilliseconds + 1_500
        return (minimum...maximum).contains(actualMilliseconds)
    }
}
