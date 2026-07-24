import ApplicationServices
import CoreGraphics
import CryptoKit
import Foundation

struct AXHitEvidence: Codable, Equatable, Sendable {
    let rolePath: [String]
    let semanticHints: [String]
    let actionNames: [String]
    let hasMessageListAncestor: Bool
    let hasPressAction: Bool
    let hasVoiceSemantic: Bool
    let hasUnifiedVoicePressNode: Bool
    let forbiddenRole: String?
    let actionableRole: String?
    let actionableFrame: WindowFrame?
    let semanticDigest: String
    let occurrenceIdentifier: String?
    let signature: String

    var isStrictVoiceTarget: Bool {
        hasMessageListAncestor
            && hasUnifiedVoicePressNode
            && forbiddenRole == nil
    }
}

fileprivate struct AXResolvedHit {
    let evidence: AXHitEvidence
    let actionableElement: AXUIElement
}

struct AXVoiceCandidateResolution: Sendable {
    let candidate: ScannedVoiceCandidate
    let evidence: AXHitEvidence?
}

enum AXVoiceCandidateResolver {
    private static let horizontalOffsets: [Double] = [
        0, -0.035, 0.035, -0.07, 0.07, -0.11, 0.11, -0.15, 0.15, -0.20, 0.20
    ]

    static func resolve(
        snapshot: WindowSnapshot,
        candidate: ScannedVoiceCandidate,
        region: NormalizedRect
    ) -> AXVoiceCandidateResolution {
        var matches: [(candidate: ScannedVoiceCandidate, hit: AXResolvedHit, distance: Double)] = []
        let originalCenter = candidate.rect.x + candidate.rect.width / 2
        for offset in horizontalOffsets {
            let desiredCenter = originalCenter + offset
            let halfWidth = candidate.rect.width / 2
            let center = min(
                max(desiredCenter, region.x + halfWidth),
                region.x + region.width - halfWidth
            )
            let rect = NormalizedRect(
                x: center - halfWidth,
                y: candidate.rect.y,
                width: candidate.rect.width,
                height: candidate.rect.height
            )
            guard MessageRegionPolicy.contains(region, rect),
                  MessageRegionPolicy.containsHardBounds(rect),
                  let hit = try? MacAXHitInspector.inspectResolved(
                    snapshot: snapshot,
                    rect: rect
                  ),
                  hit.evidence.isStrictVoiceTarget else { continue }
            let resolved = ScannedVoiceCandidate(
                sequenceInViewport: candidate.sequenceInViewport,
                durationMilliseconds: candidate.durationMilliseconds,
                senderLabel: candidate.senderLabel,
                timestampLabel: candidate.timestampLabel,
                rect: rect,
                confidence: candidate.confidence,
                fingerprint: candidate.fingerprint,
                axSemanticSignature: hit.evidence.signature,
                axSemanticDigest: hit.evidence.semanticDigest,
                axOccurrenceIdentifier: hit.evidence.occurrenceIdentifier
            )
            let distance = abs(center - originalCenter)
            if let index = matches.firstIndex(where: {
                CFEqual($0.hit.actionableElement, hit.actionableElement)
            }) {
                if matches[index].distance > distance {
                    matches[index] = (resolved, hit, distance)
                }
            } else {
                matches.append((resolved, hit, distance))
            }
        }
        guard matches.count == 1, let match = matches.first else {
            return AXVoiceCandidateResolution(candidate: candidate, evidence: nil)
        }
        return AXVoiceCandidateResolution(
            candidate: match.candidate,
            evidence: match.hit.evidence
        )
    }
}

enum MacAXHitInspector {
    private static let messageContainerRoles = Set([
        "AXScrollArea", "AXList", "AXOutline", "AXTable"
    ])
    private static let forbiddenRoles = Set([
        "AXTextArea", "AXTextField", "AXSearchField", "AXMenu", "AXMenuItem",
        "AXToolbar", "AXCheckBox", "AXRadioButton", "AXPopUpButton", "AXComboBox"
    ])
    private static let semanticAttributes = [
        kAXIdentifierAttribute,
        kAXDescriptionAttribute,
        kAXHelpAttribute,
        kAXSubroleAttribute,
        kAXTitleAttribute,
        kAXValueAttribute
    ]
    private static let strongSemanticAttributes = Set([
        kAXIdentifierAttribute,
        kAXDescriptionAttribute,
        kAXHelpAttribute,
        kAXSubroleAttribute
    ])

    static func inspect(
        snapshot: WindowSnapshot,
        rect: NormalizedRect
    ) throws -> AXHitEvidence {
        try inspectResolved(snapshot: snapshot, rect: rect).evidence
    }

    fileprivate static func inspectResolved(
        snapshot: WindowSnapshot,
        rect: NormalizedRect
    ) throws -> AXResolvedHit {
        let point = CGPoint(
            x: snapshot.frame.minX + (rect.x + rect.width / 2) * snapshot.frame.width,
            y: snapshot.frame.minY + (rect.y + rect.height / 2) * snapshot.frame.height
        )
        return try inspectResolved(
            point: point,
            processIdentifier: snapshot.processIdentifier,
            windowID: snapshot.windowID
        )
    }

    static func inspect(
        point: CGPoint,
        processIdentifier: pid_t,
        windowID: CGWindowID
    ) throws -> AXHitEvidence {
        try inspectResolved(
            point: point,
            processIdentifier: processIdentifier,
            windowID: windowID
        ).evidence
    }

    private static func inspectResolved(
        point: CGPoint,
        processIdentifier: pid_t,
        windowID: CGWindowID
    ) throws -> AXResolvedHit {
        let application = AXUIElementCreateApplication(processIdentifier)
        var element: AXUIElement?
        let error = AXUIElementCopyElementAtPosition(
            application,
            Float(point.x),
            Float(point.y),
            &element
        )
        guard error == .success, let element else {
            throw VoiceMP4Error.safetyViolation("辅助功能命中测试失败")
        }
        var owner: pid_t = 0
        guard AXUIElementGetPid(element, &owner) == .success, owner == processIdentifier else {
            throw VoiceMP4Error.safetyViolation("命中位置不属于绑定的微信进程")
        }

        var rolePath: [String] = []
        var semanticHints = Set<String>()
        var strongSemanticValues: [String] = []
        var actionNames = Set<String>()
        var foundMessageContainer = false
        var hasUnifiedVoicePressNode = false
        var containerIdentity = ""
        var forbiddenRole: String?
        var actionableElement: AXUIElement?
        var actionableRole: String?
        var actionableFrame: WindowFrame?
        var actionableSignatureParts: [String] = []
        var occurrenceIdentifier: String?
        var current: AXUIElement? = element
        var insideTargetScope = true

        for _ in 0..<24 {
            guard let node = current,
                  let role: String = value(node, kAXRoleAttribute) else {
                throw VoiceMP4Error.safetyViolation("无法证明命中元素的辅助功能层级")
            }
            rolePath.append(role)
            if forbiddenRole == nil, forbiddenRoles.contains(role) {
                forbiddenRole = role
            }
            let isMessageContainer = messageContainerRoles.contains(role)
            if insideTargetScope, !isMessageContainer {
                let nodeActions = actions(node)
                actionNames.formUnion(nodeActions)
                var nodeStrongSemanticValues: [String] = []
                var nodeSemanticParts: [String] = []
                for attribute in semanticAttributes {
                    guard let text: String = value(node, attribute),
                          !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                        continue
                    }
                    let clipped = String(text.prefix(160))
                    semanticHints.insert("\(attribute)=\(clipped)")
                    nodeSemanticParts.append("\(attribute)=\(clipped)")
                    if strongSemanticAttributes.contains(attribute) {
                        strongSemanticValues.append(clipped)
                        nodeStrongSemanticValues.append(clipped)
                    }
                }
                if nodeActions.contains(kAXPressAction),
                   nodeStrongSemanticValues.contains(where: containsVoiceMarker),
                   actionableElement == nil {
                    hasUnifiedVoicePressNode = true
                    actionableElement = node
                    actionableRole = role
                    actionableFrame = frame(of: node)
                    let rawIdentifier: String? = value(node, kAXIdentifierAttribute)
                    if let rawIdentifier = rawIdentifier?
                        .trimmingCharacters(in: .whitespacesAndNewlines),
                       !rawIdentifier.isEmpty {
                        occurrenceIdentifier = occurrenceID(
                            processIdentifier: processIdentifier,
                            windowID: windowID,
                            rawIdentifier: rawIdentifier
                        )
                    }
                    actionableSignatureParts = [
                        role,
                        nodeSemanticParts.sorted().joined(separator: "|"),
                        nodeActions.sorted().joined(separator: "|"),
                        frameIdentity(actionableFrame)
                    ]
                }
            }
            if isMessageContainer {
                foundMessageContainer = true
                let identifier: String = value(node, kAXIdentifierAttribute) ?? ""
                let description: String = value(node, kAXDescriptionAttribute) ?? ""
                containerIdentity = "\(role)|\(identifier)|\(description)"
                insideTargetScope = false
            }
            if role == "AXWindow" { break }
            current = value(node, kAXParentAttribute)
        }

        let sortedHints = semanticHints.sorted()
        let sortedActions = actionNames.sorted()
        let hasPress = actionNames.contains(kAXPressAction)
        let hasVoiceSemantic = strongSemanticValues.contains(where: containsVoiceMarker)
        guard let actionableElement else {
            throw VoiceMP4Error.safetyViolation(
                "命中位置没有同一节点同时提供语音语义与 AXPress"
            )
        }
        let signatureInput = actionableSignatureParts + [
            containerIdentity,
            "unified-voice-press"
        ]
        let semanticMaterial = actionableSignatureParts.dropLast().joined(separator: "\n")
        let semanticDigest = SHA256.hash(data: Data(semanticMaterial.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
        let signatureMaterial = signatureInput.joined(separator: "\n")
        let signature = SHA256.hash(data: Data(signatureMaterial.utf8))
            .map { String(format: "%02x", $0) }
            .joined()

        let evidence = AXHitEvidence(
            rolePath: rolePath,
            semanticHints: sortedHints,
            actionNames: sortedActions,
            hasMessageListAncestor: foundMessageContainer,
            hasPressAction: hasPress,
            hasVoiceSemantic: hasVoiceSemantic,
            hasUnifiedVoicePressNode: hasUnifiedVoicePressNode,
            forbiddenRole: forbiddenRole,
            actionableRole: actionableRole,
            actionableFrame: actionableFrame,
            semanticDigest: semanticDigest,
            occurrenceIdentifier: occurrenceIdentifier,
            signature: signature
        )
        return AXResolvedHit(evidence: evidence, actionableElement: actionableElement)
    }

    private static func occurrenceID(
        processIdentifier: pid_t,
        windowID: CGWindowID,
        rawIdentifier: String
    ) -> String {
        let material = "ax-occ-v1|\(processIdentifier)|\(windowID)|\(rawIdentifier)"
        return SHA256.hash(data: Data(material.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
    }

    private static func frame(of element: AXUIElement) -> WindowFrame? {
        guard let position = pointValue(element, kAXPositionAttribute),
              let size = sizeValue(element, kAXSizeAttribute) else { return nil }
        return WindowFrame(
            x: position.x,
            y: position.y,
            width: size.width,
            height: size.height
        )
    }

    private static func frameIdentity(_ frame: WindowFrame?) -> String {
        guard let frame else { return "frame=unknown" }
        return String(
            format: "frame=%.1f,%.1f,%.1f,%.1f",
            frame.x,
            frame.y,
            frame.width,
            frame.height
        )
    }

    private static func pointValue(_ element: AXUIElement, _ attribute: String) -> CGPoint? {
        var raw: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, attribute as CFString, &raw) == .success,
              let raw,
              CFGetTypeID(raw) == AXValueGetTypeID() else { return nil }
        var point = CGPoint.zero
        guard AXValueGetValue(raw as! AXValue, .cgPoint, &point) else { return nil }
        return point
    }

    private static func sizeValue(_ element: AXUIElement, _ attribute: String) -> CGSize? {
        var raw: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, attribute as CFString, &raw) == .success,
              let raw,
              CFGetTypeID(raw) == AXValueGetTypeID() else { return nil }
        var size = CGSize.zero
        guard AXValueGetValue(raw as! AXValue, .cgSize, &size) else { return nil }
        return size
    }

    private static func containsVoiceMarker(_ raw: String) -> Bool {
        let value = raw.folding(
            options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive],
            locale: Locale(identifier: "en_US_POSIX")
        )
        return value.contains("语音")
            || value.contains("voice message")
            || value.contains("voice-message")
            || value.contains("voicemessage")
            || value.contains("audio message")
    }

    private static func actions(_ element: AXUIElement) -> [String] {
        var raw: CFArray?
        guard AXUIElementCopyActionNames(element, &raw) == .success,
              let raw else { return [] }
        return raw as? [String] ?? []
    }

    private static func value<T>(_ element: AXUIElement, _ attribute: String) -> T? {
        var raw: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, attribute as CFString, &raw) == .success else {
            return nil
        }
        return raw as? T
    }
}
