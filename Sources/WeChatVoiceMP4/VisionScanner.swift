import CryptoKit
import CoreGraphics
import Foundation
import Vision

struct RecognizedTextBlock: Sendable {
    let text: String
    let confidence: Double
    let rect: NormalizedRect
}

enum VisionTextRecognizer {
    static func recognize(in image: CGImage) throws -> [RecognizedTextBlock] {
        let request = VNRecognizeTextRequest()
        request.recognitionLevel = .accurate
        request.recognitionLanguages = ["zh-Hans", "en-US"]
        request.usesLanguageCorrection = false
        let handler = VNImageRequestHandler(cgImage: image, orientation: .up, options: [:])
        try handler.perform([request])

        return (request.results ?? []).compactMap { observation in
            guard let candidate = observation.topCandidates(1).first else { return nil }
            let box = observation.boundingBox
            return RecognizedTextBlock(
                text: candidate.string,
                confidence: Double(candidate.confidence),
                rect: NormalizedRect(
                    x: box.minX,
                    y: 1 - box.maxY,
                    width: box.width,
                    height: box.height
                )
            )
        }
    }
}

enum ChatHeaderRecognizer {
    static func detect(in image: CGImage) throws -> String? {
        let ignored = Set(["微信", "WeChat", "搜索", "+"])
        let candidates = try VisionTextRecognizer.recognize(in: image).filter { block in
            let centerX = block.rect.x + block.rect.width / 2
            return block.rect.y < 0.095
                && centerX > 0.28
                && centerX < 0.92
                && block.text.count >= 2
                && !ignored.contains(block.text)
        }
        return candidates.max { lhs, rhs in
            headerScore(lhs) < headerScore(rhs)
        }?.text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func headerScore(_ block: RecognizedTextBlock) -> Double {
        let centerX = block.rect.x + block.rect.width / 2
        let centered = max(0, 1 - abs(centerX - 0.62))
        return block.rect.height * 20 + block.confidence + centered
    }
}

struct VisionVoiceCandidateScanner: VoiceCandidateScanning, Sendable {
    static let version = "vision-quoted-duration-ax-occurrence-v5"

    func scan(
        _ snapshot: WindowSnapshot,
        within region: NormalizedRect
    ) async throws -> [ScannedVoiceCandidate] {
        guard region.isInsideUnitSquare else {
            throw VoiceMP4Error.validation("消息区域必须位于窗口归一化坐标 0...1 内")
        }
        let blocks = try VisionTextRecognizer.recognize(in: snapshot.image)
        let durationBlocks = blocks.compactMap { block -> (RecognizedTextBlock, Int)? in
            guard contains(region, centerOf: block.rect),
                  let duration = Self.parseDurationMilliseconds(block.text) else { return nil }
            return (block, duration)
        }
        .sorted { lhs, rhs in
            if abs(lhs.0.rect.y - rhs.0.rect.y) < 0.01 {
                return lhs.0.rect.x < rhs.0.rect.x
            }
            return lhs.0.rect.y < rhs.0.rect.y
        }

        return durationBlocks.enumerated().map { index, item in
            let (block, duration) = item
            let clickRect = expandedClickRect(block.rect, constrainedTo: region)
            let timestamp = nearbyTimestamp(for: block, among: blocks)
            return ScannedVoiceCandidate(
                sequenceInViewport: index + 1,
                durationMilliseconds: duration,
                senderLabel: nil,
                timestampLabel: timestamp,
                rect: clickRect,
                confidence: block.confidence,
                fingerprint: fingerprint(
                    image: snapshot.image,
                    rowRect: rowContextRect(clickRect, region: region),
                    duration: duration
                )
            )
        }
    }

    static func parseDurationMilliseconds(_ raw: String) -> Int? {
        let compact = raw
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: " ", with: "")
        let suffixes = ["″", "\"", "”", "“", "''", "’", "′"]
        guard let suffix = suffixes.first(where: { compact.hasSuffix($0) }) else { return nil }
        let number = compact.dropLast(suffix.count)
        guard let seconds = Int(number), (1...60).contains(seconds) else { return nil }
        return seconds * 1_000
    }

    private func nearbyTimestamp(
        for duration: RecognizedTextBlock,
        among blocks: [RecognizedTextBlock]
    ) -> String? {
        blocks
            .filter { block in
                block.rect.y <= duration.rect.y
                    && duration.rect.y - block.rect.y < 0.16
                    && looksLikeTimestamp(block.text)
            }
            .min { lhs, rhs in
                abs(duration.rect.y - lhs.rect.y) < abs(duration.rect.y - rhs.rect.y)
            }?.text
    }

    private func looksLikeTimestamp(_ value: String) -> Bool {
        value.range(of: #"(?:^|\s)\d{1,2}:\d{2}(?:\s|$)"#, options: .regularExpression) != nil
            || value.contains("昨天")
            || value.contains("星期")
            || value.contains("月")
    }

    private func expandedClickRect(
        _ rect: NormalizedRect,
        constrainedTo region: NormalizedRect
    ) -> NormalizedRect {
        let desiredWidth = max(rect.width + 0.045, 0.075)
        let desiredHeight = max(rect.height + 0.025, 0.05)
        let centerX = rect.x + rect.width / 2
        let centerY = rect.y + rect.height / 2
        let x = min(max(centerX - desiredWidth / 2, region.x), region.x + region.width - desiredWidth)
        let y = min(max(centerY - desiredHeight / 2, region.y), region.y + region.height - desiredHeight)
        return NormalizedRect(x: x, y: y, width: desiredWidth, height: desiredHeight)
    }

    private func rowContextRect(_ rect: NormalizedRect, region: NormalizedRect) -> NormalizedRect {
        let y = max(region.y, rect.y - 0.025)
        let maxY = min(region.y + region.height, rect.y + rect.height + 0.025)
        return NormalizedRect(x: region.x, y: y, width: region.width, height: maxY - y)
    }

    private func fingerprint(image: CGImage, rowRect: NormalizedRect, duration: Int) -> String {
        CandidateVisualFingerprint.make(
            image: image,
            rowRect: rowRect,
            durationMilliseconds: duration
        )
    }

    private func pixelRect(_ rect: NormalizedRect, image: CGImage) -> CGRect {
        CGRect(
            x: rect.x * Double(image.width),
            y: rect.y * Double(image.height),
            width: rect.width * Double(image.width),
            height: rect.height * Double(image.height)
        ).integral
    }

    private func contains(_ outer: NormalizedRect, centerOf inner: NormalizedRect) -> Bool {
        let x = inner.x + inner.width / 2
        let y = inner.y + inner.height / 2
        return x >= outer.x && x <= outer.x + outer.width
            && y >= outer.y && y <= outer.y + outer.height
    }

    private func centerOf(_ rect: NormalizedRect) -> (Double, Double) {
        (rect.x + rect.width / 2, rect.y + rect.height / 2)
    }
}

enum CandidateVisualFingerprint {
    static func make(
        image: CGImage,
        candidateRect: NormalizedRect,
        region: NormalizedRect,
        durationMilliseconds: Int
    ) -> String {
        let y = max(region.y, candidateRect.y - 0.025)
        let maxY = min(
            region.y + region.height,
            candidateRect.y + candidateRect.height + 0.025
        )
        return make(
            image: image,
            rowRect: NormalizedRect(
                x: region.x,
                y: y,
                width: region.width,
                height: maxY - y
            ),
            durationMilliseconds: durationMilliseconds
        )
    }

    static func make(
        image: CGImage,
        rowRect: NormalizedRect,
        durationMilliseconds: Int
    ) -> String {
        var data = Data("\(durationMilliseconds)|".utf8)
        let pixelRect = CGRect(
            x: rowRect.x * Double(image.width),
            y: rowRect.y * Double(image.height),
            width: rowRect.width * Double(image.width),
            height: rowRect.height * Double(image.height)
        ).integral
        if let cropped = image.cropping(to: pixelRect),
           let providerData = cropped.dataProvider?.data {
            data.append(providerData as Data)
        }
        return SHA256.hash(data: data).prefix(12).map { String(format: "%02x", $0) }.joined()
    }
}

enum ScreenshotDiagnostics {
    static func writePNG(
        _ snapshot: WindowSnapshot,
        candidates: [ScannedVoiceCandidate],
        to url: URL
    ) throws {
        guard let context = CGContext(
            data: nil,
            width: snapshot.image.width,
            height: snapshot.image.height,
            bitsPerComponent: 8,
            bytesPerRow: 0,
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
        ) else {
            throw VoiceMP4Error.unavailable("无法创建诊断截图画布")
        }
        let full = CGRect(x: 0, y: 0, width: snapshot.image.width, height: snapshot.image.height)
        context.draw(snapshot.image, in: full)
        context.setStrokeColor(CGColor(red: 1, green: 0.15, blue: 0.1, alpha: 1))
        context.setLineWidth(max(2, Double(snapshot.image.width) / 600))
        for candidate in candidates {
            let rect = candidate.rect
            let pixel = CGRect(
                x: rect.x * Double(snapshot.image.width),
                y: (1 - rect.y - rect.height) * Double(snapshot.image.height),
                width: rect.width * Double(snapshot.image.width),
                height: rect.height * Double(snapshot.image.height)
            )
            context.stroke(pixel)
        }
        guard let result = context.makeImage(),
              let destination = CGImageDestinationCreateWithURL(
                url as CFURL,
                "public.png" as CFString,
                1,
                nil
              ) else {
            throw VoiceMP4Error.unavailable("无法创建诊断 PNG")
        }
        CGImageDestinationAddImage(destination, result, nil)
        guard CGImageDestinationFinalize(destination) else {
            throw VoiceMP4Error.unavailable("无法写入诊断 PNG")
        }
    }
}
