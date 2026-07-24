import AVFoundation
import CryptoKit
import Foundation

struct MediaInspection: Sendable {
    let url: URL
    let hasAudio: Bool
    let isPlayable: Bool
    let durationMilliseconds: Int?
    let sha256: String

    var isUsableAudio: Bool {
        hasAudio && isPlayable && (durationMilliseconds ?? 0) > 0
    }
}

enum MediaInspector {
    static func inspect(_ url: URL) async -> MediaInspection {
        let digest = (try? sha256(url)) ?? ""
        let asset = AVURLAsset(url: url)
        do {
            let playable = try await asset.load(.isPlayable)
            let duration = try await asset.load(.duration)
            let audioTracks = try await asset.loadTracks(withMediaType: .audio)
            let milliseconds: Int?
            if duration.isNumeric {
                milliseconds = Int((CMTimeGetSeconds(duration) * 1_000).rounded())
            } else {
                milliseconds = nil
            }
            return MediaInspection(
                url: url,
                hasAudio: !audioTracks.isEmpty,
                isPlayable: playable,
                durationMilliseconds: milliseconds,
                sha256: digest
            )
        } catch {
            return MediaInspection(
                url: url,
                hasAudio: false,
                isPlayable: false,
                durationMilliseconds: nil,
                sha256: digest
            )
        }
    }

    static func copyCandidate(_ source: URL, into directory: URL, name: String) throws -> URL {
        let destination = directory.appendingPathComponent(name)
        if FileManager.default.fileExists(atPath: destination.path) {
            throw VoiceMP4Error.validation("候选文件已存在：\(destination.lastPathComponent)")
        }
        try FileManager.default.copyItem(at: source, to: destination)
        return destination
    }

    static func durationMatches(
        expectedMilliseconds: Int,
        actualMilliseconds: Int?,
        absoluteToleranceMilliseconds: Int = 750,
        proportionalTolerance: Double = 0.03
    ) -> Bool {
        guard let actualMilliseconds else { return false }
        let tolerance = max(
            absoluteToleranceMilliseconds,
            Int(Double(expectedMilliseconds) * proportionalTolerance)
        )
        return abs(expectedMilliseconds - actualMilliseconds) <= tolerance
    }

    private static func sha256(_ url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while let chunk = try handle.read(upToCount: 1_048_576), !chunk.isEmpty {
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
