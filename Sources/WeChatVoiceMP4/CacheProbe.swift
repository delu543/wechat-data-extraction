import CryptoKit
import Foundation

struct FileFingerprint: Equatable, Sendable {
    let url: URL
    let size: UInt64
    let modifiedAt: Date

    var redactedID: String {
        let digest = SHA256.hash(data: Data(url.path.utf8))
        return digest.prefix(8).map { String(format: "%02x", $0) }.joined()
    }
}

struct CacheChange: Sendable {
    enum Kind: String, Sendable { case created, modified }

    let kind: Kind
    let fingerprint: FileFingerprint
}

struct CacheSnapshot: Sendable {
    let capturedAt: Date
    let filesByPath: [String: FileFingerprint]

    func changes(comparedTo older: CacheSnapshot) -> [CacheChange] {
        filesByPath.values.compactMap { current in
            guard let previous = older.filesByPath[current.url.path] else {
                return CacheChange(kind: .created, fingerprint: current)
            }
            guard previous.size != current.size || previous.modifiedAt != current.modifiedAt else {
                return nil
            }
            return CacheChange(kind: .modified, fingerprint: current)
        }
        .sorted { lhs, rhs in
            if lhs.fingerprint.modifiedAt == rhs.fingerprint.modifiedAt {
                return lhs.fingerprint.size > rhs.fingerprint.size
            }
            return lhs.fingerprint.modifiedAt > rhs.fingerprint.modifiedAt
        }
    }
}

struct WeChatDataLocator: Sendable {
    let homeDirectory: URL

    init(homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser) {
        self.homeDirectory = homeDirectory
    }

    func probeRoots() -> [URL] {
        let base = homeDirectory.appendingPathComponent(
            "Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files",
            isDirectory: true
        )
        guard let accounts = try? FileManager.default.contentsOfDirectory(
            at: base,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        ) else { return [] }

        let relativeCandidates = [
            "msg",
            "cache",
            "temp",
            "business/favorite"
        ]

        return accounts.flatMap { account in
            relativeCandidates.map { account.appendingPathComponent($0, isDirectory: true) }
        }
        .filter { FileManager.default.fileExists(atPath: $0.path) }
    }
}

struct CacheProbe: Sendable {
    let roots: [URL]
    let maximumFiles: Int

    init(roots: [URL], maximumFiles: Int = 100_000) {
        self.roots = roots
        self.maximumFiles = maximumFiles
    }

    func snapshot(modifiedSince: Date? = nil) throws -> CacheSnapshot {
        var files: [String: FileFingerprint] = [:]
        let keys: [URLResourceKey] = [
            .isRegularFileKey,
            .fileSizeKey,
            .contentModificationDateKey
        ]

        for root in roots {
            guard let enumerator = FileManager.default.enumerator(
                at: root,
                includingPropertiesForKeys: keys,
                options: [.skipsHiddenFiles, .skipsPackageDescendants]
            ) else { continue }

            for case let fileURL as URL in enumerator {
                if files.count >= maximumFiles {
                    throw VoiceMP4Error.validation("缓存探针文件过多，请缩小扫描目录")
                }
                let values = try fileURL.resourceValues(forKeys: Set(keys))
                guard values.isRegularFile == true,
                      let size = values.fileSize,
                      let modifiedAt = values.contentModificationDate else { continue }
                if let modifiedSince, modifiedAt < modifiedSince { continue }
                files[fileURL.path] = FileFingerprint(
                    url: fileURL,
                    size: UInt64(max(size, 0)),
                    modifiedAt: modifiedAt
                )
            }
        }
        return CacheSnapshot(capturedAt: Date(), filesByPath: files)
    }

    func waitForStableChanges(
        after baseline: CacheSnapshot,
        timeoutSeconds: Double,
        pollMilliseconds: UInt64 = 350
    ) async throws -> [CacheChange] {
        let deadline = Date().addingTimeInterval(timeoutSeconds)
        var previous = baseline
        var lastChanges: [CacheChange] = []
        var stableRounds = 0

        while Date() < deadline {
            try await Task.sleep(for: .milliseconds(pollMilliseconds))
            let current = try snapshot(modifiedSince: baseline.capturedAt.addingTimeInterval(-1))
            let changes = current.changes(comparedTo: baseline)
            if sameSignatures(changes, lastChanges), !changes.isEmpty {
                stableRounds += 1
                if stableRounds >= 2 { return changes }
            } else {
                stableRounds = 0
                lastChanges = changes
            }
            previous = current
            _ = previous
        }
        return lastChanges
    }

    private func sameSignatures(_ lhs: [CacheChange], _ rhs: [CacheChange]) -> Bool {
        lhs.map { ($0.fingerprint.url.path, $0.fingerprint.size) }
            .elementsEqual(rhs.map { ($0.fingerprint.url.path, $0.fingerprint.size) }) {
                $0.0 == $1.0 && $0.1 == $1.1
            }
    }
}
