import AudioToolbox
@preconcurrency import AVFoundation
import CryptoKit
import Foundation

enum DirectAudioDurationPolicy {
    static let expectedMilliseconds = 100...61_000
}

struct DirectAudioManifest: Codable, Equatable, Sendable {
    static let currentSchemaVersion = 1

    var schemaVersion: Int
    var title: String
    var expectedCount: Int
    var items: [DirectAudioItem]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case title
        case expectedCount = "expected_count"
        case items
    }

    func validated() throws -> DirectAudioManifest {
        guard schemaVersion == Self.currentSchemaVersion else {
            throw VoiceMP4Error.validation("直连清单版本不受支持：\(schemaVersion)")
        }
        guard !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw VoiceMP4Error.validation("直连清单标题不能为空")
        }
        guard expectedCount > 0, expectedCount == items.count else {
            throw VoiceMP4Error.validation("直连清单条数与 expectedCount 不一致")
        }
        guard items.map(\.sequence) == Array(1...items.count) else {
            throw VoiceMP4Error.validation("直连清单 sequence 必须从 1 连续递增")
        }
        guard Set(items.map(\.serverID)).count == items.count else {
            throw VoiceMP4Error.validation("直连清单包含重复 serverID")
        }
        guard Set(items.map(\.sourcePath)).count == items.count else {
            throw VoiceMP4Error.validation("直连清单重复引用同一个音频文件")
        }
        for item in items {
            guard !item.serverID.isEmpty,
                  item.serverID != "0",
                  item.serverID.utf8.allSatisfy({ (48...57).contains($0) }),
                  !item.sourcePath.isEmpty,
                  !item.sourcePath.hasPrefix("/"),
                  URL(fileURLWithPath: item.sourcePath).lastPathComponent == item.sourcePath,
                  item.sourcePath.lowercased().hasSuffix(".m4a"),
                  DirectAudioDurationPolicy.expectedMilliseconds.contains(
                    item.expectedDurationMilliseconds
                  ),
                  item.sha256.count == 64,
                  item.sha256.allSatisfy({ $0.isHexDigit }) else {
                throw VoiceMP4Error.validation("直连清单第 \(item.sequence) 条字段无效")
            }
        }
        return self
    }
}

struct DirectAudioItem: Codable, Equatable, Sendable {
    var sequence: Int
    var serverID: String
    var sourcePath: String
    var expectedDurationMilliseconds: Int
    var sha256: String

    enum CodingKeys: String, CodingKey {
        case sequence
        case serverID = "server_id"
        case sourcePath = "source_path"
        case expectedDurationMilliseconds = "expected_duration_milliseconds"
        case sha256
    }
}

struct DirectAudioConversionReport: Codable, Sendable {
    var output: String
    var durationMilliseconds: Int
    var sha256: String
}

struct DirectAudioAssemblyReport: Codable, Sendable {
    var output: String
    var itemCount: Int
    var durationMilliseconds: Int
    var fileSize: UInt64
    var sha256: String
}

enum DirectAudioPipeline {
    static func convertPCMToM4A(
        inputURL: URL,
        outputURL: URL,
        sampleRate: Int,
        expectedDurationMilliseconds: Int?
    ) async throws -> DirectAudioConversionReport {
        guard [8_000, 12_000, 16_000, 24_000, 32_000, 44_100, 48_000]
            .contains(sampleRate) else {
            throw VoiceMP4Error.invalidArguments("PCM 采样率不受支持：\(sampleRate)")
        }
        guard outputURL.pathExtension.lowercased() == "m4a" else {
            throw VoiceMP4Error.invalidArguments("PCM 转换输出必须使用 .m4a 扩展名")
        }
        let inputValues = try inputURL.resourceValues(forKeys: [
            .isRegularFileKey,
            .isSymbolicLinkKey
        ])
        guard inputValues.isRegularFile == true,
              inputValues.isSymbolicLink != true,
              FileManager.default.isReadableFile(atPath: inputURL.path) else {
            throw VoiceMP4Error.validation("PCM 文件不可读：\(inputURL.path)")
        }
        guard !FileManager.default.fileExists(atPath: outputURL.path) else {
            throw VoiceMP4Error.validation("M4A 输出已存在：\(outputURL.path)")
        }

        let pcm = try Data(contentsOf: inputURL, options: .mappedIfSafe)
        guard !pcm.isEmpty, pcm.count.isMultiple(of: 2) else {
            throw VoiceMP4Error.validation("PCM 必须是非空的 16-bit little-endian 单声道数据")
        }
        let frameCount = pcm.count / 2
        let durationMilliseconds = Int(
            (Double(frameCount) * 1_000 / Double(sampleRate)).rounded()
        )
        if let expectedDurationMilliseconds {
            let allowed = DirectAudioDurationPolicy.expectedMilliseconds
            guard allowed.contains(expectedDurationMilliseconds) else {
                throw VoiceMP4Error.invalidArguments(
                    "数据库语音时长必须介于 \(allowed.lowerBound)...\(allowed.upperBound) 毫秒"
                )
            }
            guard MediaInspector.durationMatches(
                expectedMilliseconds: expectedDurationMilliseconds,
                actualMilliseconds: durationMilliseconds,
                absoluteToleranceMilliseconds: 120,
                proportionalTolerance: 0.02
            ) else {
                throw VoiceMP4Error.validation(
                    "PCM 时长与数据库不符：预期 \(expectedDurationMilliseconds)ms，实际 \(durationMilliseconds)ms"
                )
            }
        }

        try FileManager.default.createDirectory(
            at: outputURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        guard (100...65_000).contains(durationMilliseconds) else {
            throw VoiceMP4Error.validation("PCM 时长超出单条微信语音安全范围")
        }
        let encoderSampleRate = 48_000.0
        guard let format = AVAudioFormat(
            commonFormat: .pcmFormatFloat32,
            sampleRate: encoderSampleRate,
            channels: 1,
            interleaved: false
        ) else {
            throw VoiceMP4Error.unavailable("无法创建 PCM 音频格式")
        }
        let resampledFrameCount = Int(
            (Double(frameCount) * encoderSampleRate / Double(sampleRate)).rounded()
        )
        let frames = AVAudioFrameCount(resampledFrameCount)
        guard let buffer = AVAudioPCMBuffer(pcmFormat: format, frameCapacity: frames),
              let samples = buffer.floatChannelData?[0] else {
            throw VoiceMP4Error.unavailable("无法分配 PCM 转换缓冲区")
        }
        buffer.frameLength = frames
        pcm.withUnsafeBytes { raw in
            let bytes = raw.bindMemory(to: UInt8.self)
            func sample(at index: Int) -> Float {
                let bounded = min(max(index, 0), frameCount - 1)
                let lower = UInt16(bytes[bounded * 2])
                let upper = UInt16(bytes[bounded * 2 + 1]) << 8
                return Float(Int16(bitPattern: lower | upper)) / 32_768
            }
            for index in 0..<resampledFrameCount {
                let sourcePosition = Double(index) * Double(sampleRate) / encoderSampleRate
                let lowerIndex = Int(sourcePosition.rounded(.down))
                let fraction = Float(sourcePosition - Double(lowerIndex))
                let lower = sample(at: lowerIndex)
                let upper = sample(at: lowerIndex + 1)
                samples[index] = lower + (upper - lower) * fraction
            }
        }
        let temporaryURL = outputURL.deletingLastPathComponent()
            .appendingPathComponent(".\(UUID().uuidString)-audio.m4a")
        defer { try? FileManager.default.removeItem(at: temporaryURL) }
        do {
            let settings: [String: Any] = [
                AVFormatIDKey: kAudioFormatMPEG4AAC,
                AVSampleRateKey: encoderSampleRate,
                AVNumberOfChannelsKey: 1,
                AVEncoderBitRateKey: 64_000
            ]
            let file = try AVAudioFile(
                forWriting: temporaryURL,
                settings: settings,
                commonFormat: .pcmFormatFloat32,
                interleaved: false
            )
            try file.write(from: buffer)
        }

        let inspection = await MediaInspector.inspect(temporaryURL)
        guard inspection.isUsableAudio,
              MediaInspector.durationMatches(
                expectedMilliseconds: durationMilliseconds,
                actualMilliseconds: inspection.durationMilliseconds,
                absoluteToleranceMilliseconds: 120,
                proportionalTolerance: 0
              ),
              let inspectedDuration = inspection.durationMilliseconds else {
            throw VoiceMP4Error.validation("M4A 转换后未通过完整音频校验")
        }
        try FileManager.default.moveItem(at: temporaryURL, to: outputURL)
        return DirectAudioConversionReport(
            output: outputURL.path,
            durationMilliseconds: inspectedDuration,
            sha256: inspection.sha256
        )
    }

    static func assemble(
        manifestURL: URL,
        outputURL: URL,
        gapMilliseconds: Int
    ) async throws -> DirectAudioAssemblyReport {
        guard FileManager.default.isReadableFile(atPath: manifestURL.path) else {
            throw VoiceMP4Error.validation("直连清单不可读：\(manifestURL.path)")
        }
        let manifest = try JSONDecoder().decode(
            DirectAudioManifest.self,
            from: Data(contentsOf: manifestURL)
        ).validated()
        let manifestDirectory = manifestURL.deletingLastPathComponent()
        var urls: [URL] = []
        for item in manifest.items {
            let source = try resolvedSource(item.sourcePath, relativeTo: manifestDirectory)
            let values = try source.resourceValues(forKeys: [
                .isRegularFileKey,
                .isSymbolicLinkKey
            ])
            guard values.isRegularFile == true,
                  values.isSymbolicLink != true,
                  FileManager.default.isReadableFile(atPath: source.path) else {
                throw VoiceMP4Error.validation("第 \(item.sequence) 条音频不可读")
            }
            let actualHash = try sha256(source)
            guard actualHash == item.sha256.lowercased() else {
                throw VoiceMP4Error.safetyViolation("第 \(item.sequence) 条音频哈希发生变化")
            }
            let inspection = await MediaInspector.inspect(source)
            guard inspection.isUsableAudio,
                  MediaInspector.durationMatches(
                    expectedMilliseconds: item.expectedDurationMilliseconds,
                    actualMilliseconds: inspection.durationMilliseconds,
                    absoluteToleranceMilliseconds: 350,
                    proportionalTolerance: 0.02
                  ) else {
                throw VoiceMP4Error.validation(
                    "第 \(item.sequence) 条音频时长与数据库不符"
                )
            }
            urls.append(source)
        }
        try await AVFoundationMediaAssembler().assemble(
            segments: urls,
            gapMilliseconds: gapMilliseconds,
            title: manifest.title,
            outputURL: outputURL
        )
        let inspection = try await AVFoundationMediaAssembler.inspectAndValidate(outputURL)
        return DirectAudioAssemblyReport(
            output: outputURL.path,
            itemCount: urls.count,
            durationMilliseconds: inspection.durationMilliseconds,
            fileSize: inspection.fileSize,
            sha256: try sha256(outputURL)
        )
    }

    private static func resolvedSource(_ path: String, relativeTo base: URL) throws -> URL {
        guard !path.hasPrefix("/"),
              URL(fileURLWithPath: path).lastPathComponent == path else {
            throw VoiceMP4Error.safetyViolation("直连清单音频路径必须是同目录文件名")
        }
        let resolvedBase = base.standardizedFileURL.resolvingSymlinksInPath()
        let source = resolvedBase.appendingPathComponent(path).standardizedFileURL
        guard source.deletingLastPathComponent() == resolvedBase else {
            throw VoiceMP4Error.safetyViolation("直连清单音频路径越界")
        }
        return source
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
