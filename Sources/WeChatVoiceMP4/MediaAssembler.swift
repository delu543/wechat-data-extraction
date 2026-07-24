import AudioToolbox
@preconcurrency import AVFoundation
import CoreMedia
import CoreVideo
import Foundation

struct AssembledMediaInspection: Codable, Sendable {
    let durationMilliseconds: Int
    let audioCodec: String
    let videoCodec: String
    let fileSize: UInt64
}

struct AVFoundationMediaAssembler: MediaAssembling, Sendable {
    func assemble(
        segments: [URL],
        gapMilliseconds: Int,
        title: String,
        outputURL: URL
    ) async throws {
        guard !segments.isEmpty else {
            throw VoiceMP4Error.validation("没有可合并的音频片段")
        }
        guard (0...5_000).contains(gapMilliseconds) else {
            throw VoiceMP4Error.validation("片段间隔必须介于 0...5000 毫秒")
        }
        guard outputURL.pathExtension.lowercased() == "mp4" else {
            throw VoiceMP4Error.validation("最终输出必须使用 .mp4 扩展名")
        }
        guard !FileManager.default.fileExists(atPath: outputURL.path) else {
            throw VoiceMP4Error.validation("最终 MP4 已存在：\(outputURL.path)")
        }
        try FileManager.default.createDirectory(
            at: outputURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )

        let composition = AVMutableComposition()
        guard let audioDestination = composition.addMutableTrack(
            withMediaType: .audio,
            preferredTrackID: kCMPersistentTrackID_Invalid
        ) else {
            throw VoiceMP4Error.unavailable("无法创建合并音轨")
        }
        let gap = CMTime(value: CMTimeValue(gapMilliseconds * 48), timescale: 48_000)
        var cursor = CMTime.zero
        for (index, url) in segments.enumerated() {
            let asset = AVURLAsset(url: url)
            guard let source = try await asset.loadTracks(withMediaType: .audio).first else {
                throw VoiceMP4Error.validation("片段没有音轨：\(url.lastPathComponent)")
            }
            let range = try await source.load(.timeRange)
            guard range.duration.isValid, range.duration > .zero else {
                throw VoiceMP4Error.validation("片段时长无效：\(url.lastPathComponent)")
            }
            try audioDestination.insertTimeRange(range, of: source, at: cursor)
            cursor = cursor + range.duration
            if index != segments.indices.last { cursor = cursor + gap }
        }
        guard cursor.isNumeric, cursor > .zero else {
            throw VoiceMP4Error.validation("合并后的总时长无效")
        }

        let identifier = UUID().uuidString
        let workingDirectory = outputURL.deletingLastPathComponent()
        let backdropURL = workingDirectory.appendingPathComponent(".\(identifier)-backdrop.mp4")
        let partialURL = workingDirectory.appendingPathComponent(".\(identifier)-partial.mp4")
        defer {
            try? FileManager.default.removeItem(at: backdropURL)
            try? FileManager.default.removeItem(at: partialURL)
        }

        try await makeBackdrop(url: backdropURL, duration: cursor)
        try await addBackdrop(from: backdropURL, to: composition, duration: cursor)
        try await export(composition: composition, title: title, to: partialURL)
        _ = try await Self.inspectAndValidate(
            partialURL,
            expectedDuration: cursor,
            toleranceMilliseconds: 120
        )
        try FileManager.default.moveItem(at: partialURL, to: outputURL)
    }

    static func inspectAndValidate(
        _ url: URL,
        expectedDuration: CMTime? = nil,
        toleranceMilliseconds: Int = 150
    ) async throws -> AssembledMediaInspection {
        let values = try url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
        guard values.isRegularFile == true, let size = values.fileSize, size > 0 else {
            throw VoiceMP4Error.validation("MP4 文件为空或不存在")
        }
        let asset = AVURLAsset(url: url)
        let duration = try await asset.load(.duration)
        let audioTracks = try await asset.loadTracks(withMediaType: .audio)
        let videoTracks = try await asset.loadTracks(withMediaType: .video)
        guard audioTracks.count == 1, videoTracks.count == 1,
              let audio = audioTracks.first, let video = videoTracks.first else {
            throw VoiceMP4Error.validation("MP4 必须且只能包含一条音轨和一条视频轨")
        }
        let audioCodec = try await codec(of: audio)
        let videoCodec = try await codec(of: video)
        guard audioCodec == "aac " else {
            throw VoiceMP4Error.validation("MP4 音频编码不是 AAC：\(audioCodec)")
        }
        guard videoCodec == "avc1" else {
            throw VoiceMP4Error.validation("MP4 视频编码不是 H.264：\(videoCodec)")
        }
        let milliseconds = Int((CMTimeGetSeconds(duration) * 1_000).rounded())
        if let expectedDuration {
            let expected = Int((CMTimeGetSeconds(expectedDuration) * 1_000).rounded())
            guard abs(expected - milliseconds) <= toleranceMilliseconds else {
                throw VoiceMP4Error.validation(
                    "MP4 时长不符：预期 \(expected)ms，实际 \(milliseconds)ms"
                )
            }
        }
        let audioRange = try await audio.load(.timeRange)
        let videoRange = try await video.load(.timeRange)
        try validateTrackCoverage(
            audioRange,
            assetDuration: duration,
            toleranceMilliseconds: toleranceMilliseconds,
            label: "音频"
        )
        try validateTrackCoverage(
            videoRange,
            assetDuration: duration,
            toleranceMilliseconds: toleranceMilliseconds,
            label: "视频"
        )
        try decodeToEnd(asset: asset, track: audio)
        try decodeToEnd(asset: asset, track: video)
        return AssembledMediaInspection(
            durationMilliseconds: milliseconds,
            audioCodec: audioCodec,
            videoCodec: videoCodec,
            fileSize: UInt64(size)
        )
    }

    private func makeBackdrop(url: URL, duration: CMTime) async throws {
        let width = 640
        let height = 360
        let writer = try AVAssetWriter(outputURL: url, fileType: .mp4)
        writer.shouldOptimizeForNetworkUse = true
        let settings: [String: Any] = [
            AVVideoCodecKey: AVVideoCodecType.h264,
            AVVideoWidthKey: width,
            AVVideoHeightKey: height,
            AVVideoCompressionPropertiesKey: [
                AVVideoAverageBitRateKey: 180_000,
                AVVideoExpectedSourceFrameRateKey: 1,
                AVVideoMaxKeyFrameIntervalKey: 8,
                AVVideoProfileLevelKey: AVVideoProfileLevelH264MainAutoLevel
            ]
        ]
        guard writer.canApply(outputSettings: settings, forMediaType: .video) else {
            throw VoiceMP4Error.unavailable("当前系统不支持 H.264 输出设置")
        }
        let input = AVAssetWriterInput(mediaType: .video, outputSettings: settings)
        let attributes: [String: Any] = [
            kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA,
            kCVPixelBufferWidthKey as String: width,
            kCVPixelBufferHeightKey as String: height,
            kCVPixelBufferIOSurfacePropertiesKey as String: [:]
        ]
        let adaptor = AVAssetWriterInputPixelBufferAdaptor(
            assetWriterInput: input,
            sourcePixelBufferAttributes: attributes
        )
        guard writer.canAdd(input) else {
            throw VoiceMP4Error.unavailable("无法创建 H.264 视频轨")
        }
        writer.add(input)
        guard writer.startWriting() else {
            throw writer.error ?? VoiceMP4Error.unavailable("静态视频写入器启动失败")
        }
        writer.startSession(atSourceTime: .zero)
        guard let pool = adaptor.pixelBufferPool else {
            throw VoiceMP4Error.unavailable("无法创建视频像素缓冲池")
        }
        var optionalBuffer: CVPixelBuffer?
        guard CVPixelBufferPoolCreatePixelBuffer(nil, pool, &optionalBuffer) == kCVReturnSuccess,
              let buffer = optionalBuffer else {
            throw VoiceMP4Error.unavailable("无法分配视频像素缓冲")
        }
        fillBackdrop(buffer, width: width, height: height)

        let durationSeconds = CMTimeGetSeconds(duration)
        let frameCount = max(1, Int(ceil(durationSeconds)))
        for frame in 0..<frameCount {
            try await waitUntilReady(input, writer: writer)
            let presentationTime = CMTime(value: CMTimeValue(frame), timescale: 1)
            guard adaptor.append(buffer, withPresentationTime: presentationTime) else {
                throw writer.error ?? VoiceMP4Error.unavailable("静态视频帧写入失败")
            }
        }
        writer.endSession(atSourceTime: duration)
        input.markAsFinished()
        await writer.finishWriting()
        guard writer.status == .completed else {
            throw writer.error ?? VoiceMP4Error.unavailable("静态视频生成失败")
        }
    }

    private func fillBackdrop(_ buffer: CVPixelBuffer, width: Int, height: Int) {
        CVPixelBufferLockBaseAddress(buffer, [])
        defer { CVPixelBufferUnlockBaseAddress(buffer, []) }
        guard let base = CVPixelBufferGetBaseAddress(buffer) else { return }
        let rowBytes = CVPixelBufferGetBytesPerRow(buffer)
        for row in 0..<height {
            let bytes = base.advanced(by: row * rowBytes).assumingMemoryBound(to: UInt8.self)
            let blend = UInt8(28 + (row * 22 / max(height - 1, 1)))
            for column in 0..<width {
                let offset = column * 4
                bytes[offset] = blend + 18
                bytes[offset + 1] = blend + 7
                bytes[offset + 2] = blend
                bytes[offset + 3] = 255
            }
        }
    }

    private func waitUntilReady(
        _ input: AVAssetWriterInput,
        writer: AVAssetWriter
    ) async throws {
        let deadline = Date().addingTimeInterval(10)
        while !input.isReadyForMoreMediaData {
            guard writer.status == .writing else {
                throw writer.error ?? VoiceMP4Error.unavailable("静态视频编码器提前停止")
            }
            guard Date() < deadline else {
                writer.cancelWriting()
                throw VoiceMP4Error.unavailable("等待静态视频编码器超时")
            }
            try await Task.sleep(for: .milliseconds(2))
        }
    }

    private func addBackdrop(
        from url: URL,
        to composition: AVMutableComposition,
        duration: CMTime
    ) async throws {
        let asset = AVURLAsset(url: url)
        guard let source = try await asset.loadTracks(withMediaType: .video).first,
              let destination = composition.addMutableTrack(
                withMediaType: .video,
                preferredTrackID: kCMPersistentTrackID_Invalid
              ) else {
            throw VoiceMP4Error.unavailable("无法读取静态视频轨")
        }
        let sourceRange = try await source.load(.timeRange)
        let usableDuration = CMTimeMinimum(sourceRange.duration, duration)
        try destination.insertTimeRange(
            CMTimeRange(start: sourceRange.start, duration: usableDuration),
            of: source,
            at: .zero
        )
    }

    private func export(
        composition: AVMutableComposition,
        title: String,
        to url: URL
    ) async throws {
        guard let session = AVAssetExportSession(
            asset: composition,
            presetName: AVAssetExportPresetHighestQuality
        ) else {
            throw VoiceMP4Error.unavailable("无法创建 MP4 导出会话")
        }
        guard session.supportedFileTypes.contains(.mp4) else {
            throw VoiceMP4Error.unavailable("当前系统不支持 MP4 导出")
        }
        session.shouldOptimizeForNetworkUse = true
        session.allowsParallelizedExport = true
        let metadata = AVMutableMetadataItem()
        metadata.identifier = .commonIdentifierTitle
        metadata.value = title as NSString
        session.metadata = [metadata]
        try await session.export(to: url, as: .mp4)
    }

    private static func codec(of track: AVAssetTrack) async throws -> String {
        let descriptions = try await track.load(.formatDescriptions)
        guard !descriptions.isEmpty else {
            throw VoiceMP4Error.validation("媒体轨缺少编码描述")
        }
        let values = Set(descriptions.map { description in
            fourCC(CMFormatDescriptionGetMediaSubType(description))
        })
        guard values.count == 1, let codec = values.first else {
            throw VoiceMP4Error.validation("媒体轨包含混合编码：\(values.sorted())")
        }
        return codec
    }

    private static func fourCC(_ code: FourCharCode) -> String {
        let bytes: [UInt8] = [
            UInt8((code >> 24) & 0xff), UInt8((code >> 16) & 0xff),
            UInt8((code >> 8) & 0xff), UInt8(code & 0xff)
        ]
        return String(bytes: bytes, encoding: .macOSRoman)
            ?? String(format: "0x%08x", code)
    }

    private static func validateTrackCoverage(
        _ range: CMTimeRange,
        assetDuration: CMTime,
        toleranceMilliseconds: Int,
        label: String
    ) throws {
        let startMilliseconds = Int((CMTimeGetSeconds(range.start) * 1_000).rounded())
        let trackEndMilliseconds = Int((CMTimeGetSeconds(range.end) * 1_000).rounded())
        let assetEndMilliseconds = Int((CMTimeGetSeconds(assetDuration) * 1_000).rounded())
        guard abs(startMilliseconds) <= toleranceMilliseconds,
              abs(trackEndMilliseconds - assetEndMilliseconds) <= toleranceMilliseconds else {
            throw VoiceMP4Error.validation(
                "\(label)轨未覆盖完整时间线：\(startMilliseconds)...\(trackEndMilliseconds)ms"
            )
        }
    }

    private static func decodeToEnd(asset: AVAsset, track: AVAssetTrack) throws {
        let reader = try AVAssetReader(asset: asset)
        let settings: [String: Any]
        switch track.mediaType {
        case .audio:
            settings = [
                AVFormatIDKey: kAudioFormatLinearPCM,
                AVLinearPCMBitDepthKey: 16,
                AVLinearPCMIsFloatKey: false,
                AVLinearPCMIsNonInterleaved: false
            ]
        case .video:
            settings = [
                kCVPixelBufferPixelFormatTypeKey as String: Int(kCVPixelFormatType_32BGRA)
            ]
        default:
            throw VoiceMP4Error.validation("不支持的媒体轨解码类型")
        }
        let output = AVAssetReaderTrackOutput(track: track, outputSettings: settings)
        output.alwaysCopiesSampleData = false
        guard reader.canAdd(output) else {
            throw VoiceMP4Error.validation("媒体轨无法进入解码校验")
        }
        reader.add(output)
        guard reader.startReading() else {
            throw reader.error ?? VoiceMP4Error.validation("媒体轨无法开始解码")
        }
        var decodedSamples = 0
        while output.copyNextSampleBuffer() != nil {
            decodedSamples += 1
        }
        guard decodedSamples > 0, reader.status == .completed else {
            throw reader.error ?? VoiceMP4Error.validation("媒体轨未能完整解码")
        }
    }
}

enum SyntheticMediaFactory {
    static func makeTone(
        at url: URL,
        durationSeconds: Double,
        frequency: Double
    ) throws {
        guard durationSeconds > 0, frequency > 0 else {
            throw VoiceMP4Error.invalidArguments("模拟音频参数必须为正数")
        }
        let sampleRate = 48_000.0
        guard let format = AVAudioFormat(
            commonFormat: .pcmFormatFloat32,
            sampleRate: sampleRate,
            channels: 1,
            interleaved: false
        ) else {
            throw VoiceMP4Error.unavailable("无法创建模拟音频格式")
        }
        let settings: [String: Any] = [
            AVFormatIDKey: kAudioFormatMPEG4AAC,
            AVSampleRateKey: sampleRate,
            AVNumberOfChannelsKey: 1,
            AVEncoderBitRateKey: 96_000
        ]
        let file = try AVAudioFile(
            forWriting: url,
            settings: settings,
            commonFormat: .pcmFormatFloat32,
            interleaved: false
        )
        let frames = AVAudioFrameCount((durationSeconds * sampleRate).rounded())
        guard let buffer = AVAudioPCMBuffer(pcmFormat: format, frameCapacity: frames),
              let samples = buffer.floatChannelData?[0] else {
            throw VoiceMP4Error.unavailable("无法分配模拟音频缓冲")
        }
        buffer.frameLength = frames
        for index in 0..<Int(frames) {
            let phase = 2 * Double.pi * frequency * Double(index) / sampleRate
            samples[index] = Float(0.18 * sin(phase))
        }
        try file.write(from: buffer)
    }

    static func verifyToneSequence(at url: URL) async throws {
        let file = try AVAudioFile(forReading: url)
        let format = file.processingFormat
        guard format.commonFormat == .pcmFormatFloat32,
              !format.isInterleaved,
              format.sampleRate > 0,
              file.length > 0 else {
            throw VoiceMP4Error.validation("模拟 MP4 无法以 Float32 PCM 校验")
        }
        let capacity = AVAudioFrameCount(file.length)
        guard let buffer = AVAudioPCMBuffer(pcmFormat: format, frameCapacity: capacity) else {
            throw VoiceMP4Error.unavailable("无法分配模拟 MP4 校验缓冲")
        }
        try file.read(into: buffer)
        guard buffer.frameLength == capacity,
              let samples = buffer.floatChannelData?[0] else {
            throw VoiceMP4Error.validation("模拟 MP4 音频未能完整读取")
        }
        let sampleRate = format.sampleRate
        let firstRange = sampleRange(0.10, 0.60, sampleRate: sampleRate, length: capacity)
        // AVAudioFile exposes the packed media samples and omits the track's empty
        // edit; the second tone therefore starts around raw-media time 0.70s.
        let secondRange = sampleRange(0.80, 1.30, sampleRate: sampleRate, length: capacity)
        let firstRMS = rms(samples, range: firstRange)
        let secondRMS = rms(samples, range: secondRange)
        let firstFrequency = zeroCrossingFrequency(
            samples,
            range: firstRange,
            sampleRate: sampleRate
        )
        let secondFrequency = zeroCrossingFrequency(
            samples,
            range: secondRange,
            sampleRate: sampleRate
        )
        let timelineGapVerified = try await verifyTimelineGap(at: url)
        guard firstRMS > 0.05,
              secondRMS > 0.05,
              (410...470).contains(firstFrequency),
              (620...700).contains(secondFrequency),
              firstFrequency < secondFrequency,
              timelineGapVerified else {
            throw VoiceMP4Error.validation(
                String(
                    format: "模拟 MP4 内容/顺序失败：rms %.4f/%.4f，频率 %.1f/%.1fHz，间隔 %@",
                    firstRMS,
                    secondRMS,
                    firstFrequency,
                    secondFrequency,
                    timelineGapVerified ? "yes" : "no"
                )
            )
        }
    }

    private static func verifyTimelineGap(at url: URL) async throws -> Bool {
        let asset = AVURLAsset(url: url)
        guard let track = try await asset.loadTracks(withMediaType: .audio).first else {
            return false
        }
        let segments = try await track.load(.segments)
        var hasBeforeGap = false
        var hasAfterGap = false
        var emptySegmentCoversGap = false
        for segment in segments {
            let target = segment.timeMapping.target
            let start = CMTimeGetSeconds(target.start)
            let end = CMTimeGetSeconds(target.end)
            if !segment.isEmpty, end <= 0.76 { hasBeforeGap = true }
            if !segment.isEmpty, start >= 0.90 { hasAfterGap = true }
            if segment.isEmpty, start <= 0.78, end >= 0.88 {
                emptySegmentCoversGap = true
            }
        }
        return hasBeforeGap
            && hasAfterGap
            && emptySegmentCoversGap
    }

    private static func sampleRange(
        _ start: Double,
        _ end: Double,
        sampleRate: Double,
        length: AVAudioFrameCount
    ) -> Range<Int> {
        let lower = max(0, min(Int((start * sampleRate).rounded()), Int(length)))
        let upper = max(lower, min(Int((end * sampleRate).rounded()), Int(length)))
        return lower..<upper
    }

    private static func rms(
        _ samples: UnsafeMutablePointer<Float>,
        range: Range<Int>
    ) -> Double {
        guard !range.isEmpty else { return 0 }
        var sum = 0.0
        for index in range {
            let value = Double(samples[index])
            sum += value * value
        }
        return sqrt(sum / Double(range.count))
    }

    private static func zeroCrossingFrequency(
        _ samples: UnsafeMutablePointer<Float>,
        range: Range<Int>,
        sampleRate: Double
    ) -> Double {
        guard range.count > 1 else { return 0 }
        var crossings = 0
        var previous = samples[range.lowerBound]
        for index in range.dropFirst() {
            let current = samples[index]
            if (previous <= 0 && current > 0) || (previous >= 0 && current < 0) {
                crossings += 1
            }
            previous = current
        }
        let seconds = Double(range.count) / sampleRate
        return Double(crossings) / 2 / seconds
    }
}
