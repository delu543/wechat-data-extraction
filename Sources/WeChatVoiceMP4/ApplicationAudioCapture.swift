import AudioToolbox
@preconcurrency import AVFoundation
import CoreGraphics
import CoreMedia
import Foundation
import ScreenCaptureKit

private enum AudioWriterFailure: LocalizedError {
    case unsupportedSettings
    case cannotAddInput
    case startFailed(Error?)
    case backPressure
    case appendFailed(Error?)
    case noSamples
    case noAudibleSamples
    case finishFailed(Error?)

    var errorDescription: String? {
        switch self {
        case .unsupportedSettings: "系统不支持 AAC 录音设置"
        case .cannotAddInput: "无法创建 AAC 音频写入通道"
        case .startFailed(let error): "音频写入启动失败：\(error?.localizedDescription ?? "未知错误")"
        case .backPressure: "音频写入器来不及接收数据；本条必须重录"
        case .appendFailed(let error): "音频样本写入失败：\(error?.localizedDescription ?? "未知错误")"
        case .noSamples: "没有收到微信应用音频样本"
        case .noAudibleSamples: "收到的样本中没有检测到可听声音"
        case .finishFailed(let error): "音频文件收尾失败：\(error?.localizedDescription ?? "未知错误")"
        }
    }
}

private struct AudibleRange: Sendable {
    let startSeconds: Double
    let endSeconds: Double
}

private final class AudioSampleBufferWriter: @unchecked Sendable {
    private let writer: AVAssetWriter
    private let input: AVAssetWriterInput
    private var sessionStarted = false
    private var firstPresentationTime: CMTime?
    private var firstAudibleTime: CMTime?
    private var lastAudibleTime: CMTime?
    private(set) var latestAmplitude: Float = 0
    private(set) var receivedSamples = 0
    private(set) var lastAudibleWallTime: Date?
    private(set) var terminalError: Error?

    init(outputURL: URL) throws {
        let settings: [String: Any] = [
            AVFormatIDKey: kAudioFormatMPEG4AAC,
            AVSampleRateKey: 48_000,
            AVNumberOfChannelsKey: 2,
            AVEncoderBitRateKey: 128_000
        ]
        writer = try AVAssetWriter(outputURL: outputURL, fileType: .m4a)
        guard writer.canApply(outputSettings: settings, forMediaType: .audio) else {
            throw AudioWriterFailure.unsupportedSettings
        }
        input = AVAssetWriterInput(mediaType: .audio, outputSettings: settings)
        input.expectsMediaDataInRealTime = true
        guard writer.canAdd(input) else { throw AudioWriterFailure.cannotAddInput }
        writer.add(input)
        guard writer.startWriting() else {
            throw AudioWriterFailure.startFailed(writer.error)
        }
    }

    func append(_ sampleBuffer: CMSampleBuffer) {
        guard terminalError == nil,
              CMSampleBufferIsValid(sampleBuffer),
              CMSampleBufferDataIsReady(sampleBuffer) else { return }
        let presentationTime = CMSampleBufferGetPresentationTimeStamp(sampleBuffer)
        if !sessionStarted {
            writer.startSession(atSourceTime: presentationTime)
            firstPresentationTime = presentationTime
            sessionStarted = true
        }

        receivedSamples += 1
        latestAmplitude = Self.maximumAmplitude(in: sampleBuffer) ?? 0
        if latestAmplitude >= 0.0015 {
            if firstAudibleTime == nil { firstAudibleTime = presentationTime }
            lastAudibleTime = presentationTime
            lastAudibleWallTime = Date()
        }

        guard input.isReadyForMoreMediaData else {
            terminalError = AudioWriterFailure.backPressure
            return
        }
        guard input.append(sampleBuffer) else {
            terminalError = AudioWriterFailure.appendFailed(writer.error)
            return
        }
    }

    var hasSettledQuiet: Bool {
        guard receivedSamples >= 3, latestAmplitude < 0.0015 else { return false }
        guard let lastAudibleWallTime else { return true }
        return Date().timeIntervalSince(lastAudibleWallTime) >= 0.3
    }

    var hasAudibleSamples: Bool { firstAudibleTime != nil }

    func finish() async throws -> AudibleRange {
        guard sessionStarted else {
            writer.cancelWriting()
            throw AudioWriterFailure.noSamples
        }
        input.markAsFinished()
        await writer.finishWriting()
        guard writer.status == .completed else {
            throw AudioWriterFailure.finishFailed(writer.error)
        }
        if let terminalError { throw terminalError }
        guard let firstPresentationTime, let firstAudibleTime, let lastAudibleTime else {
            throw AudioWriterFailure.noAudibleSamples
        }
        // The amplitude detector is only a boundary hint. Preserve generous
        // pre/post roll so quiet consonants are not clipped by the threshold.
        let start = max(0, CMTimeGetSeconds(firstAudibleTime - firstPresentationTime) - 0.30)
        let end = max(start + 0.05,
                      CMTimeGetSeconds(lastAudibleTime - firstPresentationTime) + 0.45)
        return AudibleRange(startSeconds: start, endSeconds: end)
    }

    private static func maximumAmplitude(in sampleBuffer: CMSampleBuffer) -> Float? {
        guard let format = CMSampleBufferGetFormatDescription(sampleBuffer),
              let pointer = CMAudioFormatDescriptionGetStreamBasicDescription(format) else {
            return nil
        }
        let description = pointer.pointee
        guard description.mFormatID == kAudioFormatLinearPCM,
              description.mBitsPerChannel == 32,
              description.mFormatFlags & kAudioFormatFlagIsFloat != 0 else { return nil }

        var requiredSize = 0
        var status = CMSampleBufferGetAudioBufferListWithRetainedBlockBuffer(
            sampleBuffer,
            bufferListSizeNeededOut: &requiredSize,
            bufferListOut: nil,
            bufferListSize: 0,
            blockBufferAllocator: nil,
            blockBufferMemoryAllocator: nil,
            flags: UInt32(kCMSampleBufferFlag_AudioBufferList_Assure16ByteAlignment),
            blockBufferOut: nil
        )
        guard status == noErr, requiredSize > 0 else { return nil }
        let storage = UnsafeMutableRawPointer.allocate(
            byteCount: requiredSize,
            alignment: MemoryLayout<AudioBufferList>.alignment
        )
        defer { storage.deallocate() }
        let list = storage.bindMemory(to: AudioBufferList.self, capacity: 1)
        var retainedBlock: CMBlockBuffer?
        status = CMSampleBufferGetAudioBufferListWithRetainedBlockBuffer(
            sampleBuffer,
            bufferListSizeNeededOut: nil,
            bufferListOut: list,
            bufferListSize: requiredSize,
            blockBufferAllocator: nil,
            blockBufferMemoryAllocator: nil,
            flags: UInt32(kCMSampleBufferFlag_AudioBufferList_Assure16ByteAlignment),
            blockBufferOut: &retainedBlock
        )
        guard status == noErr else { return nil }

        var maximum: Float = 0
        for buffer in UnsafeMutableAudioBufferListPointer(list) {
            guard let data = buffer.mData else { continue }
            let count = Int(buffer.mDataByteSize) / MemoryLayout<Float>.size
            let values = data.bindMemory(to: Float.self, capacity: count)
            for index in 0..<count {
                maximum = max(maximum, abs(values[index]))
            }
        }
        _ = retainedBlock
        return maximum
    }
}

final class WeChatApplicationAudioCapturer: NSObject,
    ApplicationAudioCapturing,
    SCStreamOutput,
    SCStreamDelegate,
    @unchecked Sendable
{
    private let binding: BoundWindowIdentity
    private let sampleQueue = DispatchQueue(label: "local.wechat-voice.audio-samples")
    private let lifecycleLock = NSLock()
    private var stream: SCStream?
    private var started = false
    private var captureStartedAt: Date?
    private var rawOutputURL: URL?
    private var finalOutputURL: URL?
    private var sampleWriter: AudioSampleBufferWriter?
    private var streamError: Error?

    init(binding: BoundWindowIdentity) {
        self.binding = binding
        super.init()
    }

    var isReady: Bool {
        get async {
            lifecycleLock.withLock { started && stream != nil }
        }
    }

    var isQuiet: Bool {
        get async {
            // Zero samples is never "quiet": it may mean ScreenCaptureKit is
            // not delivering audio yet, in which case clicking could lose the
            // beginning of the message.
            sampleQueue.sync { sampleWriter?.hasSettledQuiet == true }
        }
    }

    var hasDetectedAudibleAudio: Bool {
        get async { sampleQueue.sync { sampleWriter?.hasAudibleSamples == true } }
    }

    func beginSegment(outputURL: URL) async throws {
        let alreadyActive = lifecycleLock.withLock { self.stream != nil }
        guard !alreadyActive else {
            throw VoiceMP4Error.safetyViolation("已有音频片段正在采集")
        }
        guard CGPreflightScreenCaptureAccess() else {
            throw VoiceMP4Error.unavailable("缺少屏幕与系统音频录制权限")
        }
        try MacRuntimeSafetyGuard.validate(binding: binding)
        guard !FileManager.default.fileExists(atPath: outputURL.path) else {
            throw VoiceMP4Error.validation("片段输出已存在：\(outputURL.lastPathComponent)")
        }

        let rawURL = outputURL.deletingPathExtension()
            .appendingPathExtension("raw.m4a")
        if FileManager.default.fileExists(atPath: rawURL.path) {
            try FileManager.default.removeItem(at: rawURL)
        }

        let content = try await SCShareableContent.excludingDesktopWindows(
            true,
            onScreenWindowsOnly: false
        )
        let selection = try selectCaptureTarget(from: content)
        let application = selection.application
        let display = selection.display

        let writer = try AudioSampleBufferWriter(outputURL: rawURL)
        let filter = SCContentFilter(
            display: display,
            including: [application],
            exceptingWindows: []
        )
        let configuration = SCStreamConfiguration()
        configuration.capturesAudio = true
        configuration.sampleRate = 48_000
        configuration.channelCount = 2
        configuration.excludesCurrentProcessAudio = true
        configuration.captureMicrophone = false
        let captureStream = SCStream(filter: filter, configuration: configuration, delegate: self)
        try captureStream.addStreamOutput(self, type: .audio, sampleHandlerQueue: sampleQueue)

        sampleQueue.sync {
            self.sampleWriter = writer
            self.rawOutputURL = rawURL
            self.finalOutputURL = outputURL
            self.streamError = nil
        }
        lifecycleLock.withLock {
            self.stream = captureStream
            captureStartedAt = Date()
        }
        do {
            try await captureStream.startCapture()
            lifecycleLock.withLock { started = true }
        } catch {
            lifecycleLock.withLock {
                self.stream = nil
                started = false
                captureStartedAt = nil
            }
            sampleQueue.sync { self.sampleWriter = nil }
            throw VoiceMP4Error.unavailable("微信应用音频采集启动失败：\(error.localizedDescription)")
        }
    }

    func endSegment() async throws -> URL {
        let activeStream = lifecycleLock.withLock { self.stream }
        guard let activeStream else {
            throw VoiceMP4Error.safetyViolation("当前没有正在采集的音频片段")
        }
        do {
            try await activeStream.stopCapture()
        } catch {
            await cancelSegment()
            throw VoiceMP4Error.unavailable("停止应用音频采集失败：\(error.localizedDescription)")
        }
        lifecycleLock.withLock {
            stream = nil
            started = false
            captureStartedAt = nil
        }

        let state = sampleQueue.sync {
            (sampleWriter, rawOutputURL, finalOutputURL, streamError)
        }
        guard let writer = state.0, let rawURL = state.1, let outputURL = state.2 else {
            throw VoiceMP4Error.unavailable("音频采集内部状态不完整")
        }
        if let streamError = state.3 { throw streamError }
        let audibleRange = try await writer.finish()
        try await trim(rawURL: rawURL, to: outputURL, audibleRange: audibleRange)
        try? FileManager.default.removeItem(at: rawURL)
        sampleQueue.sync {
            sampleWriter = nil
            rawOutputURL = nil
            finalOutputURL = nil
            streamError = nil
        }
        return outputURL
    }

    func cancelSegment() async {
        let activeStream = lifecycleLock.withLock { () -> SCStream? in
            let activeStream = self.stream
            self.stream = nil
            started = false
            captureStartedAt = nil
            return activeStream
        }
        try? await activeStream?.stopCapture()
        let raw = sampleQueue.sync { () -> URL? in
            let raw = rawOutputURL
            sampleWriter = nil
            rawOutputURL = nil
            finalOutputURL = nil
            streamError = nil
            return raw
        }
        if let raw { try? FileManager.default.removeItem(at: raw) }
    }

    func stream(
        _ stream: SCStream,
        didOutputSampleBuffer sampleBuffer: CMSampleBuffer,
        of outputType: SCStreamOutputType
    ) {
        guard outputType == .audio else { return }
        sampleWriter?.append(sampleBuffer)
    }

    func stream(_ stream: SCStream, didStopWithError error: Error) {
        sampleQueue.async { [weak self] in self?.streamError = error }
    }

    private func trim(
        rawURL: URL,
        to outputURL: URL,
        audibleRange: AudibleRange
    ) async throws {
        let asset = AVURLAsset(url: rawURL)
        let duration = try await asset.load(.duration)
        let durationSeconds = CMTimeGetSeconds(duration)
        let start = min(max(0, audibleRange.startSeconds), durationSeconds)
        let end = min(max(start + 0.05, audibleRange.endSeconds), durationSeconds)
        guard end > start else { throw AudioWriterFailure.noAudibleSamples }
        guard let session = AVAssetExportSession(asset: asset, presetName: AVAssetExportPresetAppleM4A) else {
            throw VoiceMP4Error.unavailable("无法创建音频裁切会话")
        }
        session.timeRange = CMTimeRange(
            start: CMTime(seconds: start, preferredTimescale: 48_000),
            end: CMTime(seconds: end, preferredTimescale: 48_000)
        )
        try await session.export(to: outputURL, as: .m4a)
    }

    private func area(_ rect: CGRect) -> CGFloat { rect.width * rect.height }

    private func selectCaptureTarget(
        from content: SCShareableContent
    ) throws -> (application: SCRunningApplication, display: SCDisplay) {
        for application in content.applications {
            guard application.bundleIdentifier == binding.bundleIdentifier,
                  application.processID == binding.processIdentifier else {
                continue
            }
            for window in content.windows {
                guard window.windowID == binding.windowID,
                      window.owningApplication?.processID == application.processID,
                      window.isOnScreen,
                      framesMatch(window.frame, binding.frame.cgRect) else { continue }
                let center = CGPoint(x: window.frame.midX, y: window.frame.midY)
                for display in content.displays where display.frame.contains(center) {
                    return (application, display)
                }
                throw VoiceMP4Error.unavailable("音频采集器找不到绑定窗口所在显示器")
            }
            throw VoiceMP4Error.safetyViolation("音频采集窗口与已批准窗口不一致")
        }
        throw VoiceMP4Error.safetyViolation("音频采集器找不到已批准的微信进程")
    }

    private func framesMatch(_ lhs: CGRect, _ rhs: CGRect) -> Bool {
        abs(lhs.origin.x - rhs.origin.x) <= 0.75
            && abs(lhs.origin.y - rhs.origin.y) <= 0.75
            && abs(lhs.width - rhs.width) <= 0.75
            && abs(lhs.height - rhs.height) <= 0.75
    }
}
