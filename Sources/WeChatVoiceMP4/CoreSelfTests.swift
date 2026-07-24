import Foundation

struct CoreSelfTestReport: Codable, Sendable {
    let passed: Bool
    let checks: [String]
}

private enum CoreSelfTestFailure: LocalizedError {
    case failed(String)

    var errorDescription: String? {
        switch self {
        case .failed(let message): "核心自检失败：\(message)"
        }
    }
}

enum CoreSelfTests {
    static func run() async throws -> CoreSelfTestReport {
        var checks: [String] = []
        try testArguments()
        checks.append("arguments")
        try testSafetyGate()
        checks.append("safety_gate_and_hard_bounds")
        try testClickNonce()
        checks.append("single_use_click_nonce")
        try testTaskExecutionLock()
        checks.append("task_and_global_wechat_control_locks")
        try testCacheDiff()
        checks.append("cache_diff")
        try testDurationTolerance()
        checks.append("duration_tolerance")
        try testVisionDurationGrammar()
        checks.append("voice_duration_grammar")
        try testViewportOverlapWithDuplicates()
        checks.append("occurrence_aware_viewport_overlap")
        try testTitleMatching()
        checks.append("chat_title_matching")
        try await testFrozenPlanDigest()
        checks.append("immutable_frozen_plan_digest")
        try await testTaskStore()
        checks.append("task_and_inflight_round_trip")
        try await testDirectAudioPipeline()
        checks.append("direct_pcm_manifest_and_mp4")
        return CoreSelfTestReport(passed: true, checks: checks)
    }

    private static func testArguments() throws {
        let args = try CommandLineArguments(arguments: [
            "tool", "dry-run", "--task", "/tmp/test", "--pages", "3", "--save-screenshot"
        ])
        try require(args.command == "dry-run", "命令解析")
        try require(args.options["task"] == "/tmp/test", "路径参数解析")
        try require(try args.integer("pages") == 3, "整数参数解析")
        try require(args.flags.contains("save-screenshot"), "标志解析")
    }

    private static func testSafetyGate() throws {
        let region = NormalizedRect(x: 0.31, y: 0.12, width: 0.66, height: 0.61)
        let base = SafetySnapshot(
            foregroundBundleIdentifier: "com.tencent.xinWeChat",
            observedChatTitle: "测试群",
            focusedRole: "AXGroup",
            targetRect: NormalizedRect(x: 0.42, y: 0.24, width: 0.12, height: 0.07),
            messageRegion: region,
            modalStateKnown: true,
            hasModalWindow: false,
            audioCaptureReady: true,
            applicationAudioQuiet: true,
            playbackActive: false
        )
        try require(
            SafetyGate.mayClick(snapshot: base, expectedChatTitle: "测试群").allowed,
            "合法消息气泡应通过"
        )
        let textFocused = SafetySnapshot(
            foregroundBundleIdentifier: base.foregroundBundleIdentifier,
            observedChatTitle: base.observedChatTitle,
            focusedRole: "AXTextArea",
            targetRect: base.targetRect,
            messageRegion: base.messageRegion,
            modalStateKnown: true,
            hasModalWindow: false,
            audioCaptureReady: true,
            applicationAudioQuiet: true,
            playbackActive: false
        )
        try require(
            !SafetyGate.mayClick(snapshot: textFocused, expectedChatTitle: "测试群").allowed,
            "文本焦点必须拒绝"
        )
        let unknownModal = SafetySnapshot(
            foregroundBundleIdentifier: base.foregroundBundleIdentifier,
            observedChatTitle: base.observedChatTitle,
            focusedRole: base.focusedRole,
            targetRect: base.targetRect,
            messageRegion: base.messageRegion,
            modalStateKnown: false,
            hasModalWindow: true,
            audioCaptureReady: true,
            applicationAudioQuiet: true,
            playbackActive: false
        )
        try require(
            !SafetyGate.mayClick(snapshot: unknownModal, expectedChatTitle: "测试群").allowed,
            "未知弹窗状态必须拒绝"
        )
        let composer = NormalizedRect(x: 0.42, y: 0.82, width: 0.15, height: 0.06)
        try require(
            !MessageRegionPolicy.containsHardBounds(composer),
            "输入框区域必须在硬边界之外"
        )
    }

    private static func testClickNonce() throws {
        var machine = CaptureStateMachine()
        try machine.transition(to: .bindChat)
        try machine.transition(to: .plan)
        try machine.transition(to: .seekFirst)
        try machine.transition(to: .locateNext)
        try machine.transition(to: .armClick)
        try machine.arm(targetID: "voice-1")
        try machine.transition(to: .clickOnce)
        try machine.consumeClick()
        do {
            try machine.consumeClick()
            throw CoreSelfTestFailure.failed("点击许可可被重复使用")
        } catch is VoiceMP4Error {
            return
        }
    }

    private static func testCacheDiff() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let a = URL(fileURLWithPath: "/tmp/a")
        let b = URL(fileURLWithPath: "/tmp/b")
        let old = CacheSnapshot(
            capturedAt: now,
            filesByPath: [a.path: FileFingerprint(url: a, size: 10, modifiedAt: now)]
        )
        let newer = CacheSnapshot(
            capturedAt: now.addingTimeInterval(1),
            filesByPath: [
                a.path: FileFingerprint(url: a, size: 20, modifiedAt: now.addingTimeInterval(1)),
                b.path: FileFingerprint(url: b, size: 5, modifiedAt: now.addingTimeInterval(1))
            ]
        )
        let changes = newer.changes(comparedTo: old)
        try require(changes.count == 2, "缓存新增/修改数量")
        try require(changes.contains { $0.kind == .created && $0.fingerprint.url == b }, "缓存新增")
        try require(changes.contains { $0.kind == .modified && $0.fingerprint.url == a }, "缓存修改")
    }

    private static func testTaskExecutionLock() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("wechat-voice-lock-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let first = try TaskExecutionLock(taskRoot: root, operation: "first")
        do {
            _ = try TaskExecutionLock(taskRoot: root, operation: "second")
            throw CoreSelfTestFailure.failed("同一任务可被重复加锁")
        } catch is VoiceMP4Error {
            first.release()
        }
        let afterRelease = try TaskExecutionLock(taskRoot: root, operation: "after-release")
        afterRelease.release()

        let global = try TaskExecutionLock.acquireWeChatControl(operation: "first-global")
        do {
            _ = try TaskExecutionLock.acquireWeChatControl(operation: "second-global")
            throw CoreSelfTestFailure.failed("不同任务仍可同时控制微信 UI")
        } catch is VoiceMP4Error {
            global.release()
        }
        let globalAfterRelease = try TaskExecutionLock.acquireWeChatControl(
            operation: "after-global-release"
        )
        globalAfterRelease.release()
    }

    private static func testDurationTolerance() throws {
        try require(
            MediaInspector.durationMatches(
                expectedMilliseconds: 50_000,
                actualMilliseconds: 50_500
            ),
            "合理时长误差"
        )
        try require(
            !MediaInspector.durationMatches(
                expectedMilliseconds: 50_000,
                actualMilliseconds: 47_000
            ),
            "异常时长必须拒绝"
        )
        try require(
            VoiceSegmentDurationPolicy.matches(
                expectedMilliseconds: 50_000,
                actualMilliseconds: 49_050
            ),
            "整秒显示允许小量下取整误差"
        )
        try require(
            !VoiceSegmentDurationPolicy.matches(
                expectedMilliseconds: 50_000,
                actualMilliseconds: 48_900
            ),
            "缺失超过一秒的长语音必须拒绝"
        )
        try require(
            !VoiceSegmentDurationPolicy.matches(
                expectedMilliseconds: 1_000,
                actualMilliseconds: 300
            ),
            "短提示音不能冒充一秒语音"
        )
    }

    private static func testVisionDurationGrammar() throws {
        try require(
            VisionVoiceCandidateScanner.parseDurationMilliseconds("50″") == 50_000,
            "微信引号时长应被识别"
        )
        try require(
            VisionVoiceCandidateScanner.parseDurationMilliseconds("50秒") == nil,
            "普通文本中的秒数不能被识别成语音"
        )
        try require(
            VisionVoiceCandidateScanner.parseDurationMilliseconds("61″") == nil,
            "超出微信单条语音时长范围必须拒绝"
        )
    }

    private static func testViewportOverlapWithDuplicates() throws {
        let previous = [
            candidate("X", occurrence: "id-x", duration: 10_000, y: 0.10),
            candidate("A", occurrence: "id-a1", duration: 20_000, y: 0.20),
            candidate("A", occurrence: "id-a2", duration: 20_000, y: 0.30),
            candidate("B", occurrence: "id-b", duration: 30_000, y: 0.40)
        ]
        let current = [
            candidate("A", occurrence: "id-a2", duration: 20_000, y: 0.10),
            candidate("B", occurrence: "id-b", duration: 30_000, y: 0.20),
            candidate("C", occurrence: "id-c", duration: 40_000, y: 0.30)
        ]
        let overlap = try ViewportOverlap.uniqueCount(previous: previous, current: current)
        try require(overlap == 2, "重复时长/指纹页间重叠")
        let merged = previous + current.dropFirst(overlap)
        try require(merged.map(\.fingerprint) == ["X", "A", "A", "B", "C"], "重复出现不能被去重")
        let ambiguousPrevious = [
            candidate("X", occurrence: "id-x", duration: 10_000, y: 0.10),
            candidate("A", occurrence: "generic-id", duration: 20_000, y: 0.20),
            candidate("A", occurrence: "generic-id", duration: 20_000, y: 0.30)
        ]
        let ambiguousCurrent = [
            candidate("A", occurrence: "generic-id", duration: 20_000, y: 0.10),
            candidate("A", occurrence: "generic-id", duration: 20_000, y: 0.20),
            candidate("C", occurrence: "id-c", duration: 40_000, y: 0.30)
        ]
        var rejectedGenericID = false
        do {
            _ = try ViewportOverlap.uniqueCount(
                previous: ambiguousPrevious,
                current: ambiguousCurrent
            )
        } catch is VoiceMP4Error {
            rejectedGenericID = true
        }
        try require(rejectedGenericID, "通用重复 AXIdentifier 未被拒绝")

        let reusedPrevious = [
            candidate("X", occurrence: "id-x", duration: 10_000, y: 0.10),
            candidate("OLD", occurrence: "reused-cell", duration: 50_000, y: 0.20)
        ]
        let reusedCurrent = [
            candidate("NEW", occurrence: "reused-cell", duration: 10_000, y: 0.10),
            candidate("C", occurrence: "id-c", duration: 40_000, y: 0.20)
        ]
        var rejectedReusedCell = false
        do {
            _ = try ViewportOverlap.uniqueCount(
                previous: reusedPrevious,
                current: reusedCurrent
            )
        } catch is VoiceMP4Error {
            rejectedReusedCell = true
        }
        try require(rejectedReusedCell, "同 ID 不同消息的虚拟 cell 复用未被拒绝")
    }

    private static func testTitleMatching() throws {
        try require(
            ChatTitleMatcher.matches(observed: "测试群（12）", expected: "测试群(12)"),
            "标题括号归一化"
        )
        try require(
            !ChatTitleMatcher.matches(observed: "测试群A", expected: "测试群B"),
            "不同群名必须拒绝"
        )
    }

    private static func testFrozenPlanDigest() async throws {
        var task = CaptureTask(
            id: "task-1",
            chatTitle: "测试群",
            startTime: Date(timeIntervalSince1970: 100),
            endTime: Date(timeIntervalSince1970: 200),
            expectedCount: 1,
            outputDirectory: "output"
        )
        task.messageRegion = NormalizedRect(x: 0.31, y: 0.12, width: 0.66, height: 0.61)
        task.boundWindow = BoundWindowIdentity(
            bundleIdentifier: "com.tencent.xinWeChat",
            processIdentifier: 123,
            windowID: 456,
            frame: WindowFrame(x: 10, y: 20, width: 900, height: 700),
            pointPixelScale: 2
        )
        task.scannerVersion = "scanner-test"
        task.targets = [VoiceTarget(
            id: "voice-1",
            sequence: 1,
            viewportIndex: 0,
            detectionConfidence: 0.98,
            expectedDurationMilliseconds: 50_000,
            bubbleRect: NormalizedRect(x: 0.42, y: 0.24, width: 0.12, height: 0.07),
            contextFingerprint: "abcdef1234567890",
            axRolePath: ["AXGroup", "AXScrollArea", "AXWindow"],
            axSemanticHints: ["AXDescription=语音消息"],
            axSemanticSignature: "ax-signature",
            axSemanticDigest: "ax-semantic-digest",
            axVoiceSemanticConfirmed: true,
            status: .located
        )]
        task.viewportPlans = [ViewportPlan(
            viewportIndex: 0,
            overlapWithPrevious: 0,
            candidates: [ViewportCandidateAnchor(
                durationMilliseconds: 50_000,
                rect: NormalizedRect(x: 0.42, y: 0.24, width: 0.12, height: 0.07),
                fingerprint: "abcdef1234567890",
                axSemanticDigest: "ax-semantic-digest"
            )]
        )]
        task.diagnosticScreenshots = [DiagnosticScreenshotRecord(
            viewportIndex: 0,
            relativePath: "diagnostics/dry-run-page-01.png",
            sha256: "screenshot-sha"
        )]
        let original = try await TaskStore.shared.digest(task.frozenPlan())
        task.targets[0].status = .validated
        let afterRuntimeStatus = try await TaskStore.shared.digest(task.frozenPlan())
        try require(original == afterRuntimeStatus, "运行状态不应破坏批准摘要")
        task.diagnosticScreenshots[0].sha256 = "changed-screenshot-sha"
        let afterScreenshotChange = try await TaskStore.shared.digest(task.frozenPlan())
        try require(original != afterScreenshotChange, "红框截图变化必须破坏批准摘要")
        task.diagnosticScreenshots[0].sha256 = "screenshot-sha"
        task.targets[0].axVoiceSemanticConfirmed = false
        do {
            _ = try task.frozenPlan()
            throw CoreSelfTestFailure.failed("缺少 AX 语音语义仍可冻结")
        } catch is VoiceMP4Error {
            task.targets[0].axVoiceSemanticConfirmed = true
        }
        var malformed = task
        malformed.viewportPlans[0].overlapWithPrevious = -1
        var rejectedMalformedPlan = false
        do {
            _ = try malformed.frozenPlan()
        } catch is VoiceMP4Error {
            rejectedMalformedPlan = true
        }
        try require(rejectedMalformedPlan, "损坏的负 overlap 计划未安全拒绝")
        task.chatTitle = "另一个群"
        let changedTitle = try await TaskStore.shared.digest(task.frozenPlan())
        try require(original != changedTitle, "群名变化必须破坏批准摘要")
    }

    private static func testTaskStore() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("wechat-voice-test-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let task = CaptureTask(
            id: "round-trip-task",
            chatTitle: "测试群",
            startTime: Date(timeIntervalSince1970: 100),
            endTime: Date(timeIntervalSince1970: 200),
            expectedCount: 2,
            outputDirectory: "output"
        )
        _ = try await TaskStore.shared.create(task: task, at: root)
        let loaded = try await TaskStore.shared.loadTask(from: root)
        try require(loaded.id == task.id, "任务 ID 持久化")
        try require(loaded.chatTitle == task.chatTitle, "任务群名持久化")
        try require(abs(loaded.startTime.timeIntervalSince(task.startTime)) < 0.001, "开始时间持久化")
        try require(abs(loaded.endTime.timeIntervalSince(task.endTime)) < 0.001, "结束时间持久化")

        var runtime = try await TaskStore.shared.loadRuntime(from: root)
        runtime.updatedAt = Date(timeIntervalSince1970: 300)
        runtime.inFlight = InFlightRecord(
            targetID: "voice-1",
            sequence: 1,
            stage: .clicked,
            initiatedAt: Date(timeIntervalSince1970: 250)
        )
        try await TaskStore.shared.saveRuntime(runtime, at: root)
        let reloadedRuntime = try await TaskStore.shared.loadRuntime(from: root)
        try require(reloadedRuntime == runtime, "点击中断状态必须原子持久化")
    }

    private static func testDirectAudioPipeline() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("wechat-direct-audio-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }

        let sampleRate = 24_000
        var reports: [DirectAudioConversionReport] = []
        for (index, duration) in [1.20, 1.40].enumerated() {
            let pcmURL = root.appendingPathComponent("\(index + 1).pcm")
            let m4aURL = root.appendingPathComponent("\(index + 1).m4a")
            var pcm = Data()
            let frameCount = Int(Double(sampleRate) * duration)
            pcm.reserveCapacity(frameCount * 2)
            for frame in 0..<frameCount {
                let phase = 2 * Double.pi * Double(440 + index * 220)
                    * Double(frame) / Double(sampleRate)
                let value = Int16((0.15 * sin(phase) * Double(Int16.max)).rounded())
                let bits = UInt16(bitPattern: value)
                pcm.append(UInt8(bits & 0xff))
                pcm.append(UInt8((bits >> 8) & 0xff))
            }
            try pcm.write(to: pcmURL, options: .atomic)
            reports.append(try await DirectAudioPipeline.convertPCMToM4A(
                inputURL: pcmURL,
                outputURL: m4aURL,
                sampleRate: sampleRate,
                expectedDurationMilliseconds: Int((duration * 1_000).rounded())
            ))
        }

        let mismatchedOutput = root.appendingPathComponent("duration-mismatch.m4a")
        var rejectedMismatchedPCM = false
        do {
            _ = try await DirectAudioPipeline.convertPCMToM4A(
                inputURL: root.appendingPathComponent("1.pcm"),
                outputURL: mismatchedOutput,
                sampleRate: sampleRate,
                expectedDurationMilliseconds: 3_000
            )
        } catch is VoiceMP4Error {
            rejectedMismatchedPCM = true
        }
        try require(rejectedMismatchedPCM, "数据库精确时长不符的 PCM 未被拒绝")
        try require(
            !FileManager.default.fileExists(atPath: mismatchedOutput.path),
            "失败的 PCM 转换留下半成品"
        )

        let manifest = DirectAudioManifest(
            schemaVersion: DirectAudioManifest.currentSchemaVersion,
            title: "直连自检",
            expectedCount: 2,
            items: reports.enumerated().map { index, report in
                DirectAudioItem(
                    sequence: index + 1,
                    serverID: "900000000000\(index + 1)",
                    sourcePath: URL(fileURLWithPath: report.output).lastPathComponent,
                    expectedDurationMilliseconds: report.durationMilliseconds,
                    sha256: report.sha256
                )
            }
        )
        _ = try manifest.validated()
        try require(
            DirectAudioDurationPolicy.expectedMilliseconds.lowerBound == 100
                && DirectAudioDurationPolicy.expectedMilliseconds.upperBound == 61_000,
            "直连数据库语音时长安全边界"
        )
        var sixtySecondMetadata = manifest
        sixtySecondMetadata.items[0].expectedDurationMilliseconds = 60_060
        _ = try sixtySecondMetadata.validated()
        var overlongMetadata = manifest
        overlongMetadata.items[0].expectedDurationMilliseconds = 61_001
        var rejectedOverlongMetadata = false
        do {
            _ = try overlongMetadata.validated()
        } catch is VoiceMP4Error {
            rejectedOverlongMetadata = true
        }
        try require(
            rejectedOverlongMetadata,
            "超过 61000ms 的直连数据库语音时长未被拒绝"
        )
        var duplicate = manifest
        duplicate.items[1].serverID = duplicate.items[0].serverID
        var rejectedDuplicate = false
        do {
            _ = try duplicate.validated()
        } catch is VoiceMP4Error {
            rejectedDuplicate = true
        }
        try require(rejectedDuplicate, "重复 serverID 未被拒绝")

        var escaped = manifest
        escaped.items[0].sourcePath = "../1.m4a"
        var rejectedEscapedPath = false
        do {
            _ = try escaped.validated()
        } catch is VoiceMP4Error {
            rejectedEscapedPath = true
        }
        try require(rejectedEscapedPath, "越界音频路径未被拒绝")

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let manifestURL = root.appendingPathComponent("direct-manifest.json")
        try encoder.encode(manifest).write(to: manifestURL, options: .atomic)
        let outputURL = root.appendingPathComponent("direct.mp4")
        let assembled = try await DirectAudioPipeline.assemble(
            manifestURL: manifestURL,
            outputURL: outputURL,
            gapMilliseconds: 100
        )
        try require(assembled.itemCount == 2, "直连 MP4 条数")
        try require(!assembled.sha256.isEmpty, "直连 MP4 SHA-256")
    }

    private static func candidate(
        _ fingerprint: String,
        occurrence: String? = nil,
        duration: Int,
        y: Double
    ) -> ScannedVoiceCandidate {
        ScannedVoiceCandidate(
            sequenceInViewport: 1,
            durationMilliseconds: duration,
            senderLabel: nil,
            timestampLabel: nil,
            rect: NormalizedRect(x: 0.42, y: y, width: 0.12, height: 0.06),
            confidence: 0.99,
            fingerprint: fingerprint,
            axSemanticDigest: "semantic-\(fingerprint)",
            axOccurrenceIdentifier: occurrence
        )
    }

    private static func require(
        _ condition: @autoclosure () throws -> Bool,
        _ message: String
    ) throws {
        guard try condition() else { throw CoreSelfTestFailure.failed(message) }
    }
}
