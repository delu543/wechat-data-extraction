import ApplicationServices
import CoreGraphics
import Foundation

enum CaptureCommands {
    private static let defaultMessageRegion = NormalizedRect(
        x: 0.31,
        y: 0.12,
        width: 0.66,
        height: 0.61
    )
    private static let scrollLines: Int32 = 4

    static func dryRun(taskRoot: URL, args: CommandLineArguments) async throws {
        let weChatControlLock = try TaskExecutionLock.acquireWeChatControl(operation: "dry-run")
        defer { weChatControlLock.release() }
        let operationLock = try TaskExecutionLock(taskRoot: taskRoot, operation: "dry-run")
        defer { operationLock.release() }
        var task = try await TaskStore.shared.loadTask(from: taskRoot)
        var runtime = try await TaskStore.shared.loadRuntime(from: taskRoot)
        guard runtime.taskID == task.id,
              runtime.startedAt == nil,
              runtime.completedTargetIDs.isEmpty,
              runtime.failedTargetIDs.isEmpty,
              runtime.segments.isEmpty,
              runtime.inFlight == nil,
              runtime.finalMP4RelativePath == nil else {
            throw VoiceMP4Error.safetyViolation(
                "该任务已经进入过采集阶段；禁止用新干跑覆盖旧运行状态，请创建新任务"
            )
        }
        guard let expected = task.expectedCount, expected > 0 else {
            throw VoiceMP4Error.safetyViolation("干跑前必须用 --expected 指定准确语音条数")
        }
        let region = try parseRegion(args.options["message-region"]) ?? defaultMessageRegion
        guard MessageRegionPolicy.validate(region) else {
            throw VoiceMP4Error.safetyViolation("消息区域只能是系统硬边界内的保守子区域")
        }
        let pages = try args.integer("pages") ?? 1
        guard (1...30).contains(pages) else {
            throw VoiceMP4Error.invalidArguments("--pages 必须介于 1...30")
        }
        if pages > 1, !args.flags.contains("allow-scroll") {
            throw VoiceMP4Error.safetyViolation("多页干跑必须显式传入 --allow-scroll")
        }

        let provider = MacWeChatWindowProvider()
        let scanner = VisionVoiceCandidateScanner()
        let input = MacRestrictedInputDriver()
        var targets: [VoiceTarget] = []
        var viewportPlans: [ViewportPlan] = []
        var screenshotRecords: [DiagnosticScreenshotRecord] = []
        var previousPage: [ScannedVoiceCandidate] = []
        var firstPage: [ScannedVoiceCandidate] = []
        var seenNewOccurrenceIDs = Set<String>()
        var binding: BoundWindowIdentity?
        var restoreRemaining = 0
        let screenshotRunDirectory: URL?
        if args.flags.contains("save-screenshot") {
            let runName = "run-\(outputTimestamp())-\(UUID().uuidString.lowercased())"
            let directory = TaskPaths(root: taskRoot).screenshots
                .appendingPathComponent(runName, isDirectory: true)
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: false
            )
            screenshotRunDirectory = directory
        } else {
            screenshotRunDirectory = nil
        }

        do {
            for page in 0..<pages {
                let snapshot = try await provider.currentWeChatWindow()
                let currentBinding = binding ?? BoundWindowIdentity(snapshot: snapshot)
                try assertBound(snapshot, to: task, binding: currentBinding, region: region)
                binding = currentBinding

                let rawCandidates = try await scanner.scan(snapshot, within: region)
                    .filter { $0.confidence >= CandidateIdentityPolicy.minimumConfidence }
                let observations = rawCandidates.map {
                    AXVoiceCandidateResolver.resolve(
                        snapshot: snapshot,
                        candidate: $0,
                        region: region
                    )
                }
                let scanned = observations.map(\.candidate)
                guard !scanned.isEmpty else {
                    throw VoiceMP4Error.validation("第 \(page + 1) 屏没有识别到带引号时长的语音候选")
                }
                if pages > 1 {
                    try validateOccurrenceIdentities(scanned, page: page)
                }
                if page == 0 { firstPage = scanned }
                let overlap = page == 0 ? 0 : try ViewportOverlap.uniqueCount(
                    previous: previousPage,
                    current: scanned
                )
                if page > 0 {
                    guard overlap > 0 else {
                        throw VoiceMP4Error.safetyViolation("页间没有可验证重叠，无法证明没有遗漏")
                    }
                    guard overlap < scanned.count else {
                        throw VoiceMP4Error.safetyViolation("滚动没有露出新的语音候选")
                    }
                }
                if pages > 1 {
                    let newIDs = scanned.dropFirst(overlap).compactMap(\.axOccurrenceIdentifier)
                    guard Set(newIDs).isDisjoint(with: seenNewOccurrenceIDs) else {
                        throw VoiceMP4Error.safetyViolation(
                            "第 \(page + 1) 屏在连续重叠前缀之外复用了旧 AXIdentifier"
                        )
                    }
                    seenNewOccurrenceIDs.formUnion(newIDs)
                }
                viewportPlans.append(ViewportPlan(
                    viewportIndex: page,
                    overlapWithPrevious: overlap,
                    candidates: scanned.map {
                        ViewportCandidateAnchor(
                            durationMilliseconds: $0.durationMilliseconds,
                            rect: $0.rect,
                            fingerprint: $0.fingerprint,
                            axSemanticDigest: $0.axSemanticDigest,
                            axOccurrenceIdentifier: $0.axOccurrenceIdentifier
                        )
                    }
                ))
                let newObservations = observations.dropFirst(overlap)

                if let screenshotRunDirectory {
                    let url = screenshotRunDirectory
                        .appendingPathComponent(String(format: "page-%02d.png", page + 1))
                    try ScreenshotDiagnostics.writePNG(snapshot, candidates: scanned, to: url)
                    screenshotRecords.append(DiagnosticScreenshotRecord(
                        viewportIndex: page,
                        relativePath: relativePath(url, root: taskRoot),
                        sha256: try await TaskStore.shared.digestFile(url)
                    ))
                }
                for observation in newObservations {
                    let candidate = observation.candidate
                    let axEvidence = observation.evidence
                    let strictAX = axEvidence?.isStrictVoiceTarget == true
                    targets.append(VoiceTarget(
                        sequence: targets.count + 1,
                        viewportIndex: page,
                        detectionConfidence: candidate.confidence,
                        senderLabel: candidate.senderLabel,
                        observedTimestampLabel: candidate.timestampLabel,
                        messageTime: nil,
                        expectedDurationMilliseconds: candidate.durationMilliseconds,
                        bubbleRect: candidate.rect,
                        contextFingerprint: candidate.fingerprint,
                        axRolePath: axEvidence?.rolePath ?? [],
                        axSemanticHints: axEvidence?.semanticHints ?? [],
                        axSemanticSignature: strictAX ? axEvidence?.signature : nil,
                        axSemanticDigest: strictAX ? axEvidence?.semanticDigest : nil,
                        axOccurrenceIdentifier: strictAX
                            ? axEvidence?.occurrenceIdentifier : nil,
                        axVoiceSemanticConfirmed: strictAX,
                        status: .located
                    ))
                    if targets.count >= expected { break }
                }
                if targets.count >= expected { break }
                previousPage = scanned
                guard page < pages - 1 else { break }
                try await input.scrollMessageList(in: snapshot, deltaLines: -scrollLines)
                restoreRemaining += 1
            }

            while restoreRemaining > 0 {
                let snapshot = try await provider.currentWeChatWindow()
                guard let binding else { throw VoiceMP4Error.safetyViolation("丢失窗口绑定") }
                try assertBound(snapshot, to: task, binding: binding, region: region)
                try await input.scrollMessageList(in: snapshot, deltaLines: scrollLines)
                restoreRemaining -= 1
            }
            guard let binding else { throw VoiceMP4Error.safetyViolation("干跑没有建立窗口绑定") }
            let restored = try await provider.currentWeChatWindow()
            try assertBound(restored, to: task, binding: binding, region: region)
            let restoredRawCandidates = try await scanner.scan(restored, within: region)
                .filter { $0.confidence >= CandidateIdentityPolicy.minimumConfidence }
            let restoredCandidates = restoredRawCandidates.map {
                AXVoiceCandidateResolver.resolve(
                    snapshot: restored,
                    candidate: $0,
                    region: region
                ).candidate
            }
            guard pageIdentityMatches(firstPage, restoredCandidates) else {
                throw VoiceMP4Error.safetyViolation("滚动恢复后起始屏视觉锚点不一致")
            }
        } catch {
            while restoreRemaining > 0 {
                guard let snapshot = try? await provider.currentWeChatWindow(),
                      let binding,
                      (try? assertBound(snapshot, to: task, binding: binding, region: region)) != nil,
                      (try? await input.scrollMessageList(
                        in: snapshot,
                        deltaLines: scrollLines
                      )) != nil else { break }
                restoreRemaining -= 1
            }
            throw error
        }

        task.messageRegion = region
        task.boundWindow = binding
        task.scannerVersion = VisionVoiceCandidateScanner.version
        task.targets = targets
        task.viewportPlans = viewportPlans
        task.diagnosticScreenshots = screenshotRecords
        task.approval = nil
        try await TaskStore.shared.saveTask(task, at: taskRoot)
        runtime.approvedPlanDigest = nil
        runtime.updatedAt = Date()
        try await TaskStore.shared.saveRuntime(runtime, at: taskRoot)
        try await audit(
            task: task,
            root: taskRoot,
            kind: "dry_run_completed",
            message: "候选扫描与起始屏恢复校验完成",
            metadata: ["candidate_count": "\(targets.count)", "pages": "\(pages)"]
        )
        try printJSON(DryRunReport(
            observedChatTitle: task.chatTitle,
            candidateCount: targets.count,
            expectedCount: expected,
            messageRegion: region,
            firstAnchor: String((targets.first?.contextFingerprint ?? "").prefix(12)),
            lastAnchor: String((targets.last?.contextFingerprint ?? "").prefix(12)),
            boundaryMode: "用户定位第一条 + expected 条数 + 首尾视觉锚点人工批准",
            diagnosticScreenshotDirectory: screenshotRunDirectory.map {
                relativePath($0, root: taskRoot)
            },
            candidates: targets.map {
                DryRunCandidate(
                    sequence: $0.sequence,
                    viewportIndex: $0.viewportIndex,
                    durationMilliseconds: $0.expectedDurationMilliseconds,
                    observedTimestampLabel: $0.observedTimestampLabel,
                    rect: $0.bubbleRect ?? .zero,
                    fingerprint: String(($0.contextFingerprint ?? "").prefix(12)),
                    axVoiceSemanticConfirmed: $0.axVoiceSemanticConfirmed,
                    axSemanticDigest: $0.axSemanticDigest,
                    axOccurrenceIdentifier: $0.axOccurrenceIdentifier,
                    axRolePath: $0.axRolePath,
                    axSemanticHints: $0.axSemanticHints
                )
            }
        ))
        if targets.count != expected {
            throw VoiceMP4Error.validation(
                "干跑找到 \(targets.count) 条，预期 \(expected) 条；清单已保存但不能批准"
            )
        }
        let semanticFailures = targets.filter { !$0.axVoiceSemanticConfirmed }.map(\.sequence)
        if !semanticFailures.isEmpty {
            throw VoiceMP4Error.validation(
                "第 \(semanticFailures.map(String.init).joined(separator: ",")) 条没有在同一 AX 节点上同时出现稳定语音语义与 AXPress；清单已保存供诊断，但正式点击保持锁定"
            )
        }
    }

    static func capture(taskRoot: URL, args: CommandLineArguments) async throws {
        let weChatControlLock = try TaskExecutionLock.acquireWeChatControl(operation: "capture")
        defer { weChatControlLock.release() }
        let operationLock = try TaskExecutionLock(taskRoot: taskRoot, operation: "capture")
        defer { operationLock.release() }
        var task = try await TaskStore.shared.loadTask(from: taskRoot)
        var runtime = try await TaskStore.shared.loadRuntime(from: taskRoot)
        let paths = TaskPaths(root: taskRoot)
        guard runtime.taskID == task.id else {
            throw VoiceMP4Error.safetyViolation("运行状态不属于当前任务")
        }
        guard AXIsProcessTrusted(), CGPreflightPostEventAccess(), CGPreflightScreenCaptureAccess() else {
            throw VoiceMP4Error.unavailable("屏幕与系统音频录制/辅助功能权限未就绪")
        }
        let plan = try task.frozenPlan()
        guard plan.scannerVersion == VisionVoiceCandidateScanner.version else {
            throw VoiceMP4Error.safetyViolation("冻结计划由旧版扫描器生成；必须重新干跑并批准")
        }
        guard let approval = task.approval,
              approval.chatTitle == task.chatTitle,
              approval.approvedCandidateCount == plan.expectedCount,
              approval.allCandidatesConfirmedAsVoice else {
            throw VoiceMP4Error.safetyViolation("任务没有有效的已批准计划")
        }
        let planDigest = try await TaskStore.shared.digest(plan)
        guard planDigest == approval.frozenPlanDigest else {
            throw VoiceMP4Error.safetyViolation("批准后的群名、时间、区域、窗口或候选清单发生变化")
        }
        guard runtime.approvedPlanDigest == planDigest else {
            throw VoiceMP4Error.safetyViolation("运行状态没有绑定当前冻结计划")
        }
        try await verifyDiagnosticScreenshots(plan: plan, taskRoot: taskRoot)
        if let inFlight = runtime.inFlight,
           !runtime.completedTargetIDs.contains(inFlight.targetID) {
            guard args.options["ack-interrupted"] == inFlight.targetID else {
                throw VoiceMP4Error.safetyViolation(
                    "上次在第 \(inFlight.sequence) 条点击期间中断；确认语音已停止后，显式传入 --ack-interrupted \(inFlight.targetID)"
                )
            }
            runtime.inFlight = nil
            runtime.updatedAt = Date()
            try await TaskStore.shared.saveRuntime(runtime, at: taskRoot)
            try await audit(
                task: task,
                root: taskRoot,
                targetID: inFlight.targetID,
                kind: "interrupted_click_acknowledged",
                message: "用户显式确认中断状态并允许重新定位",
                metadata: [:]
            )
        }

        let incomplete = task.targets.filter { !runtime.completedTargetIDs.contains($0.id) }
        if incomplete.isEmpty {
            print("所有批准片段已经采集完成；请运行 assemble。")
            return
        }
        guard incomplete.map(\.viewportIndex).min() == 0 else {
            throw VoiceMP4Error.safetyViolation(
                "无法证明跨页断点仍位于原始起点；请从剩余第一条创建新任务，禁止盲滚恢复"
            )
        }

        let provider = MacWeChatWindowProvider()
        let scanner = VisionVoiceCandidateScanner()
        let input = MacRestrictedInputDriver()
        let audio = WeChatApplicationAudioCapturer(binding: plan.boundWindow)
        let cacheRoots = args.flags.contains("probe-cache") ? WeChatDataLocator().probeRoots() : []
        let cacheProbe = CacheProbe(roots: cacheRoots, maximumFiles: 60_000)
        let maxItems = try args.integer("max-items") ?? Int.max
        guard maxItems > 0 else { throw VoiceMP4Error.invalidArguments("--max-items 必须大于 0") }
        var capturedThisRun = 0
        var machine = CaptureStateMachine()
        try machine.transition(to: .bindChat)
        let initial = try await provider.currentWeChatWindow()
        try assertBound(initial, to: task, binding: plan.boundWindow, region: plan.messageRegion)
        let initialCandidates = try await scanResolvedCandidates(
            scanner: scanner,
            snapshot: initial,
            region: plan.messageRegion
        )
        try validateViewport(
            page: 0,
            candidates: initialCandidates,
            task: task,
            completedTargetIDs: Set(runtime.completedTargetIDs)
        )
        guard let firstIncomplete = incomplete.first,
              (try? locate(firstIncomplete, among: initialCandidates)) != nil else {
            throw VoiceMP4Error.safetyViolation("当前页面不是已批准的起始页面")
        }
        try machine.transition(to: .plan)
        try machine.transition(to: .seekFirst)
        try machine.transition(to: .locateNext)
        runtime.startedAt = runtime.startedAt ?? Date()
        runtime.updatedAt = Date()
        try await TaskStore.shared.saveRuntime(runtime, at: taskRoot)

        let grouped = Dictionary(grouping: task.targets, by: \VoiceTarget.viewportIndex)
        let lastPage = task.targets.map(\.viewportIndex).max() ?? 0
        do {
            for page in 0...lastPage {
                let pageSnapshot = try await provider.currentWeChatWindow()
                try assertBound(
                    pageSnapshot,
                    to: task,
                    binding: plan.boundWindow,
                    region: plan.messageRegion
                )
                let pageCandidates = try await scanResolvedCandidates(
                    scanner: scanner,
                    snapshot: pageSnapshot,
                    region: plan.messageRegion
                )
                try validateViewport(
                    page: page,
                    candidates: pageCandidates,
                    task: task,
                    completedTargetIDs: Set(runtime.completedTargetIDs)
                )
                let pageTargets = (grouped[page] ?? [])
                    .filter { !runtime.completedTargetIDs.contains($0.id) }
                    .sorted { $0.sequence < $1.sequence }
                if pageTargets.isEmpty, page < lastPage {
                    throw VoiceMP4Error.safetyViolation(
                        "当前屏已全部完成，无法在新进程中安全证明下一屏位置"
                    )
                }
                for planned in pageTargets {
                    let snapshot = try await provider.currentWeChatWindow()
                    try assertBound(snapshot, to: task, binding: plan.boundWindow, region: plan.messageRegion)
                    let scanned = try await scanResolvedCandidates(
                        scanner: scanner,
                        snapshot: snapshot,
                        region: plan.messageRegion
                    )
                    _ = try locate(planned, among: scanned)
                    let baseline = cacheRoots.isEmpty
                        ? nil
                        : try? cacheProbe.snapshot(modifiedSince: Date().addingTimeInterval(-10))
                    let suffix = UUID().uuidString.prefix(8)
                    let capturedURL = paths.segments.appendingPathComponent(
                        String(format: "%03d-%@-captured.m4a", planned.sequence, String(suffix))
                    )

                    try await audio.beginSegment(outputURL: capturedURL)
                    try await waitUntilAudioArmedAndQuiet(audio)
                    let armedSnapshot = try await provider.currentWeChatWindow()
                    try assertBound(
                        armedSnapshot,
                        to: task,
                        binding: plan.boundWindow,
                        region: plan.messageRegion
                    )
                    let armedCandidates = try await scanResolvedCandidates(
                        scanner: scanner,
                        snapshot: armedSnapshot,
                        region: plan.messageRegion
                    )
                    let armedCandidate = try locate(planned, among: armedCandidates)
                    let quiet = await audio.isQuiet
                    let preClickAudioDetected = await audio.hasDetectedAudibleAudio
                    let decision = SafetyGate.mayClick(
                        snapshot: SafetySnapshot(
                            foregroundBundleIdentifier: armedSnapshot.foregroundBundleIdentifier,
                            observedChatTitle: armedSnapshot.title,
                            focusedRole: armedSnapshot.focusedRole,
                            targetRect: armedCandidate.rect,
                            messageRegion: plan.messageRegion,
                            modalStateKnown: armedSnapshot.modalStateKnown,
                            hasModalWindow: armedSnapshot.hasModalWindow,
                            audioCaptureReady: await audio.isReady,
                            applicationAudioQuiet: quiet,
                            playbackActive: preClickAudioDetected
                        ),
                        expectedChatTitle: task.chatTitle
                    )
                    guard decision.allowed else {
                        throw VoiceMP4Error.safetyViolation(
                            "点击门禁拒绝：\(decision.reasons.joined(separator: "；"))"
                        )
                    }

                    runtime.inFlight = InFlightRecord(
                        targetID: planned.id,
                        sequence: planned.sequence,
                        stage: .intentPersisted,
                        initiatedAt: Date()
                    )
                    runtime.updatedAt = Date()
                    try await TaskStore.shared.saveRuntime(runtime, at: taskRoot)
                    try machine.transition(to: .armClick)
                    try machine.arm(targetID: planned.id)
                    try machine.transition(to: .clickOnce)
                    try machine.consumeClick()
                    try await input.clickVoiceBubble(
                        in: armedSnapshot,
                        candidate: armedCandidate,
                        target: planned,
                        messageRegion: plan.messageRegion,
                        expectedChatTitle: task.chatTitle,
                        binding: plan.boundWindow
                    )
                    runtime.inFlight?.stage = .clicked
                    runtime.updatedAt = Date()
                    try await TaskStore.shared.saveRuntime(runtime, at: taskRoot)
                    try await audit(
                        task: task,
                        root: taskRoot,
                        targetID: planned.id,
                        kind: "voice_clicked_once",
                        message: "已执行一次受限左键播放",
                        metadata: ["sequence": "\(planned.sequence)"]
                    )
                    try machine.transition(to: .waitStart)
                    try await waitForPlaybackStart(
                        audio,
                        provider: provider,
                        task: task,
                        plan: plan
                    )
                    runtime.inFlight?.stage = .capturing
                    runtime.updatedAt = Date()
                    try await TaskStore.shared.saveRuntime(runtime, at: taskRoot)
                    try machine.transition(to: .capturing)
                    try await waitForPlaybackEnd(
                        audio,
                        expectedMilliseconds: planned.expectedDurationMilliseconds,
                        provider: provider,
                        task: task,
                        plan: plan
                    )
                    let finalSnapshot = try await provider.currentWeChatWindow()
                    try assertBound(
                        finalSnapshot,
                        to: task,
                        binding: plan.boundWindow,
                        region: plan.messageRegion
                    )
                    try machine.transition(to: .waitEnd)
                    let captured = try await audio.endSegment()
                    try machine.transition(to: .validateSegment)
                    let cacheDiagnostics = try await diagnoseCacheChanges(
                        target: planned,
                        baseline: baseline,
                        cacheProbe: cacheProbe,
                        paths: paths
                    )
                    let inspection = await MediaInspector.inspect(captured)
                    guard inspection.isUsableAudio,
                          VoiceSegmentDurationPolicy.matches(
                            expectedMilliseconds: planned.expectedDurationMilliseconds,
                            actualMilliseconds: inspection.durationMilliseconds
                          ) else {
                        throw VoiceMP4Error.validation(
                            "第 \(planned.sequence) 条时长/音轨校验失败；禁止自动重试"
                        )
                    }

                    let record = SegmentRecord(
                        id: UUID().uuidString,
                        targetID: planned.id,
                        sequence: planned.sequence,
                        source: .applicationAudio,
                        relativePath: relativePath(captured, root: taskRoot),
                        expectedDurationMilliseconds: planned.expectedDurationMilliseconds,
                        actualDurationMilliseconds: inspection.durationMilliseconds,
                        sha256: inspection.sha256,
                        validated: true,
                        failureReason: nil
                    )
                    try machine.transition(to: .commit)
                    runtime.segments.removeAll { $0.targetID == planned.id }
                    runtime.segments.append(record)
                    runtime.completedTargetIDs.append(planned.id)
                    runtime.failedTargetIDs.removeAll { $0 == planned.id }
                    runtime.inFlight = nil
                    runtime.updatedAt = Date()
                    if let index = task.targets.firstIndex(where: { $0.id == planned.id }) {
                        task.targets[index].status = .validated
                    }
                    try await TaskStore.shared.saveRuntime(runtime, at: taskRoot)
                    try await TaskStore.shared.saveTask(task, at: taskRoot)
                    try await audit(
                        task: task,
                        root: taskRoot,
                        targetID: planned.id,
                        kind: "segment_validated",
                        message: "应用音频片段已校验并提交",
                        metadata: [
                            "sequence": "\(planned.sequence)",
                            "duration_ms": "\(inspection.durationMilliseconds ?? -1)",
                            "cache_diagnostics": "\(cacheDiagnostics)"
                        ]
                    )
                    try machine.transition(to: .advance)
                    try machine.transition(to: .locateNext)
                    capturedThisRun += 1
                    if capturedThisRun >= maxItems {
                        print("本次校准采集完成：\(capturedThisRun) 条。保持起始屏不变后可继续。")
                        return
                    }
                }
                guard page < lastPage else { continue }
                let snapshot = try await provider.currentWeChatWindow()
                try assertBound(snapshot, to: task, binding: plan.boundWindow, region: plan.messageRegion)
                try await input.scrollMessageList(in: snapshot, deltaLines: -scrollLines)
            }
            try machine.transition(to: .reconcile)
            guard runtime.completedTargetIDs.count == task.targets.count,
                  runtime.segments.filter(\.validated).count == task.targets.count else {
                throw VoiceMP4Error.validation("采集完成数与批准清单不一致")
            }
            try machine.transition(to: .finalVerify)
            try machine.transition(to: .finished)
            print("采集完成：\(runtime.completedTargetIDs.count) 条。请运行 assemble。")
        } catch {
            machine.pause()
            await audio.cancelSegment()
            if var inFlight = runtime.inFlight {
                inFlight.stage = .uncertain
                runtime.inFlight = inFlight
                if !runtime.failedTargetIDs.contains(inFlight.targetID) {
                    runtime.failedTargetIDs.append(inFlight.targetID)
                }
            }
            runtime.updatedAt = Date()
            try? await TaskStore.shared.saveRuntime(runtime, at: taskRoot)
            try? await audit(
                task: task,
                root: taskRoot,
                kind: "capture_paused",
                message: "采集已安全暂停：\(error.localizedDescription)",
                metadata: ["phase": machine.phase.rawValue]
            )
            throw error
        }
    }

    static func assemble(taskRoot: URL, args: CommandLineArguments) async throws {
        let operationLock = try TaskExecutionLock(taskRoot: taskRoot, operation: "assemble")
        defer { operationLock.release() }
        let task = try await TaskStore.shared.loadTask(from: taskRoot)
        var runtime = try await TaskStore.shared.loadRuntime(from: taskRoot)
        let plan = try task.frozenPlan()
        let planDigest = try await TaskStore.shared.digest(plan)
        guard runtime.taskID == task.id,
              runtime.inFlight == nil,
              let approval = task.approval,
              approval.allCandidatesConfirmedAsVoice,
              approval.frozenPlanDigest == planDigest,
              runtime.approvedPlanDigest == planDigest else {
            throw VoiceMP4Error.safetyViolation("任务计划、运行状态或中断状态无效")
        }
        let valid = runtime.segments.filter(\.validated).sorted { $0.sequence < $1.sequence }
        let approvedIDs = Set(task.targets.map(\.id))
        let validIDs = Set(valid.map(\.targetID))
        guard valid.count == task.targets.count,
              validIDs == approvedIDs,
              Set(runtime.completedTargetIDs) == approvedIDs,
              runtime.failedTargetIDs.isEmpty,
              Set(valid.map(\.sequence)).count == task.targets.count else {
            throw VoiceMP4Error.validation("只有全部批准片段均校验通过后才能合并")
        }
        let approvedByID = Dictionary(uniqueKeysWithValues: task.targets.map { ($0.id, $0) })
        let stagingRoot = TaskPaths(root: taskRoot).segments.appendingPathComponent(
            ".assembly-\(UUID().uuidString)",
            isDirectory: true
        )
        try FileManager.default.createDirectory(at: stagingRoot, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: stagingRoot) }
        var segmentURLs: [URL] = []
        for record in valid {
            guard let approvedTarget = approvedByID[record.targetID],
                  record.source == .applicationAudio,
                  record.sequence == approvedTarget.sequence,
                  record.expectedDurationMilliseconds
                    == approvedTarget.expectedDurationMilliseconds else {
                throw VoiceMP4Error.safetyViolation("片段元数据与冻结候选不一致")
            }
            let url = taskRoot.appendingPathComponent(record.relativePath).standardizedFileURL
            let segmentRoot = TaskPaths(root: taskRoot).segments.standardizedFileURL.path + "/"
            guard url.path.hasPrefix(segmentRoot),
                  FileManager.default.isReadableFile(atPath: url.path) else {
                throw VoiceMP4Error.validation("片段不可读：\(url.lastPathComponent)")
            }
            let inspection = await MediaInspector.inspect(url)
            guard inspection.isUsableAudio,
                  !inspection.sha256.isEmpty,
                  inspection.sha256 == record.sha256,
                  MediaInspector.durationMatches(
                    expectedMilliseconds: record.actualDurationMilliseconds
                        ?? record.expectedDurationMilliseconds,
                    actualMilliseconds: inspection.durationMilliseconds,
                    absoluteToleranceMilliseconds: 120,
                    proportionalTolerance: 0
                  ) else {
                throw VoiceMP4Error.safetyViolation(
                    "片段在验证后被替换、损坏或时长改变：\(url.lastPathComponent)"
                )
            }
            let stagedURL = stagingRoot.appendingPathComponent(
                String(format: "%03d-%@.m4a", record.sequence, record.targetID)
            )
            try FileManager.default.copyItem(at: url, to: stagedURL)
            let stagedInspection = await MediaInspector.inspect(stagedURL)
            guard stagedInspection.isUsableAudio,
                  stagedInspection.sha256 == record.sha256 else {
                throw VoiceMP4Error.safetyViolation("片段封存复核失败")
            }
            segmentURLs.append(stagedURL)
        }
        let gap = try args.integer("gap-ms") ?? 300
        let outputURL: URL
        if let explicit = args.options["output"] {
            outputURL = URL(fileURLWithPath: explicit).standardizedFileURL
        } else {
            outputURL = TaskPaths(root: taskRoot).output
                .appendingPathComponent("wechat-voices-\(outputTimestamp()).mp4")
        }
        try await AVFoundationMediaAssembler().assemble(
            segments: segmentURLs,
            gapMilliseconds: gap,
            title: task.chatTitle,
            outputURL: outputURL
        )
        let inspection = try await AVFoundationMediaAssembler.inspectAndValidate(outputURL)
        runtime.finalMP4RelativePath = relativePath(outputURL, root: taskRoot)
        runtime.updatedAt = Date()
        try await TaskStore.shared.saveRuntime(runtime, at: taskRoot)
        try await audit(
            task: task,
            root: taskRoot,
            kind: "mp4_assembled",
            message: "最终 MP4 已生成并验证",
            metadata: [
                "duration_ms": "\(inspection.durationMilliseconds)",
                "file_size": "\(inspection.fileSize)"
            ]
        )
        print(outputURL.path)
    }

    static func syntheticSelfTest(outputURL: URL) async throws {
        let directory = outputURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let first = directory.appendingPathComponent(".self-test-\(UUID().uuidString)-1.m4a")
        let second = directory.appendingPathComponent(".self-test-\(UUID().uuidString)-2.m4a")
        defer {
            try? FileManager.default.removeItem(at: first)
            try? FileManager.default.removeItem(at: second)
        }
        try SyntheticMediaFactory.makeTone(at: first, durationSeconds: 0.7, frequency: 440)
        try SyntheticMediaFactory.makeTone(at: second, durationSeconds: 0.9, frequency: 660)
        try await AVFoundationMediaAssembler().assemble(
            segments: [first, second],
            gapMilliseconds: 250,
            title: "WeChat Voice MP4 Self Test",
            outputURL: outputURL
        )
        let inspection = try await AVFoundationMediaAssembler.inspectAndValidate(outputURL)
        try await SyntheticMediaFactory.verifyToneSequence(at: outputURL)
        try printJSON(inspection)
    }

    private static func waitUntilAudioArmedAndQuiet(
        _ audio: WeChatApplicationAudioCapturer
    ) async throws {
        let deadline = Date().addingTimeInterval(2.5)
        while Date() < deadline {
            if await audio.hasDetectedAudibleAudio {
                throw VoiceMP4Error.safetyViolation(
                    "点击前检测到微信应用声音；为防止混入通知、通话或上一条语音，本段已取消"
                )
            }
            if await audio.isReady, await audio.isQuiet { return }
            try await Task.sleep(for: .milliseconds(120))
        }
        throw VoiceMP4Error.safetyViolation("微信应用音频未能在点击前进入静默就绪状态")
    }

    private static func waitForPlaybackStart(
        _ audio: WeChatApplicationAudioCapturer,
        provider: MacWeChatWindowProvider,
        task: CaptureTask,
        plan: FrozenCapturePlan
    ) async throws {
        let deadline = Date().addingTimeInterval(3)
        while Date() < deadline {
            try MacRuntimeSafetyGuard.validate(binding: plan.boundWindow)
            if await audio.hasDetectedAudibleAudio { return }
            try await Task.sleep(for: .milliseconds(100))
        }
        let snapshot = try await provider.currentWeChatWindow()
        try assertBound(snapshot, to: task, binding: plan.boundWindow, region: plan.messageRegion)
        throw VoiceMP4Error.validation("点击后 3 秒内没有检测到语音开始，目标可能不是语音气泡")
    }

    private static func waitForPlaybackEnd(
        _ audio: WeChatApplicationAudioCapturer,
        expectedMilliseconds: Int,
        provider: MacWeChatWindowProvider,
        task: CaptureTask,
        plan: FrozenCapturePlan
    ) async throws {
        let startedAt = Date()
        let minimum = max(Double(expectedMilliseconds) / 1_000 + 0.35, 0.6)
        let deadline = startedAt.addingTimeInterval(Double(expectedMilliseconds) / 1_000 + 3.5)
        var nextTitleCheck = Date().addingTimeInterval(4)
        while Date() < deadline {
            try MacRuntimeSafetyGuard.validate(binding: plan.boundWindow)
            if Date() >= nextTitleCheck {
                let snapshot = try await provider.currentWeChatWindow()
                try assertBound(snapshot, to: task, binding: plan.boundWindow, region: plan.messageRegion)
                nextTitleCheck = Date().addingTimeInterval(4)
            }
            if Date().timeIntervalSince(startedAt) >= minimum, await audio.isQuiet { return }
            try await Task.sleep(for: .milliseconds(120))
        }
        throw VoiceMP4Error.validation("语音在预期时长后仍未结束，可能连续播放或混入其他微信声音")
    }

    private static func diagnoseCacheChanges(
        target: VoiceTarget,
        baseline: CacheSnapshot?,
        cacheProbe: CacheProbe,
        paths: TaskPaths
    ) async throws -> Int {
        guard let baseline else { return 0 }
        let changes = (try? await cacheProbe.waitForStableChanges(
            after: baseline,
            timeoutSeconds: 1.2
        )) ?? []
        var copied = 0
        for change in changes.prefix(20) {
            let file = change.fingerprint
            guard file.size >= 1_024, file.size <= 100 * 1_024 * 1_024 else { continue }
            let inspection = await MediaInspector.inspect(file.url)
            guard inspection.isUsableAudio,
                  MediaInspector.durationMatches(
                    expectedMilliseconds: target.expectedDurationMilliseconds,
                    actualMilliseconds: inspection.durationMilliseconds,
                    absoluteToleranceMilliseconds: 1_000,
                    proportionalTolerance: 0.04
                  ) else { continue }
            let ext = file.url.pathExtension.isEmpty ? "bin" : file.url.pathExtension
            let name = String(format: "%03d-%@.%@", target.sequence, file.redactedID, ext)
            _ = try? MediaInspector.copyCandidate(file.url, into: paths.cacheCandidates, name: name)
            copied += 1
        }
        return copied
    }

    private static func verifyDiagnosticScreenshots(
        plan: FrozenCapturePlan,
        taskRoot: URL
    ) async throws {
        let screenshotRoot = TaskPaths(root: taskRoot).screenshots.standardizedFileURL.path + "/"
        for record in plan.diagnosticScreenshots {
            let url = taskRoot.appendingPathComponent(record.relativePath).standardizedFileURL
            guard url.path.hasPrefix(screenshotRoot),
                  FileManager.default.isReadableFile(atPath: url.path),
                  try await TaskStore.shared.digestFile(url) == record.sha256 else {
                throw VoiceMP4Error.safetyViolation("批准红框截图缺失或哈希变化")
            }
        }
    }

    private static func scanResolvedCandidates(
        scanner: VisionVoiceCandidateScanner,
        snapshot: WindowSnapshot,
        region: NormalizedRect
    ) async throws -> [ScannedVoiceCandidate] {
        try await scanner.scan(snapshot, within: region)
            .filter { $0.confidence >= CandidateIdentityPolicy.minimumConfidence }
            .map {
                AXVoiceCandidateResolver.resolve(
                    snapshot: snapshot,
                    candidate: $0,
                    region: region
                ).candidate
            }
    }

    private static func validateViewport(
        page: Int,
        candidates: [ScannedVoiceCandidate],
        task: CaptureTask,
        completedTargetIDs: Set<String>
    ) throws {
        guard let plannedPage = task.viewportPlans.first(where: {
            $0.viewportIndex == page
        }), plannedPage.candidates.count == candidates.count else {
            throw VoiceMP4Error.safetyViolation("第 \(page + 1) 屏候选总数与冻结视口不一致")
        }
        let completed = task.targets.filter {
            $0.viewportIndex == page && completedTargetIDs.contains($0.id)
        }
        for (index, pair) in zip(plannedPage.candidates, candidates).enumerated() {
            let planned = pair.0
            let observed = pair.1
            guard planned.durationMilliseconds == observed.durationMilliseconds,
                  centerDistance(planned.rect, observed.rect)
                    <= CandidateIdentityPolicy.maximumCenterDrift else {
                throw VoiceMP4Error.safetyViolation(
                    "第 \(page + 1) 屏第 \(index + 1) 个候选位置或时长发生变化"
                )
            }
            if let plannedOccurrence = planned.axOccurrenceIdentifier {
                guard observed.axOccurrenceIdentifier == plannedOccurrence else {
                    throw VoiceMP4Error.safetyViolation(
                        "第 \(page + 1) 屏第 \(index + 1) 个 AX 消息身份发生变化"
                    )
                }
            } else if task.viewportPlans.count > 1 {
                throw VoiceMP4Error.safetyViolation("跨页冻结视口缺少稳定 AX 消息身份")
            }
            if let plannedSemantic = planned.axSemanticDigest {
                guard observed.axSemanticDigest == plannedSemantic else {
                    throw VoiceMP4Error.safetyViolation(
                        "第 \(page + 1) 屏第 \(index + 1) 个 AX 语义证据发生变化"
                    )
                }
            } else if task.viewportPlans.count > 1 {
                throw VoiceMP4Error.safetyViolation("跨页冻结视口缺少稳定 AX 语义摘要")
            }
            let belongsToCompletedTarget = completed.contains { target in
                target.contextFingerprint == planned.fingerprint
                    && target.expectedDurationMilliseconds == planned.durationMilliseconds
                    && target.bubbleRect.map {
                        centerDistance($0, planned.rect)
                            <= CandidateIdentityPolicy.maximumCenterDrift
                    } == true
            }
            let isCompletedOverlap = page > 0 && index < plannedPage.overlapWithPrevious
            if !belongsToCompletedTarget, !isCompletedOverlap,
               planned.fingerprint != observed.fingerprint {
                throw VoiceMP4Error.safetyViolation(
                    "第 \(page + 1) 屏第 \(index + 1) 个未播放候选视觉指纹变化"
                )
            }
        }
    }

    private static func assertBound(
        _ snapshot: WindowSnapshot,
        to task: CaptureTask,
        binding: BoundWindowIdentity,
        region: NormalizedRect
    ) throws {
        guard MessageRegionPolicy.validate(region) else {
            throw VoiceMP4Error.safetyViolation("消息区域越过硬边界")
        }
        guard binding.matches(snapshot) else {
            throw VoiceMP4Error.safetyViolation("微信进程、窗口、尺寸或缩放与干跑不一致")
        }
        guard snapshot.foregroundBundleIdentifier == snapshot.bundleIdentifier else {
            throw VoiceMP4Error.safetyViolation("微信不是前台应用")
        }
        guard ChatTitleMatcher.matches(observed: snapshot.title, expected: task.chatTitle) else {
            throw VoiceMP4Error.safetyViolation(
                "当前聊天标题不一致：观察到 \(snapshot.title ?? "无法识别")"
            )
        }
        guard snapshot.modalStateKnown, !snapshot.hasModalWindow else {
            throw VoiceMP4Error.safetyViolation("无法排除微信弹窗、菜单或附加窗口")
        }
        try MacRuntimeSafetyGuard.validate(binding: binding)
    }

    private static func locate(
        _ target: VoiceTarget,
        among candidates: [ScannedVoiceCandidate]
    ) throws -> ScannedVoiceCandidate {
        let matches = candidates.filter { CandidateIdentityPolicy.matches($0, target: target) }
        guard matches.count == 1, let only = matches.first else {
            throw VoiceMP4Error.safetyViolation(
                "无法按精确视觉指纹和位置唯一重定位第 \(target.sequence) 条；禁止按时长回退"
            )
        }
        return only
    }

    private static func validateOccurrenceIdentities(
        _ candidates: [ScannedVoiceCandidate],
        page: Int
    ) throws {
        let identities = candidates.compactMap(\.axOccurrenceIdentifier)
        guard identities.count == candidates.count else {
            throw VoiceMP4Error.safetyViolation(
                "第 \(page + 1) 屏并非每个语音节点都有 per-message AXIdentifier；禁止跨页"
            )
        }
        guard Set(identities).count == identities.count else {
            throw VoiceMP4Error.safetyViolation(
                "第 \(page + 1) 屏 AXIdentifier 重复，可能是虚拟列表通用 ID；禁止跨页"
            )
        }
        let semanticDigests = candidates.compactMap(\.axSemanticDigest)
        guard semanticDigests.count == candidates.count,
              semanticDigests.allSatisfy({ !$0.isEmpty }) else {
            throw VoiceMP4Error.safetyViolation(
                "第 \(page + 1) 屏缺少稳定 AX 语义摘要；禁止跨页"
            )
        }
    }

    private static func pageIdentityMatches(
        _ lhs: [ScannedVoiceCandidate],
        _ rhs: [ScannedVoiceCandidate]
    ) -> Bool {
        guard lhs.count == rhs.count else { return false }
        return zip(lhs, rhs).allSatisfy { first, second in
            first.fingerprint == second.fingerprint
                && first.durationMilliseconds == second.durationMilliseconds
                && first.axOccurrenceIdentifier == second.axOccurrenceIdentifier
                && centerDistance(first.rect, second.rect) <= CandidateIdentityPolicy.maximumCenterDrift
        }
    }

    private static func parseRegion(_ value: String?) throws -> NormalizedRect? {
        guard let value else { return nil }
        let parts = value.split(separator: ",").compactMap { Double($0) }
        guard parts.count == 4 else {
            throw VoiceMP4Error.invalidArguments("--message-region 格式应为 x,y,w,h")
        }
        let rect = NormalizedRect(x: parts[0], y: parts[1], width: parts[2], height: parts[3])
        guard MessageRegionPolicy.validate(rect) else {
            throw VoiceMP4Error.invalidArguments("--message-region 必须位于硬安全区域内")
        }
        return rect
    }

    private static func centerDistance(_ lhs: NormalizedRect, _ rhs: NormalizedRect) -> Double {
        let dx = lhs.x + lhs.width / 2 - rhs.x - rhs.width / 2
        let dy = lhs.y + lhs.height / 2 - rhs.y - rhs.height / 2
        return sqrt(dx * dx + dy * dy)
    }

    private static func relativePath(_ url: URL, root: URL) -> String {
        let rootPath = root.standardizedFileURL.path
        let path = url.standardizedFileURL.path
        guard path.hasPrefix(rootPath + "/") else { return path }
        return String(path.dropFirst(rootPath.count + 1))
    }

    private static func audit(
        task: CaptureTask,
        root: URL,
        targetID: String? = nil,
        kind: String,
        message: String,
        metadata: [String: String]
    ) async throws {
        try await TaskStore.shared.append(
            AuditEvent(
                timestamp: Date(),
                taskID: task.id,
                targetID: targetID,
                kind: kind,
                message: message,
                metadata: metadata
            ),
            at: root
        )
    }

    private static func printJSON<T: Encodable>(_ value: T) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        FileHandle.standardOutput.write(try encoder.encode(value))
        print()
    }

    private static func outputTimestamp() -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter.string(from: Date())
    }
}

private struct DryRunReport: Encodable {
    let observedChatTitle: String
    let candidateCount: Int
    let expectedCount: Int
    let messageRegion: NormalizedRect
    let firstAnchor: String
    let lastAnchor: String
    let boundaryMode: String
    let diagnosticScreenshotDirectory: String?
    let candidates: [DryRunCandidate]
}

private struct DryRunCandidate: Encodable {
    let sequence: Int
    let viewportIndex: Int
    let durationMilliseconds: Int
    let observedTimestampLabel: String?
    let rect: NormalizedRect
    let fingerprint: String
    let axVoiceSemanticConfirmed: Bool
    let axSemanticDigest: String?
    let axOccurrenceIdentifier: String?
    let axRolePath: [String]
    let axSemanticHints: [String]
}
