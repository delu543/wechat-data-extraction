import Foundation

enum CLI {
    static func run(_ args: CommandLineArguments) async throws {
        switch args.command {
        case "help", "--help", "-h":
            printHelp()
        case "doctor":
            try printJSON(Doctor.run())
        case "init-task":
            try await initializeTask(args)
        case "inspect-task":
            try await inspectTask(args)
        case "approve":
            try await approveDryRun(args)
        case "cache-roots":
            try printJSON(WeChatDataLocator().probeRoots().map(\.path))
        case "dry-run":
            try await runDryRun(args)
        case "capture":
            try await runCapture(args)
        case "assemble":
            try await runAssemble(args)
        case "pcm-to-m4a":
            try await convertPCM(args)
        case "assemble-direct":
            try await assembleDirect(args)
        case "self-test":
            let output = URL(fileURLWithPath: try args.require("output")).standardizedFileURL
            try await CaptureCommands.syntheticSelfTest(outputURL: output)
        case "verify-core":
            try printJSON(try await CoreSelfTests.run())
        default:
            throw VoiceMP4Error.invalidArguments("未知命令：\(args.command)")
        }
    }

    private static func initializeTask(_ args: CommandLineArguments) async throws {
        let chat = try args.require("chat")
        let start = try LocalDateParser.parse(args.require("start"))
        let end = try LocalDateParser.parse(args.require("end"))
        guard start < end else {
            throw VoiceMP4Error.invalidArguments("开始时间必须早于结束时间")
        }

        guard let expected = try args.integer("expected") else {
            throw VoiceMP4Error.invalidArguments("创建任务时必须显式传入 --expected")
        }
        if expected <= 0 {
            throw VoiceMP4Error.invalidArguments("--expected 必须大于 0")
        }

        let root: URL
        if let explicit = args.options["task-dir"] {
            root = URL(fileURLWithPath: explicit).standardizedFileURL
        } else {
            let stamp = ISO8601DateFormatter().string(from: Date())
                .replacingOccurrences(of: ":", with: "-")
            root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
                .appendingPathComponent("tasks/\(stamp)-\(slug(chat))", isDirectory: true)
        }

        let task = CaptureTask(
            chatTitle: chat,
            startTime: start,
            endTime: end,
            expectedCount: expected,
            strictMode: true,
            outputDirectory: "output"
        )
        let paths = try await TaskStore.shared.create(task: task, at: root)
        print(paths.root.path)
    }

    private static func inspectTask(_ args: CommandLineArguments) async throws {
        let root = try taskRoot(args)
        let task = try await TaskStore.shared.loadTask(from: root)
        let runtime = try await TaskStore.shared.loadRuntime(from: root)
        struct Inspection: Codable { let task: CaptureTask; let runtime: RuntimeState }
        try printJSON(Inspection(task: task, runtime: runtime))
    }

    private static func approveDryRun(_ args: CommandLineArguments) async throws {
        let root = try taskRoot(args)
        let operationLock = try TaskExecutionLock(taskRoot: root, operation: "approve")
        defer { operationLock.release() }
        var task = try await TaskStore.shared.loadTask(from: root)
        guard let count = try args.integer("count") else {
            throw VoiceMP4Error.invalidArguments("批准时必须显式传入 --count")
        }
        guard !task.targets.isEmpty, count == task.targets.count else {
            throw VoiceMP4Error.validation("批准条数必须与干跑候选条数一致")
        }
        guard let expected = task.expectedCount, count == expected else {
            throw VoiceMP4Error.validation("批准条数必须与任务预期条数一致")
        }
        let confirmedChat = try args.require("confirm-chat")
        guard confirmedChat == task.chatTitle else {
            throw VoiceMP4Error.safetyViolation("确认的聊天标题与任务不一致")
        }
        let plan = try task.frozenPlan()
        guard plan.scannerVersion == VisionVoiceCandidateScanner.version else {
            throw VoiceMP4Error.safetyViolation("干跑计划来自旧版扫描器；必须重新 dry-run")
        }
        let expectedFirst = String(plan.firstVisualAnchor.prefix(12))
        let expectedLast = String(plan.lastVisualAnchor.prefix(12))
        guard try args.require("confirm-first") == expectedFirst else {
            throw VoiceMP4Error.safetyViolation("首条视觉锚点确认不一致")
        }
        guard try args.require("confirm-last") == expectedLast else {
            throw VoiceMP4Error.safetyViolation("末条视觉锚点确认不一致")
        }
        guard args.flags.contains("confirm-all-voice") else {
            throw VoiceMP4Error.safetyViolation(
                "必须先逐一查看红框截图，并显式传入 --confirm-all-voice"
            )
        }
        let screenshotRoot = TaskPaths(root: root).screenshots.standardizedFileURL.path + "/"
        for record in plan.diagnosticScreenshots {
            let url = root.appendingPathComponent(record.relativePath).standardizedFileURL
            guard url.path.hasPrefix(screenshotRoot),
                  FileManager.default.isReadableFile(atPath: url.path),
                  try await TaskStore.shared.digestFile(url) == record.sha256 else {
                throw VoiceMP4Error.safetyViolation(
                    "红框截图缺失或在干跑后发生变化；必须重新 dry-run --save-screenshot"
                )
            }
        }
        let digest = try await TaskStore.shared.digest(plan)
        var runtime = try await TaskStore.shared.loadRuntime(from: root)
        guard runtime.taskID == task.id,
              runtime.startedAt == nil,
              runtime.completedTargetIDs.isEmpty,
              runtime.failedTargetIDs.isEmpty,
              runtime.segments.isEmpty,
              runtime.inFlight == nil,
              runtime.finalMP4RelativePath == nil else {
            throw VoiceMP4Error.safetyViolation(
                "任务已进入采集阶段，不能重新批准；请为新计划创建新任务"
            )
        }
        task.approval = CaptureApproval(
            chatTitle: confirmedChat,
            approvedCandidateCount: count,
            allCandidatesConfirmedAsVoice: true,
            approvedAt: Date(),
            frozenPlanDigest: digest
        )
        try await TaskStore.shared.saveTask(task, at: root)
        runtime.approvedPlanDigest = digest
        runtime.updatedAt = Date()
        try await TaskStore.shared.saveRuntime(runtime, at: root)
        print("已冻结并批准干跑清单：\(count) 条。尚未开始点击。")
    }

    private static func runDryRun(_ args: CommandLineArguments) async throws {
        let root = try taskRoot(args)
        try await CaptureCommands.dryRun(taskRoot: root, args: args)
    }

    private static func runCapture(_ args: CommandLineArguments) async throws {
        let root = try taskRoot(args)
        guard args.flags.contains("arm") else {
            throw VoiceMP4Error.safetyViolation("正式采集必须显式传入 --arm")
        }
        try await CaptureCommands.capture(taskRoot: root, args: args)
    }

    private static func runAssemble(_ args: CommandLineArguments) async throws {
        let root = try taskRoot(args)
        try await CaptureCommands.assemble(taskRoot: root, args: args)
    }

    private static func convertPCM(_ args: CommandLineArguments) async throws {
        let input = URL(fileURLWithPath: try args.require("input")).standardizedFileURL
        let output = URL(fileURLWithPath: try args.require("output")).standardizedFileURL
        let sampleRate = try args.integer("sample-rate") ?? 24_000
        let expected = try args.integer("expected-ms")
        try printJSON(try await DirectAudioPipeline.convertPCMToM4A(
            inputURL: input,
            outputURL: output,
            sampleRate: sampleRate,
            expectedDurationMilliseconds: expected
        ))
    }

    private static func assembleDirect(_ args: CommandLineArguments) async throws {
        let manifest = URL(fileURLWithPath: try args.require("manifest")).standardizedFileURL
        let output = URL(fileURLWithPath: try args.require("output")).standardizedFileURL
        let gap = try args.integer("gap-ms") ?? 300
        try printJSON(try await DirectAudioPipeline.assemble(
            manifestURL: manifest,
            outputURL: output,
            gapMilliseconds: gap
        ))
    }

    private static func taskRoot(_ args: CommandLineArguments) throws -> URL {
        URL(fileURLWithPath: try args.require("task")).standardizedFileURL
    }

    private static func printJSON<T: Encodable>(_ value: T) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        FileHandle.standardOutput.write(try encoder.encode(value))
        print()
    }

    private static func slug(_ value: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_"))
        let mapped = value.unicodeScalars.map { allowed.contains($0) ? String($0) : "-" }.joined()
        return mapped.replacingOccurrences(of: "--", with: "-").prefix(48).description
    }

    private static func printHelp() {
        print(HelpText.value)
    }
}
