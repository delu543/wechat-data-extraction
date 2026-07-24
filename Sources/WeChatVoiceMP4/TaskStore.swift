import CryptoKit
import Foundation

struct TaskPaths: Sendable {
    let root: URL

    var definition: URL { root.appendingPathComponent("task.json") }
    var runtime: URL { root.appendingPathComponent("runtime.json") }
    var audit: URL { root.appendingPathComponent("audit.jsonl") }
    var segments: URL { root.appendingPathComponent("segments", isDirectory: true) }
    var cacheCandidates: URL { root.appendingPathComponent("cache-candidates", isDirectory: true) }
    var output: URL { root.appendingPathComponent("output", isDirectory: true) }
    var screenshots: URL { root.appendingPathComponent("diagnostics", isDirectory: true) }
}

actor TaskStore {
    static let shared = TaskStore()

    private let encoder: JSONEncoder
    private let decoder: JSONDecoder
    private let fileManager = FileManager.default

    init() {
        encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601

        decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
    }

    func create(task: CaptureTask, at root: URL) throws -> TaskPaths {
        let paths = TaskPaths(root: root)
        guard !fileManager.fileExists(atPath: root.path) else {
            throw VoiceMP4Error.validation("任务目录已存在：\(root.path)")
        }

        try fileManager.createDirectory(at: root, withIntermediateDirectories: true)
        for directory in [paths.segments, paths.cacheCandidates, paths.output, paths.screenshots] {
            try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        }

        try write(task, to: paths.definition)
        try write(RuntimeState.empty(taskID: task.id), to: paths.runtime)
        try Data().write(to: paths.audit, options: .atomic)
        return paths
    }

    func loadTask(from root: URL) throws -> CaptureTask {
        try read(CaptureTask.self, from: TaskPaths(root: root).definition)
    }

    func saveTask(_ task: CaptureTask, at root: URL) throws {
        try write(task, to: TaskPaths(root: root).definition)
    }

    func loadRuntime(from root: URL) throws -> RuntimeState {
        try read(RuntimeState.self, from: TaskPaths(root: root).runtime)
    }

    func saveRuntime(_ state: RuntimeState, at root: URL) throws {
        try write(state, to: TaskPaths(root: root).runtime)
    }

    func append(_ event: AuditEvent, at root: URL) throws {
        let url = TaskPaths(root: root).audit
        let lineEncoder = JSONEncoder()
        lineEncoder.dateEncodingStrategy = .iso8601
        lineEncoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var data = try lineEncoder.encode(event)
        data.append(0x0A)

        guard let handle = try? FileHandle(forWritingTo: url) else {
            throw VoiceMP4Error.unavailable("无法写入审计日志：\(url.path)")
        }
        defer { try? handle.close() }
        try handle.seekToEnd()
        try handle.write(contentsOf: data)
        try handle.synchronize()
    }

    func digest<T: Encodable>(_ value: T) throws -> String {
        let data = try encoder.encode(value)
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    func digestFile(_ url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while let chunk = try handle.read(upToCount: 1_048_576), !chunk.isEmpty {
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private func write<T: Encodable>(_ value: T, to url: URL) throws {
        let data = try encoder.encode(value)
        try data.write(to: url, options: .atomic)
    }

    private func read<T: Decodable>(_ type: T.Type, from url: URL) throws -> T {
        let data = try Data(contentsOf: url)
        return try decoder.decode(type, from: data)
    }
}
