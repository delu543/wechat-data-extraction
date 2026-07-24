import Foundation

struct CommandLineArguments: Sendable {
    let command: String
    let options: [String: String]
    let flags: Set<String>
    let positionals: [String]

    init(arguments: [String]) throws {
        guard arguments.count >= 2 else {
            self.command = "help"
            self.options = [:]
            self.flags = []
            self.positionals = []
            return
        }

        command = arguments[1]
        var parsedOptions: [String: String] = [:]
        var parsedFlags = Set<String>()
        var parsedPositionals: [String] = []
        var index = 2

        while index < arguments.count {
            let item = arguments[index]
            guard item.hasPrefix("--") else {
                parsedPositionals.append(item)
                index += 1
                continue
            }

            let key = String(item.dropFirst(2))
            guard !key.isEmpty else {
                throw VoiceMP4Error.invalidArguments("发现空选项")
            }

            if index + 1 < arguments.count, !arguments[index + 1].hasPrefix("--") {
                parsedOptions[key] = arguments[index + 1]
                index += 2
            } else {
                parsedFlags.insert(key)
                index += 1
            }
        }

        options = parsedOptions
        flags = parsedFlags
        positionals = parsedPositionals
    }

    func require(_ name: String) throws -> String {
        guard let value = options[name], !value.isEmpty else {
            throw VoiceMP4Error.invalidArguments("缺少 --\(name)")
        }
        return value
    }

    func integer(_ name: String) throws -> Int? {
        guard let raw = options[name] else { return nil }
        guard let value = Int(raw) else {
            throw VoiceMP4Error.invalidArguments("--\(name) 必须是整数")
        }
        return value
    }
}

enum LocalDateParser {
    private static let formats = [
        "yyyy-MM-dd HH:mm:ss",
        "yyyy-MM-dd HH:mm",
        "yyyy-MM-dd'T'HH:mm:ssZZZZZ"
    ]

    static func parse(_ value: String) throws -> Date {
        for format in formats {
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.timeZone = .current
            formatter.dateFormat = format
            if let date = formatter.date(from: value) {
                return date
            }
        }
        throw VoiceMP4Error.invalidArguments(
            "时间格式无效：\(value)。请使用 yyyy-MM-dd HH:mm[:ss]"
        )
    }
}
