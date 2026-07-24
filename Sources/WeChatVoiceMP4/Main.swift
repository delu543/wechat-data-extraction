import Foundation

@main
struct WeChatVoiceMP4Main {
    static func main() async {
        do {
            let arguments = try CommandLineArguments(arguments: CommandLine.arguments)
            try await CLI.run(arguments)
        } catch {
            let message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            FileHandle.standardError.write(Data(("错误：\(message)\n").utf8))
            exit(1)
        }
    }
}
