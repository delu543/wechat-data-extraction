// swift-tools-version: 6.1

import PackageDescription

let package = Package(
    name: "WeChatVoiceMP4",
    platforms: [
        .macOS(.v15)
    ],
    products: [
        .executable(name: "wechat-voice-mp4", targets: ["WeChatVoiceMP4"])
    ],
    targets: [
        .executableTarget(
            name: "WeChatVoiceMP4",
            path: "Sources/WeChatVoiceMP4",
            linkerSettings: [
                .linkedFramework("AppKit"),
                .linkedFramework("ApplicationServices"),
                .linkedFramework("AVFoundation"),
                .linkedFramework("CoreGraphics"),
                .linkedFramework("CoreMedia"),
                .linkedFramework("CoreVideo"),
                .linkedFramework("ScreenCaptureKit"),
                .linkedFramework("Vision")
            ]
        )
    ]
)
