// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "OpenPGPMail",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "PGPMailCore", targets: ["PGPMailCore"]),
        .library(name: "PGPMailXPC", targets: ["PGPMailXPC"]),
    ],
    targets: [
        .target(name: "PGPMailCore"),
        .executableTarget(name: "opgpm", dependencies: ["PGPMailCore"]),
        .target(name: "PGPMailXPC", dependencies: ["PGPMailCore"]),
        .testTarget(name: "PGPMailCoreTests", dependencies: ["PGPMailCore", "PGPMailXPC"]),
    ]
)
