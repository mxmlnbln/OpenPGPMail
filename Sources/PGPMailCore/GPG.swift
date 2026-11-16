import Foundation

public enum GPGError: Error, Sendable {
    case binaryNotFound
    case launchFailed(String)
}

public struct GPGResult: Sendable {
    public let stdout: Data
    /// Human-readable diagnostics only (may contain attacker-influenced text; never parsed).
    public let stderr: String
    public let exitCode: Int32
    /// Machine-readable status lines, written by gpg to a private file (`--status-file`).
    public let statusText: String
    public var status: [GPGStatus] { GPGStatus.parse(statusText) }
}

/// Thin wrapper around the `gpg` binary. All crypto stays in GnuPG; we only drive it
/// via `--status-fd` (machine readable) and never link against it.
public struct GPG: Sendable {
    public let executable: URL
    /// Extra environment for every invocation (e.g. `GNUPGHOME`).
    public var environment: [String: String]

    public static let searchPaths = [
        // GPG Suite's MacGPG2 first: it matches the gpg-agent most users run. Mixing client and agent
        // versions (e.g. Homebrew gpg 2.5 with a 2.2 agent, or the reverse) can break imported keys.
        "/usr/local/MacGPG2/bin/gpg", "/opt/homebrew/bin/gpg", "/usr/local/bin/gpg", "/usr/bin/gpg",
    ]

    public init(executable: URL, environment: [String: String] = [:]) { self.executable = executable; self.environment = environment }

    public static func locate() throws -> GPG {
        for p in searchPaths where FileManager.default.isExecutableFile(atPath: p) {
            return GPG(executable: URL(fileURLWithPath: p))
        }
        throw GPGError.binaryNotFound
    }

    /// Runs gpg with `--batch --status-file <private temp file>`. Status lines are kept apart from stderr so that
    /// text gpg prints about a message (file names, notations, user IDs) can never be mistaken for a status line.
    public func run(_ args: [String], stdin: Data = Data(), environment: [String: String] = [:], timeout: TimeInterval? = nil) throws -> GPGResult {
        let p = Process()
        p.executableURL = executable
        let statusURL = FileManager.default.temporaryDirectory.appendingPathComponent("opgpm-status-\(UUID().uuidString)")
        FileManager.default.createFile(atPath: statusURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
        defer { try? FileManager.default.removeItem(at: statusURL) }
        p.arguments = ["--batch", "--no-tty", "--status-file", statusURL.path, "--with-colons"] + args
        p.environment = ProcessInfo.processInfo.environment.merging(self.environment) { $1 }.merging(environment) { $1 }
        let inPipe = Pipe(), outPipe = Pipe(), errPipe = Pipe()
        p.standardInput = inPipe; p.standardOutput = outPipe; p.standardError = errPipe
        do { try p.run() } catch { throw GPGError.launchFailed("\(error)") }
        if let timeout { DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { if p.isRunning { p.terminate() } } }

        // Drain pipes concurrently to avoid deadlocks on large payloads. Dedicated threads (not the global
        // dispatch pool): many concurrent callers could otherwise exhaust the pool and deadlock.
        let box = Box()
        let outDone = DispatchSemaphore(value: 0), errDone = DispatchSemaphore(value: 0)
        let t1 = Thread { box.out = outPipe.fileHandleForReading.readDataToEndOfFile(); outDone.signal() }
        let t2 = Thread { box.err = errPipe.fileHandleForReading.readDataToEndOfFile(); errDone.signal() }
        t1.start(); t2.start()
        try? inPipe.fileHandleForWriting.write(contentsOf: stdin)
        try? inPipe.fileHandleForWriting.close()
        p.waitUntilExit()
        outDone.wait(); errDone.wait()
        let statusText = (try? Data(contentsOf: statusURL)).map { String(decoding: $0, as: UTF8.self) } ?? ""
        return GPGResult(stdout: box.out, stderr: String(decoding: box.err, as: UTF8.self), exitCode: p.terminationStatus, statusText: statusText)
    }
}

private final class Box: @unchecked Sendable { var out = Data(), err = Data() }

public enum GPGStatus: Sendable, Equatable {
    case decryptionOkay
    case decryptionFailed
    case goodSignature(keyID: String, userID: String)
    case badSignature(keyID: String, userID: String)
    case errorSignature(keyID: String)       // e.g. missing public key
    /// EXPSIG / EXPKEYSIG / REVKEYSIG: cryptographically correct, but signature or key expired / key revoked.
    case staleSignature(keyID: String, userID: String, reason: String)
    case validSignature(fingerprint: String)
    case noPublicKey(keyID: String)
    case encryptedTo(keyID: String)
    case noSecretKey(keyID: String)
    case other(String)

    public static func parse(_ stderr: String) -> [GPGStatus] {
        stderr.split(whereSeparator: \.isNewline).compactMap { line in
            guard line.hasPrefix("[GNUPG:] ") else { return nil }
            let f = line.dropFirst(9).split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false).map(String.init)
            switch f[0] {
            case "DECRYPTION_OKAY": return .decryptionOkay
            case "DECRYPTION_FAILED": return .decryptionFailed
            case "GOODSIG": return .goodSignature(keyID: f[safe: 1] ?? "", userID: f[safe: 2] ?? "")
            case "BADSIG": return .badSignature(keyID: f[safe: 1] ?? "", userID: f[safe: 2] ?? "")
            case "EXPSIG", "EXPKEYSIG", "REVKEYSIG":
                return .staleSignature(keyID: f[safe: 1] ?? "", userID: f[safe: 2] ?? "", reason: f[0])
            case "ERRSIG": return .errorSignature(keyID: f[safe: 1] ?? "")
            case "VALIDSIG": return .validSignature(fingerprint: f[safe: 1] ?? "")
            case "NO_PUBKEY": return .noPublicKey(keyID: f[safe: 1] ?? "")
            case "ENC_TO": return .encryptedTo(keyID: f[safe: 1].map { String($0.split(separator: " ").first ?? "") } ?? "")
            case "NO_SECKEY": return .noSecretKey(keyID: f[safe: 1] ?? "")
            default: return .other(f.joined(separator: " "))
            }
        }
    }
}

extension Array {
    subscript(safe i: Int) -> Element? { indices.contains(i) ? self[i] : nil }
}
