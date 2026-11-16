import Testing
import Foundation
@testable import PGPMailXPC
@testable import PGPMailCore

/// In-process anonymous listener: exercises the real NSXPC encoding without launchd.
@Test func xpcRoundTripPlainMessage() throws {
    let listener = NSXPCListener.anonymous()
    let delegate = GPGServiceListenerDelegate(service: GPGService(gpg: nil))
    listener.delegate = delegate
    listener.resume()

    let c = NSXPCConnection(listenerEndpoint: listener.endpoint)
    c.remoteObjectInterface = NSXPCInterface(with: GPGServiceProtocol.self)
    c.resume()
    defer { c.invalidate() }

    let sem = DispatchSemaphore(value: 0)
    nonisolated(unsafe) var answer = ""
    (c.remoteObjectProxy as! GPGServiceProtocol).ping { answer = $0; sem.signal() }
    #expect(sem.wait(timeout: .now() + 5) == .success)
    #expect(answer == "pong")
}

@Test func decodedIsCodable() throws {
    let d = PGPMIME.Decoded(message: Data("x".utf8), wasEncrypted: true,
                            signature: .init(state: .good, keyID: "K", userID: "U", fingerprint: nil))
    let back = try JSONDecoder().decode(PGPMIME.Decoded.self, from: JSONEncoder().encode(d))
    #expect(back.signature?.state == .good && back.wasEncrypted)
}
