import Foundation
import PGPMailCore

public enum GPGClientError: Error, Sendable { case timeout, service(String), connection }

/// Client side: used by the Mail extension. `decodedMessage(forMessageData:)` in MailKit is
/// synchronous, so we offer a blocking call with a generous timeout (pinentry may be showing).
public final class GPGServiceClient: @unchecked Sendable {
    private let connection: NSXPCConnection

    public init(serviceName: String = GPGServiceName.helper) {
        connection = NSXPCConnection(serviceName: serviceName)
        connection.remoteObjectInterface = NSXPCInterface(with: GPGServiceProtocol.self)
        connection.resume()
    }

    deinit { connection.invalidate() }

    public func decodeBlocking(_ raw: Data, timeout: TimeInterval = 120) throws -> DecodeOutcome {
        let sem = DispatchSemaphore(value: 0)
        let box = Box()
        let proxy = connection.remoteObjectProxyWithErrorHandler { _ in
            box.error = .connection; sem.signal()
        } as? GPGServiceProtocol
        guard let proxy else { throw GPGClientError.connection }
        proxy.decode(raw) { json, err in
            if let json { box.json = json } else { box.error = .service(err ?? "unknown") }
            sem.signal()
        }
        guard sem.wait(timeout: .now() + timeout) == .success else { throw GPGClientError.timeout }
        if let e = box.error { throw e }
        return try JSONDecoder().decode(DecodeOutcome.self, from: box.json ?? Data())
    }

    public func encodingStatusBlocking(_ req: EncodingRequest, timeout: TimeInterval = 30) throws -> EncodingStatus {
        try call(req, timeout: timeout) { $0.encodingStatus }
    }

    public func encodeBlocking(_ req: EncodingRequest, timeout: TimeInterval = 180) throws -> EncodeOutcome {
        try call(req, timeout: timeout) { $0.encode }
    }

    private func call<R: Decodable>(_ req: EncodingRequest, timeout: TimeInterval,
                                    _ method: (GPGServiceProtocol) -> (Data, @escaping @Sendable (Data?, String?) -> Void) -> Void) throws -> R {
        let sem = DispatchSemaphore(value: 0)
        let box = Box()
        let proxy = connection.remoteObjectProxyWithErrorHandler { _ in box.error = .connection; sem.signal() } as? GPGServiceProtocol
        guard let proxy else { throw GPGClientError.connection }
        method(proxy)(try JSONEncoder().encode(req)) { json, err in
            if let json { box.json = json } else { box.error = .service(err ?? "unknown") }
            sem.signal()
        }
        guard sem.wait(timeout: .now() + timeout) == .success else { throw GPGClientError.timeout }
        if let e = box.error { throw e }
        return try JSONDecoder().decode(R.self, from: box.json ?? Data())
    }

    public func ping() -> Bool {
        let sem = DispatchSemaphore(value: 0)
        let box = Box()
        (connection.remoteObjectProxyWithErrorHandler { _ in sem.signal() } as? GPGServiceProtocol)?.ping { _ in box.ok = true; sem.signal() }
        _ = sem.wait(timeout: .now() + 5)
        return box.ok
    }

    private final class Box: @unchecked Sendable {
        var json: Data?; var error: GPGClientError?; var ok = false
    }
}
