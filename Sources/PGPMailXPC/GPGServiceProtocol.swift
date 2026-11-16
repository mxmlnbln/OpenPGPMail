import Foundation

/// Mach/XPC interface between the sandboxed Mail extension and the unsandboxed helper
/// that is allowed to talk to gpg and gpg-agent. Payloads are JSON so the wire format
/// stays independent of NSSecureCoding class whitelists.
@objc public protocol GPGServiceProtocol {
    /// Decrypts / verifies a raw RFC 5322 message. Reply: JSON-encoded `DecodeOutcome` (never nil on success of the call itself).
    func decode(_ rawMessage: Data, reply: @escaping @Sendable (_ outcomeJSON: Data?, _ transportError: String?) -> Void)
    /// JSON `EncodingRequest` → JSON `EncodingStatus`.
    func encodingStatus(_ requestJSON: Data, reply: @escaping @Sendable (_ statusJSON: Data?, _ transportError: String?) -> Void)
    /// JSON `EncodingRequest` (with raw message) → JSON `EncodeOutcome`.
    func encode(_ requestJSON: Data, reply: @escaping @Sendable (_ outcomeJSON: Data?, _ transportError: String?) -> Void)
    func ping(reply: @escaping @Sendable (String) -> Void)
}

public enum GPGServiceName {
    /// Name of the XPC service bundle embedded in the Mail extension.
    public static let helper = "org.openpgpmail.app.MailExtension.GPGHelper"
}
