import Foundation
import PGPMailCore
import Security

/// Server side: runs inside the helper process.
public final class GPGService: NSObject, GPGServiceProtocol, @unchecked Sendable {
    private let queue = DispatchQueue(label: "gpg-service", attributes: .concurrent)
    private let gpg: GPG?

    public init(gpg: GPG? = try? GPG.locate()) { self.gpg = gpg }

    public func decode(_ rawMessage: Data, reply: @escaping @Sendable (Data?, String?) -> Void) {
        guard let gpg else { return reply(nil, "gpg not found") }
        queue.async {
            let outcome = Self.decode(rawMessage, gpg: gpg, config: KeyConfig.load())
            reply(try? JSONEncoder().encode(outcome), nil)
        }
    }

    /// Pure function so it can be tested without XPC.
    static func decode(_ raw: Data, gpg: GPG, config: KeyConfig) -> DecodeOutcome {
        do {
            return DecodeOutcome(decoded: try PGPMIME(gpg: gpg).decode(raw), failure: nil)
        } catch PGPMIME.DecodeError.noSecretKey(let ids) {
            let keys = (try? KeyRing.secretKeys(using: gpg)) ?? []
            let missing = AddressExtractor.recipients(of: MIMEEntity(data: raw)).filter {
                KeyResolver.resolve(address: $0, keys: keys, config: config) == .none
            }
            return DecodeOutcome(decoded: nil, failure: .init(kind: .noSecretKey, recipientKeyIDs: ids, addressesWithoutKey: missing))
        } catch PGPMIME.DecodeError.malformed(let detail) {
            return DecodeOutcome(decoded: nil, failure: .init(kind: .malformed, message: detail))
        } catch {
            return DecodeOutcome(decoded: nil, failure: .init(kind: .other, message: "\(error)"))
        }
    }

    public func encodingStatus(_ requestJSON: Data, reply: @escaping @Sendable (Data?, String?) -> Void) {
        guard let gpg else { return reply(nil, "gpg not found") }
        guard let req = try? JSONDecoder().decode(EncodingRequest.self, from: requestJSON) else { return reply(nil, "bad request") }
        queue.async { reply(try? JSONEncoder().encode(Self.encodingStatus(req, gpg: gpg, config: KeyConfig.load())), nil) }
    }

    public func encode(_ requestJSON: Data, reply: @escaping @Sendable (Data?, String?) -> Void) {
        guard let gpg else { return reply(nil, "gpg not found") }
        guard let req = try? JSONDecoder().decode(EncodingRequest.self, from: requestJSON) else { return reply(nil, "bad request") }
        queue.async { reply(try? JSONEncoder().encode(Self.encode(req, gpg: gpg, config: KeyConfig.load())), nil) }
    }

    /// Key used to sign for `from`: explicit mapping or the single matching key.
    static func senderKey(_ from: String, gpg: GPG, config: KeyConfig) -> (SecretKey?, String?) {
        let keys = (try? KeyRing.secretKeys(using: gpg)) ?? []
        switch KeyResolver.resolve(address: from, keys: keys, config: config) {
        case .configured(let k), .automatic(let k): return (k, nil)
        case .ambiguous: return (nil, "Mehrere private Schlüssel passen zu \(from) – bitte in OpenPGPMail einen auswählen.")
        case .none: return (nil, "Für \(from) ist kein privater Schlüssel hinterlegt.")
        }
    }

    static func encodingStatus(_ req: EncodingRequest, gpg: GPG, config: KeyConfig) -> EncodingStatus {
        let (key, err) = senderKey(req.from, gpg: gpg, config: config)
        let failing = (req.recipients + req.hiddenRecipients).filter { KeyRing.locateEncryptionKey(for: $0, using: gpg, trust: config.trustModel, wkd: config.wkdLookup) == nil }
        // Encrypting also needs the sender key (we encrypt to self so sent mail stays readable).
        return EncodingStatus(canSign: key != nil, canEncrypt: failing.isEmpty && key != nil,
                              addressesFailingEncryption: failing, error: key == nil ? err : nil)
    }

    static func encode(_ req: EncodingRequest, gpg: GPG, config: KeyConfig) -> EncodeOutcome {
        guard let raw = req.raw else { return EncodeOutcome(signingError: "Keine Nachrichtendaten.") }
        let (key, err) = senderKey(req.from, gpg: gpg, config: config)
        guard let key else { return req.encrypt ? EncodeOutcome(encryptionError: err) : EncodeOutcome(signingError: err) }
        var recipients: [String] = [], hidden: [String] = []
        if req.encrypt {
            func find(_ a: String) -> String? {
                KeyRing.locateEncryptionKey(for: a, using: gpg, trust: config.trustModel, wkd: config.wkdLookup)
            }
            for a in req.recipients {
                guard let f = find(a) else { return EncodeOutcome(encryptionError: "Kein öffentlicher Schlüssel für \(a).") }
                if !recipients.contains(f) { recipients.append(f) }
            }
            if !recipients.contains(key.fingerprint) { recipients.append(key.fingerprint) }   // encrypt to self
            for a in req.hiddenRecipients {
                guard let f = find(a) else { return EncodeOutcome(encryptionError: "Kein öffentlicher Schlüssel für \(a).") }
                if !recipients.contains(f), !hidden.contains(f) { hidden.append(f) }
            }
        }
        do {
            let out = try PGPMIMEEncoder(gpg: gpg).encode(raw, options: .init(
                signerFingerprint: req.sign ? key.fingerprint : nil, recipientFingerprints: recipients,
                hiddenRecipientFingerprints: hidden,
                trustModel: config.trustModel, format: config.sendFormat))
            return EncodeOutcome(raw: out)
        } catch PGPMIMEEncoder.EncodeError.signingFailed(let m) { return EncodeOutcome(signingError: m)
        } catch PGPMIMEEncoder.EncodeError.encryptionFailed(let m) { return EncodeOutcome(encryptionError: m)
        } catch { return req.encrypt ? EncodeOutcome(encryptionError: "\(error)") : EncodeOutcome(signingError: "\(error)") }
    }

    public func ping(reply: @escaping @Sendable (String) -> Void) { reply("pong") }
}

/// Accepts connections only from our own extension / app.
public final class GPGServiceListenerDelegate: NSObject, NSXPCListenerDelegate {
    private let service: GPGService
    public init(service: GPGService = GPGService()) { self.service = service }

    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection c: NSXPCConnection) -> Bool {
        // Only binaries signed by the same team as this helper (our extension / app) may connect.
        // Ad-hoc signed local builds have no team: there the only protection is that launchd offers an XPC service
        // embedded in a bundle to that bundle alone.
        if let team = Self.ownTeamIdentifier() {
            c.setCodeSigningRequirement("anchor apple generic and certificate leaf[subject.OU] = \"\(team)\" and (identifier \"org.openpgpmail.app.MailExtension\" or identifier \"org.openpgpmail.app\")")
        }
        c.exportedInterface = NSXPCInterface(with: GPGServiceProtocol.self)
        c.exportedObject = service
        c.resume()
        return true
    }

    /// Team identifier from this process's own code signature (nil for unsigned / ad-hoc builds).
    static func ownTeamIdentifier() -> String? {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return nil }
        return dict[kSecCodeInfoTeamIdentifier as String] as? String
    }
}
