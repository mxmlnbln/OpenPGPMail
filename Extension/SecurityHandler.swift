import MailKit
import os
import PGPMailCore
import PGPMailXPC

/// Decode path only. `decodedMessage(forMessageData:)` is synchronous in MailKit, so we block on
/// the XPC helper (the extension sandbox cannot reach gpg-agent; the helper is unsandboxed).
nonisolated final class SecurityHandler: NSObject, @preconcurrency MEMessageSecurityHandler {
    private let helper = GPGServiceClient()
    private let log = Logger(subsystem: "org.openpgpmail", category: "handler")

    // MARK: MEMessageDecoder
    func decodedMessage(forMessageData data: Data) -> MEDecodedMessage? {
        let entity = MIMEEntity(data: data)
        guard PGPMIME.classify(entity) != .plain || PGPMIME.hasInlineArmor(data) else { return nil }
        let outcome: DecodeOutcome
        do { outcome = try helper.decodeBlocking(data) } catch {
            log.error("helper unreachable: \(String(describing: error), privacy: .public)")
            return nil
        }
        if let failure = outcome.failure {
            if failure.kind == .malformed {
                // Mail also calls us with incomplete data (headers/part headers only, body not yet downloaded).
                // Returning an error here would be cached as "broken PGP/MIME"; returning nil lets Mail retry later.
                log.info("ignoring malformed or partial message")
                return nil
            }
            return failedMessage(raw: data, failure: failure)
        }
        guard let decoded = outcome.decoded else { return nil }
        // Nothing to show (e.g. a mail that only quotes a PGP block): let Mail display it as usual.
        guard decoded.wasEncrypted || decoded.signature != nil else { return nil }
        var signers: [MEMessageSigner] = []
        var sigError: Error?
        if let sig = decoded.signature {
            signers = [MEMessageSigner(emailAddresses: sig.emails.map { MEEmailAddress(rawString: $0) },
                                       signatureLabel: sig.userID.isEmpty ? sig.keyID : sig.userID,
                                       context: Data(sig.keyID.utf8))]
            let problem: String? = switch sig.state {
            case .good: sig.matchesSender ? nil : "Die Signatur ist gültig, stammt aber nicht vom Absender der Mail, sondern von: \(sig.userID.isEmpty ? sig.keyID : sig.userID)"
            case .bad: "Die Signatur ist ungültig – die Nachricht wurde verändert oder nicht von diesem Schlüssel signiert."
            case .unknownKey: "Die Signatur kann nicht geprüft werden: Der öffentliche Schlüssel \(sig.keyID) fehlt."
            case .stale: "Die Signatur stammt von einem abgelaufenen oder widerrufenen Schlüssel."
            }
            if let problem { sigError = NSError(domain: "OpenPGPMail", code: 1, userInfo: [NSLocalizedDescriptionKey: problem]) }
        }
        let info = MEMessageSecurityInformation(signers: signers,
                                                isEncrypted: decoded.wasEncrypted,
                                                signingError: sigError,
                                                encryptionError: nil)
        return MEDecodedMessage(data: decoded.message, securityInformation: info,
                                context: nil, banner: nil)
    }

    /// Shows the original message plus a banner explaining why it could not be decrypted.
    private func failedMessage(raw: Data, failure: DecodeFailure) -> MEDecodedMessage {
        let title: String
        switch failure.kind {
        case .noSecretKey:
            let ids = failure.recipientKeyIDs.joined(separator: ", ")
            if failure.addressesWithoutKey.isEmpty {
                title = "Kein passender privater Schlüssel (verschlüsselt für \(ids))."
            } else {
                title = "Für \(failure.addressesWithoutKey.joined(separator: ", ")) ist kein privater Schlüssel hinterlegt."
            }
        case .malformed: title = "Die PGP/MIME-Nachricht ist fehlerhaft aufgebaut."
        case .other: title = "Entschlüsselung fehlgeschlagen oder abgebrochen (Passphrase?)."
        }
        log.error("decode failed: kind=\(failure.kind.rawValue, privacy: .public)")
        let err = NSError(domain: "OpenPGPMail", code: 2, userInfo: [NSLocalizedDescriptionKey: title])
        let info = MEMessageSecurityInformation(signers: [], isEncrypted: true, signingError: nil, encryptionError: err)
        let banner = MEDecodedMessageBanner(title: title, primaryActionTitle: "Schlüssel verwalten", dismissable: true)
        return MEDecodedMessage(data: raw, securityInformation: info,
                                context: try? JSONEncoder().encode(failure), banner: banner)
    }

    // MARK: MEMessageEncoder
    private func request(_ m: MEMessage, _ c: MEComposeContext, withRaw: Bool) -> EncodingRequest {
        func addr(_ a: MEEmailAddress) -> String { (a.addressString ?? a.rawString).lowercased() }
        let rcpt = Set((m.toAddresses + m.ccAddresses).map(addr))
        let bcc = Set(m.bccAddresses.map(addr)).subtracting(rcpt)
        return EncodingRequest(from: addr(m.fromAddress), recipients: rcpt.sorted(), hiddenRecipients: bcc.sorted(),
                               sign: c.shouldSign, encrypt: c.shouldEncrypt, raw: withRaw ? m.rawData : nil)
    }

    func getEncodingStatus(for message: MEMessage, composeContext: MEComposeContext,
                           completionHandler: @escaping (MEOutgoingMessageEncodingStatus) -> Void) {
        let req = request(message, composeContext, withRaw: false)
        let done = Unchecked(completionHandler)
        DispatchQueue.global().async { [helper, log] in
            let status: EncodingStatus
            do { status = try helper.encodingStatusBlocking(req) } catch {
                log.error("encodingStatus failed: \(String(describing: error), privacy: .public)")
                status = EncodingStatus(canSign: false, canEncrypt: false, addressesFailingEncryption: [], error: "OpenPGPMail-Helper nicht erreichbar.")
            }
            let err = status.error.map { NSError(domain: "OpenPGPMail", code: 3, userInfo: [NSLocalizedDescriptionKey: $0]) }
            done.value(MEOutgoingMessageEncodingStatus(
                canSign: status.canSign, canEncrypt: status.canEncrypt, securityError: err,
                addressesFailingEncryption: status.addressesFailingEncryption.map { MEEmailAddress(rawString: $0) }))
        }
    }

    func encode(_ message: MEMessage, composeContext: MEComposeContext,
                completionHandler: @escaping (MEMessageEncodingResult) -> Void) {
        let req = request(message, composeContext, withRaw: true)
        let done = Unchecked(completionHandler)
        DispatchQueue.global().async { [helper, log] in
            func fail(_ text: String) -> MEMessageEncodingResult {
                let e = NSError(domain: "OpenPGPMail", code: 4, userInfo: [NSLocalizedDescriptionKey: text])
                return req.encrypt ? MEMessageEncodingResult(encodedMessage: nil, signingError: nil, encryptionError: e)
                                   : MEMessageEncodingResult(encodedMessage: nil, signingError: e, encryptionError: nil)
            }
            guard req.sign || req.encrypt else {
                return done.value(MEMessageEncodingResult(encodedMessage: nil, signingError: nil, encryptionError: nil))
            }
            do {
                let out = try helper.encodeBlocking(req)
                if let raw = out.raw {
                    done.value(MEMessageEncodingResult(
                        encodedMessage: MEEncodedOutgoingMessage(rawData: raw, isSigned: req.sign, isEncrypted: req.encrypt),
                        signingError: nil, encryptionError: nil))
                } else {
                    log.error("encode failed: sign=\(req.sign) encrypt=\(req.encrypt)")
                    done.value(fail(out.encryptionError ?? out.signingError ?? "Unbekannter Fehler."))
                }
            } catch {
                log.error("encode helper error: \(String(describing: error), privacy: .public)")
                done.value(fail("OpenPGPMail-Helper nicht erreichbar oder Zeitüberschreitung."))
            }
        }
    }

    // MARK: UI
    func extensionViewController(signers: [MEMessageSigner]) -> MEExtensionViewController? { nil }
    func extensionViewController(messageContext: Data) -> MEExtensionViewController? { makeViewController(context: messageContext) }

    func primaryActionClicked(forMessageContext context: Data,
                              completionHandler: @escaping (MEExtensionViewController?) -> Void) {
        let vc = makeViewController(context: context)
        completionHandler(vc)
    }

    /// MailKit may call us off the main thread; AppKit objects must be created on it.
    private func makeViewController(context: Data) -> MEExtensionViewController? {
        guard let failure = try? JSONDecoder().decode(DecodeFailure.self, from: context) else { return nil }
        let make = { MainActor.assumeIsolated { FailureViewController(failure: failure) as MEExtensionViewController? } }
        return Thread.isMainThread ? make() : DispatchQueue.main.sync(execute: make)
    }
}

/// MailKit hands us non-Sendable completion handlers; we call each exactly once.
private struct Unchecked<T>: @unchecked Sendable { let value: T; init(_ v: T) { value = v } }
