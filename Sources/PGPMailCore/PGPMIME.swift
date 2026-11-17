import Foundation

/// RFC 3156 PGP/MIME handling: classification, decryption and signature verification.
public struct PGPMIME: Sendable {
    public enum Kind: Sendable, Equatable { case encrypted, signed, plain }

    public struct SignatureInfo: Sendable, Equatable, Codable {
        /// `stale`: mathematically correct, but the signature or key is expired, or the key is revoked.
        public enum State: String, Sendable, Equatable, Codable { case good, bad, unknownKey, stale }
        public var state: State
        public var keyID: String
        public var userID: String
        public var fingerprint: String?
        /// All e-mail addresses in the signing key's user IDs (lowercased).
        public var emails: [String] = []
        /// False when the signature is good but the key does not belong to the sender address (From:).
        /// A valid signature by *someone* must not look like a signature by the sender.
        public var matchesSender: Bool = true
    }

    public struct Decoded: Sendable, Codable {
        /// Full RFC 5322 message with the PGP structure removed.
        public var message: Data
        public var wasEncrypted: Bool
        public var signature: SignatureInfo?
    }

    public enum DecodeError: Error, Sendable {
        case malformed(String)
        /// Encrypted to keys we do not hold; `recipientKeyIDs` are the key IDs the message was encrypted to.
        case noSecretKey(recipientKeyIDs: [String])
        case decryptionFailed(String)
    }

    let gpg: GPG
    public init(gpg: GPG) { self.gpg = gpg }

    public static func classify(_ entity: MIMEEntity) -> Kind {
        guard let ct = entity.contentType else { return .plain }
        switch (ct.type, ct.parameters["protocol"]?.lowercased()) {
        case ("multipart/encrypted", "application/pgp-encrypted"): return .encrypted
        case ("multipart/signed", "application/pgp-signature"): return .signed
        default: return .plain
        }
    }

    public func decode(_ raw: Data) throws -> Decoded {
        let outer = MIMEEntity(data: raw)
        var result: Decoded
        switch Self.classify(outer) {
        case .plain:
            guard Self.hasInlineArmor(raw), let inline = try decodeInline(outer) else {
                return Decoded(message: raw, wasEncrypted: false, signature: nil)
            }
            result = inline
        case .encrypted:
            result = try decodeEncrypted(outer)
        case .signed:
            result = try decodeSigned(outer)
        }
        // Keep one line-ending style throughout: Mail splits header and body at the first blank line, and
        // a CRLF header block followed by an LF body (or vice versa) has none ("empty message").
        if var sig = result.signature, let fpr = sig.fingerprint, Self.isHex(fpr) {
            sig.emails = KeyRing.emails(ofKey: fpr, using: gpg)
            let from = AddressExtractor.addresses(in: outer.header("From") ?? "")
            sig.matchesSender = !from.isEmpty && from.allSatisfy { sig.emails.contains($0) }
            result.signature = sig
        }
        let usesCRLF = (String(data: raw, encoding: .isoLatin1) ?? "").contains("\r\n")
        result.message = Self.normalizeLineEndings(result.message, crlf: usesCRLF)
        return result
    }

    static func isHex(_ s: String) -> Bool { !s.isEmpty && s.allSatisfy(\.isHexDigit) }

    public static func normalizeLineEndings(_ data: Data, crlf: Bool) -> Data {
        guard let s = String(data: data, encoding: .isoLatin1) else { return data }
        let lf = s.replacingOccurrences(of: "\r\n", with: "\n")
        return (crlf ? lf.replacingOccurrences(of: "\n", with: "\r\n") : lf).data(using: .isoLatin1) ?? data
    }

    private func decodeEncrypted(_ outer: MIMEEntity) throws -> Decoded {
        guard let parts = outer.multipartParts(), parts.count == 2 else { throw DecodeError.malformed(Self.describe(outer)) }
        let payload = MIMEEntity(string: parts[1]).body
        // Incomplete downloads / broken copies: no armored message in the second part → not decodable (yet).
        guard payload.contains("-----BEGIN PGP MESSAGE-----") else { throw DecodeError.malformed(Self.describe(outer)) }
        let (plain, status) = try runDecrypt(Data(payload.utf8))
        let inner = MIMEEntity(data: plain)
        var sig = Self.signature(from: status)
        var result = Self.merge(outerHeaders: outer.headers, inner: inner)

        // Encrypt-then-sign nesting: the plaintext may itself be multipart/signed.
        if Self.classify(inner) == .signed, let d = try? decodeSigned(inner) {
            sig = d.signature
            result = Self.merge(outerHeaders: outer.headers, inner: MIMEEntity(data: d.message))
        }
        return Decoded(message: result.data, wasEncrypted: true, signature: sig)
    }

    /// Runs `gpg --decrypt` and maps failures to `DecodeError`. Also handles cleartext signatures
    /// (no DECRYPTION_OKAY, but a signature status).
    func runDecrypt(_ input: Data, allowSignatureOnly: Bool = false) throws -> (Data, [GPGStatus]) {
        let r = try gpg.run(["--decrypt"], stdin: input)
        let status = r.status
        let hasSig = status.contains { switch $0 { case .goodSignature, .badSignature, .errorSignature, .staleSignature: true; default: false } }
        if status.contains(.decryptionOkay) || (allowSignatureOnly && hasSig) { return (r.stdout, status) }
        let recipients = status.compactMap { if case .encryptedTo(let k) = $0 { k } else { nil } }
        // NO_SECKEY is also printed for recipients we do not hold while another recipient key IS ours
        // (multi-recipient mails). Only report "no secret key" if none of the recipient keys is ours.
        let ours = (try? KeyRing.secretKeys(using: gpg)) ?? []
        let weHoldOne = recipients.contains { id in ours.contains { $0.owns(keyID: id) } }
        if !weHoldOne, status.contains(where: { if case .noSecretKey = $0 { true } else { false } }) {
            throw DecodeError.noSecretKey(recipientKeyIDs: recipients)
        }
        if status.contains(where: { if case .other(let t) = $0 { t.hasPrefix("NODATA") } else { false } }) {
            throw DecodeError.malformed("no OpenPGP data")
        }
        throw DecodeError.decryptionFailed(r.stderr)
    }

    private func decodeSigned(_ outer: MIMEEntity) throws -> Decoded {
        guard let parts = outer.multipartParts(), parts.count == 2 else { throw DecodeError.malformed(Self.describe(outer)) }
        let signedPart = parts[0]
        let sigBody = MIMEEntity(string: parts[1]).body

        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("sig-\(UUID().uuidString).asc")
        try Data(sigBody.utf8).write(to: tmp)
        defer { try? FileManager.default.removeItem(at: tmp) }

        // RFC 3156: the signed data is the first part canonicalised to CRLF.
        let canonical = signedPart.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\n", with: "\r\n")
        let r = try gpg.run(["--verify", tmp.path, "-"], stdin: canonical.data(using: .isoLatin1) ?? Data())
        let sig = Self.signature(from: r.status)

        let content = MIMEEntity(string: signedPart)
        return Decoded(message: Self.merge(outerHeaders: outer.headers, inner: content).data,
                       wasEncrypted: false, signature: sig)
    }

    /// Structure-only summary (no content) for diagnostics.
    static func describe(_ e: MIMEEntity) -> String {
        let ct = e.contentType
        var out = "ct=\(ct?.type ?? "-") params=\(ct?.parameters.keys.sorted().joined(separator: ",") ?? "-") bodyLen=\(e.body.count)"
        if let parts = e.multipartParts() {
            let types = parts.map { MIMEEntity(string: $0).contentType?.type ?? "?" }
            out += " parts=\(parts.count)[\(types.joined(separator: ","))]"
        } else { out += " parts=none boundaryFound=\(ct?.parameters["boundary"] != nil)" }
        out += " cte=\(e.header("Content-Transfer-Encoding") ?? "-")"
        return out
    }

    static func signature(from status: [GPGStatus]) -> SignatureInfo? {
        let fpr = status.compactMap { if case .validSignature(let f) = $0 { f } else { nil } }.first
        for s in status {
            switch s {
            case .goodSignature(let k, let u): return .init(state: .good, keyID: k, userID: u, fingerprint: fpr)
            case .badSignature(let k, let u): return .init(state: .bad, keyID: k, userID: u, fingerprint: nil)
            case .errorSignature(let k): return .init(state: .unknownKey, keyID: k, userID: "", fingerprint: nil)
            case .staleSignature(let k, let u, _): return .init(state: .stale, keyID: k, userID: u, fingerprint: fpr)
            default: continue
            }
        }
        return nil
    }

    /// Keeps routing/identity headers of the outer message, takes Content-* from the inner entity.
    static func merge(outerHeaders: [(name: String, value: String)], inner rawInner: MIMEEntity) -> MIMEEntity {
        let inner = stripProtectedHeaderParts(rawInner)
        let kept = outerHeaders.filter { !$0.name.lowercased().hasPrefix("content-") && $0.name.lowercased() != "mime-version" }
        let innerContent = inner.headers.filter { $0.name.lowercased().hasPrefix("content-") }
        var headers = kept
        headers.append((name: "MIME-Version", value: "1.0"))
        headers += innerContent.isEmpty ? [(name: "Content-Type", value: "text/plain")] : innerContent
        return MIMEEntity(headers: headers, body: inner.body)
    }

    /// Header protection (`protected-headers="v1"`): some senders put a copy of the headers into an extra part,
    /// either `text/rfc822-headers` or a "legacy display" `text/plain; protected-headers=...` part. It only
    /// duplicates the header block; Mail would show it as an attachment or as extra text, so it is removed.
    static func stripProtectedHeaderParts(_ entity: MIMEEntity) -> MIMEEntity {
        guard let ct = entity.contentType, ct.type == "multipart/mixed",
              ct.parameters["protected-headers"] != nil,
              let boundary = ct.parameters["boundary"], let parts = entity.multipartParts() else { return entity }
        let kept = parts.filter { part in
            guard let pct = MIMEEntity(string: part).contentType else { return true }
            return !(pct.type == "text/rfc822-headers" || (pct.type == "text/plain" && pct.parameters["protected-headers"] != nil))
        }
        guard kept.count < parts.count, !kept.isEmpty else { return entity }
        if kept.count == 1 { return MIMEEntity(string: kept[0]) }
        let body = kept.map { "--\(boundary)\r\n\($0)\r\n" }.joined() + "--\(boundary)--\r\n"
        return MIMEEntity(headers: entity.headers, body: body)
    }
}

// MARK: - Wire types shared by helper and extension

public struct DecodeFailure: Codable, Sendable, Equatable {
    public enum Kind: String, Codable, Sendable { case noSecretKey, malformed, other }
    public var kind: Kind
    /// Key IDs the message is encrypted to.
    public var recipientKeyIDs: [String] = []
    /// Recipient addresses of the message for which no private key is configured.
    public var addressesWithoutKey: [String] = []
    public var message: String = ""
    public init(kind: Kind, recipientKeyIDs: [String] = [], addressesWithoutKey: [String] = [], message: String = "") {
        self.kind = kind; self.recipientKeyIDs = recipientKeyIDs
        self.addressesWithoutKey = addressesWithoutKey; self.message = message
    }
}

public struct DecodeOutcome: Codable, Sendable {
    public var decoded: PGPMIME.Decoded?
    public var failure: DecodeFailure?
    public init(decoded: PGPMIME.Decoded?, failure: DecodeFailure?) { self.decoded = decoded; self.failure = failure }
}
