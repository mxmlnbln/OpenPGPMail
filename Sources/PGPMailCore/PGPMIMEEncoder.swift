import Foundation

/// RFC 3156 PGP/MIME encoding: multipart/signed and multipart/encrypted.
public struct PGPMIMEEncoder: Sendable {
    public struct Options: Sendable {
        public var signerFingerprint: String?          // nil → do not sign
        public var recipientFingerprints: [String]     // empty → do not encrypt
        /// Bcc recipients: encrypted with `--hidden-recipient` so their key IDs are not visible to the others.
        public var hiddenRecipientFingerprints: [String] = []
        public var trustModel: TrustModel
        public var format: SendFormat
        public init(signerFingerprint: String?, recipientFingerprints: [String], hiddenRecipientFingerprints: [String] = [],
                    trustModel: TrustModel = .always, format: SendFormat = .automatic) {
            self.signerFingerprint = signerFingerprint; self.recipientFingerprints = recipientFingerprints
            self.hiddenRecipientFingerprints = hiddenRecipientFingerprints
            self.trustModel = trustModel; self.format = format
        }
    }

    public enum EncodeError: Error, Sendable, Equatable {
        case nothingToDo
        case signingFailed(String)
        case encryptionFailed(String)
    }

    private let gpg: GPG
    public init(gpg: GPG) { self.gpg = gpg }

    public func encode(_ raw: Data, options: Options) throws -> Data {
        let wantSign = options.signerFingerprint != nil
        let wantEncrypt = !options.recipientFingerprints.isEmpty
        guard wantSign || wantEncrypt else { throw EncodeError.nothingToDo }
        // Key arguments must be plain fingerprints: never let anything else reach gpg's command line.
        let allKeys = options.recipientFingerprints + options.hiddenRecipientFingerprints + [options.signerFingerprint].compactMap { $0 }
        guard allKeys.allSatisfy(PGPMIME.isHex) else {
            throw wantEncrypt ? EncodeError.encryptionFailed("invalid key fingerprint") : EncodeError.signingFailed("invalid key fingerprint")
        }

        let outer = MIMEEntity(data: raw)
        if options.format != .pgpMIME, let inline = try encodeInline(outer, raw: raw, options: options) { return inline }
        // Mail hands us LF-only messages; returning CRLF there makes Mail's header lookups fail
        // (e.g. "Message-Id" values ending in "\r") and crash. Keep the line-ending style of the input.
        let useLF = !(String(data: raw, encoding: .isoLatin1) ?? "").contains("\r\n")
        func finish(_ e: MIMEEntity) -> Data { Self.lineEndings(e.data, lf: useLF) }
        let routing = outer.headers.filter {
            let n = $0.name.lowercased()
            return !n.hasPrefix("content-") && n != "mime-version"
        }
        var contentHeaders = outer.headers.filter { $0.name.lowercased().hasPrefix("content-") }
        if contentHeaders.isEmpty { contentHeaders = [(name: "Content-Type", value: "text/plain; charset=utf-8")] }
        let inner = MIMEEntity(headers: contentHeaders, body: outer.body)
        let canonical = Self.canonicalize(inner.serialized)
        let boundary = "=_opgpm_" + UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()

        if wantEncrypt {
            var args = ["--yes", "--armor", "--trust-model", options.trustModel.gpgName, "--encrypt"]
            if let s = options.signerFingerprint { args += ["--sign", "-u", s] }
            for r in options.recipientFingerprints { args += ["-r", r] }
            for r in options.hiddenRecipientFingerprints { args += ["-R", r] }
            let r = try gpg.run(args, stdin: canonical.data(using: .isoLatin1) ?? Data())
            guard r.exitCode == 0, !r.stdout.isEmpty else { throw EncodeError.encryptionFailed(Self.errorText(r)) }
            let armored = String(decoding: r.stdout, as: UTF8.self).replacingOccurrences(of: "\n", with: "\r\n")
            let cid = { "<\(UUID().uuidString.lowercased())@openpgpmail.invalid>" }
            let body = "--\(boundary)\r\nContent-Type: application/pgp-encrypted\r\nContent-Description: PGP/MIME version identification\r\nContent-Transfer-Encoding: 7bit\r\nContent-ID: \(cid())\r\n\r\nVersion: 1\r\n\r\n"
                + "--\(boundary)\r\nContent-Type: application/octet-stream; name=\"encrypted.asc\"\r\nContent-Description: OpenPGP encrypted message\r\nContent-Disposition: inline; filename=\"encrypted.asc\"\r\nContent-Transfer-Encoding: 7bit\r\nContent-ID: \(cid())\r\n\r\n"
                + armored + "\r\n--\(boundary)--\r\n"
            let headers = routing + [
                (name: "MIME-Version", value: "1.0"),
                (name: "Content-Type", value: "multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"\(boundary)\""),
            ]
            return finish(MIMEEntity(headers: headers, body: body))
        }

        // sign only
        let signer = options.signerFingerprint!
        let r = try gpg.run(["--yes", "--armor", "--detach-sign", "-u", signer], stdin: canonical.data(using: .isoLatin1) ?? Data())
        guard r.exitCode == 0, !r.stdout.isEmpty else { throw EncodeError.signingFailed(Self.errorText(r)) }
        let armored = String(decoding: r.stdout, as: UTF8.self).replacingOccurrences(of: "\n", with: "\r\n")
        let micalg = Self.micalg(from: r.status)
        let body = "--\(boundary)\r\n" + canonical
            + "\r\n--\(boundary)\r\nContent-Type: application/pgp-signature; name=\"signature.asc\"\r\nContent-Description: OpenPGP digital signature\r\nContent-Disposition: attachment; filename=\"signature.asc\"\r\nContent-Transfer-Encoding: 7bit\r\nContent-ID: <\(UUID().uuidString.lowercased())@openpgpmail.invalid>\r\n\r\n"
            + armored + "\r\n--\(boundary)--\r\n"
        let headers = routing + [
            (name: "MIME-Version", value: "1.0"),
            (name: "Content-Type", value: "multipart/signed; protocol=\"application/pgp-signature\"; micalg=\(micalg); boundary=\"\(boundary)\""),
        ]
        return finish(MIMEEntity(headers: headers, body: body))
    }

    /// Inline PGP for a single-part text/plain message. Returns nil when the message is not suitable
    /// (multipart, HTML, 8-bit text that must be clear-signed) so the caller falls back to PGP/MIME.
    func encodeInline(_ outer: MIMEEntity, raw: Data, options: Options) throws -> Data? {
        let type = outer.contentType?.type ?? "text/plain"
        guard type == "text/plain" else { return nil }
        let cs = (outer.contentType?.parameters["charset"] ?? "utf-8").lowercased()
        guard ["utf-8", "us-ascii", "utf8"].contains(cs) else { return nil }
        let text = PGPMIME.decodeTransfer(outer.body, cte: outer.header("Content-Transfer-Encoding"))
        let wantEncrypt = !options.recipientFingerprints.isEmpty
        // Clear-signed text stays readable and would need 8-bit transport for non-ASCII: use PGP/MIME instead.
        if !wantEncrypt, text.unicodeScalars.contains(where: { $0.value > 127 }) { return nil }
        let useLF = !(String(data: raw, encoding: .isoLatin1) ?? "").contains("\r\n")
        let input = (text.replacingOccurrences(of: "\r\n", with: "\n")).data(using: .isoLatin1) ?? Data()

        let armored: String
        if wantEncrypt {
            var args = ["--yes", "--armor", "--trust-model", options.trustModel.gpgName, "--encrypt"]
            if let s = options.signerFingerprint { args += ["--sign", "-u", s] }
            for r in options.recipientFingerprints { args += ["-r", r] }
            for r in options.hiddenRecipientFingerprints { args += ["-R", r] }
            let r = try gpg.run(args, stdin: input)
            guard r.exitCode == 0, !r.stdout.isEmpty else { throw EncodeError.encryptionFailed(Self.errorText(r)) }
            armored = String(decoding: r.stdout, as: UTF8.self)
        } else {
            let r = try gpg.run(["--yes", "--clearsign", "-u", options.signerFingerprint!], stdin: input)
            guard r.exitCode == 0, !r.stdout.isEmpty else { throw EncodeError.signingFailed(Self.errorText(r)) }
            armored = String(decoding: r.stdout, as: UTF8.self)
        }
        var headers = outer.headers.filter { !["content-type", "content-transfer-encoding", "mime-version"].contains($0.name.lowercased()) }
        headers += [(name: "MIME-Version", value: "1.0"),
                    (name: "Content-Type", value: "text/plain; charset=utf-8"),
                    (name: "Content-Transfer-Encoding", value: "7bit")]
        let body = armored.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\n", with: "\r\n")
        return Self.lineEndings(MIMEEntity(headers: headers, body: body).data, lf: useLF)
    }

    /// Converts CRLF to LF (or leaves the data alone). Signatures are made over the canonical CRLF form,
    /// which receivers re-create before verifying, so LF on the wire is fine.
    public static func lineEndings(_ data: Data, lf: Bool) -> Data {
        guard lf, let s = String(data: data, encoding: .isoLatin1) else { return data }
        return s.replacingOccurrences(of: "\r\n", with: "\n").data(using: .isoLatin1) ?? data
    }

    static func canonicalize(_ s: String) -> String {
        s.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\n", with: "\r\n")
    }

    /// `SIG_CREATED <type> <pk-algo> <hash-algo> …` → RFC 3156 micalg value.
    static func micalg(from status: [GPGStatus]) -> String {
        let names = [1: "md5", 2: "sha1", 3: "ripemd160", 8: "sha256", 9: "sha384", 10: "sha512", 11: "sha224"]
        for s in status {
            if case .other(let t) = s, t.hasPrefix("SIG_CREATED "), let h = Int(t.split(separator: " ")[safe: 3] ?? "") {
                return "pgp-" + (names[h] ?? "sha256")
            }
        }
        return "pgp-sha256"
    }

    static func errorText(_ r: GPGResult) -> String {
        let human = r.stderr.split(whereSeparator: \.isNewline).filter { !$0.hasPrefix("[GNUPG:]") }.joined(separator: " ")
        return human.isEmpty ? "gpg exit \(r.exitCode)" : human
    }
}

// MARK: - Recipient key lookup

extension KeyRing {
    /// Fingerprint of a valid public key usable for encryption to `email`, if any.
    public static func encryptionKeyFingerprint(for email: String, using gpg: GPG, trust: TrustModel = .always) -> String? {
        guard AddressExtractor.isValid(email),
              let r = try? gpg.run(["--list-keys", "--with-fingerprint", "--with-subkey-fingerprints", "--", "<\(email.lowercased())>"]),
              r.exitCode == 0 else { return nil }
        return parsePublicKeys(String(decoding: r.stdout, as: UTF8.self), requireTrust: trust == .webOfTrust).first
    }

    private static let wkdMisses = MissCache()

    /// Like `encryptionKeyFingerprint`, but when no local key exists and `wkd` is true, tries Web Key Directory
    /// (`gpg --locate-keys`, which imports a found key into the keyring). Failed lookups are remembered for
    /// 10 minutes so composing a mail does not hit the network on every status request.
    public static func locateEncryptionKey(for email: String, using gpg: GPG, trust: TrustModel = .always, wkd: Bool) -> String? {
        if let f = encryptionKeyFingerprint(for: email, using: gpg, trust: trust) { return f }
        let addr = email.lowercased()
        guard wkd, AddressExtractor.isValid(addr), !wkdMisses.recentlyMissed(addr) else { return nil }
        _ = try? gpg.run(["--auto-key-locate", "clear,wkd", "--locate-keys", "--", addr], timeout: 20)
        let found = encryptionKeyFingerprint(for: addr, using: gpg, trust: trust)
        if found == nil { wkdMisses.record(addr) }
        return found
    }

    /// First valid primary key that has a valid encryption capability (primary 'E' or an 'e' subkey).
    static func parsePublicKeys(_ colons: String, requireTrust: Bool = false) -> [String] {
        var result: [String] = []
        var primaryFpr = "", primaryOK = false, canEncrypt = false
        func flush() { if primaryOK && canEncrypt && !primaryFpr.isEmpty { result.append(primaryFpr) }; primaryFpr = ""; primaryOK = false; canEncrypt = false }
        var expectPrimaryFpr = false
        for line in colons.split(whereSeparator: \.isNewline) {
            let f = line.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
            switch f.first {
            case "pub":
                flush()
                let v = f[safe: 1] ?? ""
                primaryOK = !v.contains(where: { "redni".contains($0) })   // revoked, expired, disabled, invalid, (n)ever trust
                if requireTrust { primaryOK = primaryOK && v.contains(where: { "mfus".contains($0) }) }   // marginal, full, ultimate, (s)pecial
                canEncrypt = (f[safe: 11] ?? "").contains("E")
                expectPrimaryFpr = true
            case "sub":
                let v = f[safe: 1] ?? ""
                if !v.contains(where: { "red".contains($0) }), (f[safe: 11] ?? "").contains("e") { canEncrypt = true }
            case "fpr":
                if expectPrimaryFpr { primaryFpr = f[safe: 9] ?? ""; expectPrimaryFpr = false }
            default: break
            }
        }
        flush()
        return result
    }
}

// MARK: - Wire types

public struct EncodingRequest: Codable, Sendable {
    public var from: String
    public var recipients: [String]
    /// Bcc recipients (not contained in `recipients`).
    public var hiddenRecipients: [String]
    public var sign: Bool
    public var encrypt: Bool
    public var raw: Data?
    public init(from: String, recipients: [String], hiddenRecipients: [String] = [], sign: Bool, encrypt: Bool, raw: Data? = nil) {
        self.from = from; self.recipients = recipients; self.hiddenRecipients = hiddenRecipients
        self.sign = sign; self.encrypt = encrypt; self.raw = raw
    }
}

public struct EncodingStatus: Codable, Sendable, Equatable {
    public var canSign: Bool
    public var canEncrypt: Bool
    public var addressesFailingEncryption: [String]
    public var error: String?
    public init(canSign: Bool, canEncrypt: Bool, addressesFailingEncryption: [String], error: String?) {
        self.canSign = canSign; self.canEncrypt = canEncrypt
        self.addressesFailingEncryption = addressesFailingEncryption; self.error = error
    }
}

public struct EncodeOutcome: Codable, Sendable {
    public var raw: Data?
    public var signingError: String?
    public var encryptionError: String?
    public init(raw: Data? = nil, signingError: String? = nil, encryptionError: String? = nil) {
        self.raw = raw; self.signingError = signingError; self.encryptionError = encryptionError
    }
}

private final class MissCache: @unchecked Sendable {
    private let lock = NSLock()
    private var misses: [String: Date] = [:]
    func recentlyMissed(_ a: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return misses[a].map { Date().timeIntervalSince($0) < 600 } ?? false
    }
    func record(_ a: String) { lock.lock(); misses[a] = Date(); lock.unlock() }
}
