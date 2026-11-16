import Foundation

public struct UserID: Sendable, Equatable, Codable, Hashable {
    public var name: String
    public var email: String?   // lowercased
}

public struct SecretKey: Sendable, Equatable, Codable, Identifiable, Hashable {
    public var id: String { fingerprint }
    public var fingerprint: String
    public var keyID: String            // long key ID (16 hex)
    public var subkeyIDs: [String]
    public var userIDs: [UserID]
    public var algorithm: String        // e.g. "rsa4096"
    public var created: Date?
    public var isExpired: Bool
    public var isRevoked: Bool

    public var isUsable: Bool { !isExpired && !isRevoked }
    public var emails: [String] { userIDs.compactMap(\.email) }
    public var displayName: String { userIDs.first.map { $0.name.isEmpty ? ($0.email ?? keyID) : $0.name } ?? keyID }

    /// True if `id` (16 hex long ID or fingerprint tail) names this key or one of its subkeys.
    public func owns(keyID id: String) -> Bool {
        let u = id.uppercased()
        return keyID == u || fingerprint.hasSuffix(u) || subkeyIDs.contains { $0 == u }
    }
}

public enum KeyRing {
    public static func secretKeys(using gpg: GPG) throws -> [SecretKey] {
        let r = try gpg.run(["--list-secret-keys", "--with-fingerprint", "--with-subkey-fingerprints", "--keyid-format", "long"])
        return parse(String(decoding: r.stdout, as: UTF8.self))
    }

    /// Parses `gpg --with-colons` output of `--list-secret-keys`.
    public static func parse(_ colons: String) -> [SecretKey] {
        var keys: [SecretKey] = []
        var cur: SecretKey?
        var expectFpr: Bool = false      // next fpr line belongs to primary key
        var inSubkey = false
        var lastSubkeyIndex: Int?
        func flush() { if let k = cur { keys.append(k) }; cur = nil }

        for line in colons.split(whereSeparator: \.isNewline) {
            let f = line.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
            guard let tag = f.first else { continue }
            switch tag {
            case "sec":
                flush()
                inSubkey = false
                let validity = f[safe: 1] ?? ""
                cur = SecretKey(fingerprint: "", keyID: f[safe: 4] ?? "", subkeyIDs: [], userIDs: [],
                                algorithm: Self.algo(f[safe: 3], f[safe: 2]),
                                created: (f[safe: 5]).flatMap(TimeInterval.init).map(Date.init(timeIntervalSince1970:)),
                                isExpired: validity.contains("e"), isRevoked: validity.contains("r"))
                expectFpr = true
            case "ssb":
                inSubkey = true
                if let id = f[safe: 4], !id.isEmpty { cur?.subkeyIDs.append(id) }
                lastSubkeyIndex = (cur?.subkeyIDs.count ?? 1) - 1
            case "fpr":
                if inSubkey { _ = lastSubkeyIndex } else if expectFpr, let fp = f[safe: 9] { cur?.fingerprint = fp; expectFpr = false }
            case "uid":
                if let raw = f[safe: 9] { cur?.userIDs.append(Self.parseUserID(raw)) }
            default: break
            }
        }
        flush()
        return keys.filter { !$0.fingerprint.isEmpty }
    }

    static func algo(_ id: String?, _ bits: String?) -> String {
        let name = ["1": "rsa", "17": "dsa", "16": "elg", "18": "ecdh", "19": "ecdsa", "22": "ed25519"][id ?? ""] ?? "algo\(id ?? "?")"
        return name == "ed25519" ? name : name + (bits ?? "")
    }

    static func parseUserID(_ raw: String) -> UserID {
        // gpg escapes ":" as \x3a in colon listings
        let s = raw.replacingOccurrences(of: "\\x3a", with: ":")
        if let lt = s.lastIndex(of: "<"), let gt = s.lastIndex(of: ">"), lt < gt {
            let email = String(s[s.index(after: lt)..<gt]).lowercased()
            let name = s[..<lt].trimmingCharacters(in: .whitespaces)
            return UserID(name: name, email: email)
        }
        return UserID(name: s, email: s.contains("@") ? s.lowercased() : nil)
    }
}

// MARK: - Address → key configuration

/// How much a recipient key must be trusted before we encrypt to it.
public enum TrustModel: String, Codable, Sendable, CaseIterable {
    /// Encrypt to any valid key in the keyring (the keyring is the user's decision). Default.
    case always
    /// GnuPG's web of trust: the key must be at least marginally valid (signed by a trusted key / ultimately trusted).
    case webOfTrust

    var gpgName: String { self == .always ? "always" : "pgp" }
}

/// Which format outgoing mails use. Inline is only possible for plain-text mails; others fall back to PGP/MIME.
public enum SendFormat: String, Codable, Sendable, CaseIterable {
    /// Inline PGP for plain-text mails, PGP/MIME for everything else (HTML, attachments). Default.
    case automatic
    case pgpMIME
    /// Legacy value from earlier configs; treated as `automatic` (see `KeyConfig.init(from:)`).
    case inline
}

public struct KeyConfig: Codable, Sendable, Equatable {
    public var defaultFingerprint: String?
    /// lowercased e-mail address → key fingerprint
    public var accounts: [String: String] = [:]
    public var trustModel: TrustModel = .always
    /// Look up missing recipient keys via Web Key Directory (contacts the recipient's mail domain).
    public var wkdLookup: Bool = true
    public var sendFormat: SendFormat = .automatic

    // Tolerant decoding: missing keys fall back to defaults (hand-edited or older config files).
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        defaultFingerprint = try c.decodeIfPresent(String.self, forKey: .defaultFingerprint)
        accounts = try c.decodeIfPresent([String: String].self, forKey: .accounts) ?? [:]
        trustModel = (try? c.decodeIfPresent(TrustModel.self, forKey: .trustModel)) ?? .always
        wkdLookup = try c.decodeIfPresent(Bool.self, forKey: .wkdLookup) ?? true
        sendFormat = (try? c.decodeIfPresent(SendFormat.self, forKey: .sendFormat)) ?? .automatic
        if sendFormat == .inline { sendFormat = .automatic }
    }

    public init(defaultFingerprint: String? = nil, accounts: [String: String] = [:], trustModel: TrustModel = .always,
                wkdLookup: Bool = true, sendFormat: SendFormat = .automatic) {
        self.defaultFingerprint = defaultFingerprint; self.accounts = accounts
        self.trustModel = trustModel; self.wkdLookup = wkdLookup; self.sendFormat = sendFormat
    }

    /// Real home directory (the sandbox container's HOME is not what we want in unsandboxed processes).
    public static var defaultURL: URL {
        let home = getpwuid(getuid()).map { String(cString: $0.pointee.pw_dir) } ?? NSHomeDirectory()
        return URL(fileURLWithPath: home).appendingPathComponent("Library/Application Support/OpenPGPMail/config.json")
    }

    public static func load(from url: URL = defaultURL) -> KeyConfig {
        (try? JSONDecoder().decode(KeyConfig.self, from: Data(contentsOf: url))) ?? KeyConfig()
    }

    public func save(to url: URL = defaultURL) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let enc = JSONEncoder(); enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        try enc.encode(self).write(to: url, options: .atomic)
    }
}

public enum KeyResolution: Sendable, Equatable {
    case configured(SecretKey)      // explicit mapping
    case automatic(SecretKey)       // exactly one usable key has this address in a user ID
    case ambiguous([SecretKey])     // several candidates, user must choose
    case none                       // no private key for this address
}

public enum KeyResolver {
    public static func resolve(address: String, keys: [SecretKey], config: KeyConfig) -> KeyResolution {
        let addr = address.lowercased()
        if let fpr = config.accounts[addr], let k = keys.first(where: { $0.fingerprint == fpr }), k.isUsable { return .configured(k) }
        let matches = keys.filter { $0.isUsable && $0.emails.contains(addr) }
        switch matches.count {
        case 0:
            if let fpr = config.defaultFingerprint, let k = keys.first(where: { $0.fingerprint == fpr && $0.isUsable }) { return .configured(k) }
            return .none
        case 1: return .automatic(matches[0])
        default: return .ambiguous(matches)
        }
    }
}

public enum AddressExtractor {
    /// Conservative address syntax. Also guarantees the string cannot be read as a gpg option
    /// (must not start with "-") and contains no characters special to gpg's user-ID search ("<", ">", "=", "*", …).
    static let pattern = "[A-Za-z0-9_][A-Za-z0-9._%+\\-]*@[A-Za-z0-9][A-Za-z0-9.\\-]*\\.[A-Za-z]{2,}"

    public static func isValid(_ address: String) -> Bool {
        address.range(of: "^" + pattern + "$", options: .regularExpression) != nil
    }

    /// All e-mail addresses in a piece of header text (lowercased, unique, in order).
    public static func addresses(in text: String) -> [String] {
        guard let re = try? NSRegularExpression(pattern: pattern) else { return [] }
        let ns = text as NSString
        var seen = Set<String>(), out: [String] = []
        for m in re.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
            let a = ns.substring(with: m.range).lowercased()
            if seen.insert(a).inserted { out.append(a) }
        }
        return out
    }

    /// E-mail addresses from the recipient headers of a message.
    public static func recipients(of entity: MIMEEntity) -> [String] {
        let names = ["to", "cc", "delivered-to", "x-original-to"]
        return addresses(in: entity.headers.filter { names.contains($0.name.lowercased()) }.map(\.value).joined(separator: " "))
    }
}

extension KeyRing {
    /// E-mail addresses of all (non-revoked) user IDs of the public key with this fingerprint.
    public static func emails(ofKey fingerprint: String, using gpg: GPG) -> [String] {
        guard fingerprint.allSatisfy(\.isHexDigit), !fingerprint.isEmpty,
              let r = try? gpg.run(["--list-keys", "--", fingerprint]), r.exitCode == 0 else { return [] }
        var out: [String] = []
        for line in String(decoding: r.stdout, as: UTF8.self).split(whereSeparator: \.isNewline) {
            let f = line.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
            guard f.first == "uid", !(f[safe: 1] ?? "").contains("r"), let raw = f[safe: 9] else { continue }
            if let e = parseUserID(raw).email, !out.contains(e) { out.append(e) }
        }
        return out
    }
}

public struct KeyImportResult: Sendable, Equatable {
    public var processed = 0
    public var imported = 0
    public var unchanged = 0
    public var secretImported = 0
    public var secretUnchanged = 0
    public var succeeded: Bool
    public var message: String
}

extension KeyRing {
    /// Imports a (public and/or secret) key file via `gpg --import`. Passphrase prompts for secret keys
    /// are handled by gpg-agent / pinentry.
    public static func importKey(at url: URL, using gpg: GPG) throws -> KeyImportResult {
        let r = try gpg.run(["--import", "--", url.path])
        var res = KeyImportResult(succeeded: false, message: "")
        for line in r.statusText.split(whereSeparator: \.isNewline) where line.hasPrefix("[GNUPG:] IMPORT_RES ") {
            // count no_user_id imported unchanged n_uids n_subk n_sigs n_revoc sec_read sec_imported sec_dups skipped_new_keys
            let n = line.dropFirst(20).split(separator: " ").compactMap { Int($0) }
            if n.count >= 11 {
                res.processed = n[0]; res.imported = n[2]; res.unchanged = n[3]
                res.secretImported = n[9]; res.secretUnchanged = n[10]
            }
        }
        res.succeeded = r.exitCode == 0 && res.processed > 0
        res.message = res.succeeded ? "" : r.stderr.split(whereSeparator: \.isNewline).filter { !$0.hasPrefix("[GNUPG:]") }.joined(separator: "\n")
        return res
    }
}

public struct KeyTestResult: Sendable, Equatable {
    public var ok: Bool
    public var detail: String
}

extension KeyRing {
    /// Encrypts a short text to `key` and decrypts it again. Triggers the pinentry passphrase prompt,
    /// so it verifies passphrase and key material independently of Mail.
    public static func testDecryption(of key: SecretKey, using gpg: GPG) throws -> KeyTestResult {
        let enc = try gpg.run(["--armor", "--trust-model", "always", "-r", key.fingerprint, "--encrypt"], stdin: Data("opgpm-selftest".utf8))
        guard enc.exitCode == 0, !enc.stdout.isEmpty else {
            return .init(ok: false, detail: "Verschlüsseln an diesen Schlüssel nicht möglich (kein Verschlüsselungs-Unterschlüssel?).")
        }
        let dec = try gpg.run(["--decrypt"], stdin: enc.stdout)
        let status = dec.status
        if status.contains(.decryptionOkay) { return .init(ok: true, detail: "Entschlüsselung erfolgreich.") }
        let code: Int? = status.compactMap { s -> Int? in
            if case .other(let t) = s, t.hasPrefix("ERROR pkdecrypt_failed "), let n = Int(t.split(separator: " ").last ?? "") { return n & 0xFFFF }
            return nil
        }.first
        let reason: String
        switch code {
        case 99?, 198?: reason = "Passphrase-Eingabe abgebrochen."
        case 11?: reason = "Passphrase falsch."
        case 7?: reason = "Der Schlüssel konnte nicht verwendet werden („fehlerhafter geheimer Schlüssel“). Meist falsche Passphrase oder eine beschädigte Schlüsseldatei."
        default: reason = "Entschlüsselung fehlgeschlagen\(code.map { " (gpg-Fehlercode \($0))" } ?? "")."
        }
        return .init(ok: false, detail: reason)
    }
}
