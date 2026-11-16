import Foundation

/// Inline PGP: an ASCII-armored block inside a text/plain body (RFC 4880 §6, no PGP/MIME).
extension PGPMIME {
    static let beginMarkers = ["-----BEGIN PGP MESSAGE-----", "-----BEGIN PGP SIGNED MESSAGE-----"]

    /// Cheap pre-check on the raw bytes (the extension is called for every message).
    public static func hasInlineArmor(_ raw: Data) -> Bool {
        guard let s = String(data: raw, encoding: .isoLatin1) else { return false }
        return beginMarkers.contains { lineStart(of: $0, in: s, from: s.startIndex) != nil }
    }

    struct ArmorRange { var range: Range<String.Index>; var encrypted: Bool }

    /// First occurrence of `marker` at the beginning of a line. Quoted blocks ("> -----BEGIN …") do not count.
    static func lineStart(of marker: String, in text: String, from: String.Index) -> Range<String.Index>? {
        var search = from
        while let r = text.range(of: marker, range: search..<text.endIndex) {
            if r.lowerBound == text.startIndex { return r }
            let before = text[text.index(before: r.lowerBound)]
            if before == "\n" || before == "\r\n" || before == "\r" { return r }
            search = r.upperBound
        }
        return nil
    }

    /// First armored block in `text` (encrypted message or cleartext signature).
    static func findArmor(in text: String) -> ArmorRange? {
        guard let begin = beginMarkers.compactMap({ lineStart(of: $0, in: text, from: text.startIndex) })
            .min(by: { $0.lowerBound < $1.lowerBound }) else { return nil }
        let encrypted = !text[begin].contains("SIGNED")
        let endMarker = encrypted ? "-----END PGP MESSAGE-----" : "-----END PGP SIGNATURE-----"
        guard let end = lineStart(of: endMarker, in: text, from: begin.upperBound) else { return nil }
        return ArmorRange(range: begin.lowerBound..<end.upperBound, encrypted: encrypted)
    }

    /// Decodes quoted-printable / base64 transfer encoding of a body (as Latin-1 bytes).
    static func decodeTransfer(_ body: String, cte: String?) -> String {
        switch cte?.lowercased() {
        case "quoted-printable":
            var out = [UInt8](), bytes = Array(body.utf8), i = 0
            while i < bytes.count {
                let c = bytes[i]
                if c == UInt8(ascii: "="), i + 1 < bytes.count {
                    if bytes[i + 1] == 10 { i += 2; continue }                                   // soft break (LF)
                    if bytes[i + 1] == 13, i + 2 < bytes.count, bytes[i + 2] == 10 { i += 3; continue }   // soft break (CRLF)
                    if i + 2 < bytes.count, let v = UInt8(String(decoding: bytes[i + 1...i + 2], as: UTF8.self), radix: 16) {
                        out.append(v); i += 3; continue
                    }
                }
                out.append(c); i += 1
            }
            return String(data: Data(out), encoding: .isoLatin1) ?? body
        case "base64":
            let d = Data(base64Encoded: body, options: .ignoreUnknownCharacters) ?? Data()
            return String(data: d, encoding: .isoLatin1) ?? body
        default:
            return body
        }
    }

    /// Decrypts / verifies an inline-armored text body. Returns nil if there is nothing we can safely handle.
    ///
    /// Only two shapes are accepted, to rule out "direct exfiltration" (EFAIL-style) tricks where an attacker
    /// wraps someone else's ciphertext between HTML parts of their own:
    ///  - a single text/plain message, or
    ///  - a multipart message without any HTML part, whose first text/plain part carries the armor
    ///    (typical: text + attachments).
    func decodeInline(_ outer: MIMEEntity) throws -> Decoded? {
        if let ct = outer.contentType, ct.type.hasPrefix("multipart/") {
            guard let parts = outer.multipartParts(), !outer.body.lowercased().contains("text/html") else { return nil }
            for part in parts {
                let e = MIMEEntity(string: part)
                guard (e.contentType?.type ?? "text/plain") == "text/plain" else { continue }
                guard let (newBody, decoded) = try processText(e) else { return nil }   // only the first text part
                var fixed = e
                fixed.body = newBody
                fixed.headers = Self.textHeaders(e.headers)
                guard let r = outer.body.range(of: part) else { return nil }
                var out = outer
                out.body = outer.body.replacingCharacters(in: r, with: fixed.serialized)
                return Decoded(message: out.data, wasEncrypted: decoded.wasEncrypted, signature: decoded.signature)
            }
            return nil
        }
        guard (outer.contentType?.type ?? "text/plain") == "text/plain" else { return nil }
        guard let (newBody, decoded) = try processText(outer) else { return nil }
        var out = outer
        out.body = newBody
        out.headers = Self.textHeaders(outer.headers)
        return Decoded(message: out.data, wasEncrypted: decoded.wasEncrypted, signature: decoded.signature)
    }

    /// Returns the new body text (UTF-8 bytes held as Latin-1) and result metadata, or nil if the part has no armor.
    private func processText(_ e: MIMEEntity) throws -> (String, Decoded)? {
        let text = Self.decodeTransfer(e.body, cte: e.header("Content-Transfer-Encoding"))
        guard let armor = Self.findArmor(in: text) else { return nil }
        let block = String(text[armor.range])
        let (plain, status) = try runDecrypt(block.data(using: .isoLatin1) ?? Data(), allowSignatureOnly: !armor.encrypted)
        let decryptedText = String(data: plain, encoding: .isoLatin1) ?? ""
        let charset = e.contentType?.parameters["charset"]
        let before = Self.toUTF8(String(text[..<armor.range.lowerBound]), charset: charset)
        let after = Self.toUTF8(String(text[armor.range.upperBound...]), charset: charset)
        var newBody = decryptedText
        // Text outside the armor is neither signed nor encrypted. Mark the protected part so that nobody can
        // wrap their own words around somebody else's signed text and have it all look verified.
        if !(before + after).trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            let what = armor.encrypted ? "verschlüsselten" : "signierten"
            func mark(_ s: String) -> String { String(data: Data(s.utf8), encoding: .isoLatin1) ?? s }
            newBody = before + mark("\n[OpenPGP: Beginn des \(what) Teils – Text außerhalb ist NICHT geschützt]\n")
                + decryptedText + mark("\n[OpenPGP: Ende des \(what) Teils]\n") + after
        }
        return (newBody, Decoded(message: Data(), wasEncrypted: armor.encrypted, signature: Self.signature(from: status)))
    }

    /// Re-encodes text held as Latin-1 bytes from `charset` to UTF-8 bytes (again held as Latin-1).
    static func toUTF8(_ s: String, charset: String?) -> String {
        let enc: String.Encoding
        switch (charset ?? "us-ascii").lowercased() {
        case "utf-8", "utf8", "us-ascii", "ascii": return s
        case "iso-8859-1", "latin1": enc = .isoLatin1
        case "iso-8859-15": enc = String.Encoding(rawValue: CFStringConvertEncodingToNSStringEncoding(CFStringEncoding(CFStringEncodings.isoLatin9.rawValue)))
        case "windows-1252", "cp1252": enc = .windowsCP1252
        default: return s
        }
        guard let bytes = s.data(using: .isoLatin1), let decoded = String(data: bytes, encoding: enc) else { return s }
        return String(data: Data(decoded.utf8), encoding: .isoLatin1) ?? s
    }

    /// The decrypted bytes are almost always UTF-8; tell Mail so and drop the old transfer encoding.
    static func textHeaders(_ headers: [(name: String, value: String)]) -> [(name: String, value: String)] {
        var h = headers.filter { !["content-type", "content-transfer-encoding"].contains($0.name.lowercased()) }
        h.append((name: "Content-Type", value: "text/plain; charset=utf-8"))
        h.append((name: "Content-Transfer-Encoding", value: "8bit"))
        return h
    }
}
