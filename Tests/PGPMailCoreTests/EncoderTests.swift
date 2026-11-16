import Testing
import Foundation
@testable import PGPMailCore
@testable import PGPMailXPC

private func tempHome() throws -> URL {
    let h = URL(fileURLWithPath: "/tmp/pgh-\(UUID().uuidString.prefix(8))")
    try FileManager.default.createDirectory(at: h, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    return h
}
private func cleanup(_ h: URL) {
    let p = Process(); p.executableURL = GPGTestSupport.gpgconf
    p.arguments = ["--kill", "gpg-agent"]; p.environment = ["GNUPGHOME": h.path]; try? p.run(); p.waitUntilExit()
    try? FileManager.default.removeItem(at: h)
}
private func makeKey(_ g: GPG, _ uid: String) throws -> SecretKey {
    _ = try g.run(["--passphrase", "", "--pinentry-mode", "loopback", "--quick-generate-key", uid, "default", "default", "never"])
    return try #require(try KeyRing.secretKeys(using: g).first)
}
private let mail = "From: Alice <alice@example.org>\r\nTo: bob@example.org\r\nSubject: Hi\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\nHallo Welt\r\n"

@Test func signedMessageVerifies() throws {
    let h = try tempHome(); defer { cleanup(h) }
    var g = try GPG.locate(); g.environment = ["GNUPGHOME": h.path]
    let key = try makeKey(g, "Alice <alice@example.org>")
    let out = try PGPMIMEEncoder(gpg: g).encode(Data(mail.utf8), options: .init(signerFingerprint: key.fingerprint, recipientFingerprints: [], format: .pgpMIME))
    let e = MIMEEntity(data: out)
    #expect(PGPMIME.classify(e) == .signed)
    #expect(e.header("Subject") == "Hi")
    let d = try PGPMIME(gpg: g).decode(out)
    #expect(d.signature?.state == .good)
    #expect(String(decoding: d.message, as: UTF8.self).contains("Hallo Welt"))
}

@Test func encryptedAndSignedRoundTrip() throws {
    let h = try tempHome(); defer { cleanup(h) }
    var g = try GPG.locate(); g.environment = ["GNUPGHOME": h.path]
    let key = try makeKey(g, "Alice <alice@example.org>")
    // recipient lookup by e-mail
    #expect(KeyRing.encryptionKeyFingerprint(for: "ALICE@example.org", using: g) == key.fingerprint)
    #expect(KeyRing.encryptionKeyFingerprint(for: "nobody@example.org", using: g) == nil)

    let out = try PGPMIMEEncoder(gpg: g).encode(Data(mail.utf8), options: .init(signerFingerprint: key.fingerprint, recipientFingerprints: [key.fingerprint], format: .pgpMIME))
    let e = MIMEEntity(data: out)
    #expect(PGPMIME.classify(e) == .encrypted)
    #expect(!out.isEmpty && !String(decoding: out, as: UTF8.self).contains("Hallo Welt"))
    let d = try PGPMIME(gpg: g).decode(out)
    #expect(d.wasEncrypted)
    #expect(d.signature?.state == .good)
    #expect(String(decoding: d.message, as: UTF8.self).contains("Hallo Welt"))
}

@Test func serviceEncodingStatusAndErrors() throws {
    let h = try tempHome(); defer { cleanup(h) }
    var g = try GPG.locate(); g.environment = ["GNUPGHOME": h.path]
    _ = try makeKey(g, "Alice <alice@example.org>")
    let ok = GPGService.encodingStatus(.init(from: "alice@example.org", recipients: ["alice@example.org"], sign: true, encrypt: true), gpg: g, config: .init())
    #expect(ok.canSign && ok.canEncrypt)
    let missing = GPGService.encodingStatus(.init(from: "alice@example.org", recipients: ["bob@example.org"], sign: true, encrypt: true), gpg: g, config: .init())
    #expect(missing.canSign && !missing.canEncrypt && missing.addressesFailingEncryption == ["bob@example.org"])
    let nokey = GPGService.encodingStatus(.init(from: "carol@example.org", recipients: [], sign: true, encrypt: false), gpg: g, config: .init())
    #expect(!nokey.canSign && nokey.error != nil)
    let enc = GPGService.encode(.init(from: "alice@example.org", recipients: ["bob@example.org"], sign: false, encrypt: true, raw: Data(mail.utf8)), gpg: g, config: .init())
    #expect(enc.raw == nil && enc.encryptionError != nil)
}

@Test func parsesPublicKeyListing() {
    let colons = """
    pub:u:2048:1:DDDD4444EEEE5555:1600000000:::u:::scESC:::::::
    fpr:::::::::AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555:
    uid:u::::1600000000::H::max <max@example.org>::::::::::0:
    sub:u:2048:1:0000FFFF1111AAAA:1600000000::::::e::::::
    fpr:::::::::7777CCCC8888DDDD9999EEEE0000FFFF1111AAAA:
    pub:r:2048:1:AAAAAAAAAAAAAAAA:1600000000:::u:::scESC:::::::
    fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:
    sub:r:2048:1:BBBBBBBBBBBBBBBB:1600000000::::::e::::::
    """
    #expect(KeyRing.parsePublicKeys(colons) == ["AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"])
}

/// Mail passes LF-only messages; the result must stay LF-only (CRLF made Mail crash) and still verify.
@Test func lfInputStaysLFAndVerifies() throws {
    let h = try tempHome(); defer { cleanup(h) }
    var g = try GPG.locate(); g.environment = ["GNUPGHOME": h.path]
    let key = try makeKey(g, "Alice <alice@example.org>")
    let lfMail = mail.replacingOccurrences(of: "\r\n", with: "\n")
    for recipients in [[String](), [key.fingerprint]] {
        let out = try PGPMIMEEncoder(gpg: g).encode(Data(lfMail.utf8), options: .init(signerFingerprint: key.fingerprint, recipientFingerprints: recipients))
        #expect(!String(decoding: out, as: UTF8.self).contains("\r"))
        let d = try PGPMIME(gpg: g).decode(out)
        #expect(d.signature?.state == .good)
        #expect(String(decoding: d.message, as: UTF8.self).contains("Hallo Welt"))
    }
}

/// Decoded output must use a single line-ending style, otherwise Mail sees no header/body separator.
@Test func decodedMessageKeepsInputLineEndings() throws {
    let h = try tempHome(); defer { cleanup(h) }
    var g = try GPG.locate(); g.environment = ["GNUPGHOME": h.path]
    let key = try makeKey(g, "Alice <alice@example.org>")
    for lf in [true, false] {
        let src = lf ? mail.replacingOccurrences(of: "\r\n", with: "\n") : mail
        for recipients in [[String](), [key.fingerprint]] {
            let enc = try PGPMIMEEncoder(gpg: g).encode(Data(src.utf8), options: .init(signerFingerprint: key.fingerprint, recipientFingerprints: recipients))
            let msg = String(decoding: try PGPMIME(gpg: g).decode(enc).message, as: UTF8.self)
            #expect(msg.contains("Hallo Welt"))
            if lf { #expect(!msg.contains("\r")) } else { #expect(!msg.replacingOccurrences(of: "\r\n", with: "").contains("\n")) }
            // header/body separator must exist in the style used
            #expect(msg.contains(lf ? "\n\nHallo Welt" : "\r\n\r\nHallo Welt"))
        }
    }
}

private let complexMail = [
    "From: Alice <alice@example.org>", "To: bob@example.org, carol@example.org", "Subject: =?utf-8?Q?Gr=C3=BC=C3=9Fe?=",
    "MIME-Version: 1.0", "Content-Type: multipart/mixed; boundary=\"OUTER\"", "",
    "--OUTER", "Content-Type: multipart/alternative; boundary=\"ALT\"", "",
    "--ALT", "Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: quoted-printable", "", "Hallo =C3=A4=C3=B6=C3=BC Welt", "",
    "--ALT", "Content-Type: text/html; charset=utf-8", "Content-Transfer-Encoding: quoted-printable", "", "<p>Hallo <b>Welt</b></p>", "",
    "--ALT--", "",
    "--OUTER", "Content-Type: application/octet-stream; name=\"x.bin\"", "Content-Transfer-Encoding: base64",
    "Content-Disposition: attachment; filename=\"x.bin\"", "", "AAECAwQFBgcICQoLDA0ODw==", "",
    "--OUTER--", "",
].joined(separator: "\n")

@Test func complexMessageRoundTripsWithAttachmentAndMultipleRecipients() throws {
    let h = try tempHome(); defer { cleanup(h) }
    var g = try GPG.locate(); g.environment = ["GNUPGHOME": h.path]
    let key = try makeKey(g, "Alice <alice@example.org>")
    let out = try PGPMIMEEncoder(gpg: g).encode(Data(complexMail.utf8), options: .init(signerFingerprint: key.fingerprint, recipientFingerprints: [key.fingerprint, key.fingerprint], format: .pgpMIME))
    #expect(!out.contains(Data("x.bin".utf8)))
    #expect(!out.contains(Data("Hallo".utf8)))
    let d = try PGPMIME(gpg: g).decode(out)
    #expect(d.wasEncrypted)
    #expect(d.signature?.state == .good)
    let text = String(decoding: d.message, as: UTF8.self)
    #expect(text.contains("multipart/alternative"))
    #expect(text.contains("<p>Hallo <b>Welt</b></p>"))
    #expect(text.contains("AAECAwQFBgcICQoLDA0ODw=="))
    #expect(text.contains("Subject: =?utf-8?Q?Gr=C3=BC=C3=9Fe?="))
}

private let plainUmlaut = "From: Alice <alice@example.org>\nTo: bob@example.org\nSubject: Hi\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: quoted-printable\n\nHallo =C3=A4=C3=B6=C3=BC Welt\n"

@Test func inlineEncryptRoundTrip() throws {
    let h = try tempHome(); defer { cleanup(h) }
    var g = try GPG.locate(); g.environment = ["GNUPGHOME": h.path]
    let key = try makeKey(g, "Alice <alice@example.org>")
    let out = try PGPMIMEEncoder(gpg: g).encode(Data(plainUmlaut.utf8), options: .init(
        signerFingerprint: key.fingerprint, recipientFingerprints: [key.fingerprint], format: .inline))
    let e = MIMEEntity(data: out)
    #expect(PGPMIME.classify(e) == .plain)                       // not PGP/MIME
    #expect(PGPMIME.hasInlineArmor(out))
    #expect(!out.contains(Data("\r\n".utf8)))                    // input was LF → output stays LF
    #expect(!String(decoding: out, as: UTF8.self).contains("Welt"))
    let d = try PGPMIME(gpg: g).decode(out)
    #expect(d.wasEncrypted && d.signature?.state == .good)
    #expect(String(decoding: d.message, as: UTF8.self).contains("Hallo äöü Welt"))
}

@Test func inlineClearsignAsciiOnlyAndFallbacks() throws {
    let h = try tempHome(); defer { cleanup(h) }
    var g = try GPG.locate(); g.environment = ["GNUPGHOME": h.path]
    let key = try makeKey(g, "Alice <alice@example.org>")
    let enc = PGPMIMEEncoder(gpg: g)
    let opts = PGPMIMEEncoder.Options(signerFingerprint: key.fingerprint, recipientFingerprints: [], format: .inline)
    // ASCII text → clearsigned inline
    let ascii = "From: a@example.org\nTo: b@example.org\nSubject: x\nContent-Type: text/plain; charset=us-ascii\n\nplain text\n"
    let out = try enc.encode(Data(ascii.utf8), options: opts)
    #expect(String(decoding: out, as: UTF8.self).contains("BEGIN PGP SIGNED MESSAGE"))
    #expect(try PGPMIME(gpg: g).decode(out).signature?.state == .good)
    // non-ASCII signed-only → PGP/MIME fallback
    let umlaut = try enc.encode(Data(plainUmlaut.utf8), options: opts)
    #expect(PGPMIME.classify(MIMEEntity(data: umlaut)) == .signed)
    // multipart → PGP/MIME fallback
    let multi = try enc.encode(Data(complexMail.utf8), options: opts)
    #expect(PGPMIME.classify(MIMEEntity(data: multi)) == .signed)
}

@Test func trustModelFiltersUntrustedKeys() {
    let colons = "pub:-:4096:1:AAAAAAAAAAAAAAAA:1:::-:::scESC::::::23::0:\nfpr:::::::::AAAA1111:\nuid:-::::1::HASH::Bob <bob@example.org>::::::::::0:\nsub:-:4096:1:BBBBBBBBBBBBBBBB:1::::::e::::::23:\n"
    #expect(KeyRing.parsePublicKeys(colons, requireTrust: false) == ["AAAA1111"])
    #expect(KeyRing.parsePublicKeys(colons, requireTrust: true).isEmpty)           // validity "-" = unknown
    #expect(KeyRing.parsePublicKeys(colons.replacingOccurrences(of: "pub:-:", with: "pub:f:"), requireTrust: true) == ["AAAA1111"])
}

@Test func configDecodingIsTolerantAndDefaultsAreSafe() throws {
    let old = Data(#"{"debugEncodeMode":"real","defaultFingerprint":"X"}"#.utf8)
    let c = try JSONDecoder().decode(KeyConfig.self, from: old)
    #expect(c.trustModel == .always && c.wkdLookup && c.sendFormat == .automatic && c.defaultFingerprint == "X")
    let bad = try JSONDecoder().decode(KeyConfig.self, from: Data(#"{"trustModel":"nonsense","sendFormat":"x"}"#.utf8))
    #expect(bad.trustModel == .always && bad.sendFormat == .automatic)
}

@Test func locateWithoutWKDDoesNotTouchTheNetwork() throws {
    let h = try tempHome(); defer { cleanup(h) }
    var g = try GPG.locate(); g.environment = ["GNUPGHOME": h.path]
    #expect(KeyRing.locateEncryptionKey(for: "nobody@example.invalid", using: g, wkd: false) == nil)
}
