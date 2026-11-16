import Testing
import Foundation
@testable import PGPMailCore

@Test func classifiesEncrypted() {
    let m = MIMEEntity(string: "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"b\"\r\n\r\n")
    #expect(PGPMIME.classify(m) == .encrypted)
}

@Test func splitsMultipart() {
    let m = MIMEEntity(string: "Content-Type: multipart/signed; boundary=\"b\"; protocol=\"application/pgp-signature\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b\r\nContent-Type: application/pgp-signature\r\n\r\nSIG\r\n--b--\r\n")
    let parts = m.multipartParts()
    #expect(parts?.count == 2)
    #expect(parts?[0] == "Content-Type: text/plain\r\n\r\nhi")
}

@Test func parsesStatus() {
    let s = GPGStatus.parse("[GNUPG:] GOODSIG ABCD1234 Alice <a@b.c>\n[GNUPG:] VALIDSIG FPR123 x\n")
    #expect(s.first == .goodSignature(keyID: "ABCD1234", userID: "Alice <a@b.c>"))
    #expect(PGPMIME.signature(from: s)?.fingerprint == "FPR123")
}

/// End-to-end against a throw-away GNUPGHOME: sign + verify through our code path.
@Test func verifiesRealSignature() throws {
    let home = URL(fileURLWithPath: "/tmp/pgh-\(UUID().uuidString.prefix(8))") // short path: unix socket limit (104 bytes)
    try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer {
        let p = Process(); p.executableURL = GPGTestSupport.gpgconf
        p.arguments = ["--kill", "gpg-agent"]; p.environment = ["GNUPGHOME": home.path]; try? p.run(); p.waitUntilExit()
        try? FileManager.default.removeItem(at: home)
    }
    var gpg = try GPG.locate()
    gpg.environment = ["GNUPGHOME": home.path]
    _ = try gpg.run(["--passphrase", "", "--pinentry-mode", "loopback", "--quick-generate-key", "Test <t@example.org>", "default", "default", "never"])
    let content = "Content-Type: text/plain\r\n\r\nhello"
    let sig = try gpg.run(["--detach-sign", "--armor", "--pinentry-mode", "loopback", "--passphrase", ""], stdin: Data(content.utf8))
    let raw = "From: t@example.org\r\nContent-Type: multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=\"B\"\r\n\r\n--B\r\n\(content)\r\n--B\r\nContent-Type: application/pgp-signature\r\n\r\n\(String(decoding: sig.stdout, as: UTF8.self))\r\n--B--\r\n"
    let d = try PGPMIME(gpg: gpg).decode(Data(raw.utf8))
    #expect(d.signature?.state == .good)
}


/// Mail stores LF headers but our armored bodies carry CRLF: the first blank line must win.
@Test func splitsMixedLineEndingsAtFirstBlankLine() {
    let raw = "Return-Path: <a@b.c>\nContent-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"B\"\n\n--B\nContent-Type: application/pgp-encrypted\n\nVersion: 1\n\n--B\nContent-Type: application/octet-stream\n\r\n-----BEGIN PGP MESSAGE-----\r\n\r\nabc\r\n-----END PGP MESSAGE-----\n--B--\n"
    let e = MIMEEntity(string: raw)
    #expect(e.headers.map(\.name) == ["Return-Path", "Content-Type"])
    #expect(e.multipartParts()?.count == 2)
}
