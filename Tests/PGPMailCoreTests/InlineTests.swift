import Testing
import Foundation
@testable import PGPMailCore

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

private func setup() throws -> (GPG, URL, SecretKey) {
    let h = try tempHome()
    var g = try GPG.locate(); g.environment = ["GNUPGHOME": h.path]
    _ = try g.run(["--passphrase", "", "--pinentry-mode", "loopback", "--quick-generate-key", "Alice <alice@example.org>", "default", "default", "never"])
    return (g, h, try #require(try KeyRing.secretKeys(using: g).first))
}

@Test func inlineEncryptedPlainText() throws {
    let (g, h, key) = try setup(); defer { cleanup(h) }
    let enc = try g.run(["--armor", "--trust-model", "always", "-r", key.fingerprint, "--encrypt"], stdin: Data("Geheimer Text äöü".utf8))
    let armor = String(decoding: enc.stdout, as: UTF8.self)
    let mail = "From: a@b.c\nSubject: x\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 7bit\n\n\(armor)\n"
    #expect(PGPMIME.hasInlineArmor(Data(mail.utf8)))
    let d = try PGPMIME(gpg: g).decode(Data(mail.utf8))
    let text = String(decoding: d.message, as: UTF8.self)
    #expect(d.wasEncrypted)
    #expect(text.contains("Geheimer Text äöü"))
    #expect(!text.contains("BEGIN PGP"))
    #expect(!text.contains("\r"))                       // LF in, LF out
    #expect(text.contains("charset=utf-8"))
}

@Test func inlineClearsignedKeepsSurroundingText() throws {
    let (g, h, key) = try setup(); defer { cleanup(h) }
    let sig = try g.run(["--armor", "--clearsign", "-u", key.fingerprint], stdin: Data("Signierter Text\n- mit Strich".utf8))
    let armor = String(decoding: sig.stdout, as: UTF8.self)
    let mail = "From: a@b.c\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\nVorspann\r\n\(armor.replacingOccurrences(of: "\n", with: "\r\n"))Nachspann\r\n"
    let d = try PGPMIME(gpg: g).decode(Data(mail.utf8))
    let text = String(decoding: d.message, as: UTF8.self)
    #expect(d.signature?.state == .good)
    #expect(!d.wasEncrypted)
    #expect(text.contains("Vorspann") && text.contains("Signierter Text") && text.contains("Nachspann"))
    #expect(text.contains("- mit Strich"))               // dash-escaping removed by gpg
    #expect(!text.contains("BEGIN PGP"))
}

@Test func inlineInsideMultipartAlternativeAndQuotedPrintable() throws {
    let (g, h, key) = try setup(); defer { cleanup(h) }
    let enc = try g.run(["--armor", "--trust-model", "always", "-r", key.fingerprint, "--encrypt"], stdin: Data("Mehrteilig".utf8))
    let qp = String(decoding: enc.stdout, as: UTF8.self).replacingOccurrences(of: "=", with: "=3D")
    let mail = "From: a@b.c\nContent-Type: multipart/mixed; boundary=\"B\"\n\n--B\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: quoted-printable\n\n\(qp)\n--B\nContent-Type: application/octet-stream; name=\"x.bin\"\nContent-Disposition: attachment; filename=\"x.bin\"\n\nAAAA\n--B--\n"
    let d = try PGPMIME(gpg: g).decode(Data(mail.utf8))
    let text = String(decoding: d.message, as: UTF8.self)
    #expect(d.wasEncrypted)
    #expect(text.contains("Mehrteilig"))
    #expect(text.contains("x.bin"))                      // attachment part untouched
    #expect(!text.contains("BEGIN PGP"))
}

@Test func plainTextWithoutArmorIsUntouched() throws {
    let (g, h, _) = try setup(); defer { cleanup(h) }
    let mail = "From: a@b.c\nContent-Type: text/plain\n\nnur Text\n"
    #expect(!PGPMIME.hasInlineArmor(Data(mail.utf8)))
    let d = try PGPMIME(gpg: g).decode(Data(mail.utf8))
    #expect(d.message == Data(mail.utf8) && !d.wasEncrypted && d.signature == nil)
}
