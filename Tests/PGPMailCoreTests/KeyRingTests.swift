import Testing
import Foundation
@testable import PGPMailCore
@testable import PGPMailXPC

private let sample = """
sec:u:4096:1:4444DDDD5555EEEE:1500000000:::u:::scESC:::+:::23::0:
fpr:::::::::1111AAAA2222BBBB3333CCCC4444DDDD5555EEEE:
grp:::::::::AAAA:
uid:u::::1500000000::H1::Max Mustermann <Max@Example.org>::::::::::0:
uid:u::::1500000000::H2::Max (Work) <max@work.example>::::::::::0:
ssb:u:4096:1:2222BBBB3333CCCC:1500000000::::::e:::+:::23:
fpr:::::::::SUBFPR0000000000000000000000002222BBBB3333CCCC:
sec:e:1024:17:6666CCCC5555BBBB:1200000000:::u:::scESC:::+:::23::0:
fpr:::::::::9999FFFF8888EEEE7777DDDD6666CCCC5555BBBB:
uid:e::::1200000000::H3::Alt <alt@example.org>::::::::::0:
"""

@Test func parsesSecretKeys() {
    let keys = KeyRing.parse(sample)
    #expect(keys.count == 2)
    #expect(keys[0].fingerprint == "1111AAAA2222BBBB3333CCCC4444DDDD5555EEEE")
    #expect(keys[0].emails == ["max@example.org", "max@work.example"])
    #expect(keys[0].owns(keyID: "2222bbbb3333cccc"))
    #expect(keys[0].algorithm == "rsa4096")
    #expect(keys[1].isExpired && !keys[1].isUsable)
}

@Test func resolvesAddresses() {
    let keys = KeyRing.parse(sample)
    #expect(KeyResolver.resolve(address: "MAX@example.org", keys: keys, config: .init()) == .automatic(keys[0]))
    // expired key does not count
    #expect(KeyResolver.resolve(address: "alt@example.org", keys: keys, config: .init()) == .none)
    #expect(KeyResolver.resolve(address: "nobody@example.org", keys: keys, config: .init()) == .none)
    // explicit mapping wins and also covers addresses without a matching user ID
    let cfg = KeyConfig(accounts: ["nobody@example.org": keys[0].fingerprint])
    #expect(KeyResolver.resolve(address: "nobody@example.org", keys: keys, config: cfg) == .configured(keys[0]))
}

@Test func extractsRecipients() {
    let m = MIMEEntity(string: "To: A <a@x.org>, b@y.org\r\nCc: A <A@x.org>\r\nDelivered-To: c@z.org\r\n\r\n")
    #expect(AddressExtractor.recipients(of: m) == ["a@x.org", "b@y.org", "c@z.org"])
}

/// Encrypt to one keyring, decrypt with another that lacks the secret key → structured failure.
@Test func reportsMissingSecretKey() throws {
    func makeHome() throws -> URL {
        let h = URL(fileURLWithPath: "/tmp/pgh-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: h, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return h
    }
    func kill(_ h: URL) {
        let p = Process(); p.executableURL = GPGTestSupport.gpgconf
        p.arguments = ["--kill", "gpg-agent"]; p.environment = ["GNUPGHOME": h.path]; try? p.run(); p.waitUntilExit()
        try? FileManager.default.removeItem(at: h)
    }
    let a = try makeHome(), b = try makeHome()
    defer { kill(a); kill(b) }
    var gpgA = try GPG.locate(), gpgB = gpgA
    gpgA.environment = ["GNUPGHOME": a.path]; gpgB.environment = ["GNUPGHOME": b.path]
    _ = try gpgA.run(["--passphrase", "", "--pinentry-mode", "loopback", "--quick-generate-key", "Alice <alice@example.org>", "default", "default", "never"])
    let enc = try gpgA.run(["--armor", "--trust-model", "always", "-r", "alice@example.org", "--encrypt"], stdin: Data("hi".utf8))
    let raw = "To: Alice <alice@example.org>\r\nContent-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--B\r\nContent-Type: application/octet-stream\r\n\r\n\(String(decoding: enc.stdout, as: UTF8.self))\r\n--B--\r\n"

    // Secret key present → decrypts
    #expect(GPGService.decode(Data(raw.utf8), gpg: gpgA, config: .init()).decoded?.wasEncrypted == true)

    // Different keyring → no secret key, and Alice's address is reported as having no key
    let out = GPGService.decode(Data(raw.utf8), gpg: gpgB, config: .init())
    #expect(out.failure?.kind == .noSecretKey)
    #expect(out.failure?.addressesWithoutKey == ["alice@example.org"])
    #expect(out.failure?.recipientKeyIDs.isEmpty == false)
}

@Test func importsSecretKeyFile() throws {
    func home() throws -> URL {
        let h = URL(fileURLWithPath: "/tmp/pgh-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: h, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]); return h
    }
    let a = try home(), b = try home()
    defer { for h in [a, b] {
        let p = Process(); p.executableURL = GPGTestSupport.gpgconf
        p.arguments = ["--kill", "gpg-agent"]; p.environment = ["GNUPGHOME": h.path]; try? p.run(); p.waitUntilExit()
        try? FileManager.default.removeItem(at: h) } }
    var ga = try GPG.locate(), gb = ga
    ga.environment = ["GNUPGHOME": a.path]; gb.environment = ["GNUPGHOME": b.path]
    _ = try ga.run(["--passphrase", "", "--pinentry-mode", "loopback", "--quick-generate-key", "Bob <bob@example.org>", "default", "default", "never"])
    let exp = try ga.run(["--pinentry-mode", "loopback", "--passphrase", "", "--export-secret-keys"])
    let file = FileManager.default.temporaryDirectory.appendingPathComponent("k-\(UUID().uuidString).pgp")
    try exp.stdout.write(to: file); defer { try? FileManager.default.removeItem(at: file) }

    #expect(try KeyRing.secretKeys(using: gb).isEmpty)
    let res = try KeyRing.importKey(at: file, using: gb)
    #expect(res.succeeded && res.secretImported == 1)
    #expect(try KeyRing.secretKeys(using: gb).count == 1)
}

@Test func selfTestDecryption() throws {
    let h = URL(fileURLWithPath: "/tmp/pgh-\(UUID().uuidString.prefix(8))")
    try FileManager.default.createDirectory(at: h, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer {
        let p = Process(); p.executableURL = GPGTestSupport.gpgconf
        p.arguments = ["--kill", "gpg-agent"]; p.environment = ["GNUPGHOME": h.path]; try? p.run(); p.waitUntilExit()
        try? FileManager.default.removeItem(at: h)
    }
    var g = try GPG.locate(); g.environment = ["GNUPGHOME": h.path]
    _ = try g.run(["--passphrase", "", "--pinentry-mode", "loopback", "--quick-generate-key", "Eve <eve@example.org>", "default", "default", "never"])
    let key = try #require(try KeyRing.secretKeys(using: g).first)
    #expect(try KeyRing.testDecryption(of: key, using: g).ok)
}
