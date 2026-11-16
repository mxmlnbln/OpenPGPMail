import Foundation

enum GPGTestSupport {
    /// `gpgconf` next to whichever gpg `GPG.locate()` picks.
    static var gpgconf: URL {
        for p in ["/usr/local/MacGPG2/bin/gpgconf", "/opt/homebrew/bin/gpgconf", "/usr/local/bin/gpgconf"]
        where FileManager.default.isExecutableFile(atPath: p) { return URL(fileURLWithPath: p) }
        return URL(fileURLWithPath: "/usr/bin/gpgconf")
    }
}
