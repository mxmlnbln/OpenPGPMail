import SwiftUI
import AppKit
import PGPMailCore

struct SetupCheck: Identifiable, Equatable {
    enum State { case ok, missing, warning }
    let id: String
    let title: String
    let state: State
    let detail: String
    /// Instructions shown when the check is not OK.
    var help: [String] = []
    var command: String?          // copyable shell command
    var link: (title: String, url: URL)?
    var action: Action?

    enum Action: Equatable { case openMail }

    static func == (l: Self, r: Self) -> Bool { l.id == r.id && l.state == r.state && l.detail == r.detail }
}

enum SetupChecker {
    static let extensionID = "org.openpgpmail.app.MailExtension"

    static func run() -> [SetupCheck] { [gnupg(), pinentry(), bundledExtension(), mailExtension()] }

    static func gnupg() -> SetupCheck {
        if let g = try? GPG.locate() {
            let v = (try? g.run(["--version"]))
                .flatMap { String(decoding: $0.stdout, as: UTF8.self).split(whereSeparator: \.isNewline).first.map(String.init) } ?? "gpg"
            return .init(id: "gpg", title: "GnuPG", state: .ok, detail: "\(v) · \(g.executable.path)")
        }
        return .init(id: "gpg", title: "GnuPG", state: .missing, detail: "gpg wurde nicht gefunden.",
                     help: ["Installiere GPG Suite (empfohlen: enthält gpg, Passphrase-Dialog und Schlüsselverwaltung) …",
                            "… oder installiere GnuPG mit Homebrew:"],
                     command: "brew install gnupg pinentry-mac",
                     link: ("GPG Suite herunterladen", URL(string: "https://gpgtools.org")!))
    }

    static func pinentry() -> SetupCheck {
        let paths = ["/usr/local/MacGPG2/libexec/pinentry-mac.app", "/opt/homebrew/bin/pinentry-mac", "/usr/local/bin/pinentry-mac",
                     "/Applications/pinentry-mac.app"]
        if let p = paths.first(where: { FileManager.default.fileExists(atPath: $0) }) {
            return .init(id: "pinentry", title: "Passphrase-Dialog (pinentry-mac)", state: .ok, detail: p)
        }
        return .init(id: "pinentry", title: "Passphrase-Dialog (pinentry-mac)", state: .warning,
                     detail: "Nicht gefunden – geschützte Schlüssel können evtl. nicht entsperrt werden.",
                     help: ["Mit Homebrew installieren und in ~/.gnupg/gpg-agent.conf eintragen (GPG Suite bringt ihn mit):"],
                     command: "brew install pinentry-mac && echo \"pinentry-program $(brew --prefix)/bin/pinentry-mac\" >> ~/.gnupg/gpg-agent.conf && gpgconf --kill gpg-agent")
    }

    static func bundledExtension() -> SetupCheck {
        let appex = Bundle.main.builtInPlugInsURL?.appendingPathComponent("MailExtension.appex")
        if let appex, FileManager.default.fileExists(atPath: appex.path) {
            return .init(id: "bundle", title: "Mail-Erweiterung in der App", state: .ok, detail: "Enthalten.")
        }
        return .init(id: "bundle", title: "Mail-Erweiterung in der App", state: .missing,
                     detail: "Die Erweiterung fehlt in diesem App-Paket.",
                     help: ["Lade die App neu herunter bzw. baue sie komplett neu (siehe README)."])
    }

    /// Asks pluginkit about the extension: "+" = enabled, "-" = disabled, nothing = not registered.
    static func mailExtension() -> SetupCheck {
        let title = "Erweiterung in Mail aktiviert"
        let mailHelp = ["Öffne Mail → Einstellungen (⌘,) → „Erweiterungen“.",
                        "Setze den Haken bei „OpenPGPMail“ und starte Mail danach neu."]
        let out = shell("/usr/bin/pluginkit", ["-m", "-A", "-p", "com.apple.email.extension", "-i", extensionID])
        let line = out.split(whereSeparator: \.isNewline).first(where: { $0.contains(extensionID) }).map(String.init) ?? ""
        switch line.trimmingCharacters(in: .whitespaces).first {
        case "+": return .init(id: "ext", title: title, state: .ok, detail: "Aktiv.")
        case "-": return .init(id: "ext", title: title, state: .missing, detail: "Die Erweiterung ist installiert, aber ausgeschaltet.",
                               help: mailHelp, action: .openMail)
        default:
            return .init(id: "ext", title: title, state: .missing, detail: "Die Erweiterung ist dem System noch nicht bekannt.",
                         help: ["Verschiebe OpenPGPMailApp in den Ordner „Programme“ (oder ~/Applications) und starte sie einmal." ] + mailHelp,
                         action: .openMail)
        }
    }

    private static func shell(_ path: String, _ args: [String]) -> String {
        let p = Process(); p.executableURL = URL(fileURLWithPath: path); p.arguments = args
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = Pipe()
        guard (try? p.run()) != nil else { return "" }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }
}

@MainActor
final class SetupModel: ObservableObject {
    @Published var checks: [SetupCheck] = []
    @Published var dismissed = false
    @Published var checking = false

    var blocking: Bool { checks.contains { $0.state == .missing } }

    func refresh() {
        guard !checking else { return }
        checking = true
        Task.detached {
            let result = SetupChecker.run()
            await MainActor.run { self.checks = result; self.checking = false }
        }
    }
}

// MARK: - Views

struct CheckRow: View {
    let check: SetupCheck
    var showHelp = true
    @State private var copied = false

    var icon: (String, Color) {
        switch check.state {
        case .ok: ("checkmark.circle.fill", .green)
        case .missing: ("xmark.octagon.fill", .red)
        case .warning: ("exclamationmark.triangle.fill", .orange)
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon.0).foregroundStyle(icon.1).font(.title3).frame(width: 24)
            VStack(alignment: .leading, spacing: 4) {
                Text(check.title).font(.headline)
                Text(check.detail).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                if showHelp && check.state != .ok {
                    ForEach(Array(check.help.enumerated()), id: \.offset) { _, line in
                        Text("• " + line).font(.callout).fixedSize(horizontal: false, vertical: true)
                    }
                    if let cmd = check.command {
                        HStack {
                            Text(cmd).font(.caption.monospaced()).textSelection(.enabled).lineLimit(3)
                                .padding(6).background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
                            Button(copied ? "Kopiert" : "Kopieren") {
                                NSPasteboard.general.clearContents(); NSPasteboard.general.setString(cmd, forType: .string)
                                copied = true
                            }.controlSize(.small)
                        }
                    }
                    HStack {
                        if let l = check.link { Button(l.title) { NSWorkspace.shared.open(l.url) }.controlSize(.small) }
                        if check.action == .openMail {
                            Button("Mail öffnen") { NSWorkspace.shared.open(URL(fileURLWithPath: "/System/Applications/Mail.app")) }.controlSize(.small)
                        }
                    }
                }
            }
            Spacer(minLength: 0)
        }
    }
}

/// Covers the window while required parts are missing.
struct SetupOverlay: View {
    @ObservedObject var setup: SetupModel

    var body: some View {
        ZStack {
            Color(nsColor: .windowBackgroundColor).ignoresSafeArea()
            VStack(spacing: 16) {
                Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 64, height: 64)
                Text("Einrichtung unvollständig").font(.title2.bold())
                Text("OpenPGPMail braucht noch ein paar Dinge, bevor es in Mail funktioniert.")
                    .foregroundStyle(.secondary)
                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        let sorted = setup.checks.filter { $0.state != .ok } + setup.checks.filter { $0.state == .ok }
                        ForEach(sorted) { CheckRow(check: $0); if $0.id != sorted.last?.id { Divider() } }
                    }
                    .padding(16)
                }
                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
                .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(.quaternary))
                .frame(maxWidth: 560, maxHeight: 340)
                HStack {
                    Button { setup.refresh() } label: { Label("Erneut prüfen", systemImage: "arrow.clockwise") }
                        .keyboardShortcut(.defaultAction)
                    Button("Trotzdem fortfahren") { setup.dismissed = true }
                    if setup.checking { ProgressView().controlSize(.small) }
                }
            }
            .padding(24)
        }
    }
}
