import SwiftUI
import PGPMailCore

@main
struct OpenPGPMailApp: App {
    var body: some Scene {
        Window("OpenPGPMail", id: "main") { KeySettingsView() }
            .windowResizability(.contentMinSize)
    }
}

@MainActor
final class KeySettingsModel: ObservableObject {
    @Published var keys: [SecretKey] = []
    @Published var config = KeyConfig.load()
    @Published var newAddress = ""
    @Published var error: String?
    @Published var importMessage: String?
    @Published var testResults: [String: String] = [:]
    @Published var testing: Set<String> = []

    func reload() {
        do { keys = try KeyRing.secretKeys(using: GPG.locate()); error = nil }
        catch { self.error = "gpg nicht gefunden oder Schlüsselliste nicht lesbar (\(error))." }
        config = KeyConfig.load()
        // Show every address that appears in one of our keys, so the user sees what is covered.
        for a in keys.filter(\.isUsable).flatMap(\.emails) where config.accounts[a] == nil { config.accounts[a] = "" }
    }

    func importKey(from url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do {
            let r = try KeyRing.importKey(at: url, using: GPG.locate())
            if r.succeeded {
                importMessage = r.secretImported > 0 ? "\(r.secretImported) privater Schlüssel importiert."
                    : (r.secretUnchanged > 0 ? "Privater Schlüssel war bereits vorhanden."
                       : "\(r.imported) öffentlicher Schlüssel importiert (kein privater Teil in der Datei).")
            } else { importMessage = "Import fehlgeschlagen: \(r.message)" }
        } catch { importMessage = "Import fehlgeschlagen: \(error)" }
        reload()
    }

    func test(_ key: SecretKey) {
        testing.insert(key.fingerprint); testResults[key.fingerprint] = nil
        Task.detached {
            let text: String
            do {
                let r = try KeyRing.testDecryption(of: key, using: GPG.locate())
                text = (r.ok ? "✓ " : "✗ ") + r.detail
            } catch { text = "✗ \(error)" }
            await MainActor.run { self.testResults[key.fingerprint] = text; self.testing.remove(key.fingerprint) }
        }
    }

    func save() {
        var c = config
        c.accounts = c.accounts.filter { !$0.value.isEmpty }
        do { try c.save() } catch { self.error = "Speichern fehlgeschlagen: \(error)" }
    }

    func resolution(_ address: String) -> KeyResolution {
        var c = config; c.accounts = c.accounts.filter { !$0.value.isEmpty }
        return KeyResolver.resolve(address: address, keys: keys, config: c)
    }

    func addAddress() {
        let a = newAddress.trimmingCharacters(in: .whitespaces).lowercased()
        guard a.contains("@") else { return }
        if config.accounts[a] == nil { config.accounts[a] = "" }
        newAddress = ""
    }
}

enum SettingsTab: String, CaseIterable, Identifiable {
    case keys = "Schlüssel", sending = "Senden", about = "Hilfe"
    var id: String { rawValue }
    var icon: String {
        switch self {
        case .keys: "key.fill"
        case .sending: "paperplane.fill"
        case .about: "questionmark.circle.fill"
        }
    }
}

struct KeySettingsView: View {
    @StateObject private var model = KeySettingsModel()
    @State private var showImporter = false
    @State private var tab: SettingsTab = .keys
    @StateObject private var setup = SetupModel()

    var body: some View {
        TabView(selection: $tab) {
            ForEach(SettingsTab.allCases) { t in
                page(t).tabItem { Label(t.rawValue, systemImage: t.icon) }.tag(t)
            }
        }
        .padding(.top, 6)
        .frame(minWidth: 640, idealWidth: 680, minHeight: 500, idealHeight: 540)
        .overlay { if setup.blocking && !setup.dismissed { SetupOverlay(setup: setup) } }
        .onAppear { model.reload(); setup.refresh() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            model.reload(); setup.refresh()
        }
        .onReceive(Timer.publish(every: 3, on: .main, in: .common).autoconnect()) { _ in
            if setup.blocking && !setup.dismissed { setup.refresh() }
        }
        .fileImporter(isPresented: $showImporter, allowedContentTypes: [.data], allowsMultipleSelection: false) { result in
            if case .success(let urls) = result, let u = urls.first { model.importKey(from: u) }
        }
    }

    @ViewBuilder func page(_ t: SettingsTab) -> some View {
        switch t {
        case .keys: keysPage
        case .sending: sendingPage
        case .about: aboutPage
        }
    }

    // MARK: Schlüssel
    var keysPage: some View {
        Form {
            if let e = model.error { Label(e, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red) }
            Section {
                if model.keys.isEmpty {
                    ContentUnavailable(icon: "key.slash", title: "Noch kein privater Schlüssel",
                                       text: "Importiere eine Schlüsseldatei (.asc / .pgp), um Mails entschlüsseln und signieren zu können.")
                }
                ForEach(model.keys) { key in KeyCard(key: key, model: model) }
            } header: {
                HStack {
                    Text("Private Schlüssel (\(model.keys.count))")
                    Spacer()
                    if let m = model.importMessage { Text(m).font(.caption).foregroundStyle(.secondary).textCase(nil) }
                    Button { showImporter = true } label: { Label("Importieren …", systemImage: "square.and.arrow.down") }
                    Button { model.reload() } label: { Image(systemName: "arrow.clockwise") }.help("Schlüssel neu laden")
                }
            }
            Section {
                ForEach(model.config.accounts.keys.sorted(), id: \.self) { address in
                    HStack(spacing: 10) {
                        statusIcon(model.resolution(address))
                        Text(address).lineLimit(1).truncationMode(.middle)
                        Spacer()
                        Picker("", selection: Binding(
                            get: { model.config.accounts[address] ?? "" },
                            set: { model.config.accounts[address] = $0; model.save() })) {
                            Text("Automatisch").tag("")
                            ForEach(model.keys.filter(\.isUsable)) { Text("\($0.displayName) (\($0.keyID.suffix(8)))").tag($0.fingerprint) }
                        }.labelsHidden().fixedSize()
                    }
                }
            } header: { Text("Welcher Schlüssel gehört zu welcher Adresse?") }
            footer: {
                Label("Adressen mit rotem Warnsymbol haben keinen privaten Schlüssel: Mails dafür lassen sich weder entschlüsseln noch signieren.",
                      systemImage: "info.circle").font(.caption).foregroundStyle(.secondary)
            }
            Section("Adresse hinzufügen") {
                HStack {
                    TextField("name@example.org", text: $model.newAddress).onSubmit { model.addAddress() }
                    Button("Hinzufügen") { model.addAddress() }.disabled(!model.newAddress.contains("@"))
                }
            }
        }
        .formStyle(.grouped)
    }

    // MARK: Senden
    var sendingPage: some View {
        Form {
            Section {
                Picker("Format", selection: Binding(get: { model.config.sendFormat }, set: { model.config.sendFormat = $0; model.save() })) {
                    Text("Automatisch (empfohlen)").tag(SendFormat.automatic)
                    Text("Immer PGP/MIME").tag(SendFormat.pgpMIME)
                }
                switch model.config.sendFormat {
                case .pgpMIME:
                    Hint("Jede Mail wird als PGP/MIME verschickt: Text, HTML und Anhänge sind geschützt. Das versteht jedes moderne Mailprogramm. Sehr alte Programme zeigen die Mail nur als Anhang.")
                default:
                    Hint("Reine Textmails gehen als Inline-PGP raus: Der verschlüsselte Block steht direkt im Mailtext und ist praktisch überall lesbar. Mails mit HTML-Formatierung oder Anhängen – und nur signierte Mails mit Umlauten – gehen als PGP/MIME, weil Inline dort Anhänge ungeschützt ließe oder Umlaute beschädigen könnte.")
                }
            } header: { Text("Format ausgehender Mails") }

            Section {
                Picker("Vertrauen", selection: Binding(get: { model.config.trustModel }, set: { model.config.trustModel = $0; model.save() })) {
                    Text("Allen Schlüsseln im Schlüsselbund").tag(TrustModel.always)
                    Text("Web of Trust (gpg-Standard)").tag(TrustModel.webOfTrust)
                }
                switch model.config.trustModel {
                case .always:
                    Hint("Es wird an jeden gültigen Schlüssel verschlüsselt, den du importiert hast – du entscheidest selbst, welchen Schlüsseln du traust. Einfach, aber ein untergeschobener Schlüssel würde nicht auffallen.")
                case .webOfTrust:
                    Hint("Es wird nur an Schlüssel verschlüsselt, die du mit gpg beglaubigt hast (Vertrauen „marginal“ oder höher). Sicherer, aber neue Schlüssel musst du erst in GPG Suite oder mit `gpg --sign-key` bestätigen.")
                }
            } header: { Text("Empfängerschlüssel") }

            Section {
                Toggle("Fehlende öffentliche Schlüssel automatisch suchen (WKD)", isOn: Binding(
                    get: { model.config.wkdLookup }, set: { model.config.wkdLookup = $0; model.save() }))
                Hint("Beim Verschlüsseln an eine Adresse ohne Schlüssel fragt die App den Server der Empfänger-Domain ab (Web Key Directory, z. B. openpgpkey.example.org). Dabei erfährt dieser Server, dass du an die Adresse schreibst. Ohne WKD musst du Schlüssel selbst importieren.")
            } header: { Text("Schlüsselsuche") }
        }
        .formStyle(.grouped)
    }

    // MARK: Hilfe
    var aboutPage: some View {
        Form {
            Section("Systemprüfung") {
                ForEach(setup.checks) { CheckRow(check: $0) }
                Button { setup.refresh() } label: { Label("Erneut prüfen", systemImage: "arrow.clockwise") }
            }
            Section("Erste Schritte") {
                StepRow(n: 1, text: "Privaten Schlüssel im Tab „Schlüssel“ importieren und mit „Passphrase testen“ prüfen.")
                StepRow(n: 2, text: "Darunter prüfen, dass jede deiner Absenderadressen einen grünen Haken hat.")
                StepRow(n: 3, text: "In Mail die Erweiterung aktivieren und Mail neu starten. Passphrasen gibst nur du im Pinentry-Fenster ein.")
            }
            Section("Über") {
                HStack(spacing: 12) {
                    Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 48, height: 48)
                    VStack(alignment: .leading) {
                        Text("OpenPGPMail").font(.headline)
                        Text("Freie PGP-Unterstützung für Apple Mail · MIT-Lizenz").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
        }
        .formStyle(.grouped)
    }

    @ViewBuilder func statusIcon(_ r: KeyResolution) -> some View {
        switch r {
        case .configured, .automatic: Image(systemName: "checkmark.seal.fill").foregroundStyle(.green).help("Schlüssel vorhanden")
        case .ambiguous: Image(systemName: "questionmark.circle.fill").foregroundStyle(.orange).help("Mehrere Schlüssel passen – bitte auswählen")
        case .none: Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red).help("Kein privater Schlüssel hinterlegt")
        }
    }
}

struct KeyCard: View {
    let key: SecretKey
    @ObservedObject var model: KeySettingsModel

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: "key.fill").font(.title2).foregroundStyle(key.isUsable ? Color.accentColor : .secondary)
                .frame(width: 30)
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(key.displayName).font(.headline)
                    if key.isExpired { Badge(text: "abgelaufen", color: .orange) }
                    if key.isRevoked { Badge(text: "widerrufen", color: .red) }
                }
                if !key.emails.isEmpty, key.emails != [key.displayName] { Text(key.emails.joined(separator: ", ")).font(.callout).foregroundStyle(.secondary) }
                Text("\(key.algorithm) · \(key.keyID)").font(.caption.monospaced()).foregroundStyle(.tertiary).textSelection(.enabled)
                if let r = model.testResults[key.fingerprint] {
                    Text(r).font(.caption).foregroundStyle(r.hasPrefix("✓") ? .green : .red)
                }
            }
            Spacer(minLength: 12)
            if model.testing.contains(key.fingerprint) { ProgressView().controlSize(.small) }
            Button("Passphrase testen") { model.test(key) }
                .disabled(!key.isUsable || model.testing.contains(key.fingerprint))
        }
        .padding(.vertical, 4)
    }
}

struct Hint: View {
    let text: String
    init(_ t: String) { text = t }
    var body: some View {
        Label { Text(text).fixedSize(horizontal: false, vertical: true) } icon: { Image(systemName: "info.circle") }
            .font(.caption).foregroundStyle(.secondary)
    }
}

struct StepRow: View {
    let n: Int; let text: String
    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text("\(n)").font(.caption.bold()).foregroundStyle(.white)
                .frame(width: 20, height: 20).background(Color.accentColor, in: Circle())
            Text(text)
        }
    }
}

struct ContentUnavailable: View {
    let icon: String, title: String, text: String
    var body: some View {
        VStack(spacing: 6) {
            Image(systemName: icon).font(.largeTitle).foregroundStyle(.secondary)
            Text(title).font(.headline)
            Text(text).font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
        }.frame(maxWidth: .infinity).padding(.vertical, 16)
    }
}

struct Badge: View {
    let text: String; let color: Color
    var body: some View {
        Text(text).font(.caption2).padding(.horizontal, 6).padding(.vertical, 1)
            .background(color.opacity(0.2), in: Capsule()).foregroundStyle(color)
    }
}
