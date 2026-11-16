import MailKit
import SwiftUI
import PGPMailCore

/// Popover shown when the user clicks the banner's action: explains what is missing and opens the host app.
final class FailureViewController: MEExtensionViewController {
    private let failure: DecodeFailure
    init(failure: DecodeFailure) {
        self.failure = failure
        super.init(nibName: nil, bundle: nil)
    }
    required init?(coder: NSCoder) { fatalError("not used") }

    override func loadView() {
        let host = NSHostingView(rootView: FailureView(failure: failure))
        host.frame = NSRect(x: 0, y: 0, width: 360, height: 220)
        view = host
        preferredContentSize = host.frame.size
    }
}

private struct FailureView: View {
    let failure: DecodeFailure
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Nachricht nicht entschlüsselt", systemImage: "exclamationmark.triangle.fill")
                .font(.headline).foregroundStyle(.orange)
            if !failure.recipientKeyIDs.isEmpty {
                Text("Verschlüsselt für Schlüssel:").font(.caption).foregroundStyle(.secondary)
                Text(failure.recipientKeyIDs.joined(separator: "\n")).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
            }
            if !failure.addressesWithoutKey.isEmpty {
                Text("Kein privater Schlüssel hinterlegt für:").font(.caption).foregroundStyle(.secondary)
                Text(failure.addressesWithoutKey.joined(separator: "\n")).font(.caption)
            }
            Spacer(minLength: 0)
            Button("Schlüsselverwaltung öffnen") {
                NSWorkspace.shared.open(URL(string: "openpgpmail://keys")!)
            }.keyboardShortcut(.defaultAction)
        }
        .padding(16)
        .frame(width: 360, height: 220, alignment: .topLeading)
    }
}
