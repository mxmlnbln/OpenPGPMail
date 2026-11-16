import Foundation
import PGPMailCore

// Debug helper: `opgpm decode < message.eml` runs the same decode path as the Mail extension.
let input = FileHandle.standardInput.readDataToEndOfFile()
let args = CommandLine.arguments
guard args.count >= 2, args[1] == "decode" else { FileHandle.standardError.write(Data("usage: opgpm decode < message\n".utf8)); exit(2) }
do {
    let gpg = try GPG.locate()
    let d = try PGPMIME(gpg: gpg).decode(input)
    print("encrypted=\(d.wasEncrypted) signature=\(String(describing: d.signature?.state)) keyID=\(d.signature?.keyID ?? "-")")
    let text = String(decoding: d.message, as: UTF8.self)
    print("decoded bytes=\(d.message.count) crlf=\(text.contains("\r\n")) lf-only-body=\(text.contains("\n\n") && !text.contains("\r"))")
} catch {
    print("ERROR: \(error)")
}
