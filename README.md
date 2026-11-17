# OpenPGPMail

OpenPGP (PGP/MIME and inline PGP) for Apple Mail: a free, pure Swift implementation built on the public
**MailKit** API (`MEMessageSecurityHandler`). No Mail bundle, no swizzling, no Objective-C.

The cryptography is done by your existing **GnuPG**. OpenPGPMail only runs `gpg` as a process and never sees a passphrase.

## Features
- Decryption and signature verification: PGP/MIME (RFC 3156) and inline PGP
- Signing and encryption when sending (PGP/MIME; inline PGP automatically for plain-text mails)
- Key management: import and test a private key, map addresses to keys, warning when a key is missing
- Recipient keys via Web Key Directory (can be turned off), selectable trust model
- Setup check in the app (GnuPG, pinentry, extension enabled?)

## Requirements
- macOS 13 or later, Xcode 16 or later
- [XcodeGen](https://github.com/yonaskolb/XcodeGen): `brew install xcodegen`
- GnuPG: [GPG Suite](https://gpgtools.org) (recommended) or `brew install gnupg pinentry-mac`
- An Apple account in Xcode (Xcode → Settings → Accounts). The free "Personal Team" is enough.

## Build, self-sign, install
```bash
git clone https://github.com/mxmlnbln/OpenPGPMail.git && cd OpenPGPMail
DEVELOPMENT_TEAM=<YOUR_TEAM_ID> scripts/build-and-install.sh
```
You can find your team ID in Xcode under Settings → Accounts → your team, or in the Apple Developer portal under "Membership".
Alternatively: run `xcodegen generate`, open `OpenPGPMail.xcodeproj` in Xcode, select your team under "Signing & Capabilities"
for all three targets and build the `OpenPGPMailApp` scheme; copy the app to `~/Applications` or `/Applications` and launch it once.

Then: **Mail → Settings → Extensions → enable "OpenPGPMail"** and restart Mail. The app shows what is still missing.

Notes on self-signing:
- With the free Personal Team the certificate expires after a while; just rebuild.
- Do not put your team ID into the repository (use the environment variable or a local `.xcconfig`).
- The XPC helper only accepts connections from programs signed with **the same team ID** as itself
  (read at runtime from its own signature).

## Structure
- `Sources/PGPMailCore` – MIME parser, `gpg` wrapper, PGP/MIME and inline decode/encode, key and configuration model
- `Sources/PGPMailXPC` – XPC protocol, service and client
- `Extension/` – MailKit extension (sandboxed, no network)
- `Helper/` – XPC service (not sandboxed; runs `gpg`, reaches `gpg-agent`), embedded in the extension
- `App/` – host app: keys, settings, setup check
- `Sources/opgpm` – debug CLI: `swift run opgpm decode < message.eml`
- `tools/make-icon.swift` – generates the app icon

`swift test` runs the tests against a temporary `GNUPGHOME`; your keyring is left untouched.

## Security
What the software does to protect you:
- **Status kept apart from messages:** gpg writes status lines to a private file (`--status-file`), never mixed with text from messages.
- **No option injection:** addresses and fingerprints are strictly validated before they are passed to `gpg`, and they come after `--`.
- **Signature ≠ sender:** a valid signature is only shown without a warning if the key belongs to the sender address.
  Expired or revoked keys are not treated as valid.
- **Inline PGP:** text outside the signed/encrypted block is visibly marked as unprotected. Inline blocks in mails with
  HTML parts are not decrypted (protection against EFAIL-style tricks).
- **Bcc:** Bcc recipients are encrypted to as hidden recipients; their key IDs are not visible to others.
- The extension runs sandboxed without network access; only the helper talks to `gpg`.

Known limitations:
- **Subject and headers are not encrypted** when sending (no "protected headers"). Header copies in received mails are hidden.
- The default trust model "trust all keys in the keyring" is convenient, but a planted key goes unnoticed.
  With "Web of Trust", gpg's validity check applies.
- WKD tells the recipient's domain that you are writing to an address; keys found via WKD are imported without asking.
- No third-party audit. Please report vulnerabilities as a GitHub issue or confidentially via "Security Advisories".

## Settings
Stored in `~/Library/Application Support/OpenPGPMail/config.json`: address → key mapping, send format
(automatic or always PGP/MIME), trust model, WKD lookup.

## Notes on Mail/MailKit
- Mail passes messages with **LF** line endings. If `encode` returns CRLF, Mail crashes (`-[__NSSetM addObject:]: object cannot be nil`
  in `ComposeBackEndWK2`). Keep the line endings of the input.
- Decrypted messages must have **consistent** line endings, otherwise Mail finds no blank line between header and body ("no content").
- `decodedMessage` is also called with **incomplete** data (body not downloaded yet). Return `nil` then, not an error;
  Mail caches error results.
- The principal class and the handler must not be `@MainActor` (Mail calls them on XPC threads).
- **gpg versions:** MacGPG2 is preferred over Homebrew. A gpg 2.5 with a 2.2 agent (or the reverse) caused
  "bad secret key" for imported RSA keys in one case.
- Tests: `GNUPGHOME` must be short (length limit for Unix sockets).

## License and disclaimer
MIT, see `LICENSE`. This project is a new implementation against MailKit and contains no code from GPGMail or Free-GPGMail.
It is not affiliated with GPGTools; "GPGMail" and "GPG Suite" are their names.
