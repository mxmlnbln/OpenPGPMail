# OpenPGPMail

OpenPGP (PGP/MIME und Inline-PGP) für Apple Mail – als freie, reine Swift-Implementierung auf Basis der öffentlichen
**MailKit**-API (`MEMessageSecurityHandler`). Kein Mail-Bundle, kein Swizzling, kein Objective-C.

Die Kryptografie macht dein vorhandenes **GnuPG**; OpenPGPMail ruft `gpg` nur als Prozess auf und sieht nie eine Passphrase.

> **Status:** früher Stand, vom Autor im Alltag getestet (macOS 27, Mail, MacGPG2 2.2). Es gibt **keine fertigen Downloads**:
> Du baust und signierst die App selbst (siehe unten). Ein kostenloser Apple-Account genügt.

## Funktionen
- Entschlüsseln und Signaturprüfung: PGP/MIME (RFC 3156) und Inline-PGP
- Signieren und Verschlüsseln beim Senden (PGP/MIME; Inline-PGP automatisch für reine Textmails)
- Schlüsselverwaltung: privaten Schlüssel importieren und testen, Zuordnung Adresse → Schlüssel, Warnung bei fehlendem Schlüssel
- Empfängerschlüssel per Web Key Directory (abschaltbar), wählbares Vertrauensmodell
- Einrichtungsprüfung in der App (GnuPG, Pinentry, Erweiterung aktiv?)

## Voraussetzungen
- macOS 13 oder neuer, Xcode 16 oder neuer
- [XcodeGen](https://github.com/yonaskolb/XcodeGen): `brew install xcodegen`
- GnuPG: [GPG Suite](https://gpgtools.org) (empfohlen) oder `brew install gnupg pinentry-mac`
- Ein Apple-Account in Xcode (Xcode → Einstellungen → Accounts). Das kostenlose „Personal Team“ reicht.

## Bauen, selbst signieren, installieren
```bash
git clone <dieses Repository> && cd OpenPGPMail
DEVELOPMENT_TEAM=<DEINE_TEAM_ID> scripts/build-and-install.sh
```
Die Team-ID findest du in Xcode unter Einstellungen → Accounts → dein Team, oder im Apple-Developer-Portal unter „Membership“.
Alternativ: `xcodegen generate`, `OpenPGPMail.xcodeproj` in Xcode öffnen, bei allen drei Targets unter „Signing & Capabilities“ dein Team
wählen und das Schema `OpenPGPMailApp` bauen; die App nach `~/Applications` oder `/Programme` kopieren und einmal starten.

Danach: **Mail → Einstellungen → Erweiterungen → „OpenPGPMail“ aktivieren**, Mail neu starten. Die App zeigt an, was noch fehlt.

Hinweise zum Selbst-Signieren:
- Mit dem kostenlosen Personal Team läuft das Zertifikat nach einiger Zeit ab; dann einfach neu bauen.
- Trage deine Team-ID nicht ins Repository ein (Umgebungsvariable oder lokale `.xcconfig`).
- Der XPC-Helper lässt nur Verbindungen von Programmen zu, die mit **derselben Team-ID** signiert sind wie er selbst
  (wird zur Laufzeit aus der eigenen Signatur gelesen).

## Aufbau
- `Sources/PGPMailCore` – MIME-Parser, `gpg`-Wrapper, PGP/MIME- und Inline-Decode/Encode, Schlüssel- und Konfigurationsmodell
- `Sources/PGPMailXPC` – XPC-Protokoll, Service und Client
- `Extension/` – MailKit-Erweiterung (sandboxed, ohne Netzwerk)
- `Helper/` – XPC-Service (nicht sandboxed; startet `gpg`, erreicht `gpg-agent`), eingebettet in die Erweiterung
- `App/` – Host-App: Schlüssel, Einstellungen, Einrichtungsprüfung
- `Sources/opgpm` – Debug-CLI: `swift run opgpm decode < nachricht.eml`
- `tools/make-icon.swift` – erzeugt das App-Icon

`swift test` führt die Tests aus – gegen ein temporäres `GNUPGHOME`, dein Schlüsselbund bleibt unberührt.

## Sicherheit
Was die Software tut, um dich zu schützen:
- **Status und Meldungen getrennt:** gpg schreibt Statuszeilen in eine private Datei (`--status-file`), nie gemischt mit Text aus Nachrichten.
- **Keine Options-Injection:** Adressen und Fingerabdrücke werden streng geprüft, bevor sie an `gpg` gehen, und stehen hinter `--`.
- **Signatur ≠ Absender:** Eine gültige Signatur wird nur dann ohne Warnung angezeigt, wenn der Schlüssel zur Absenderadresse gehört.
  Abgelaufene oder widerrufene Schlüssel gelten nicht als gültig.
- **Inline-PGP:** Text außerhalb des signierten/verschlüsselten Blocks wird sichtbar als ungeschützt markiert. Inline-Blöcke in Mails mit
  HTML-Teilen werden nicht entschlüsselt (Schutz gegen EFAIL-artige Tricks).
- **Bcc:** Bcc-Empfänger werden als versteckte Empfänger verschlüsselt; ihre Schlüssel-IDs sind für andere nicht sichtbar.
- Die Erweiterung läuft in der Sandbox ohne Netzwerkzugriff; nur der Helper spricht mit `gpg`.

Bekannte Grenzen:
- **Betreff und Kopfzeilen sind nicht verschlüsselt** (keine „Protected Headers“).
- Standard-Vertrauensmodell „allen Schlüsseln im Schlüsselbund vertrauen“: bequem, aber ein untergeschobener Schlüssel fällt nicht auf.
  Mit „Web of Trust“ gilt gpgs Gültigkeitsprüfung.
- WKD verrät der Empfänger-Domain, dass du an eine Adresse schreibst; per WKD gefundene Schlüssel werden ohne Rückfrage importiert.
- Kein Audit durch Dritte. Sicherheitslücken bitte als GitHub-Issue oder vertraulich über „Security Advisories“ melden.

## Einstellungen
Gespeichert in `~/Library/Application Support/OpenPGPMail/config.json`: Zuordnung Adresse → Schlüssel, Sendeformat
(automatisch oder immer PGP/MIME), Vertrauensmodell, WKD-Suche.

## Erkenntnisse zu Mail/MailKit
- Mail übergibt Nachrichten mit **LF**-Zeilenenden. Gibt `encode` CRLF zurück, stürzt Mail ab (`-[__NSSetM addObject:]: object cannot be nil`
  in `ComposeBackEndWK2`). Zeilenenden der Eingabe beibehalten.
- Entschlüsselte Nachrichten müssen **einheitliche** Zeilenenden haben, sonst findet Mail keine Leerzeile zwischen Kopf und Text („kein Inhalt“).
- `decodedMessage` wird auch mit **unvollständigen** Daten aufgerufen (Body noch nicht geladen). Dann `nil` zurückgeben, keinen Fehler –
  Mail speichert Fehlerergebnisse zwischen.
- Principal-Klasse und Handler dürfen nicht `@MainActor` sein (Mail ruft sie auf XPC-Threads auf).
- **gpg-Versionen:** MacGPG2 wird vor Homebrew bevorzugt. Ein gpg 2.5 mit einem 2.2-Agent (oder umgekehrt) hat in einem Fall
  „fehlerhafter geheimer Schlüssel“ bei importierten RSA-Schlüsseln verursacht.
- Tests: `GNUPGHOME` muss kurz sein (Längenlimit für Unix-Sockets).

## Lizenz und Abgrenzung
MIT, siehe `LICENSE`. Dieses Projekt ist ein Neubau gegen MailKit und enthält keinen Code aus GPGMail oder Free-GPGMail.
Es steht in keiner Verbindung zu GPGTools; „GPGMail“ und „GPG Suite“ sind deren Namen.
