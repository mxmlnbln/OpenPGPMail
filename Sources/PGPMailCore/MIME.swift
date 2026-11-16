import Foundation

/// Minimal RFC 5322 / RFC 2045 entity model. Bytes are kept as ISO-8859-1 so that
/// round-tripping (needed for PGP/MIME signature verification) is lossless.
public struct MIMEEntity: Sendable, Equatable {
    public var headers: [(name: String, value: String)]
    public var body: String

    public static func == (l: Self, r: Self) -> Bool {
        l.body == r.body && l.headers.elementsEqual(r.headers) { $0.name == $1.name && $0.value == $1.value }
    }

    public init(headers: [(name: String, value: String)], body: String) {
        self.headers = headers
        self.body = body
    }

    public init(data: Data) {
        self.init(string: String(data: data, encoding: .isoLatin1) ?? "")
    }

    public init(string: String) {
        let (head, body) = Self.splitHeaderBody(string)
        self.headers = Self.parseHeaders(head)
        self.body = body
    }

    public var data: Data { serialized.data(using: .isoLatin1) ?? Data() }

    public var serialized: String {
        headers.map { "\($0.name): \($0.value)" }.joined(separator: "\r\n") + "\r\n\r\n" + body
    }

    public func header(_ name: String) -> String? {
        headers.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value
    }

    public var contentType: ContentType? { header("Content-Type").map(ContentType.init) }

    /// Splits a multipart body into its parts (raw text of each part, without delimiters).
    public func multipartParts() -> [String]? {
        guard let boundary = contentType?.parameters["boundary"] else { return nil }
        let delimiter = "--" + boundary
        var parts: [String] = []
        var current: [String] = []
        var inPart = false
        for line in body.components(separatedBy: "\n") {
            var trimmed = line.hasSuffix("\r") ? String(line.dropLast()) : line
            if trimmed.hasPrefix(delimiter) { while trimmed.last == " " || trimmed.last == "\t" { trimmed.removeLast() } }
            if trimmed == delimiter || trimmed == delimiter + "--" {
                if inPart { parts.append(Self.join(current)) }
                current = []
                inPart = trimmed == delimiter
                if !inPart { break }
            } else if inPart {
                current.append(line)
            }
        }
        return parts
    }

    private static func join(_ lines: [String]) -> String {
        // The CRLF before a delimiter belongs to the delimiter (RFC 2046 §5.1.1).
        var s = lines.joined(separator: "\n")
        if s.hasSuffix("\r") { s.removeLast() }
        return s
    }

    /// Splits at the *first* blank line. Mail stores messages with mixed line endings (LF headers,
    /// CRLF in bodies we created), so we must not prefer one separator over the other.
    static func splitHeaderBody(_ s: String) -> (String, String) {
        var best: Range<String.Index>?
        for sep in ["\r\n\r\n", "\n\n", "\r\n\n", "\n\r\n"] {
            if let r = s.range(of: sep), best == nil || r.lowerBound < best!.lowerBound { best = r }
        }
        if let r = best { return (String(s[..<r.lowerBound]), String(s[r.upperBound...])) }
        return (s, "")
    }

    static func parseHeaders(_ head: String) -> [(name: String, value: String)] {
        var result: [(String, String)] = []
        for raw in head.split(whereSeparator: \.isNewline) {
            if raw.first == " " || raw.first == "\t", !result.isEmpty {
                result[result.count - 1].1 += " " + raw.trimmingCharacters(in: .whitespaces)
            } else if let colon = raw.firstIndex(of: ":") {
                result.append((String(raw[..<colon]),
                               raw[raw.index(after: colon)...].trimmingCharacters(in: .whitespaces)))
            }
        }
        return result
    }
}

public struct ContentType: Sendable, Equatable {
    public let type: String            // lowercased, e.g. "multipart/encrypted"
    public let parameters: [String: String]

    public init(_ header: String) {
        let pieces = header.split(separator: ";", omittingEmptySubsequences: true)
        type = pieces.first.map { $0.trimmingCharacters(in: .whitespaces).lowercased() } ?? ""
        var params: [String: String] = [:]
        for p in pieces.dropFirst() {
            guard let eq = p.firstIndex(of: "=") else { continue }
            let key = p[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            var value = p[p.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            if value.hasPrefix("\""), value.hasSuffix("\""), value.count >= 2 { value = String(value.dropFirst().dropLast()) }
            params[key] = value
        }
        parameters = params
    }
}
