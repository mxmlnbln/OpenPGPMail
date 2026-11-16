import MailKit

/// Mail instantiates the principal class off the main thread, so this class must not be
/// `@MainActor` (Swift 6 would trap with "Block was expected to execute on queue main-thread").
nonisolated final class MailExtension: NSObject, @preconcurrency MEExtension {
    func handlerForMessageSecurity() -> MEMessageSecurityHandler {
        SecurityHandler()
    }
}
