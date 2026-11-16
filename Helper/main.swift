import Foundation
import PGPMailXPC

let delegate = GPGServiceListenerDelegate()
let listener = NSXPCListener.service()
listener.delegate = delegate
listener.resume()
