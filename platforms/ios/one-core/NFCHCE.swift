import Foundation
import CoreNFC
import OSLog

@available(iOS 17.4, *)
public class NFCHCE: NSObject {
  private let logger = Logger(subsystem: "ch.procivis.one.core", category: "NFC")
  private let lock = NSLock()
  private var cardSession: CardSession?
}

@available(iOS 17.4, *)
extension NFCHCE: NfcHce {
  public func isSupported() async -> Bool {
    if !CardSession.isSupported {
      return false
    }

    // Beware of this call - it raises fatal error if app not eligible
    let eligible = await CardSession.isEligible
    return eligible
  }

  public func isEnabled() -> Bool {
    return true
  }

  public func startHosting(handler: NfcHceHandler, message: String?) async throws {
    logger.debug("startHosting, message: \(message ?? "N/A")")

    let supported = await isSupported()
    if (!supported) {
      throw NfcError.NotSupported;
    }

    try lock.withLock {
      if (cardSession != nil) {
        throw NfcError.AlreadyStarted
      }
    }

    let presentmentIntent: NFCPresentmentIntentAssertion
    let session: CardSession
    do {
      presentmentIntent = try await NFCPresentmentIntentAssertion.acquire()
      session = try await CardSession()
    } catch {
      throw NfcError.Unknown(reason: "Failed to create session: \(error)");
    }

    lock.withLock {
      cardSession = session
    }

    Task {
      do {
        for try await event in session.eventStream {
          logger.debug("Event \(String(describing: event), privacy: .sensitive)")

          switch event {
          case .sessionStarted:
            if let message = message {
              session.alertMessage = message
            }
            try await session.startEmulation()
            break

          case .readerDetected:
            break

          case .received(let cardAPDU):
            let response = handler.handleCommand(apdu: cardAPDU.payload)
            try await cardAPDU.respond(response: response)
            logger.debug("response sent: \(response, privacy: .sensitive)")
            break

          case .readerDeselected:
            await handler.onScannerDisconnected()
            break

          case .sessionInvalidated(reason: let reason):
            await handler.onSessionStopped(reason: translateError(reason))
            await stop(status: .failure)
            return
          }
        }
      } catch {
        await stop(status: .failure)
      }
    }
  }

  public func stopHosting(success: Bool) async {
    logger.debug("stopHosting, success: \(success)")
    await stop(status: success ? .success : .failure)
  }

  private func stop(status: CardSession.EmulationUIStatus) async {
    await cardSession?.stopEmulation(status: status)
    cardSession?.invalidate()
    cardSession = nil
  }

  private func translateError(_ error: CardSession.Error) -> NfcError {
    switch error {
    case .invalidated: fallthrough
    case .userInvalidated: fallthrough
    case .emulationStopped:
      return NfcError.Cancelled
    case .maxSessionDurationReached:
      return NfcError.SessionClosed
    case .systemEligibilityFailed:
      return NfcError.NotSupported
    case .radioDisabled: fallthrough
    case .systemNotAvailable:
      return NfcError.NotEnabled
    default:
      return NfcError.Unknown(reason: error.localizedDescription)
    }
  }
}
