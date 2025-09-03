//
//  NFCScanner.swift
//

import Foundation
import CoreNFC

typealias ThrowingResultCallback<T> = (Result<T, Error>) -> Void

public class NFCScanner: NSObject {
    private let lock = NSLock()
    private var activeSession: NFCTagReaderSession?
    private var scanCallback: ThrowingResultCallback<Void>?
}

extension NFCScanner: NfcScanner {
    public func isSupported() -> Bool {
#if targetEnvironment(simulator)
        return false
#else
        return NFCTagReaderSession.readingAvailable
#endif
    }

    public func isEnabled() -> Bool {
        return true // on iOS NFC cannot be disabled
    }

    public func scan(message: String?) async throws {
        if (!isSupported()) {
            throw NfcError.NotSupported;
        }


        try lock.withLock {
            if (activeSession != nil) {
                throw NfcError.AlreadyStarted
            }
        }

        guard let session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self) else {
            throw NfcError.Unknown(reason: "Could not start NFC tag reading session")
        }

        if let message = message {
            session.alertMessage = message
        }

        return try await withCheckedThrowingContinuation { continuation in
            lock.withLock {
                if (activeSession != nil) {
                    continuation.resume(throwing: NfcError.AlreadyStarted)
                    return
                }

                activeSession = session
                scanCallback = { [weak self] result in
                    self?.scanCallback = nil
                    continuation.resume(with: result)
                }
            }
            session.begin()
        }
    }

    public func setMessage(message: String) async throws {
        try lock.withLock {
            if let session = activeSession {
                session.alertMessage = message
            } else {
                throw NfcError.NotStarted
            }
        }
    }

    public func cancelScan() async throws {
        try lock.withLock {
            guard let session = activeSession else {
                throw NfcError.NotStarted
            }

            session.invalidate()
            activeSession = nil
        }
    }

    public func transceive(commandApdu: Data) async throws -> Data {
        guard let apdu = NFCISO7816APDU(data: commandApdu) else {
            throw NfcError.Unknown(reason: "Invalid command")
        }

        let session = lock.withLock { activeSession }
        guard let session = session else {
            throw NfcError.SessionClosed
        }

        guard let tag = session.connectedTag else {
            throw NfcError.SessionClosed
        }

        if (!tag.isAvailable) {
            throw NfcError.SessionClosed
        }

        guard let tag = getIsoDep(tag) else {
            throw NfcError.Unknown(reason: "Invalid tag")
        }

        let (data, sw1, sw2) = try await tag.sendCommand(apdu: apdu)
        return data + Data([sw1, sw2])
    }
}

extension NFCScanner: NFCTagReaderSessionDelegate {
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
#if DEBUG
        print("TagReaderSession \(session) didBecomeActive")
#endif
        // nothing to do here
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: any Error) {
#if DEBUG
        print("TagReaderSession \(session) didInvalidateWithError \(String(describing: error))")
#endif
        lock.withLock {
            activeSession = nil
            scanCallback?(Result.failure(NfcError.Cancelled))
        }
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
#if DEBUG
        print("TagReaderSession \(session) didDetect \(tags)")
#endif

        guard let tag = tags.first(where: { $0.isAvailable && getIsoDep($0) != nil }) else {
#if DEBUG
            print("No conforming tag found")
#endif
            return
        }

        let session = lock.withLock { activeSession }
        session?.connect(to: tag, completionHandler: { [weak self] error in
#if DEBUG
            print("Tag connection completed: \(String(describing: error))")
#endif
            self?.lock.withLock{
                if let error = error {
                    self?.scanCallback?(Result.failure(error))
                } else {
                    self?.scanCallback?(Result.success(()))
                }
            }
        })
    }
}


private func getIsoDep(_ tag: NFCTag) -> (any NFCISO7816Tag)? {
    guard case .iso7816(let nFCISO7816Tag) = tag else {
        return nil
    }
    return nFCISO7816Tag
}
