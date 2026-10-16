import IdentityDocumentServices

public class IOSCredentialManager: CredentialManager {

    public init() {}
    
    public func synchronize(credentials: [ProcivisOneCore.DigitalCredentialRegistration]) async throws {
        guard #available(iOS 26.0, *) else {
            throw CredentialManagerError.SynchronizationError(reason: "IdentityDocumentProviderRegistrationStore unavailable")
        }
        let store = IdentityDocumentProviderRegistrationStore()
        let status = try await store.status
        if status == .notSupported {
            throw CredentialManagerError.SynchronizationError(reason: "Device platform is not supported for document providing")
        }
        if status == .notAuthorized {
            throw CredentialManagerError.SynchronizationError(reason: "The user did not authorize app for document providing")
        }
        let registrations = try await store.registrations
        let registeredIds = registrations.map { registration in
            return registration.documentIdentifier
        }
        let credentialIds = credentials.map { credential in
            return credential.credentialId
        }
        for credential in credentials {
            if registeredIds.contains(credential.credentialId) {
                continue
            }
            guard case let .mdoc(doctype) = credential.metadata else {
                continue
            }
            let registration = MobileDocumentRegistration(
                mobileDocumentType: doctype,
                supportedAuthorityKeyIdentifiers: [],
                documentIdentifier: credential.credentialId,
            )
            try await store.addRegistration(registration)
        }
        for registration in registrations {
            if credentialIds.contains(registration.documentIdentifier) {
                continue
            }
            try await store.removeRegistration(forDocumentIdentifier: registration.documentIdentifier)
        }
    }
}
