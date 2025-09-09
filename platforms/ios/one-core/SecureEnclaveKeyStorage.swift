//
//  SecureEnclaveKeyStorage.swift
//

import Foundation
import CryptoKit
import LocalAuthentication
import DeviceCheck

public class SecureEnclaveKeyStorage: NativeKeyStorage {
    public init() {}
    
    public func generateKey(keyAlias: String) async throws -> GeneratedKeyBindingDto {
        if (!isSupported()) {
            throw NativeKeyStorageError.Unsupported;
        }
        
        do {
            let accessControl = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage],
                nil
            );
            
            let newKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl!, authenticationContext: LAContext());
            
            // convert to compressed form
            let publicKeyBytes = [UInt8](newKey.publicKey.rawRepresentation);
            let x = publicKeyBytes[0..<32];
            let ySign: UInt8 = publicKeyBytes[63] & 1;
            var compressed: [UInt8] = [2 + ySign];
            compressed.append(contentsOf: x);
            
            return GeneratedKeyBindingDto(keyReference: newKey.dataRepresentation, publicKey: Data(compressed));
        } catch {
            throw NativeKeyStorageError.KeyGenerationFailure(reason: error.localizedDescription);
        }
    }

    public func generateAttestation(keyReference: Data, nonce: String?) async throws -> [String] {
        guard isAttestationSupported() else {
            throw NativeKeyStorageError.Unsupported
        }

        guard #available(iOS 14.0, *) else {
            throw NativeKeyStorageError.Unsupported
        }

        guard let nonce = nonce, let nonceData = nonce.data(using: .utf8) else {
            throw NativeKeyStorageError.KeyGenerationFailure(reason: "Invalid nonce \(nonce ?? "nil")")
        }
        guard let keyId = String(data: keyReference, encoding: .utf8) else {
            throw NativeKeyStorageError.KeyGenerationFailure(reason: "Invalid key reference format for App Attest")
        }
        let hash = Data(SHA256.hash(data: nonceData))
        do {
            let attestationData = try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: hash)
            return [attestationData.base64EncodedString()]
        } catch let error as NSError {
            if error.domain == "com.apple.devicecheck.error" {
                switch error.code {
                case 1:
                    throw NativeKeyStorageError.Unknown(reason: "Device Check service unavailable")
                case 2:
                    throw NativeKeyStorageError.KeyGenerationFailure(reason: "Invalid key ID or client data hash for App Attest service")
                case 3:
                    throw NativeKeyStorageError.Unknown(reason: "Device Check feature disabled")
                case 4:
                    throw NativeKeyStorageError.Unknown(reason: "Device Check server unavailable")
                default:
                    throw NativeKeyStorageError.Unknown(reason: "Device Check error \(error.code): \(error.localizedDescription)")
                }
            } else {
                throw NativeKeyStorageError.Unknown(reason: error.localizedDescription)
            }
        }
    }

    public func sign(keyReference: Data, message: Data) async throws -> Data {
        if (!isSupported()) {
            throw NativeKeyStorageError.Unsupported;
        }
        
        do {
            let privateKey = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyReference, authenticationContext: LAContext());
            let signature = try privateKey.signature(for: message);
            return signature.rawRepresentation;
        } catch {
            throw NativeKeyStorageError.SignatureFailure(reason: error.localizedDescription);
        }
    }

    public func generateAttestationKey(keyAlias: String, nonce: String?) async throws -> GeneratedKeyBindingDto {
        guard #available(iOS 14.0, *) else {
            throw NativeKeyStorageError.Unsupported
        }

        guard isAttestationSupported() else {
            throw NativeKeyStorageError.Unsupported
        }

        return try await withCheckedThrowingContinuation { continuation in
            DCAppAttestService.shared.generateKey { keyId, error in
                if let error = error {
                    continuation.resume(throwing: NativeKeyStorageError.KeyGenerationFailure(reason: error.localizedDescription))
                } else if let keyId = keyId {
                    let keyReference = keyId.data(using: .utf8) ?? Data()
                    continuation.resume(returning: GeneratedKeyBindingDto(keyReference: keyReference, publicKey: Data()))
                } else {
                    continuation.resume(throwing: NativeKeyStorageError.KeyGenerationFailure(reason: "No key ID returned"))
                }
            }
        }
    }

    private func isSupported() -> Bool {
        #if targetEnvironment(simulator)
            return false
        #else
            return SecureEnclave.isAvailable
        #endif
    }

    private func isAttestationSupported() -> Bool {
        #if targetEnvironment(simulator)
            return false
        #else
            if #available(iOS 14.0, *) {
                return DCAppAttestService.shared.isSupported
            } else {
                return false
            }
        #endif
    }
  }
