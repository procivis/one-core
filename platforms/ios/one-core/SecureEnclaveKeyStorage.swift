//
//  SecureEnclaveKeyStorage.swift
//

import Foundation
import CryptoKit
import LocalAuthentication

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
        throw NativeKeyStorageError.Unsupported;
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

    private func isSupported() -> Bool {
        #if targetEnvironment(simulator)
            return false
        #else
            return SecureEnclave.isAvailable
        #endif
    }
}
