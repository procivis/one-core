//
//  SecureEnclaveKeyStorage.swift
//

import Foundation
import CryptoKit
import LocalAuthentication

class SecureEnclaveKeyStorage: NativeKeyStorage {
    func generateKey(keyAlias: String) throws -> GeneratedKeyBindingDto {
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
    
    func sign(keyReference: Data, message: Data) throws -> Data {
        do {
            let privateKey = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyReference, authenticationContext: LAContext());
            let signature = try privateKey.signature(for: message);
            return signature.rawRepresentation;
        } catch {
            throw NativeKeyStorageError.SignatureFailure(reason: error.localizedDescription);
        }
    }
}
