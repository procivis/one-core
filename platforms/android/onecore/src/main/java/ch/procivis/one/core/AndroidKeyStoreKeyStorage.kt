package ch.procivis.one.core

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import uniffi.one_core.GeneratedKeyBindingDto
import uniffi.one_core.NativeKeyStorage
import uniffi.one_core.NativeKeyStorageException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

class AndroidKeyStoreKeyStorage : NativeKeyStorage {
    override fun generateKey(keyAlias: String): GeneratedKeyBindingDto {
        try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
                throw NativeKeyStorageException.KeyGenerationFailure("Insufficient SDK version `${Build.VERSION.SDK_INT}`");
            }

            val keyStore = getAndroidKeyStore()
            if (keyStore.isKeyEntry(keyAlias)) {
                throw NativeKeyStorageException.KeyGenerationFailure("Key alias `${keyAlias}` already exists");
            }

            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
            )

            var keyPurposes = KeyProperties.PURPOSE_SIGN;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                keyPurposes += KeyProperties.PURPOSE_AGREE_KEY
            }

            val builder = KeyGenParameterSpec.Builder(keyAlias, keyPurposes)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)


            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder.setUnlockedDeviceRequired(true).setIsStrongBoxBacked(true)
            }

            keyPairGenerator.initialize(builder.build())
            val pair = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                try {
                    keyPairGenerator.generateKeyPair()
                } catch (e: StrongBoxUnavailableException) {
                    builder.setIsStrongBoxBacked(false)
                    keyPairGenerator.initialize(builder.build())
                    keyPairGenerator.generateKeyPair()
                }
            } else {
                keyPairGenerator.generateKeyPair()
            }

            val privateKey = pair.private
            val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
            val keyInfo = factory.getKeySpec(
                privateKey,
                KeyInfo::class.java
            )

            if (!keyInfo.isInsideSecureHardware) {
                throw NativeKeyStorageException.KeyGenerationFailure("No HW backing");
            }

            // convert to compressed form
            val publicKey = pair.public as ECPublicKey
            val x = toRawBytes(publicKey.w.affineX.toByteArray())
            val y = toRawBytes(publicKey.w.affineY.toByteArray())
            val ySign = ((y[31].toInt() and 0x01) + 0x02).toByte()
            val compressed = byteArrayOf(ySign) + x

            return GeneratedKeyBindingDto(keyAlias.toByteArray(Charsets.UTF_8), compressed)
        } catch (e: NativeKeyStorageException) {
            throw e;
        } catch (e: Throwable) {
            throw NativeKeyStorageException.KeyGenerationFailure(e.toString());
        }
    }

    override fun sign(keyReference: ByteArray, message: ByteArray): ByteArray {
        try {
            val keyAlias = keyReference.toString(Charsets.UTF_8)

            val keyStore = getAndroidKeyStore()
            val privateKey = keyStore.getKey(keyAlias, null) as PrivateKey
            val signature: Signature = Signature.getInstance("SHA256withECDSA")

            signature.initSign(privateKey)
            signature.update(message)
            return extractSignatureBytes(signature.sign())
        } catch (e: NativeKeyStorageException) {
            throw e;
        } catch (e: Throwable) {
            throw NativeKeyStorageException.SignatureFailure(e.toString());
        }
    }

    private fun getAndroidKeyStore(): KeyStore {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore
    }

    private fun toRawBytes(value: ByteArray): ByteArray {
        // strip leading zero
        if (value.size == 33 && value[0].toInt() == 0x00) {
            return value.copyOfRange(1, 33)
        }
        return value
    }

    private fun extractSignatureBytes(signature: ByteArray): ByteArray {
        val startR = if (signature[1].toInt() and 0x80 != 0) 3 else 2
        val lengthR = signature[startR + 1].toInt()
        val startS = startR + 2 + lengthR
        val lengthS = signature[startS + 1].toInt()
        val r = signature.copyOfRange(startR + 2, startR + 2 + lengthR)
        val s = signature.copyOfRange(startS + 2, startS + 2 + lengthS)
        return toRawBytes(r) + toRawBytes(s)
    }
}