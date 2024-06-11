package ch.procivis.one.core

import android.content.Context
import android.content.pm.PackageManager
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
import java.security.spec.ECGenParameterSpec
import java.util.Arrays

class AndroidKeyStoreKeyStorage(private val context: Context) : NativeKeyStorage {
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

            var strongbox = false
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                strongbox = this.context.packageManager
                    .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

                if (strongbox) {
                    builder.setIsStrongBoxBacked(true)
                }
            }

            keyPairGenerator.initialize(builder.build())
            val pair = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                try {
                    keyPairGenerator.generateKeyPair()
                } catch (e: StrongBoxUnavailableException) {
                    builder.setIsStrongBoxBacked(false)
                    strongbox = false
                    keyPairGenerator.initialize(builder.build())
                    keyPairGenerator.generateKeyPair()
                }
            } else {
                keyPairGenerator.generateKeyPair()
            }

            val privateKey = pair.private
            val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")

            // on Samsung S20 (with Strongbox support) the keyInfo reports the generated key as Software security level
            // we will assume the generated key is HW secured in this case, since the generation did not produce the `StrongBoxUnavailableException`
            if (!strongbox) {
                val keyInfo = factory.getKeySpec(
                    privateKey,
                    KeyInfo::class.java
                )

                if (!keyInfo.isInsideSecureHardware) {
                    throw NativeKeyStorageException.Unsupported();
                }
            }

            // convert to compressed form
            val encoded = pair.public.encoded
            val pubKeyUncompressedParts = encoded.copyOfRange(encoded.size - 64, encoded.size)
            val x = pubKeyUncompressedParts.copyOfRange(0, 32)
            val y = pubKeyUncompressedParts.copyOfRange(32, 64)
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
        val combined = ByteArray(value.size + 32)
        System.arraycopy(value, 0, combined, 32, value.size)
        return Arrays.copyOfRange(combined, combined.size - 32, combined.size)
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