package ch.procivis.one.core

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.Base64
import android.util.Log
import androidx.core.graphics.drawable.toBitmap
import androidx.credentials.registry.digitalcredentials.mdoc.MdocEntry
import androidx.credentials.registry.digitalcredentials.mdoc.MdocField
import androidx.credentials.registry.digitalcredentials.openid4vp.OpenId4VpRegistry
import androidx.credentials.registry.digitalcredentials.sdjwt.SdJwtClaim
import androidx.credentials.registry.digitalcredentials.sdjwt.SdJwtEntry
import androidx.credentials.registry.provider.ClearCredentialRegistryRequest
import androidx.credentials.registry.provider.RegistryManager
import androidx.credentials.registry.provider.digitalcredentials.DigitalCredentialEntry
import androidx.credentials.registry.provider.digitalcredentials.VerificationEntryDisplayProperties
import androidx.credentials.registry.provider.digitalcredentials.VerificationFieldDisplayProperties

/**
 * Default implementation of native credential manager
 */
@SuppressLint("LogNotTimber")
class AndroidCredentialManager(private val context: Context) : CredentialManager {
    internal companion object {
        private const val TAG = "CredentialManager"
        private const val ID = "ch.procivis.one.core.CredentialManager.ID"
    }

    override suspend fun synchronize(credentials: List<DigitalCredentialRegistration>) {
        Log.d(TAG, "synchronize: credentials: ${credentials.size}")

        try {
            val registryManager = RegistryManager.create(context)
            val request = OpenId4VpRegistry(
                buildCredentialEntries(credentials), id = ID
            )

            // remove old entries
            registryManager.clearCredentialRegistry(
                request = ClearCredentialRegistryRequest(
                    deletePerTypeConfig = ClearCredentialRegistryRequest.PerTypeConfig(
                        isDeleteAll = false, type = request.type, registryIds = listOf(ID)
                    )
                )
            )

            // register new entries
            val result = registryManager.registerCredentials(request)
            Log.d(TAG, "Credentials registered: ${result.type}")

        } catch (e: CredentialManagerException) {
            Log.d(TAG, "CredentialManager::synchronize error", e)
            throw e;
        } catch (e: Throwable) {
            Log.w(TAG, "CredentialManager::synchronize unknown error", e)
            throw CredentialManagerException.SynchronizationException(e.toString());
        }
    }

    private fun buildCredentialEntries(credentials: List<DigitalCredentialRegistration>): List<DigitalCredentialEntry> {
        val result = mutableListOf<DigitalCredentialEntry>()
        for (credential in credentials) {
            result.add(buildCredentialEntry(credential))
        }
        return result
    }

    private fun buildCredentialEntry(credential: DigitalCredentialRegistration): DigitalCredentialEntry {
        val (credentialId, metadata, claims, display) = credential

        return when (metadata) {
            is DigitalCredentialMetadata.Mdoc -> {
                MdocEntry(
                    id = credentialId,
                    docType = metadata.doctype,
                    fields = buildMdocFields(claims),
                    entryDisplayPropertySet = setOf(buildEntryDisplayProperties(display))
                )
            }

            is DigitalCredentialMetadata.SdJwtVc -> {
                SdJwtEntry(
                    id = credentialId,
                    verifiableCredentialType = metadata.vct,
                    claims = buildSdJwtClaims(claims),
                    entryDisplayPropertySet = setOf(buildEntryDisplayProperties(display))
                )
            }
        }
    }

    private fun buildMdocFields(claims: List<DigitalCredentialClaim>): List<MdocField> {
        val result = mutableListOf<MdocField>()
        for ((path, displayName, _) in claims) {
            if (path.size < 2) {
                throw CredentialManagerException.SynchronizationException("Invalid claim path: $path");
            } else if (path.size > 2) {
                Log.d(TAG, "Skipping nested claim: $path")
                continue;
            }

            result.add(
                MdocField(
                    namespace = path[0], identifier = path[1], fieldDisplayPropertySet = setOf(
                        VerificationFieldDisplayProperties(
                            displayName = displayName ?: path[1], displayValue = null
                        )
                    ), fieldValue = null
                )
            )
        }
        return result
    }

    private fun buildSdJwtClaims(claims: List<DigitalCredentialClaim>): List<SdJwtClaim> {
        val result = mutableListOf<SdJwtClaim>()
        for ((path, displayName, selectivelyDisclosable) in claims) {
            result.add(
                SdJwtClaim(
                    path = path,
                    value = null,
                    fieldDisplayPropertySet = setOf(
                        VerificationFieldDisplayProperties(
                            displayName = displayName ?: path.joinToString("/"), displayValue = null
                        )
                    ),
                    isSelectivelyDisclosable = selectivelyDisclosable,
                )
            )
        }
        return result
    }

    private fun buildEntryDisplayProperties(display: DigitalCredentialDisplay): VerificationEntryDisplayProperties {
        return VerificationEntryDisplayProperties(
            title = display.credentialName,
            subtitle = display.issuerName,
            icon = tryDecodeLogo(display.logo) ?: getAppIcon(),
            explainer = null,
            warning = null,
            metadataDisplayText = null
        )
    }

    private fun getAppIcon(): Bitmap {
        val packageManager = context.packageManager
        val drawable = packageManager.getApplicationIcon(context.packageName)

        val width = drawable.intrinsicWidth.takeIf { it >= 32 } ?: 32
        val height = drawable.intrinsicHeight.takeIf { it >= 32 } ?: 32
        return drawable.toBitmap(width, height)
    }

    private fun tryDecodeLogo(logo: String?): Bitmap? {
        if (logo == null) {
            return null
        }

        // Only PNG/JPEG data URL supported
        if (!logo.startsWith("data:image/png;base64,") && !logo.startsWith("data:image/jpeg;base64,")) {
            return null
        }

        try {
            val base64Cleaned = logo.substring(logo.indexOf(",") + 1)
            val decodedBytes = Base64.decode(base64Cleaned, Base64.DEFAULT)
            return BitmapFactory.decodeByteArray(decodedBytes, 0, decodedBytes.size)
        } catch (e: Throwable) {
            Log.w(TAG, "Failed to decode logo image", e)
            return null
        }
    }
}