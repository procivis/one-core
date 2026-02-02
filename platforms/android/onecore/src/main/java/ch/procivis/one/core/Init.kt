package ch.procivis.one.core

import android.content.Context

internal object Init {
    init {
        System.loadLibrary("procivis_one_core")
    }

    private external fun rustlsInit(context: Context): String

    fun initializeRustls(context: Context) {
        val result = rustlsInit(context)
        if (!result.isNullOrEmpty()) {
            throw RuntimeException("Failed to initialize rustls: $result")
        }
    }
}

/**
 * Creates a new instance of Procivis ONE Core SDK
 *
 * @param context Android application context
 * @param params Additional optional init parameters
 * @param dataDirPath Optional directory where ONE Core SDK should persist its data
 *
 * Note that [InitParamsDto.bleCentral], [InitParamsDto.blePeripheral] and [InitParamsDto.nativeSecureElement] fallback to the default implmementations if not provided
 */
public fun initializeCore(context: Context, params: InitParamsDto, dataDirPath: String = context.filesDir.absolutePath): OneCoreBindingInterface {
    Init.initializeRustls(context)

    return uniffiInitializeCore(
        dataDirPath = dataDirPath,
        params = InitParamsDto(
            configJson = params.configJson,
            nativeSecureElement = params.nativeSecureElement ?: AndroidKeyStoreKeyStorage(context),
            bleCentral = params.bleCentral ?: AndroidBLECentral(context),
            blePeripheral = params.blePeripheral ?: AndroidBLEPeripheral(context),
            remoteSecureElement = params.remoteSecureElement,
            nfcHce = params.nfcHce,
            nfcScanner = params.nfcScanner
        )
    )
}
