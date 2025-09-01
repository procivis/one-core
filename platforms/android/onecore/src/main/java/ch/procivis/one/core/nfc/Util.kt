package ch.procivis.one.core.nfc

import android.util.Log
import ch.procivis.one.core.NfcException

object Util {
    private val HEX_ARRAY: CharArray = "0123456789ABCDEF".toCharArray()
    fun bytesToHex(bytes: ByteArray): String {
        val hexChars = CharArray(bytes.size * 2)

        for (j in bytes.indices) {
            val v = bytes[j].toInt() and 0xFF
            hexChars[j * 2] = HEX_ARRAY[v ushr 4]
            hexChars[j * 2 + 1] = HEX_ARRAY[v and 0x0F]
        }

        return String(hexChars)
    }

    inline fun <R> exceptionWrapper(function: () -> R): R {
        try {
            return function()
        } catch (error: NfcException) {
            Log.w("NFC", "NfcException: $error")
            throw error
        } catch (error: Throwable) {
            Log.w("NFC", "Throwable: $error")
            throw NfcException.Unknown(error.toString())
        }
    }
}