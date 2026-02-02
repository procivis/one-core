package ch.procivis.one.core.nfc

import android.nfc.TagLostException
import android.util.Log
import ch.procivis.one.core.NfcException
import java.io.IOException

internal object Util {
    inline fun <R> exceptionWrapper(function: () -> R): R {
        try {
            return function()
        } catch (error: NfcException) {
            Log.w("NFC", "NfcException: $error")
            throw error
        } catch (error: TagLostException) {
            Log.w("NFC", "TagLostException: $error")
            throw NfcException.SessionClosed()
        } catch (error: IOException) {
            Log.w("NFC", "IOException: $error")
            throw NfcException.Cancelled()
        } catch (error: Throwable) {
            Log.w("NFC", "Throwable: $error")
            throw NfcException.Unknown(error.toString())
        }
    }
}
