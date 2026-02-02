package ch.procivis.one.core.nfc

import android.app.Activity

fun interface ActivityAccessor {
    /**
     * Provides access to the current android [Activity] for reader-mode setup of NFC scanning
     */
    fun getCurrentActivity(): Activity?
}