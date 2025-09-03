package ch.procivis.one.core.nfc

import android.app.Activity

fun interface ActivityAccessor {
    fun getCurrentActivity(): Activity?
}