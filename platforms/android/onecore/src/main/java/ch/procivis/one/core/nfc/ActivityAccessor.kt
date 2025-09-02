package ch.procivis.one.core.nfc

import android.app.Activity

interface ActivityAccessor {
    fun getCurrentActivity(): Activity?
}