package ch.procivis.one.core.nfc

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.nfc.NfcAdapter
import ch.procivis.one.core.NfcException
import ch.procivis.one.core.NfcHce
import ch.procivis.one.core.nfc.Util.exceptionWrapper
import org.greenrobot.eventbus.EventBus
import org.greenrobot.eventbus.Subscribe
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

class HCE(val context: Context) : NfcHce {
    private val mNfcAdapter = NfcAdapter.getDefaultAdapter(context)

    private var mStarted = false

    override suspend fun isEnabled(): Boolean {
        return mNfcAdapter != null && mNfcAdapter.isEnabled
    }

    override suspend fun isSupported(): Boolean {
        return mNfcAdapter != null && context.packageManager
            .hasSystemFeature(PackageManager.FEATURE_NFC_HOST_CARD_EMULATION)
    }

    override suspend fun startHostData(data: ByteArray) {
        return exceptionWrapper {
            if (!isSupported()) {
                throw NfcException.NotSupported()
            }
            if (!isEnabled()) {
                throw NfcException.NotEnabled()
            }
            if (mStarted) {
                throw NfcException.AlreadyStarted()
            }

            val intent: Intent = Intent(context, EngagementService::class.java)
            intent.putExtra("data", data)
            if (context.startService(intent) == null) {
                throw NfcException.Unknown("Engagement service not started")
            }

            mStarted = true
        }
    }

    override suspend fun stopHostData(): Boolean {
        if (!mStarted) {
            throw NfcException.NotStarted()
        }

        return suspendCoroutine { continuation ->
            EventBus.getDefault().register(object : Any() {
                @Subscribe
                fun onStopResponse(event: StopHceResponse) {
                    continuation.resume(event.messageRead)
                    mStarted = false
                    EventBus.getDefault().unregister(this)
                }
            })
            EventBus.getDefault().post(StopHceRequest())
        }
    }
}