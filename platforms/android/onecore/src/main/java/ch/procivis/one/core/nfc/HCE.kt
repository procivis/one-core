package ch.procivis.one.core.nfc

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.nfc.NfcAdapter
import android.util.Log
import ch.procivis.one.core.NfcException
import ch.procivis.one.core.NfcHce
import ch.procivis.one.core.NfcHceHandler
import ch.procivis.one.core.nfc.Util.exceptionWrapper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlin.coroutines.EmptyCoroutineContext
import org.greenrobot.eventbus.EventBus
import org.greenrobot.eventbus.Subscribe

class HCE(val context: Context) : NfcHce {
    companion object {
        private const val TAG = "NFC_HCE"

        private val RESPONSE_STATUS_ERROR_NO_PRECISE_DIAGNOSIS = byteArrayOf(0x6f.toByte(), 0x00.toByte())

        private val eventBus = EventBus.getDefault()
        private val scope = CoroutineScope(EmptyCoroutineContext)
    }

    class ApduCommand(val command: ByteArray)
    class ApduResponse(val response: ByteArray)
    class DisconnectEvent
    class StopHostingRequest

    private val mNfcAdapter = NfcAdapter.getDefaultAdapter(context)

    private class Handler(val handler: NfcHceHandler) {
        @Subscribe
        fun onApduCommand(event: ApduCommand) {
            Log.d(TAG, "onApduCommand: ${event.command.size}")
            var response: ByteArray? = null
            try {
                response = handler.handleCommand(event.command)
            } catch (e: Throwable) {
                Log.wtf(TAG, "Failure handling command: $e")
            }

            eventBus.post(ApduResponse(response ?: RESPONSE_STATUS_ERROR_NO_PRECISE_DIAGNOSIS))
        }

        @Subscribe
        fun onDisconnect(event: DisconnectEvent) {
            Log.d(TAG, "onDisconnect")
            scope.launch {
                try {
                    handler.onScannerDisconnected()
                } catch (error: Throwable) {
                    Log.wtf(TAG, "onScannerDisconnected failed: $error")
                }
            }
        }
    }

    private var mHandler: Handler? = null

    override suspend fun isEnabled(): Boolean {
        return mNfcAdapter != null && mNfcAdapter.isEnabled
    }

    override suspend fun isSupported(): Boolean {
        return mNfcAdapter != null && context.packageManager
            .hasSystemFeature(PackageManager.FEATURE_NFC_HOST_CARD_EMULATION)
    }

    override suspend fun startHosting(handler: NfcHceHandler, message: String?) {
        Log.d(TAG, "startHosting")
        return exceptionWrapper {
            if (!isSupported()) {
                throw NfcException.NotSupported()
            }
            if (!isEnabled()) {
                throw NfcException.NotEnabled()
            }

            synchronized(this) {
                if (mHandler != null) {
                    throw NfcException.AlreadyStarted()
                }

                val intent: Intent = Intent(context, EngagementService::class.java)
                if (context.startService(intent) == null) {
                    throw NfcException.Unknown("Engagement service not started")
                }

                mHandler = Handler(handler)
                eventBus.register(mHandler)
            }
        }
    }

    override suspend fun stopHosting(success: Boolean) {
        Log.d(TAG, "stopHosting")
        synchronized(this) {
            if (mHandler == null) {
                throw NfcException.NotStarted()
            }

            eventBus.unregister(mHandler)
            mHandler = null

            eventBus.post(StopHostingRequest())
        }
    }
}