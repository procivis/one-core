package ch.procivis.one.core.nfc

import android.content.Intent
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log
import org.greenrobot.eventbus.EventBus
import org.greenrobot.eventbus.Subscribe

/**
 * Provided implementation of NFC HCE
 *
 * Must be used together with the [HCE]
 */
class EngagementService : HostApduService() {
    internal companion object {
        private const val TAG = "NFCEngagementService"

        private val RESPONSE_ERROR_FILE_OR_APPLICATION_NOT_FOUND = byteArrayOf(0x6a.toByte(), 0x82.toByte())
    }

    private val eventBus = EventBus.getDefault()

    override fun onStartCommand(intent: Intent, flags: Int, startId: Int): Int {
        Log.d(TAG, "onStartCommand: flags: $flags, startId: $startId")
        if (!eventBus.isRegistered(this)) {
            eventBus.register(this)
        }
        return START_STICKY
    }

    override fun onDestroy() {
        Log.d(TAG, "onDestroy")
        super.onDestroy()
        eventBus.unregister(this)
    }

    @Subscribe
    fun onStopRequest(event: HCE.StopHostingRequest) {
        Log.d(TAG, "onStopRequest");
        eventBus.unregister(this)
        this.stopSelf()
    }

    @Subscribe
    fun onResponse(event: HCE.ApduResponse) {
        Log.d(TAG, "onResponse: ${event.response.size}")
        sendResponseApdu(event.response)
    }

    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray? {
        Log.d(TAG, "processCommandApdu | incoming commandApdu: ${commandApdu.size}")

        // no handler available
        if (!eventBus.hasSubscriberForEvent(HCE.ApduCommand::class.java)) {
            Log.w(TAG, "no subscriber")
            return RESPONSE_ERROR_FILE_OR_APPLICATION_NOT_FOUND
        }

        eventBus.post(HCE.ApduCommand(commandApdu))

        // the response will be sent asynchronously
        return null
    }

    override fun onDeactivated(reason: Int) {
        Log.i(TAG, "onDeactivated, reason: $reason")
        eventBus.post(HCE.DisconnectEvent())
    }
}