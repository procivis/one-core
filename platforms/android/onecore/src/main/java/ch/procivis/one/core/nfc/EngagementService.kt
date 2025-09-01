package ch.procivis.one.core.nfc

import android.content.Intent
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log
import org.greenrobot.eventbus.EventBus
import org.greenrobot.eventbus.Subscribe

class EngagementService : HostApduService() {
    private object Companion {
        const val TAG = "NFCEngagementService"

        val CAPABILITY_CONTAINER = byteArrayOf(
            0x00.toByte(), 0x0f.toByte(), // CCLEN, length of the CC file (15 bytes)
            0x20.toByte(), // Mapping Version 2.0
        ).plus(toLengthBytes(Constant.Apdu.MAX_R_APDU))
            .plus(toLengthBytes(Constant.Apdu.MAX_C_APDU))
            .plus(
                byteArrayOf(
                    0x04.toByte(), // T field of the NDEF File Control TLV
                    0x06.toByte(), // L field of the NDEF File Control TLV
                )
            ).plus(Constant.HceFile.NDEF_FILE_ID).plus(
                byteArrayOf(
                    0xFF.toByte(), 0xFE.toByte(), // Maximum NDEF file size of 65534 bytes
                    0x00.toByte(), // Read access without any security
                    0xFF.toByte(), // no Write access (read-only)
                )
            )

        // Big-endian 2-byte representation
        fun toLengthBytes(value: Int): ByteArray {
            return byteArrayOf(toByte(value / 0x100), toByte(value))
        }

        private fun toByte(value: Int): Byte {
            return (value and 0xff).toByte()
        }
    }

    private var mNDEFFile: ByteArray? = null; // nlen + handoverSelect message
    private var mSelectedFile: ByteArray? = null;
    private var mMessageRead: Boolean = false;

    override fun onStartCommand(intent: Intent, flags: Int, startId: Int): Int {
        Log.d(Companion.TAG, "onStartCommand: flags: $flags, startId: $startId")
        if (!intent.hasExtra("data")) {
            return START_STICKY;
        }

        val data = intent.getByteArrayExtra("data")
            ?: return START_STICKY

        mNDEFFile = Companion.toLengthBytes(data.size).plus(data);
        mMessageRead = false

        EventBus.getDefault().register(this);
        return START_STICKY;
    }

    @Subscribe
    fun onStopRequest(event: StopHceRequest) {
        Log.d(Companion.TAG, "onStopRequest");
        mNDEFFile = null;
        EventBus.getDefault().unregister(this);
        EventBus.getDefault().post(StopHceResponse(mMessageRead))
        this.stopSelf()
    }

    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray? {
        //
        // The following flow is based on Appendix E "Example of Mapping Version 2.0 Command Flow"
        // in the NFC Forum specification
        //
        Log.d(Companion.TAG, "processCommandApdu() | incoming commandApdu: $commandApdu")

        if (mNDEFFile == null) {
            Log.d(Companion.TAG, "Currently not available")
            return Constant.HceResponse.A_NOT_AVAILABLE;
        }

        //
        // First command: NDEF Tag Application select (Section 5.5.2 in NFC Forum spec)
        //
        if (commandApdu.contentEquals(Constant.HceCommand.SELECT_APPLICATION)) {
            Log.d(Companion.TAG, "SELECT_APPLICATION triggered.")
            mSelectedFile = null;
            return Constant.HceResponse.A_OKAY
        }

        // Select file (CC or NDEF)
        if (commandApdu.sliceArray(0..4).contentEquals(Constant.HceCommand.SELECT_FILE)) {
            val fileID = commandApdu.sliceArray(5..6);
            if (fileID.contentEquals(Constant.HceFile.CAPABILITY_CONTAINER_ID)) {
                Log.d(Companion.TAG, "SELECT CC triggered.")
                mSelectedFile = Companion.CAPABILITY_CONTAINER;
                return Constant.HceResponse.A_OKAY
            }

            if (fileID.contentEquals(Constant.HceFile.NDEF_FILE_ID)) {
                Log.d(Companion.TAG, "SELECT NDEF triggered.")
                mSelectedFile = mNDEFFile;
                mMessageRead = true
                return Constant.HceResponse.A_OKAY
            }
        }

        // Read file (previously selected)
        if (commandApdu.sliceArray(0..1).contentEquals(Constant.HceCommand.NDEF_READ_BINARY)) {
            val selectedFile = mSelectedFile;
            if (selectedFile == null) {
                Log.wtf(Companion.TAG, "NDEF_READ_BINARY - No file selected")
                return Constant.HceResponse.A_ERROR
            }

            val offset = Util.bytesToHex(commandApdu.sliceArray(2..3)).toInt(16)
            val expectedLength = Util.bytesToHex(commandApdu.sliceArray(4..4)).toInt(16)

            Log.d(Companion.TAG, "NDEF_READ_BINARY triggered.")
            Log.d(Companion.TAG, "READ_BINARY - OFFSET: $offset - LEN: $expectedLength")

            if (selectedFile.size <= offset) {
                Log.wtf(Companion.TAG, "NDEF_READ_BINARY - OFFSET: $offset outside bounds")
                return Constant.HceResponse.A_ERROR
            }
            val returnedLength =
                if (selectedFile.size < offset + expectedLength) selectedFile.size - offset else expectedLength;
            val slicedData = selectedFile.sliceArray(offset until offset + returnedLength)
            val response = slicedData.plus(Constant.HceResponse.A_OKAY)

            Log.i(
                Companion.TAG,
                "NDEF_READ_BINARY triggered. Our Response: " + Util.bytesToHex(response)
            )
            return response
        }

        //
        // We're doing something outside our scope
        //
        Log.wtf(Companion.TAG, "processCommandApdu() | unknown command")
        return Constant.HceResponse.A_ERROR
    }

    override fun onDeactivated(reason: Int) {
        Log.i(Companion.TAG, "onDeactivated(), Reason: $reason")
        mSelectedFile = null;
    }
}