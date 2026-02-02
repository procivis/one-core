package ch.procivis.one.core.nfc

import android.app.Activity
import android.content.Context
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.util.Log
import ch.procivis.one.core.NfcException
import ch.procivis.one.core.NfcScanner
import ch.procivis.one.core.nfc.Util.exceptionWrapper
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine
import kotlin.time.Duration.Companion.seconds

/**
 * Provided implementation of NFC Scanner
 */
class Scanner(private val context: Context, private val activityAccessor: ActivityAccessor) : NfcScanner,
    NfcAdapter.ReaderCallback {
    internal companion object {
        private const val TAG = "NFCScanner"
    }

    private val mNfcAdapter = NfcAdapter.getDefaultAdapter(context)

    override suspend fun isEnabled(): Boolean {
        return mNfcAdapter != null && mNfcAdapter.isEnabled
    }

    override suspend fun isSupported(): Boolean {
        return mNfcAdapter != null
    }

    // connected tag session
    private var mTech: IsoDep? = null

    // activity within which the scanning is happening
    // continuation present if tag not yet discovered
    private var mScanInProgress: Pair<Activity, Continuation<Unit>?>? = null

    override suspend fun scan(message: String?) {
        return exceptionWrapper {
            if (!isSupported()) {
                throw NfcException.NotSupported()
            }
            if (!isEnabled()) {
                throw NfcException.NotEnabled()
            }
            val activity = activityAccessor.getCurrentActivity()
                ?: throw NfcException.Unknown("Activity not available")

            return@exceptionWrapper suspendCoroutine { continuation ->
                try {
                    synchronized(this) {
                        if (mScanInProgress != null) {
                            throw NfcException.AlreadyStarted()
                        }
                        mScanInProgress = Pair(activity, continuation)
                    }

                    Log.d(TAG, "enableReaderMode")
                    mNfcAdapter.enableReaderMode(
                        activity,
                        this,
                        NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK + NfcAdapter.FLAG_READER_NFC_A + NfcAdapter.FLAG_READER_NFC_B,
                        null
                    )
                } catch (e: Throwable) {
                    synchronized(this) {
                        mScanInProgress = null
                    }
                    continuation.resumeWithException(e)
                }
            }
        }
    }

    override fun onTagDiscovered(tag: Tag?) {
        var continuation: Continuation<Unit>? = null
        var activity: Activity? = null
        try {
            Log.d(TAG, "onTagDiscovered $tag")
            if (tag == null) {
                return
            }

            synchronized(this) {
                val a = mScanInProgress?.first ?: throw NfcException.Unknown("No scan running")
                activity = a
                continuation =
                    mScanInProgress?.second ?: throw NfcException.Unknown("A tag already connected")
                mScanInProgress = Pair(a, null)
            }
            connect(tag)
            continuation?.resume(Unit)
        } catch (e: Throwable) {
            Log.w(TAG, "Failed to process discovered tag: $e")
            if (activity != null) {
                mNfcAdapter.disableReaderMode(activity)
            }
            synchronized(this) {
                mScanInProgress = null
            }
            continuation?.resumeWithException(e)
        }
    }

    private fun connect(tag: Tag) {
        val tech = IsoDep.get(tag)
        if (tech == null) {
            throw NfcException.Unknown("Not an IsoDep tag")
        }

        synchronized(this) {
            mTech = tech
        }

        tech.connect()
        tech.timeout = 5.seconds.inWholeMilliseconds.toInt()
    }

    override suspend fun setMessage(message: String) {
        throw NfcException.NotSupported()
    }

    override suspend fun cancelScan(errorMessage: String?) {
        Log.d(TAG, "cancelScan, errorMessage: $errorMessage")
        return exceptionWrapper {
            synchronized(this) {
                try {
                    mTech?.close()
                    mTech = null
                } catch (e: Throwable) {
                    Log.wtf(TAG, "Closing tech failed: $e")
                }

                if (mScanInProgress != null) {
                    mNfcAdapter.disableReaderMode(mScanInProgress?.first)
                    mScanInProgress?.second?.resumeWithException(NfcException.Cancelled())
                    mScanInProgress = null
                }
            }
        }
    }

    override suspend fun transceive(commandApdu: ByteArray): ByteArray {
        Log.d(TAG, "transceive ${commandApdu.size}")
        return exceptionWrapper {
            val tech = synchronized(this) {
                return@synchronized mTech ?: throw NfcException.SessionClosed()
            }

            if (!tech.isConnected) {
                throw NfcException.SessionClosed()
            }

            val response = tech.transceive(commandApdu)
            Log.d(TAG, "response ${response.size}")
            return@exceptionWrapper response
        }
    }
}
