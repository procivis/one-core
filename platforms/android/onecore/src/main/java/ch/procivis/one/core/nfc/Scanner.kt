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


class Scanner(val context: Context, val activityAccessor: ActivityAccessor) : NfcScanner {
    companion object {
        private const val TAG = "NFCScanner"
    }

    private val mNfcAdapter = NfcAdapter.getDefaultAdapter(context)

    override suspend fun isEnabled(): Boolean {
        return mNfcAdapter != null && mNfcAdapter.isEnabled
    }

    override suspend fun isSupported(): Boolean {
        return mNfcAdapter != null
    }

    private var mTech: IsoDep? = null // connected tag session
    private var mScanInProgress: Activity? = null // activity within which the scanning is happening

    override suspend fun scan(message: String?) {
        return exceptionWrapper {
            if (!isSupported()) {
                throw NfcException.NotSupported()
            }
            if (!isEnabled()) {
                throw NfcException.NotEnabled()
            }
            val activity = activityAccessor.getCurrentActivity() ?: throw NfcException.NotEnabled()

            synchronized(this) {
                if (mScanInProgress != null) {
                    throw NfcException.AlreadyStarted()
                }
                mScanInProgress = activity
            }

            return@exceptionWrapper suspendCoroutine { continuation ->
                try {
                    scanInternal(activity, continuation)
                } catch (e: Throwable) {
                    synchronized(this) {
                        mScanInProgress = null
                    }
                    continuation.resumeWithException(e)
                }
            }
        }
    }

    private fun scanInternal(activity: Activity, continuation: Continuation<Unit>) {
        mNfcAdapter.enableReaderMode(
            activity,
            { tag ->
                {
                    try {
                        onTagDiscovered(tag)
                        continuation.resume(Unit)
                    } catch (e: Throwable) {
                        synchronized(this) {
                            mScanInProgress = null
                        }
                        continuation.resumeWithException(e)
                        mNfcAdapter.disableReaderMode(activity)
                    }
                }
            },
            NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK + NfcAdapter.FLAG_READER_NFC_A + NfcAdapter.FLAG_READER_NFC_B,
            null
        )
    }

    private fun onTagDiscovered(tag: Tag) {
        Log.d(TAG, "Tag discovered: $tag")
        val tech = IsoDep.get(tag)

        if (tech == null) {
            throw NfcException.Unknown("Not an IsoDep tag")
        }

        tech.connect()

        synchronized(this) {
            mTech = tech
        }
    }

    override suspend fun setMessage(message: String) {
        throw NfcException.NotSupported()
    }

    override suspend fun cancelScan() {
        return exceptionWrapper {
            synchronized(this) {
                if (mScanInProgress != null) {
                    mNfcAdapter.disableReaderMode(mScanInProgress)
                    mScanInProgress = null
                }

                try {
                    mTech?.close()
                    mTech = null
                } catch (e: Throwable) {
                    Log.wtf(TAG, "Closing tech failed: $e")
                }
            }
        }
    }

    override suspend fun transceive(commandApdu: ByteArray): ByteArray {
        return exceptionWrapper {
            val tech = synchronized(this) {
                return@synchronized mTech ?: throw NfcException.SessionClosed()
            }

            if (!tech.isConnected) {
                throw NfcException.SessionClosed()
            }

            return@exceptionWrapper tech.transceive(commandApdu)
        }
    }
}