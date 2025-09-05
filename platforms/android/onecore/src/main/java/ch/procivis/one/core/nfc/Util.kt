package ch.procivis.one.core.nfc

import android.nfc.TagLostException
import android.util.Log
import ch.procivis.one.core.NfcException
import java.io.IOException

object Util {
    private val HEX_ARRAY: CharArray = "0123456789ABCDEF".toCharArray()
    fun bytesToHex(bytes: ByteArray): String {
        val hexChars = CharArray(bytes.size * 2)

        for (j in bytes.indices) {
            val v = bytes[j].toInt() and 0xFF
            hexChars[j * 2] = HEX_ARRAY[v ushr 4]
            hexChars[j * 2 + 1] = HEX_ARRAY[v and 0x0F]
        }

        return String(hexChars)
    }

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

    class CommandApdu(
        val cla: Int,
        val ins: Int,
        val p: Pair<Int, Int>,
        val payload: ByteArray,
        val le: Int
    ) {
        companion object {
            fun decode(encoded: ByteArray): CommandApdu {
                require(encoded.size >= 4)
                val cla = encoded.getUInt8(0)
                val ins = encoded.getUInt8(1)
                val p1 = encoded.getUInt8(2)
                val p2 = encoded.getUInt8(3)
                var payload = byteArrayOf()
                var le = 0
                if (encoded.size == 5) {
                    val encLe = encoded.getUInt8(4).toInt()
                    le = if (encLe == 0) 0x100 else encLe
                } else if (encoded.size > 5) {
                    var lc = encoded.getUInt8(4).toInt()
                    var lcEndsAt = 5
                    if (lc == 0) {
                        lc = encoded.getUInt16(5).toInt()
                        lcEndsAt = 7
                    }
                    if (lc > 0 && lcEndsAt + lc <= encoded.size) {
                        val payloadArray = ByteArray(lc)
                        encoded.copyInto(payloadArray, 0, lcEndsAt, lcEndsAt + lc)
                        payload = payloadArray
                    } else {
                        lc = 0
                        lcEndsAt = 4
                    }
                    val leLen = encoded.size - lcEndsAt - lc
                    le = when (leLen) {
                        0 -> 0
                        1 -> {
                            val encLe = encoded.getUInt8(encoded.size - 1).toInt()
                            if (encLe == 0) 0x100 else encLe
                        }
                        2, 3 -> {
                            val encLe = encoded.getUInt16(encoded.size - 2).toInt()
                            if (encLe == 0) 0x10000 else encLe
                        }
                        else -> throw IllegalStateException("Invalid LE len $leLen")
                    }
                }
                return CommandApdu(
                    cla = cla.toInt(),
                    ins = ins.toInt(),
                    p = Pair(p1.toInt(), p2.toInt()),
                    payload = payload,
                    le = le
                )
            }
        }
    }
}

fun ByteArray.getUInt8(offset: Int): UByte {
    return (this[offset].toInt() and 0xFF).toUByte()
}

fun ByteArray.getUInt16(offset: Int): UShort {
    val higher = this[offset].toInt() and 0xFF
    val lower = this[offset + 1].toInt() and 0xFF
    return ((higher shl 8) or lower).toUShort()
}