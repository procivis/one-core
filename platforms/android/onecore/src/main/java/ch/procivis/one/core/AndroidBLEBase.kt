package ch.procivis.one.core

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothStatusCodes
import android.content.Context
import android.content.pm.PackageManager
import android.util.Log
import java.util.UUID
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

abstract class AndroidBLEBase(val context: Context, logTag: String) {
    val MAX_MTU = 512
    val CLIENT_CONFIG_DESCRIPTOR = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    val TAG = logTag

    private var bluetoothManager: BluetoothManager? = null
    protected fun getBluetoothManager(): BluetoothManager {
        var manager = bluetoothManager
        if (manager == null) {
            manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
            bluetoothManager = manager
        }
        return manager
    }

    protected fun getBluetoothAdapter(): BluetoothAdapter {
        return getBluetoothManager().adapter
    }

    protected fun getAdapterEnabled(): Boolean {
        return exceptionWrapper {
            if (!context.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE)) {
                throw BleException.NotSupported()
            }

            val adapter = getBluetoothAdapter()
            return@exceptionWrapper when (adapter.state) {
                BluetoothAdapter.STATE_ON -> true
                else -> false
            }
        }
    }

    protected data class CharacteristicAddress constructor(
        val service: UUID,
        val characteristic: UUID
    ) {}

    protected data class DeviceCharacteristicAddress constructor(
        val deviceAddress: String,
        val service: UUID,
        val characteristic: UUID
    ) {}

    protected inline fun <R> exceptionWrapper(function: () -> R): R {
        try {
            return function()
        } catch (error: BleException) {
            Log.w(TAG, "BleException: $error")
            throw error
        } catch (error: IllegalArgumentException) {
            Log.w(TAG, "IllegalArgumentException: $error")
            throw BleException.InvalidUuid(error.toString())
        } catch (error: SecurityException) {
            Log.w(TAG, "SecurityException: $error")
            throw BleException.NotAuthorized()
        } catch (error: Throwable) {
            Log.w(TAG, "Throwable: $error")
            throw BleException.Unknown(error.toString())
        }
    }

    protected fun statusCodeException(
        statusCode: Int,
        service: UUID,
        characteristic: UUID
    ): BleException {
        return when (statusCode) {
            BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ALLOWED, BluetoothStatusCodes.ERROR_MISSING_BLUETOOTH_CONNECT_PERMISSION -> BleException.NotAuthorized()
            BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ENABLED -> BleException.AdapterNotEnabled()
            BluetoothStatusCodes.ERROR_GATT_WRITE_NOT_ALLOWED -> BleException.InvalidCharacteristicOperation(
                service.toString(),
                characteristic.toString(),
                "write"
            )

            else -> BleException.Unknown("BLE error status: $statusCode")
        }
    }

    /**
     * shared synchronization object
     * @sample
     *   synchronized(lock) {
     *     // prevent data-races here
     *   }
     */
    protected val lock = Any()

    protected class Promise<in T>(private val continuation: Continuation<T>) {
        @Volatile
        private var finished = false

        @Synchronized
        fun succeed(result: T) {
            if (!finished) {
                finished = true
                continuation.resume(result)
            }
        }

        @Synchronized
        fun fail(error: Throwable) {
            if (!finished) {
                finished = true
                continuation.resumeWithException(error)
            }
        }
    }

    protected suspend inline fun <T> asyncCallback(crossinline block: (Promise<T>) -> Unit): T {
        return exceptionWrapper {
            return@exceptionWrapper suspendCoroutine { continuation ->
                val promise = Promise(continuation)
                try {
                    block(promise)
                } catch (error: Throwable) {
                    promise.fail(error)
                }
            }
        }
    }
}
