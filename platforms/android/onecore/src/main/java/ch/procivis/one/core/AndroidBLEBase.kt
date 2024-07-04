package ch.procivis.one.core

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothStatusCodes
import android.content.Context
import android.content.pm.PackageManager
import android.util.Log
import java.util.UUID

open class AndroidBLEBase(val context: Context, val TAG: String) {
    val MAX_MTU = 512
    val CLIENT_CONFIG_DESCRIPTOR = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

    private var bluetoothManager: BluetoothManager? = null
    fun getBluetoothManager(): BluetoothManager {
        var manager = bluetoothManager
        if (manager == null) {
            manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
            bluetoothManager = manager
        }
        return manager
    }

    fun getBluetoothAdapter(): BluetoothAdapter {
        return getBluetoothManager().adapter
    }

    fun getAdapterEnabled(): Boolean {
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

    data class CharacteristicAddress constructor(
        val service: UUID,
        val characteristic: UUID
    ) {}

    data class DeviceCharacteristicAddress constructor(
        val deviceAddress: String,
        val service: UUID,
        val characteristic: UUID
    ) {}

    inline fun <R> exceptionWrapper(function: () -> R): R {
        try {
            return function()
        } catch (error: BleErrorWrapper) {
            Log.w(TAG, "BleErrorWrapper: $error")
            throw error
        } catch (error: BleException) {
            Log.w(TAG, "BleException: $error")
            throw BleErrorWrapper.Ble(error)
        } catch (error: IllegalArgumentException) {
            Log.w(TAG, "IllegalArgumentException: $error")
            throw BleErrorWrapper.Ble(BleException.InvalidUuid(error.toString()))
        } catch (error: SecurityException) {
            Log.w(TAG, "SecurityException: $error")
            throw BleErrorWrapper.Ble(BleException.NotAuthorized())
        } catch (error: Throwable) {
            Log.w(TAG, "Throwable: $error")
            throw BleErrorWrapper.Ble(BleException.Unknown(error.toString()))
        }
    }

    fun statusCodeException(
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
}