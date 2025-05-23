package ch.procivis.one.core

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import java.lang.ref.WeakReference
import java.util.UUID
import kotlin.math.min

class AndroidBLECentral(context: Context) : BleCentral, AndroidBLEBase(context, "BLE_CENTRAL") {
    override suspend fun isAdapterEnabled(): Boolean {
        return getAdapterEnabled()
    }

    private class DeviceScanning {
        var callback: ScanCallback? = null // ongoing scan

        // next batch for getDiscoveredDevices
        val devices: MutableList<PeripheralDiscoveryDataBindingDto> = mutableListOf()
        var promise: Promise<List<PeripheralDiscoveryDataBindingDto>>? = null

        // cache of scanned devices
        val scannedDevices: MutableMap<String, BluetoothDevice> = HashMap()
    }

    private val mScanning = DeviceScanning()

    @SuppressLint("MissingPermission")
    override suspend fun startScan(filterServices: List<String>?) {
        return exceptionWrapper {
            val adapter = getBluetoothAdapter()
            val scanner = adapter.bluetoothLeScanner

            val filters = filterServices?.map { UUID.fromString(it) } ?: listOf()

            val scanCallback = getScanCallback(filters)

            val scanSettings =
                ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build()

            synchronized(lock) {
                if (mScanning.callback != null) {
                    throw BleException.ScanAlreadyStarted()
                }

                mScanning.scannedDevices.clear()
                mScanning.callback = scanCallback
                scanner.startScan(
                    null, // service UUID filter not working on some devices
                    scanSettings, scanCallback
                )
            }
        }
    }

    override suspend fun getDiscoveredDevices(): List<PeripheralDiscoveryDataBindingDto> {
        return asyncCallback { promise ->
            synchronized(lock) {
                if (mScanning.callback == null) {
                    throw BleException.BroadcastNotStarted()
                }

                if (mScanning.promise != null) {
                    throw BleException.AnotherOperationInProgress()
                }

                if (mScanning.devices.isEmpty()) {
                    mScanning.promise = promise
                } else {
                    promise.succeed(mScanning.devices.toList())
                    mScanning.devices.clear()
                }
            }
        }
    }

    @SuppressLint("MissingPermission")
    override suspend fun stopScan() {
        return exceptionWrapper {
            val adapter = getBluetoothAdapter()
            val scanner = adapter.bluetoothLeScanner

            synchronized(lock) {
                if (mScanning.callback == null) {
                    throw BleException.ScanNotStarted()
                }

                scanner.stopScan(mScanning.callback)
                mScanning.callback = null
                mScanning.devices.clear()

                mScanning.promise?.fail(BleException.Unknown("Scanning stopped"))
                mScanning.promise = null
            }
        }
    }

    override suspend fun isScanning(): Boolean {
        return mScanning.callback != null
    }

    override suspend fun subscribeToCharacteristicNotifications(
        peripheral: String, service: String, characteristic: String
    ) {
        return setCharacteristicSubscription(peripheral, service, characteristic, true)
    }

    override suspend fun unsubscribeFromCharacteristicNotifications(
        peripheral: String, service: String, characteristic: String
    ) {
        return setCharacteristicSubscription(peripheral, service, characteristic, false)
    }

    private class SubscriptionData {
        val messages: MutableList<ByteArray> = mutableListOf()
        var promise: Promise<List<ByteArray>>? = null
    }

    private val mSubscriptions: MutableMap<DeviceCharacteristicAddress, SubscriptionData> =
        HashMap()

    private data class SubscribingEntry(val promise: Promise<Unit>, val enable: Boolean) {}

    private val mSubscribingInProgress: MutableMap<DeviceCharacteristicAddress, SubscribingEntry> =
        HashMap()

    @SuppressLint("MissingPermission")
    private suspend fun setCharacteristicSubscription(
        peripheral: String, service: String, characteristic: String, enable: Boolean
    ) {
        return asyncCallback { promise ->
            synchronized(lock) {
                val (ch, gatt, address) = getCharacteristic(peripheral, service, characteristic)

                if (mSubscribingInProgress.containsKey(address)) {
                    throw BleException.AnotherOperationInProgress()
                }

                if (enable) {
                    if (mSubscriptions.containsKey(address)) {
                        throw BleException.BroadcastAlreadyStarted()
                    }
                } else if (!mSubscriptions.containsKey(address)) {
                    throw BleException.BroadcastNotStarted()
                }

                if (!gatt.setCharacteristicNotification(ch, enable)) {
                    throw BleException.Unknown("Characteristic notifications subscription failed")
                }

                setCharacteristicSubscriptionCCCD(ch, address, gatt, enable, promise)
            }
        }
    }

    private fun setCharacteristicSubscriptionCCCD(
        characteristic: BluetoothGattCharacteristic,
        address: DeviceCharacteristicAddress,
        gatt: BluetoothGatt,
        enable: Boolean,
        promise: Promise<Unit>
    ) {
        val descriptor = characteristic.getDescriptor(CLIENT_CONFIG_DESCRIPTOR)
        if (descriptor != null) {
            setSubscriptionCCCD(descriptor, address, gatt, enable, promise)
        } else {
            if (enable) {
                mSubscriptions[address] = SubscriptionData()
            } else {
                val ongoing = mSubscriptions.remove(address)
                ongoing?.promise?.fail(BleException.BroadcastNotStarted())
            }
            promise.succeed(Unit)
        }
    }

    @SuppressLint("MissingPermission")
    private fun setSubscriptionCCCD(
        descriptor: BluetoothGattDescriptor,
        address: DeviceCharacteristicAddress,
        gatt: BluetoothGatt,
        enable: Boolean,
        promise: Promise<Unit>
    ) {
        val value = if (enable) {
            BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
        } else {
            BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val statusCode = gatt.writeDescriptor(descriptor, value)
            if (statusCode != BluetoothStatusCodes.SUCCESS) {
                throw statusCodeException(
                    statusCode, address.service, address.characteristic
                )
            }
        } else {
            if (!descriptor.setValue(value) || !gatt.writeDescriptor(descriptor)) {
                throw BleException.Unknown("Failed to write Characteristic descriptor")
            }
        }

        mSubscribingInProgress[address] = SubscribingEntry(promise, enable)
    }

    override suspend fun getNotifications(
        peripheral: String, service: String, characteristic: String
    ): List<ByteArray> {
        return asyncCallback { promise ->
            val subscription = DeviceCharacteristicAddress(
                peripheral, UUID.fromString(service), UUID.fromString(characteristic)
            )

            synchronized(lock) {
                val data = mSubscriptions[subscription] ?: throw BleException.BroadcastNotStarted()

                if (data.promise != null) {
                    data.promise!!.fail(BleException.Unknown("cancelled due to new request"))
                    data.promise = null
                }

                if (data.messages.isEmpty()) {
                    data.promise = promise
                } else {
                    promise.succeed(data.messages.toList())
                    data.messages.clear()
                }
            }
        }
    }

    // currently connected peripherals
    private val mConnections: MutableMap<String, BluetoothGatt> = HashMap()

    @SuppressLint("MissingPermission")
    override suspend fun connect(peripheral: String): UShort {
        return asyncCallback { promise ->
            synchronized(lock) {
                val device = mScanning.scannedDevices[peripheral]
                if (device == null) {
                    Log.w(TAG, "Device not found: $peripheral");
                    throw BleException.DeviceAddressNotFound(peripheral)
                }

                val callback = getConnectCallback(peripheral, promise)

                val gatt = device.connectGatt(this.context, false, callback)
                gatt.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_HIGH)
                mConnections[peripheral] = gatt
            }
        }
    }

    private val mReadInProgress: MutableMap<DeviceCharacteristicAddress, Promise<ByteArray>> =
        HashMap()

    @SuppressLint("MissingPermission")
    override suspend fun readData(
        peripheral: String, service: String, characteristic: String
    ): ByteArray {
        return asyncCallback { promise ->
            synchronized(lock) {
                val (ch, gatt, address) = getCharacteristic(
                    peripheral,
                    service,
                    characteristic
                )

                if (mReadInProgress.containsKey(address)) {
                    throw BleException.AnotherOperationInProgress()
                }

                if (!gatt.readCharacteristic(ch)) {
                    Log.w(TAG, "Read Characteristic failed: $characteristic");
                    throw BleException.Unknown("Read Characteristic failed: $characteristic")
                }

                mReadInProgress[address] = promise
            }
        }

    }

    private val mWriteInProgress: MutableMap<DeviceCharacteristicAddress, Promise<Unit>> =
        HashMap()

    @SuppressLint("MissingPermission")
    override suspend fun writeData(
        peripheral: String,
        service: String,
        characteristic: String,
        data: ByteArray,
        writeType: CharacteristicWriteTypeBindingEnum
    ) {
        return asyncCallback { promise ->
            synchronized(lock) {
                val (ch, gatt, address) = getCharacteristic(
                    peripheral, service, characteristic
                )

                if (mWriteInProgress.containsKey(address)) {
                    throw BleException.AnotherOperationInProgress()
                }

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    writeDataNewApi(ch, gatt, address, data, writeType)
                } else {
                    writeDataOldApi(ch, gatt, data, writeType)
                }

                mWriteInProgress[address] = promise
            }
        }
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    @SuppressLint("MissingPermission")
    private fun writeDataNewApi(
        characteristic: BluetoothGattCharacteristic,
        gatt: BluetoothGatt,
        address: DeviceCharacteristicAddress,
        data: ByteArray,
        writeType: CharacteristicWriteTypeBindingEnum
    ) {
        val statusCode =
            gatt.writeCharacteristic(characteristic, data, getWriteType(writeType))
        if (statusCode != BluetoothStatusCodes.SUCCESS) {
            throw statusCodeException(
                statusCode,
                address.service,
                address.characteristic
            )
        }
    }

    @SuppressLint("MissingPermission")
    private fun writeDataOldApi(
        characteristic: BluetoothGattCharacteristic,
        gatt: BluetoothGatt,
        data: ByteArray,
        writeType: CharacteristicWriteTypeBindingEnum
    ) {
        characteristic.writeType = getWriteType(writeType)
        if (!characteristic.setValue(data) || !gatt.writeCharacteristic(
                characteristic
            )
        ) {
            throw BleException.Unknown("Write Characteristic failed")
        }
    }

    @SuppressLint("MissingPermission")
    override suspend fun disconnect(peripheral: String) {
        return exceptionWrapper {
            synchronized(lock) {
                val device = mConnections.remove(peripheral)
                if (device == null) {
                    Log.w(TAG, "Device not found: $peripheral");
                    throw BleException.DeviceAddressNotFound(peripheral)
                }

                device.disconnect()
                device.close()

                onDeviceDisconnected(peripheral)
            }
        }
    }

    @SuppressLint("MissingPermission")
    private fun getScanCallback(filters: List<UUID>): ScanCallback {
        return object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                Log.d(TAG, "onScanResult: $result")

                val advertisedServices =
                    result.scanRecord?.serviceUuids?.map { it.uuid } ?: listOf()

                // skip non-matching
                if (filters.isNotEmpty() && filters.find { advertisedServices.contains(it) } == null) {
                    return
                }

                val device = result.device
                val serviceData = result.scanRecord?.serviceData
                val advertisedData = if (serviceData != null) {
                    val data: MutableMap<String, ByteArray> = mutableMapOf()
                    serviceData.forEach { data[it.key.toString()] = it.value }
                    data
                } else null

                val data = PeripheralDiscoveryDataBindingDto(
                    device.address,
                    device.name,
                    advertisedServices.map { it.toString() },
                    advertisedData
                )

                synchronized(lock) {
                    if (mScanning.callback == null) {
                        return // scanning already stopped
                    }

                    mScanning.scannedDevices[device.address] = device

                    // replace outdated results
                    mScanning.devices.removeAll { it.deviceAddress == data.deviceAddress }
                    mScanning.devices.add(data)
                    val promise = mScanning.promise
                    if (promise != null) {
                        promise.succeed(mScanning.devices.toList())
                        mScanning.promise = null
                        mScanning.devices.clear()
                    }
                }
            }

            override fun onScanFailed(errorCode: Int) {
                Log.w(TAG, "Scan failed: $errorCode")
                synchronized(lock) {
                    mScanning.callback = null
                    mScanning.promise?.fail(BleException.Unknown("Scan failed: $errorCode"))
                    mScanning.promise = null
                }
            }
        }
    }

    private fun getConnectCallback(
        peripheral: String,
        connectPromise: Promise<UShort>
    ): BluetoothGattCallback {
        return ConnectCallback(WeakReference(this), peripheral, connectPromise)
    }

    private fun onDeviceDisconnected(deviceAddress: String) {
        mConnections.remove(deviceAddress)

        mSubscribingInProgress.filter { it.key.deviceAddress == deviceAddress }.forEach {
            it.value.promise.fail(BleException.DeviceNotConnected(deviceAddress))
            mSubscribingInProgress.remove(it.key)
        }

        mSubscriptions.filter { it.key.deviceAddress == deviceAddress }.forEach {
            it.value.promise?.fail(BleException.DeviceNotConnected(deviceAddress))
            mSubscriptions.remove(it.key)
        }

        mReadInProgress.filter { it.key.deviceAddress == deviceAddress }.forEach {
            it.value.fail(BleException.DeviceNotConnected(deviceAddress))
            mReadInProgress.remove(it.key)
        }

        mWriteInProgress.filter { it.key.deviceAddress == deviceAddress }.forEach {
            it.value.fail(BleException.DeviceNotConnected(deviceAddress))
            mWriteInProgress.remove(it.key)
        }
    }

    private fun getCharacteristic(
        deviceAddress: String, serviceUuid: String, characteristicUuid: String
    ): Triple<BluetoothGattCharacteristic, BluetoothGatt, DeviceCharacteristicAddress> {
        val gatt =
            mConnections[deviceAddress] ?: throw BleException.DeviceAddressNotFound(deviceAddress)

        val address = DeviceCharacteristicAddress(
            deviceAddress, UUID.fromString(serviceUuid), UUID.fromString(characteristicUuid)
        )

        val service =
            gatt.getService(address.service) ?: throw BleException.ServiceNotFound(serviceUuid)
        val characteristic = service.getCharacteristic(address.characteristic)
            ?: throw BleException.CharacteristicNotFound(characteristicUuid)
        return Triple(characteristic, gatt, address)
    }

    private fun getWriteType(writeType: CharacteristicWriteTypeBindingEnum): Int {
        return when (writeType) {
            CharacteristicWriteTypeBindingEnum.WITH_RESPONSE -> BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
            CharacteristicWriteTypeBindingEnum.WITHOUT_RESPONSE -> BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
        }
    }

    private class ConnectCallback(
        private val parent: WeakReference<AndroidBLECentral>,
        private val peripheral: String,
        private val connectPromise: Promise<UShort>,
    ) : BluetoothGattCallback() {
        private var mMTU: UShort? = null
        private var connected = false
        private var servicesDiscovered = false
        private val TAG: String = parent.get()?.TAG.toString()

        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(
            gatt: BluetoothGatt, status: Int, newState: Int
        ) {
            super.onConnectionStateChange(gatt, status, newState)
            Log.d(TAG, "onConnectionStateChange: $newState")

            if (status != BluetoothGatt.GATT_SUCCESS) {
                gatt.close()
                connectPromise.fail(BleException.Unknown("Connection failure, status: $status, state: $newState"))
                return
            }

            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    Log.d(TAG, "Device connected")
                    connected = true
                    if (mMTU != null) {
                        connectPromise.succeed(mMTU!!)
                    } else if (!gatt.discoverServices()) {
                        connectPromise.fail(BleException.Unknown("Couldn't discover services"))
                    }
                }

                BluetoothProfile.STATE_DISCONNECTED -> {
                    Log.d(TAG, "Device disconnected")
                    connectPromise.fail(BleException.DeviceNotConnected(peripheral))
                    synchronized(lock) {
                        parent.get()?.onDeviceDisconnected(peripheral)
                    }
                    gatt.close()
                }
            }
        }

        @SuppressLint("MissingPermission")
        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            super.onServicesDiscovered(gatt, status)
            Log.d(TAG, "onServicesDiscovered: $status")

            if (status != BluetoothGatt.GATT_SUCCESS) {
                gatt.close()
                connectPromise.fail(BleException.Unknown("Service discovery failure, status: $status"))
                return
            }

            servicesDiscovered = true

            if (mMTU != null) {
                connectPromise.succeed(mMTU!!)
            } else if (!gatt.requestMtu(MAX_MTU)) {
                connectPromise.fail(BleException.Unknown("Couldn't request MTU"))
            }
        }

        @SuppressLint("MissingPermission")
        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            super.onMtuChanged(gatt, mtu, status)
            Log.d(TAG, "onMtuChanged: $mtu")

            if (status != BluetoothGatt.GATT_SUCCESS) {
                gatt.close()
                connectPromise.fail(BleException.Unknown("MTU request failure, status: $status"))
                return
            }

            val m = min(mtu, MAX_MTU).toUShort()
            if (connected && servicesDiscovered) {
                connectPromise.succeed(m)
            } else {
                mMTU = m
            }
        }

        @Deprecated("Deprecated in Java")
        override fun onCharacteristicChanged(
            gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic
        ) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                super.onCharacteristicChanged(gatt, characteristic)
                onCharacteristicChanged(
                    gatt, characteristic, characteristic.value
                )
            }
        }

        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray
        ) {
            Log.d(TAG, "onCharacteristicChanged: " + characteristic.uuid)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                super.onCharacteristicChanged(gatt, characteristic, value)
            }

            val address = DeviceCharacteristicAddress(
                gatt.device.address, characteristic.service.uuid, characteristic.uuid
            )
            synchronized(lock) {
                val data = parent.get()?.mSubscriptions?.get(address)
                if (data != null) {
                    data.messages.add(value)
                    val p = data.promise
                    if (p != null) {
                        p.succeed(data.messages.toList())
                        data.promise = null
                        data.messages.clear()
                    }
                }
            }
        }

        @Deprecated("Deprecated in Java")
        override fun onCharacteristicRead(
            gatt: BluetoothGatt?,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                super.onCharacteristicRead(gatt, characteristic, status)
                onCharacteristicRead(
                    gatt!!, characteristic, characteristic.value, status
                )
            }
        }

        override fun onCharacteristicRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            data: ByteArray,
            status: Int
        ) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                super.onCharacteristicRead(gatt, characteristic, data, status);
            }

            Log.d(TAG, "onCharacteristicRead: ${characteristic.uuid}, status: $status")
            val address = DeviceCharacteristicAddress(
                gatt.device.address, characteristic.service.uuid, characteristic.uuid
            )

            synchronized(lock) {
                val readInProgress = parent.get()?.mReadInProgress?.remove(address)
                if (readInProgress != null) {
                    when (status) {
                        BluetoothGatt.GATT_SUCCESS -> {
                            readInProgress.succeed(data)
                        }

                        else -> {
                            readInProgress.fail(BleException.Unknown("Characteristic Read failure, status: $status"))
                        }
                    }
                }
            }
        }

        override fun onCharacteristicWrite(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
            super.onCharacteristicWrite(gatt, characteristic, status);
            Log.d(TAG, "onCharacteristicWrite: ${characteristic.uuid}, status: $status")

            val address = DeviceCharacteristicAddress(
                gatt.device.address, characteristic.service.uuid, characteristic.uuid
            )

            synchronized(lock) {
                val writeInProgress = parent.get()?.mWriteInProgress?.remove(address)
                if (writeInProgress != null) {
                    when (status) {
                        BluetoothGatt.GATT_SUCCESS -> {
                            writeInProgress.succeed(Unit)
                        }

                        else -> {
                            writeInProgress.fail(BleException.Unknown("Characteristic write failure, status: $status"))
                        }
                    }
                }
            }
        }

        override fun onDescriptorWrite(
            gatt: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int
        ) {
            super.onDescriptorWrite(gatt, descriptor, status);
            Log.d(TAG, "onDescriptorWrite: ${descriptor.uuid}, status: $status")

            val subscription = DeviceCharacteristicAddress(
                gatt.device.address,
                descriptor.characteristic.service.uuid,
                descriptor.characteristic.uuid
            )

            synchronized(lock) {
                parent.get()?.mSubscribingInProgress?.remove(subscription)
                    ?.let { subscribingInProgress ->
                        when (status) {
                            BluetoothGatt.GATT_SUCCESS -> {
                                parent.get()?.mSubscriptions?.let { mSubscriptions ->
                                    if (subscribingInProgress.enable) {
                                        mSubscriptions[subscription] = SubscriptionData()
                                    } else {
                                        mSubscriptions.remove(subscription)?.let { ongoing ->
                                            ongoing.promise?.fail(BleException.BroadcastNotStarted())
                                        }
                                    }
                                }

                                subscribingInProgress.promise.succeed(Unit)
                            }

                            else -> {
                                subscribingInProgress.promise.fail(
                                    BleException.Unknown("Descriptor write failure, status: $status")
                                )
                            }
                        }
                    }
            }
        }
    }
}
