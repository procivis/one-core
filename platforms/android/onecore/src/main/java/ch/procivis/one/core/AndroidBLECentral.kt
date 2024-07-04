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
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Build
import android.os.ParcelUuid
import android.util.Log
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine
import kotlin.math.min

class AndroidBLECentral(context: Context) : BleCentral, AndroidBLEBase(context, "BLE_CENTRAL") {
    override suspend fun isAdapterEnabled(): Boolean {
        return getAdapterEnabled()
    }

    // cache of scanned devices
    private val mScannedDevices: MutableMap<String, BluetoothDevice> = ConcurrentHashMap()

    private class DeviceScanning {
        val devices: MutableList<PeripheralDiscoveryDataBindingDto> = mutableListOf()
        var continuation: Continuation<List<PeripheralDiscoveryDataBindingDto>>? = null
        var callback: ScanCallback? = null
    }

    private val mScanning = DeviceScanning()

    @SuppressLint("MissingPermission")
    override suspend fun startScan(filterServices: List<String>?) {
        return exceptionWrapper {
            val adapter = getBluetoothAdapter()
            val scanner = adapter.bluetoothLeScanner

            val filters = filterServices?.map { it ->
                ScanFilter.Builder().setServiceUuid(ParcelUuid(UUID.fromString(it))).build()
            }

            val scanCallback = object : ScanCallback() {
                override fun onScanResult(callbackType: Int, result: ScanResult) {
                    Log.d(TAG, "onScanResult: $result")

                    val device = result.device
                    mScannedDevices[device.address] = device

                    val serviceData = result.scanRecord?.serviceData
                    val advertisedData = if (serviceData != null) {
                        val data: MutableMap<String, ByteArray> = mutableMapOf()
                        serviceData.forEach { data[it.key.toString()] = it.value }
                        data
                    } else null

                    val data = PeripheralDiscoveryDataBindingDto(device.address,
                        device.name,
                        result.scanRecord?.serviceUuids?.map { it.uuid.toString() } ?: listOf(),
                        advertisedData)

                    synchronized(mScanning) {
                        // replace outdated results
                        mScanning.devices.removeAll { it.deviceAddress == data.deviceAddress }
                        mScanning.devices.add(data)
                        val c = mScanning.continuation
                        if (c != null) {
                            c.resume(mScanning.devices.toList())
                            mScanning.continuation = null
                            mScanning.devices.clear()
                        }
                    }
                }

                override fun onScanFailed(errorCode: Int) {
                    Log.w(TAG, "Scan failed: $errorCode")
                    synchronized(mScanning) {
                        mScanning.callback = null
                        mScanning.continuation?.resumeWithException(BleException.Unknown("Scan failed: $errorCode"))
                        mScanning.continuation = null
                    }
                }
            }

            synchronized(mScanning) {
                if (mScanning.callback != null) {
                    throw BleException.ScanAlreadyStarted()
                }
                mScanning.callback = scanCallback
                scanner.startScan(
                    filters,
                    ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build(),
                    scanCallback
                )
            }
        }
    }

    override suspend fun getDiscoveredDevices(): List<PeripheralDiscoveryDataBindingDto> {
        return exceptionWrapper {
            return@exceptionWrapper suspendCoroutine<List<PeripheralDiscoveryDataBindingDto>> { continuation ->
                synchronized(mScanning) {
                    if (mScanning.callback == null) {
                        continuation.resumeWithException(BleException.BroadcastNotStarted())
                        return@suspendCoroutine
                    }

                    if (mScanning.continuation != null) {
                        continuation.resumeWithException(BleException.AnotherOperationInProgress())
                        return@suspendCoroutine
                    }

                    if (mScanning.devices.isEmpty()) {
                        mScanning.continuation = continuation
                    } else {
                        continuation.resume(mScanning.devices.toList())
                        mScanning.devices.clear()
                    }
                }
            }
        }
    }

    @SuppressLint("MissingPermission")
    override suspend fun stopScan() {
        return exceptionWrapper {
            val adapter = getBluetoothAdapter()
            val scanner = adapter.bluetoothLeScanner

            synchronized(mScanning) {
                if (mScanning.callback == null) {
                    throw BleException.ScanNotStarted()
                }

                scanner.stopScan(mScanning.callback)
                mScanning.callback = null
                mScanning.devices.clear()
                val c = mScanning.continuation
                if (c != null) {
                    c.resumeWithException(BleException.Unknown("Scanning stopped"))
                    mScanning.continuation = null
                }
            }
        }
    }

    override suspend fun isScanning(): Boolean {
        return mScanning.callback != null
    }

    override suspend fun subscribeToCharacteristicNotifications(
        peripheral: String,
        service: String,
        characteristic: String
    ) {
        return setCharacteristicSubscription(peripheral, service, characteristic, true)
    }

    override suspend fun unsubscribeFromCharacteristicNotifications(
        peripheral: String,
        service: String,
        characteristic: String
    ) {
        return setCharacteristicSubscription(peripheral, service, characteristic, false)
    }

    private class SubscriptionData {
        val messages: MutableList<ByteArray> = mutableListOf()
        var continuation: Continuation<List<ByteArray>>? = null
    }

    private val mSubscriptions: MutableMap<DeviceCharacteristicAddress, SubscriptionData> =
        HashMap()
    private val mSubscribingInProgress: MutableMap<DeviceCharacteristicAddress, Pair<Continuation<Unit>, Boolean>> =
        ConcurrentHashMap()

    @SuppressLint("MissingPermission")
    private suspend fun setCharacteristicSubscription(
        peripheral: String,
        service: String,
        characteristic: String,
        enable: Boolean
    ) {
        return exceptionWrapper {
            val (ch, gatt, address) = getCharacteristic(peripheral, service, characteristic)

            if (mSubscribingInProgress.containsKey(address)) {
                throw BleException.AnotherOperationInProgress()
            }

            return@exceptionWrapper suspendCoroutine { continuation ->
                synchronized(mSubscriptions) {
                    if (enable) {
                        if (mSubscriptions.containsKey(address)) {
                            continuation.resumeWithException(BleException.BroadcastAlreadyStarted())
                            return@suspendCoroutine
                        }
                    } else if (!mSubscriptions.containsKey(address)) {
                        continuation.resumeWithException(BleException.BroadcastNotStarted())
                        return@suspendCoroutine
                    }

                    if (!gatt.setCharacteristicNotification(ch, enable)) {
                        continuation.resumeWithException(BleException.Unknown("Characteristic notifications subscription failed"))
                        return@suspendCoroutine
                    }

                    val descriptor = ch.getDescriptor(CLIENT_CONFIG_DESCRIPTOR)
                    if (descriptor != null) {
                        val value = if (enable) {
                            BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                        } else {
                            BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE
                        }

                        mSubscribingInProgress[address] = Pair(continuation, enable)
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            val statusCode = gatt.writeDescriptor(descriptor, value)
                            if (statusCode != BluetoothStatusCodes.SUCCESS) {
                                mSubscribingInProgress.remove(address)
                                continuation.resumeWithException(
                                    statusCodeException(
                                        statusCode,
                                        address.service,
                                        address.characteristic
                                    )
                                )
                            }
                        } else {
                            if (!descriptor.setValue(value) || !gatt.writeDescriptor(descriptor)) {
                                mSubscribingInProgress.remove(address)
                                continuation.resumeWithException(BleException.Unknown("Failed to write Characteristic descriptor"))
                            }
                        }
                    } else {
                        if (enable) {
                            mSubscriptions[address] = SubscriptionData()
                        } else {
                            val ongoing = mSubscriptions.remove(address)
                            if (ongoing != null) {
                                ongoing.continuation?.resumeWithException(BleException.BroadcastNotStarted())
                            }
                        }
                    }
                }
            }
        }
    }

    override suspend fun getNotifications(
        peripheral: String,
        service: String,
        characteristic: String
    ): List<ByteArray> {
        return exceptionWrapper {
            val subscription = DeviceCharacteristicAddress(
                peripheral,
                UUID.fromString(service),
                UUID.fromString(characteristic)
            )

            return@exceptionWrapper suspendCoroutine<List<ByteArray>> { continuation ->
                synchronized(mSubscriptions) {
                    val data = mSubscriptions[subscription]
                    if (data == null) {
                        continuation.resumeWithException(BleException.BroadcastNotStarted())
                        return@suspendCoroutine
                    }
                    if (data.continuation != null) {
                        continuation.resumeWithException(BleException.Unknown("Already awaiting this notification"))
                        return@suspendCoroutine
                    }

                    if (data.messages.isEmpty()) {
                        data.continuation = continuation
                    } else {
                        continuation.resume(data.messages.toList())
                        data.messages.clear()
                    }
                }
            }
        }
    }

    // currently connected peripherals
    private val mConnections: MutableMap<String, BluetoothGatt> = ConcurrentHashMap()

    @SuppressLint("MissingPermission")
    override suspend fun connect(deviceAddress: String): UShort {
        return exceptionWrapper {
            val device = mScannedDevices[deviceAddress]
            if (device == null) {
                Log.w(TAG, "Device not found: $deviceAddress");
                throw BleException.DeviceAddressNotFound(deviceAddress)
            }

            return@exceptionWrapper suspendCoroutine<UShort> { continuation ->
                var mMTU: UShort? = null
                var connected = false
                var servicesDiscovered = false
                var connectedResponded = false

                val callback = object : BluetoothGattCallback() {
                    override fun onConnectionStateChange(
                        gatt: BluetoothGatt, status: Int, newState: Int
                    ) {
                        super.onConnectionStateChange(gatt, status, newState)
                        Log.d(TAG, "onConnectionStateChange: $newState")

                        if (status != BluetoothGatt.GATT_SUCCESS) {
                            gatt.close()
                            if (!connectedResponded) {
                                connectedResponded = true
                                continuation.resumeWithException(
                                    BleException.Unknown(
                                        "Connection failure, status: $status, state: $newState"
                                    )
                                )
                            }
                            return
                        }

                        when (newState) {
                            BluetoothProfile.STATE_CONNECTED -> {
                                Log.d(TAG, "Device connected")
                                if (mMTU != null && !connectedResponded) {
                                    connectedResponded = true
                                    continuation.resume(mMTU!!)
                                } else {
                                    connected = true
                                    if (!gatt.discoverServices()) {
                                        connectedResponded = true
                                        continuation.resumeWithException(
                                            BleException.Unknown("Couldn't discover services")
                                        )
                                    }
                                }
                            }

                            BluetoothProfile.STATE_DISCONNECTED -> {
                                Log.d(TAG, "Device disconnected")
                                if (!connectedResponded) {
                                    connectedResponded = true
                                    continuation.resumeWithException(
                                        BleException.DeviceNotConnected(deviceAddress)
                                    )
                                }

                                onDeviceDisconnected(deviceAddress)
                                gatt.close()
                            }
                        }
                    }

                    override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
                        super.onServicesDiscovered(gatt, status)
                        Log.d(TAG, "onServicesDiscovered: $status")

                        if (status != BluetoothGatt.GATT_SUCCESS) {
                            gatt.close()
                            if (!connectedResponded) {
                                connectedResponded = true
                                continuation.resumeWithException(
                                    BleException.Unknown(
                                        "Service discovery failure, status: $status"
                                    )
                                )
                            }
                            return
                        }

                        servicesDiscovered = true
                        if (connectedResponded) return

                        if (mMTU != null) {
                            connectedResponded = true
                            continuation.resume(mMTU!!)
                        } else {
                            if (!gatt.requestMtu(MAX_MTU)) {
                                connectedResponded = true
                                continuation.resumeWithException(
                                    BleException.Unknown("Couldn't request MTU")
                                )
                            }
                        }
                    }

                    override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
                        super.onMtuChanged(gatt, mtu, status)
                        Log.d(TAG, "onMtuChanged: $mtu")

                        if (status != BluetoothGatt.GATT_SUCCESS) {
                            gatt.close()
                            if (!connectedResponded) {
                                connectedResponded = true
                                continuation.resumeWithException(
                                    BleException.Unknown(
                                        "MTU request failure, status: $status"
                                    )
                                )
                            }
                            return
                        }

                        val m = min(mtu, MAX_MTU).toUShort()
                        if (connected && servicesDiscovered && !connectedResponded) {
                            connectedResponded = true
                            continuation.resume(m)
                        } else {
                            mMTU = m
                        }
                    }

                    @Deprecated("Deprecated in Java")
                    override fun onCharacteristicChanged(
                        gatt: BluetoothGatt,
                        characteristic: BluetoothGattCharacteristic
                    ) {
                        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                            super.onCharacteristicChanged(gatt, characteristic)
                            onCharacteristicChanged(
                                gatt,
                                characteristic,
                                characteristic.value
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
                            gatt.device.address,
                            characteristic.service.uuid,
                            characteristic.uuid
                        )
                        synchronized(mSubscriptions) {
                            val data = mSubscriptions[address]
                            if (data != null) {
                                data.messages.add(value)
                                val c = data.continuation
                                if (c != null) {
                                    c.resume(data.messages.toList())
                                    data.continuation = null
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
                                gatt!!,
                                characteristic,
                                characteristic.value,
                                status
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
                            gatt.device.address,
                            characteristic.service.uuid,
                            characteristic.uuid
                        )

                        synchronized(mReadInProgress) {
                            val readInProgress = mReadInProgress.remove(address)
                            if (readInProgress != null) {
                                when (status) {
                                    BluetoothGatt.GATT_SUCCESS -> {
                                        readInProgress.resume(data)
                                    }

                                    else -> {
                                        readInProgress.resumeWithException(BleException.Unknown("Characteristic Read failure, status: $status"))
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
                            gatt.device.address,
                            characteristic.service.uuid,
                            characteristic.uuid
                        )

                        synchronized(mWriteInProgress) {
                            val writeInProgress = mWriteInProgress.remove(address)
                            if (writeInProgress != null) {
                                when (status) {
                                    BluetoothGatt.GATT_SUCCESS -> {
                                        writeInProgress.resume(Unit)
                                    }

                                    else -> {
                                        writeInProgress.resumeWithException(BleException.Unknown("Characteristic write failure, status: $status"))
                                    }
                                }
                            }
                        }
                    }

                    override fun onDescriptorWrite(
                        gatt: BluetoothGatt,
                        descriptor: BluetoothGattDescriptor,
                        status: Int
                    ) {
                        super.onDescriptorWrite(gatt, descriptor, status);
                        Log.d(TAG, "onDescriptorWrite: ${descriptor.uuid}, status: $status")

                        val subscription = DeviceCharacteristicAddress(
                            gatt.device.address,
                            descriptor.characteristic.service.uuid,
                            descriptor.characteristic.uuid
                        )
                        val subscribingInProgress = mSubscribingInProgress.remove(subscription)
                        if (subscribingInProgress != null) {
                            when (status) {
                                BluetoothGatt.GATT_SUCCESS -> {
                                    synchronized(mSubscriptions) {
                                        if (subscribingInProgress.second) {
                                            mSubscriptions[subscription] = SubscriptionData()
                                        } else {
                                            val ongoing = mSubscriptions.remove(subscription)
                                            if (ongoing != null) {
                                                ongoing.continuation?.resumeWithException(
                                                    BleException.BroadcastNotStarted()
                                                )
                                            }
                                        }
                                    }

                                    subscribingInProgress.first.resume(Unit)
                                }

                                else -> {
                                    subscribingInProgress.first.resumeWithException(
                                        BleException.Unknown(
                                            "Descriptor write failure, status: $status"
                                        )
                                    )
                                }
                            }
                        }
                    }
                }

                val gatt = device.connectGatt(this.context, false, callback)
                gatt.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_HIGH)
                mConnections[deviceAddress] = gatt
            }
        }
    }

    private val mReadInProgress: MutableMap<DeviceCharacteristicAddress, Continuation<ByteArray>> =
        HashMap()

    @SuppressLint("MissingPermission")
    override suspend fun readData(
        deviceAddress: String, serviceUuid: String, characteristicUuid: String
    ): ByteArray {
        return exceptionWrapper {
            val (characteristic, gatt, address) = getCharacteristic(
                deviceAddress,
                serviceUuid,
                characteristicUuid
            )
            return@exceptionWrapper suspendCoroutine<ByteArray> { continuation ->
                synchronized(mReadInProgress) {
                    if (mReadInProgress.containsKey(address)) {
                        continuation.resumeWithException(BleException.AnotherOperationInProgress())
                        return@suspendCoroutine
                    }

                    if (!gatt.readCharacteristic(characteristic)) {
                        Log.w(TAG, "Read Characteristic failed: $characteristicUuid");
                        continuation.resumeWithException(BleException.Unknown("Read Characteristic failed: $characteristicUuid"))
                        return@suspendCoroutine
                    }

                    mReadInProgress[address] = continuation
                }
            }
        }
    }

    private val mWriteInProgress: MutableMap<DeviceCharacteristicAddress, Continuation<Unit>> =
        HashMap()

    @SuppressLint("MissingPermission")
    override suspend fun writeData(
        deviceAddress: String,
        serviceUuid: String,
        characteristicUuid: String,
        data: ByteArray,
        writeType: CharacteristicWriteTypeBindingEnum
    ) {
        return exceptionWrapper {
            val (characteristic, gatt, address) = getCharacteristic(
                deviceAddress,
                serviceUuid,
                characteristicUuid
            )
            return@exceptionWrapper suspendCoroutine { continuation ->
                synchronized(mWriteInProgress) {
                    if (mWriteInProgress.containsKey(address)) {
                        continuation.resumeWithException(BleException.AnotherOperationInProgress())
                        return@suspendCoroutine
                    }

                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        val statusCode =
                            gatt.writeCharacteristic(characteristic, data, getWriteType(writeType))
                        if (statusCode != BluetoothStatusCodes.SUCCESS) {
                            continuation.resumeWithException(
                                statusCodeException(
                                    statusCode,
                                    address.service,
                                    address.characteristic
                                )
                            )
                            return@suspendCoroutine
                        }

                    } else if (!characteristic.setValue(data) || !gatt.writeCharacteristic(
                            characteristic
                        )
                    ) {
                        continuation.resumeWithException(BleException.Unknown("Write Characteristic failed"))
                        return@suspendCoroutine
                    }

                    if (writeType == CharacteristicWriteTypeBindingEnum.WITHOUT_RESPONSE) {
                        continuation.resume(Unit)
                    } else {
                        mWriteInProgress[address] = continuation
                    }
                }
            }
        }
    }

    @SuppressLint("MissingPermission")
    override suspend fun disconnect(deviceAddress: String) {
        return exceptionWrapper {
            val device = mConnections.remove(deviceAddress)
            if (device == null) {
                Log.w(TAG, "Device not found: $deviceAddress");
                throw BleException.DeviceAddressNotFound(deviceAddress)
            }

            device.disconnect()
            device.close()

            onDeviceDisconnected(deviceAddress)
        }
    }

    private fun onDeviceDisconnected(deviceAddress: String) {
        mConnections.remove(deviceAddress)

        synchronized(mSubscriptions) {
            mSubscriptions.filter { it.key.deviceAddress == deviceAddress }
                .forEach {
                    it.value.continuation?.resumeWithException(
                        BleException.DeviceNotConnected(
                            deviceAddress
                        )
                    )
                    mSubscriptions.remove(it.key)
                }
        }

        synchronized(mReadInProgress) {
            mReadInProgress.filter { it.key.deviceAddress == deviceAddress }.forEach {
                it.value.resumeWithException(
                    BleException.DeviceNotConnected(deviceAddress)
                )
                mReadInProgress.remove(it.key)
            }
        }

        synchronized(mWriteInProgress) {
            mWriteInProgress.filter { it.key.deviceAddress == deviceAddress }.forEach {
                it.value.resumeWithException(
                    BleException.DeviceNotConnected(deviceAddress)
                )
                mWriteInProgress.remove(it.key)
            }
        }
    }

    private fun getCharacteristic(
        deviceAddress: String,
        serviceUuid: String,
        characteristicUuid: String
    ): Triple<BluetoothGattCharacteristic, BluetoothGatt, DeviceCharacteristicAddress> {
        val gatt =
            mConnections[deviceAddress] ?: throw BleException.DeviceAddressNotFound(deviceAddress)

        val address =
            DeviceCharacteristicAddress(
                deviceAddress,
                UUID.fromString(serviceUuid),
                UUID.fromString(characteristicUuid)
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
}
