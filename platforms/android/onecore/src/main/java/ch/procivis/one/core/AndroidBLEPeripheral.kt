package ch.procivis.one.core

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.os.Build
import android.os.ParcelUuid
import android.util.Log
import java.lang.ref.WeakReference
import java.util.UUID

/**
 * Default implementation of BLE peripheral-server
 */
class AndroidBLEPeripheral(context: Context) : BlePeripheral,
    AndroidBLEBase(context, "BLE_PERIPHERAL") {
    override suspend fun isAdapterEnabled(): Boolean {
        return getAdapterEnabled()
    }

    private data class Advertisement constructor(
        val callback: AdvertiseCallback,
        val advertiser: BluetoothLeAdvertiser
    ) {}

    private var mAdvertisement: Advertisement? = null
    private var mServer: BluetoothGattServer? = null

    @SuppressLint("MissingPermission")
    override suspend fun startAdvertisement(
        deviceName: String?,
        services: List<ServiceDescriptionBindingDto>
    ): String? {
        return asyncCallback { promise ->
            synchronized(lock) {
                if (mAdvertisement != null) {
                    throw BleException.BroadcastAlreadyStarted()
                }

                val adapter = getBluetoothAdapter()
                val advertiser = setupAdvertiser(adapter, deviceName)

                val advertiseDataBuilder = AdvertiseData.Builder()
                    .setIncludeDeviceName(deviceName != null)
                    .setIncludeTxPowerLevel(false)

                val scanResultBuilder =
                    AdvertiseData.Builder().setIncludeDeviceName(false)
                        .setIncludeTxPowerLevel(false)

                val server = startServer()

                for (service in services) {
                    val s = addServiceToBuilders(service, advertiseDataBuilder, scanResultBuilder)
                    if (!server.addService(s)) {
                        throw BleException.Unknown("Failed to add service ${service.uuid}")
                    }
                }

                val settings = AdvertiseSettings.Builder()
                    .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                    .setConnectable(true)
                    .setTimeout(0)
                    .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
                    .build()

                val callback = getAdvertiseCallback(server, adapter, promise)

                mAdvertisement = Advertisement(callback, advertiser)
                advertiser.startAdvertising(
                    settings,
                    advertiseDataBuilder.build(),
                    scanResultBuilder.build(),
                    callback
                )
            }
        }
    }

    @SuppressLint("MissingPermission")
    private fun setupAdvertiser(
        adapter: BluetoothAdapter,
        deviceName: String?
    ): BluetoothLeAdvertiser {
        val advertiser = adapter.bluetoothLeAdvertiser
        if (advertiser == null) {
            Log.w(TAG, "Failed to get BLE Advertiser, Bluetooth OFF or not supported")
            throw BleException.AdapterNotEnabled()
        }

        if (deviceName != null && !adapter.setName(deviceName)) {
            throw BleException.Unknown("Setting device name failed")
        }

        return advertiser
    }

    @SuppressLint("MissingPermission")
    private fun startServer(): BluetoothGattServer {
        mServer?.clearServices()
        val server = mServer ?: getBluetoothManager().openGattServer(
            this.context,
            getServerCallback()
        )
        if (server == null) {
            Log.w(TAG, "Unable to create GATT server");
            throw BleException.Unknown("Unable to create GATT server")
        }

        mServer = server
        return server
    }

    private fun addServiceToBuilders(
        service: ServiceDescriptionBindingDto,
        advertiseDataBuilder: AdvertiseData.Builder,
        scanResultBuilder: AdvertiseData.Builder
    ): BluetoothGattService {
        val uuid = UUID.fromString(service.uuid)
        val s = BluetoothGattService(
            uuid,
            BluetoothGattService.SERVICE_TYPE_PRIMARY
        )

        for (characteristic in service.characteristics) {
            val ch = BluetoothGattCharacteristic(
                UUID.fromString(characteristic.uuid),
                getCharacteristicProperties(characteristic.properties),
                getCharacteristicPermissions(characteristic.permissions)
            )

            if (characteristic.properties.contains(CharacteristicPropertyBindingEnum.NOTIFY)) {
                val descriptor = BluetoothGattDescriptor(
                    CLIENT_CONFIG_DESCRIPTOR,
                    BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE
                )
                descriptor.setValue(BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE)
                ch.addDescriptor(descriptor)
            }

            if (!s.addCharacteristic(ch)) {
                throw BleException.Unknown("Failed to add characteristic ${characteristic.uuid}")
            }
        }

        val parcelId = ParcelUuid(uuid)
        if (service.advertise) {
            advertiseDataBuilder.addServiceUuid(parcelId)

            if (service.advertisedServiceData != null) {
                advertiseDataBuilder.addServiceData(
                    parcelId,
                    service.advertisedServiceData
                )
            }
        } else if (service.advertisedServiceData != null) {
            scanResultBuilder.addServiceData(parcelId, service.advertisedServiceData)
        }

        return s
    }

    @SuppressLint("MissingPermission")
    private fun getAdvertiseCallback(
        server: BluetoothGattServer,
        adapter: BluetoothAdapter,
        advertisePromise: Promise<String?>
    ): AdvertiseCallback {
        return object : AdvertiseCallback() {
            @SuppressLint("HardwareIds")
            override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
                super.onStartSuccess(settingsInEffect)
                // https://developer.android.com/about/versions/marshmallow/android-6.0-changes.html#behavior-hardware-id
                advertisePromise.succeed(if (Build.VERSION.SDK_INT < 23) adapter.address else null)
            }

            override fun onStartFailure(errorCode: Int) {
                super.onStartFailure(errorCode)
                Log.w(TAG, "Failed to start BLE Advertiser: $errorCode")

                synchronized(lock) {
                    advertisePromise.fail(BleException.Unknown("Failed to start BLE Advertiser: $errorCode"))
                    server.close()
                    mServer = null
                    mAdvertisement = null
                }
            }
        }
    }

    @SuppressLint("MissingPermission")
    override suspend fun stopAdvertisement() {
        return exceptionWrapper {
            synchronized(lock) {
                val advertisement = mAdvertisement ?: throw BleException.BroadcastNotStarted()

                Log.d(TAG, "Stopping advertising")
                advertisement.advertiser.stopAdvertising(advertisement.callback)
                mAdvertisement = null
            }
        }
    }

    override suspend fun isAdvertising(): Boolean {
        return mAdvertisement != null
    }

    @SuppressLint("MissingPermission")
    override suspend fun stopServer() {
        return exceptionWrapper {
            synchronized(lock) {
                val server = mServer ?: throw BleException.ServerNotRunning()

                val advertisement = mAdvertisement
                if (advertisement != null) {
                    Log.d(TAG, "Stopping advertising before server stop")
                    advertisement.advertiser.stopAdvertising(advertisement.callback)
                    mAdvertisement = null
                }

                for (device in getBluetoothManager().getConnectedDevices(BluetoothProfile.GATT)) {
                    Log.d(TAG, "Disconnecting device:" + device.address)
                    server.cancelConnection(device)
                }

                Log.d(TAG, "Closing GATT server")
                server.close()
                mServer = null

                mWrites.values.forEach {
                    it.promise?.fail(BleException.BroadcastNotStarted())
                }
                mWrites.clear()

                mReads.values.forEach { readData ->
                    readData.device.forEach {
                        it.value.promise?.fail(BleException.BroadcastNotStarted())
                    }
                }
                mReads.clear()

                mNotifications.values.forEach {
                    it.fail(BleException.BroadcastNotStarted())
                }
                mNotifications.clear()

                mConnections.promise?.fail(BleException.BroadcastNotStarted())
                mConnections.promise = null
                mConnections.events.clear()
            }
        }
    }

    private class Connections {
        val events: MutableList<ConnectionEventBindingEnum> = mutableListOf()
        var promise: Promise<List<ConnectionEventBindingEnum>>? = null
    }

    private val mConnections = Connections()

    override suspend fun getConnectionChangeEvents(): List<ConnectionEventBindingEnum> {
        return asyncCallback { promise ->
            synchronized(lock) {
                if (mConnections.promise != null) {
                    throw BleException.AnotherOperationInProgress()
                }

                if (mConnections.events.isEmpty()) {
                    mConnections.promise = promise
                } else {
                    promise.succeed(mConnections.events.toList())
                    mConnections.events.clear()
                }
            }
        }
    }

    private class CharacteristicReadDeviceData {
        var read = false
        var promise: Promise<Unit>? = null
    }

    private class CharacteristicReadData constructor(val data: ByteArray) {
        val device: MutableMap<String, CharacteristicReadDeviceData> = mutableMapOf()
    }

    private val mReads: MutableMap<CharacteristicAddress, CharacteristicReadData> =
        HashMap()

    override suspend fun setCharacteristicData(
        service: String,
        characteristic: String,
        data: ByteArray
    ) {
        return exceptionWrapper {
            synchronized(lock) {
                val (ch, characteristicAddress) = getCharacteristic(
                    service,
                    characteristic
                )
                if ((ch.properties and BluetoothGattCharacteristic.PROPERTY_READ) == 0) {
                    Log.w(TAG, "Characteristic doesn't have read property: $characteristic")
                    throw BleException.InvalidCharacteristicOperation(
                        service,
                        characteristic,
                        "read"
                    )
                }

                val ongoingWait =
                    mReads[characteristicAddress]?.device?.values?.find { it.promise != null }
                if (ongoingWait != null) {
                    throw BleException.AnotherOperationInProgress()
                }

                if (!ch.setValue(data)) {
                    Log.w(TAG, "Characteristic value not set: $characteristic")
                    throw BleException.Unknown("Characteristic value not set")
                }

                mReads[characteristicAddress] = CharacteristicReadData(data)
            }
        }
    }

    override suspend fun waitForCharacteristicRead(
        device: String,
        service: String,
        characteristic: String
    ) {
        return asyncCallback { promise ->
            synchronized(lock) {
                val characteristicAddress = CharacteristicAddress(
                    UUID.fromString(service),
                    UUID.fromString(characteristic)
                )

                val readData = mReads[characteristicAddress]
                    ?: throw BleException.InvalidCharacteristicOperation(
                        service,
                        characteristic,
                        "read-wait"
                    )

                readData.device[device]?.let {
                    if (it.promise != null) {
                        throw BleException.Unknown("Already awaiting this read")
                    }

                    if (it.read) {
                        promise.succeed(Unit)
                    } else {
                        it.promise = promise
                    }
                    return@asyncCallback
                }

                val deviceData = CharacteristicReadDeviceData()
                deviceData.promise = promise
                readData.device[device] = deviceData
            }
        }
    }

    private class CharacteristicWriteData {
        val data: MutableList<ByteArray> = mutableListOf()
        var promise: Promise<List<ByteArray>>? = null
    }

    private val mWrites: MutableMap<DeviceCharacteristicAddress, CharacteristicWriteData> =
        mutableMapOf()

    override suspend fun getCharacteristicWrites(
        device: String,
        service: String,
        characteristic: String
    ): List<ByteArray> {
        return asyncCallback { promise ->
            synchronized(lock) {
                val (ch, characteristicAddress) = getCharacteristic(service, characteristic)
                if ((ch.properties and (BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE)) == 0) {
                    Log.w(TAG, "Characteristic doesn't have write property: $characteristic")
                    throw BleException.InvalidCharacteristicOperation(
                        service,
                        characteristic,
                        "write"
                    )
                }

                val deviceCharacteristicAddress = DeviceCharacteristicAddress(
                    device,
                    characteristicAddress.service,
                    characteristicAddress.characteristic
                )

                mWrites[deviceCharacteristicAddress]?.let { writeData ->
                    if (writeData.promise != null) {
                        throw BleException.Unknown("Already awaiting this write")
                    }

                    if (writeData.data.isEmpty()) {
                        writeData.promise = promise
                    } else {
                        promise.succeed(writeData.data.toList())
                        writeData.data.clear()
                    }

                    return@asyncCallback
                }

                val data = CharacteristicWriteData()
                data.promise = promise
                mWrites[deviceCharacteristicAddress] = data
            }
        }
    }

    // in-progress notifications
    private val mNotifications: MutableMap<String, Promise<Unit>> = HashMap()

    @SuppressLint("MissingPermission")
    override suspend fun notifyCharacteristicData(
        deviceAddress: String,
        service: String,
        characteristic: String,
        data: ByteArray
    ) {
        return asyncCallback { promise ->
            synchronized(lock) {
                val server = mServer ?: throw BleException.ServerNotRunning()
                val (ch, characteristicAddress) = getCharacteristic(
                    service,
                    characteristic
                )
                if ((ch.properties and BluetoothGattCharacteristic.PROPERTY_NOTIFY) == 0) {
                    Log.w(TAG, "Characteristic doesn't have notify property: $characteristic")
                    throw BleException.InvalidCharacteristicOperation(
                        service,
                        characteristic,
                        "notify"
                    )
                }

                val descriptorValue = ch.getDescriptor(CLIENT_CONFIG_DESCRIPTOR)?.value
                if (!BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE.contentEquals(descriptorValue)) {
                    Log.w(TAG, "Descriptor notifications disabled: $characteristic")
                    throw BleException.BroadcastNotStarted()
                }

                if (mNotifications.containsKey(deviceAddress)) {
                    throw BleException.AnotherOperationInProgress()
                }

                val device = findDevice(deviceAddress)
                notifyCharacteristicInternal(server, device, ch, characteristicAddress, data)
                mNotifications[deviceAddress] = promise
            }
        }
    }

    @SuppressLint("MissingPermission")
    private fun findDevice(deviceAddress: String): BluetoothDevice {
        val manager = getBluetoothManager()
        val device = manager.getConnectedDevices(BluetoothProfile.GATT)
            .find { it.address == deviceAddress }
        if (device == null) {
            Log.w(TAG, "Device not found: $deviceAddress")
            throw BleException.DeviceAddressNotFound(deviceAddress)
        }

        return device
    }

    @SuppressLint("MissingPermission")
    private fun notifyCharacteristicInternal(
        server: BluetoothGattServer,
        device: BluetoothDevice,
        characteristic: BluetoothGattCharacteristic,
        characteristicAddress: CharacteristicAddress,
        data: ByteArray
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val statusCode = server.notifyCharacteristicChanged(device, characteristic, false, data)
            if (statusCode != BluetoothStatusCodes.SUCCESS) {
                throw statusCodeException(
                    statusCode,
                    characteristicAddress.service,
                    characteristicAddress.characteristic
                )
            }
        } else {
            if (!characteristic.setValue(data) || !server.notifyCharacteristicChanged(
                    device,
                    characteristic,
                    false
                )
            ) {
                Log.w(
                    TAG,
                    "Characteristic notification failure: ${characteristicAddress.characteristic}"
                )
                throw BleException.Unknown("Characteristic notification failure")
            }
        }
    }

    private fun onMtuNegotiated(deviceAddress: String, mtu: Int) {
        synchronized(lock) {
            onConnectionEvent(
                ConnectionEventBindingEnum.Connected(
                    DeviceInfoBindingDto(
                        deviceAddress, mtu.coerceAtMost(
                            MAX_MTU
                        ).toUShort()
                    )
                )
            )
        }
    }

    private fun onConnectionEvent(
        event: ConnectionEventBindingEnum
    ) {
        val deviceAddress = when (event) {
            is ConnectionEventBindingEnum.Connected ->
                event.deviceInfo.address

            is ConnectionEventBindingEnum.Disconnected ->
                event.deviceAddress
        }

        // replace outdated events
        mConnections.events.removeAll {
            when (val oldEvent = it) {
                is ConnectionEventBindingEnum.Connected ->
                    oldEvent.deviceInfo.address == deviceAddress

                is ConnectionEventBindingEnum.Disconnected ->
                    oldEvent.deviceAddress == deviceAddress
            }
        }

        mConnections.events.add(event)
        val promise = mConnections.promise
        if (promise != null) {
            promise.succeed(mConnections.events.toList())
            mConnections.promise = null
            mConnections.events.clear()
        }
    }

    private fun onDeviceDisconnected(deviceAddress: String) {
        mWrites.filter { it.key.deviceAddress == deviceAddress }.forEach {
            it.value.promise?.fail(BleException.DeviceNotConnected(deviceAddress))
            mWrites.remove(it.key)
        }

        mReads.values.forEach {
            val deviceData = it.device.remove(deviceAddress)
            deviceData?.promise?.fail(BleException.DeviceNotConnected(deviceAddress))
        }

        val ongoing = mNotifications.remove(deviceAddress)
        ongoing?.fail(BleException.DeviceNotConnected(deviceAddress))
    }

    private fun getCharacteristic(
        serviceUuid: String,
        characteristicUuid: String
    ): Pair<BluetoothGattCharacteristic, CharacteristicAddress> {
        val server = mServer ?: throw BleException.ServerNotRunning()

        val characteristicAddress = CharacteristicAddress(
            UUID.fromString(serviceUuid),
            UUID.fromString(characteristicUuid)
        )

        val service =
            server.getService(characteristicAddress.service) ?: throw BleException.ServiceNotFound(
                serviceUuid
            )
        val characteristic = service.getCharacteristic(characteristicAddress.characteristic)
            ?: throw BleException.CharacteristicNotFound(characteristicUuid)
        return Pair(characteristic, characteristicAddress)
    }

    private fun getCharacteristicProperties(properties: List<CharacteristicPropertyBindingEnum>): Int {
        var result = 0
        properties.forEach {
            result = result or when (it) {
                CharacteristicPropertyBindingEnum.READ -> BluetoothGattCharacteristic.PROPERTY_READ
                CharacteristicPropertyBindingEnum.WRITE -> BluetoothGattCharacteristic.PROPERTY_WRITE
                CharacteristicPropertyBindingEnum.WRITE_WITHOUT_RESPONSE -> BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE
                CharacteristicPropertyBindingEnum.NOTIFY -> BluetoothGattCharacteristic.PROPERTY_NOTIFY
                CharacteristicPropertyBindingEnum.INDICATE -> BluetoothGattCharacteristic.PROPERTY_INDICATE
            }
        }
        return result
    }

    private fun getCharacteristicPermissions(permissions: List<CharacteristicPermissionBindingEnum>): Int {
        var result = 0
        permissions.forEach {
            result = result or when (it) {
                CharacteristicPermissionBindingEnum.READ -> BluetoothGattCharacteristic.PERMISSION_READ
                CharacteristicPermissionBindingEnum.WRITE -> BluetoothGattCharacteristic.PERMISSION_WRITE
            }
        }
        return result
    }

    private fun getServerCallback(): BluetoothGattServerCallback {
        return ServerCallback(WeakReference(this))
    }

    private class ServerCallback(private val parent: WeakReference<AndroidBLEPeripheral>) :
        BluetoothGattServerCallback() {
        private val TAG: String = parent.get()?.TAG.toString()

        @SuppressLint("MissingPermission")
        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice, requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean, responseNeeded: Boolean,
            offset: Int, value: ByteArray
        ) {
            val deviceAddress = device.address
            Log.d(TAG, "onCharacteristicWriteRequest: " + characteristic.uuid)

            val characteristicAddress = DeviceCharacteristicAddress(
                deviceAddress,
                characteristic.service.uuid,
                characteristic.uuid
            )

            synchronized(lock) {
                parent.get()?.mWrites?.let { mWrites ->
                    val writeData = mWrites[characteristicAddress]
                    if (writeData == null) {
                        val data = CharacteristicWriteData()
                        data.data.add(value)
                        mWrites[characteristicAddress] = data
                    } else {
                        writeData.data.add(value)
                        val promise = writeData.promise
                        if (promise != null) {
                            promise.succeed(writeData.data.toList())
                            writeData.promise = null
                            writeData.data.clear()
                        }
                    }
                }

                if (responseNeeded) {
                    parent.get()?.mServer?.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_SUCCESS,
                        0,
                        byteArrayOf()
                    )
                }
            }
        }

        @SuppressLint("MissingPermission")
        override fun onCharacteristicReadRequest(
            device: BluetoothDevice, requestId: Int,
            offset: Int, characteristic: BluetoothGattCharacteristic
        ) {
            val deviceAddress = device.address
            Log.d(
                TAG,
                "onCharacteristicReadRequest: ${characteristic.uuid}"
            )

            val characteristicAddress =
                CharacteristicAddress(characteristic.service.uuid, characteristic.uuid)

            synchronized(lock) {
                val readData = parent.get()?.mReads?.get(characteristicAddress)
                if (readData == null) {
                    Log.w(
                        TAG,
                        "Characteristic Read data not set: ${characteristic.uuid}"
                    )

                    parent.get()?.mServer?.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_FAILURE,
                        0,
                        byteArrayOf()
                    )
                    return
                }

                parent.get()?.mServer?.sendResponse(
                    device,
                    requestId,
                    BluetoothGatt.GATT_SUCCESS,
                    0,
                    readData.data
                )

                val deviceData = readData.device[deviceAddress]
                if (deviceData == null) {
                    val data = CharacteristicReadDeviceData()
                    data.read = true
                    readData.device[deviceAddress] = data
                } else {
                    deviceData.read = true
                    deviceData.promise?.succeed(Unit)
                    deviceData.promise = null
                }
            }
        }

        override fun onNotificationSent(device: BluetoothDevice, status: Int) {
            super.onNotificationSent(device, status)
            val deviceAddress = device.address
            synchronized(lock) {
                val result = parent.get()?.mNotifications?.remove(deviceAddress)
                if (result == null) {
                    Log.w(TAG, "Notification not found: $deviceAddress")
                    return
                }

                if (status == BluetoothGatt.GATT_SUCCESS) {
                    result.succeed(Unit)
                } else {
                    result.fail(BleException.Unknown("Notification failure: $status"))
                }
            }
        }

        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            super.onMtuChanged(device, mtu)
            val deviceAddress = device.address
            Log.d(TAG, "New MTU: $mtu for device: $deviceAddress")
            parent.get()?.onMtuNegotiated(deviceAddress, mtu)
        }

        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(
            device: BluetoothDevice,
            status: Int,
            newState: Int
        ) {
            super.onConnectionStateChange(device, status, newState)
            val deviceAddress = device.address
            Log.d(TAG, "New connection state: $newState for device: $deviceAddress")
            when (newState) {
                BluetoothProfile.STATE_DISCONNECTED -> {
                    synchronized(lock) {
                        val event = ConnectionEventBindingEnum.Disconnected(deviceAddress)
                        parent.get()?.onConnectionEvent(event)
                        parent.get()?.onDeviceDisconnected(deviceAddress)
                    }
                }

                BluetoothProfile.STATE_CONNECTED -> {
                    // workaround to trigger MTU negotiation from BLE peripheral
                    Log.d(TAG, "Forceful MTU negotiation: $deviceAddress")
                    device.connectGatt(
                        parent.get()?.context,
                        false,
                        object : BluetoothGattCallback() {
                            override fun onConnectionStateChange(
                                gatt: BluetoothGatt, status: Int,
                                newState: Int
                            ) {
                                Log.d(TAG, "Gatt connection state: $newState, status: $status")
                                if (status == BluetoothGatt.GATT_SUCCESS) {
                                    val result = gatt.requestMtu(MAX_MTU)
                                    Log.d(TAG, "MTU request result: $result")
                                }
                            }

                            override fun onMtuChanged(
                                gatt: BluetoothGatt?,
                                mtu: Int,
                                status: Int
                            ) {
                                Log.d(TAG, "Gatt MTU CHANGED: $mtu, status: $status")
                                if (status == BluetoothGatt.GATT_SUCCESS) {
                                    parent.get()?.onMtuNegotiated(deviceAddress, mtu)
                                }
                            }
                        })
                }
            }
        }

        @SuppressLint("MissingPermission")
        override fun onDescriptorReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            descriptor: BluetoothGattDescriptor
        ) {
            super.onDescriptorReadRequest(device, requestId, offset, descriptor)
            Log.d(TAG, "onDescriptorReadRequest: " + descriptor.characteristic.uuid)
            parent.get()?.mServer?.sendResponse(
                device,
                requestId,
                BluetoothGatt.GATT_SUCCESS,
                0,
                descriptor.value
            )
        }

        @SuppressLint("MissingPermission")
        override fun onDescriptorWriteRequest(
            device: BluetoothDevice, requestId: Int,
            descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean, responseNeeded: Boolean,
            offset: Int, value: ByteArray
        ) {
            super.onDescriptorWriteRequest(
                device,
                requestId,
                descriptor,
                preparedWrite,
                responseNeeded,
                offset,
                value
            )
            Log.d(TAG, "onDescriptorWriteRequest: " + descriptor.characteristic.uuid)
            descriptor.setValue(value)
            if (responseNeeded) {
                parent.get()?.mServer?.sendResponse(
                    device,
                    requestId,
                    BluetoothGatt.GATT_SUCCESS,
                    0,
                    byteArrayOf()
                )
            }
        }
    }
}
