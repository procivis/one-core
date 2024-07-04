package ch.procivis.one.core

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
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
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine
import kotlin.math.min

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
        return exceptionWrapper {
            val manager = getBluetoothManager()
            val adapter = getBluetoothAdapter()

            if (deviceName != null) {
                adapter.setName(deviceName)
            }

            val advertiseDataBuilder = AdvertiseData.Builder()
                .setIncludeDeviceName(deviceName != null)
                .setIncludeTxPowerLevel(false)

            val scanResultBuilder =
                AdvertiseData.Builder().setIncludeDeviceName(false).setIncludeTxPowerLevel(false)

            val advertiser = adapter.bluetoothLeAdvertiser
            if (advertiser == null) {
                Log.w(TAG, "Failed to get BLE Advertiser, Bluetooth OFF or not supported")
                throw BleException.AdapterNotEnabled()
            }

            mServer?.close()
            val server = manager.openGattServer(this.context, getServerCallback())
            if (server == null) {
                Log.w(TAG, "Unable to create GATT server");
                throw BleException.Unknown("Unable to create GATT server")
            }

            for (service in services) {
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

                if (!server.addService(s)) {
                    throw BleException.Unknown("Failed to add service ${service.uuid}")
                }

                val parcelId = ParcelUuid(uuid)
                if (service.advertise) {
                    advertiseDataBuilder.addServiceUuid(parcelId)

                    if (service.advertisedServiceData != null) {
                        advertiseDataBuilder.addServiceData(parcelId, service.advertisedServiceData)
                    }
                } else if (service.advertisedServiceData != null) {
                    scanResultBuilder.addServiceData(parcelId, service.advertisedServiceData)
                }
            }

            val advertiseData = advertiseDataBuilder.build()
            val scanResult = scanResultBuilder.build()

            val settings = AdvertiseSettings.Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                .setConnectable(true)
                .setTimeout(0)
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
                .build()

            return@exceptionWrapper suspendCoroutine { continuation ->
                val callback = object : AdvertiseCallback() {
                    @SuppressLint("HardwareIds")
                    override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
                        super.onStartSuccess(settingsInEffect)
                        // https://developer.android.com/about/versions/marshmallow/android-6.0-changes.html#behavior-hardware-id
                        continuation.resume(if (Build.VERSION.SDK_INT < 23) adapter.address else null)
                    }

                    override fun onStartFailure(errorCode: Int) {
                        super.onStartFailure(errorCode)
                        Log.w(TAG, "Failed to start BLE Advertiser: $errorCode")
                        continuation.resumeWithException(BleException.Unknown("Failed to start BLE Advertiser: $errorCode"))

                        server.close()
                        mServer = null
                        mAdvertisement = null
                    }
                }

                synchronized(this) {
                    if (mAdvertisement != null) {
                        continuation.resumeWithException(BleException.BroadcastAlreadyStarted())
                        return@suspendCoroutine
                    }

                    mServer = server
                    mAdvertisement = Advertisement(callback, advertiser)
                    advertiser.startAdvertising(settings, advertiseData, scanResult, callback)
                }
            }
        }
    }

    @SuppressLint("MissingPermission")
    override suspend fun stopAdvertisement() {
        return exceptionWrapper {
            synchronized(this) {
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
            synchronized(this) {
                val advertisement = mAdvertisement
                if (advertisement != null) {
                    Log.d(TAG, "Stopping advertising before server stop")
                    advertisement.advertiser.stopAdvertising(advertisement.callback)
                    mAdvertisement = null
                }

                val server = mServer ?: throw BleException.ServerNotRunning()

                for (device in getBluetoothManager().getConnectedDevices(BluetoothProfile.GATT)) {
                    Log.d(TAG, "Disconnecting device:" + device.address)
                    server.cancelConnection(device)
                }

                Log.d(TAG, "Closing GATT server")
                server.close()
                mServer = null
            }

            synchronized(mWrites) {
                mWrites.forEach {
                    it.value.continuation?.resumeWithException(BleException.BroadcastNotStarted())
                }
                mWrites.clear()
            }

            synchronized(mReads) {
                mReads.values.forEach { readData ->
                    readData.device.forEach {
                        it.value.continuation?.resumeWithException(BleException.BroadcastNotStarted())
                    }
                }
                mReads.clear()
            }

            synchronized(mNotifications) {
                mNotifications.forEach {
                    it.value.resumeWithException(BleException.BroadcastNotStarted())
                }
                mNotifications.clear()
            }

            synchronized(mConnections) {
                mConnections.continuation?.resumeWithException(BleException.BroadcastNotStarted())
                mConnections.continuation = null
                mConnections.events.clear()
            }
        }
    }

    private class Connections {
        val events: MutableList<ConnectionEventBindingEnum> = mutableListOf()
        var continuation: Continuation<List<ConnectionEventBindingEnum>>? = null
    }

    private val mConnections = Connections()

    override suspend fun getConnectionChangeEvents(): List<ConnectionEventBindingEnum> {
        return exceptionWrapper {
            if (mAdvertisement == null) {
                throw BleException.BroadcastNotStarted()
            }

            return@exceptionWrapper suspendCoroutine<List<ConnectionEventBindingEnum>> { continuation ->
                synchronized(mConnections) {
                    if (mConnections.continuation != null) {
                        continuation.resumeWithException(BleException.AnotherOperationInProgress())
                        return@suspendCoroutine
                    }

                    if (mConnections.events.isEmpty()) {
                        mConnections.continuation = continuation
                    } else {
                        continuation.resume(mConnections.events.toList())
                        mConnections.events.clear()
                    }
                }
            }
        }
    }

    private class CharacteristicReadDeviceData {
        var read = false
        var continuation: Continuation<Unit>? = null
    }

    private class CharacteristicReadData constructor(val data: ByteArray) {
        val device: MutableMap<String, CharacteristicReadDeviceData> = mutableMapOf()
    }

    private val mReads: MutableMap<CharacteristicAddress, CharacteristicReadData> =
        HashMap()

    override suspend fun setCharacteristicData(
        serviceUuid: String,
        characteristicUuid: String,
        data: ByteArray
    ) {
        return exceptionWrapper {
            val (characteristic, characteristicAddress) = getCharacteristic(
                serviceUuid,
                characteristicUuid
            )
            if ((characteristic.properties and BluetoothGattCharacteristic.PROPERTY_READ) == 0) {
                Log.w(TAG, "Characteristic doesn't have read property: $characteristicUuid")
                throw BleException.InvalidCharacteristicOperation(
                    serviceUuid,
                    characteristicUuid,
                    "read"
                )
            }

            synchronized(mReads) {
                val ongoingWait =
                    mReads[characteristicAddress]?.device?.values?.find { it.continuation != null }
                if (ongoingWait != null) {
                    throw BleException.AnotherOperationInProgress()
                }

                if (!characteristic.setValue(data)) {
                    Log.w(TAG, "Characteristic value not set: $characteristicUuid")
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
        return exceptionWrapper {
            val characteristicAddress = CharacteristicAddress(
                UUID.fromString(service),
                UUID.fromString(characteristic)
            )
            return@exceptionWrapper suspendCoroutine<Unit> { continuation ->
                synchronized(mReads) {
                    val readData = mReads[characteristicAddress]
                    if (readData == null) {
                        continuation.resumeWithException(
                            BleException.InvalidCharacteristicOperation(
                                service,
                                characteristic,
                                "read-wait"
                            )
                        )
                        return@suspendCoroutine
                    }

                    if (readData.device.containsKey(device)) {
                        val deviceData = readData.device[device]!!
                        if (deviceData.continuation != null) {
                            continuation.resumeWithException(BleException.Unknown("Already awaiting this read"))
                            return@suspendCoroutine
                        }

                        if (deviceData.read) {
                            continuation.resume(Unit)
                        } else {
                            deviceData.continuation = continuation
                        }
                    } else {
                        val deviceData = CharacteristicReadDeviceData()
                        deviceData.continuation = continuation
                        readData.device[device] = deviceData
                    }
                }
            }
        }
    }

    private class CharacteristicWriteData {
        val data: MutableList<ByteArray> = mutableListOf()
        var continuation: Continuation<List<ByteArray>>? = null
    }

    private val mWrites: MutableMap<DeviceCharacteristicAddress, CharacteristicWriteData> =
        mutableMapOf()

    override suspend fun getCharacteristicWrites(
        device: String,
        service: String,
        characteristic: String
    ): List<ByteArray> {
        return exceptionWrapper {
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

            return@exceptionWrapper suspendCoroutine<List<ByteArray>> { continuation ->
                synchronized(mWrites) {
                    val writeData = mWrites[deviceCharacteristicAddress]
                    if (writeData == null) {
                        val data = CharacteristicWriteData()
                        data.continuation = continuation
                        mWrites[deviceCharacteristicAddress] = data
                    } else {
                        if (writeData.continuation != null) {
                            continuation.resumeWithException(BleException.Unknown("Already awaiting this write"))
                            return@suspendCoroutine
                        }

                        if (writeData.data.isEmpty()) {
                            writeData.continuation = continuation
                        } else {
                            continuation.resume(writeData.data.toList())
                            writeData.data.clear()
                        }
                    }
                }
            }
        }
    }

    // in-progress notifications
    private val mNotifications: MutableMap<String, Continuation<Unit>> = HashMap()

    @SuppressLint("MissingPermission")
    override suspend fun notifyCharacteristicData(
        deviceAddress: String,
        serviceUuid: String,
        characteristicUuid: String,
        data: ByteArray
    ) {
        return exceptionWrapper {
            val server = mServer ?: throw BleException.ServerNotRunning()
            val (characteristic, characteristicAddress) = getCharacteristic(
                serviceUuid,
                characteristicUuid
            )
            if ((characteristic.properties and BluetoothGattCharacteristic.PROPERTY_NOTIFY) == 0) {
                Log.w(TAG, "Characteristic doesn't have notify property: $characteristicUuid")
                throw BleException.InvalidCharacteristicOperation(
                    serviceUuid,
                    characteristicUuid,
                    "notify"
                )
            }

            val descriptorValue = characteristic.getDescriptor(CLIENT_CONFIG_DESCRIPTOR)?.value
            if (!BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE.contentEquals(descriptorValue)) {
                Log.w(TAG, "Descriptor notifications disabled: $characteristicUuid")
                throw BleException.BroadcastNotStarted()
            }

            val manager = getBluetoothManager()
            val device = manager.getConnectedDevices(BluetoothProfile.GATT)
                .find { it.address == deviceAddress }
            if (device == null) {
                Log.w(TAG, "Device not found: $deviceAddress")
                throw BleException.DeviceAddressNotFound(deviceAddress)
            }

            return@exceptionWrapper suspendCoroutine { continuation ->
                synchronized(mNotifications) {
                    if (mNotifications.containsKey(deviceAddress)) {
                        continuation.resumeWithException(BleException.AnotherOperationInProgress())
                        return@suspendCoroutine
                    }

                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        val statusCode =
                            server.notifyCharacteristicChanged(
                                device,
                                characteristic,
                                false,
                                data
                            )
                        if (statusCode != BluetoothStatusCodes.SUCCESS) {
                            continuation.resumeWithException(
                                statusCodeException(
                                    statusCode,
                                    characteristicAddress.service,
                                    characteristicAddress.characteristic
                                )
                            )
                            return@suspendCoroutine
                        }
                    } else {
                        if (!characteristic.setValue(data) || !server.notifyCharacteristicChanged(
                                device,
                                characteristic,
                                false
                            )
                        ) {
                            Log.w(TAG, "Characteristic notification failure: $characteristicUuid")
                            continuation.resumeWithException(BleException.Unknown("Characteristic notification failure"))
                            return@suspendCoroutine
                        }
                    }

                    mNotifications[deviceAddress] = continuation
                }
            }
        }
    }

    private fun getServerCallback(): BluetoothGattServerCallback {
        return object : BluetoothGattServerCallback() {
            // negotiated MTU's
            private val mMTU: MutableMap<String, Int> = ConcurrentHashMap()

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

                synchronized(mWrites) {
                    val writeData = mWrites[characteristicAddress]
                    if (writeData == null) {
                        val data = CharacteristicWriteData()
                        data.data.add(value)
                        mWrites[characteristicAddress] = data
                    } else {
                        writeData.data.add(value)
                        val c = writeData.continuation
                        if (c != null) {
                            c.resume(writeData.data.toList())
                            writeData.continuation = null
                            writeData.data.clear()
                        }
                    }
                }

                if (responseNeeded) {
                    mServer?.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_SUCCESS,
                        0,
                        byteArrayOf()
                    )
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

                synchronized(mReads) {
                    val readData = mReads[characteristicAddress]
                    if (readData == null) {
                        Log.w(
                            TAG,
                            "Characteristic Read data not set: ${characteristic.uuid}"
                        )

                        mServer?.sendResponse(
                            device,
                            requestId,
                            BluetoothGatt.GATT_FAILURE,
                            0,
                            byteArrayOf()
                        )
                        return
                    }

                    mServer?.sendResponse(
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
                        deviceData.continuation?.resume(Unit)
                        deviceData.continuation = null
                    }
                }
            }

            override fun onNotificationSent(device: BluetoothDevice, status: Int) {
                super.onNotificationSent(device, status)
                val deviceAddress = device.address
                synchronized(mNotifications) {
                    val result = mNotifications.remove(deviceAddress)
                    if (result == null) {
                        Log.w(TAG, "Notification not found: $deviceAddress")
                        return
                    }

                    if (status == BluetoothGatt.GATT_SUCCESS) {
                        result.resume(Unit)
                    } else {
                        result.resumeWithException(BleException.Unknown("Notification failure: $status"))
                    }
                }
            }

            override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
                super.onMtuChanged(device, mtu)
                val deviceAddress = device.address
                Log.d(TAG, "New MTU: $mtu for device: $deviceAddress")
                val calculatedMtu = min(mtu, MAX_MTU)
                mMTU[deviceAddress] = calculatedMtu

                // try to update a pending connected event, if not yet read
                synchronized(mConnections) {
                    val pendingEvent = mConnections.events.find {
                        when (val event = it) {
                            is ConnectionEventBindingEnum.Connected ->
                                event.deviceInfo.address == deviceAddress

                            else -> false
                        }
                    } as ConnectionEventBindingEnum.Connected?
                    if (pendingEvent != null) {
                        pendingEvent.deviceInfo.mtu = calculatedMtu.toUShort()
                    }
                }
            }

            override fun onConnectionStateChange(
                device: BluetoothDevice,
                status: Int,
                newState: Int
            ) {
                super.onConnectionStateChange(device, status, newState)
                val deviceAddress = device.address
                Log.d(TAG, "New connection state: $newState for device: $deviceAddress")
                when (newState) {
                    BluetoothProfile.STATE_CONNECTED, BluetoothProfile.STATE_DISCONNECTED -> {
                        val newEvent = when (newState) {
                            BluetoothProfile.STATE_CONNECTED -> {
                                val mtu = mMTU[deviceAddress] ?: MAX_MTU
                                ConnectionEventBindingEnum.Connected(
                                    DeviceInfoBindingDto(deviceAddress, mtu.toUShort())
                                )
                            }

                            BluetoothProfile.STATE_DISCONNECTED -> ConnectionEventBindingEnum.Disconnected(
                                deviceAddress
                            )

                            else -> return // cannot happen
                        }

                        synchronized(mConnections) {
                            // replace outdated events
                            mConnections.events.removeAll {
                                when (val event = it) {
                                    is ConnectionEventBindingEnum.Connected ->
                                        event.deviceInfo.address == deviceAddress

                                    is ConnectionEventBindingEnum.Disconnected ->
                                        event.deviceAddress == deviceAddress
                                }
                            }
                            mConnections.events.add(newEvent)
                            val c = mConnections.continuation
                            if (c != null) {
                                c.resume(mConnections.events.toList())
                                mConnections.continuation = null
                                mConnections.events.clear()
                            }
                        }

                        if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                            onDeviceDisconnected(deviceAddress)
                        }
                    }
                }
            }
        }
    }

    private fun onDeviceDisconnected(deviceAddress: String) {
        synchronized(mWrites) {
            mWrites.filter { it.key.deviceAddress == deviceAddress }.forEach {
                it.value.continuation?.resumeWithException(
                    BleException.DeviceNotConnected(
                        deviceAddress
                    )
                )
                mWrites.remove(it.key)
            }
        }

        synchronized(mReads) {
            mReads.values.forEach {
                val deviceData = it.device.remove(deviceAddress)
                if (deviceData != null) {
                    deviceData.continuation?.resumeWithException(
                        BleException.DeviceNotConnected(
                            deviceAddress
                        )
                    )
                }
            }
        }

        synchronized(mNotifications) {
            val ongoing = mNotifications.remove(deviceAddress)
            ongoing?.resumeWithException(BleException.DeviceNotConnected(deviceAddress))
        }
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
}