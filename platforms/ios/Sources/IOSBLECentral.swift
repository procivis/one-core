import CoreBluetooth
import UIKit

class IOSBLECentral: NSObject {
    
    private lazy var centralManager: CBCentralManager = {
        return CBCentralManager(delegate: self,
                                queue: nil)
    }()
    
    
    private var adapterStateCallback: BLEResultCallback<CBManagerState>?
    private var peripheralConnectResultCallback: BLEThrowingResultCallback<Void>?
    private var peripheralDisconnectResultCallback: BLEThrowingResultCallback<Void>?
    private var getDiscoveredDevicesCallback: BLEResultCallback<[PeripheralDiscoveryDataBindingDto]>?
    private var characteristicWriteResultCallbacks: [CharacteristicKey: BLEThrowingResultCallback<Void>] = [:]
    private var characteristicWriteWithoutResponseResultCallbacks: [UUID: BLEThrowingResultCallback<Void>] = [:]
    private var characteristicReadResultCallbacks: [CharacteristicKey: BLEThrowingResultCallback<Data>] = [:]
    private var subscribeToCharacteristicNotificationsResultCallbacks: [CharacteristicKey: BLEThrowingResultCallback<Void>] = [:]
    private var subscribedCharacteristics = Set<CharacteristicKey>()
    private var unsubscribeFromCharacteristicNotificationsResultCallbacks: [CharacteristicKey: BLEThrowingResultCallback<Void>] = [:]
    private var getNotificationsCallbacks: [CharacteristicKey: BLEThrowingResultCallback<[Data]>] = [:]
    private var discoverServicesResultCallback: BLEThrowingResultCallback<[ServiceDescriptionBindingDto]>?
    private var discoverCharacteristicsResultCallbacks: [CBUUID: BLEThrowingResultCallback<ServiceDescriptionBindingDto>] = [:]
    
    private let deviceDiscoveryLock = NSLock()
    private let deviceDisconnectLock = NSLock()
    private let writeLock = NSLock()
    private let notificationsLock = NSLock()
    
    private var connectedPeripherals: Set<CBPeripheral> = []
    private var discoveredPeripheralsQueue: [PeripheralDiscoveryDataBindingDto] = []
    private var disconnectedPeripheralsQueue: [String] = []
    private var notificationsQueues: [CharacteristicKey: [Data]] = [:]
}

// MARK: - BLECentral interface implementation

extension IOSBLECentral: BleCentral {
    
    func isAdapterEnabled() async throws -> Bool {
        var state = centralManager.state
        if (state == .unknown) {
            state = await withCheckedContinuation { continuation in
                adapterStateCallback = { [weak self] result in
                    self?.adapterStateCallback = nil
                    continuation.resume(with: result)
                }
            }
        }
#if DEBUG
        print("centralManager state \(state)")
#endif
        return state == .poweredOn
    }
    
    func startScan(filterServices: [String]?) async throws {
        guard try await isAdapterEnabled() else {
            throw BleErrorWrapper.Ble(error: BleError.AdapterNotEnabled)
        }
        guard !centralManager.isScanning else {
            throw BleErrorWrapper.Ble(error: BleError.ScanAlreadyStarted)
        }
        discoveredPeripheralsQueue = []
        centralManager.scanForPeripherals(withServices: filterServices?.map { CBUUID(string: $0) })
    }
    
    func stopScan() async throws {
        guard centralManager.isScanning else {
            return
        }
        centralManager.stopScan()
    }
    
    func isScanning() async throws -> Bool {
        return centralManager.isScanning
    }
    
    func connect(deviceAddress: String) async throws -> UInt16 {
        guard let peripheralUuid = UUID(uuidString: deviceAddress) else {
            throw BleErrorWrapper.Ble(error: BleError.InvalidUuid(uuid: deviceAddress))
        }
        try await connectWithoutDiscovery(peripheral: peripheralUuid)
        let discoveredServices = try await discoverServices(peripheral: peripheralUuid, services: nil)
        let servicesWithCharacteristics = try await withThrowingTaskGroup(of: ServiceDescriptionBindingDto.self) { group in
            var services = [ServiceDescriptionBindingDto]()
            let serviceUUIDs = Array(Set(discoveredServices)).map { $0.uuid }
            services.reserveCapacity(serviceUUIDs.count)
            for uuid in serviceUUIDs {
                group.addTask {
                    return try await self.discoverCharacteristics(peripheral: peripheralUuid, service: CBUUID(string: uuid), characteristics: nil)
                }
            }
            for try await service in group {
                services.append(service)
#if DEBUG
                print("service \(services.count) of \(serviceUUIDs.count)")
#endif
            }
            return services
        }
#if DEBUG
        print("conected and discovered characteristics \(servicesWithCharacteristics)")
#endif
        let mtu = try getMtu(peripheral: peripheralUuid)
#if DEBUG
        print("MTU \(mtu)")
#endif
        return mtu
    }
    
    func disconnect(deviceAddress: String) async throws {
        guard let peripheralUuid = UUID(uuidString: deviceAddress) else {
            throw BleErrorWrapper.Ble(error: BleError.InvalidUuid(uuid: deviceAddress))
        }
        let cbPeripheral = try retrievePeripheral(peripheral: peripheralUuid)
        return try await withCheckedThrowingContinuation { continuation in
            deviceDisconnectLock.withLock {
                centralManager.cancelPeripheralConnection(cbPeripheral)
                peripheralDisconnectResultCallback = { [weak self] result in
                    self?.peripheralDisconnectResultCallback = nil
                    continuation.resume(with: result)
                }
            }
        }
    }
    
    func getDiscoveredDevices() async throws -> [PeripheralDiscoveryDataBindingDto] {
        return await withCheckedContinuation { continuation in
            deviceDiscoveryLock.withLock {
                guard discoveredPeripheralsQueue.isEmpty else {
                    let peripherals = discoveredPeripheralsQueue
                    discoveredPeripheralsQueue = []
                    continuation.resume(with: Result.success(peripherals))
                    return
                }
                getDiscoveredDevicesCallback = { [weak self] result in
                    self?.getDiscoveredDevicesCallback = nil
                    continuation.resume(with: result)
                }
            }
        }
    }
    
    func writeData(deviceAddress: String, serviceUuid: String, characteristicUuid: String, data: Data, writeType: CharacteristicWriteTypeBindingEnum) async throws {
        return try await withCheckedThrowingContinuation { continuation in
            writeLock.withLock {
                guard let peripheralUuid = UUID(uuidString: deviceAddress) else {
                    continuation.resume(throwing: BleErrorWrapper.Ble(error: BleError.InvalidUuid(uuid: deviceAddress)))
                    return
                }
                let service = CBUUID(string: serviceUuid)
                let characteristic = CBUUID(string: characteristicUuid)
                let characteristicKey = characteristicKey(peripheral: peripheralUuid, service: service, characteristic: characteristic)
                guard characteristicWriteResultCallbacks[characteristicKey] == nil, characteristicWriteWithoutResponseResultCallbacks[peripheralUuid] == nil, characteristicReadResultCallbacks[characteristicKey] == nil else {
                    continuation.resume(throwing: BleErrorWrapper.Ble(error: BleError.AnotherOperationInProgress))
                    return
                }
                let cbCharacteristic: CBCharacteristic
                let cbPeripheral: CBPeripheral
                do {
                    (cbCharacteristic, cbPeripheral) = try retrieveCharacteristic(peripheral: peripheralUuid, service: service, characteristic: characteristic)
                } catch let error {
                    continuation.resume(throwing: error)
                    return
                }
                
                let delayedWrite = writeType == .withoutResponse && !cbPeripheral.canSendWriteWithoutResponse
                if (!delayedWrite) {
                    cbPeripheral.writeValue(data, for: cbCharacteristic, type: writeType.cbCharacteristicWriteType)
                    if (writeType == .withoutResponse) {
                        continuation.resume(with: Result.success(()))
                        return
                    }
                }
                
                if (delayedWrite) {
                    characteristicWriteWithoutResponseResultCallbacks[peripheralUuid] = { [weak self] result in
                        self?.characteristicWriteWithoutResponseResultCallbacks[peripheralUuid] = nil
                        switch (result) {
                        case .success:
                            cbPeripheral.writeValue(data, for: cbCharacteristic, type: writeType.cbCharacteristicWriteType)
                            break
                        default:
                            break
                        }
                        continuation.resume(with: result)
                    }
                } else {
                    characteristicWriteResultCallbacks[characteristicKey] = { [weak self] result in
                        self?.characteristicWriteResultCallbacks[characteristicKey] = nil
                        continuation.resume(with: result)
                    }
                }
            }
        }
    }
    
    func readData(deviceAddress: String, serviceUuid: String, characteristicUuid: String) async throws -> Data {
        guard let peripheralUuid = UUID(uuidString: deviceAddress) else {
            throw BleErrorWrapper.Ble(error: BleError.InvalidUuid(uuid: deviceAddress))
        }
        let service = CBUUID(string: serviceUuid)
        let characteristic = CBUUID(string: characteristicUuid)
        let characteristicKey = characteristicKey(peripheral: peripheralUuid, service: service, characteristic: characteristic)
        guard characteristicWriteResultCallbacks[characteristicKey] == nil, characteristicWriteWithoutResponseResultCallbacks[peripheralUuid] == nil, characteristicReadResultCallbacks[characteristicKey] == nil else {
            throw BleErrorWrapper.Ble(error: BleError.AnotherOperationInProgress)
        }
        guard !subscribedCharacteristics.contains(characteristicKey) else {
            throw BleErrorWrapper.Ble(error: BleError.InvalidCharacteristicOperation(service: serviceUuid,
                                                                                     characteristic: characteristicUuid,
                                                                                     operation: "read"))
        }
        let (cbCharacteristic, cbPeripheral) = try retrieveCharacteristic(peripheral: peripheralUuid, service: service, characteristic: characteristic)
        cbPeripheral.readValue(for: cbCharacteristic)
        return try await withCheckedThrowingContinuation { continuation in
            characteristicReadResultCallbacks[characteristicKey] = { [weak self] result in
                self?.characteristicReadResultCallbacks[characteristicKey] = nil
                continuation.resume(with: result)
            }
        }
    }
    
    func subscribeToCharacteristicNotifications(peripheral: String, service: String, characteristic: String) async throws {
        guard let peripheralUuid = UUID(uuidString: peripheral) else {
            throw BleErrorWrapper.Ble(error: BleError.InvalidUuid(uuid: peripheral))
        }
        let serviceUuid = CBUUID(string: service)
        let characteristicUuid = CBUUID(string: characteristic)
        let characteristicKey = characteristicKey(peripheral: peripheralUuid, service: serviceUuid, characteristic: characteristicUuid)
        guard characteristicReadResultCallbacks[characteristicKey] == nil &&
                unsubscribeFromCharacteristicNotificationsResultCallbacks[characteristicKey] == nil &&
                !subscribedCharacteristics.contains(characteristicKey) else {
            throw BleErrorWrapper.Ble(error: BleError.InvalidCharacteristicOperation(service: service,
                                                                                     characteristic: characteristic,
                                                                                     operation: "subscribe"))
        }
        let (cbCharacteristic, cbPeripheral) = try retrieveCharacteristic(peripheral: peripheralUuid, service: serviceUuid, characteristic: characteristicUuid)
        subscribedCharacteristics.insert(characteristicKey)
        cbPeripheral.setNotifyValue(true, for: cbCharacteristic)
        return try await withCheckedThrowingContinuation { continuation in
            subscribeToCharacteristicNotificationsResultCallbacks[characteristicKey] = { [weak self] result in
                self?.subscribeToCharacteristicNotificationsResultCallbacks[characteristicKey] = nil
                continuation.resume(with: result)
            }
        }
    }
    
    func unsubscribeFromCharacteristicNotifications(peripheral: String, service: String, characteristic: String) async throws {
        guard let peripheralUuid = UUID(uuidString: peripheral) else {
            throw BleErrorWrapper.Ble(error: BleError.InvalidUuid(uuid: peripheral))
        }
        let serviceUuid = CBUUID(string: service)
        let characteristicUuid = CBUUID(string: characteristic)
        let characteristicKey = characteristicKey(peripheral: peripheralUuid, service: serviceUuid, characteristic: characteristicUuid)
        guard subscribedCharacteristics.contains(characteristicKey) &&
                subscribeToCharacteristicNotificationsResultCallbacks[characteristicKey] == nil else {
            throw BleErrorWrapper.Ble(error: BleError.InvalidCharacteristicOperation(service: service,
                                                                                     characteristic: characteristic,
                                                                                     operation: "unsubscribe"))
        }
        let (cbCharacteristic, cbPeripheral) = try retrieveCharacteristic(peripheral: peripheralUuid, service: serviceUuid, characteristic: characteristicUuid)
        subscribedCharacteristics.remove(characteristicKey)
        cbPeripheral.setNotifyValue(false, for: cbCharacteristic)
        return try await withCheckedThrowingContinuation { continuation in
            unsubscribeFromCharacteristicNotificationsResultCallbacks[characteristicKey] = { [weak self] result in
                self?.unsubscribeFromCharacteristicNotificationsResultCallbacks[characteristicKey] = nil
                continuation.resume(with: result)
            }
        }
    }
    
    @discardableResult
    
    func getNotifications(peripheral: String, service: String, characteristic: String) async throws -> [Data] {
        guard let peripheralUuid = UUID(uuidString: peripheral) else {
            throw BleErrorWrapper.Ble(error: BleError.InvalidUuid(uuid: peripheral))
        }
        let serviceUuid = CBUUID(string: service)
        let characteristicUuid = CBUUID(string: characteristic)
        let characteristicKey = characteristicKey(peripheral: peripheralUuid, service: serviceUuid, characteristic: characteristicUuid)
        return try await withCheckedThrowingContinuation { continuation in
            notificationsLock.withLock {
                if let notificationsData = notificationsQueues[characteristicKey], !notificationsData.isEmpty {
                    notificationsQueues[characteristicKey] = nil
                    continuation.resume(with: Result.success(notificationsData))
                    return
                }
                getNotificationsCallbacks[characteristicKey] = { [weak self] result in
                    self?.getNotificationsCallbacks[characteristicKey] = nil
                    continuation.resume(with: result)
                }
            }
        }
    }
}

// MARK: - Connect helpers

private extension IOSBLECentral {
    
    private func connectWithoutDiscovery(peripheral: UUID) async throws {
        guard peripheralConnectResultCallback == nil else {
            throw BleErrorWrapper.Ble(error: BleError.Unknown(reason: "Already connecting"))
        }
        let cbPeripheral = try retrievePeripheral(peripheral: peripheral, connected: false)
        centralManager.connect(cbPeripheral)
        return try await withCheckedThrowingContinuation { continuation in
            peripheralConnectResultCallback = { [weak self] result in
                self?.peripheralConnectResultCallback = nil
                continuation.resume(with: result)
            }
        }
    }
    
    private func discoverServices(peripheral: UUID, services: [CBUUID]?) async throws -> [ServiceDescriptionBindingDto] {
        let cbPeripheral: CBPeripheral
        if let services = services, !services.isEmpty {
            cbPeripheral = try retrieveConnectedPeripheral(peripheral: peripheral, services: services)
        } else {
            cbPeripheral = try retrievePeripheral(peripheral: peripheral)
        }
        cbPeripheral.discoverServices(services)
        return try await withCheckedThrowingContinuation { continuation in
            discoverServicesResultCallback = { [weak self] result in
                self?.discoverServicesResultCallback = nil
                continuation.resume(with: result)
            }
        }
    }
    
    private func getMtu(peripheral: UUID) throws -> UInt16 {
        let cbPeripheral = try retrievePeripheral(peripheral: peripheral)
        // for safety select the smaller MTU
        let mtuWithResponse = cbPeripheral.maximumWriteValueLength(for: .withResponse)
        let mtuWithoutResponse = cbPeripheral.maximumWriteValueLength(for: .withoutResponse)
        let mtu = min(mtuWithResponse, mtuWithoutResponse)
        return UInt16(mtu)
    }
    
    @MainActor
    private func discoverCharacteristics(peripheral: UUID, service: CBUUID, characteristics: [CBUUID]?) async throws -> ServiceDescriptionBindingDto {
        let (cbService, cbPeripheral) = try retrieveService(peripheral: peripheral, service: service)
        cbPeripheral.discoverCharacteristics(characteristics, for: cbService)
        return try await withCheckedThrowingContinuation { continuation in
            discoverCharacteristicsResultCallbacks[service] = { [weak self] result in
                continuation.resume(with: result)
                self?.discoverCharacteristicsResultCallbacks[service] = nil
            }
        }
    }
}

// MARK: - Common helpers

private extension IOSBLECentral {
    
    func retrievePeripheral(peripheral: UUID, connected: Bool = true) throws -> CBPeripheral {
        let peripherals = centralManager.retrievePeripherals(withIdentifiers: [peripheral])
        guard let cbPeripheral = peripherals.first else {
            throw BleErrorWrapper.Ble(error: BleError.DeviceAddressNotFound(address: peripheral.uuidString))
        }
        guard cbPeripheral.state == .connected || !connected else {
            throw BleErrorWrapper.Ble(error: BleError.DeviceNotConnected(address: peripheral.uuidString))
        }
        return cbPeripheral
    }
    
    func retrieveConnectedPeripheral(peripheral: UUID, services: [CBUUID]?) throws -> CBPeripheral {
        let peripherals = centralManager.retrieveConnectedPeripherals(withServices: services ?? [])
        guard let cbPeripheral = peripherals.first(where: { $0.identifier == peripheral }) else {
            throw BleErrorWrapper.Ble(error: BleError.DeviceAddressNotFound(address: peripheral.uuidString))
        }
        return cbPeripheral
    }
    
    func retrieveService(peripheral: UUID, service: CBUUID) throws -> (CBService, CBPeripheral) {
        let cbPeripheral = try retrieveConnectedPeripheral(peripheral: peripheral, services: [service])
        guard let cbService = cbPeripheral.services?.first(where: { $0.uuid == service }) else {
            throw BleErrorWrapper.Ble(error: BleError.ServiceNotFound(service: service.uuidString))
        }
        return (cbService, cbPeripheral)
    }
    
    func retrieveCharacteristic(peripheral: UUID, service: CBUUID, characteristic: CBUUID) throws -> (CBCharacteristic, CBPeripheral) {
        let (cbService, cbPeripheral) = try retrieveService(peripheral: peripheral, service: service)
        guard let cbCharacteristic = cbService.characteristics?.first(where: { $0.uuid == characteristic }) else {
            throw BleErrorWrapper.Ble(error: BleError.CharacteristicNotFound(characteristic: characteristic.uuidString))
        }
        return (cbCharacteristic, cbPeripheral)
    }
    
    private func characteristicKey(peripheral: UUID, service: CBUUID, characteristic: CBUUID) -> CharacteristicKey {
        return CharacteristicKey(deviceAddress: peripheral, serviceUUID: service, characteristicUUID: characteristic)
    }
    
    private func characteristicKey(peripheral: CBPeripheral, characteristic: CBCharacteristic) -> CharacteristicKey? {
        guard let serviceUUID = characteristic.service?.uuid else {
            return nil
        }
        let deviceAddress = peripheral.identifier
        let characteristicUUID = characteristic.uuid
        let characteristicKey = CharacteristicKey(deviceAddress: deviceAddress, serviceUUID: serviceUUID, characteristicUUID: characteristicUUID)
        return characteristicKey
    }
    
    func getResult<T>(value: T?, error: Error?) -> Result<T, Error> {
        let result: Result<T, Error>
        if let error = error {
            result = Result.failure(error)
        } else if let value = value {
            result = Result.success(value)
        } else {
            result = Result.failure(BleErrorWrapper.Ble(error: BleError.Unknown(reason: error?.localizedDescription ?? "Unknown")))
        }
        return result
    }
}

// MARK: - CBCentralManagerDelegate methods

extension IOSBLECentral: CBCentralManagerDelegate {
    
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
#if DEBUG
        print("central manager did update state \(central.state)")
#endif
        adapterStateCallback?(Result.success(central.state))
    }
    
    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String : Any], rssi RSSI: NSNumber) {
        deviceDiscoveryLock.withLock {
            let uuids = (advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID])?.map { $0.uuidString } ?? []
            let peripheral = PeripheralDiscoveryDataBindingDto(deviceAddress: peripheral.identifier.uuidString,
                                                               localDeviceName: advertisementData[CBAdvertisementDataLocalNameKey] as? String,
                                                               advertisedServices: uuids,
                                                               advertisedServiceData: advertisementData[CBAdvertisementDataServiceDataKey] as? [String: Data])
            guard let callback = getDiscoveredDevicesCallback else {
                discoveredPeripheralsQueue.append(peripheral)
                return
            }
            callback(Result.success([peripheral]))
        }
    }
    
    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
#if DEBUG
        print("connected to \(peripheral.name ?? "unnamed") \(peripheral.identifier)")
#endif
        peripheral.delegate = self
        connectedPeripherals.insert(peripheral)
        peripheralConnectResultCallback?(Result.success(()))
    }
    
    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: (any Error)?) {
#if DEBUG
        print("failed to connect to \(peripheral.name ?? "unnamed") \(peripheral.identifier)")
#endif
        peripheralConnectResultCallback?(Result.failure(BleErrorWrapper.Ble(error: BleError.Unknown(reason: error?.localizedDescription ?? "Unknown"))))
    }
    
    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: (any Error)?) {
#if DEBUG
        print("disconnected from \(peripheral.name ?? "unnamed") \(peripheral.identifier)")
#endif
        deviceDisconnectLock.withLock {
            cleanupAwaitingCallbacks(peripheral: peripheral)
            peripheralDisconnectResultCallback?(Result.success(()))
            connectedPeripherals.remove(peripheral)
        }
    }
    
    private func cleanupAwaitingCallbacks(peripheral: CBPeripheral) {
        let error = BleErrorWrapper.Ble(error: BleError.DeviceNotConnected(address: peripheral.identifier.uuidString))
        
        if let keys = getKeys(characteristicWriteResultCallbacks.keys, for: peripheral) {
            keys.forEach { key in
                if let callback = characteristicWriteResultCallbacks[key] {
                    characteristicWriteResultCallbacks[key] = nil
                    callback(Result.failure(error))
                }
            }
        }
        
        if let writeWithoutResponse = characteristicWriteWithoutResponseResultCallbacks[peripheral.identifier] {
            writeWithoutResponse(Result.failure(error))
        }
        
        if let keys = getKeys(characteristicReadResultCallbacks.keys, for: peripheral) {
            keys.forEach { key in
                if let callback = characteristicReadResultCallbacks[key] {
                    characteristicReadResultCallbacks[key] = nil
                    callback(Result.failure(error))
                }
            }
        }
        
        if let keys = getKeys(subscribeToCharacteristicNotificationsResultCallbacks.keys, for: peripheral) {
            keys.forEach { key in
                if let callback = subscribeToCharacteristicNotificationsResultCallbacks[key] {
                    subscribeToCharacteristicNotificationsResultCallbacks[key] = nil
                    callback(Result.failure(error))
                }
            }
        }
        
        if let keys = getKeys(unsubscribeFromCharacteristicNotificationsResultCallbacks.keys, for: peripheral) {
            keys.forEach { key in
                if let callback = unsubscribeFromCharacteristicNotificationsResultCallbacks[key] {
                    unsubscribeFromCharacteristicNotificationsResultCallbacks[key] = nil
                    callback(Result.failure(error))
                }
            }
        }
        
        notificationsLock.withLock {
            if let keys = getKeys(getNotificationsCallbacks.keys, for: peripheral) {
                keys.forEach { key in
                    if let callback = getNotificationsCallbacks[key] {
                        getNotificationsCallbacks[key] = nil
                        callback(Result.failure(error))
                    }
                }
            }
        }
        
        subscribedCharacteristics.filter { $0.deviceAddress == peripheral.identifier }.forEach { characteristicKey in
            subscribedCharacteristics.remove(characteristicKey)
        }
    }
    
    private func getKeys<T>(_ keys: Dictionary<CharacteristicKey, T>.Keys, for peripheral: CBPeripheral) -> [CharacteristicKey]? {
        let deviceKey = peripheral.identifier
        let result = keys.filter({ $0.deviceAddress == deviceKey })
        guard !result.isEmpty else {
            return nil
        }
        return result
    }
}

// MARK: - CBPeripheralDelegate methods

extension IOSBLECentral: CBPeripheralDelegate {
    
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: (any Error)?) {
        let result = getResult(value: peripheral.servicesDescriptions, error: error)
        discoverServicesResultCallback?(result)
        let deviceAddress: UUID = peripheral.identifier
        let services: [ServiceDescriptionBindingDto] = peripheral.servicesDescriptions
#if DEBUG
        print("discovered services of \(peripheral.name ?? "") \(deviceAddress)")
        print(services)
#endif
    }
    
    func peripheral(_ peripheral: CBPeripheral, didModifyServices invalidatedServices: [CBService]) {
#if DEBUG
        print("peripheral \(peripheral.identifier) did modify services: \(invalidatedServices)")
#endif
    }
    
    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: (any Error)?) {
        let result = getResult(value: service.servicesDescription, error: error)
        discoverCharacteristicsResultCallbacks[service.uuid]?(result)
#if DEBUG
        let deviceAddress: UUID = peripheral.identifier
        let characteristics = service.characteristics
        print("discovered characteristics of \(peripheral.name ?? "") \(deviceAddress) \(service)")
        print("\(characteristics?.description ?? "[]")")
#endif
    }
    
    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: (any Error)?) {
        writeLock.withLock {
            guard let characteristicKey = characteristicKey(peripheral: peripheral, characteristic: characteristic) else {
                return
            }
            let result = getResult(value: (), error: error)
            characteristicWriteResultCallbacks[characteristicKey]?(result)
#if DEBUG
            print("did write value for \(characteristic): \(String(describing: characteristic.value))")
#endif
        }
    }
    
    func peripheralIsReady(toSendWriteWithoutResponse peripheral: CBPeripheral) {
        writeLock.withLock {
#if DEBUG
            print("peripheralIsReady")
#endif
            let result = getResult(value: (), error: nil)
            characteristicWriteWithoutResponseResultCallbacks[peripheral.identifier]?(result)
        }
    }
    
    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: (any Error)?) {
        guard let characteristicKey = characteristicKey(peripheral: peripheral, characteristic: characteristic) else {
            return
        }
        let value = characteristic.value ?? Data()
        handleSubscribedCharacteristicNotification(key: characteristicKey,
                                                   data: value,
                                                   error: error)
        let result = getResult(value: value, error: error)
        handleCharacteristicReadResult(key: characteristicKey,
                                       result: result)
#if DEBUG
        print("did update value for \(characteristic): \(String(describing: characteristic.value))")
#endif
    }
    
    private func handleSubscribedCharacteristicNotification(key characteristicKey: CharacteristicKey, data: Data, error: (any Error)?) {
        notificationsLock.withLock {
            if (subscribedCharacteristics.contains(characteristicKey)) {
                if let callback = getNotificationsCallbacks[characteristicKey] {
                    callback(getResult(value: [data], error: error))
                } else {
                    if notificationsQueues[characteristicKey] == nil {
                        notificationsQueues[characteristicKey] = []
                    }
                    notificationsQueues[characteristicKey]?.append(data)
                }
            }
        }
    }
    
    private func handleCharacteristicReadResult(key characteristicKey: CharacteristicKey, result: Result<Data, Error>) {
        if let callback = characteristicReadResultCallbacks[characteristicKey] {
            callback(result)
        }
    }
    
    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: (any Error)?) {
#if DEBUG
        print("update notification state for \(characteristic): \(String(describing: characteristic.value)) (error: \(String(describing: error)))")
#endif
        guard let characteristicKey = characteristicKey(peripheral: peripheral, characteristic: characteristic) else {
            return
        }
        let result = getResult(value: (), error: error)
        if let callback = subscribeToCharacteristicNotificationsResultCallbacks[characteristicKey] {
            callback(result)
        } else if let callback = unsubscribeFromCharacteristicNotificationsResultCallbacks[characteristicKey] {
            callback(result)
        }
    }
}
