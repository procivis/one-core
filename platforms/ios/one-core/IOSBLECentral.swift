import CoreBluetooth

public class IOSBLECentral: NSObject {
    
    private var _centralManager: CBCentralManager?
    private var centralManager: CBCentralManager {
        get {
            if _centralManager == nil {
                _centralManager = CBCentralManager(delegate: self, queue: nil)
            }
            return _centralManager!
        }
    }
    
    private var discoverServicesResultCallback: BLEThrowingResultCallback<[ServiceDescriptionBindingDto]>?
    private var discoverCharacteristicsResultCallbacks: [CBUUID: BLEThrowingResultCallback<ServiceDescriptionBindingDto>] = [:]
    
    private let adapterStateLock = NSLock()
    private var adapterStateCallback: BLEResultCallback<CBManagerState>?
    
    private let deviceDiscoveryLock = NSLock()
    private var getDiscoveredDevicesCallback: BLEThrowingResultCallback<[PeripheralDiscoveryDataBindingDto]>?
    private var discoveredPeripheralsQueue: [PeripheralDiscoveryDataBindingDto] = []
    
    private let deviceConnectionLock = NSLock()
    private var peripheralConnectResultCallback: BLEThrowingResultCallback<Void>?
    private var peripheralDisconnectResultCallback: BLEThrowingResultCallback<Void>?
    private var connectedPeripherals: Set<CBPeripheral> = []
    
    private let writeLock = NSLock()
    private var characteristicWriteResultCallbacks: [CharacteristicKey: BLEThrowingResultCallback<Void>] = [:]
    private var characteristicWriteWithoutResponseResultCallbacks: [CharacteristicKey: BLEThrowingResultCallback<Void>] = [:]
    
    private let readLock = NSLock()
    private var characteristicReadResultCallbacks: [CharacteristicKey: BLEThrowingResultCallback<Data>] = [:]
    
    private let notificationsLock = NSLock()
    private var getNotificationsCallbacks: [CharacteristicKey: BLEThrowingResultCallback<[Data]>] = [:]
    private var notificationsQueues: [CharacteristicKey: [Data]] = [:]
    private var subscribeToCharacteristicNotificationsResultCallbacks: [CharacteristicKey: BLEThrowingResultCallback<Void>] = [:]
    private var unsubscribeFromCharacteristicNotificationsResultCallbacks: [CharacteristicKey: BLEThrowingResultCallback<Void>] = [:]
    private var subscribedCharacteristics = Set<CharacteristicKey>()
}

// MARK: - BLECentral interface implementation

extension IOSBLECentral: BleCentral {
    
    public func isAdapterEnabled() async throws -> Bool {
        return await withCheckedContinuation { continuation in
            adapterStateLock.withLock {
                let state = centralManager.state
                if (state == .unknown) {
                    adapterStateCallback = { [weak self] result in
                        self?.adapterStateCallback = nil
                        if case .success(let updatedState) = result {
#if DEBUG
                            print("centralManager updatedState \(updatedState)")
#endif
                            continuation.resume(returning: updatedState == .poweredOn)
                        }
                    }
                } else {
#if DEBUG
                    print("centralManager state \(state)")
#endif
                    continuation.resume(returning: state == .poweredOn)
                }
            }
        }
    }
    
    public func startScan(filterServices: [String]?) async throws {
#if DEBUG
        print("startScan: \(filterServices)")
#endif
        guard try await isAdapterEnabled() else {
            throw BleError.AdapterNotEnabled
        }
        guard !centralManager.isScanning else {
            throw BleError.ScanAlreadyStarted
        }
        discoveredPeripheralsQueue = []
        centralManager.scanForPeripherals(withServices: filterServices?.map { CBUUID(string: $0) })
    }
    
    public func stopScan() async throws {
#if DEBUG
        print("stopScan")
#endif
        guard centralManager.isScanning else {
            return
        }
        centralManager.stopScan()
        
        deviceDiscoveryLock.withLock {
            getDiscoveredDevicesCallback?(Result.failure(BleError.ScanNotStarted))
        }
    }
    
    public func isScanning() async throws -> Bool {
        guard let manager = _centralManager else {
            return false
        }
        return manager.isScanning
    }
    
    public func connect(peripheral: String) async throws -> UInt16 {
#if DEBUG
        print("connect: \(peripheral)")
#endif
        guard let peripheralUuid = UUID(uuidString: peripheral) else {
            throw BleError.InvalidUuid(uuid: peripheral)
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
    
    public func disconnect(peripheral: String) async throws {
#if DEBUG
        print("disconnect: \(peripheral)")
#endif
        guard let peripheralUuid = UUID(uuidString: peripheral) else {
            throw BleError.InvalidUuid(uuid: peripheral)
        }
        let cbPeripheral = try retrievePeripheral(peripheral: peripheralUuid)
        return try await withCheckedThrowingContinuation { continuation in
            deviceConnectionLock.withLock {
                centralManager.cancelPeripheralConnection(cbPeripheral)
                peripheralDisconnectResultCallback = { [weak self] result in
                    self?.peripheralDisconnectResultCallback = nil
                    continuation.resume(with: result)
                }
            }
        }
    }
    
    public func getDiscoveredDevices() async throws -> [PeripheralDiscoveryDataBindingDto] {
        return try await withCheckedThrowingContinuation { continuation in
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
    
    public func writeData(peripheral: String, service: String, characteristic: String, data: Data, writeType: CharacteristicWriteTypeBindingEnum) async throws {
#if DEBUG
        print("writeData: \(peripheral), characteristic: \(characteristic)")
#endif
        guard let peripheralUuid = UUID(uuidString: peripheral) else {
            throw BleError.InvalidUuid(uuid: peripheral)
        }
        
        let service = CBUUID(string: service)
        let characteristic = CBUUID(string: characteristic)
        let characteristicKey = characteristicKey(peripheral: peripheralUuid, service: service, characteristic: characteristic)
        return try await withCheckedThrowingContinuation { continuation in
            writeLock.withLock {
                guard characteristicWriteResultCallbacks[characteristicKey] == nil, characteristicWriteWithoutResponseResultCallbacks[characteristicKey] == nil else {
                    continuation.resume(throwing: BleError.AnotherOperationInProgress)
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
                    characteristicWriteWithoutResponseResultCallbacks[characteristicKey] = { [weak self] result in
                        self?.characteristicWriteWithoutResponseResultCallbacks[characteristicKey] = nil
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
    
    public func readData(peripheral: String, service: String, characteristic: String) async throws -> Data {
#if DEBUG
        print("readData: \(peripheral), characteristic: \(characteristic)")
#endif
        guard let peripheralUuid = UUID(uuidString: peripheral) else {
            throw BleError.InvalidUuid(uuid: peripheral)
        }
        let service = CBUUID(string: service)
        let characteristic = CBUUID(string: characteristic)
        let characteristicKey = characteristicKey(peripheral: peripheralUuid, service: service, characteristic: characteristic)
        try notificationsLock.withLock {
            guard !subscribedCharacteristics.contains(characteristicKey) else {
                throw BleError.InvalidCharacteristicOperation(service: service.uuidString,
                                                              characteristic: characteristic.uuidString,
                                                              operation: "read")
            }
        }
        let (cbCharacteristic, cbPeripheral) = try retrieveCharacteristic(peripheral: peripheralUuid, service: service, characteristic: characteristic)
        return try await withCheckedThrowingContinuation { continuation in
            readLock.withLock {
                guard characteristicReadResultCallbacks[characteristicKey] == nil else {
                    continuation.resume(throwing: BleError.AnotherOperationInProgress)
                    return
                }
                cbPeripheral.readValue(for: cbCharacteristic)
                characteristicReadResultCallbacks[characteristicKey] = { [weak self] result in
                    self?.characteristicReadResultCallbacks[characteristicKey] = nil
                    continuation.resume(with: result)
                }
            }
        }
    }
    
    public func subscribeToCharacteristicNotifications(peripheral: String, service: String, characteristic: String) async throws {
#if DEBUG
        print("subscribeToCharacteristicNotifications: \(peripheral), characteristic: \(characteristic)")
#endif
        guard let peripheralUuid = UUID(uuidString: peripheral) else {
            throw BleError.InvalidUuid(uuid: peripheral)
        }
        let serviceUuid = CBUUID(string: service)
        let characteristicUuid = CBUUID(string: characteristic)
        let characteristicKey = characteristicKey(peripheral: peripheralUuid, service: serviceUuid, characteristic: characteristicUuid)
        try readLock.withLock {
            guard characteristicReadResultCallbacks[characteristicKey] == nil else {
                throw BleError.AnotherOperationInProgress
            }
        }
        let (cbCharacteristic, cbPeripheral) = try retrieveCharacteristic(peripheral: peripheralUuid, service: serviceUuid, characteristic: characteristicUuid)
        return try await withCheckedThrowingContinuation { continuation in
            notificationsLock.withLock {
                guard unsubscribeFromCharacteristicNotificationsResultCallbacks[characteristicKey] == nil &&
                        !subscribedCharacteristics.contains(characteristicKey) else {
                    continuation.resume(throwing: BleError.InvalidCharacteristicOperation(service: service,
                                                                                          characteristic: characteristic,
                                                                                          operation: "subscribe"))
                    return
                }
                subscribedCharacteristics.insert(characteristicKey)
                cbPeripheral.setNotifyValue(true, for: cbCharacteristic)
                subscribeToCharacteristicNotificationsResultCallbacks[characteristicKey] = { [weak self] result in
                    self?.subscribeToCharacteristicNotificationsResultCallbacks[characteristicKey] = nil
                    continuation.resume(with: result)
                }
            }
        }
    }
    
    public func unsubscribeFromCharacteristicNotifications(peripheral: String, service: String, characteristic: String) async throws {
#if DEBUG
        print("unsubscribeFromCharacteristicNotifications: \(peripheral), characteristic: \(characteristic)")
#endif
        guard let peripheralUuid = UUID(uuidString: peripheral) else {
            throw BleError.InvalidUuid(uuid: peripheral)
        }
        let serviceUuid = CBUUID(string: service)
        let characteristicUuid = CBUUID(string: characteristic)
        let characteristicKey = characteristicKey(peripheral: peripheralUuid, service: serviceUuid, characteristic: characteristicUuid)
        let (cbCharacteristic, cbPeripheral) = try retrieveCharacteristic(peripheral: peripheralUuid, service: serviceUuid, characteristic: characteristicUuid)
        return try await withCheckedThrowingContinuation { continuation in
            notificationsLock.withLock {
                guard subscribedCharacteristics.contains(characteristicKey) &&
                        subscribeToCharacteristicNotificationsResultCallbacks[characteristicKey] == nil else {
                    continuation.resume(throwing: BleError.InvalidCharacteristicOperation(service: service,
                                                                                          characteristic: characteristic,
                                                                                          operation: "unsubscribe"))
                    return
                }
                subscribedCharacteristics.remove(characteristicKey)
                cbPeripheral.setNotifyValue(false, for: cbCharacteristic)
                unsubscribeFromCharacteristicNotificationsResultCallbacks[characteristicKey] = { [weak self] result in
                    self?.unsubscribeFromCharacteristicNotificationsResultCallbacks[characteristicKey] = nil
                    continuation.resume(with: result)
                }
            }
        }
    }
    
    @discardableResult
    
    public func getNotifications(peripheral: String, service: String, characteristic: String) async throws -> [Data] {
        guard let peripheralUuid = UUID(uuidString: peripheral) else {
            throw BleError.InvalidUuid(uuid: peripheral)
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
        let cbPeripheral = try retrievePeripheral(peripheral: peripheral, connected: false)
        return try await withCheckedThrowingContinuation { continuation in
            deviceConnectionLock.withLock {
                guard peripheralConnectResultCallback == nil else {
                    continuation.resume(throwing: BleError.Unknown(reason: "Already connecting"))
                    return
                }
                centralManager.connect(cbPeripheral)
                peripheralConnectResultCallback = { [weak self] result in
                    self?.peripheralConnectResultCallback = nil
                    continuation.resume(with: result)
                }
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
        return try await withCheckedThrowingContinuation { continuation in
            discoverServicesResultCallback = { [weak self] result in
                self?.discoverServicesResultCallback = nil
                continuation.resume(with: result)
            }
            cbPeripheral.discoverServices(services)
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
        return try await withCheckedThrowingContinuation { continuation in
            discoverCharacteristicsResultCallbacks[service] = { [weak self] result in
                continuation.resume(with: result)
                self?.discoverCharacteristicsResultCallbacks[service] = nil
            }
            cbPeripheral.discoverCharacteristics(characteristics, for: cbService)
        }
    }
}

// MARK: - Common helpers

private extension IOSBLECentral {
    
    func retrievePeripheral(peripheral: UUID, connected: Bool = true) throws -> CBPeripheral {
        let peripherals = centralManager.retrievePeripherals(withIdentifiers: [peripheral])
        guard let cbPeripheral = peripherals.first else {
            throw BleError.DeviceAddressNotFound(address: peripheral.uuidString)
        }
        guard cbPeripheral.state == .connected || !connected else {
            throw BleError.DeviceNotConnected(address: peripheral.uuidString)
        }
        return cbPeripheral
    }
    
    func retrieveConnectedPeripheral(peripheral: UUID, services: [CBUUID]?) throws -> CBPeripheral {
        let peripherals = centralManager.retrieveConnectedPeripherals(withServices: services ?? [])
        guard let cbPeripheral = peripherals.first(where: { $0.identifier == peripheral }) else {
            throw BleError.DeviceAddressNotFound(address: peripheral.uuidString)
        }
        return cbPeripheral
    }
    
    func retrieveService(peripheral: UUID, service: CBUUID) throws -> (CBService, CBPeripheral) {
        let cbPeripheral = try retrieveConnectedPeripheral(peripheral: peripheral, services: [service])
        guard let cbService = cbPeripheral.services?.first(where: { $0.uuid == service }) else {
            throw BleError.ServiceNotFound(service: service.uuidString)
        }
        return (cbService, cbPeripheral)
    }
    
    func retrieveCharacteristic(peripheral: UUID, service: CBUUID, characteristic: CBUUID) throws -> (CBCharacteristic, CBPeripheral) {
        let (cbService, cbPeripheral) = try retrieveService(peripheral: peripheral, service: service)
        guard let cbCharacteristic = cbService.characteristics?.first(where: { $0.uuid == characteristic }) else {
            throw BleError.CharacteristicNotFound(characteristic: characteristic.uuidString)
        }
        return (cbCharacteristic, cbPeripheral)
    }
}

// MARK: - static helper functions

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

private func getResult<T>(value: T?, error: Error?) -> Result<T, Error> {
    let result: Result<T, Error>
    if let error = error {
        result = Result.failure(error)
    } else if let value = value {
        result = Result.success(value)
    } else {
        result = Result.failure(BleError.Unknown(reason: error?.localizedDescription ?? "Unknown"))
    }
    return result
}

private func getKeys<T>(_ keys: Dictionary<CharacteristicKey, T>.Keys, for peripheral: CBPeripheral, service: CBUUID?) -> [CharacteristicKey]? {
    let deviceKey = peripheral.identifier
    let result = keys.filter({ $0.deviceAddress == deviceKey && (service == nil || $0.serviceUUID == service) })
    guard !result.isEmpty else {
        return nil
    }
    return result
}

// MARK: - CBCentralManagerDelegate methods

extension IOSBLECentral: CBCentralManagerDelegate {
    
    public func centralManagerDidUpdateState(_ central: CBCentralManager) {
#if DEBUG
        print("central manager did update state \(central.state)")
#endif
        adapterStateLock.withLock {
            adapterStateCallback?(Result.success(central.state))
        }
    }
    
    public func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String : Any], rssi RSSI: NSNumber) {
#if DEBUG
        print("central manager did discover \(peripheral)")
#endif
        let uuids = (advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID])?.map { $0.uuidString } ?? []
        let peripheral = PeripheralDiscoveryDataBindingDto(deviceAddress: peripheral.identifier.uuidString,
                                                           localDeviceName: advertisementData[CBAdvertisementDataLocalNameKey] as? String,
                                                           advertisedServices: uuids,
                                                           advertisedServiceData: advertisementData[CBAdvertisementDataServiceDataKey] as? [String: Data])
        deviceDiscoveryLock.withLock {
            guard let callback = getDiscoveredDevicesCallback else {
                discoveredPeripheralsQueue.append(peripheral)
                return
            }
            callback(Result.success([peripheral]))
        }
    }
    
    public func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
#if DEBUG
        print("connected to \(peripheral.name ?? "unnamed") \(peripheral.identifier)")
#endif
        peripheral.delegate = self
        deviceConnectionLock.withLock {
            connectedPeripherals.insert(peripheral)
            peripheralConnectResultCallback?(Result.success(()))
        }
    }
    
    public func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: (any Error)?) {
#if DEBUG
        print("failed to connect to \(peripheral.name ?? "unnamed") \(peripheral.identifier)")
#endif
        deviceConnectionLock.withLock {
            peripheralConnectResultCallback?(Result.failure(BleError.Unknown(reason: error?.localizedDescription ?? "Unknown")))
        }
    }
    
    public func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: (any Error)?) {
#if DEBUG
        print("disconnected from \(peripheral.name ?? "unnamed") \(peripheral.identifier)")
#endif
        invalidateAwaitingCallbacks(peripheral: peripheral, service: nil)
        deviceConnectionLock.withLock {
            peripheralDisconnectResultCallback?(Result.success(()))
            connectedPeripherals.remove(peripheral)
            
            if connectedPeripherals.isEmpty && !central.isScanning {
                _centralManager = nil
            }
        }
    }
    
    private func invalidateAwaitingCallbacks(peripheral: CBPeripheral, service: CBUUID?) {
        let error = BleError.DeviceNotConnected(address: peripheral.identifier.uuidString)
        
        writeLock.withLock {
            if let keys = getKeys(characteristicWriteResultCallbacks.keys, for: peripheral, service: service) {
                keys.forEach { key in
                    if let callback = characteristicWriteResultCallbacks[key] {
                        characteristicWriteResultCallbacks[key] = nil
                        callback(Result.failure(error))
                    }
                }
            }
            
            if let keys = getKeys(characteristicWriteWithoutResponseResultCallbacks.keys, for: peripheral, service: service) {
                keys.forEach { key in
                    if let callback = characteristicWriteWithoutResponseResultCallbacks[key] {
                        characteristicWriteWithoutResponseResultCallbacks[key] = nil
                        callback(Result.failure(error))
                    }
                }
            }
        }
        
        readLock.withLock {
            if let keys = getKeys(characteristicReadResultCallbacks.keys, for: peripheral, service: service) {
                keys.forEach { key in
                    if let callback = characteristicReadResultCallbacks[key] {
                        characteristicReadResultCallbacks[key] = nil
                        callback(Result.failure(error))
                    }
                }
            }
        }
        
        notificationsLock.withLock {
            if let keys = getKeys(getNotificationsCallbacks.keys, for: peripheral, service: service) {
                keys.forEach { key in
                    if let callback = getNotificationsCallbacks[key] {
                        getNotificationsCallbacks[key] = nil
                        callback(Result.failure(error))
                    }
                }
            }
            
            
            if let keys = getKeys(subscribeToCharacteristicNotificationsResultCallbacks.keys, for: peripheral, service: service) {
                keys.forEach { key in
                    if let callback = subscribeToCharacteristicNotificationsResultCallbacks[key] {
                        subscribeToCharacteristicNotificationsResultCallbacks[key] = nil
                        callback(Result.failure(error))
                    }
                }
            }
            
            if let keys = getKeys(unsubscribeFromCharacteristicNotificationsResultCallbacks.keys, for: peripheral, service: service) {
                keys.forEach { key in
                    if let callback = unsubscribeFromCharacteristicNotificationsResultCallbacks[key] {
                        unsubscribeFromCharacteristicNotificationsResultCallbacks[key] = nil
                        callback(Result.failure(error))
                    }
                }
            }
            
            subscribedCharacteristics.filter { $0.deviceAddress == peripheral.identifier && (service == nil || $0.serviceUUID == service) }.forEach { characteristicKey in
                subscribedCharacteristics.remove(characteristicKey)
            }
        }
    }
}

// MARK: - CBPeripheralDelegate methods

extension IOSBLECentral: CBPeripheralDelegate {
    
    public func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: (any Error)?) {
        let result = getResult(value: peripheral.servicesDescriptions, error: error)
        discoverServicesResultCallback?(result)
#if DEBUG
        let deviceAddress: UUID = peripheral.identifier
        print("discovered services of \(peripheral.name ?? "") \(deviceAddress)")
        let services: [ServiceDescriptionBindingDto] = peripheral.servicesDescriptions
        print(services)
#endif
    }
    
    public func peripheral(_ peripheral: CBPeripheral, didModifyServices invalidatedServices: [CBService]) {
        // This is signaled if the peripheral server stops
#if DEBUG
        print("peripheral \(peripheral.identifier) did modify services: \(invalidatedServices)")
#endif
        invalidatedServices.forEach { service in
            invalidateAwaitingCallbacks(peripheral: peripheral, service: service.uuid)
        }
    }
    
    public func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: (any Error)?) {
        let result = getResult(value: service.servicesDescription, error: error)
        discoverCharacteristicsResultCallbacks[service.uuid]?(result)
#if DEBUG
        let deviceAddress: UUID = peripheral.identifier
        let characteristics = service.characteristics
        print("discovered characteristics of \(peripheral.name ?? "") \(deviceAddress) \(service)")
        print("\(characteristics?.description ?? "[]")")
#endif
    }
    
    public func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: (any Error)?) {
        guard let characteristicKey = characteristicKey(peripheral: peripheral, characteristic: characteristic) else {
            return
        }
        let result = getResult(value: (), error: error)
        writeLock.withLock {
            characteristicWriteResultCallbacks[characteristicKey]?(result)
#if DEBUG
            print("did write value for \(characteristic): \(String(describing: characteristic.value))")
#endif
        }
    }
    
    public func peripheralIsReady(toSendWriteWithoutResponse peripheral: CBPeripheral) {
#if DEBUG
        print("peripheralIsReady")
#endif
        let result = getResult(value: (), error: nil)
        writeLock.withLock {
            if let keys = getKeys(characteristicWriteWithoutResponseResultCallbacks.keys, for: peripheral, service: nil) {
                keys.forEach { key in
                    characteristicWriteWithoutResponseResultCallbacks[key]?(result)
                }
            }
        }
    }
    
    public func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: (any Error)?) {
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
        readLock.withLock {
            if let callback = characteristicReadResultCallbacks[characteristicKey] {
                callback(result)
            }
        }
    }
    
    public func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: (any Error)?) {
#if DEBUG
        print("update notification state for \(characteristic): \(String(describing: characteristic.value)) (error: \(String(describing: error)))")
#endif
        guard let characteristicKey = characteristicKey(peripheral: peripheral, characteristic: characteristic) else {
            return
        }
        let result = getResult(value: (), error: error)
        notificationsLock.withLock {
            if let callback = subscribeToCharacteristicNotificationsResultCallbacks[characteristicKey] {
                callback(result)
            } else if let callback = unsubscribeFromCharacteristicNotificationsResultCallbacks[characteristicKey] {
                callback(result)
            }
        }
    }
}
