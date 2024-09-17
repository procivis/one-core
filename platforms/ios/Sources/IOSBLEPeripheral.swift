import CoreBluetooth
import UIKit

class IOSBLEPeripheral: NSObject {
    
    private var _peripheralManager: CBPeripheralManager?
    private var peripheralManager: CBPeripheralManager {
        get {
            if _peripheralManager == nil {
                _peripheralManager = CBPeripheralManager(delegate: self,
                                                         queue: nil)
            }
            return _peripheralManager!
        }
    }
    
    private var adapterStateCallback: BLEResultCallback<CBManagerState>?
    private var startAdvertisementResultCallback: BLEThrowingResultCallback<String?>?
    private var getConnectionChangeEventsResultCallback: BLEResultCallback<[ConnectionEventBindingEnum]>?
    private var readyToUpdateSubscribersCallbacks: [() async -> Void] = []
    private var getCharacteristicWritesResultCallbacks: [CharacteristicKey: BLEResultCallback<[Data]>] = [:]
    private var getCharacteristicReadResultCallbacks: [CharacteristicKey: BLEResultCallback<Void>] = [:]
    
    private let notifyLock = NSLock()
    private let readLock = NSLock()
    private let writeLock = NSLock()
    private let connectionLock = NSLock()
    
    private var services: [CBMutableService] = []
    private var connectedCentrals: [CBCentral: [CBCharacteristic]] = [:]
    private var characteristicValues: [String: Data] = [:]
    private var connectionChangeEventsQueue: [ConnectionEventBindingEnum] = []
    private var characteristicWritesQueue: [CharacteristicKey: [Data]] = [:]
    private var characteristicReadsQueue: [String: Set<String>] = [:]
}

// MARK: - BLEPeripheral interface implementation

extension IOSBLEPeripheral: BlePeripheral {
    
    func isAdapterEnabled() async throws -> Bool {
        var state = peripheralManager.state
        if (state == .unknown) {
            state = await withCheckedContinuation { continuation in
                adapterStateCallback = { [weak self] result in
                    self?.adapterStateCallback = nil
                    continuation.resume(with: result)
                }
            }
        }
#if DEBUG
        print("peripheralManager state \(state)")
#endif
        return state == .poweredOn
    }
    
    private func setupServicesAndCharacteristics(servicesWithCharacteristics: [ServiceDescriptionBindingDto]) {
        peripheralManager.removeAllServices()
        services = servicesWithCharacteristics.map { CBMutableService(with: $0) }
        services.forEach { service in
            peripheralManager.add(service)
        }
    }
    
    @discardableResult
    func startAdvertisement(deviceName: String?, services: [ServiceDescriptionBindingDto]) async throws -> String? {
        guard try await isAdapterEnabled() else {
            throw BleErrorWrapper.Ble(error: BleError.AdapterNotEnabled)
        }
        guard !peripheralManager.isAdvertising else {
            throw BleErrorWrapper.Ble(error: BleError.BroadcastAlreadyStarted)
        }
        setupServicesAndCharacteristics(servicesWithCharacteristics: services)
        let uuids = services.compactMap { $0.advertise ? CBUUID(string: $0.uuid) : nil }
        var advertisementData: [String: Any] = [:]
        if let deviceName = deviceName {
            advertisementData[CBAdvertisementDataLocalNameKey] = deviceName
        }
        if !services.isEmpty {
            advertisementData[CBAdvertisementDataServiceUUIDsKey] = uuids
        }
        peripheralManager.startAdvertising(advertisementData)
        return try await withCheckedThrowingContinuation { continuation in
            startAdvertisementResultCallback = { [weak self] result in
                self?.startAdvertisementResultCallback = nil
                continuation.resume(with: result)
            }
        }
    }
    
    func stopAdvertisement() async throws {
        guard peripheralManager.isAdvertising else {
            return
        }
        peripheralManager.stopAdvertising()
    }
    
    func stopServer() async throws {
        _peripheralManager = nil
        startAdvertisementResultCallback = nil
        getConnectionChangeEventsResultCallback = nil
        readyToUpdateSubscribersCallbacks = []
        getCharacteristicWritesResultCallbacks = [:]
        getCharacteristicReadResultCallbacks = [:]
        services = []
        connectedCentrals = [:]
        characteristicValues = [:]
        connectionChangeEventsQueue = []
        characteristicWritesQueue = [:]
        characteristicReadsQueue = [:]
    }
    
    func isAdvertising() async throws -> Bool {
        return peripheralManager.isAdvertising
    }
    
    func setCharacteristicData(serviceUuid: String, characteristicUuid: String, data: Data) async throws {
        let service = CBUUID(string: serviceUuid)
        let characteristic = CBUUID(string: characteristicUuid)
        let characteristicValueKey = characteristicValueKey(service: service, characteristic: characteristic)
        characteristicValues[characteristicValueKey] = data
        characteristicReadsQueue[characteristicValueKey] = Set<String>()
    }
    
    func notifyCharacteristicData(deviceAddress: String, serviceUuid: String, characteristicUuid: String, data: Data) async throws {
        try await setCharacteristicData(serviceUuid: serviceUuid, characteristicUuid: characteristicUuid, data: data)
        let service = CBUUID(string: serviceUuid)
        let characteristic = CBUUID(string: characteristicUuid)
        let cbCharacteristic = try retrieveCharacteristic(service: service, characteristic: characteristic)
        let subscribedCentrals = retrieveCentralsSubscribedToCharacteristic(characteristic: characteristic).filter { central in
            central.identifier == UUID(uuidString: deviceAddress)
        }
        guard !subscribedCentrals.isEmpty else {
            return
        }
        
        return try await withCheckedThrowingContinuation { continuation in
            notifyLock.withLock {
                let updateResult = peripheralManager.updateValue(data, for: cbCharacteristic, onSubscribedCentrals: subscribedCentrals)
#if DEBUG
                print("update value result \(updateResult)")
#endif
                if updateResult {
                    continuation.resume()
                    return
                }
                
                readyToUpdateSubscribersCallbacks.append({ [weak self] in
                    guard let self = self else {
                        continuation.resume(throwing: BleErrorWrapper.Ble(error: BleError.InvalidCharacteristicOperation(service: serviceUuid,
                                                                                                                         characteristic: characteristicUuid,
                                                                                                                         operation: "notify")))
                        return
                    }

                    do {
                        try await self.notifyCharacteristicData(deviceAddress: deviceAddress,
                                                                serviceUuid: serviceUuid,
                                                                characteristicUuid: characteristicUuid,
                                                                data: data)
                        continuation.resume()
                    } catch {
                        continuation.resume(throwing: error)
                    }
                })
            }
        }
    }
    
    func getConnectionChangeEvents() async throws -> [ConnectionEventBindingEnum] {
        return await withCheckedContinuation { continuation in
            connectionLock.withLock {
                guard connectionChangeEventsQueue.isEmpty else {
                    let events = connectionChangeEventsQueue
                    connectionChangeEventsQueue = []
                    continuation.resume(with: Result.success(events))
                    return
                }
                getConnectionChangeEventsResultCallback = { [weak self] result in
                    self?.getConnectionChangeEventsResultCallback = nil
                    continuation.resume(with: result)
                }
            }
        }
    }
    
    func getCharacteristicWrites(device: String, service: String, characteristic: String) async throws -> [Data] {
        guard let centralUuid = UUID(uuidString: device) else {
            throw BleErrorWrapper.Ble(error: BleError.InvalidUuid(uuid: device))
        }
        let serviceUuid = CBUUID(string: service)
        let characteristicUuid = CBUUID(string: characteristic)
        let characteristicKey = characteristicKey(central: centralUuid, service: serviceUuid, characteristic: characteristicUuid)
        return await withCheckedContinuation { continuation in
            writeLock.withLock {
                if let writes = characteristicWritesQueue[characteristicKey], !writes.isEmpty {
                    characteristicWritesQueue[characteristicKey] = nil
                    continuation.resume(with: Result.success(writes))
                    return
                }
                getCharacteristicWritesResultCallbacks[characteristicKey] = { [weak self] result in
                    self?.getCharacteristicWritesResultCallbacks[characteristicKey] = nil
                    continuation.resume(with: result)
                }
            }
        }
    }
    
    func waitForCharacteristicRead(device: String, service: String, characteristic: String) async throws {
        guard let centralUuid = UUID(uuidString: device) else {
            throw BleErrorWrapper.Ble(error: BleError.InvalidUuid(uuid: device))
        }
        let serviceUuid = CBUUID(string: service)
        let characteristicUuid = CBUUID(string: characteristic)
        let characteristicValueKey = characteristicValueKey(service: serviceUuid, characteristic: characteristicUuid)
        return await withCheckedContinuation { continuation in
            readLock.withLock {
                if let reads = characteristicReadsQueue[characteristicValueKey], reads.contains(device) {
                    characteristicReadsQueue[characteristicValueKey]?.remove(device)
                    continuation.resume(with: Result.success(()))
                    return
                }
                let characteristicKey = characteristicKey(central: centralUuid, service: serviceUuid, characteristic: characteristicUuid)
                getCharacteristicReadResultCallbacks[characteristicKey] = { [weak self] result in
                    self?.getCharacteristicReadResultCallbacks[characteristicKey] = nil
                    continuation.resume(with: result)
                }
            }
        }
    }
}

// MARK: - Common helpers

private extension IOSBLEPeripheral {
    
    private func retrieveService(service: CBUUID) throws -> CBMutableService {
        guard let cbService = services.first(where: { $0.uuid == service }) else {
            throw BleErrorWrapper.Ble(error: BleError.ServiceNotFound(service: service.uuidString))
        }
        return cbService
    }
    
    private func retrieveCharacteristic(service: CBUUID, characteristic: CBUUID) throws -> CBMutableCharacteristic {
        let service = try retrieveService(service: service)
        guard let cbCharacteristic = service.characteristics?.first(where: { $0.uuid == characteristic }) as? CBMutableCharacteristic else {
            throw BleErrorWrapper.Ble(error: BleError.CharacteristicNotFound(characteristic: characteristic.uuidString))
        }
        return cbCharacteristic
    }
    
    private func retrieveCentralsSubscribedToCharacteristic(characteristic: CBUUID) -> [CBCentral] {
        connectedCentrals.keys.filter { central in
            connectedCentrals[central]?.contains(where: { cbCharacteristic in
                cbCharacteristic.uuid == characteristic
            }) == true
        }
    }
    
    private func characteristicKey(central: UUID, service: CBUUID, characteristic: CBUUID) -> CharacteristicKey {
        return CharacteristicKey(deviceAddress: central, serviceUUID: service, characteristicUUID: characteristic)
    }
    
    private func characteristicKey(central: CBCentral, characteristic: CBCharacteristic) -> CharacteristicKey? {
        let characteristicUUID = characteristic.uuid
        guard let service = characteristic.service?.uuid else {
            return nil
        }
        let characteristicKey = characteristicKey(central: central.identifier, service: service, characteristic: characteristicUUID)
        return characteristicKey
    }
    
    private func characteristicValueKey(service: CBUUID, characteristic: CBUUID) -> String {
        return "\(service.uuidString)_\(characteristic.uuidString)"
    }
    
    private func characteristicValueKey(characteristic: CBCharacteristic) -> String? {
        let characteristicUUID = characteristic.uuid
        guard let service = characteristic.service?.uuid else {
            return nil
        }
        let characteristicValueKey = characteristicValueKey(service: service, characteristic: characteristicUUID)
        return characteristicValueKey
    }
    
    private func sendConnectedEventIfIsNewCentral(central: CBCentral) {
        if connectedCentrals[central] == nil {
            connectedCentrals[central] = []
            let deviceInfo = DeviceInfoBindingDto(address: central.identifier.uuidString,
                                                  mtu: UInt16(central.maximumUpdateValueLength))
            if let callback = getConnectionChangeEventsResultCallback {
                callback(Result.success([.connected(deviceInfo: deviceInfo)]))
            } else {
                connectionChangeEventsQueue.append(.connected(deviceInfo: deviceInfo))
            }
        }
    }
}

// MARK: - CBPeripheralManagerDelegate methods

extension IOSBLEPeripheral: CBPeripheralManagerDelegate {
    
    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
#if DEBUG
        print("peripheral manager did update state \(peripheral.state)")
#endif
        adapterStateCallback?(Result.success(peripheral.state))
    }
    
    func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: (any Error)?) {
#if DEBUG
        print("did start advertising \(peripheral) \(String(describing: error))")
#endif
        guard let callback = startAdvertisementResultCallback else {
            return
        }
        if let error = error {
            callback(Result.failure(error))
        } else {
            callback(Result.success(nil))
        }
    }
    
    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveRead request: CBATTRequest) {
#if DEBUG
        print("did receive read request \(request)")
#endif
        connectionLock.withLock {
            sendConnectedEventIfIsNewCentral(central: request.central)
        }
        
        guard let characteristicValueKey = characteristicValueKey(characteristic: request.characteristic),
              let value = characteristicValues[characteristicValueKey] ?? request.characteristic.value else  {
            peripheral.respond(to: request, withResult: .attributeNotFound)
            return
        }
        request.value = value
        peripheral.respond(to: request, withResult: .success)
        
        readLock.withLock {
            guard let characteristicKey = characteristicKey(central: request.central, characteristic: request.characteristic),
                  let callback = getCharacteristicReadResultCallbacks[characteristicKey] else {
                characteristicReadsQueue[characteristicValueKey] = characteristicReadsQueue[characteristicValueKey] ?? Set<String>()
                characteristicReadsQueue[characteristicValueKey]?.insert(request.central.identifier.uuidString)
                return
            }
            callback(Result.success(()))
        }
    }
    
    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
#if DEBUG
        print("did receive write requests \(requests)")
#endif
        writeLock.withLock {
            requests.forEach { request in
#if DEBUG
                if let value = request.value {
                    print("write data: \(String(describing: String(data: value, encoding: .ascii)))")
                }
#endif
                connectionLock.withLock {
                    sendConnectedEventIfIsNewCentral(central: request.central)
                }
                peripheral.respond(to: request, withResult: .success)
                
                guard let characteristicKey = characteristicKey(central: request.central, characteristic: request.characteristic) else {
                    return
                }
                guard let callback = getCharacteristicWritesResultCallbacks[characteristicKey] else {
                    characteristicWritesQueue[characteristicKey] = characteristicWritesQueue[characteristicKey] ?? []
                    characteristicWritesQueue[characteristicKey]?.append(request.value ?? Data())
                    return
                }
                callback(Result.success([request.value ?? Data()]))
            }
        }
    }
    
    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didSubscribeTo characteristic: CBCharacteristic) {
#if DEBUG
        print("central \(central) subscribed to \(characteristic)")
#endif
        connectionLock.withLock {
            sendConnectedEventIfIsNewCentral(central: central)
            connectedCentrals[central]?.removeAll(where: { $0.uuid == characteristic.uuid })
            connectedCentrals[central]?.append(characteristic)
        }
    }
    
    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didUnsubscribeFrom characteristic: CBCharacteristic) {
#if DEBUG
        print("central \(central) unsubscribed from \(characteristic)")
#endif
        connectionLock.withLock {
            connectedCentrals[central]?.removeAll(where: { $0.uuid == characteristic.uuid })
            if connectedCentrals[central]?.isEmpty == true {
                connectedCentrals[central] = nil
            }
            if connectedCentrals[central] == nil {
                guard let callback = getConnectionChangeEventsResultCallback else {
                    connectionChangeEventsQueue.append(.disconnected(deviceAddress: central.identifier.uuidString))
                    return
                }
                callback(Result.success([.disconnected(deviceAddress: central.identifier.uuidString)]))
            }
        }
    }
    
    func peripheralManagerIsReady(toUpdateSubscribers peripheral: CBPeripheralManager) {
#if DEBUG
        print("peripheral manager ready to update subscribers")
#endif
        notifyLock.withLock {
            readyToUpdateSubscribersCallbacks.forEach { callback in
                Task {
                    await callback()
                }
            }
            readyToUpdateSubscribersCallbacks = []
        }
    }
}
