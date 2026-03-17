import CoreBluetooth

typealias BLEResultCallback<T> = (Result<T, Never>) -> Void
typealias BLEThrowingResultCallback<T> = (Result<T, Error>) -> Void

struct CharacteristicKey: Hashable, Equatable {
    let deviceAddress: UUID
    let serviceUUID: CBUUID
    let characteristicUUID: CBUUID
}

extension CBCharacteristicProperties {
    
    init(with propertiesArray: [CharacteristicProperty]) {
        self.init()
        propertiesArray.forEach { property in
            switch property {
            case .read:
                self.insert(.read)
            case .write:
                self.insert(.write)
            case .writeWithoutResponse:
                self.insert(.writeWithoutResponse)
            case .notify:
                self.insert(.notify)
            case .indicate:
                self.insert(.indicate)
            }
        }
    }
    
    var propertiesArray: [CharacteristicProperty] {
        get {
            var properties: [CharacteristicProperty] = []
            if self.contains(.read) {
                properties.append(.read)
            }
            if self.contains(.write) {
                properties.append(.write)
            }
            if self.contains(.notify) {
                properties.append(.notify)
            }
            return properties
        }
    }
}

extension Array where Element == CharacteristicProperty {
    
    var propertiesSet: CBCharacteristicProperties {
        get {
            CBCharacteristicProperties(with: self)
        }
    }
}

extension CBAttributePermissions {
    
    init(with permissionsArray: [CharacteristicPermission]) {
        self.init()
        permissionsArray.forEach { property in
            switch property {
            case .read:
                self.insert(.readable)
            case .write:
                self.insert(.writeable)
            }
        }
    }
    
    var permissionsArray: [CharacteristicPermission] {
        get {
            var permissions: [CharacteristicPermission] = []
            if self.contains(.readable) {
                permissions.append(.read)
            }
            if self.contains(.writeable) {
                permissions.append(.write)
            }
            return permissions
        }
    }
}

extension Array where Element == CharacteristicPermission {
    
    var permissionsSet: CBAttributePermissions {
        get {
            CBAttributePermissions(with: self)
        }
    }
}

extension CBCharacteristic {
    
    var characteristic: CharacteristicSettings {
        get {
            var permissions: [CharacteristicPermission] = []
            if let mutableCharacteristic = self as? CBMutableCharacteristic {
                permissions = mutableCharacteristic.permissions.permissionsArray
            }
            let properties = self.properties.propertiesArray
            return CharacteristicSettings(uuid: uuid.uuidString,
                                          permissions: permissions,
                                          properties: properties)
        }
    }
}

extension CBMutableCharacteristic {
    
    convenience init(with characteristic: CharacteristicSettings) {
        self.init(type: CBUUID(string: characteristic.uuid),
                  properties: characteristic.properties.propertiesSet,
                  value: nil,
                  permissions: characteristic.permissions.permissionsSet)
    }
}

extension CBService {
    
    var servicesDescription: ServiceDescription {
        get {
            return ServiceDescription(uuid: self.uuid.uuidString,
                                      advertise: false,
                                      advertisedServiceData: nil,
                                      characteristics: self.characteristics?.map { $0.characteristic } ?? [])
        }
    }
}

extension CBMutableService {
    
    convenience init(with serviceDescription: ServiceDescription, primary: Bool = true) {
        self.init(type: CBUUID(string: serviceDescription.uuid), primary: primary)
        self.characteristics = serviceDescription.characteristics.map { CBMutableCharacteristic(with: $0) }
    }
}

extension CBPeripheral {
    
    var servicesDescriptions: [ServiceDescription] {
        get {
            return self.services?.map { service in
                return service.servicesDescription
            } ?? []
        }
    }
}

extension CharacteristicWriteType {
    
    var cbCharacteristicWriteType: CBCharacteristicWriteType {
        get {
            switch self {
            case .withResponse:
                return .withResponse
            case .withoutResponse:
                return .withoutResponse
            }
        }
    }
}
