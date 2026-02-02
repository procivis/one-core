import Foundation

/**
 Creates a new instance of Procivis ONE Core SDK

 - Parameter params: Additional optional init parameters
 - Parameter dataDirPath: Optional directory where ONE Core SDK should persist its data

 - Note: ``InitParamsDto/bleCentral``, ``InitParamsDto/blePeripheral``, ``InitParamsDto/nativeSecureElement`` and ``InitParamsDto/nfcScanner`` fallback to the default implmementations if not provided
*/
public func initializeCore(params: InitParamsDto, dataDirPath: String? = nil) throws -> OneCoreBindingProtocol {
  var dataDir: String? = dataDirPath
  if dataDir == nil {
    dataDir = NSSearchPathForDirectoriesInDomains(
      .applicationSupportDirectory,
      .userDomainMask,
      true
      ).first
  }
  if dataDir == nil {
      throw BindingError.ErrorResponse(
        data: ErrorResponseBindingDto(code: "BR_0000", message: "invalid DataDir", cause: nil)
      )
    }

  // create folder if not exists
  try FileManager.default.createDirectory(
    atPath: dataDir!,
    withIntermediateDirectories: true
  )

  return try uniffiInitializeCore(
    dataDirPath: dataDir!,
    params: InitParamsDto(
      configJson: params.configJson,
      nativeSecureElement: params.nativeSecureElement ?? SecureEnclaveKeyStorage(),
      remoteSecureElement: params.remoteSecureElement,
      bleCentral: params.bleCentral ?? IOSBLECentral(),
      blePeripheral: params.blePeripheral ?? IOSBLEPeripheral(),
      nfcHce: params.nfcHce,
      nfcScanner: params.nfcScanner ?? NFCScanner()
    )
  )
}
