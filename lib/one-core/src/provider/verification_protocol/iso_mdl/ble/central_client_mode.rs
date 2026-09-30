use hkdf::Hkdf;
use sha2::Sha256;

use crate::proto::bluetooth_low_energy::low_level::dto::{
    CharacteristicPermissions, CharacteristicProperties, CreateCharacteristicOptions,
};
use crate::provider::credential_formatter::mdoc_formatter::util::EmbeddedCbor;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::iso_mdl::common::EphemeralSessionKey;

/// ISO 18013-5, Table 12
pub(crate) const STATE: &str = "00000005-A123-48CE-896B-4C76973373E6";
pub(crate) const CLIENT_2_SERVER: &str = "00000006-A123-48CE-896B-4C76973373E6";
pub(crate) const SERVER_2_CLIENT: &str = "00000007-A123-48CE-896B-4C76973373E6";
pub(crate) const IDENT: &str = "00000008-A123-48CE-896B-4C76973373E6";

/// set of BLE service characteristics with settings according to ISO 18013-5, Table 12
#[expect(unused)]
pub(crate) fn get_characteristic_options(
    e_device_key_bytes: &EmbeddedCbor<EphemeralSessionKey>,
) -> Result<Vec<CreateCharacteristicOptions>, VerificationProtocolError> {
    Ok(vec![
        CreateCharacteristicOptions {
            uuid: STATE.into(),
            permissions: vec![
                CharacteristicPermissions::Read,
                CharacteristicPermissions::Write,
            ],
            properties: vec![
                CharacteristicProperties::Notify,
                CharacteristicProperties::WriteWithoutResponse,
            ],
            initial_value: None,
        },
        CreateCharacteristicOptions {
            uuid: CLIENT_2_SERVER.into(),
            permissions: vec![CharacteristicPermissions::Write],
            properties: vec![CharacteristicProperties::WriteWithoutResponse],
            initial_value: None,
        },
        CreateCharacteristicOptions {
            uuid: SERVER_2_CLIENT.into(),
            permissions: vec![CharacteristicPermissions::Read],
            properties: vec![CharacteristicProperties::Notify],
            initial_value: None,
        },
        CreateCharacteristicOptions {
            uuid: IDENT.into(),
            permissions: vec![CharacteristicPermissions::Read],
            properties: vec![CharacteristicProperties::Read],
            initial_value: Some(derive_ident_value(e_device_key_bytes)?),
        },
    ])
}

/// ISO 18013-5, 8.3.3.1.1.3
pub(super) fn derive_ident_value(
    e_device_key_bytes: &EmbeddedCbor<EphemeralSessionKey>,
) -> Result<Vec<u8>, VerificationProtocolError> {
    let mut result = [0u8; 16];

    let hkdf = Hkdf::<Sha256>::new(None, e_device_key_bytes.bytes());
    hkdf.expand(b"BLEIdent", &mut result).map_err(|e| {
        VerificationProtocolError::Failed(format!("Failed to create BLEIdent: {e}"))
    })?;

    Ok(result.to_vec())
}
