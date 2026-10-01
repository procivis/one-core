use crate::proto::bluetooth_low_energy::low_level::dto::{
    CharacteristicPermissions, CharacteristicProperties, CreateCharacteristicOptions,
};

/// ISO 18013-5, Table 11
pub(crate) const STATE: &str = "00000001-A123-48CE-896B-4C76973373E6";
pub(crate) const CLIENT_2_SERVER: &str = "00000002-A123-48CE-896B-4C76973373E6";
pub(crate) const SERVER_2_CLIENT: &str = "00000003-A123-48CE-896B-4C76973373E6";

/// set of BLE service characteristics with settings according to ISO 18013-5, Table 11
pub(crate) fn get_characteristic_options() -> Vec<CreateCharacteristicOptions> {
    vec![
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
        },
        CreateCharacteristicOptions {
            uuid: CLIENT_2_SERVER.into(),
            permissions: vec![CharacteristicPermissions::Write],
            properties: vec![CharacteristicProperties::WriteWithoutResponse],
        },
        CreateCharacteristicOptions {
            uuid: SERVER_2_CLIENT.into(),
            permissions: vec![CharacteristicPermissions::Read],
            properties: vec![CharacteristicProperties::Notify],
        },
    ]
}
