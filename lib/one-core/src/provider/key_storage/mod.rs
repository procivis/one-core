use dto_mapper::{convert_inner, From, Into};
use serde::Serialize;

pub mod pkcs11;
pub mod secure_element;

#[derive(Clone, Debug, Serialize, Eq, PartialEq, From, Into)]
#[serde(rename_all = "UPPERCASE")]
#[from(one_providers::key_storage::model::KeySecurity)]
#[into(one_providers::key_storage::model::KeySecurity)]
pub enum KeySecurity {
    Hardware,
    Software,
}

#[derive(Clone, Debug, Default, Serialize, From, Into)]
#[from(one_providers::key_storage::model::KeyStorageCapabilities)]
#[into(one_providers::key_storage::model::KeyStorageCapabilities)]
pub struct KeyStorageCapabilities {
    #[into(with_fn = convert_inner)]
    #[from(with_fn = convert_inner)]
    pub features: Vec<String>,
    #[into(with_fn = convert_inner)]
    #[from(with_fn = convert_inner)]
    pub algorithms: Vec<String>,
    #[into(with_fn = convert_inner)]
    #[from(with_fn = convert_inner)]
    pub security: Vec<KeySecurity>,
}
