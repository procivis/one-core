use crate::{dto::VersionBindingDTO, OneCoreBinding};

impl OneCoreBinding {
    pub fn version(&self) -> VersionBindingDTO {
        one_core::OneCore::version()
    }
}
