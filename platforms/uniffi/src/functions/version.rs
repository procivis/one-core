use crate::dto::VersionBindingDTO;
use crate::OneCoreBinding;

impl OneCoreBinding {
    pub fn version(&self) -> VersionBindingDTO {
        one_core::OneCore::version()
    }
}
