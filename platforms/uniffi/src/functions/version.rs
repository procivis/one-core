use crate::dto::VersionBindingDTO;
use crate::OneCoreBinding;

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
    pub fn version(&self) -> VersionBindingDTO {
        one_core::OneCore::version().into()
    }
}
