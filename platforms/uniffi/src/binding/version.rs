use one_dto_mapper::From;

use crate::OneCoreBinding;

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
    pub fn version(&self) -> VersionBindingDTO {
        one_core::OneCore::version().into()
    }
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(one_core::Version)]
pub struct VersionBindingDTO {
    pub target: String,
    pub build_time: String,
    pub branch: String,
    pub tag: String,
    pub commit: String,
    pub rust_version: String,
    pub pipeline_id: String,
}
