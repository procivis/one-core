use one_dto_mapper::From;

use crate::OneCore;

#[uniffi::export]
impl OneCore {
    /// Returns build information.
    #[uniffi::method]
    pub fn version(&self) -> VersionBindingDTO {
        one_core::OneCore::version().into()
    }
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(one_core::Version)]
#[uniffi(name = "Version")]
pub struct VersionBindingDTO {
    pub target: String,
    pub build_time: String,
    pub branch: String,
    pub tag: String,
    pub commit: String,
    pub rust_version: String,
    pub pipeline_id: String,
}
