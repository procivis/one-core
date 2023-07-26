use crate::OneCore;

pub type Version = one_core::Version;

impl OneCore {
    pub fn version(&self) -> Version {
        one_core::OneCore::version()
    }
}
