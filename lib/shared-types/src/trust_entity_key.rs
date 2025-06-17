use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::DidValue;
use crate::macros::{impl_display, impl_from, impl_into};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(transparent)]
#[repr(transparent)]
pub struct TrustEntityKey(String);

impl FromStr for TrustEntityKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(TrustEntityKey(s.to_string()))
    }
}

impl AsRef<str> for TrustEntityKey {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl_display!(TrustEntityKey);
impl_from!(TrustEntityKey; String);
impl_into!(TrustEntityKey; String);

#[cfg(feature = "sea-orm")]
use crate::macros::impls_for_seaorm_newtype;

#[cfg(feature = "sea-orm")]
impls_for_seaorm_newtype!(TrustEntityKey);

impl From<&DidValue> for TrustEntityKey {
    fn from(value: &DidValue) -> Self {
        Self(value.as_str().to_string())
    }
}

impl From<DidValue> for TrustEntityKey {
    fn from(value: DidValue) -> Self {
        Self(value.as_str().to_string())
    }
}
