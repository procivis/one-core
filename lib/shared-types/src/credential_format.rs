use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::macros::{impl_display, impl_from};

#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct CredentialFormat(String);

#[derive(Debug, Error)]
pub enum CredentialFormatParseError {
    // empty because parsing is infallible
}

impl FromStr for CredentialFormat {
    type Err = CredentialFormatParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

impl From<&str> for CredentialFormat {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl AsRef<str> for CredentialFormat {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl_display!(CredentialFormat);
impl_from!(CredentialFormat; String);

#[cfg(feature = "sea-orm")]
use crate::macros::impls_for_seaorm_newtype;
#[cfg(feature = "sea-orm")]
impls_for_seaorm_newtype!(CredentialFormat);
