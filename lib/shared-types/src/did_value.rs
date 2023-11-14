use std::{convert::Infallible, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::macros::{impl_display, impls_for_seaorm_newtype};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(transparent)]
#[repr(transparent)]
pub struct DidValue(String);

impl DidValue {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for DidValue {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

impl_display!(DidValue);

#[cfg(feature = "sea-orm")]
impls_for_seaorm_newtype!(DidValue);
