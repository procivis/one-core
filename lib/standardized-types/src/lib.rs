//! Crate with data types that are defined in a standard.
//!
//! Generally, types defined in this crate should:
//! * have concise names
//! * be public, with public fields
//! * Always derive `Debug`, `Clone`, `PartialEq`, `Eq`, `Serialize`, `Deserialize`
//! * if appropriate, additionally derive any of `Default`, `Display`
//! * if appropriate, derive `utoipa::ToSchema` and `options_not_nullable` behind the `utoipa` feature flag
//!   * **Note**: `utoipa` cannot handle multiple types with the same name. Make sure to disambiguate
//!     conflicting types using the following attribute: `#[cfg_attr(feature = "utoipa", schema(as = new_name))]`
//! * use `secrecy` for sensitive values
//! * should be grouped into modules by their defining standards
//!   * if there are multiple versions of the standard, keep the common types in the module with the
//!     standard name and have submodules for each version with the types that differ
//! * may contain only a subset of what the relevant standard defines
//! * must not contain any non-standard elements (e.g. EUDI / swiyu adjustments)

pub mod jwa;
pub mod jwk;
pub mod openid4vp;

// Crate utility for `secrecy` string values
mod secret_string {
    use secrecy::{ExposeSecret, SecretString};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(secret: &SecretString, s: S) -> Result<S::Ok, S::Error> {
        secret.expose_secret().serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<SecretString, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data = String::deserialize(d)?;
        Ok(SecretString::from(data))
    }
}
