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
//! * must not contain any non-standard elements
//!   * a *published specification* belongs here and gets its own top-level module, even when it
//!     originates from an ecosystem rather than a standards body (e.g. `eudi_ts2`)
//!   * an ecosystem's *adjustment* of another standard does not (e.g. EUDI / swiyu flavours of
//!     OpenID4VCI); those stay in `one-core` next to the provider implementing them

pub mod csc;
pub mod etsi_119_472;
pub mod etsi_119_475;
pub mod etsi_119_602;
pub mod etsi_119_612;
pub mod eudi_ts12;
pub mod eudi_ts2;
pub mod iana;
pub mod jades;
pub mod jwe;
pub mod jwk;
pub mod mapper;
pub mod oauth2;
pub mod openid4vci;
pub mod openid4vp;
pub mod sd_jwt_vc;
pub mod w3c_vcdm;
pub mod x509;
pub mod xades;
