//! Spec: https://datatracker.ietf.org/doc/html/rfc7518

use serde::{Deserialize, Serialize};
use strum::Display;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Display)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum EncryptionAlgorithm {
    A128GCM,
    // AES GCM using 256-bit key
    A256GCM,
    #[serde(rename = "A128CBC-HS256")]
    #[strum(to_string = "A128CBC-HS256")]
    A128CBCHS256,
}
