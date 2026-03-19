use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use standardized_types::etsi_119_602::TrustedEntityInformation;

use crate::model::trust_list_role::TrustListRoleEnum;

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct PreprocessedLote {
    /// Role of this LoTE
    pub role: Option<TrustListRoleEnum>,
    /// List of all trusted entities in the LoTE.
    pub trusted_entities: Vec<TrustedEntityInformation>,
    /// Map of cert fingerprints to indices into `trust_entities`
    pub certificate_fingerprints: HashMap<String, usize>,
    /// Map of subject key identifiers to indices into `trust_entities`
    pub subject_key_identifiers: HashMap<String, usize>,
    /// Map of subject names to indices into `trust_entities`
    pub subject_names: HashMap<String, usize>,
    /// Map of raw Base64 encoded public keys to indices into `trust_entities`
    pub public_keys: HashMap<String, usize>,
}
