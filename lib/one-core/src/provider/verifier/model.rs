use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use shared_types::TrustCollectionId;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verifier {
    pub verifier_name: String,
    pub app_version: Option<VerifierAppVersion>,
    #[serde(default)]
    pub trust_collections: HashMap<TrustCollectionId, TrustCollectionParams>, // FIX ME: This is a temporary solution, should be changed to a proper structure ONE-9309
    pub feature_flags: FeatureFlags,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierAppVersion {
    pub minimum: Option<String>,
    pub minimum_recommended: Option<String>,
    pub reject: Option<Vec<String>>,
    pub update_screen: Option<VerifierUpdateScreen>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierUpdateScreen {
    pub link: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeatureFlags {
    pub trust_ecosystems_enabled: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustCollectionParams {
    pub logo: String,
    pub display_name: HashMap<String, String>,
    pub description: HashMap<String, String>,
}
