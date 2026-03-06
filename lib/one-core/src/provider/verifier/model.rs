use serde::Deserialize;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verifier {
    pub verifier_name: String,
    pub app_version: Option<VerifierAppVersion>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierAppVersion {
    pub minimum: Option<String>,
    pub minimum_recommended: Option<String>,
    pub reject: Option<Vec<String>>,
    pub update_screen: Option<VerifierUpdateScreen>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierUpdateScreen {
    pub link: String,
}
