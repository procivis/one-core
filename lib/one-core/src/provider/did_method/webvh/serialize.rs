use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::provider::credential_formatter::vcdm::VcdmProof;
use crate::provider::did_method::dto::DidVerificationMethodDTO;
use crate::provider::did_method::webvh::common::DidLogParameters;

#[derive(Debug, Serialize)]
pub(super) struct DidDocState {
    pub value: DidDocument,
}

#[derive(Debug)]
pub(super) struct DidLogEntry {
    pub version_id: String,
    pub version_time: OffsetDateTime,
    pub parameters: DidLogParameters,
    pub state: DidDocState,
    pub proof: Vec<VcdmProof>,
}

impl Serialize for DidLogEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(5))?;
        seq.serialize_element(&self.version_id)?;

        let version_time = self
            .version_time
            .format(&Rfc3339)
            .map_err(serde::ser::Error::custom)?;
        seq.serialize_element(&version_time)?;

        seq.serialize_element(&self.parameters)?;
        seq.serialize_element(&self.state)?;

        if !self.proof.is_empty() {
            seq.serialize_element(&self.proof)?;
        }

        seq.end()
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verification_method: Vec<DidVerificationMethodDTO>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertion_method: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_agreement: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_invocation: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_delegation: Vec<String>,
}
