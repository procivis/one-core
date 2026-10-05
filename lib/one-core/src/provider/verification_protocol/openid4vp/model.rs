use std::collections::HashMap;

use anyhow::Context;
use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{InteractionId, KeyId, TransactionDataId, TransactionDataType};
use standardized_types::jwk::PublicJwk;
use standardized_types::openid4vp::dcql::{CredentialQueryId, DcqlQuery};
use standardized_types::openid4vp::{
    ClientIdPrefix, ClientMetadata, EncryptedResponse, ResponseMode, VerifierInfoAttestation,
    VpTokenResponse,
};
use time::OffsetDateTime;
use url::Url;

use super::mapper::{deserialize_with_serde_json, unix_timestamp_option};
use crate::model::claim::Claim;
use crate::model::credential::CredentialCommon;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::relation::{Related, RelatedVec};
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::provider::verification_protocol::error::VerificationProtocolError;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct JwePayload {
    pub aud: Option<Url>,
    #[serde(default, with = "unix_timestamp_option")]
    pub exp: Option<OffsetDateTime>,
    #[serde(flatten)]
    pub submission_data: VpSubmissionData,
    pub state: Option<String>,
}

impl JwePayload {
    pub(crate) fn try_from_json(payload: &[u8]) -> anyhow::Result<Self> {
        let payload =
            serde_json::from_slice(payload).context("JWE payload deserialization failed")?;

        Ok(payload)
    }

    pub(crate) fn try_into_json(&self) -> anyhow::Result<Vec<u8>> {
        let payload = serde_json::to_vec(self).context("JWE payload serialization failed")?;
        Ok(payload)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DcqlSubmissionEudi {
    pub vp_token: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum VpSubmissionData {
    Dcql(#[serde(deserialize_with = "deserialize_lenient_vp_token_response")] VpTokenResponse),
    DcqlEudi(DcqlSubmissionEudi),
    EncryptedResponse(EncryptedResponse),
}

/// Accepts `vp_token` both as a JSON object and as a JSON-encoded string.
///
/// This is required for the swiyu wallet because it submits the JSON object as string, i.e. `{"vp_token": "{\"<query id>\":[\"<vp>\"]}"}`.
fn deserialize_lenient_vp_token_response<'de, D>(
    deserializer: D,
) -> Result<VpTokenResponse, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct LenientVpTokenResponse {
        #[serde(deserialize_with = "deserialize_with_serde_json")]
        vp_token: HashMap<String, Vec<String>>,
    }

    let LenientVpTokenResponse { vp_token } = LenientVpTokenResponse::deserialize(deserializer)?;
    Ok(VpTokenResponse { vp_token })
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenID4VPDirectPostRequestDTO {
    #[serde(flatten)]
    pub submission_data: VpSubmissionData,
    pub state: Option<InteractionId>,
}

/// Interaction data used for OpenID4VP on verifier side
/// - HTTP transport generates this
///
/// Important: This structure is used to deserialize
/// also from all the other verifier interaction data structures
/// during proof submission validation
#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug)]
pub(crate) struct OpenID4VPVerifierInteractionContent {
    pub nonce: String,
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub dcql_query: DcqlQuery,
    /// with client_id_scheme prefix (for Final 1.0)
    pub client_id: String,
    pub client_id_scheme: Option<ClientIdPrefix>,
    pub response_uri: Option<String>,
    pub encryption_key: Option<PublicJwk>,
    #[serde(flatten)]
    pub common: CommonVerifierInteractionContent,
}

/// Interaction data that is common between the data created on proof create
/// and proof share.
#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub(crate) struct CommonVerifierInteractionContent {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transaction_data: Vec<TransactionDataRequest>,
}

/// Transaction data as provided at proof-request creation, turned into an OpenID4VP
/// `transaction_data` entry by the transaction data provider named by `name`
#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug)]
pub(crate) struct TransactionDataRequest {
    pub r#type: TransactionDataType,
    // Corresponds to the ids of the underlying credential schemas
    pub credential_ids: Vec<CredentialQueryId>,
    /// Transaction data as supplied when creating the proof request
    pub data: Option<serde_json::Value>,
    /// Base64-encoded transaction data to be included with the proof request
    pub encoded: String,
}

#[derive(Debug, Clone)]
pub(crate) struct SubmissionRequestData {
    pub submission_data: VpSubmissionData,
    pub state: InteractionId,
    pub mdoc_generated_nonce: Option<String>,
    pub encryption_key: Option<KeyId>,
}

/// Verified submission data before issuer and holder identifiers are resolved for persistence.
#[derive(Clone, Debug)]
pub(crate) struct ProvedCredential {
    pub common: CredentialCommon,
    pub claims: RelatedVec<Claim>,
    pub format: Related<CredentialSchemaFormat>,
    pub issuer_details: IdentifierDetails,
    pub holder_details: IdentifierDetails,
}

/// Interaction data used for OpenID4VP (HTTP) on holder side
#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug)]
pub(crate) struct OpenID4VPHolderInteractionData {
    pub response_type: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub client_id_scheme: ClientIdPrefix,

    /// without client_id_scheme prefix (in case of Final 1.0)
    pub client_id: String,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub client_metadata: Option<ClientMetadata>,
    pub client_metadata_uri: Option<Url>,
    pub response_mode: Option<ResponseMode>,
    pub response_uri: Option<Url>,
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub dcql_query: DcqlQuery,
    #[serde(default)]
    pub transaction_data: HolderTxData,

    #[serde(default, skip_serializing)]
    pub redirect_uri: Option<String>,

    #[serde(default)]
    pub verifier_details: Option<IdentifierDetails>,
    #[serde(default)]
    pub verifier_info: Vec<VerifierInfoAttestation>,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub(crate) enum HolderTxData {
    Unvalidated(Vec<String>),
    // stored as a sequence: the interaction data passes through `serde_json::Value`,
    // which sorts object keys and would lose the order of the authorization request
    Validated(
        #[serde(with = "indexmap::map::serde_seq")]
        IndexMap<TransactionDataId, ValidatedHolderTxData>,
    ),
}

impl Default for HolderTxData {
    fn default() -> Self {
        Self::Unvalidated(Vec::new())
    }
}

impl HolderTxData {
    pub fn validated(
        &self,
    ) -> Result<IndexMap<TransactionDataId, ValidatedHolderTxData>, VerificationProtocolError> {
        match self {
            HolderTxData::Validated(tx_data) => Ok(tx_data.clone()),
            HolderTxData::Unvalidated(d) if d.is_empty() => Ok(IndexMap::new()),
            HolderTxData::Unvalidated(_) => Err(VerificationProtocolError::Failed(
                "Unvalidated transaction data".to_string(),
            )),
        }
    }
}

#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug)]
pub(crate) struct ValidatedHolderTxData {
    /// Raw base64URL-encoded transaction data.
    pub raw: String,
    /// Credential ids the transaction data is for.
    pub credential_query_ids: Vec<CredentialQueryId>,
    /// Config name of the `TransactionData` provider that validated this entry.
    pub transaction_data_type: TransactionDataType,
}

// Apparently the indirection via functions is required: https://github.com/serde-rs/serde/issues/368
pub(crate) fn default_presentation_url_scheme() -> String {
    "openid4vp".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VCRedirectUriParams {
    pub enabled: bool,
    pub allowed_schemes: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct OpenID4VCVerifierAttestationPayload {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirect_uris: Vec<String>,
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;
    use uuid::Uuid;

    use super::*;

    fn validated_tx_data(ids: &[&str]) -> HolderTxData {
        HolderTxData::Validated(
            ids.iter()
                .map(|id| {
                    (
                        TransactionDataId::from(Uuid::parse_str(id).unwrap()),
                        ValidatedHolderTxData {
                            raw: id.to_string(),
                            credential_query_ids: vec![],
                            transaction_data_type: "QES_APPROVAL".into(),
                        },
                    )
                })
                .collect(),
        )
    }

    // keys in descending order, so that `serde_json::Value` sorting them would show
    const IDS: [&str; 2] = [
        "ffffffff-0000-4000-8000-000000000000",
        "00000000-0000-4000-8000-000000000000",
    ];

    #[test]
    fn test_validated_tx_data_keeps_order_through_serde_json_value() {
        let value = serde_json::to_value(validated_tx_data(&IDS)).unwrap();

        let HolderTxData::Validated(tx_data) = serde_json::from_value(value).unwrap() else {
            panic!("expected validated transaction data");
        };

        let ids: Vec<String> = tx_data.keys().map(ToString::to_string).collect();
        assert_eq!(ids, IDS);
    }

    const VP: &str = "eyJhbGciOiJFUzI1NiJ9.payload.signature";

    fn expected_dcql_submission() -> HashMap<String, Vec<String>> {
        HashMap::from([("credential_query_1".to_string(), vec![VP.to_string()])])
    }

    /// The swiyu wallet JSON-encodes `vp_token` as a string inside the JWE payload.
    #[test]
    fn test_jwe_payload_accepts_json_string_vp_token() {
        let payload = format!(
            r#"{{"vp_token":"{{\"credential_query_1\":[\"{VP}\"]}}","state":"the-state"}}"#
        );

        let payload = JwePayload::try_from_json(payload.as_bytes()).unwrap();

        let VpSubmissionData::Dcql(VpTokenResponse { vp_token }) = payload.submission_data else {
            panic!("expected a DCQL submission");
        };
        assert_eq!(expected_dcql_submission(), vp_token);
        assert_eq!(Some("the-state".to_string()), payload.state);
    }

    #[test]
    fn test_jwe_payload_accepts_object_vp_token() {
        let payload =
            format!(r#"{{"vp_token":{{"credential_query_1":["{VP}"]}},"state":"the-state"}}"#);

        let payload = JwePayload::try_from_json(payload.as_bytes()).unwrap();

        let VpSubmissionData::Dcql(VpTokenResponse { vp_token }) = payload.submission_data else {
            panic!("expected a DCQL submission");
        };
        assert_eq!(expected_dcql_submission(), vp_token);
    }

    #[test]
    fn test_jwe_payload_round_trip_serializes_vp_token_as_object() {
        let payload = JwePayload {
            aud: Some("https://verifier.example/response".parse().unwrap()),
            exp: Some(OffsetDateTime::from_unix_timestamp(1757000000).unwrap()),
            submission_data: VpSubmissionData::Dcql(VpTokenResponse {
                vp_token: expected_dcql_submission(),
            }),
            state: Some("the-state".to_string()),
        };

        let json = payload.try_into_json().unwrap();
        assert!(
            serde_json::from_slice::<serde_json::Value>(&json).unwrap()["vp_token"].is_object(),
            "vp_token must stay a JSON object on the wire"
        );

        let deserialized = JwePayload::try_from_json(&json).unwrap();
        assert_eq!(payload.aud, deserialized.aud);
        assert_eq!(payload.exp, deserialized.exp);
        assert_eq!(payload.state, deserialized.state);
        let VpSubmissionData::Dcql(VpTokenResponse { vp_token }) = deserialized.submission_data
        else {
            panic!("expected a DCQL submission");
        };
        assert_eq!(expected_dcql_submission(), vp_token);
    }
}
