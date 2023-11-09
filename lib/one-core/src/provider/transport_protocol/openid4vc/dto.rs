use std::collections::HashMap;

use crate::{
    model::{claim_schema::ClaimSchemaId, interaction::InteractionId},
    provider::transport_protocol::openid4vc::mapper::deserialize_with_serde_json,
};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenID4VCICredential {
    pub format: String,
    pub credential_definition: OpenID4VCICredentialDefinition,
    pub proof: OpenID4VCIProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenID4VCIProof {
    pub proof_type: String,
    pub jwt: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenID4VCICredentialDefinition {
    pub r#type: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "credentialSubject")]
    pub credential_subject: Option<OpenID4VCICredentialSubject>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenID4VCICredentialOfferCredentialDTO {
    pub format: String,
    pub credential_definition: OpenID4VCICredentialDefinition,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenID4VCICredentialOffer {
    pub credential_issuer: String,
    pub credentials: Vec<OpenID4VCICredentialOfferCredentialDTO>,
    pub grants: OpenID4VCIGrants,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenID4VCICredentialSubject {
    #[serde(flatten)]
    pub keys: HashMap<String, OpenID4VCICredentialValueDetails>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenID4VCICredentialValueDetails {
    pub value: String,
    pub value_type: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenID4VCIGrants {
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub code: OpenID4VCIGrant,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenID4VCIGrant {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenID4VPClientMetadata {
    pub vp_formats: HashMap<String, OpenID4VPFormat>,
    pub client_id_scheme: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenID4VPFormat {
    pub alg: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenID4VPPresentationDefinition {
    pub id: InteractionId,
    pub input_descriptors: Vec<OpenID4VPPresentationDefinitionInputDescriptors>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenID4VPPresentationDefinitionInputDescriptors {
    pub id: String,
    pub constraints: OpenID4VPPresentationDefinitionConstraint,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct OpenID4VPPresentationDefinitionConstraint {
    pub fields: Vec<OpenID4VPPresentationDefinitionConstraintField>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenID4VPPresentationDefinitionConstraintField {
    pub id: ClaimSchemaId,
    pub path: Vec<String>,
    pub optional: bool,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct OpenID4VPInteractionData {
    pub response_type: String,
    pub state: Option<Uuid>,
    pub nonce: String,
    pub client_id_scheme: String,
    pub client_id: Url,
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub client_metadata: OpenID4VPClientMetadata,
    pub response_mode: String,
    pub response_uri: Url,
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub presentation_definition: OpenID4VPPresentationDefinition,

    #[serde(skip_serializing)]
    pub redirect_uri: Option<String>,
}
