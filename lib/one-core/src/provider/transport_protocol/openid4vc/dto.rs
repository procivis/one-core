use std::collections::HashMap;

use crate::{
    common_mapper::deserialize_with_serde_json,
    model::{credential_schema::WalletStorageTypeEnum, interaction::InteractionId},
};
use serde::{Deserialize, Serialize};
use shared_types::ClaimSchemaId;
use time::OffsetDateTime;
use url::Url;

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

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCICredentialDefinition {
    pub r#type: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "credentialSubject")]
    pub credential_subject: Option<OpenID4VCICredentialSubject>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCICredentialOfferCredentialDTO {
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_definition: Option<OpenID4VCICredentialDefinition>,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<HashMap<String, OpenID4VCICredentialOfferClaim>>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct OpenID4VCICredentialOfferClaim {
    pub value: OpenID4VCICredentialOfferClaimValue,
    pub value_type: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum OpenID4VCICredentialOfferClaimValue {
    Nested(HashMap<String, OpenID4VCICredentialOfferClaim>),
    String(String),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCICredentialOfferDTO {
    pub credential_issuer: String,
    pub credentials: Vec<OpenID4VCICredentialOfferCredentialDTO>,
    pub grants: OpenID4VCIGrants,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCICredentialSubject {
    #[serde(flatten)]
    pub keys: HashMap<String, OpenID4VCICredentialValueDetails>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCICredentialValueDetails {
    pub value: String,
    pub value_type: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCIGrants {
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub code: OpenID4VCIGrant,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCIGrant {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VPClientMetadata {
    pub vp_formats: HashMap<String, OpenID4VPFormat>,
    pub client_id_scheme: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VPFormat {
    pub alg: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VPPresentationDefinition {
    pub id: InteractionId,
    pub input_descriptors: Vec<OpenID4VPPresentationDefinitionInputDescriptor>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VPPresentationDefinitionInputDescriptor {
    pub id: String,
    pub constraints: OpenID4VPPresentationDefinitionConstraint,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VPPresentationDefinitionConstraint {
    pub fields: Vec<OpenID4VPPresentationDefinitionConstraintField>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub validity_credential_nbf: Option<OffsetDateTime>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VPPresentationDefinitionConstraintField {
    pub id: Option<ClaimSchemaId>,
    pub path: Vec<String>,
    pub optional: Option<bool>,
    pub filter: Option<OpenID4VPPresentationDefinitionConstraintFieldFilter>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VPPresentationDefinitionConstraintFieldFilter {
    pub r#type: String,
    pub r#const: String,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct OpenID4VPInteractionData {
    pub response_type: String,
    pub state: Option<String>,
    pub nonce: String,
    pub client_id_scheme: String,
    pub client_id: Url,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub client_metadata: Option<OpenID4VPClientMetadata>,
    pub client_metadata_uri: Option<Url>,
    pub response_mode: String,
    pub response_uri: Url,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub presentation_definition: Option<OpenID4VPPresentationDefinition>,
    pub presentation_definition_uri: Option<Url>,

    #[serde(skip_serializing)]
    pub redirect_uri: Option<String>,
}
