use std::collections::HashMap;

use one_core::model::proof::{ProofStateEnum, SortableProofColumn};
use one_core::provider::exchange_protocol::dto::{
    PresentationDefinitionFieldDTO, PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum,
};
use one_core::provider::exchange_protocol::openid4vc::model::ClientIdSchemaType;
use one_core::service::proof::dto::{
    CreateProofRequestDTO, ProofClaimDTO, ProofClaimValueDTO, ProofDetailResponseDTO,
    ProofInputDTO, ProofListItemResponseDTO, ScanToVerifyBarcodeTypeEnum, ScanToVerifyRequestDTO,
    ShareProofRequestDTO, ShareProofRequestParamsDTO,
};
use one_dto_mapper::{convert_inner, From, Into};
use serde::{Deserialize, Serialize};
use shared_types::{DidId, KeyId, OrganisationId, ProofId, ProofSchemaId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::dto::common::{ExactColumn, ListQueryParamsRest};
use crate::endpoint::credential::dto::GetCredentialResponseRestDTO;
use crate::endpoint::credential_schema::dto::CredentialSchemaListItemResponseRestDTO;
use crate::endpoint::did::dto::DidListItemResponseRestDTO;
use crate::endpoint::proof_schema::dto::{
    GetProofSchemaListItemResponseRestDTO, ProofClaimSchemaResponseRestDTO,
};
use crate::serialize::{front_time, front_time_option};

/// The state representation of the proof request in the system.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, ToSchema, From, Into)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from(ProofStateEnum)]
#[into(ProofStateEnum)]
pub enum ProofStateRestEnum {
    Created,
    Pending,
    Requested,
    Accepted,
    Rejected,
    Error,
}

/// Exchange protocol being used.
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(CreateProofRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct CreateProofRequestRestDTO {
    /// ID of the proof schema used to request the proof.
    pub proof_schema_id: ProofSchemaId,
    #[into(rename = "verifier_did_id")]
    #[schema(example = "<uuid; did identifier>")]
    pub verifier_did: DidId,
    /// Specify the exchange protocol to use for credential exchange. Check
    /// the `exchange` object of the configuration for supported options and
    /// reference the configuration instance.
    #[schema(example = "OPENID4VC")]
    pub exchange: String,
    /// When a shared proof is accepted, the holder will be redirected to
    /// the resource specified here, if redirects are enabled in the system
    /// configuration. The URI must use a scheme (for example `https`, `myapp`)
    /// that is allowed by the system configuration.
    pub redirect_uri: Option<String>,
    /// If multiple keys are specified for the authentication method of the
    /// DID, use this value to specify which key should be used as the
    /// authentication method for this proof request. If a key isn't
    /// specified here, the first key listed during DID creation will be
    /// used.
    pub verifier_key: Option<KeyId>,
    /// Only for use when verifying VC Barcodes.
    #[into(with_fn = convert_inner)]
    pub scan_to_verify: Option<ScanToVerifyRequestRestDTO>,
    /// Not for use via the API; for ISO mDL verification over BLE using the
    /// SDK.
    #[into(with_fn = convert_inner)]
    pub iso_mdl_engagement: Option<String>,
    /// Specify the transport protocol to use for credential exchange. Check
    /// the `transport` object of the configuration for supported options and
    /// reference the configuration instance.
    #[into(with_fn = convert_inner)]
    #[schema(example = "HTTP")]
    pub transport: Option<Vec<String>>,
}

/// Only for use when verifying VC Barcodes.
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(ScanToVerifyRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct ScanToVerifyRequestRestDTO {
    pub credential: String,
    pub barcode: String,
    pub barcode_type: ScanToVerifyBarcodeTypeRestEnum,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[into(ScanToVerifyBarcodeTypeEnum)]
pub enum ScanToVerifyBarcodeTypeRestEnum {
    MRZ,
    PDF417,
}

// list endpoint
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(SortableProofColumn)]
pub enum SortableProofColumnRestEnum {
    #[serde(rename = "schema.name")]
    SchemaName,
    VerifierDid,
    CreatedDate,
    State,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct ProofsFilterQueryParamsRest {
    /// Specify the organization from which to return proof requests.
    pub organisation_id: OrganisationId,
    /// Return only proof requests with a name starting with this string.
    /// Not case-sensitive.
    #[param(nullable = false)]
    pub name: Option<String>,
    /// Return proof requests according to their current state in the system.
    #[param(rename = "proofStates[]", inline, nullable = false)]
    pub proof_states: Option<Vec<ProofStateRestEnum>>,
    /// Filter proof requests by their associated proof schema. Pass an array
    /// of UUID strings.
    #[param(rename = "proofSchemaIds[]", inline, nullable = false)]
    pub proof_schema_ids: Option<Vec<ProofSchemaId>>,
    /// Specify proof requests to be returned by their UUID.
    #[param(rename = "ids[]", inline, nullable = false)]
    pub ids: Option<Vec<ProofId>>,
    /// Set which filters apply in an exact way.
    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<ExactColumn>>,
}

pub type GetProofQuery =
    ListQueryParamsRest<ProofsFilterQueryParamsRest, SortableProofColumnRestEnum>;

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(ProofListItemResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct ProofListItemResponseRestDTO {
    pub id: Uuid,

    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,

    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,

    /// When proof request was shared.
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub issuance_date: OffsetDateTime,

    /// When proof request state changed from `PENDING` to `REQUESTED`.
    /// Not supported in all exchange protocols.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub requested_date: Option<OffsetDateTime>,

    /// Time at which the data shared by the holder for this proof request will be deleted.
    /// Determined by the `expireDuration` parameter of the proof schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub retain_until_date: Option<OffsetDateTime>,

    /// When holder submitted valid proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub completed_date: Option<OffsetDateTime>,

    #[from(with_fn = convert_inner)]
    pub verifier_did: Option<DidListItemResponseRestDTO>,
    pub exchange: String,
    /// Exchange protocol being used.
    pub transport: String,
    pub state: ProofStateRestEnum,
    #[from(with_fn = convert_inner)]
    pub schema: Option<GetProofSchemaListItemResponseRestDTO>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(PresentationDefinitionResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct PresentationDefinitionResponseRestDTO {
    #[from(with_fn = convert_inner)]
    pub request_groups: Vec<PresentationDefinitionRequestGroupResponseRestDTO>,
    #[from(with_fn = convert_inner)]
    pub credentials: Vec<GetCredentialResponseRestDTO>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(PresentationDefinitionRequestGroupResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct PresentationDefinitionRequestGroupResponseRestDTO {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    pub rule: PresentationDefinitionRuleRestDTO,
    #[from(with_fn = convert_inner)]
    pub requested_credentials: Vec<PresentationDefinitionRequestedCredentialResponseRestDTO>,
}

/// Summary of the credentials requested by the verifier, including suitable
/// credentials filtered from the wallet.
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(PresentationDefinitionRequestedCredentialResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct PresentationDefinitionRequestedCredentialResponseRestDTO {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[from(with_fn = convert_inner)]
    pub fields: Vec<PresentationDefinitionFieldRestDTO>,
    #[from(with_fn = convert_inner)]
    pub applicable_credentials: Vec<String>,
    #[from(with_fn = convert_inner)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub inapplicable_credentials: Vec<String>,
    #[serde(
        serialize_with = "front_time_option",
        skip_serializing_if = "Option::is_none"
    )]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    validity_credential_nbf: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(PresentationDefinitionFieldDTO)]
pub struct PresentationDefinitionFieldRestDTO {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    pub key_map: HashMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema, From)]
#[from(PresentationDefinitionRuleTypeEnum)]
pub enum PresentationDefinitionRuleTypeRestEnum {
    #[serde(rename = "all")]
    All,
    #[serde(rename = "pick")]
    Pick,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(PresentationDefinitionRuleDTO)]
pub struct PresentationDefinitionRuleRestDTO {
    pub r#type: PresentationDefinitionRuleTypeRestEnum,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
}

// detail endpoint
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(ProofDetailResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct ProofDetailResponseRestDTO {
    pub id: Uuid,

    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,

    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,

    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub issuance_date: OffsetDateTime,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub requested_date: Option<OffsetDateTime>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub retain_until_date: Option<OffsetDateTime>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub completed_date: Option<OffsetDateTime>,

    #[from(with_fn = convert_inner)]
    pub verifier_did: Option<DidListItemResponseRestDTO>,
    #[from(with_fn = convert_inner)]
    pub holder_did: Option<DidListItemResponseRestDTO>,
    pub exchange: String,
    pub transport: String,
    pub state: ProofStateRestEnum,
    #[from(with_fn = convert_inner)]
    pub organisation_id: Option<Uuid>,
    #[from(with_fn = convert_inner)]
    pub schema: Option<GetProofSchemaListItemResponseRestDTO>,
    pub redirect_uri: Option<String>,
    #[from(with_fn = convert_inner)]
    pub proof_inputs: Vec<ProofInputRestDTO>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub claims_removed_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ProofClaimDTO)]
pub struct ProofClaimRestDTO {
    pub schema: ProofClaimSchemaResponseRestDTO,
    #[from(with_fn = convert_inner)]
    pub value: Option<ProofClaimValueRestDTO>,
    pub path: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(ProofClaimValueDTO)]
#[serde(untagged)]
pub enum ProofClaimValueRestDTO {
    Value(String),
    #[schema(no_recursion)]
    Claims(#[from(with_fn = convert_inner)] Vec<ProofClaimRestDTO>),
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ProofInputDTO)]
pub struct ProofInputRestDTO {
    /// The set of claims being asserted by the credential shared during the
    /// proof request.
    #[from(with_fn = convert_inner)]
    pub claims: Vec<ProofClaimRestDTO>,
    /// The credentials exchanged as part of the successfully shared proof.
    #[from(with_fn = convert_inner)]
    pub credential: Option<GetCredentialResponseRestDTO>,
    pub credential_schema: CredentialSchemaListItemResponseRestDTO,
    /// Defines the maximum age at which an LVVC will be validated.
    pub validity_constraint: Option<i64>,
}

#[derive(Clone, Debug, Default, Deserialize, ToSchema, Into)]
#[into(ShareProofRequestDTO)]
pub struct ShareProofRequestRestDTO {
    #[into(with_fn = "convert_inner")]
    #[serde(default)]
    pub params: Option<ShareProofRequestParamsRestDTO>,
}

#[derive(Clone, Debug, Default, Deserialize, ToSchema, Into)]
#[into(ShareProofRequestParamsDTO)]
#[serde(rename_all = "camelCase")]
pub struct ShareProofRequestParamsRestDTO {
    #[into(with_fn = "convert_inner")]
    #[serde(default)]
    pub client_id_schema: Option<ClientIdSchemaTypeRestDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From, Into)]
#[from(ClientIdSchemaType)]
#[into(ClientIdSchemaType)]
#[serde(rename_all = "snake_case")]
pub enum ClientIdSchemaTypeRestDTO {
    RedirectUri,
    VerifierAttestation,
    Did,
    X509SanDns,
}
