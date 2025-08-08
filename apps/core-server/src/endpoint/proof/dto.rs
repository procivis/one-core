use std::collections::HashMap;

use one_core::model::proof::{ProofRole, ProofStateEnum, SortableProofColumn};
use one_core::provider::verification_protocol::dto::{
    PresentationDefinitionFieldDTO, PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum,
};
use one_core::provider::verification_protocol::openid4vp::model::ClientIdScheme;
use one_core::service::proof::dto::{
    CreateProofRequestDTO, ProofClaimDTO, ProofClaimValueDTO, ProofDetailResponseDTO,
    ProofInputDTO, ProofListItemResponseDTO, ScanToVerifyBarcodeTypeEnum, ScanToVerifyRequestDTO,
    ShareProofRequestDTO, ShareProofRequestParamsDTO,
};
use one_dto_mapper::{From, Into, TryFrom, convert_inner, try_convert_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::{
    CertificateId, DidId, IdentifierId, KeyId, OrganisationId, ProofId, ProofSchemaId,
};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};

use crate::deserialize::deserialize_timestamp;
use crate::dto::common::{ExactColumn, ListQueryParamsRest};
use crate::endpoint::certificate::dto::CertificateResponseRestDTO;
use crate::endpoint::credential::dto::GetCredentialResponseRestDTO;
use crate::endpoint::credential_schema::dto::CredentialSchemaListItemResponseRestDTO;
use crate::endpoint::identifier::dto::GetIdentifierListItemResponseRestDTO;
use crate::endpoint::proof_schema::dto::{
    GetProofSchemaListItemResponseRestDTO, ProofClaimSchemaResponseRestDTO,
};
use crate::mapper::MapperError;
use crate::serialize::{front_time, front_time_option};

/// The state representation of the proof request in the system.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, ToSchema, From, Into)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from(ProofStateEnum)]
#[into(ProofStateEnum)]
pub(crate) enum ProofStateRestEnum {
    Created,
    Pending,
    Requested,
    Accepted,
    Rejected,
    Retracted,
    Error,
}

/// The role the system has in relation to the proof.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, ToSchema, From, Into)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from(ProofRole)]
#[into(ProofRole)]
pub(crate) enum ProofRoleRestEnum {
    Holder,
    Verifier,
}

#[options_not_nullable(skip_serializing_none = false)]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(CreateProofRequestDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateProofRequestRestDTO {
    /// Choose a proof schema to use.
    pub proof_schema_id: ProofSchemaId,
    #[into(rename = "verifier_did_id")]
    #[schema(
        example = "<uuid; did identifier>",
        nullable = false,
        deprecated = true
    )]
    /// Choose a DID to use as an identifier.
    pub verifier_did: Option<DidId>,
    #[into(rename = "verifier_identifier_id")]
    #[schema(example = "<uuid; identifier id>", nullable = false)]
    /// Choose an identifier to use when making the request.
    pub verifier: Option<IdentifierId>,
    /// Specify the verification protocol to use for credential exchange. Check
    /// the `verificationProtocol` object of the configuration for supported options and
    /// reference the configuration instance.
    #[schema(example = "OPENID4VP_DRAFT20")]
    pub protocol: String,
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
    /// If multiple active certificates are available under the verifier,
    /// use this value to specify which certificate should be used
    /// for this proof request. If a certificate isn't specified here,
    /// an active certificate will be used.
    pub verifier_certificate: Option<CertificateId>,
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
    #[schema(example = json!(["HTTP"]), nullable = false)]
    pub transport: Option<Vec<String>>,
    /// Optional profile to associate with this proof request
    pub profile: Option<String>,
}

/// Only for use when verifying VC Barcodes.
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(ScanToVerifyRequestDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScanToVerifyRequestRestDTO {
    pub credential: String,
    pub barcode: String,
    pub barcode_type: ScanToVerifyBarcodeTypeRestEnum,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[into(ScanToVerifyBarcodeTypeEnum)]
pub(crate) enum ScanToVerifyBarcodeTypeRestEnum {
    #[allow(clippy::upper_case_acronyms)]
    MRZ,
    PDF417,
}

// list endpoint
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(SortableProofColumn)]
pub(crate) enum SortableProofColumnRestEnum {
    #[serde(rename = "schema.name")]
    SchemaName,
    Verifier,
    CreatedDate,
    State,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProofsFilterQueryParamsRest {
    /// Specify the organization from which to return proof requests.
    pub organisation_id: OrganisationId,
    /// Return only proof requests with a name starting with this string.
    /// Not case-sensitive.
    #[param(nullable = false)]
    pub name: Option<String>,
    /// Return only proof requests with the specified profile.
    #[param(nullable = false)]
    pub profile: Option<String>,
    /// Return proof requests according to their current state in the system.
    #[param(rename = "proofStates[]", inline, nullable = false)]
    pub proof_states: Option<Vec<ProofStateRestEnum>>,
    /// Return proof requests according to their current role in the system.
    #[param(rename = "proofRoles[]", inline, nullable = false)]
    pub proof_roles: Option<Vec<ProofRoleRestEnum>>,
    /// Filter proof requests by their associated proof schema. Pass an array
    /// of UUID strings.
    #[param(rename = "proofSchemaIds[]", inline, nullable = false)]
    pub proof_schema_ids: Option<Vec<ProofSchemaId>>,
    /// Specify proof requests to return by their UUID.
    #[param(rename = "ids[]", inline, nullable = false)]
    pub ids: Option<Vec<ProofId>>,
    /// Set which filters apply in an exact way.
    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<ExactColumn>>,

    /// Return only proof requests which were created after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only proof requests which were created before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only proof requests which were last modified after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub last_modified_after: Option<OffsetDateTime>,
    /// Return only proof requests which were last modified before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub last_modified_before: Option<OffsetDateTime>,
    /// Return only proof requests which were requested after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub requested_date_after: Option<OffsetDateTime>,
    /// Return only proof requests which were requested before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub requested_date_before: Option<OffsetDateTime>,
    /// Return only proof requests which were completed after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub completed_date_after: Option<OffsetDateTime>,
    /// Return only proof requests which were completed before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub completed_date_before: Option<OffsetDateTime>,
}

pub(crate) type GetProofQuery =
    ListQueryParamsRest<ProofsFilterQueryParamsRest, SortableProofColumnRestEnum>;

#[options_not_nullable]
#[derive(Debug, Serialize, ToSchema, From)]
#[from(ProofListItemResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProofListItemResponseRestDTO {
    pub id: ProofId,

    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,

    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,

    /// When proof request state changed from `PENDING` to `REQUESTED`.
    /// Not supported in all exchange protocols.
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub requested_date: Option<OffsetDateTime>,

    /// Time at which the data shared by the holder for this proof request will be deleted.
    /// Determined by the `expireDuration` parameter of the proof schema.
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub retain_until_date: Option<OffsetDateTime>,

    /// When holder submitted valid proof.
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub completed_date: Option<OffsetDateTime>,

    #[from(with_fn = convert_inner)]
    pub verifier: Option<GetIdentifierListItemResponseRestDTO>,

    /// Verification protocol used.
    pub protocol: String,
    /// Transport protocol used.
    pub transport: String,
    pub state: ProofStateRestEnum,
    pub role: ProofRoleRestEnum,
    #[from(with_fn = convert_inner)]
    pub schema: Option<GetProofSchemaListItemResponseRestDTO>,
    /// Profile associated with this proof request
    #[from(with_fn = convert_inner)]
    pub profile: Option<String>,
}

#[derive(Debug, Serialize, ToSchema, TryFrom)]
#[try_from(T = PresentationDefinitionResponseDTO, Error = MapperError)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PresentationDefinitionResponseRestDTO {
    #[try_from(with_fn = convert_inner, infallible)]
    pub request_groups: Vec<PresentationDefinitionRequestGroupResponseRestDTO>,
    #[try_from(with_fn = try_convert_inner)]
    pub credentials: Vec<GetCredentialResponseRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(PresentationDefinitionRequestGroupResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PresentationDefinitionRequestGroupResponseRestDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub rule: PresentationDefinitionRuleRestDTO,
    #[from(with_fn = convert_inner)]
    pub requested_credentials: Vec<PresentationDefinitionRequestedCredentialResponseRestDTO>,
}

/// Summary of the credentials requested by the verifier, including suitable
/// credentials filtered from the wallet.
#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(PresentationDefinitionRequestedCredentialResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PresentationDefinitionRequestedCredentialResponseRestDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    #[from(with_fn = convert_inner)]
    pub fields: Vec<PresentationDefinitionFieldRestDTO>,
    #[from(with_fn = convert_inner)]
    pub applicable_credentials: Vec<String>,
    #[from(with_fn = convert_inner)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub inapplicable_credentials: Vec<String>,
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    validity_credential_nbf: Option<OffsetDateTime>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(PresentationDefinitionFieldDTO)]
pub(crate) struct PresentationDefinitionFieldRestDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub required: Option<bool>,
    pub key_map: HashMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema, From)]
#[from(PresentationDefinitionRuleTypeEnum)]
pub(crate) enum PresentationDefinitionRuleTypeRestEnum {
    #[serde(rename = "all")]
    All,
    #[serde(rename = "pick")]
    Pick,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(PresentationDefinitionRuleDTO)]
pub(crate) struct PresentationDefinitionRuleRestDTO {
    pub r#type: PresentationDefinitionRuleTypeRestEnum,
    pub min: Option<u32>,
    pub max: Option<u32>,
    pub count: Option<u32>,
}

// detail endpoint
#[options_not_nullable]
#[derive(Debug, Serialize, ToSchema, TryFrom)]
#[try_from(T = ProofDetailResponseDTO, Error = MapperError)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProofDetailResponseRestDTO {
    #[try_from(infallible)]
    pub id: ProofId,

    #[try_from(infallible)]
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,

    #[try_from(infallible)]
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,

    #[try_from(infallible)]
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub requested_date: Option<OffsetDateTime>,

    #[try_from(infallible)]
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub retain_until_date: Option<OffsetDateTime>,

    #[try_from(infallible)]
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub completed_date: Option<OffsetDateTime>,

    #[try_from(with_fn = convert_inner, infallible)]
    pub verifier: Option<GetIdentifierListItemResponseRestDTO>,

    #[try_from(with_fn = try_convert_inner)]
    pub verifier_certificate: Option<CertificateResponseRestDTO>,

    #[try_from(with_fn = convert_inner, infallible)]
    pub holder: Option<GetIdentifierListItemResponseRestDTO>,

    #[try_from(infallible)]
    pub protocol: String,

    #[try_from(infallible)]
    pub transport: String,

    #[try_from(infallible)]
    pub state: ProofStateRestEnum,

    #[try_from(infallible)]
    pub role: ProofRoleRestEnum,

    #[try_from(infallible)]
    pub organisation_id: OrganisationId,

    #[try_from(with_fn = convert_inner, infallible)]
    pub schema: Option<GetProofSchemaListItemResponseRestDTO>,

    #[try_from(with_fn = convert_inner, infallible)]
    pub redirect_uri: Option<String>,

    #[try_from(with_fn = try_convert_inner)]
    pub proof_inputs: Vec<ProofInputRestDTO>,

    #[try_from(infallible)]
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub claims_removed_at: Option<OffsetDateTime>,

    #[try_from(with_fn = convert_inner, infallible)]
    pub profile: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ProofClaimDTO)]
pub(crate) struct ProofClaimRestDTO {
    pub schema: ProofClaimSchemaResponseRestDTO,
    #[from(with_fn = convert_inner)]
    pub value: Option<ProofClaimValueRestDTO>,
    pub path: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(ProofClaimValueDTO)]
#[serde(untagged)]
pub(crate) enum ProofClaimValueRestDTO {
    Value(String),
    #[schema(no_recursion)]
    Claims(#[from(with_fn = convert_inner)] Vec<ProofClaimRestDTO>),
}

#[options_not_nullable]
#[derive(Debug, Serialize, ToSchema, TryFrom)]
#[serde(rename_all = "camelCase")]
#[try_from(T = ProofInputDTO, Error = MapperError)]
pub(crate) struct ProofInputRestDTO {
    /// The set of claims being asserted by the credential shared during the
    /// proof request.
    #[try_from(with_fn = convert_inner, infallible)]
    pub claims: Vec<ProofClaimRestDTO>,

    /// The credentials exchanged as part of the successfully shared proof.
    #[try_from(with_fn = try_convert_inner)]
    pub credential: Option<GetCredentialResponseRestDTO>,

    #[try_from(infallible)]
    pub credential_schema: CredentialSchemaListItemResponseRestDTO,

    /// Defines the maximum age at which an LVVC will be validated.
    #[try_from(with_fn = convert_inner, infallible)]
    pub validity_constraint: Option<i64>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Default, Deserialize, ToSchema, Into)]
#[into(ShareProofRequestDTO)]
pub(crate) struct ShareProofRequestRestDTO {
    #[into(with_fn = "convert_inner")]
    #[serde(default)]
    pub params: Option<ShareProofRequestParamsRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Default, Deserialize, ToSchema, Into)]
#[into(ShareProofRequestParamsDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ShareProofRequestParamsRestDTO {
    #[into(with_fn = "convert_inner")]
    #[serde(default)]
    pub client_id_scheme: Option<ClientIdSchemeRestEnum>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From, Into)]
#[from(ClientIdScheme)]
#[into(ClientIdScheme)]
#[serde(rename_all = "snake_case")]
pub enum ClientIdSchemeRestEnum {
    RedirectUri,
    VerifierAttestation,
    /// Accepts both "did" and "decentralized_identifier" as valid values.
    /// Swagger UI will show decentralized_identifier as the value.
    #[serde(rename = "decentralized_identifier", alias = "did")]
    Did,
    X509SanDns,
}
