use one_core::service::error::ServiceError;
use one_core::service::proof_schema::dto::{
    CreateProofSchemaClaimRequestDTO, CreateProofSchemaRequestDTO, GetProofSchemaListItemDTO,
    GetProofSchemaResponseDTO, ImportProofSchemaClaimSchemaDTO,
    ImportProofSchemaCredentialSchemaDTO, ImportProofSchemaDTO, ImportProofSchemaInputSchemaDTO,
    ImportProofSchemaRequestDTO, ProofClaimSchemaResponseDTO, ProofInputSchemaRequestDTO,
    ProofInputSchemaResponseDTO, ProofSchemaShareResponseDTO,
};
use one_dto_mapper::{From, Into, TryInto, convert_inner, try_convert_inner};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{OrganisationId, ProofSchemaId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

use crate::dto::common::{ExactColumn, ListQueryParamsRest};
use crate::endpoint::credential_schema::dto::{
    CredentialSchemaLayoutPropertiesRestDTO, CredentialSchemaLayoutType,
    CredentialSchemaListItemResponseRestDTO, CredentialSchemaType, WalletStorageTypeRestEnum,
};
use crate::serialize::{front_time, front_time_option};

#[skip_serializing_none]
#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema, Validate, Into)]
#[into(CreateProofSchemaRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct CreateProofSchemaRequestRestDTO {
    #[validate(length(min = 1))]
    #[schema(min_length = 1)]
    pub name: String,
    /// Specify the organization.
    pub organisation_id: Uuid,
    /// Defines the length of storage of received proofs, in seconds. After
    /// the defined duration, the received proof and its data are deleted
    /// from the system. If 0, the proofs received when using this proof
    /// schema will not be deleted.
    pub expire_duration: Option<u32>,
    #[into(with_fn = convert_inner)]
    #[schema(min_items = 1)]
    pub proof_input_schemas: Vec<ProofInputSchemaRequestRestDTO>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema, Validate, Into)]
#[into(ProofInputSchemaRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct ProofInputSchemaRequestRestDTO {
    /// ID of the credential schema from which the `claimSchemas` object
    /// is assembled.
    pub credential_schema_id: Uuid,
    /// Defines the maximum age at which an LVVC will be validated.
    pub validity_constraint: Option<i64>,
    /// Defines the set of attributes being requested when making proof requests using this schema.
    #[into(with_fn = convert_inner)]
    #[schema(min_items = 1)]
    pub claim_schemas: Vec<ClaimProofSchemaRequestRestDTO>,
}

/// Defines the set of attributes being requested when making proof requests
/// using this schema.
#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(CreateProofSchemaClaimRequestDTO)]
pub struct ClaimProofSchemaRequestRestDTO {
    /// The `id` of the attribute being requested, from the `claims` object.
    pub id: Uuid,
    /// Whether the attribute is required in the proof request.
    pub required: bool,
}

#[derive(Clone, Debug, Deserialize, ToSchema, TryInto)]
#[try_into(T=ImportProofSchemaRequestDTO, Error=ServiceError)]
#[serde(rename_all = "camelCase")]
pub struct ImportProofSchemaRequestRestDTO {
    #[try_into(infallible)]
    pub organisation_id: Uuid,
    pub schema: ImportProofSchemaRestDTO,
}

#[derive(Clone, Debug, Deserialize, ToSchema, TryInto)]
#[try_into(T=ImportProofSchemaDTO, Error=ServiceError)]
#[serde(rename_all = "camelCase")]
pub struct ImportProofSchemaRestDTO {
    #[try_into(infallible)]
    pub id: ProofSchemaId,
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    #[try_into(infallible)]
    pub created_date: OffsetDateTime,
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    #[try_into(infallible)]
    pub last_modified: OffsetDateTime,
    #[try_into(infallible)]
    pub name: String,
    #[try_into(infallible)]
    pub imported_source_url: String,
    #[try_into(infallible)]
    pub organisation_id: OrganisationId,
    #[try_into(infallible)]
    pub expire_duration: u32,
    #[try_into(with_fn = try_convert_inner)]
    pub proof_input_schemas: Vec<ImportProofSchemaInputSchemaRestDTO>,
}

#[derive(Clone, Debug, Deserialize, ToSchema, TryInto)]
#[try_into(T=ImportProofSchemaInputSchemaDTO, Error=ServiceError)]
#[serde(rename_all = "camelCase")]
pub struct ImportProofSchemaInputSchemaRestDTO {
    #[try_into(with_fn = convert_inner, infallible)]
    pub claim_schemas: Vec<ImportProofSchemaClaimSchemaRestDTO>,
    pub credential_schema: ImportProofSchemaCredentialSchemaRestDTO,
    #[try_into(with_fn = convert_inner, infallible)]
    pub validity_constraint: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(ImportProofSchemaClaimSchemaDTO)]
#[serde(rename_all = "camelCase")]
pub struct ImportProofSchemaClaimSchemaRestDTO {
    pub id: Uuid,
    pub requested: bool,
    pub required: bool,
    pub key: String,
    #[schema(example = "STRING")]
    pub data_type: String,
    #[into(with_fn = convert_inner)]
    #[serde(default)]
    #[schema(no_recursion)]
    pub claims: Vec<ImportProofSchemaClaimSchemaRestDTO>,
    pub array: bool,
}

#[derive(Clone, Debug, Deserialize, ToSchema, TryInto)]
#[try_into(T=ImportProofSchemaCredentialSchemaDTO, Error=ServiceError)]
#[serde(rename_all = "camelCase")]
pub struct ImportProofSchemaCredentialSchemaRestDTO {
    #[try_into(infallible)]
    pub id: Uuid,
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    #[try_into(infallible)]
    pub created_date: OffsetDateTime,
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    #[try_into(infallible)]
    pub last_modified: OffsetDateTime,
    #[try_into(infallible)]
    pub name: String,
    #[try_into(infallible)]
    pub format: String,
    #[try_into(infallible)]
    pub revocation_method: String,
    #[try_into(infallible)]
    pub imported_source_url: String,
    #[try_into(with_fn = convert_inner, infallible)]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
    #[try_into(infallible)]
    pub schema_id: String,
    #[try_into(infallible)]
    pub schema_type: CredentialSchemaType,
    #[try_into(with_fn = convert_inner, infallible)]
    pub layout_type: Option<CredentialSchemaLayoutType>,
    #[try_into(with_fn = try_convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
}

// list endpoint
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into("one_core::model::proof_schema::SortableProofSchemaColumn")]
pub enum SortableProofSchemaColumnRestEnum {
    Name,
    CreatedDate,
}

pub type GetProofSchemaQuery =
    ListQueryParamsRest<ProofSchemasFilterQueryParamsRest, SortableProofSchemaColumnRestEnum>;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct ProofSchemasFilterQueryParamsRest {
    /// Specify the organization from which to return proof schemas.
    pub organisation_id: OrganisationId,
    /// Return only proof schemas with a name starting with this string.
    /// Not case-sensitive.
    #[param(nullable = false)]
    pub name: Option<String>,
    /// Specify proof schemas to be returned by their UUID.
    #[param(rename = "ids[]", inline, nullable = false)]
    pub ids: Option<Vec<ProofSchemaId>>,
    /// Set which filters apply in an exact way.
    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<ExactColumn>>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(GetProofSchemaListItemDTO)]
pub struct GetProofSchemaListItemResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub deleted_at: Option<OffsetDateTime>,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    /// The duration of storage of received proofs, in seconds. After the defined duration, the received proof and its data are deleted from the system.
    /// If 0, the proofs received when using this proof schema will not be deleted.
    pub expire_duration: u32,
}

// detail endpoint
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(GetProofSchemaResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct GetProofSchemaResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub expire_duration: u32,
    pub imported_source_url: Option<String>,
    pub organisation_id: Uuid,
    #[from(with_fn = convert_inner)]
    pub proof_input_schemas: Vec<ProofInputSchemaResponseRestDTO>,
}

/// The set of attributes being requested when using this proof schema.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ProofClaimSchemaResponseDTO)]
pub struct ProofClaimSchemaResponseRestDTO {
    pub id: Uuid,
    /// Marking attributes that are targeted with proof request
    pub requested: bool,
    /// Requested as mandatory or optional
    pub required: bool,
    pub key: String,
    /// The type of data accepted for this attribute.
    #[schema(example = "STRING")]
    pub data_type: String,
    #[from(with_fn = convert_inner)]
    #[schema(no_recursion)]
    pub claims: Vec<ProofClaimSchemaResponseRestDTO>,
    pub array: bool,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ProofInputSchemaResponseDTO)]
pub struct ProofInputSchemaResponseRestDTO {
    /// Defines the set of attributes being requested when making proof requests using this schema.
    #[from(with_fn = convert_inner)]
    pub claim_schemas: Vec<ProofClaimSchemaResponseRestDTO>,
    pub credential_schema: CredentialSchemaListItemResponseRestDTO,
    /// Defines the maximum age at which an LVVC will be validated.
    pub validity_constraint: Option<i64>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ProofSchemaShareResponseDTO)]
pub struct ProofSchemaShareResponseRestDTO {
    pub url: String,
}
