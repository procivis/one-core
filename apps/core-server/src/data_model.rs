use one_core::data_layer::data_model::{
    ClaimProofSchemaRequest, CreateCredentialSchemaRequest, CreateOrganisationRequest,
    CreateOrganisationResponse, CreateProofSchemaRequest, CreateProofSchemaResponse,
    CredentialClaimSchemaRequest, CredentialClaimSchemaResponse, CredentialSchemaResponse,
    GetCredentialClaimSchemaResponse, GetProofSchemaResponse, ProofClaimSchemaResponse,
    ProofSchemaResponse,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

// TODO create proper serialization function when
time::serde::format_description!(
    front_time,
    OffsetDateTime,
    "[year]-[month]-[day padding:zero]T[hour padding:zero]:[minute padding:zero]:[second padding:zero].000Z"
);

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Format {
    #[default]
    Jwt,
    SdJwt,
    JsonLd,
    Mdoc,
}

impl From<Format> for one_core::data_layer::data_model::Format {
    fn from(value: Format) -> Self {
        match value {
            Format::Jwt => one_core::data_layer::data_model::Format::Jwt,
            Format::SdJwt => one_core::data_layer::data_model::Format::SdJwt,
            Format::JsonLd => one_core::data_layer::data_model::Format::JsonLd,
            Format::Mdoc => one_core::data_layer::data_model::Format::Mdoc,
        }
    }
}

impl From<one_core::data_layer::data_model::Format> for Format {
    fn from(value: one_core::data_layer::data_model::Format) -> Self {
        match value {
            one_core::data_layer::data_model::Format::Jwt => Format::Jwt,
            one_core::data_layer::data_model::Format::SdJwt => Format::SdJwt,
            one_core::data_layer::data_model::Format::JsonLd => Format::JsonLd,
            one_core::data_layer::data_model::Format::Mdoc => Format::Mdoc,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum RevocationMethod {
    #[default]
    StatusList2021,
    Lvvc,
}

impl From<RevocationMethod> for one_core::data_layer::data_model::RevocationMethod {
    fn from(value: RevocationMethod) -> Self {
        match value {
            RevocationMethod::StatusList2021 => {
                one_core::data_layer::data_model::RevocationMethod::StatusList2021
            }
            RevocationMethod::Lvvc => one_core::data_layer::data_model::RevocationMethod::Lvvc,
        }
    }
}

impl From<one_core::data_layer::data_model::RevocationMethod> for RevocationMethod {
    fn from(value: one_core::data_layer::data_model::RevocationMethod) -> Self {
        match value {
            one_core::data_layer::data_model::RevocationMethod::StatusList2021 => {
                RevocationMethod::StatusList2021
            }
            one_core::data_layer::data_model::RevocationMethod::Lvvc => RevocationMethod::Lvvc,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum Datatype {
    #[default]
    String,
    Date,
    Number,
}

impl From<Datatype> for one_core::data_layer::data_model::Datatype {
    fn from(value: Datatype) -> Self {
        match value {
            Datatype::String => one_core::data_layer::data_model::Datatype::String,
            Datatype::Date => one_core::data_layer::data_model::Datatype::Date,
            Datatype::Number => one_core::data_layer::data_model::Datatype::Number,
        }
    }
}

impl From<one_core::data_layer::data_model::Datatype> for Datatype {
    fn from(value: one_core::data_layer::data_model::Datatype) -> Self {
        match value {
            one_core::data_layer::data_model::Datatype::String => Datatype::String,
            one_core::data_layer::data_model::Datatype::Date => Datatype::Date,
            one_core::data_layer::data_model::Datatype::Number => Datatype::Number,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, ToSchema)]
pub enum SortDirection {
    #[serde(rename = "ASC")]
    Ascending,
    #[serde(rename = "DESC")]
    Descending,
}

impl From<SortDirection> for one_core::data_layer::data_model::SortDirection {
    fn from(value: SortDirection) -> Self {
        match value {
            SortDirection::Ascending => one_core::data_layer::data_model::SortDirection::Ascending,
            SortDirection::Descending => {
                one_core::data_layer::data_model::SortDirection::Descending
            }
        }
    }
}

#[derive(Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct GetListQueryParams<T> {
    // pagination
    pub page: u32,
    pub page_size: u32,

    // sorting
    #[param(value_type = Option<String>)]
    pub sort: Option<T>,
    pub sort_direction: Option<SortDirection>,

    // filtering
    pub name: Option<String>,
    pub organisation_id: String,
}

impl<T, K> From<GetListQueryParams<T>> for one_core::data_layer::data_model::GetListQueryParams<K>
where
    K: From<T>,
{
    fn from(value: GetListQueryParams<T>) -> Self {
        Self {
            page: value.page,
            page_size: value.page_size,
            sort: value.sort.map(|sort| sort.into()),
            sort_direction: value.sort_direction.map(|dir| dir.into()),
            name: value.name,
            organisation_id: value.organisation_id,
        }
    }
}

pub type GetCredentialSchemaQuery = GetListQueryParams<SortableCredentialSchemaColumn>;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum SortableCredentialSchemaColumn {
    Name,
    Format,
    CreatedDate,
}

impl From<SortableCredentialSchemaColumn>
    for one_core::data_layer::data_model::SortableCredentialSchemaColumn
{
    fn from(value: SortableCredentialSchemaColumn) -> Self {
        match value {
            SortableCredentialSchemaColumn::Name => {
                one_core::data_layer::data_model::SortableCredentialSchemaColumn::Name
            }
            SortableCredentialSchemaColumn::Format => {
                one_core::data_layer::data_model::SortableCredentialSchemaColumn::Format
            }
            SortableCredentialSchemaColumn::CreatedDate => {
                one_core::data_layer::data_model::SortableCredentialSchemaColumn::CreatedDate
            }
        }
    }
}

pub type GetProofSchemaQuery = GetListQueryParams<SortableProofSchemaColumn>;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum SortableProofSchemaColumn {
    Name,
    CreatedDate,
}

impl From<SortableProofSchemaColumn>
    for one_core::data_layer::data_model::SortableProofSchemaColumn
{
    fn from(value: SortableProofSchemaColumn) -> Self {
        match value {
            SortableProofSchemaColumn::Name => {
                one_core::data_layer::data_model::SortableProofSchemaColumn::Name
            }
            SortableProofSchemaColumn::CreatedDate => {
                one_core::data_layer::data_model::SortableProofSchemaColumn::CreatedDate
            }
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase")]
pub struct CreateCredentialSchemaRequestDTO {
    #[validate(length(min = 1))]
    pub name: String,
    pub format: Format,
    pub revocation_method: RevocationMethod,
    pub organisation_id: Uuid,
    #[validate(length(min = 1))]
    pub claims: Vec<CredentialClaimSchemaRequestDTO>,
}

impl From<CreateCredentialSchemaRequestDTO> for CreateCredentialSchemaRequest {
    fn from(value: CreateCredentialSchemaRequestDTO) -> Self {
        CreateCredentialSchemaRequest {
            name: value.name,
            format: value.format.into(),
            revocation_method: value.revocation_method.into(),
            organisation_id: value.organisation_id,
            claims: value.claims.into_iter().map(|claim| claim.into()).collect(),
        }
    }
}

impl From<CredentialClaimSchemaRequestDTO> for CredentialClaimSchemaRequest {
    fn from(value: CredentialClaimSchemaRequestDTO) -> Self {
        CredentialClaimSchemaRequest {
            key: value.key,
            datatype: value.datatype.into(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
pub struct CredentialClaimSchemaRequestDTO {
    pub key: String,
    pub datatype: Datatype,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GetCredentialClaimSchemaResponseDTO {
    pub values: Vec<CredentialSchemaResponseDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaResponseDTO {
    pub id: String,
    #[serde(with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: Format,
    pub revocation_method: RevocationMethod,
    pub organisation_id: String,
    pub claims: Vec<CredentialClaimSchemaResponseDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialClaimSchemaResponseDTO {
    pub id: String,
    #[serde(with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: Datatype,
}

impl From<GetCredentialClaimSchemaResponse> for GetCredentialClaimSchemaResponseDTO {
    fn from(value: GetCredentialClaimSchemaResponse) -> Self {
        Self {
            values: value.values.into_iter().map(|item| item.into()).collect(),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}

impl From<CredentialSchemaResponse> for CredentialSchemaResponseDTO {
    fn from(value: CredentialSchemaResponse) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            format: value.format.into(),
            revocation_method: value.revocation_method.into(),
            organisation_id: value.organisation_id,
            claims: value.claims.into_iter().map(|claim| claim.into()).collect(),
        }
    }
}

impl From<CredentialClaimSchemaResponse> for CredentialClaimSchemaResponseDTO {
    fn from(value: CredentialClaimSchemaResponse) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            key: value.key,
            datatype: value.datatype.into(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GetProofSchemaResponseDTO {
    pub values: Vec<ProofSchemaResponseDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProofSchemaResponseDTO {
    pub id: String,
    #[serde(with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub expire_duration: u32,
    pub organisation_id: String,
    pub claim_schemas: Vec<ProofClaimSchemaResponseDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProofClaimSchemaResponseDTO {
    pub id: String,
    pub is_required: bool,
    pub key: String,
    pub credential_schema_id: String,
    pub credential_schema_name: String,
}

impl From<GetProofSchemaResponse> for GetProofSchemaResponseDTO {
    fn from(value: GetProofSchemaResponse) -> Self {
        Self {
            values: value.values.into_iter().map(|item| item.into()).collect(),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}

impl From<ProofSchemaResponse> for ProofSchemaResponseDTO {
    fn from(value: ProofSchemaResponse) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            organisation_id: value.organisation_id,
            expire_duration: value.expire_duration,
            claim_schemas: value
                .claim_schemas
                .into_iter()
                .map(|claim| claim.into())
                .collect(),
        }
    }
}

impl From<ProofClaimSchemaResponse> for ProofClaimSchemaResponseDTO {
    fn from(value: ProofClaimSchemaResponse) -> Self {
        Self {
            id: value.id,
            is_required: value.is_required,
            key: value.key,
            credential_schema_id: value.credential_schema_id,
            credential_schema_name: value.credential_schema_name,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase")]
pub struct CreateProofSchemaRequestDTO {
    #[validate(length(min = 1))]
    pub name: String,
    pub organisation_id: Uuid,
    pub expire_duration: u32,
    #[validate(length(min = 1))]
    pub claim_schemas: Vec<ClaimProofSchemaRequestDTO>,
}

impl From<CreateProofSchemaRequestDTO> for CreateProofSchemaRequest {
    fn from(value: CreateProofSchemaRequestDTO) -> Self {
        Self {
            name: value.name,
            organisation_id: value.organisation_id,
            expire_duration: value.expire_duration,
            claim_schemas: value
                .claim_schemas
                .into_iter()
                .map(|claim| claim.into())
                .collect(),
        }
    }
}

impl From<ClaimProofSchemaRequestDTO> for ClaimProofSchemaRequest {
    fn from(value: ClaimProofSchemaRequestDTO) -> Self {
        Self { id: value.id }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClaimProofSchemaRequestDTO {
    pub id: Uuid,
    //pub is_required: bool, // Todo: Bring it back later
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateProofSchemaResponseDTO {
    pub id: String,
}

impl From<CreateProofSchemaResponse> for CreateProofSchemaResponseDTO {
    fn from(value: CreateProofSchemaResponse) -> Self {
        Self { id: value.id }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateOrganisationRequestDTO {
    pub id: Option<Uuid>,
}

impl From<CreateOrganisationRequestDTO> for CreateOrganisationRequest {
    fn from(value: CreateOrganisationRequestDTO) -> Self {
        Self { id: value.id }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateOrganisationResponseDTO {
    pub id: String,
}

impl From<CreateOrganisationResponse> for CreateOrganisationResponseDTO {
    fn from(value: CreateOrganisationResponse) -> Self {
        Self { id: value.id }
    }
}