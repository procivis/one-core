use crate::data_layer::{entities, DataLayerError};
use sea_orm::FromQueryResult;
use time::OffsetDateTime;
use uuid::Uuid;

use super::entities::{
    claim, claim_schema, credential_schema, credential_state, did, organisation, proof,
    proof_schema, proof_state,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum Format {
    #[default]
    Jwt,
    SdJwt,
    JsonLd,
    Mdoc,
}

impl From<Format> for super::entities::credential_schema::Format {
    fn from(value: Format) -> Self {
        match value {
            Format::Jwt => credential_schema::Format::Jwt,
            Format::SdJwt => credential_schema::Format::SdJwt,
            Format::JsonLd => credential_schema::Format::JsonLd,
            Format::Mdoc => credential_schema::Format::Mdoc,
        }
    }
}

impl From<super::entities::credential_schema::Format> for Format {
    fn from(value: super::entities::credential_schema::Format) -> Self {
        match value {
            credential_schema::Format::Jwt => Format::Jwt,
            credential_schema::Format::SdJwt => Format::SdJwt,
            credential_schema::Format::JsonLd => Format::JsonLd,
            credential_schema::Format::Mdoc => Format::Mdoc,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum DidType {
    #[default]
    Remote,
    Local,
}

impl From<DidType> for super::entities::did::DidType {
    fn from(value: DidType) -> Self {
        match value {
            DidType::Remote => did::DidType::Remote,
            DidType::Local => did::DidType::Local,
        }
    }
}

impl From<super::entities::did::DidType> for DidType {
    fn from(value: super::entities::did::DidType) -> Self {
        match value {
            did::DidType::Remote => DidType::Remote,
            did::DidType::Local => DidType::Local,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum DidMethod {
    #[default]
    Key,
    Web,
}

impl From<DidMethod> for super::entities::did::DidMethod {
    fn from(value: DidMethod) -> Self {
        match value {
            DidMethod::Key => did::DidMethod::Key,
            DidMethod::Web => did::DidMethod::Web,
        }
    }
}

impl From<super::entities::did::DidMethod> for DidMethod {
    fn from(value: super::entities::did::DidMethod) -> Self {
        match value {
            did::DidMethod::Key => DidMethod::Key,
            did::DidMethod::Web => DidMethod::Web,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub enum RevocationMethod {
    #[default]
    None,
    StatusList2021,
    Lvvc,
}

impl From<RevocationMethod> for super::entities::credential_schema::RevocationMethod {
    fn from(value: RevocationMethod) -> Self {
        match value {
            RevocationMethod::StatusList2021 => credential_schema::RevocationMethod::StatusList2021,
            RevocationMethod::Lvvc => credential_schema::RevocationMethod::Lvvc,
            RevocationMethod::None => credential_schema::RevocationMethod::None,
        }
    }
}

impl From<super::entities::credential_schema::RevocationMethod> for RevocationMethod {
    fn from(value: super::entities::credential_schema::RevocationMethod) -> Self {
        match value {
            credential_schema::RevocationMethod::StatusList2021 => RevocationMethod::StatusList2021,
            credential_schema::RevocationMethod::Lvvc => RevocationMethod::Lvvc,
            credential_schema::RevocationMethod::None => RevocationMethod::None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub enum Datatype {
    #[default]
    String,
    Date,
    Number,
}

impl From<Datatype> for super::entities::claim_schema::Datatype {
    fn from(value: Datatype) -> Self {
        match value {
            Datatype::String => claim_schema::Datatype::String,
            Datatype::Date => claim_schema::Datatype::Date,
            Datatype::Number => claim_schema::Datatype::Number,
        }
    }
}

impl From<super::entities::claim_schema::Datatype> for Datatype {
    fn from(value: super::entities::claim_schema::Datatype) -> Self {
        match value {
            claim_schema::Datatype::String => Datatype::String,
            claim_schema::Datatype::Date => Datatype::Date,
            claim_schema::Datatype::Number => Datatype::Number,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SortDirection {
    Ascending,
    Descending,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableCredentialSchemaColumn {
    Name,
    Format,
    CreatedDate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableCredentialColumn {
    CreatedDate,
    SchemaName,
    IssuerDid,
    State,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableProofSchemaColumn {
    Name,
    CreatedDate,
}

#[derive(Clone, Debug)]
pub struct GetListQueryParams<SortableColumn> {
    // pagination
    pub page: u32,
    pub page_size: u32,

    // sorting
    pub sort: Option<SortableColumn>,
    pub sort_direction: Option<SortDirection>,

    // filtering
    pub name: Option<String>,
    pub organisation_id: String,
}

#[derive(Clone, Debug)]
pub struct GetListResponse<ResponseItem> {
    pub values: Vec<ResponseItem>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug)]
pub struct CreateCredentialSchemaRequest {
    pub name: String,
    pub format: Format,
    pub revocation_method: RevocationMethod,
    pub organisation_id: Uuid,
    pub claims: Vec<CredentialClaimSchemaRequest>,
}

#[derive(Clone, Debug)]
pub struct CreateCredentialSchemaFromJwtRequest {
    pub id: Uuid,
    pub name: String,
    pub format: Format,
    pub revocation_method: RevocationMethod,
    pub organisation_id: Uuid,
    pub claims: Vec<CredentialClaimSchemaFromJwtRequest>,
}

#[derive(Clone, Debug)]
pub struct CredentialClaimSchemaFromJwtRequest {
    pub id: Uuid,
    pub key: String,
    pub datatype: Datatype,
}

#[derive(Clone, Debug)]
pub struct CreateCredentialSchemaResponse {
    pub id: String,
}

#[derive(Clone, Debug)]
pub struct CredentialClaimSchemaRequest {
    pub key: String,
    pub datatype: Datatype,
}

#[derive(Clone, Debug)]
pub struct CredentialSchemaResponse {
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: Format,
    pub revocation_method: RevocationMethod,
    pub organisation_id: String,
    pub claims: Vec<CredentialClaimSchemaResponse>,
}

pub type GetCredentialClaimSchemaResponse = GetListResponse<CredentialSchemaResponse>;

#[derive(Clone, Debug)]
pub struct CredentialClaimSchemaResponse {
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: Datatype,
}

impl From<CredentialSchemaClaimSchemaCombined> for CredentialClaimSchemaResponse {
    fn from(value: CredentialSchemaClaimSchemaCombined) -> Self {
        Self {
            id: value.id.clone(),
            created_date: value.created_date,
            last_modified: value.last_modified,
            key: value.key.clone(),
            datatype: value.datatype.into(),
        }
    }
}

#[allow(clippy::ptr_arg)]
impl CredentialSchemaResponse {
    pub(super) fn from_model(
        value: credential_schema::Model,
        claim_schemas: &Vec<CredentialSchemaClaimSchemaCombined>,
    ) -> Self {
        Self {
            id: value.id.clone(),
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            format: value.format.into(),
            revocation_method: value.revocation_method.into(),
            organisation_id: value.organisation_id,
            claims: claim_schemas
                .iter()
                .filter(|claim| claim.credential_schema_id == value.id)
                .map(|claim| claim.clone().into())
                .collect(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProofSchemaResponse {
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub expire_duration: u32,
    pub organisation_id: String,
    pub claim_schemas: Vec<ProofClaimSchemaResponse>,
}

pub type GetProofSchemaResponse = GetListResponse<ProofSchemaResponse>;

#[derive(Debug, Clone, FromQueryResult)]
pub(crate) struct ProofSchemaClaimSchemaCombined {
    pub claim_schema_id: String,
    pub proof_schema_id: String,
    pub required: bool,
    pub claim_key: String,
    pub claim_created_date: OffsetDateTime,
    pub claim_last_modified: OffsetDateTime,
    pub claim_datatype: claim_schema::Datatype,
    pub credential_schema_id: String,
    pub credential_schema_created_date: OffsetDateTime,
    pub credential_schema_last_modified: OffsetDateTime,
    pub credential_schema_name: String,
    pub credential_schema_format: credential_schema::Format,
    pub credential_schema_revocation_method: credential_schema::RevocationMethod,
    pub credential_schema_organisation_id: String,
}

#[derive(Debug, Clone, FromQueryResult)]
pub(crate) struct CredentialSchemaClaimSchemaCombined {
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: claim_schema::Datatype,
    pub credential_schema_id: String,
}

#[derive(Clone, Debug)]
pub struct ProofClaimSchemaResponse {
    pub id: String,
    pub is_required: bool,
    pub key: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub datatype: claim_schema::Datatype,
    pub credential_schema: ListCredentialSchemaResponse,
}

impl ProofClaimSchemaResponse {
    pub(super) fn from_model(value: ProofSchemaClaimSchemaCombined) -> Self {
        Self {
            id: value.claim_schema_id,
            key: value.claim_key,
            is_required: value.required,
            created_date: value.claim_created_date,
            last_modified: value.claim_last_modified,
            datatype: value.claim_datatype,
            credential_schema: ListCredentialSchemaResponse {
                id: value.credential_schema_id,
                created_date: value.credential_schema_created_date,
                last_modified: value.credential_schema_last_modified,
                name: value.credential_schema_name,
                format: value.credential_schema_format.into(),
                revocation_method: value.credential_schema_revocation_method.into(),
                organisation_id: value.credential_schema_organisation_id,
            },
        }
    }

    pub(super) fn from_vec(value: Vec<ProofSchemaClaimSchemaCombined>) -> Vec<Self> {
        value.into_iter().map(Self::from_model).collect()
    }
}

impl ProofSchemaResponse {
    pub(super) fn from_model(
        value: proof_schema::Model,
        claim_schemas: Vec<ProofSchemaClaimSchemaCombined>,
    ) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            organisation_id: value.organisation_id,
            expire_duration: value.expire_duration,
            claim_schemas: ProofClaimSchemaResponse::from_vec(claim_schemas),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CreateProofSchemaRequest {
    pub name: String,
    pub organisation_id: Uuid,
    pub expire_duration: u32,
    pub claim_schemas: Vec<ClaimProofSchemaRequest>,
}

#[derive(Clone, Debug)]
pub struct ClaimProofSchemaRequest {
    pub id: Uuid,
    //pub is_required: bool, // Todo: Bring it back later
}

#[derive(Clone, Debug)]
pub struct CreateProofSchemaResponse {
    pub id: String,
}

#[derive(Clone, Debug)]
pub struct CreateOrganisationRequest {
    pub id: Option<Uuid>,
}

#[derive(Clone, Debug)]
pub struct CreateOrganisationResponse {
    pub id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetOrganisationDetailsResponse {
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
}

impl From<organisation::Model> for GetOrganisationDetailsResponse {
    fn from(value: organisation::Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CreateCredentialRequest {
    pub credential_id: Option<String>,
    pub credential_schema_id: Uuid,
    pub issuer_did: Uuid,
    pub transport: Transport,
    pub claim_values: Vec<CreateCredentialRequestClaim>,
    pub receiver_did_id: Option<Uuid>,
    pub credential: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Transport {
    ProcivisTemporary,
    OpenId4Vc,
}

impl From<Transport> for super::entities::credential::Transport {
    fn from(value: Transport) -> Self {
        match value {
            Transport::ProcivisTemporary => {
                super::entities::credential::Transport::ProcivisTemporary
            }
            Transport::OpenId4Vc => super::entities::credential::Transport::OpenId4Vc,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CreateCredentialRequestClaim {
    pub claim_id: Uuid,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct EntityResponse {
    pub id: String,
}

#[derive(Clone, Debug)]
pub struct CreateDidRequest {
    pub name: String,
    pub organisation_id: String,
    pub did: String,
    pub method: DidMethod,
    pub did_type: DidType,
}

#[derive(Clone, Debug)]
pub struct CreateDidResponse {
    pub id: String,
}

#[derive(Clone, Debug)]
pub struct GetDidDetailsResponse {
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub organisation_id: String,
    pub did: String,
    pub did_type: DidType,
    pub did_method: DidMethod,
}

impl From<did::Model> for GetDidDetailsResponse {
    fn from(value: did::Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            organisation_id: value.organisation_id,
            did: value.did,
            did_type: value.type_field.into(),
            did_method: value.method.into(),
        }
    }
}

pub type GetDidsResponse = GetListResponse<GetDidDetailsResponse>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableDidColumn {
    Name,
    CreatedDate,
}

pub struct CredentialShareResponse {
    pub credential_id: String,
    pub transport: Transport,
}

pub struct ProofShareResponse {
    pub proof_id: String,
    pub transport: Transport,
}

pub struct DetailCredentialResponse {
    pub id: String,
    pub created_date: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub state: CredentialState,
    pub last_modified: OffsetDateTime,
    pub schema: ListCredentialSchemaResponse,
    pub issuer_did: Option<String>,
    pub claims: Vec<DetailCredentialClaimResponse>,
}

pub type GetCredentialsResponse = GetListResponse<DetailCredentialResponse>;

#[derive(Clone, Debug)]
pub struct ListCredentialSchemaResponse {
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: Format,
    pub revocation_method: RevocationMethod,
    pub organisation_id: String,
}

pub struct DetailCredentialClaimResponse {
    pub schema: CredentialClaimSchemaResponse,
    pub value: String,
}

#[derive(Debug, PartialEq, Clone)]
pub enum CredentialState {
    Created,
    Pending,
    Offered,
    Accepted,
    Rejected,
    Revoked,
    Error,
}

impl From<entities::credential_state::CredentialState> for CredentialState {
    fn from(value: entities::credential_state::CredentialState) -> Self {
        match value {
            entities::credential_state::CredentialState::Created => CredentialState::Created,
            entities::credential_state::CredentialState::Pending => CredentialState::Pending,
            entities::credential_state::CredentialState::Offered => CredentialState::Offered,
            entities::credential_state::CredentialState::Accepted => CredentialState::Accepted,
            entities::credential_state::CredentialState::Rejected => CredentialState::Rejected,
            entities::credential_state::CredentialState::Revoked => CredentialState::Revoked,
            entities::credential_state::CredentialState::Error => CredentialState::Error,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum ProofRequestState {
    Created,
    Pending,
    Offered,
    Accepted,
    Rejected,
    Error,
}

impl From<entities::proof_state::ProofRequestState> for ProofRequestState {
    fn from(value: entities::proof_state::ProofRequestState) -> Self {
        match value {
            entities::proof_state::ProofRequestState::Created => ProofRequestState::Created,
            entities::proof_state::ProofRequestState::Pending => ProofRequestState::Pending,
            entities::proof_state::ProofRequestState::Offered => ProofRequestState::Offered,
            entities::proof_state::ProofRequestState::Accepted => ProofRequestState::Accepted,
            entities::proof_state::ProofRequestState::Rejected => ProofRequestState::Rejected,
            entities::proof_state::ProofRequestState::Error => ProofRequestState::Error,
        }
    }
}

#[derive(Debug, Clone, FromQueryResult)]
pub(crate) struct ClaimClaimSchemaCombined {
    pub credential_id: String,
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub value: String,
    pub key: String,
    pub datatype: claim_schema::Datatype,
}

impl From<ClaimClaimSchemaCombined> for DetailCredentialClaimResponse {
    fn from(value: ClaimClaimSchemaCombined) -> Self {
        Self {
            schema: CredentialClaimSchemaResponse {
                id: value.id,
                created_date: value.created_date,
                last_modified: value.last_modified,
                key: value.key,
                datatype: value.datatype.into(),
            },
            value: value.value,
        }
    }
}

#[derive(Debug, FromQueryResult, Clone)]
pub(crate) struct CredentialDidCredentialSchemaCombined {
    // credential table
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: OffsetDateTime,

    // did table
    pub did: Option<String>,

    // credential_state table
    pub state: credential_state::CredentialState,

    // credential_schema table
    pub schema_id: String,
    pub schema_name: String,
    pub schema_format: credential_schema::Format,
    pub schema_revocation_method: credential_schema::RevocationMethod,
    pub schema_organisation_id: String,
    pub schema_created_date: OffsetDateTime,
    pub schema_last_modified: OffsetDateTime,
}

impl From<CredentialDidCredentialSchemaCombined> for ListCredentialSchemaResponse {
    fn from(value: CredentialDidCredentialSchemaCombined) -> Self {
        Self {
            id: value.schema_id,
            created_date: value.schema_created_date,
            last_modified: value.schema_last_modified,
            name: value.schema_name,
            format: value.schema_format.into(),
            revocation_method: value.schema_revocation_method.into(),
            organisation_id: value.schema_organisation_id,
        }
    }
}

impl From<credential_schema::Model> for ListCredentialSchemaResponse {
    fn from(value: credential_schema::Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            format: value.format.into(),
            revocation_method: value.revocation_method.into(),
            organisation_id: value.organisation_id,
        }
    }
}

impl DetailCredentialResponse {
    pub(crate) fn from_combined_credential_did_and_credential_schema(
        value: CredentialDidCredentialSchemaCombined,
        claims: &[ClaimClaimSchemaCombined],
    ) -> Result<Self, DataLayerError> {
        Ok(DetailCredentialResponse {
            id: value.id.to_owned(),
            created_date: value.created_date,
            issuance_date: value.issuance_date,
            state: value.state.into(),
            last_modified: value.last_modified,
            issuer_did: value.did.to_owned(),
            claims: claims
                .iter()
                .filter(|claim| claim.credential_id == value.id)
                .map(|claim| claim.clone().into())
                .collect(),
            schema: value.into(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct CreateProofRequest {
    pub proof_schema_id: Uuid,
    pub verifier_did: String,
    pub transport: Transport,
}

#[derive(Clone, Debug)]
pub struct CreateProofResponse {
    pub id: String,
}

#[derive(Clone, Debug)]
pub struct ProofDetailsResponse {
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub state: ProofRequestState,
    pub organisation_id: String,
    pub receiver_did_id: Option<String>,
    pub claims: Vec<DetailProofClaim>,
    pub schema: DetailProofSchema,
}

impl ProofDetailsResponse {
    pub(crate) fn from_models(
        proof: proof::Model,
        state: proof_state::ProofRequestState,
        proof_schema: proof_schema::Model,
        claims: Vec<(claim::Model, claim_schema::Model, credential_schema::Model)>,
    ) -> Self {
        Self {
            id: proof.id,
            created_date: proof.created_date,
            last_modified: proof.last_modified,
            issuance_date: proof.issuance_date,
            state: state.into(),
            organisation_id: proof_schema.organisation_id,
            receiver_did_id: proof.receiver_did_id,
            schema: DetailProofSchema {
                id: proof_schema.id,
                name: proof_schema.name,
                created_date: proof_schema.created_date,
                last_modified: proof_schema.last_modified,
            },
            claims: claims
                .into_iter()
                .map(DetailProofClaim::from_models)
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DetailProofSchema {
    pub id: String,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct DetailProofClaim {
    pub schema: DetailProofClaimSchema,
    pub value: String,
}

impl DetailProofClaim {
    pub(crate) fn from_models(
        (claim, claim_schema, credential_schema): (
            claim::Model,
            claim_schema::Model,
            credential_schema::Model,
        ),
    ) -> Self {
        Self {
            schema: DetailProofClaimSchema::from_models(claim_schema, credential_schema),
            value: claim.value,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DetailProofClaimSchema {
    pub id: String,
    pub key: String,
    pub datatype: Datatype,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub credential_schema: ListCredentialSchemaResponse,
}
impl DetailProofClaimSchema {
    fn from_models(
        claim_schema: claim_schema::Model,
        credential_schema: credential_schema::Model,
    ) -> Self {
        Self {
            id: claim_schema.id,
            key: claim_schema.key,
            datatype: claim_schema.datatype.into(),
            created_date: claim_schema.created_date,
            last_modified: claim_schema.last_modified,
            credential_schema: credential_schema.into(),
        }
    }
}
