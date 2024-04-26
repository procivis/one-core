use crate::error::NativeKeyStorageError;
use crate::mapper::serialize_config_entity;
use crate::utils::{format_timestamp_opt, into_id, TimestampFormat};
use dto_mapper::convert_inner;
use dto_mapper::{From, Into, TryInto};
use one_core::model::common::ExactColumn;
use one_core::model::credential::SortableCredentialColumn;
use one_core::model::credential_schema::LayoutType;
use one_core::model::did::{KeyRole, SortableDidColumn};
use one_core::service::backup::dto::{
    BackupCreateResponseDTO, MetadataDTO, UnexportableEntitiesResponseDTO,
};
use one_core::service::credential::dto::CredentialListIncludeEntityTypeEnum;
use one_core::service::credential::dto::CredentialRole;
use one_core::service::credential_schema::dto::{
    CredentialSchemaBackgroundPropertiesRequestDTO, CredentialSchemaCodePropertiesRequestDTO,
    CredentialSchemaCodeTypeEnum, CredentialSchemaDetailResponseDTO,
    CredentialSchemaLayoutPropertiesRequestDTO, CredentialSchemaLogoPropertiesRequestDTO,
    GetCredentialSchemaListResponseDTO,
};
use one_core::service::did::dto::{DidListItemResponseDTO, GetDidListResponseDTO};
use one_core::service::error::ServiceError;
use one_core::service::key::dto::KeyListItemResponseDTO;
use one_core::service::ssi_holder::dto::PresentationSubmitCredentialRequestDTO;
use one_core::{
    model::{
        credential_schema::WalletStorageTypeEnum,
        did::DidType,
        history::{HistoryAction, HistoryEntityType, HistorySearchEnum},
    },
    provider::{
        key_storage::GeneratedKey,
        transport_protocol::dto::{
            PresentationDefinitionFieldDTO, PresentationDefinitionRequestGroupResponseDTO,
            PresentationDefinitionRequestedCredentialResponseDTO,
            PresentationDefinitionResponseDTO, PresentationDefinitionRuleDTO,
            PresentationDefinitionRuleTypeEnum,
        },
    },
    service::{
        config::dto::ConfigDTO,
        credential::dto::{
            CredentialRevocationCheckResponseDTO, CredentialStateEnum, GetCredentialListResponseDTO,
        },
        history::dto::GetHistoryListResponseDTO,
    },
};
use std::collections::HashMap;

#[derive(From)]
#[from(ConfigDTO)]
pub struct ConfigBindingDTO {
    #[from(with_fn = serialize_config_entity)]
    pub format: HashMap<String, String>,
    #[from(with_fn = serialize_config_entity)]
    pub exchange: HashMap<String, String>,
    #[from(with_fn = serialize_config_entity)]
    pub revocation: HashMap<String, String>,
    #[from(with_fn = serialize_config_entity)]
    pub did: HashMap<String, String>,
    #[from(with_fn = serialize_config_entity)]
    pub datatype: HashMap<String, String>,
    #[from(with_fn = serialize_config_entity)]
    pub key_algorithm: HashMap<String, String>,
    #[from(with_fn = serialize_config_entity)]
    pub key_storage: HashMap<String, String>,
}

#[derive(Debug, Clone, From, Into)]
#[from(CredentialStateEnum)]
#[into("one_core::model::credential::CredentialStateEnum")]
pub enum CredentialStateBindingEnum {
    Created,
    Pending,
    Offered,
    Accepted,
    Rejected,
    Revoked,
    Suspended,
    Error,
}

pub type VersionBindingDTO = one_core::Version;

#[derive(Debug, Clone, Into, From)]
#[from(CredentialRole)]
#[into(CredentialRole)]
pub enum CredentialRoleBindingDTO {
    Holder,
    Issuer,
    Verifier,
}

pub struct ListQueryBindingDTO {
    pub page: u32,
    pub page_size: u32,
    pub organisation_id: String,
}

#[derive(From)]
#[from(GetCredentialSchemaListResponseDTO)]
pub struct CredentialSchemaListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<CredentialSchemaBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, PartialEq, Into)]
#[into(ExactColumn)]
pub enum CredentialListQueryExactColumnBindingEnum {
    Name,
}

#[derive(Clone, Debug, Into)]
#[into("one_core::model::common::SortDirection")]
pub enum SortDirection {
    Ascending,
    Descending,
}

#[derive(Clone, Debug, Into)]
#[into(SortableCredentialColumn)]
pub enum SortableCredentialColumnBindingEnum {
    CreatedDate,
    SchemaName,
    IssuerDid,
    State,
}

pub struct CredentialListQueryBindingDTO {
    pub page: u32,
    pub page_size: u32,

    pub sort: Option<SortableCredentialColumnBindingEnum>,
    pub sort_direction: Option<SortDirection>,

    pub organisation_id: String,
    pub name: Option<String>,
    pub exact: Option<Vec<CredentialListQueryExactColumnBindingEnum>>,
    pub role: Option<CredentialRoleBindingDTO>,
    pub ids: Option<Vec<String>>,
    pub status: Option<Vec<CredentialStateBindingEnum>>,
    pub include: Option<Vec<CredentialListIncludeEntityTypeBindingEnum>>,
}

#[derive(Clone, Debug, Into)]
#[into(CredentialListIncludeEntityTypeEnum)]
pub enum CredentialListIncludeEntityTypeBindingEnum {
    LayoutProperties,
}

#[derive(From)]
#[from(GetCredentialListResponseDTO)]
pub struct CredentialListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<CredentialListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(From)]
#[from(GetDidListResponseDTO)]
pub struct DidListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<DidListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, Into)]
#[into(SortableDidColumn)]
pub enum SortableDidColumnBindingEnum {
    Name,
    CreatedDate,
    Method,
    Type,
    Did,
    Deactivated,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ExactDidFilterColumnBindingEnum {
    Name,
    Did,
}

#[derive(Clone, Debug, Into)]
#[into(KeyRole)]
pub enum KeyRoleBindingEnum {
    Authentication,
    AssertionMethod,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
}

pub struct DidListQueryBindingDTO {
    pub page: u32,
    pub page_size: u32,

    pub sort: Option<SortableDidColumnBindingEnum>,
    pub sort_direction: Option<SortDirection>,

    pub organisation_id: String,
    pub name: Option<String>,
    pub did: Option<String>,
    pub r#type: Option<DidTypeBindingEnum>,
    pub deactivated: Option<bool>,
    pub exact: Option<Vec<ExactDidFilterColumnBindingEnum>>,
    pub key_algorithms: Option<Vec<String>>,
    pub key_roles: Option<Vec<KeyRoleBindingEnum>>,
}

#[derive(Debug, Clone)]
pub struct CredentialDetailBindingDTO {
    pub id: String,
    pub created_date: String,
    pub issuance_date: String,
    pub last_modified: String,
    pub revocation_date: Option<String>,
    pub issuer_did: Option<String>,
    pub state: CredentialStateBindingEnum,
    pub schema: CredentialSchemaBindingDTO,
    pub claims: Vec<ClaimBindingDTO>,
    pub redirect_uri: Option<String>,
    pub role: CredentialRoleBindingDTO,
    pub lvvc_issuance_date: Option<String>,
    pub suspend_end_date: Option<String>,
}

pub struct CredentialListItemBindingDTO {
    pub id: String,
    pub created_date: String,
    pub issuance_date: String,
    pub last_modified: String,
    pub revocation_date: Option<String>,
    pub issuer_did: Option<String>,
    pub state: CredentialStateBindingEnum,
    pub schema: CredentialSchemaBindingDTO,
    pub role: CredentialRoleBindingDTO,
    pub suspend_end_date: Option<String>,
}

#[derive(Debug, Clone, From)]
#[from(KeyListItemResponseDTO)]
pub struct KeyListItemBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub name: String,
    pub public_key: Vec<u8>,
    pub key_type: String,
    pub storage_type: String,
}

#[derive(Debug, Clone, From)]
#[from(DidListItemResponseDTO)]
pub struct DidListItemBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub name: String,
    #[from(with_fn_ref = "ToString::to_string")]
    pub did: String,
    pub did_type: DidTypeBindingEnum,
    pub did_method: String,
    pub deactivated: bool,
}

#[derive(Debug, Clone, From)]
#[from(CredentialSchemaDetailResponseDTO)]
pub struct CredentialSchemaBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    #[from(with_fn = convert_inner)]
    pub wallet_storage_type: Option<WalletStorageTypeBindingEnum>,
    pub schema_id: String,
    pub schema_type: CredentialSchemaTypeBindingEnum,
    #[from(with_fn = convert_inner)]
    pub layout_type: Option<LayoutTypeBindingEnum>,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesBindingDTO>,
}

#[derive(Debug, Clone, From)]
#[from(CredentialSchemaLayoutPropertiesRequestDTO)]
pub struct CredentialSchemaLayoutPropertiesBindingDTO {
    #[from(with_fn = convert_inner)]
    pub background: Option<CredentialSchemaBackgroundPropertiesBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub logo: Option<CredentialSchemaLogoPropertiesBindingDTO>,
    pub primary_attribute: Option<String>,
    pub secondary_attribute: Option<String>,
    pub picture_attribute: Option<String>,
    #[from(with_fn = convert_inner)]
    pub code: Option<CredentialSchemaCodePropertiesBindingDTO>,
}

#[derive(Debug, Clone, From)]
#[from(CredentialSchemaBackgroundPropertiesRequestDTO)]
pub struct CredentialSchemaBackgroundPropertiesBindingDTO {
    pub color: Option<String>,
    pub image: Option<String>,
}

#[derive(Debug, Clone, From)]
#[from(CredentialSchemaLogoPropertiesRequestDTO)]
pub struct CredentialSchemaLogoPropertiesBindingDTO {
    pub font_color: Option<String>,
    pub background_color: Option<String>,
    pub image: Option<String>,
}

#[derive(Debug, Clone, From)]
#[from(CredentialSchemaCodePropertiesRequestDTO)]
pub struct CredentialSchemaCodePropertiesBindingDTO {
    pub attribute: String,
    pub r#type: CredentialSchemaCodeTypeBindingDTO,
}

#[derive(Debug, Clone, From)]
#[from(CredentialSchemaCodeTypeEnum)]
pub enum CredentialSchemaCodeTypeBindingDTO {
    Barcode,
    Mrz,
    QrCode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialSchemaTypeBindingEnum {
    ProcivisOneSchema2024 {},
    FallbackSchema2024 {},
    Mdoc {},
    Other { value: String },
}

#[derive(Clone, Debug, Eq, PartialEq, From)]
#[from(LayoutType)]
pub enum LayoutTypeBindingEnum {
    Card,
    Document,
    SingleAttribute,
}

#[derive(From, Clone, Debug)]
#[from(WalletStorageTypeEnum)]
pub enum WalletStorageTypeBindingEnum {
    Hardware,
    Software,
}

#[derive(Debug, Clone)]
pub struct ClaimBindingDTO {
    pub id: String,
    pub key: String,
    pub data_type: String,
    pub value: ClaimValueBindingDTO,
}

#[derive(Debug, Clone)]
pub enum ClaimValueBindingDTO {
    Value { value: String },
    Nested { value: Vec<ClaimBindingDTO> },
}

pub enum HandleInvitationResponseBindingEnum {
    CredentialIssuance {
        interaction_id: String,
        credential_ids: Vec<String>,
    },
    ProofRequest {
        interaction_id: String,
        proof_id: String,
    },
}

pub struct ProofRequestBindingDTO {
    pub id: String,
    pub created_date: String,
    pub last_modified: String,
    pub claims: Vec<ProofRequestClaimBindingDTO>,
    pub verifier_did: Option<String>,
    pub transport: String,
    pub redirect_uri: Option<String>,
    pub credentials: Vec<CredentialDetailBindingDTO>,
}

pub struct ProofRequestClaimBindingDTO {
    pub id: String,
    pub key: String,
    pub data_type: String,
    pub required: bool,
    pub credential_schema: CredentialSchemaBindingDTO,
}

#[derive(TryInto)]
#[try_into(T = PresentationSubmitCredentialRequestDTO, Error = ServiceError)]
pub struct PresentationSubmitCredentialRequestBindingDTO {
    #[try_into(with_fn_ref = into_id)]
    pub credential_id: String,
    #[try_into(infallible)]
    pub submit_claims: Vec<String>,
}

#[derive(From)]
#[from(PresentationDefinitionResponseDTO)]
pub struct PresentationDefinitionBindingDTO {
    #[from(with_fn = convert_inner)]
    pub request_groups: Vec<PresentationDefinitionRequestGroupBindingDTO>,
}

#[derive(From)]
#[from(PresentationDefinitionRequestGroupResponseDTO)]
pub struct PresentationDefinitionRequestGroupBindingDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub rule: PresentationDefinitionRuleBindingDTO,
    #[from(with_fn = convert_inner)]
    pub requested_credentials: Vec<PresentationDefinitionRequestedCredentialBindingDTO>,
}

#[derive(From)]
#[from(PresentationDefinitionRequestedCredentialResponseDTO)]
pub struct PresentationDefinitionRequestedCredentialBindingDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    #[from(with_fn = convert_inner)]
    pub fields: Vec<PresentationDefinitionFieldBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub applicable_credentials: Vec<String>,
    #[from(with_fn = format_timestamp_opt)]
    pub validity_credential_nbf: Option<String>,
}

#[derive(From)]
#[from(PresentationDefinitionFieldDTO)]
pub struct PresentationDefinitionFieldBindingDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    #[from(unwrap_or = true)]
    pub required: bool,
    pub key_map: HashMap<String, String>,
}

#[derive(From)]
#[from(PresentationDefinitionRuleTypeEnum)]
pub enum PresentationDefinitionRuleTypeBindingEnum {
    All,
    Pick,
}

#[derive(From)]
#[from(PresentationDefinitionRuleDTO)]
pub struct PresentationDefinitionRuleBindingDTO {
    pub r#type: PresentationDefinitionRuleTypeBindingEnum,
    pub min: Option<u32>,
    pub max: Option<u32>,
    pub count: Option<u32>,
}

pub struct KeyRequestBindingDTO {
    pub organisation_id: String,
    pub key_type: String,
    pub key_params: HashMap<String, String>,
    pub name: String,
    pub storage_type: String,
    pub storage_params: HashMap<String, String>,
}

#[derive(Debug, Clone, Into, From)]
#[into(DidType)]
#[from(DidType)]
pub enum DidTypeBindingEnum {
    Local,
    Remote,
}

pub struct DidRequestBindingDTO {
    pub organisation_id: String,
    pub name: String,
    pub did_method: String,
    pub keys: DidRequestKeysBindingDTO,
    pub params: HashMap<String, String>,
}

pub struct DidRequestKeysBindingDTO {
    pub authentication: Vec<String>,
    pub assertion_method: Vec<String>,
    pub key_agreement: Vec<String>,
    pub capability_invocation: Vec<String>,
    pub capability_delegation: Vec<String>,
}

#[derive(From)]
#[from(CredentialRevocationCheckResponseDTO)]
pub struct CredentialRevocationCheckResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub credential_id: String,
    pub status: CredentialStateBindingEnum,
    pub success: bool,
    pub reason: Option<String>,
}

#[derive(Into)]
#[into(GeneratedKey)]
pub struct GeneratedKeyBindingDTO {
    pub key_reference: Vec<u8>,
    pub public_key: Vec<u8>,
}

pub trait NativeKeyStorage: Send + Sync {
    fn generate_key(
        &self,
        key_alias: String,
    ) -> Result<GeneratedKeyBindingDTO, NativeKeyStorageError>;
    fn sign(
        &self,
        key_reference: Vec<u8>,
        message: Vec<u8>,
    ) -> Result<Vec<u8>, NativeKeyStorageError>;
}

#[derive(From, Into)]
#[from(HistoryAction)]
#[into(HistoryAction)]
pub enum HistoryActionBindingEnum {
    Accepted,
    Created,
    Deactivated,
    Deleted,
    Issued,
    Offered,
    Reactivated,
    Rejected,
    Requested,
    Revoked,
    Suspended,
    Pending,
    Restored,
}

#[derive(From, Into)]
#[from(HistoryEntityType)]
#[into(HistoryEntityType)]
pub enum HistoryEntityTypeBindingEnum {
    Key,
    Did,
    Credential,
    CredentialSchema,
    Proof,
    ProofSchema,
    Organisation,
    Backup,
}

#[derive(Debug, Clone)]
pub enum HistoryMetadataBinding {
    UnexportableEntities {
        value: UnexportableEntitiesBindingDTO,
    },
}

pub struct HistoryListItemBindingDTO {
    pub id: String,
    pub created_date: String,
    pub action: HistoryActionBindingEnum,
    pub entity_id: Option<String>,
    pub entity_type: HistoryEntityTypeBindingEnum,
    pub metadata: Option<HistoryMetadataBinding>,
    pub organisation_id: String,
}

pub struct HistoryListQueryBindingDTO {
    pub page: u32,
    pub page_size: u32,
    pub organisation_id: String,
    pub entity_id: Option<String>,
    pub entity_types: Option<Vec<HistoryEntityTypeBindingEnum>>,
    pub action: Option<HistoryActionBindingEnum>,
    pub created_date_from: Option<String>,
    pub created_date_to: Option<String>,
    pub did_id: Option<String>,
    pub credential_id: Option<String>,
    pub credential_schema_id: Option<String>,
    pub search: Option<HistorySearchBindingDTO>,
}

#[derive(From)]
#[from(GetHistoryListResponseDTO)]
pub struct HistoryListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<HistoryListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Into)]
#[into(HistorySearchEnum)]
pub enum HistorySearchEnumBindingEnum {
    ClaimName,
    ClaimValue,
    CredentialSchemaName,
    IssuerDid,
    IssuerName,
    VerifierDid,
    VerifierName,
}

pub struct HistorySearchBindingDTO {
    pub text: String,
    pub r#type: Option<HistorySearchEnumBindingEnum>,
}

#[derive(Debug, Clone, From)]
#[from(BackupCreateResponseDTO)]
pub struct BackupCreateBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub history_id: String,
    pub file: String,
    pub unexportable: UnexportableEntitiesBindingDTO,
}

#[derive(Debug, Clone, From)]
#[from(MetadataDTO)]
pub struct MetadataBindingDTO {
    pub db_version: String,
    pub db_hash: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_at: String,
}

#[derive(Debug, Clone, From)]
#[from(UnexportableEntitiesResponseDTO)]
pub struct UnexportableEntitiesBindingDTO {
    #[from(with_fn = convert_inner)]
    pub credentials: Vec<CredentialDetailBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub keys: Vec<KeyListItemBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub dids: Vec<DidListItemBindingDTO>,
    pub total_credentials: u64,
    pub total_keys: u64,
    pub total_dids: u64,
}
