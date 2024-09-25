use std::collections::HashMap;

use dto_mapper::{convert_inner, try_convert_inner, From, Into, TryInto};
use one_core::model::common::{EntityShareResponseDTO, ExactColumn};
use one_core::model::credential::SortableCredentialColumn;
use one_core::model::credential_schema::{
    LayoutType, SortableCredentialSchemaColumn, WalletStorageTypeEnum,
};
use one_core::model::did::{DidType, KeyRole, SortableDidColumn};
use one_core::model::history::{HistoryAction, HistoryEntityType, HistorySearchEnum};
use one_core::model::proof::{ProofStateEnum, SortableProofColumn};
use one_core::model::proof_schema::SortableProofSchemaColumn;
use one_core::model::trust_anchor::TrustAnchorRole;
use one_core::provider::bluetooth_low_energy::low_level::dto::{
    CharacteristicPermissions, CharacteristicProperties, CharacteristicUUID,
    CharacteristicWriteType, ConnectionEvent, CreateCharacteristicOptions, DeviceAddress,
    MacAddress, PeripheralDiscoveryData, ServiceDescription, ServiceUUID,
};
use one_core::provider::exchange_protocol::dto::{
    PresentationDefinitionFieldDTO, PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum,
};
use one_core::provider::key_storage::model::StorageGeneratedKey;
use one_core::service::backup::dto::{
    BackupCreateResponseDTO, MetadataDTO, UnexportableEntitiesResponseDTO,
};
use one_core::service::config::dto::ConfigDTO;
use one_core::service::credential::dto::{
    CredentialListIncludeEntityTypeEnum, CredentialRevocationCheckResponseDTO, CredentialRole,
    CredentialStateEnum, GetCredentialListResponseDTO,
};
use one_core::service::credential_schema::dto::{
    CredentialClaimSchemaDTO, CredentialSchemaBackgroundPropertiesRequestDTO,
    CredentialSchemaCodePropertiesRequestDTO, CredentialSchemaCodeTypeEnum,
    CredentialSchemaDetailResponseDTO, CredentialSchemaLayoutPropertiesRequestDTO,
    CredentialSchemaListIncludeEntityTypeEnum, CredentialSchemaLogoPropertiesRequestDTO,
    CredentialSchemaShareResponseDTO, GetCredentialSchemaListResponseDTO,
    ImportCredentialSchemaLayoutPropertiesDTO, ImportCredentialSchemaRequestDTO,
    ImportCredentialSchemaRequestSchemaDTO,
};
use one_core::service::did::dto::{DidListItemResponseDTO, GetDidListResponseDTO};
use one_core::service::error::ServiceError;
use one_core::service::history::dto::GetHistoryListResponseDTO;
use one_core::service::key::dto::{KeyCheckCertificateRequestDTO, KeyListItemResponseDTO};
use one_core::service::proof::dto::{
    CreateProofRequestDTO, GetProofListResponseDTO, ProofClaimDTO, ProofClaimValueDTO,
    ProofInputDTO, ProofListItemResponseDTO, ProposeProofResponseDTO, ScanToVerifyBarcodeTypeEnum,
    ScanToVerifyRequestDTO,
};
use one_core::service::proof_schema::dto::{
    GetProofSchemaListItemDTO, GetProofSchemaListResponseDTO, GetProofSchemaResponseDTO,
    ImportProofSchemaCredentialSchemaDTO, ImportProofSchemaDTO, ImportProofSchemaInputSchemaDTO,
    ImportProofSchemaRequestDTO, ProofClaimSchemaResponseDTO, ProofInputSchemaResponseDTO,
    ProofSchemaShareResponseDTO,
};
use one_core::service::ssi_holder::dto::PresentationSubmitCredentialRequestDTO;
use one_core::service::trust_anchor::dto::{
    GetTrustAnchorDetailResponseDTO, GetTrustAnchorsResponseDTO, SortableTrustAnchorColumn,
    TrustAnchorsListItemResponseDTO,
};

use crate::error::{BindingError, BleErrorWrapper, NativeKeyStorageError};
use crate::mapper::{optional_did_string, optional_time, serialize_config_entity};
use crate::utils::{format_timestamp_opt, into_id, into_id_opt, into_timestamp, TimestampFormat};

#[derive(From)]
#[from(ConfigDTO)]
pub struct ConfigBindingDTO {
    #[from(with_fn = serialize_config_entity)]
    pub format: HashMap<String, String>,
    #[from(with_fn = serialize_config_entity)]
    pub exchange: HashMap<String, String>,
    #[from(with_fn = serialize_config_entity)]
    pub transport: HashMap<String, String>,
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
    #[from(with_fn = serialize_config_entity)]
    pub cache_entities: HashMap<String, String>,
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

#[derive(From, Into)]
#[from(ProofStateEnum)]
#[into(ProofStateEnum)]
pub enum ProofStateBindingEnum {
    Created,
    Pending,
    Requested,
    Accepted,
    Rejected,
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

pub struct CredentialSchemaListQueryBindingDTO {
    pub page: u32,
    pub page_size: u32,
    pub organisation_id: String,
    pub sort: Option<SortableCredentialSchemaColumnBindingEnum>,
    pub sort_direction: Option<SortDirection>,
    pub name: Option<String>,
    pub ids: Option<Vec<String>>,
    pub exact: Option<Vec<CredentialSchemaListQueryExactColumnBindingEnum>>,
    pub include: Option<Vec<CredentialSchemaListIncludeEntityType>>,
}

#[derive(Into)]
#[into(CredentialSchemaListIncludeEntityTypeEnum)]
pub enum CredentialSchemaListIncludeEntityType {
    LayoutProperties,
}

#[derive(Into)]
#[into(SortableCredentialSchemaColumn)]
pub enum SortableCredentialSchemaColumnBindingEnum {
    Name,
    Format,
    CreatedDate,
}

#[derive(Clone, Debug, PartialEq, Into)]
#[into(ExactColumn)]
pub enum CredentialSchemaListQueryExactColumnBindingEnum {
    Name,
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

#[derive(Clone, Debug)]
pub enum SearchTypeBindingEnum {
    ClaimName,
    ClaimValue,
    CredentialSchemaName,
}

#[derive(Clone, Debug)]
pub struct CredentialListQueryBindingDTO {
    pub page: u32,
    pub page_size: u32,

    pub sort: Option<SortableCredentialColumnBindingEnum>,
    pub sort_direction: Option<SortDirection>,

    pub organisation_id: String,
    pub name: Option<String>,
    pub search_text: Option<String>,
    pub search_type: Option<Vec<SearchTypeBindingEnum>>,
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
    Credential,
}

#[derive(From)]
#[from(GetCredentialListResponseDTO)]
pub struct CredentialListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<CredentialListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, PartialEq, Into)]
#[into(ExactColumn)]
pub enum ProofListQueryExactColumnBindingEnum {
    Name,
}

#[derive(Clone, Debug, Into)]
#[into(SortableProofColumn)]
pub enum SortableProofListColumnBinding {
    SchemaName,
    VerifierDid,
    State,
    CreatedDate,
}
pub struct ProofListQueryBindingDTO {
    pub page: u32,
    pub page_size: u32,
    pub organisation_id: String,
    pub sort: Option<SortableProofListColumnBinding>,
    pub sort_direction: Option<SortDirection>,
    pub name: Option<String>,
    pub ids: Option<Vec<String>>,
    pub proof_states: Option<Vec<ProofStateBindingEnum>>,
    pub proof_schema_ids: Option<Vec<String>>,
    pub exact: Option<Vec<ProofListQueryExactColumnBindingEnum>>,
}

#[derive(From)]
#[from(ProofListItemResponseDTO)]
pub struct ProofListItemBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub issuance_date: String,
    #[from(with_fn = optional_time)]
    pub requested_date: Option<String>,
    #[from(with_fn = optional_time)]
    pub completed_date: Option<String>,
    #[from(with_fn = optional_did_string)]
    pub verifier_did: Option<String>,
    pub exchange: String,
    pub transport: String,
    pub state: ProofStateBindingEnum,
    #[from(with_fn = convert_inner)]
    pub schema: Option<GetProofSchemaListItemBindingDTO>,
    #[from(with_fn = optional_time)]
    pub retain_until_date: Option<String>,
}

#[derive(From)]
#[from(GetProofListResponseDTO)]
pub struct ProofListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<ProofListItemBindingDTO>,
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

#[derive(Debug, Clone)]
pub struct CredentialSchemaBindingDTO {
    pub id: String,
    pub created_date: String,
    pub last_modified: String,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub wallet_storage_type: Option<WalletStorageTypeBindingEnum>,
    pub schema_id: String,
    pub schema_type: CredentialSchemaTypeBindingEnum,
    pub layout_type: Option<LayoutTypeBindingEnum>,
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesBindingDTO>,
}

#[derive(Debug, Clone, TryInto)]
#[try_into(T = ImportProofSchemaCredentialSchemaDTO, Error = BindingError)]
pub struct ImportProofSchemaCredentialSchemaBindingDTO {
    #[try_into(with_fn_ref = into_id)]
    pub id: String,
    #[try_into(with_fn_ref = into_timestamp)]
    pub created_date: String,
    #[try_into(with_fn_ref = into_timestamp)]
    pub last_modified: String,
    #[try_into(infallible)]
    pub name: String,
    #[try_into(infallible)]
    pub format: String,
    #[try_into(infallible)]
    pub revocation_method: String,
    #[try_into(with_fn = convert_inner, infallible)]
    pub wallet_storage_type: Option<WalletStorageTypeBindingEnum>,
    #[try_into(infallible)]
    pub schema_id: String,
    #[try_into(infallible)]
    pub imported_source_url: String,
    #[try_into(infallible)]
    pub schema_type: CredentialSchemaTypeBindingEnum,
    #[try_into(with_fn = convert_inner, infallible)]
    pub layout_type: Option<LayoutTypeBindingEnum>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesBindingDTO>,
}

#[derive(Debug, Clone, From)]
#[from(CredentialSchemaDetailResponseDTO)]
pub struct CredentialSchemaDetailBindingDTO {
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
    pub claims: Vec<CredentialClaimSchemaBindingDTO>,
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
#[from(CredentialClaimSchemaDTO)]
pub struct CredentialClaimSchemaBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub array: bool,
    #[from(with_fn = convert_inner)]
    pub claims: Vec<CredentialClaimSchemaBindingDTO>,
}

#[derive(Debug, Clone, From, Into)]
#[from(CredentialSchemaLayoutPropertiesRequestDTO)]
#[into(CredentialSchemaLayoutPropertiesRequestDTO)]
pub struct CredentialSchemaLayoutPropertiesBindingDTO {
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub background: Option<CredentialSchemaBackgroundPropertiesBindingDTO>,
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub logo: Option<CredentialSchemaLogoPropertiesBindingDTO>,
    pub primary_attribute: Option<String>,
    pub secondary_attribute: Option<String>,
    pub picture_attribute: Option<String>,
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub code: Option<CredentialSchemaCodePropertiesBindingDTO>,
}

#[derive(Debug, Clone, From, Into)]
#[from(CredentialSchemaBackgroundPropertiesRequestDTO)]
#[into(CredentialSchemaBackgroundPropertiesRequestDTO)]
pub struct CredentialSchemaBackgroundPropertiesBindingDTO {
    pub color: Option<String>,
    pub image: Option<String>,
}

#[derive(Debug, Clone, From, Into)]
#[from(CredentialSchemaLogoPropertiesRequestDTO)]
#[into(CredentialSchemaLogoPropertiesRequestDTO)]
pub struct CredentialSchemaLogoPropertiesBindingDTO {
    pub font_color: Option<String>,
    pub background_color: Option<String>,
    pub image: Option<String>,
}

#[derive(Debug, Clone, From, Into)]
#[from(CredentialSchemaCodePropertiesRequestDTO)]
#[into(CredentialSchemaCodePropertiesRequestDTO)]
pub struct CredentialSchemaCodePropertiesBindingDTO {
    pub attribute: String,
    pub r#type: CredentialSchemaCodeTypeBindingDTO,
}

#[derive(Debug, Clone, From, Into)]
#[from(CredentialSchemaCodeTypeEnum)]
#[into(CredentialSchemaCodeTypeEnum)]
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

#[derive(Clone, Debug, Eq, PartialEq, From, Into)]
#[from(LayoutType)]
#[into(LayoutType)]
pub enum LayoutTypeBindingEnum {
    Card,
    Document,
    SingleAttribute,
}

#[derive(From, Clone, Debug, Into)]
#[from(WalletStorageTypeEnum)]
#[into(WalletStorageTypeEnum)]
pub enum WalletStorageTypeBindingEnum {
    Hardware,
    Software,
}

#[derive(Debug, Clone)]
pub struct ClaimBindingDTO {
    pub id: String,
    pub key: String,
    pub data_type: String,
    pub array: bool,
    pub value: ClaimValueBindingDTO,
}

#[derive(Debug, Clone)]
pub enum ClaimValueBindingDTO {
    Boolean { value: bool },
    Float { value: f64 },
    Integer { value: i64 },
    String { value: String },
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
    pub verifier_did: Option<String>,
    pub state: ProofStateBindingEnum,
    pub proof_schema: Option<GetProofSchemaListItemBindingDTO>,
    pub exchange: String,
    pub redirect_uri: Option<String>,
    pub proof_inputs: Vec<ProofInputBindingDTO>,
    pub retain_until_date: Option<String>,
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

pub enum ProofRequestClaimValueBindingDTO {
    Value {
        value: String,
    },
    Claims {
        value: Vec<ProofRequestClaimBindingDTO>,
    },
}

impl From<ProofClaimValueDTO> for ProofRequestClaimValueBindingDTO {
    fn from(value: ProofClaimValueDTO) -> Self {
        match value {
            ProofClaimValueDTO::Value(value) => Self::Value { value },
            ProofClaimValueDTO::Claims(claims) => ProofRequestClaimValueBindingDTO::Claims {
                value: convert_inner(claims),
            },
        }
    }
}

#[derive(Debug, From)]
#[from(ProofClaimSchemaResponseDTO)]
pub struct ProofClaimSchemaBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    pub required: bool,
    pub key: String,
    pub data_type: String,
    #[from(with_fn = convert_inner)]
    pub claims: Vec<ProofClaimSchemaBindingDTO>,
    pub array: bool,
}

#[derive(Debug)]
pub struct ImportProofSchemaClaimSchemaBindingDTO {
    pub id: String,
    pub required: bool,
    pub key: String,
    pub data_type: String,
    pub claims: Option<Vec<ImportProofSchemaClaimSchemaBindingDTO>>,
    pub array: bool,
}

#[derive(From)]
#[from(ProofClaimDTO)]
pub struct ProofRequestClaimBindingDTO {
    pub schema: ProofClaimSchemaBindingDTO,
    #[from(with_fn = convert_inner)]
    pub value: Option<ProofRequestClaimValueBindingDTO>,
}

#[derive(From)]
#[from(ProofInputDTO)]
pub struct ProofInputBindingDTO {
    #[from(with_fn = convert_inner)]
    pub claims: Vec<ProofRequestClaimBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub credential: Option<CredentialDetailBindingDTO>,
    pub credential_schema: CredentialSchemaBindingDTO,
    pub validity_constraint: Option<i64>,
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
#[into(StorageGeneratedKey)]
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

#[derive(From)]
#[from(ServiceDescription)]
pub struct ServiceDescriptionBindingDTO {
    pub uuid: String,
    pub advertise: bool,
    pub advertised_service_data: Option<Vec<u8>>,
    #[from(with_fn = convert_inner)]
    pub characteristics: Vec<CharacteristicBindingDTO>,
}

#[derive(From)]
#[from(CreateCharacteristicOptions)]
pub struct CharacteristicBindingDTO {
    pub uuid: String,
    #[from(with_fn = convert_inner)]
    pub permissions: Vec<CharacteristicPermissionBindingEnum>,
    #[from(with_fn = convert_inner)]
    pub properties: Vec<CharacteristicPropertyBindingEnum>,
}

#[derive(From)]
#[from(CharacteristicPermissions)]
pub enum CharacteristicPermissionBindingEnum {
    Read,
    Write,
}

#[derive(From)]
#[from(CharacteristicProperties)]
pub enum CharacteristicPropertyBindingEnum {
    Read,
    Write,
    Notify,
    WriteWithoutResponse,
    Indicate,
}

#[derive(Into)]
#[into(ConnectionEvent)]
pub enum ConnectionEventBindingEnum {
    Connected { device_info: DeviceInfoBindingDTO },
    Disconnected { device_address: DeviceAddress },
}

pub struct DeviceInfoBindingDTO {
    pub address: String,
    pub mtu: u16,
}

#[async_trait::async_trait]
pub trait BlePeripheral: Send + Sync {
    async fn is_adapter_enabled(&self) -> Result<bool, BleErrorWrapper>;
    async fn start_advertisement(
        &self,
        device_name: Option<String>,
        services: Vec<ServiceDescriptionBindingDTO>,
    ) -> Result<Option<MacAddress>, BleErrorWrapper>;
    async fn stop_advertisement(&self) -> Result<(), BleErrorWrapper>;
    async fn is_advertising(&self) -> Result<bool, BleErrorWrapper>;
    async fn set_characteristic_data(
        &self,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
        data: Vec<u8>,
    ) -> Result<(), BleErrorWrapper>;
    async fn notify_characteristic_data(
        &self,
        device_address: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
        data: Vec<u8>,
    ) -> Result<(), BleErrorWrapper>;
    async fn get_connection_change_events(
        &self,
    ) -> Result<Vec<ConnectionEventBindingEnum>, BleErrorWrapper>;
    async fn get_characteristic_writes(
        &self,
        device: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<Vec<Vec<u8>>, BleErrorWrapper>;
    async fn wait_for_characteristic_read(
        &self,
        device: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<(), BleErrorWrapper>;
    async fn stop_server(&self) -> Result<(), BleErrorWrapper>;
}

#[derive(From)]
#[from(CharacteristicWriteType)]
pub enum CharacteristicWriteTypeBindingEnum {
    WithResponse,
    WithoutResponse,
}

#[derive(Into)]
#[into(PeripheralDiscoveryData)]
pub struct PeripheralDiscoveryDataBindingDTO {
    pub device_address: DeviceAddress,
    pub local_device_name: Option<String>,
    pub advertised_services: Vec<ServiceUUID>,
    pub advertised_service_data: Option<HashMap<ServiceUUID, Vec<u8>>>,
}

#[async_trait::async_trait]
pub trait BleCentral: Send + Sync {
    async fn is_adapter_enabled(&self) -> Result<bool, BleErrorWrapper>;
    async fn start_scan(
        &self,
        filter_services: Option<Vec<ServiceUUID>>,
    ) -> Result<(), BleErrorWrapper>;
    async fn stop_scan(&self) -> Result<(), BleErrorWrapper>;
    async fn is_scanning(&self) -> Result<bool, BleErrorWrapper>;
    async fn write_data(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
        data: Vec<u8>,
        write_type: CharacteristicWriteTypeBindingEnum,
    ) -> Result<(), BleErrorWrapper>;
    async fn read_data(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<Vec<u8>, BleErrorWrapper>;
    async fn connect(&self, peripheral: DeviceAddress) -> Result<u16, BleErrorWrapper>;
    async fn disconnect(&self, peripheral: DeviceAddress) -> Result<(), BleErrorWrapper>;
    async fn get_discovered_devices(
        &self,
    ) -> Result<Vec<PeripheralDiscoveryDataBindingDTO>, BleErrorWrapper>;
    async fn subscribe_to_characteristic_notifications(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<(), BleErrorWrapper>;
    async fn unsubscribe_from_characteristic_notifications(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<(), BleErrorWrapper>;
    async fn get_notifications(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<Vec<Vec<u8>>, BleErrorWrapper>;
}

#[derive(From, Into)]
#[from(HistoryAction)]
#[into(HistoryAction)]
pub enum HistoryActionBindingEnum {
    Accepted,
    Created,
    Deactivated,
    Deleted,
    Errored,
    Issued,
    Offered,
    Reactivated,
    Rejected,
    Requested,
    Revoked,
    Suspended,
    Pending,
    Restored,
    Shared,
    Imported,
    ClaimsRemoved,
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
    TrustAnchor,
    TrustEntity,
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
    pub proof_schema_id: Option<String>,
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
    ProofSchemaName,
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

#[derive(Clone, Debug)]
pub struct CreateTrustAnchorRequestBindingDTO {
    pub name: String,
    pub r#type: String,
    pub publisher_reference: Option<String>,
    pub role: TrustAnchorRoleBinding,
    pub priority: Option<u32>,
    pub organisation_id: String,
}

#[derive(Clone, Debug, Into, From)]
#[into(TrustAnchorRole)]
#[from(TrustAnchorRole)]
pub enum TrustAnchorRoleBinding {
    Publisher,
    Client,
}

#[derive(Clone, Debug, From)]
#[from(GetTrustAnchorDetailResponseDTO)]
pub struct GetTrustAnchorResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    pub name: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub r#type: String,
    pub publisher_reference: Option<String>,
    pub role: TrustAnchorRoleBinding,
    pub priority: Option<u32>,
    #[from(with_fn_ref = "ToString::to_string")]
    pub organisation_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Into)]
#[into(SortableTrustAnchorColumn)]
pub enum SortableTrustAnchorColumnBindings {
    Name,
    CreatedDate,
    Type,
    Role,
    Priority,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExactTrustAnchorFilterColumnBindings {
    Name,
    Type,
}

#[derive(Clone, Debug)]
pub struct ListTrustAnchorsFiltersBindings {
    pub page: u32,
    pub page_size: u32,

    pub sort: Option<SortableTrustAnchorColumnBindings>,
    pub sort_direction: Option<SortDirection>,

    pub name: Option<String>,
    pub role: Option<TrustAnchorRoleBinding>,
    pub r#type: Option<String>,
    pub organisation_id: String,

    pub exact: Option<Vec<ExactTrustAnchorFilterColumnBindings>>,
}

#[derive(Clone, Debug, From)]
#[from(TrustAnchorsListItemResponseDTO)]
pub struct TrustAnchorsListItemResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    pub name: String,

    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,

    pub r#type: String,
    pub publisher_reference: Option<String>,
    pub role: TrustAnchorRoleBinding,
    pub priority: Option<u32>,
    #[from(with_fn_ref = "ToString::to_string")]
    pub organisation_id: String,
    pub entities: u64,
}

#[derive(From)]
#[from(GetTrustAnchorsResponseDTO)]
pub struct TrustAnchorsListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<TrustAnchorsListItemResponseBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, Into)]
#[into(SortableProofSchemaColumn)]
pub enum SortableProofSchemaColumnBinding {
    Name,
    CreatedDate,
}

#[derive(Clone, Debug, Into)]
#[into(ExactColumn)]
pub enum ProofSchemaListQueryExactColumnBinding {
    Name,
}

#[derive(Clone, Debug)]
pub struct ListProofSchemasFiltersBindingDTO {
    pub page: u32,
    pub page_size: u32,

    pub sort: Option<SortableProofSchemaColumnBinding>,
    pub sort_direction: Option<SortDirection>,

    pub organisation_id: String,
    pub name: Option<String>,
    pub exact: Option<Vec<ProofSchemaListQueryExactColumnBinding>>,
    pub ids: Option<Vec<String>>,
}

#[derive(Clone, Debug, From)]
#[from(GetProofSchemaListItemDTO)]
pub struct GetProofSchemaListItemBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    #[from(with_fn = optional_time)]
    pub deleted_at: Option<String>,
    pub name: String,
    pub expire_duration: u32,
}

#[derive(Clone, Debug, From)]
#[from(GetProofSchemaListResponseDTO)]
pub struct ProofSchemaListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<GetProofSchemaListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Debug, TryInto)]
#[try_into(T = ImportProofSchemaRequestDTO, Error = BindingError)]
pub struct ImportProofSchemaRequestBindingsDTO {
    pub schema: ImportProofSchemaBindingDTO,
    #[try_into(with_fn_ref = into_id)]
    pub organisation_id: String,
}

#[derive(Debug, TryInto)]
#[try_into(T = ImportProofSchemaDTO, Error = BindingError)]
pub struct ImportProofSchemaBindingDTO {
    #[try_into(with_fn_ref = into_id)]
    pub id: String,
    #[try_into(with_fn_ref = into_timestamp)]
    pub created_date: String,
    #[try_into(with_fn_ref = into_timestamp)]
    pub last_modified: String,
    #[try_into(infallible)]
    pub name: String,
    #[try_into(with_fn_ref = into_id)]
    pub organisation_id: String,
    #[try_into(infallible)]
    pub expire_duration: u32,
    #[try_into(infallible)]
    pub imported_source_url: String,
    #[try_into(with_fn = try_convert_inner)]
    pub proof_input_schemas: Vec<ImportProofSchemaInputSchemaBindingDTO>,
}

#[derive(Debug, From)]
#[from(GetProofSchemaResponseDTO)]
pub struct GetProofSchemaBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub name: String,
    #[from(with_fn_ref = "ToString::to_string")]
    pub organisation_id: String,
    pub expire_duration: u32,
    #[from(with_fn = convert_inner)]
    pub proof_input_schemas: Vec<ProofInputSchemaBindingDTO>,
}

#[derive(Debug, From)]
#[from(ProofInputSchemaResponseDTO)]
pub struct ProofInputSchemaBindingDTO {
    #[from(with_fn = convert_inner)]
    pub claim_schemas: Vec<ProofClaimSchemaBindingDTO>,
    pub credential_schema: CredentialSchemaBindingDTO,
    pub validity_constraint: Option<i64>,
}

#[derive(Debug, TryInto)]
#[try_into(T = ImportProofSchemaInputSchemaDTO, Error = BindingError)]
pub struct ImportProofSchemaInputSchemaBindingDTO {
    #[try_into(with_fn = try_convert_inner)]
    pub claim_schemas: Vec<ImportProofSchemaClaimSchemaBindingDTO>,
    pub credential_schema: ImportProofSchemaCredentialSchemaBindingDTO,
    #[try_into(infallible)]
    pub validity_constraint: Option<i64>,
}

#[derive(Debug, TryInto)]
#[try_into(T = one_core::service::proof_schema::dto::CreateProofSchemaRequestDTO, Error = ServiceError)]
pub struct CreateProofSchemaRequestDTO {
    #[try_into(infallible)]
    pub name: String,
    #[try_into(with_fn_ref = into_id)]
    pub organisation_id: String,
    #[try_into(infallible)]
    pub expire_duration: u32,
    #[try_into(with_fn = try_convert_inner)]
    pub proof_input_schemas: Vec<ProofInputSchemaRequestDTO>,
}

#[derive(Debug, TryInto)]
#[try_into(T = one_core::service::proof_schema::dto::ProofInputSchemaRequestDTO, Error = ServiceError)]
pub struct ProofInputSchemaRequestDTO {
    #[try_into(with_fn_ref = into_id)]
    pub credential_schema_id: String,
    #[try_into(with_fn = convert_inner, infallible)]
    pub validity_constraint: Option<i64>,
    #[try_into(with_fn = try_convert_inner)]
    pub claim_schemas: Vec<CreateProofSchemaClaimRequestDTO>,
}

#[derive(Debug, TryInto)]
#[try_into(T = one_core::service::proof_schema::dto::CreateProofSchemaClaimRequestDTO, Error = ServiceError)]
pub struct CreateProofSchemaClaimRequestDTO {
    #[try_into(with_fn_ref = into_id)]
    pub id: String,
    #[try_into(infallible)]
    pub required: bool,
}

#[derive(Debug, TryInto)]
#[try_into(T = ImportCredentialSchemaRequestDTO, Error = ServiceError)]
pub struct ImportCredentialSchemaRequestBindingDTO {
    #[try_into(with_fn_ref = into_id)]
    pub organisation_id: String,
    pub schema: ImportCredentialSchemaRequestSchemaBindingDTO,
}

#[derive(Debug, TryInto)]
#[try_into(T = ImportCredentialSchemaRequestSchemaDTO, Error = ServiceError)]
pub struct ImportCredentialSchemaRequestSchemaBindingDTO {
    #[try_into(with_fn_ref = into_id)]
    pub id: String,
    #[try_into(with_fn_ref = into_timestamp)]
    pub created_date: String,
    #[try_into(with_fn_ref = into_timestamp)]
    pub last_modified: String,
    #[try_into(infallible)]
    pub name: String,
    #[try_into(infallible)]
    pub format: String,
    #[try_into(infallible)]
    pub revocation_method: String,
    #[try_into(with_fn_ref = into_id)]
    pub organisation_id: String,

    #[try_into(with_fn = try_convert_inner)]
    pub claims: Vec<ImportCredentialSchemaClaimSchemaBindingDTO>,
    #[try_into(infallible, with_fn = convert_inner)]
    pub wallet_storage_type: Option<WalletStorageTypeBindingEnum>,
    #[try_into(infallible)]
    pub schema_id: String,
    #[try_into(infallible)]
    pub imported_source_url: String,
    #[try_into(infallible)]
    pub schema_type: CredentialSchemaTypeBindingEnum,
    #[try_into(infallible, with_fn = convert_inner)]
    pub layout_type: Option<LayoutTypeBindingEnum>,
    #[try_into(infallible, with_fn = convert_inner)]
    pub layout_properties: Option<ImportCredentialSchemaLayoutPropertiesBindingDTO>,
}

#[derive(Debug)]
pub struct ImportCredentialSchemaClaimSchemaBindingDTO {
    pub id: String,
    pub created_date: String,
    pub last_modified: String,
    pub required: bool,
    pub key: String,
    pub datatype: String,
    pub array: Option<bool>,
    pub claims: Option<Vec<ImportCredentialSchemaClaimSchemaBindingDTO>>,
}

#[derive(Debug, Into)]
#[into(ImportCredentialSchemaLayoutPropertiesDTO)]
pub struct ImportCredentialSchemaLayoutPropertiesBindingDTO {
    #[into(with_fn = convert_inner)]
    pub background: Option<CredentialSchemaBackgroundPropertiesBindingDTO>,
    #[into(with_fn = convert_inner)]
    pub logo: Option<CredentialSchemaLogoPropertiesBindingDTO>,
    pub primary_attribute: Option<String>,
    pub secondary_attribute: Option<String>,
    pub picture_attribute: Option<String>,
    #[into(with_fn = convert_inner)]
    pub code: Option<CredentialSchemaCodePropertiesBindingDTO>,
}

#[derive(TryInto)]
#[try_into(T = CreateProofRequestDTO, Error = ServiceError)]
pub struct CreateProofRequestBindingDTO {
    #[try_into(with_fn_ref = into_id)]
    pub proof_schema_id: String,
    #[try_into(with_fn_ref = into_id)]
    pub verifier_did_id: String,
    #[try_into(infallible)]
    pub exchange: String,
    #[try_into(with_fn = convert_inner, infallible)]
    pub redirect_uri: Option<String>,
    #[try_into(with_fn = into_id_opt)]
    pub verifier_key: Option<String>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub scan_to_verify: Option<ScanToVerifyRequestBindingDTO>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub iso_mdl_engagement: Option<String>,
}

#[derive(Into)]
#[into(ScanToVerifyRequestDTO)]
pub struct ScanToVerifyRequestBindingDTO {
    pub credential: String,
    pub barcode: String,
    pub barcode_type: ScanToVerifyBarcodeTypeBindingEnum,
}

#[derive(Clone, Debug, Into)]
#[into(ScanToVerifyBarcodeTypeEnum)]
pub enum ScanToVerifyBarcodeTypeBindingEnum {
    #[allow(clippy::upper_case_acronyms)]
    MRZ,
    PDF417,
}

#[derive(From)]
#[from(EntityShareResponseDTO)]
pub struct ShareProofResponseBindingDTO {
    pub url: String,
}

#[derive(From)]
#[from(ProofSchemaShareResponseDTO)]
pub struct ProofSchemaShareResponseBindingDTO {
    pub url: String,
}

#[derive(From)]
#[from(CredentialSchemaShareResponseDTO)]
pub struct CredentialSchemaShareResponseBindingDTO {
    pub url: String,
}

pub struct ResolveJsonLDContextResponseBindingDTO {
    pub context: String,
}

#[derive(Clone, Debug, From)]
#[from(ProposeProofResponseDTO)]
pub struct ProposeProofResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub proof_id: String,
    #[from(with_fn_ref = "ToString::to_string")]
    pub interaction_id: String,
    pub url: String,
}

#[derive(Clone, Debug, Into)]
#[into(KeyCheckCertificateRequestDTO)]
pub struct KeyCheckCertificateRequestBindingDTO {
    pub certificate: String,
}
