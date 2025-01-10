use std::collections::HashMap;

use one_core::model::common::{EntityShareResponseDTO, ExactColumn};
use one_core::model::credential::SortableCredentialColumn;
use one_core::model::credential_schema::{
    LayoutType, SortableCredentialSchemaColumn, WalletStorageTypeEnum,
};
use one_core::model::did::{DidType, KeyRole, SortableDidColumn};
use one_core::model::history::{HistoryAction, HistoryEntityType, HistorySearchEnum};
use one_core::model::proof::{ProofStateEnum, SortableProofColumn};
use one_core::model::proof_schema::SortableProofSchemaColumn;
use one_core::model::trust_entity::{TrustEntityRole, TrustEntityState};
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
use one_core::provider::exchange_protocol::openid4vc::model::{
    OpenID4VCITxCode, OpenID4VCITxCodeInputMode,
};
use one_core::provider::exchange_protocol::openid4vc::openidvc_http::ClientIdSchemaType;
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
    CreateProofRequestDTO, GetProofListResponseDTO, ProofClaimDTO, ProofInputDTO,
    ProofListItemResponseDTO, ProposeProofResponseDTO, ScanToVerifyBarcodeTypeEnum,
    ScanToVerifyRequestDTO, ShareProofRequestDTO, ShareProofRequestParamsDTO,
};
use one_core::service::proof_schema::dto::{
    GetProofSchemaListItemDTO, GetProofSchemaListResponseDTO, GetProofSchemaResponseDTO,
    ImportProofSchemaCredentialSchemaDTO, ImportProofSchemaDTO, ImportProofSchemaInputSchemaDTO,
    ImportProofSchemaRequestDTO, ProofClaimSchemaResponseDTO, ProofInputSchemaResponseDTO,
    ProofSchemaShareResponseDTO,
};
use one_core::service::ssi_holder::dto::PresentationSubmitCredentialRequestDTO;
use one_core::service::trust_anchor::dto::{
    CreateTrustAnchorRequestDTO, GetTrustAnchorDetailResponseDTO, GetTrustAnchorsResponseDTO,
    SortableTrustAnchorColumn, TrustAnchorsListItemResponseDTO,
};
use one_core::service::trust_entity::dto::{
    CreateRemoteTrustEntityRequestDTO, CreateTrustEntityRequestDTO, GetTrustEntitiesResponseDTO,
    GetTrustEntityResponseDTO, SortableTrustEntityColumnEnum, TrustEntitiesResponseItemDTO,
    UpdateTrustEntityActionFromDidRequestDTO, UpdateTrustEntityFromDidRequestDTO,
};
use one_dto_mapper::{convert_inner, try_convert_inner, From, Into, TryInto};

use crate::error::{BleError, ErrorResponseBindingDTO, NativeKeyStorageError};
use crate::mapper::{optional_did_string, optional_time, serialize_config_entity, OptionalString};
use crate::utils::{
    format_timestamp_opt, from_id_opt, into_id, into_id_opt, into_timestamp, TimestampFormat,
};

#[derive(Clone, Debug, From, uniffi::Record)]
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
    pub trust_management: HashMap<String, String>,
    #[from(with_fn = serialize_config_entity)]
    pub cache_entities: HashMap<String, String>,
}

#[derive(Clone, Debug, From, Into, uniffi::Enum)]
#[from(CredentialStateEnum)]
#[into(one_core::model::credential::CredentialStateEnum)]
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

#[derive(Clone, Debug, From, Into, uniffi::Enum)]
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

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(one_core::Version)]
pub struct VersionBindingDTO {
    pub target: String,
    pub build_time: String,
    pub branch: String,
    pub tag: String,
    pub commit: String,
    pub rust_version: String,
    pub pipeline_id: String,
}

#[derive(Clone, Debug, Into, From, uniffi::Enum)]
#[from(CredentialRole)]
#[into(CredentialRole)]
pub enum CredentialRoleBindingDTO {
    Holder,
    Issuer,
    Verifier,
}

#[derive(Clone, Debug, uniffi::Record)]
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

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(CredentialSchemaListIncludeEntityTypeEnum)]
pub enum CredentialSchemaListIncludeEntityType {
    LayoutProperties,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(SortableCredentialSchemaColumn)]
pub enum SortableCredentialSchemaColumnBindingEnum {
    Name,
    Format,
    CreatedDate,
}

#[derive(Clone, Debug, PartialEq, Into, uniffi::Enum)]
#[into(ExactColumn)]
pub enum CredentialSchemaListQueryExactColumnBindingEnum {
    Name,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetCredentialSchemaListResponseDTO)]
pub struct CredentialSchemaListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<CredentialSchemaBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, PartialEq, Into, uniffi::Enum)]
#[into(ExactColumn)]
pub enum CredentialListQueryExactColumnBindingEnum {
    Name,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(one_core::model::common::SortDirection)]
pub enum SortDirection {
    Ascending,
    Descending,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(SortableCredentialColumn)]
pub enum SortableCredentialColumnBindingEnum {
    CreatedDate,
    SchemaName,
    IssuerDid,
    State,
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum SearchTypeBindingEnum {
    ClaimName,
    ClaimValue,
    CredentialSchemaName,
}

#[derive(Clone, Debug, uniffi::Record)]
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

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(CredentialListIncludeEntityTypeEnum)]
pub enum CredentialListIncludeEntityTypeBindingEnum {
    LayoutProperties,
    Credential,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetCredentialListResponseDTO)]
pub struct CredentialListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<CredentialListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, PartialEq, Into, uniffi::Enum)]
#[into(ExactColumn)]
pub enum ProofListQueryExactColumnBindingEnum {
    Name,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(SortableProofColumn)]
pub enum SortableProofListColumnBinding {
    SchemaName,
    VerifierDid,
    State,
    CreatedDate,
}

#[derive(Clone, Debug, uniffi::Record)]
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

#[derive(Clone, Debug, From, uniffi::Record)]
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

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetProofListResponseDTO)]
pub struct ProofListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<ProofListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetDidListResponseDTO)]
pub struct DidListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<DidListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(SortableDidColumn)]
pub enum SortableDidColumnBindingEnum {
    Name,
    CreatedDate,
    Method,
    Type,
    Did,
    Deactivated,
}

#[derive(Clone, Debug, PartialEq, uniffi::Enum)]
pub enum ExactDidFilterColumnBindingEnum {
    Name,
    Did,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(KeyRole)]
pub enum KeyRoleBindingEnum {
    Authentication,
    AssertionMethod,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
}

#[derive(Clone, Debug, uniffi::Record)]
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
    pub key_storages: Option<Vec<String>>,
    pub key_ids: Option<Vec<String>>,
    pub did_methods: Option<Vec<String>>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct CredentialDetailBindingDTO {
    pub id: String,
    pub created_date: String,
    pub issuance_date: String,
    pub last_modified: String,
    pub revocation_date: Option<String>,
    pub issuer_did: Option<DidListItemBindingDTO>,
    pub holder_did: Option<DidListItemBindingDTO>,
    pub state: CredentialStateBindingEnum,
    pub schema: CredentialSchemaBindingDTO,
    pub claims: Vec<ClaimBindingDTO>,
    pub redirect_uri: Option<String>,
    pub role: CredentialRoleBindingDTO,
    pub lvvc_issuance_date: Option<String>,
    pub suspend_end_date: Option<String>,
    pub mdoc_mso_validity: Option<MdocMsoValidityResponseBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MdocMsoValidityResponseBindingDTO {
    pub expiration: String,
    pub next_update: String,
    pub last_update: String,
}

#[derive(Clone, Debug, uniffi::Record)]
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

#[derive(Clone, Debug, From, uniffi::Record)]
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

#[derive(Clone, Debug, From, uniffi::Record)]
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

#[derive(Clone, Debug, uniffi::Record)]
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
    pub imported_source_url: String,
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesBindingDTO>,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = ImportProofSchemaCredentialSchemaDTO, Error = ErrorResponseBindingDTO)]
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

#[derive(Clone, Debug, From, uniffi::Record)]
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
    pub imported_source_url: String,
    #[from(with_fn = convert_inner)]
    pub layout_type: Option<LayoutTypeBindingEnum>,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesBindingDTO>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
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

#[derive(Clone, Debug, From, Into, uniffi::Record)]
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

#[derive(Clone, Debug, From, Into, uniffi::Record)]
#[from(CredentialSchemaBackgroundPropertiesRequestDTO)]
#[into(CredentialSchemaBackgroundPropertiesRequestDTO)]
pub struct CredentialSchemaBackgroundPropertiesBindingDTO {
    pub color: Option<String>,
    pub image: Option<String>,
}

#[derive(Clone, Debug, From, Into, uniffi::Record)]
#[from(CredentialSchemaLogoPropertiesRequestDTO)]
#[into(CredentialSchemaLogoPropertiesRequestDTO)]
pub struct CredentialSchemaLogoPropertiesBindingDTO {
    pub font_color: Option<String>,
    pub background_color: Option<String>,
    pub image: Option<String>,
}

#[derive(Clone, Debug, From, Into, uniffi::Record)]
#[from(CredentialSchemaCodePropertiesRequestDTO)]
#[into(CredentialSchemaCodePropertiesRequestDTO)]
pub struct CredentialSchemaCodePropertiesBindingDTO {
    pub attribute: String,
    pub r#type: CredentialSchemaCodeTypeBindingDTO,
}

#[derive(Clone, Debug, From, Into, uniffi::Enum)]
#[from(CredentialSchemaCodeTypeEnum)]
#[into(CredentialSchemaCodeTypeEnum)]
pub enum CredentialSchemaCodeTypeBindingDTO {
    Barcode,
    Mrz,
    QrCode,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum CredentialSchemaTypeBindingEnum {
    ProcivisOneSchema2024 {},
    FallbackSchema2024 {},
    Mdoc {},
    Other { value: String },
}

#[derive(Clone, Debug, Eq, PartialEq, From, Into, uniffi::Enum)]
#[from(LayoutType)]
#[into(LayoutType)]
pub enum LayoutTypeBindingEnum {
    Card,
    Document,
    SingleAttribute,
}

#[derive(From, Clone, Debug, Into, uniffi::Enum)]
#[from(WalletStorageTypeEnum)]
#[into(WalletStorageTypeEnum)]
pub enum WalletStorageTypeBindingEnum {
    Hardware,
    Software,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ClaimBindingDTO {
    pub id: String,
    pub key: String,
    pub data_type: String,
    pub array: bool,
    pub value: ClaimValueBindingDTO,
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum ClaimValueBindingDTO {
    Boolean { value: bool },
    Float { value: f64 },
    Integer { value: i64 },
    String { value: String },
    Nested { value: Vec<ClaimBindingDTO> },
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum HandleInvitationResponseBindingEnum {
    CredentialIssuance {
        interaction_id: String,
        credential_ids: Vec<String>,
        tx_code: Option<OpenID4VCITxCodeBindingDTO>,
    },
    ProofRequest {
        interaction_id: String,
        proof_id: String,
    },
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(OpenID4VCITxCode)]
pub struct OpenID4VCITxCodeBindingDTO {
    pub input_mode: OpenID4VCITxCodeInputModeBindingEnum,
    #[from(with_fn = convert_inner)]
    pub length: Option<i64>,
    #[from(with_fn = convert_inner)]
    pub description: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Enum)]
#[from(OpenID4VCITxCodeInputMode)]
pub enum OpenID4VCITxCodeInputModeBindingEnum {
    Numeric,
    Text,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ProofRequestBindingDTO {
    pub id: String,
    pub created_date: String,
    pub last_modified: String,
    pub verifier_did: Option<DidListItemBindingDTO>,
    pub holder_did: Option<DidListItemBindingDTO>,
    pub state: ProofStateBindingEnum,
    pub proof_schema: Option<GetProofSchemaListItemBindingDTO>,
    pub exchange: String,
    pub redirect_uri: Option<String>,
    pub proof_inputs: Vec<ProofInputBindingDTO>,
    pub retain_until_date: Option<String>,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = PresentationSubmitCredentialRequestDTO, Error = ServiceError)]
pub struct PresentationSubmitCredentialRequestBindingDTO {
    #[try_into(with_fn_ref = into_id)]
    pub credential_id: String,
    #[try_into(infallible)]
    pub submit_claims: Vec<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(PresentationDefinitionResponseDTO)]
pub struct PresentationDefinitionBindingDTO {
    #[from(with_fn = convert_inner)]
    pub request_groups: Vec<PresentationDefinitionRequestGroupBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum ProofRequestClaimValueBindingDTO {
    Value {
        value: String,
    },
    Claims {
        value: Vec<ProofRequestClaimBindingDTO>,
    },
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ProofClaimSchemaResponseDTO)]
pub struct ProofClaimSchemaBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    pub requested: bool,
    pub required: bool,
    pub key: String,
    pub data_type: String,
    #[from(with_fn = convert_inner)]
    pub claims: Vec<ProofClaimSchemaBindingDTO>,
    pub array: bool,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ImportProofSchemaClaimSchemaBindingDTO {
    pub id: String,
    pub requested: bool,
    pub required: bool,
    pub key: String,
    pub data_type: String,
    pub claims: Option<Vec<ImportProofSchemaClaimSchemaBindingDTO>>,
    pub array: bool,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ProofClaimDTO)]
pub struct ProofRequestClaimBindingDTO {
    pub schema: ProofClaimSchemaBindingDTO,
    #[from(with_fn = convert_inner)]
    pub value: Option<ProofRequestClaimValueBindingDTO>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ProofInputDTO)]
pub struct ProofInputBindingDTO {
    #[from(with_fn = convert_inner)]
    pub claims: Vec<ProofRequestClaimBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub credential: Option<CredentialDetailBindingDTO>,
    pub credential_schema: CredentialSchemaBindingDTO,
    pub validity_constraint: Option<i64>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(PresentationDefinitionRequestGroupResponseDTO)]
pub struct PresentationDefinitionRequestGroupBindingDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub rule: PresentationDefinitionRuleBindingDTO,
    #[from(with_fn = convert_inner)]
    pub requested_credentials: Vec<PresentationDefinitionRequestedCredentialBindingDTO>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(PresentationDefinitionRequestedCredentialResponseDTO)]
pub struct PresentationDefinitionRequestedCredentialBindingDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    #[from(with_fn = convert_inner)]
    pub fields: Vec<PresentationDefinitionFieldBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub applicable_credentials: Vec<String>,
    #[from(with_fn = convert_inner)]
    pub inapplicable_credentials: Vec<String>,
    #[from(with_fn = format_timestamp_opt)]
    pub validity_credential_nbf: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(PresentationDefinitionFieldDTO)]
pub struct PresentationDefinitionFieldBindingDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    #[from(unwrap_or = true)]
    pub required: bool,
    pub key_map: HashMap<String, String>,
}

#[derive(Clone, Debug, From, uniffi::Enum)]
#[from(PresentationDefinitionRuleTypeEnum)]
pub enum PresentationDefinitionRuleTypeBindingEnum {
    All,
    Pick,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(PresentationDefinitionRuleDTO)]
pub struct PresentationDefinitionRuleBindingDTO {
    pub r#type: PresentationDefinitionRuleTypeBindingEnum,
    pub min: Option<u32>,
    pub max: Option<u32>,
    pub count: Option<u32>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct KeyRequestBindingDTO {
    pub organisation_id: String,
    pub key_type: String,
    pub key_params: HashMap<String, String>,
    pub name: String,
    pub storage_type: String,
    pub storage_params: HashMap<String, String>,
}

#[derive(Clone, Debug, Into, From, uniffi::Enum)]
#[into(DidType)]
#[from(DidType)]
pub enum DidTypeBindingEnum {
    Local,
    Remote,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct DidRequestBindingDTO {
    pub organisation_id: String,
    pub name: String,
    pub did_method: String,
    pub keys: DidRequestKeysBindingDTO,
    pub params: HashMap<String, String>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct DidRequestKeysBindingDTO {
    pub authentication: Vec<String>,
    pub assertion_method: Vec<String>,
    pub key_agreement: Vec<String>,
    pub capability_invocation: Vec<String>,
    pub capability_delegation: Vec<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(CredentialRevocationCheckResponseDTO)]
pub struct CredentialRevocationCheckResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub credential_id: String,
    pub status: CredentialStateBindingEnum,
    pub success: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(StorageGeneratedKey)]
pub struct GeneratedKeyBindingDTO {
    pub key_reference: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[uniffi::export(callback_interface)]
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

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ServiceDescription)]
pub struct ServiceDescriptionBindingDTO {
    pub uuid: String,
    pub advertise: bool,
    pub advertised_service_data: Option<Vec<u8>>,
    #[from(with_fn = convert_inner)]
    pub characteristics: Vec<CharacteristicBindingDTO>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(CreateCharacteristicOptions)]
pub struct CharacteristicBindingDTO {
    pub uuid: String,
    #[from(with_fn = convert_inner)]
    pub permissions: Vec<CharacteristicPermissionBindingEnum>,
    #[from(with_fn = convert_inner)]
    pub properties: Vec<CharacteristicPropertyBindingEnum>,
}

#[derive(Clone, Debug, From, uniffi::Enum)]
#[from(CharacteristicPermissions)]
pub enum CharacteristicPermissionBindingEnum {
    Read,
    Write,
}

#[derive(Clone, Debug, From, uniffi::Enum)]
#[from(CharacteristicProperties)]
pub enum CharacteristicPropertyBindingEnum {
    Read,
    Write,
    Notify,
    WriteWithoutResponse,
    Indicate,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(ConnectionEvent)]
pub enum ConnectionEventBindingEnum {
    Connected { device_info: DeviceInfoBindingDTO },
    Disconnected { device_address: DeviceAddress },
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct DeviceInfoBindingDTO {
    pub address: String,
    pub mtu: u16,
}

#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait BlePeripheral: Send + Sync {
    async fn is_adapter_enabled(&self) -> Result<bool, BleError>;
    async fn start_advertisement(
        &self,
        device_name: Option<String>,
        services: Vec<ServiceDescriptionBindingDTO>,
    ) -> Result<Option<MacAddress>, BleError>;
    async fn stop_advertisement(&self) -> Result<(), BleError>;
    async fn is_advertising(&self) -> Result<bool, BleError>;
    async fn set_characteristic_data(
        &self,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
        data: Vec<u8>,
    ) -> Result<(), BleError>;
    async fn notify_characteristic_data(
        &self,
        device_address: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
        data: Vec<u8>,
    ) -> Result<(), BleError>;
    async fn get_connection_change_events(
        &self,
    ) -> Result<Vec<ConnectionEventBindingEnum>, BleError>;
    async fn get_characteristic_writes(
        &self,
        device: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<Vec<Vec<u8>>, BleError>;
    async fn wait_for_characteristic_read(
        &self,
        device: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<(), BleError>;
    async fn stop_server(&self) -> Result<(), BleError>;
}

#[derive(Clone, Debug, From, uniffi::Enum)]
#[from(CharacteristicWriteType)]
pub enum CharacteristicWriteTypeBindingEnum {
    WithResponse,
    WithoutResponse,
}

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(PeripheralDiscoveryData)]
pub struct PeripheralDiscoveryDataBindingDTO {
    pub device_address: DeviceAddress,
    pub local_device_name: Option<String>,
    pub advertised_services: Vec<ServiceUUID>,
    pub advertised_service_data: Option<HashMap<ServiceUUID, Vec<u8>>>,
}

#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait BleCentral: Send + Sync {
    async fn is_adapter_enabled(&self) -> Result<bool, BleError>;
    async fn start_scan(&self, filter_services: Option<Vec<ServiceUUID>>) -> Result<(), BleError>;
    async fn stop_scan(&self) -> Result<(), BleError>;
    async fn is_scanning(&self) -> Result<bool, BleError>;
    async fn write_data(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
        data: Vec<u8>,
        write_type: CharacteristicWriteTypeBindingEnum,
    ) -> Result<(), BleError>;
    async fn read_data(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<Vec<u8>, BleError>;
    async fn connect(&self, peripheral: DeviceAddress) -> Result<u16, BleError>;
    async fn disconnect(&self, peripheral: DeviceAddress) -> Result<(), BleError>;
    async fn get_discovered_devices(
        &self,
    ) -> Result<Vec<PeripheralDiscoveryDataBindingDTO>, BleError>;
    async fn subscribe_to_characteristic_notifications(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<(), BleError>;
    async fn unsubscribe_from_characteristic_notifications(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<(), BleError>;
    async fn get_notifications(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<Vec<Vec<u8>>, BleError>;
}

#[derive(Clone, Debug, From, Into, uniffi::Enum)]
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

#[derive(Clone, Debug, From, Into, uniffi::Enum)]
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

#[derive(Clone, Debug, uniffi::Enum)]
pub enum HistoryMetadataBinding {
    UnexportableEntities {
        value: UnexportableEntitiesBindingDTO,
    },
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct HistoryListItemBindingDTO {
    pub id: String,
    pub created_date: String,
    pub action: HistoryActionBindingEnum,
    pub entity_id: Option<String>,
    pub entity_type: HistoryEntityTypeBindingEnum,
    pub metadata: Option<HistoryMetadataBinding>,
    pub organisation_id: String,
}

#[derive(Clone, Debug, uniffi::Record)]
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

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetHistoryListResponseDTO)]
pub struct HistoryListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<HistoryListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
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

#[derive(Clone, Debug, uniffi::Record)]
pub struct HistorySearchBindingDTO {
    pub text: String,
    pub r#type: Option<HistorySearchEnumBindingEnum>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(BackupCreateResponseDTO)]
pub struct BackupCreateBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub history_id: String,
    pub file: String,
    pub unexportable: UnexportableEntitiesBindingDTO,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(MetadataDTO)]
pub struct MetadataBindingDTO {
    pub db_version: String,
    pub db_hash: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_at: String,
}

#[derive(Clone, Debug, From, uniffi::Record)]
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

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(CreateTrustAnchorRequestDTO)]
pub struct CreateTrustAnchorRequestBindingDTO {
    pub name: String,
    pub r#type: String,
    pub is_publisher: Option<bool>,
    pub publisher_reference: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
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
    pub is_publisher: bool,
    pub publisher_reference: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Into, uniffi::Enum)]
#[into(SortableTrustAnchorColumn)]
pub enum SortableTrustAnchorColumnBindings {
    Name,
    CreatedDate,
    Type,
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum ExactTrustAnchorFilterColumnBindings {
    Name,
    Type,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ListTrustAnchorsFiltersBindings {
    pub page: u32,
    pub page_size: u32,

    pub sort: Option<SortableTrustAnchorColumnBindings>,
    pub sort_direction: Option<SortDirection>,

    pub name: Option<String>,
    pub is_publisher: Option<bool>,
    pub r#type: Option<String>,

    pub exact: Option<Vec<ExactTrustAnchorFilterColumnBindings>>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
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
    pub is_publisher: bool,
    pub publisher_reference: String,
    pub entities: u64,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetTrustAnchorsResponseDTO)]
pub struct TrustAnchorsListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<TrustAnchorsListItemResponseBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Into, uniffi::Enum)]
#[into(SortableTrustEntityColumnEnum)]
pub enum SortableTrustEntityColumnBindings {
    Name,
    Role,
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum ExactTrustEntityFilterColumnBindings {
    Name,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ListTrustEntitiesFiltersBindings {
    pub page: u32,
    pub page_size: u32,

    pub sort: Option<SortableTrustEntityColumnBindings>,
    pub sort_direction: Option<SortDirection>,

    pub name: Option<String>,
    pub role: Option<TrustEntityRoleBindingEnum>,
    pub trust_anchor: Option<String>,
    pub did_id: Option<String>,
    pub organisation_id: Option<String>,

    pub exact: Option<Vec<ExactTrustEntityFilterColumnBindings>>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(TrustEntitiesResponseItemDTO)]
pub struct TrustEntitiesListItemResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    pub name: String,

    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,

    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub state: TrustEntityStateBindingEnum,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRoleBindingEnum,
    pub trust_anchor: GetTrustAnchorResponseBindingDTO,
    pub did: DidListItemBindingDTO,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetTrustEntitiesResponseDTO)]
pub struct TrustEntitiesListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<TrustEntitiesListItemResponseBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = CreateTrustEntityRequestDTO, Error = ErrorResponseBindingDTO)]
pub struct CreateTrustEntityRequestBindingDTO {
    #[try_into(infallible)]
    pub name: String,
    #[try_into(infallible)]
    pub logo: Option<String>,
    #[try_into(infallible)]
    pub website: Option<String>,
    #[try_into(infallible)]
    pub terms_url: Option<String>,
    #[try_into(infallible)]
    pub privacy_url: Option<String>,
    #[try_into(infallible)]
    pub role: TrustEntityRoleBindingEnum,
    #[try_into(infallible)]
    pub state: TrustEntityStateBindingEnum,
    #[try_into(with_fn_ref = into_id)]
    pub trust_anchor_id: String,
    #[try_into(with_fn_ref = into_id)]
    pub did_id: String,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = CreateRemoteTrustEntityRequestDTO, Error = ErrorResponseBindingDTO)]
pub struct CreateRemoteTrustEntityRequestBindingDTO {
    #[try_into(with_fn_ref = into_id)]
    pub did_id: String,
    #[try_into(with_fn = into_id_opt)]
    pub trust_anchor_id: Option<String>,
    #[try_into(infallible)]
    pub name: String,
    #[try_into(infallible)]
    pub logo: Option<String>,
    #[try_into(infallible)]
    pub terms_url: Option<String>,
    #[try_into(infallible)]
    pub privacy_url: Option<String>,
    #[try_into(infallible)]
    pub website: Option<String>,
    #[try_into(infallible)]
    pub role: TrustEntityRoleBindingEnum,
}

#[derive(Clone, Debug, From, Into, uniffi::Enum)]
#[from(TrustEntityRole)]
#[into(TrustEntityRole)]
pub enum TrustEntityRoleBindingEnum {
    Issuer,
    Verifier,
    Both,
}

#[derive(Clone, Debug, From, Into, uniffi::Enum)]
#[from(TrustEntityState)]
#[into(TrustEntityState)]
pub enum TrustEntityStateBindingEnum {
    Active,
    Removed,
    Withdrawn,
    RemovedAndWithdrawn,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetTrustEntityResponseDTO)]
pub struct GetTrustEntityResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn = from_id_opt)]
    pub organisation_id: Option<String>,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub name: String,
    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRoleBindingEnum,
    pub trust_anchor: GetTrustAnchorResponseBindingDTO,
    pub did: DidListItemBindingDTO,
    pub state: TrustEntityStateBindingEnum,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(UpdateTrustEntityActionFromDidRequestDTO)]
pub enum TrustEntityUpdateActionBindingEnum {
    Activate,
    Withdraw,
    Remove,
}

#[derive(TryInto, uniffi::Record)]
#[try_into(T = UpdateTrustEntityFromDidRequestDTO, Error = ErrorResponseBindingDTO)]
pub struct UpdateRemoteTrustEntityFromDidRequestBindingDTO {
    #[try_into(skip)]
    pub did_id: String,
    #[try_into(with_fn = convert_inner, infallible)]
    pub action: Option<TrustEntityUpdateActionBindingEnum>,
    #[try_into(infallible)]
    pub name: Option<String>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub logo: Option<OptionalString>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub website: Option<OptionalString>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub terms_url: Option<OptionalString>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub privacy_url: Option<OptionalString>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub role: Option<TrustEntityRoleBindingEnum>,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(SortableProofSchemaColumn)]
pub enum SortableProofSchemaColumnBinding {
    Name,
    CreatedDate,
}

#[derive(Clone, Debug, Into, PartialEq, uniffi::Enum)]
#[into(ExactColumn)]
pub enum ProofSchemaListQueryExactColumnBinding {
    Name,
}

#[derive(Clone, Debug, uniffi::Record)]
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

#[derive(Clone, Debug, From, uniffi::Record)]
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

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetProofSchemaListResponseDTO)]
pub struct ProofSchemaListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<GetProofSchemaListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Debug, TryInto, uniffi::Record)]
#[try_into(T = ImportProofSchemaRequestDTO, Error = ErrorResponseBindingDTO)]
pub struct ImportProofSchemaRequestBindingsDTO {
    pub schema: ImportProofSchemaBindingDTO,
    #[try_into(with_fn_ref = into_id)]
    pub organisation_id: String,
}

#[derive(Debug, TryInto, uniffi::Record)]
#[try_into(T = ImportProofSchemaDTO, Error = ErrorResponseBindingDTO)]
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

#[derive(Clone, Debug, From, uniffi::Record)]
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
    #[from(with_fn = convert_inner)]
    pub imported_source_url: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ProofInputSchemaResponseDTO)]
pub struct ProofInputSchemaBindingDTO {
    #[from(with_fn = convert_inner)]
    pub claim_schemas: Vec<ProofClaimSchemaBindingDTO>,
    pub credential_schema: CredentialSchemaBindingDTO,
    pub validity_constraint: Option<i64>,
}

#[derive(Debug, TryInto, uniffi::Record)]
#[try_into(T = ImportProofSchemaInputSchemaDTO, Error = ErrorResponseBindingDTO)]
pub struct ImportProofSchemaInputSchemaBindingDTO {
    #[try_into(with_fn = try_convert_inner)]
    pub claim_schemas: Vec<ImportProofSchemaClaimSchemaBindingDTO>,
    pub credential_schema: ImportProofSchemaCredentialSchemaBindingDTO,
    #[try_into(infallible)]
    pub validity_constraint: Option<i64>,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
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

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = one_core::service::proof_schema::dto::ProofInputSchemaRequestDTO, Error = ServiceError)]
pub struct ProofInputSchemaRequestDTO {
    #[try_into(with_fn_ref = into_id)]
    pub credential_schema_id: String,
    #[try_into(with_fn = convert_inner, infallible)]
    pub validity_constraint: Option<i64>,
    #[try_into(with_fn = try_convert_inner)]
    pub claim_schemas: Vec<CreateProofSchemaClaimRequestDTO>,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = one_core::service::proof_schema::dto::CreateProofSchemaClaimRequestDTO, Error = ServiceError)]
pub struct CreateProofSchemaClaimRequestDTO {
    #[try_into(with_fn_ref = into_id)]
    pub id: String,
    #[try_into(infallible)]
    pub required: bool,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = ImportCredentialSchemaRequestDTO, Error = ServiceError)]
pub struct ImportCredentialSchemaRequestBindingDTO {
    #[try_into(with_fn_ref = into_id)]
    pub organisation_id: String,
    pub schema: ImportCredentialSchemaRequestSchemaBindingDTO,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
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
    #[try_into(infallible, with_fn = convert_inner)]
    pub allow_suspension: Option<bool>,
}

#[derive(Clone, Debug, uniffi::Record)]
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

#[derive(Clone, Debug, Into, uniffi::Record)]
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

#[derive(Clone, Debug, TryInto, uniffi::Record)]
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
    #[try_into(with_fn = convert_inner, infallible)]
    pub transport: Option<Vec<String>>,
}

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(ScanToVerifyRequestDTO)]
pub struct ScanToVerifyRequestBindingDTO {
    pub credential: String,
    pub barcode: String,
    pub barcode_type: ScanToVerifyBarcodeTypeBindingEnum,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(ScanToVerifyBarcodeTypeEnum)]
pub enum ScanToVerifyBarcodeTypeBindingEnum {
    #[allow(clippy::upper_case_acronyms)]
    MRZ,
    PDF417,
}

#[derive(Into, uniffi::Record)]
#[into(ShareProofRequestDTO)]
pub struct ShareProofRequestBindingDTO {
    #[into(with_fn = "convert_inner")]
    pub params: Option<ShareProofRequestParamsBindingDTO>,
}

#[derive(Into, uniffi::Record)]
#[into(ShareProofRequestParamsDTO)]
pub struct ShareProofRequestParamsBindingDTO {
    #[into(with_fn = "convert_inner")]
    pub client_id_schema: Option<ShareProofRequestClientIdSchemaTypeBindingDTO>,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(ClientIdSchemaType)]
pub enum ShareProofRequestClientIdSchemaTypeBindingDTO {
    RedirectUri,
    VerifierAttestation,
}

#[derive(From, uniffi::Record)]
#[from(EntityShareResponseDTO)]
pub struct ShareProofResponseBindingDTO {
    pub url: String,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ProofSchemaShareResponseDTO)]
pub struct ProofSchemaShareResponseBindingDTO {
    pub url: String,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(CredentialSchemaShareResponseDTO)]
pub struct CredentialSchemaShareResponseBindingDTO {
    pub url: String,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ResolveJsonLDContextResponseBindingDTO {
    pub context: String,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ProposeProofResponseDTO)]
pub struct ProposeProofResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub proof_id: String,
    #[from(with_fn_ref = "ToString::to_string")]
    pub interaction_id: String,
    pub url: String,
}

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(KeyCheckCertificateRequestDTO)]
pub struct KeyCheckCertificateRequestBindingDTO {
    pub certificate: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Into, From, uniffi::Enum)]
#[from("one_core::model::remote_entity_cache::CacheType")]
#[into("one_core::model::remote_entity_cache::CacheType")]
pub enum CacheTypeBindingDTO {
    DidDocument,
    JsonLdContext,
    StatusListCredential,
    VctMetadata,
    JsonSchema,
    TrustList,
}
