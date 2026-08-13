use std::collections::HashMap;

use one_core::model::certificate::{CertificateRole, CertificateState};
use one_core::model::identifier::{
    ExactIdentifierFilterColumn, IdentifierState, IdentifierType, SortableIdentifierColumn,
};
use one_core::provider::ecosystem::model::EcosystemRole;
use one_core::service::certificate::dto::{
    CertificateResponseDTO, CertificateX509AttributesDTO, CertificateX509ExtensionDTO,
    CreateCertificateRequestDTO,
};
use one_core::service::did::dto::{DidResponseDTO, DidResponseKeysDTO};
use one_core::service::identifier::dto::{
    CertificateRolesMatchMode, CreateCertificateAuthorityRequestDTO, CreateIdentifierKeyRequestDTO,
    CreateIdentifierRequestDTO, CreateIdentifierTrustInformationRequestDTO,
    CreateSelfSignedCertificateAuthorityContentRequestDTO,
    CreateSelfSignedCertificateAuthorityIssuerAlternativeNameRequest,
    CreateSelfSignedCertificateAuthorityIssuerAlternativeNameType,
    CreateSelfSignedCertificateAuthorityRequestDTO, GetIdentifierListItemResponseDTO,
    GetIdentifierListResponseDTO, GetIdentifierResponseDTO, IdentifierTrustInformationResponseDTO,
    IdentifierTrustInformationType,
};
use one_core::service::key::dto::KeyResponseDTO;
use one_dto_mapper::{
    From, Into, TryInto, convert_inner, convert_inner_of_inner, try_convert_inner,
    try_convert_inner_of_inner,
};

use super::common::SortDirection;
use super::did::{DidTypeBindingEnum, KeyRoleBindingEnum};
use super::key::{KeyGenerateCSRRequestSubjectBindingDTO, KeyListItemBindingDTO};
use crate::OneCore;
use crate::binding::mapper::optional_time;
use crate::error::{BindingError, ErrorResponseBindingDTO};
use crate::utils::{TimestampFormat, from_id_opt, into_id, into_id_opt, into_timestamp_opt};

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
    /// Creates a new identifier.
    #[uniffi::method]
    pub async fn create_identifier(
        &self,
        request: CreateIdentifierRequestBindingDTO,
    ) -> Result<String, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .identifier_service
            .create_identifier(request.try_into()?)
            .await?
            .to_string())
    }

    /// Returns a filterable list of identifiers.
    #[uniffi::method]
    pub async fn list_identifiers(
        &self,
        query: IdentifierListQueryBindingDTO,
    ) -> Result<GetIdentifierListBindingDTO, BindingError> {
        let core = self.use_core().await?;

        Ok(core
            .identifier_service
            .get_identifier_list(query.try_into()?)
            .await?
            .into())
    }

    #[uniffi::method]
    pub async fn delete_identifier(&self, id: String) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        let id = into_id(&id)?;
        Ok(core.identifier_service.delete_identifier(&id).await?)
    }

    #[uniffi::method]
    pub async fn get_identifier(
        &self,
        id: String,
    ) -> Result<GetIdentifierBindingDTO, BindingError> {
        let core = self.use_core().await?;
        let id = into_id(&id)?;
        Ok(core.identifier_service.get_identifier(&id).await?.into())
    }
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetIdentifierListResponseDTO)]
#[uniffi(name = "IdentifierList")]
pub struct GetIdentifierListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<GetIdentifierListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetIdentifierResponseDTO)]
#[uniffi(name = "IdentifierDetail")]
pub struct GetIdentifierBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub name: String,
    #[from(with_fn = "from_id_opt")]
    pub organisation_id: Option<String>,
    pub r#type: IdentifierTypeBindingEnum,
    pub is_remote: bool,
    pub state: IdentifierStateBindingEnum,
    #[from(with_fn = convert_inner)]
    pub did: Option<DidResponseBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub key: Option<KeyResponseBindingDTO>,
    #[from(with_fn = convert_inner_of_inner )]
    pub certificates: Option<Vec<CertificateResponseBindingDTO>>,
    #[from(with_fn = convert_inner)]
    pub trust_information: Vec<IdentifierTrustInformationResponseBindingDTO>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(IdentifierTrustInformationResponseDTO)]
#[uniffi(name = "IdentifierTrustInformationResponseDTO")]
pub(crate) struct IdentifierTrustInformationResponseBindingDTO {
    pub data: String,
    pub r#type: IdentifierTrustInformationTypeBindingEnum,
    #[from(with_fn = optional_time)]
    pub valid_from: Option<String>,
    #[from(with_fn = optional_time)]
    pub valid_to: Option<String>,
}

#[derive(Clone, Debug, Into, From, uniffi::Enum)]
#[into(IdentifierTrustInformationType)]
#[from(IdentifierTrustInformationType)]
#[uniffi(name = "IdentifierTrustInformationType")]
pub enum IdentifierTrustInformationTypeBindingEnum {
    RegistrationCertificate,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(DidResponseDTO)]
#[uniffi(name = "DidDetail")]
pub struct DidResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub name: String,
    #[from(with_fn = "from_id_opt")]
    pub organisation_id: Option<String>,
    pub did: String,
    pub did_type: DidTypeBindingEnum,
    pub did_method: String,
    pub keys: DidResponseKeysBindingDTO,
    pub deactivated: bool,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(DidResponseKeysDTO)]
#[uniffi(name = "DidKeys")]
pub struct DidResponseKeysBindingDTO {
    #[from(with_fn = convert_inner)]
    pub authentication: Vec<KeyListItemBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub assertion_method: Vec<KeyListItemBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub key_agreement: Vec<KeyListItemBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub capability_invocation: Vec<KeyListItemBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub capability_delegation: Vec<KeyListItemBindingDTO>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(KeyResponseDTO)]
#[uniffi(name = "KeyDetail")]
pub struct KeyResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    #[from(with_fn_ref = "ToString::to_string")]
    pub organisation_id: String,
    pub name: String,
    pub public_key: Vec<u8>,
    pub key_type: String,
    pub storage_type: String,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(CertificateResponseDTO)]
#[uniffi(name = "CertificateDetail")]
pub struct CertificateResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "ToString::to_string")]
    pub identifier_id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub state: CertificateStateBindingEnum,
    pub name: String,
    pub chain: String,
    #[from(with_fn = convert_inner)]
    pub key: Option<KeyListItemBindingDTO>,
    pub x509_attributes: CertificateX509AttributesBindingDTO,
    #[from(with_fn = convert_inner)]
    pub roles: Vec<CertificateRoleBindingEnum>,
}

#[derive(Clone, Debug, Into, From, uniffi::Enum)]
#[into(CertificateRole)]
#[from(CertificateRole)]
#[uniffi(name = "CertificateRole")]
pub enum CertificateRoleBindingEnum {
    Authentication,
    AssertionMethod,
}

#[derive(Clone, Debug, Into, From, uniffi::Enum)]
#[into(CertificateState)]
#[from(CertificateState)]
#[uniffi(name = "CertificateState")]
pub enum CertificateStateBindingEnum {
    NotYetActive,
    Active,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(CertificateX509AttributesDTO)]
#[uniffi(name = "CertificateX509Attributes")]
pub struct CertificateX509AttributesBindingDTO {
    pub serial_number: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub not_before: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub not_after: String,
    pub issuer: String,
    pub subject: String,
    pub fingerprint: String,
    #[from(with_fn = convert_inner)]
    pub extensions: Vec<CertificateX509ExtensionBindingDTO>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(CertificateX509ExtensionDTO)]
#[uniffi(name = "CertificateX509Extension")]
pub struct CertificateX509ExtensionBindingDTO {
    pub oid: String,
    pub value: String,
    pub critical: bool,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetIdentifierListItemResponseDTO)]
#[uniffi(name = "IdentifierListItem")]
pub struct GetIdentifierListItemBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub name: String,
    pub r#type: IdentifierTypeBindingEnum,
    pub is_remote: bool,
    pub state: IdentifierStateBindingEnum,
    #[from(with_fn = "from_id_opt")]
    pub organisation_id: Option<String>,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "IdentifierListQuery")]
pub struct IdentifierListQueryBindingDTO {
    pub page: u32,
    pub page_size: u32,

    pub sort: Option<SortableIdentifierColumnBindingEnum>,
    pub sort_direction: Option<SortDirection>,

    pub organisation_id: String,
    pub ids: Option<Vec<String>>,
    pub name: Option<String>,
    pub types: Option<Vec<IdentifierTypeBindingEnum>>,
    pub states: Option<Vec<IdentifierStateBindingEnum>>,
    pub exact: Option<Vec<ExactIdentifierFilterColumnBindingEnum>>,
    pub did_methods: Option<Vec<String>>,
    pub is_remote: Option<bool>,
    pub key_algorithms: Option<Vec<String>>,
    pub key_roles: Option<Vec<KeyRoleBindingEnum>>,
    pub key_storages: Option<Vec<String>>,
    pub certificate_roles: Option<Vec<CertificateRoleBindingEnum>>,
    pub certificate_roles_match_mode: Option<CertificateRolesMatchModeBindingEnum>,

    /// Deprecated, use `ecosystemCredentialSchemaId`
    pub trust_issuance_schema_id: Option<String>,
    /// Deprecated, use `ecosystemProofSchemaId`
    pub trust_verification_schema_id: Option<String>,

    pub ecosystem: Option<String>,
    pub ecosystem_roles: Option<Vec<EcosystemRoleBindingEnum>>,
    pub ecosystem_credential_schema_id: Option<String>,
    pub ecosystem_proof_schema_id: Option<String>,

    pub created_date_after: Option<String>,
    pub created_date_before: Option<String>,
    pub last_modified_after: Option<String>,
    pub last_modified_before: Option<String>,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(SortableIdentifierColumn)]
#[uniffi(name = "SortableIdentifierColumn")]
pub enum SortableIdentifierColumnBindingEnum {
    Name,
    CreatedDate,
    Type,
    State,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(EcosystemRole)]
#[uniffi(name = "EcosystemRole")]
pub enum EcosystemRoleBindingEnum {
    Holder,
    Issuer,
    Verifier,
    PidProvider,
    NationalRegistryRegistrar,
    WalletProvider,
}

#[derive(Clone, Debug, PartialEq, uniffi::Enum, Into)]
#[uniffi(name = "IdentifierListQueryExactColumn")]
#[into(ExactIdentifierFilterColumn)]
pub enum ExactIdentifierFilterColumnBindingEnum {
    Name,
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Enum, Into)]
#[uniffi(name = "CertificateRolesMatchMode")]
#[into(CertificateRolesMatchMode)]
/// The mode used to match certificate roles. Default any.
pub enum CertificateRolesMatchModeBindingEnum {
    All,
    Any,
}

#[derive(Clone, Debug, Into, From, uniffi::Enum)]
#[into(IdentifierType)]
#[from(IdentifierType)]
#[uniffi(name = "IdentifierType")]
pub enum IdentifierTypeBindingEnum {
    Key,
    Did,
    Certificate,
    CertificateAuthority,
}

#[derive(Clone, Debug, Into, From, uniffi::Enum)]
#[into(IdentifierState)]
#[from(IdentifierState)]
#[uniffi(name = "IdentifierState")]
pub enum IdentifierStateBindingEnum {
    Active,
    Deactivated,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = CreateIdentifierRequestDTO, Error = ErrorResponseBindingDTO)]
#[uniffi(name = "CreateIdentifierRequest")]
pub struct CreateIdentifierRequestBindingDTO {
    #[try_into(with_fn_ref = into_id)]
    pub organisation_id: String,
    #[try_into(infallible)]
    pub name: String,
    /// Deprecated. Use the `key` field instead.
    #[try_into(with_fn = into_id_opt)]
    pub key_id: Option<String>,
    #[try_into(with_fn = try_convert_inner)]
    pub key: Option<CreateIdentifierKeyRequestBindingDTO>,
    #[try_into(with_fn = try_convert_inner)]
    pub did: Option<CreateIdentifierDidRequestBindingDTO>,
    #[try_into(with_fn = try_convert_inner_of_inner)]
    pub certificates: Option<Vec<CreateCertificateRequestBindingDTO>>,
    #[try_into(with_fn = try_convert_inner_of_inner)]
    pub certificate_authorities: Option<Vec<CreateCertificateAuthorityRequestBindingDTO>>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub trust_information: Vec<CreateIdentifierTrustInformationRequestBindingDTO>,
}

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(CreateIdentifierTrustInformationRequestDTO)]
#[uniffi(name = "CreateIdentifierTrustInformationRequest")]
pub struct CreateIdentifierTrustInformationRequestBindingDTO {
    pub data: String,
    pub r#type: IdentifierTrustInformationTypeBindingEnum,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "CreateIdentifierDidRequest")]
pub struct CreateIdentifierDidRequestBindingDTO {
    pub name: Option<String>,
    pub method: String,
    pub keys: super::did::DidRequestKeysBindingDTO,
    pub params: HashMap<String, String>,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = CreateIdentifierKeyRequestDTO, Error = ErrorResponseBindingDTO)]
#[uniffi(name = "CreateIdentifierKeyRequest")]
pub struct CreateIdentifierKeyRequestBindingDTO {
    #[try_into(with_fn = into_id)]
    pub key_id: String,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "CreateCertificateRequest")]
pub struct CreateCertificateRequestBindingDTO {
    pub name: Option<String>,
    pub chain: String,
    pub key_id: String,
    pub roles: Vec<CertificateRoleBindingEnum>,
}

impl TryFrom<CreateCertificateRequestBindingDTO> for CreateCertificateRequestDTO {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: CreateCertificateRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            name: value.name,
            chain: Some(value.chain),
            key_id: into_id(value.key_id)?,
            content: None,
            roles: convert_inner(value.roles),
        })
    }
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = CreateCertificateAuthorityRequestDTO, Error = ErrorResponseBindingDTO)]
#[uniffi(name = "CreateCertificateAuthorityRequest")]
pub struct CreateCertificateAuthorityRequestBindingDTO {
    #[try_into(with_fn = convert_inner, infallible)]
    pub name: Option<String>,
    #[try_into(with_fn_ref = "into_id")]
    pub key_id: String,
    #[try_into(with_fn = convert_inner, infallible)]
    pub chain: Option<String>,
    #[try_into(with_fn = try_convert_inner)]
    pub self_signed: Option<CreateSelfSignedCertificateAuthorityRequestBindingDTO>,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = CreateSelfSignedCertificateAuthorityRequestDTO, Error = ErrorResponseBindingDTO)]
#[uniffi(name = "CreateSelfSignedCertificateAuthorityRequest")]
pub struct CreateSelfSignedCertificateAuthorityRequestBindingDTO {
    #[try_into(infallible)]
    pub content: CreateSelfSignedCertificateAuthorityRequestContentBindingDTO,
    #[try_into(infallible)]
    pub signer: String,
    #[try_into(with_fn = "into_timestamp_opt")]
    pub validity_start: Option<String>,
    #[try_into(with_fn = "into_timestamp_opt")]
    pub validity_end: Option<String>,
}

#[derive(Clone, Debug, uniffi::Record, Into)]
#[into(CreateSelfSignedCertificateAuthorityContentRequestDTO)]
#[uniffi(name = "CreateSelfSignedCertificateAuthorityRequestContent")]
pub struct CreateSelfSignedCertificateAuthorityRequestContentBindingDTO {
    pub subject: KeyGenerateCSRRequestSubjectBindingDTO,
    #[into(with_fn = convert_inner)]
    pub issuer_alternative_name: Option<CreateSelfSignedCaRequestIssuerAlternativeNameBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Record, Into)]
#[into(CreateSelfSignedCertificateAuthorityIssuerAlternativeNameRequest)]
#[uniffi(name = "CreateSelfSignedCertificateAuthorityIssuerAlternativeNameRequest")]
pub struct CreateSelfSignedCaRequestIssuerAlternativeNameBindingDTO {
    pub r#type: CreateSelfSignedCaRequestIssuerAlternativeNameTypeBindingEnum,
    pub name: String,
}

#[derive(Clone, Debug, uniffi::Enum, Into)]
#[into(CreateSelfSignedCertificateAuthorityIssuerAlternativeNameType)]
#[uniffi(name = "CreateSelfSignedCaRequestIssuerAlternativeNameType")]
pub enum CreateSelfSignedCaRequestIssuerAlternativeNameTypeBindingEnum {
    Email,
    Uri,
}
