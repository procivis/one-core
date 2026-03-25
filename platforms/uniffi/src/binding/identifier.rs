use std::collections::HashMap;

use one_core::model::certificate::CertificateState;
use one_core::model::identifier::{
    IdentifierFilterValue, IdentifierListQuery, IdentifierState, IdentifierType,
    SortableIdentifierColumn,
};
use one_core::model::list_filter::{
    ComparisonType, ListFilterValue, StringMatch, StringMatchType, ValueComparison,
};
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::service::certificate::dto::{
    CertificateResponseDTO, CertificateX509AttributesDTO, CertificateX509ExtensionDTO,
    CreateCertificateRequestDTO,
};
use one_core::service::did::dto::{DidResponseDTO, DidResponseKeysDTO};
use one_core::service::identifier::dto::{
    CreateCertificateAuthorityRequestDTO, CreateIdentifierKeyRequestDTO,
    CreateIdentifierRequestDTO, CreateSelfSignedCertificateAuthorityContentRequestDTO,
    CreateSelfSignedCertificateAuthorityIssuerAlternativeNameRequest,
    CreateSelfSignedCertificateAuthorityIssuerAlternativeNameType,
    CreateSelfSignedCertificateAuthorityRequestDTO, GetIdentifierListItemResponseDTO,
    GetIdentifierListResponseDTO, GetIdentifierResponseDTO,
};
use one_core::service::key::dto::KeyResponseDTO;
use one_dto_mapper::{
    From, Into, TryInto, convert_inner, convert_inner_of_inner, try_convert_inner,
    try_convert_inner_of_inner,
};

use super::common::SortDirection;
use super::did::{DidTypeBindingEnum, KeyRoleBindingEnum};
use super::key::{KeyGenerateCSRRequestSubjectBindingDTO, KeyListItemBindingDTO};
use super::mapper::deserialize_timestamp;
use crate::OneCore;
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

        let organisation_id = into_id(&query.organisation_id)?;
        let condition = {
            let exact = query.exact.unwrap_or_default();
            let get_string_match_type = |column| {
                if exact.contains(&column) {
                    StringMatchType::Equals
                } else {
                    StringMatchType::StartsWith
                }
            };

            let organisation = IdentifierFilterValue::OrganisationId(organisation_id).condition();

            let name = query.name.map(|name| {
                IdentifierFilterValue::Name(StringMatch {
                    r#match: get_string_match_type(ExactIdentifierFilterColumnBindingEnum::Name),
                    value: name,
                })
            });

            let types = query
                .types
                .map(|types| IdentifierFilterValue::Types(convert_inner(types)));

            let state = query
                .states
                .map(|states| IdentifierFilterValue::States(convert_inner(states)));

            let did_methods = query.did_methods.map(IdentifierFilterValue::DidMethods);

            let is_remote = query.is_remote.map(IdentifierFilterValue::IsRemote);

            let key_algorithms = query
                .key_algorithms
                .map(IdentifierFilterValue::KeyAlgorithms);

            let key_roles = query.key_roles.map(|roles| {
                IdentifierFilterValue::KeyRoles(roles.into_iter().map(Into::into).collect())
            });

            let key_storages = query.key_storages.map(IdentifierFilterValue::KeyStorages);

            let created_date_after = query
                .created_date_after
                .map(|date| {
                    Ok::<_, BindingError>(IdentifierFilterValue::CreatedDate(ValueComparison {
                        comparison: ComparisonType::GreaterThanOrEqual,
                        value: deserialize_timestamp(&date)?,
                    }))
                })
                .transpose()?;
            let created_date_before = query
                .created_date_before
                .map(|date| {
                    Ok::<_, BindingError>(IdentifierFilterValue::CreatedDate(ValueComparison {
                        comparison: ComparisonType::LessThanOrEqual,
                        value: deserialize_timestamp(&date)?,
                    }))
                })
                .transpose()?;

            let last_modified_after = query
                .last_modified_after
                .map(|date| {
                    Ok::<_, BindingError>(IdentifierFilterValue::LastModified(ValueComparison {
                        comparison: ComparisonType::GreaterThanOrEqual,
                        value: deserialize_timestamp(&date)?,
                    }))
                })
                .transpose()?;
            let last_modified_before = query
                .last_modified_before
                .map(|date| {
                    Ok::<_, BindingError>(IdentifierFilterValue::LastModified(ValueComparison {
                        comparison: ComparisonType::LessThanOrEqual,
                        value: deserialize_timestamp(&date)?,
                    }))
                })
                .transpose()?;

            organisation
                & name
                & types
                & state
                & did_methods
                & is_remote
                & key_algorithms
                & key_roles
                & key_storages
                & created_date_after
                & created_date_before
                & last_modified_after
                & last_modified_before
        };

        let sorting = query.sort.map(|sort| ListSorting {
            column: sort.into(),
            direction: query.sort_direction.map(Into::into),
        });

        let query = IdentifierListQuery {
            pagination: Some(ListPagination {
                page: query.page,
                page_size: query.page_size,
            }),
            sorting,
            filtering: Some(condition),
            include: None,
        };

        Ok(core
            .identifier_service
            .get_identifier_list(&organisation_id, query)
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
    pub name: Option<String>,
    pub types: Option<Vec<IdentifierTypeBindingEnum>>,
    pub states: Option<Vec<IdentifierStateBindingEnum>>,
    pub exact: Option<Vec<ExactIdentifierFilterColumnBindingEnum>>,
    pub did_methods: Option<Vec<String>>,
    pub is_remote: Option<bool>,
    pub key_algorithms: Option<Vec<String>>,
    pub key_roles: Option<Vec<KeyRoleBindingEnum>>,
    pub key_storages: Option<Vec<String>>,

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

#[derive(Clone, Debug, PartialEq, uniffi::Enum)]
#[uniffi(name = "IdentifierListQueryExactColumn")]
pub enum ExactIdentifierFilterColumnBindingEnum {
    Name,
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
}

impl TryFrom<CreateCertificateRequestBindingDTO> for CreateCertificateRequestDTO {
    type Error = ErrorResponseBindingDTO;

    fn try_from(value: CreateCertificateRequestBindingDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            name: value.name,
            chain: Some(value.chain),
            key_id: into_id(value.key_id)?,
            content: None,
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
