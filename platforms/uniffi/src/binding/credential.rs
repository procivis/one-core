use one_core::model::common::ExactColumn;
use one_core::model::credential::{CredentialFilterValue, SortableCredentialColumn};
use one_core::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::service::credential::dto::{
    CredentialRole, CredentialStateEnum, DetailCredentialClaimResponseDTO,
    GetCredentialListResponseDTO, GetCredentialQueryDTO,
};
use one_core::service::error::{BusinessLogicError, ServiceError};
use one_core::{model, service};
use one_dto_mapper::{From, Into, convert_inner};

use super::common::SortDirection;
use super::credential_schema::{CredentialClaimSchemaBindingDTO, CredentialSchemaBindingDTO};
use super::identifier::GetIdentifierListItemBindingDTO;
use super::mapper::deserialize_timestamp;
use crate::OneCore;
use crate::error::BindingError;
use crate::utils::into_id;

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
    /// Returns detailed information about a credential in the system.
    #[uniffi::method]
    pub async fn get_credential(
        &self,
        credential_id: String,
    ) -> Result<CredentialDetailBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .credential_service
            .get_credential(&into_id(&credential_id)?)
            .await?
            .into())
    }

    /// Returns a filterable list of credentials in the system.
    #[uniffi::method]
    pub async fn list_credentials(
        &self,
        query: CredentialListQueryBindingDTO,
    ) -> Result<CredentialListBindingDTO, BindingError> {
        let core = self.use_core().await?;
        let organisation_id = into_id(&query.organisation_id)?;

        let condition = {
            if query.name.is_some() && query.search_type.is_some() && query.search_text.is_some() {
                return Err(ServiceError::BusinessLogic(
                    BusinessLogicError::GeneralInputValidationError,
                )
                .into());
            }

            let exact = query.exact.unwrap_or_default();
            let get_string_match_type = |column| {
                if exact.contains(&column) {
                    StringMatchType::Equals
                } else {
                    StringMatchType::StartsWith
                }
            };

            let organisation = CredentialFilterValue::OrganisationId(organisation_id).condition();

            let name = query.name.map(|name| {
                CredentialFilterValue::CredentialSchemaName(StringMatch {
                    r#match: get_string_match_type(CredentialListQueryExactColumnBindingEnum::Name),
                    value: name,
                })
            });

            let profile = query.profiles.map(CredentialFilterValue::Profiles);

            let search_filters = match (query.search_text, query.search_type) {
                (Some(search_test), Some(search_type)) => {
                    organisation
                        & ListFilterCondition::Or(
                            search_type
                                .into_iter()
                                .map(|filter| {
                                    match filter {
                                        SearchTypeBindingEnum::ClaimName => {
                                            CredentialFilterValue::ClaimName(StringMatch {
                                                r#match: StringMatchType::Contains,
                                                value: search_test.clone(),
                                            })
                                        }
                                        SearchTypeBindingEnum::ClaimValue => {
                                            CredentialFilterValue::ClaimValue(StringMatch {
                                                r#match: StringMatchType::Contains,
                                                value: search_test.clone(),
                                            })
                                        }
                                        SearchTypeBindingEnum::CredentialSchemaName => {
                                            CredentialFilterValue::CredentialSchemaName(
                                                StringMatch {
                                                    r#match: StringMatchType::Contains,
                                                    value: search_test.clone(),
                                                },
                                            )
                                        }
                                    }
                                    .condition()
                                })
                                .collect(),
                        )
                }
                _ => organisation,
            };

            let role = query.roles.map(|roles| {
                CredentialFilterValue::Roles(
                    roles
                        .into_iter()
                        .map(service::credential::dto::CredentialRole::from)
                        .map(model::credential::CredentialRole::from)
                        .collect(),
                )
            });

            let ids = match query.ids {
                Some(ids) => {
                    let ids = ids.iter().map(into_id).collect::<Result<Vec<_>, _>>()?;
                    Some(CredentialFilterValue::CredentialIds(ids))
                }
                None => None,
            };

            let states = query.states.map(|values| {
                CredentialFilterValue::States(
                    values.into_iter().map(|status| status.into()).collect(),
                )
            });

            let credential_schema_ids = query
                .credential_schema_ids
                .map(|ids| ids.into_iter().map(into_id).collect::<Result<Vec<_>, _>>())
                .transpose()?
                .map(CredentialFilterValue::CredentialSchemaIds);

            let created_date_after = query
                .created_date_after
                .map(|date| {
                    Ok::<_, ServiceError>(CredentialFilterValue::CreatedDate(ValueComparison {
                        comparison: ComparisonType::GreaterThanOrEqual,
                        value: deserialize_timestamp(&date)?,
                    }))
                })
                .transpose()?;
            let created_date_before = query
                .created_date_before
                .map(|date| {
                    Ok::<_, ServiceError>(CredentialFilterValue::CreatedDate(ValueComparison {
                        comparison: ComparisonType::LessThanOrEqual,
                        value: deserialize_timestamp(&date)?,
                    }))
                })
                .transpose()?;

            let last_modified_after = query
                .last_modified_after
                .map(|date| {
                    Ok::<_, ServiceError>(CredentialFilterValue::LastModified(ValueComparison {
                        comparison: ComparisonType::GreaterThanOrEqual,
                        value: deserialize_timestamp(&date)?,
                    }))
                })
                .transpose()?;
            let last_modified_before = query
                .last_modified_before
                .map(|date| {
                    Ok::<_, ServiceError>(CredentialFilterValue::LastModified(ValueComparison {
                        comparison: ComparisonType::LessThanOrEqual,
                        value: deserialize_timestamp(&date)?,
                    }))
                })
                .transpose()?;

            let issuance_date_after = query
                .issuance_date_after
                .map(|date| {
                    Ok::<_, ServiceError>(CredentialFilterValue::IssuanceDate(ValueComparison {
                        comparison: ComparisonType::GreaterThanOrEqual,
                        value: deserialize_timestamp(&date)?,
                    }))
                })
                .transpose()?;
            let issuance_date_before = query
                .issuance_date_before
                .map(|date| {
                    Ok::<_, ServiceError>(CredentialFilterValue::IssuanceDate(ValueComparison {
                        comparison: ComparisonType::LessThanOrEqual,
                        value: deserialize_timestamp(&date)?,
                    }))
                })
                .transpose()?;

            let revocation_date_after = query
                .revocation_date_after
                .map(|date| {
                    Ok::<_, ServiceError>(CredentialFilterValue::RevocationDate(ValueComparison {
                        comparison: ComparisonType::GreaterThanOrEqual,
                        value: deserialize_timestamp(&date)?,
                    }))
                })
                .transpose()?;
            let revocation_date_before = query
                .revocation_date_before
                .map(|date| {
                    Ok::<_, ServiceError>(CredentialFilterValue::RevocationDate(ValueComparison {
                        comparison: ComparisonType::LessThanOrEqual,
                        value: deserialize_timestamp(&date)?,
                    }))
                })
                .transpose()?;

            search_filters
                & name
                & role
                & ids
                & states
                & profile
                & credential_schema_ids
                & created_date_after
                & created_date_before
                & last_modified_after
                & last_modified_before
                & issuance_date_after
                & issuance_date_before
                & revocation_date_after
                & revocation_date_before
        };

        Ok(core
            .credential_service
            .get_credential_list(
                &organisation_id,
                GetCredentialQueryDTO {
                    pagination: Some(ListPagination {
                        page: query.page,
                        page_size: query.page_size,
                    }),
                    sorting: query.sort.map(|column| ListSorting {
                        column: column.into(),
                        direction: convert_inner(query.sort_direction),
                    }),
                    filtering: Some(condition),
                    include: query.include.map(convert_inner),
                },
            )
            .await?
            .into())
    }

    #[uniffi::method]
    pub async fn delete_credential(&self, credential_id: String) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .credential_service
            .delete_credential(&into_id(&credential_id)?)
            .await?)
    }
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "CredentialDetail")]
pub struct CredentialDetailBindingDTO {
    pub id: String,
    pub created_date: String,
    pub issuance_date: Option<String>,
    pub last_modified: String,
    pub revocation_date: Option<String>,
    /// Credential issuer metadata.
    pub issuer: Option<GetIdentifierListItemBindingDTO>,
    /// Credential holder metadata.
    pub holder: Option<GetIdentifierListItemBindingDTO>,
    /// State representation of the credential in the system.
    pub state: CredentialStateBindingEnum,
    /// Schema of the credential.
    pub schema: CredentialSchemaBindingDTO,
    pub claims: Vec<ClaimBindingDTO>,
    pub redirect_uri: Option<String>,
    /// The role the system has in relation to the credential. For example,
    /// if the system received the credential as a wallet this value will
    /// be `HOLDER`. If the system verified this credential during a presentation,
    /// this value will be `VERIFIER`.
    pub role: CredentialRoleBindingDTO,
    /// Scheduled date for credential reactivation.
    pub suspend_end_date: Option<String>,
    /// Validity details for ISO mdocs.
    pub mdoc_mso_validity: Option<MdocMsoValidityResponseBindingDTO>,
    /// Protocol used to issue the credential.
    pub protocol: String,
    /// Country profile associated with the credential.
    pub profile: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Into, uniffi::Enum)]
#[into(ExactColumn)]
#[uniffi(name = "CredentialListQueryExactColumn")]
pub enum CredentialListQueryExactColumnBindingEnum {
    Name,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(SortableCredentialColumn)]
#[uniffi(name = "SortableCredentialColumn")]
pub enum SortableCredentialColumnBindingEnum {
    CreatedDate,
    SchemaName,
    Issuer,
    State,
}

#[derive(Clone, Debug, uniffi::Enum)]
#[uniffi(name = "CredentialListQuerySearchType")]
pub enum SearchTypeBindingEnum {
    ClaimName,
    ClaimValue,
    CredentialSchemaName,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "CredentialListQuery")]
pub struct CredentialListQueryBindingDTO {
    /// Page number to retrieve (0-based indexing).
    pub page: u32,
    /// Number of items to return per page.
    pub page_size: u32,
    /// Field value to sort results by.
    pub sort: Option<SortableCredentialColumnBindingEnum>,
    /// Direction to sort results by.
    pub sort_direction: Option<SortDirection>,
    /// Specifies the organizational context for this operation.
    pub organisation_id: String,
    /// Return only credentials with a name starting with this string.
    pub name: Option<String>,
    /// Filter by one or more country profiles.
    pub profiles: Option<Vec<String>>,
    /// Search for a string.
    pub search_text: Option<String>,
    /// Changes where `searchText` is searched. Choose one or more
    /// `searchType`s and pass a `searchText`.
    pub search_type: Option<Vec<SearchTypeBindingEnum>>,
    /// Set which filters apply in an exact way.
    pub exact: Option<Vec<CredentialListQueryExactColumnBindingEnum>>,
    /// Filter credentials by one or more roles: issued by the system,
    /// verified by the system, or held by the system as a wallet.
    pub roles: Option<Vec<CredentialRoleBindingDTO>>,
    /// Filter by one or more UUIDs.
    pub ids: Option<Vec<String>>,
    /// Filter by one or more credential states.
    pub states: Option<Vec<CredentialStateBindingEnum>>,
    /// Additional fields to include in response objects. Omitting
    /// this keeps responses shorter.
    pub include: Option<Vec<CredentialListIncludeEntityTypeBindingEnum>>,
    /// Return only credentials with the specified credential schema(s).
    pub credential_schema_ids: Option<Vec<String>>,

    /// Return only credentials created after this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub created_date_after: Option<String>,
    /// Return only credentials created before this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub created_date_before: Option<String>,
    /// Return only credentials last modified after this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub last_modified_after: Option<String>,
    /// Return only credentials last modified before this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub last_modified_before: Option<String>,
    /// Return only credentials issued after this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub issuance_date_after: Option<String>,
    /// Return only credentials issued before this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub issuance_date_before: Option<String>,
    /// Return only credentials revoked after this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub revocation_date_after: Option<String>,
    /// Return only credentials revoked before this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub revocation_date_before: Option<String>,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(one_core::model::credential::CredentialListIncludeEntityTypeEnum)]
#[uniffi(name = "CredentialListIncludeEntityType")]
pub enum CredentialListIncludeEntityTypeBindingEnum {
    LayoutProperties,
    Credential,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetCredentialListResponseDTO)]
#[uniffi(name = "CredentialList")]
pub struct CredentialListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<CredentialListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "MdocMsoValidity")]
pub struct MdocMsoValidityResponseBindingDTO {
    pub expiration: String,
    pub next_update: String,
    pub last_update: String,
}

#[derive(Clone, Debug, From, Into, Eq, PartialEq, uniffi::Enum)]
#[from(CredentialStateEnum)]
#[into(one_core::model::credential::CredentialStateEnum)]
#[uniffi(name = "CredentialState")]
pub enum CredentialStateBindingEnum {
    Created,
    Pending,
    Offered,
    Accepted,
    Rejected,
    Revoked,
    Suspended,
    Error,
    InteractionExpired,
}

#[derive(Clone, Debug, uniffi::Record, From)]
#[from(DetailCredentialClaimResponseDTO)]
#[uniffi(name = "Claim")]
pub struct ClaimBindingDTO {
    pub path: String,
    pub schema: CredentialClaimSchemaBindingDTO,
    pub value: ClaimValueBindingDTO,
}

#[derive(Clone, Debug, uniffi::Enum)]
#[uniffi(name = "ClaimValue")]
pub enum ClaimValueBindingDTO {
    Boolean { value: bool },
    Float { value: f64 },
    Integer { value: i64 },
    String { value: String },
    Nested { value: Vec<ClaimBindingDTO> },
}

#[derive(Clone, Debug, Into, From, uniffi::Enum)]
#[from(CredentialRole)]
#[into(CredentialRole)]
#[uniffi(name = "CredentialRole")]
pub enum CredentialRoleBindingDTO {
    Holder,
    Issuer,
    Verifier,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "CredentialListItem")]
pub struct CredentialListItemBindingDTO {
    pub id: String,
    pub created_date: String,
    pub issuance_date: Option<String>,
    pub last_modified: String,
    pub revocation_date: Option<String>,
    /// Credential issuer metadata.
    pub issuer: Option<String>,
    /// State representation of the credential in the system.
    pub state: CredentialStateBindingEnum,
    /// Schema of the credential.
    pub schema: CredentialSchemaBindingDTO,
    /// The role the system has in relation to the credential. For example,
    /// if the system received the credential as a wallet this value will
    /// be `HOLDER`. If the system verified this credential during a presentation,
    /// this value will be `VERIFIER`.
    pub role: CredentialRoleBindingDTO,
    /// Scheduled date for credential reactivation.
    pub suspend_end_date: Option<String>,
    /// Protocol used to issue the credential.
    pub protocol: String,
    /// Country profile associated with the credential.
    pub profile: Option<String>,
}
