use one_core::model::common::ExactColumn;
use one_core::model::credential::{CredentialFilterValue, SortableCredentialColumn};
use one_core::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::service::credential::dto::{
    CredentialRole, CredentialStateEnum, GetCredentialListResponseDTO, GetCredentialQueryDTO,
};
use one_core::service::error::{BusinessLogicError, ServiceError};
use one_core::{model, service};
use one_dto_mapper::{From, Into, convert_inner};

use super::common::SortDirection;
use super::credential_schema::CredentialSchemaBindingDTO;
use super::identifier::GetIdentifierListItemBindingDTO;
use crate::OneCoreBinding;
use crate::binding::mapper::deserialize_timestamp;
use crate::error::BindingError;
use crate::utils::into_id;

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
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

    #[uniffi::method]
    pub async fn get_credentials(
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
pub struct CredentialDetailBindingDTO {
    pub id: String,
    pub created_date: String,
    pub issuance_date: Option<String>,
    pub last_modified: String,
    pub revocation_date: Option<String>,
    pub issuer: Option<GetIdentifierListItemBindingDTO>,
    pub holder: Option<GetIdentifierListItemBindingDTO>,
    pub state: CredentialStateBindingEnum,
    pub schema: CredentialSchemaBindingDTO,
    pub claims: Vec<ClaimBindingDTO>,
    pub redirect_uri: Option<String>,
    pub role: CredentialRoleBindingDTO,
    pub lvvc_issuance_date: Option<String>,
    pub suspend_end_date: Option<String>,
    pub mdoc_mso_validity: Option<MdocMsoValidityResponseBindingDTO>,
    pub protocol: String,
    pub profile: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Into, uniffi::Enum)]
#[into(ExactColumn)]
pub enum CredentialListQueryExactColumnBindingEnum {
    Name,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(SortableCredentialColumn)]
pub enum SortableCredentialColumnBindingEnum {
    CreatedDate,
    SchemaName,
    Issuer,
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
    pub profiles: Option<Vec<String>>,
    pub search_text: Option<String>,
    pub search_type: Option<Vec<SearchTypeBindingEnum>>,
    pub exact: Option<Vec<CredentialListQueryExactColumnBindingEnum>>,
    pub roles: Option<Vec<CredentialRoleBindingDTO>>,
    pub ids: Option<Vec<String>>,
    pub states: Option<Vec<CredentialStateBindingEnum>>,
    pub include: Option<Vec<CredentialListIncludeEntityTypeBindingEnum>>,
    pub credential_schema_ids: Option<Vec<String>>,

    pub created_date_after: Option<String>,
    pub created_date_before: Option<String>,
    pub last_modified_after: Option<String>,
    pub last_modified_before: Option<String>,
    pub issuance_date_after: Option<String>,
    pub issuance_date_before: Option<String>,
    pub revocation_date_after: Option<String>,
    pub revocation_date_before: Option<String>,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(one_core::model::credential::CredentialListIncludeEntityTypeEnum)]
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

#[derive(Clone, Debug, uniffi::Record)]
pub struct MdocMsoValidityResponseBindingDTO {
    pub expiration: String,
    pub next_update: String,
    pub last_update: String,
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

#[derive(Clone, Debug, Into, From, uniffi::Enum)]
#[from(CredentialRole)]
#[into(CredentialRole)]
pub enum CredentialRoleBindingDTO {
    Holder,
    Issuer,
    Verifier,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct CredentialListItemBindingDTO {
    pub id: String,
    pub created_date: String,
    pub issuance_date: Option<String>,
    pub last_modified: String,
    pub revocation_date: Option<String>,
    pub issuer: Option<String>,
    pub state: CredentialStateBindingEnum,
    pub schema: CredentialSchemaBindingDTO,
    pub role: CredentialRoleBindingDTO,
    pub suspend_end_date: Option<String>,
    pub protocol: String,
    pub profile: Option<String>,
}
