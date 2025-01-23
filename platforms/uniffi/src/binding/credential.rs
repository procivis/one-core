use one_core::model::common::ExactColumn;
use one_core::model::credential::SortableCredentialColumn;
use one_core::model::list_filter::{
    ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
};
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::service::credential::dto::{
    CredentialFilterValue, CredentialListIncludeEntityTypeEnum, CredentialRole,
    CredentialStateEnum, GetCredentialListResponseDTO, GetCredentialQueryDTO,
};
use one_core::service::error::{BusinessLogicError, ServiceError};
use one_dto_mapper::{convert_inner, From, Into};

use super::common::SortDirection;
use super::credential_schema::CredentialSchemaBindingDTO;
use super::did::DidListItemBindingDTO;
use crate::error::BindingError;
use crate::utils::into_id;
use crate::OneCoreBinding;

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
    pub fn get_credential(
        &self,
        credential_id: String,
    ) -> Result<CredentialDetailBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .credential_service
                .get_credential(&into_id(&credential_id)?)
                .await?
                .into())
        })
    }

    #[uniffi::method]
    pub fn get_credentials(
        &self,
        query: CredentialListQueryBindingDTO,
    ) -> Result<CredentialListBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;

            let condition = {
                if query.name.is_some()
                    && query.search_type.is_some()
                    && query.search_text.is_some()
                {
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

                let organisation =
                    CredentialFilterValue::OrganisationId(into_id(&query.organisation_id)?)
                        .condition();

                let name = query.name.map(|name| {
                    CredentialFilterValue::CredentialSchemaName(StringMatch {
                        r#match: get_string_match_type(
                            CredentialListQueryExactColumnBindingEnum::Name,
                        ),
                        value: name,
                    })
                });

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

                let role = query
                    .role
                    .map(|role| CredentialFilterValue::Role(role.into()));

                let ids = match query.ids {
                    Some(ids) => {
                        let ids = ids
                            .iter()
                            .map(|id| into_id(id))
                            .collect::<Result<Vec<_>, _>>()?;
                        Some(CredentialFilterValue::CredentialIds(ids))
                    }
                    None => None,
                };

                let states = query.status.map(|values| {
                    CredentialFilterValue::State(
                        values.into_iter().map(|status| status.into()).collect(),
                    )
                });

                search_filters & name & role & ids & states
            };

            Ok(core
                .credential_service
                .get_credential_list(GetCredentialQueryDTO {
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
                })
                .await?
                .into())
        })
    }

    #[uniffi::method]
    pub fn delete_credential(&self, credential_id: String) -> Result<(), BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .credential_service
                .delete_credential(&into_id(&credential_id)?)
                .await?)
        })
    }
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
    pub issuance_date: String,
    pub last_modified: String,
    pub revocation_date: Option<String>,
    pub issuer_did: Option<String>,
    pub state: CredentialStateBindingEnum,
    pub schema: CredentialSchemaBindingDTO,
    pub role: CredentialRoleBindingDTO,
    pub suspend_end_date: Option<String>,
}
