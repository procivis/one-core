use one_core::model::history::{
    HistoryAction, HistoryEntityType, HistoryFilterValue, HistoryListQuery, HistorySearchEnum,
};
use one_core::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, ValueComparison,
};
use one_core::model::list_query::ListPagination;
use one_core::service::history::dto::GetHistoryListResponseDTO;
use one_dto_mapper::{From, Into, convert_inner};
use serde::{Deserialize, Serialize};

use super::backup::UnexportableEntitiesBindingDTO;
use crate::OneCoreBinding;
use crate::binding::mapper::deserialize_timestamp;
use crate::error::BindingError;
use crate::utils::into_id;

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    #[uniffi::method]
    pub async fn get_history_entry(
        &self,
        history_id: String,
    ) -> Result<HistoryListItemBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .history_service
            .get_history_entry(into_id(&history_id)?)
            .await?
            .into())
    }

    #[uniffi::method]
    pub async fn get_history_list(
        &self,
        query: HistoryListQueryBindingDTO,
    ) -> Result<HistoryListBindingDTO, BindingError> {
        let core = self.use_core().await?;

        let organisation_id = into_id(&query.organisation_id)?;

        let mut conditions = vec![HistoryFilterValue::OrganisationId(organisation_id).condition()];

        if let Some(value) = query.entity_id {
            conditions.push(HistoryFilterValue::EntityId(into_id(&value)?).condition());
        }
        if let Some(value) = query.entity_types {
            conditions.push(
                HistoryFilterValue::EntityTypes(
                    value
                        .into_iter()
                        .map(|entity_type| entity_type.into())
                        .collect(),
                )
                .condition(),
            );
        }
        if let Some(values) = query.actions {
            conditions.push(HistoryFilterValue::Actions(convert_inner(values)).condition());
        }
        if let Some(value) = query.identifier_id {
            conditions.push(HistoryFilterValue::IdentifierId(into_id(&value)?).condition());
        }
        if let Some(value) = query.created_date_after {
            conditions.push(
                HistoryFilterValue::CreatedDate(ValueComparison {
                    comparison: ComparisonType::GreaterThanOrEqual,
                    value: deserialize_timestamp(&value)?,
                })
                .condition(),
            );
        }
        if let Some(value) = query.created_date_before {
            conditions.push(
                HistoryFilterValue::CreatedDate(ValueComparison {
                    comparison: ComparisonType::LessThanOrEqual,
                    value: deserialize_timestamp(&value)?,
                })
                .condition(),
            );
        }
        if let Some(value) = query.credential_id {
            conditions.push(HistoryFilterValue::CredentialId(into_id(&value)?).condition());
        }
        if let Some(value) = query.credential_schema_id {
            conditions.push(HistoryFilterValue::CredentialSchemaId(into_id(&value)?).condition());
        }

        if let Some(value) = query.search {
            conditions.push(search_query_to_filter_value(value).condition());
        }

        if let Some(proof_schema_id) = query.proof_schema_id {
            conditions
                .push(HistoryFilterValue::ProofSchemaId(into_id(&proof_schema_id)?).condition());
        }

        if let Some(user) = query.user {
            conditions.push(HistoryFilterValue::User(user).condition());
        }

        Ok(core
            .history_service
            .get_history_list(HistoryListQuery {
                pagination: Some(ListPagination {
                    page: query.page,
                    page_size: query.page_size,
                }),
                sorting: None,
                filtering: Some(ListFilterCondition::And(conditions)),
                include: None,
            })
            .await?
            .into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, From, Into, uniffi::Enum)]
#[from(HistoryAction)]
#[into(HistoryAction)]
pub enum HistoryActionBindingEnum {
    Accepted,
    Created,
    CsrGenerated,
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
    Activated,
    Withdrawn,
    Removed,
    Retracted,
    Updated,
    Reactivated,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq, From, Into, uniffi::Enum)]
#[from(HistoryEntityType)]
#[into(HistoryEntityType)]
pub enum HistoryEntityTypeBindingEnum {
    Key,
    Did,
    Identifier,
    Certificate,
    Credential,
    CredentialSchema,
    Proof,
    ProofSchema,
    Organisation,
    Backup,
    TrustAnchor,
    TrustEntity,
    WalletUnit,
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum HistoryMetadataBinding {
    UnexportableEntities {
        value: UnexportableEntitiesBindingDTO,
    },
    ErrorMetadata {
        value: HistoryErrorMetadataBindingDTO,
    },
    WalletUnitJWT(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct HistoryErrorMetadataBindingDTO {
    pub error_code: String,
    pub message: String,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct HistoryListItemBindingDTO {
    pub id: String,
    pub created_date: String,
    pub action: HistoryActionBindingEnum,
    pub name: String,
    pub entity_id: Option<String>,
    pub entity_type: HistoryEntityTypeBindingEnum,
    pub metadata: Option<HistoryMetadataBinding>,
    pub organisation_id: Option<String>,
    pub target: Option<String>,
    pub user: Option<String>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct HistoryListQueryBindingDTO {
    pub page: u32,
    pub page_size: u32,
    pub organisation_id: String,
    pub entity_id: Option<String>,
    pub entity_types: Option<Vec<HistoryEntityTypeBindingEnum>>,
    pub actions: Option<Vec<HistoryActionBindingEnum>>,
    pub created_date_after: Option<String>,
    pub created_date_before: Option<String>,
    pub identifier_id: Option<String>,
    pub credential_id: Option<String>,
    pub credential_schema_id: Option<String>,
    pub proof_schema_id: Option<String>,
    pub search: Option<HistorySearchBindingDTO>,
    pub user: Option<String>,
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

fn search_query_to_filter_value(value: HistorySearchBindingDTO) -> HistoryFilterValue {
    match value.r#type {
        Some(search_type) => HistoryFilterValue::SearchQuery(value.text, search_type.into()),
        None => HistoryFilterValue::SearchQuery(value.text, HistorySearchEnum::All),
    }
}
