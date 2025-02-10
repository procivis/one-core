use one_core::model::history::{
    HistoryAction, HistoryEntityType, HistoryFilterValue, HistoryListQuery, HistorySearchEnum,
};
use one_core::model::list_filter::{ComparisonType, ListFilterCondition, ValueComparison};
use one_core::model::list_query::ListPagination;
use one_core::service::error::ServiceError;
use one_core::service::history::dto::GetHistoryListResponseDTO;
use one_dto_mapper::{convert_inner, From, Into};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::backup::UnexportableEntitiesBindingDTO;
use crate::error::BindingError;
use crate::utils::into_id;
use crate::OneCoreBinding;

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

        let mut conditions = vec![ListFilterCondition::Value(
            HistoryFilterValue::OrganisationId(organisation_id),
        )];

        if let Some(value) = query.entity_id {
            conditions.push(ListFilterCondition::Value(HistoryFilterValue::EntityId(
                into_id(&value)?,
            )));
        }
        if let Some(value) = query.entity_types {
            conditions.push(ListFilterCondition::Value(HistoryFilterValue::EntityTypes(
                value
                    .into_iter()
                    .map(|entity_type| entity_type.into())
                    .collect(),
            )));
        }
        if let Some(value) = query.action {
            conditions.push(ListFilterCondition::Value(HistoryFilterValue::Action(
                value.into(),
            )));
        }
        if let Some(value) = query.did_id {
            conditions.push(ListFilterCondition::Value(HistoryFilterValue::DidId(
                into_id(&value)?,
            )));
        }
        if let Some(value) = query.created_date_from {
            let created_date_from = deserialize_timestamp(&value)
                .map_err(|e| ServiceError::ValidationError(e.to_string()))?;
            conditions.push(ListFilterCondition::Value(HistoryFilterValue::CreatedDate(
                ValueComparison {
                    comparison: ComparisonType::GreaterThanOrEqual,
                    value: created_date_from,
                },
            )));
        }
        if let Some(value) = query.created_date_to {
            let created_date_to = deserialize_timestamp(&value)
                .map_err(|e| ServiceError::ValidationError(e.to_string()))?;
            conditions.push(ListFilterCondition::Value(HistoryFilterValue::CreatedDate(
                ValueComparison {
                    comparison: ComparisonType::LessThanOrEqual,
                    value: created_date_to,
                },
            )));
        }
        if let Some(value) = query.credential_id {
            conditions.push(ListFilterCondition::Value(
                HistoryFilterValue::CredentialId(into_id(&value)?),
            ));
        }
        if let Some(value) = query.credential_schema_id {
            conditions.push(ListFilterCondition::Value(
                HistoryFilterValue::CredentialSchemaId(into_id(&value)?),
            ));
        }

        if let Some(value) = query.search {
            conditions.push(ListFilterCondition::Value(search_query_to_filter_value(
                value,
            )));
        }

        if let Some(proof_schema_id) = query.proof_schema_id {
            conditions.push(ListFilterCondition::Value(
                HistoryFilterValue::ProofSchemaId(into_id(&proof_schema_id)?),
            ));
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
    ErrorMetadata {
        value: HistoryErrorMetadataBindingDTO,
    },
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

fn deserialize_timestamp(value: &str) -> Result<OffsetDateTime, time::error::Parse> {
    OffsetDateTime::parse(value, &Rfc3339)
}

fn search_query_to_filter_value(value: HistorySearchBindingDTO) -> HistoryFilterValue {
    match value.r#type {
        Some(search_type) => HistoryFilterValue::SearchQuery(value.text, search_type.into()),
        None => HistoryFilterValue::SearchQuery(value.text, HistorySearchEnum::All),
    }
}
