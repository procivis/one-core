use one_core::repository::error::DataLayerError;
use sea_orm::{
    ActiveValue::Set, ColumnTrait, Condition, DatabaseConnection, EntityTrait, Order, QueryFilter,
    QueryOrder, QuerySelect, RelationTrait,
};
use time::OffsetDateTime;

use crate::entity::*;

use crate::data_model::{
    ClaimClaimSchemaCombined, CredentialSchemaClaimSchemaCombined, ProofSchemaClaimSchemaCombined,
};

pub(crate) async fn fetch_claim_claim_schemas(
    db: &DatabaseConnection,
    credential_ids: &[String],
) -> Result<Vec<ClaimClaimSchemaCombined>, DataLayerError> {
    let claims = CredentialClaim::find()
        .filter(credential_claim::Column::CredentialId.is_in(credential_ids))
        .select_only()
        .columns([credential_claim::Column::CredentialId])
        .columns([claim::Column::Value])
        .columns([
            claim_schema::Column::Id,
            claim_schema::Column::Datatype,
            claim_schema::Column::Key,
            claim_schema::Column::CreatedDate,
            claim_schema::Column::LastModified,
        ])
        .join(
            sea_orm::JoinType::LeftJoin,
            credential_claim::Relation::Credential.def(),
        )
        .join(
            sea_orm::JoinType::LeftJoin,
            credential_claim::Relation::Claim.def(),
        )
        .join(
            sea_orm::JoinType::LeftJoin,
            claim::Relation::ClaimSchema.def(),
        )
        .join(
            sea_orm::JoinType::LeftJoin,
            claim_schema::Relation::CredentialSchemaClaimSchema.def(),
        )
        .order_by_asc(credential_schema_claim_schema::Column::Order)
        .into_model::<ClaimClaimSchemaCombined>()
        .all(db)
        .await
        .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

    Ok(claims)
}

pub(crate) async fn fetch_credential_schema_claim_schemas(
    db: &DatabaseConnection,
    schema_ids: &[String],
) -> Result<Vec<CredentialSchemaClaimSchemaCombined>, DataLayerError> {
    let claims = ClaimSchema::find()
        .filter(credential_schema_claim_schema::Column::CredentialSchemaId.is_in(schema_ids))
        .select_only()
        .columns([
            claim_schema::Column::CreatedDate,
            claim_schema::Column::Datatype,
            claim_schema::Column::Key,
            claim_schema::Column::Id,
            claim_schema::Column::LastModified,
        ])
        .column(credential_schema_claim_schema::Column::CredentialSchemaId)
        .join_rev(
            sea_orm::JoinType::LeftJoin,
            credential_schema_claim_schema::Relation::ClaimSchema.def(),
        )
        .order_by_asc(credential_schema_claim_schema::Column::Order)
        .into_model::<CredentialSchemaClaimSchemaCombined>()
        .all(db)
        .await
        .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

    Ok(claims)
}

pub(crate) async fn fetch_proof_schema_claim_schemas(
    db: &DatabaseConnection,
    proof_ids: &[String],
) -> Result<Vec<ProofSchemaClaimSchemaCombined>, DataLayerError> {
    let claims = ProofSchemaClaimSchema::find()
        .filter(
            Condition::all().add(proof_schema_claim_schema::Column::ProofSchemaId.is_in(proof_ids)),
        )
        .select_only()
        .columns([
            proof_schema_claim_schema::Column::ClaimSchemaId,
            proof_schema_claim_schema::Column::ProofSchemaId,
            proof_schema_claim_schema::Column::Required,
        ])
        .column_as(claim_schema::Column::Key, "claim_key")
        .column_as(claim_schema::Column::CreatedDate, "claim_created_date")
        .column_as(claim_schema::Column::LastModified, "claim_last_modified")
        .column_as(claim_schema::Column::Datatype, "claim_datatype")
        .column_as(credential_schema::Column::Id, "credential_schema_id")
        .column_as(
            credential_schema::Column::CreatedDate,
            "credential_schema_created_date",
        )
        .column_as(
            credential_schema::Column::LastModified,
            "credential_schema_last_modified",
        )
        .column_as(credential_schema::Column::Name, "credential_schema_name")
        .column_as(
            credential_schema::Column::Format,
            "credential_schema_format",
        )
        .column_as(
            credential_schema::Column::RevocationMethod,
            "credential_schema_revocation_method",
        )
        .column_as(
            credential_schema::Column::OrganisationId,
            "credential_schema_organisation_id",
        )
        .join(
            sea_orm::JoinType::LeftJoin,
            proof_schema_claim_schema::Relation::ClaimSchema.def(),
        )
        .join_rev(
            sea_orm::JoinType::LeftJoin,
            credential_schema_claim_schema::Relation::ClaimSchema.def(),
        )
        .join(
            sea_orm::JoinType::LeftJoin,
            credential_schema_claim_schema::Relation::CredentialSchema.def(),
        )
        .order_by(
            proof_schema_claim_schema::Column::Order,
            sea_orm::Order::Asc,
        )
        .into_model::<ProofSchemaClaimSchemaCombined>()
        .all(db)
        .await
        .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

    Ok(claims)
}

pub(crate) async fn get_credential_state(
    db: &DatabaseConnection,
    credential_id: &str,
) -> Result<credential_state::CredentialState, DataLayerError> {
    let credential_state = CredentialState::find()
        .filter(credential_state::Column::CredentialId.eq(credential_id))
        .order_by(credential_state::Column::CreatedDate, Order::Desc)
        .one(db)
        .await
        .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?
        .ok_or(DataLayerError::RecordNotFound)?;

    Ok(credential_state.state)
}

pub(crate) async fn insert_credential_state(
    db: &DatabaseConnection,
    credential_id: &str,
    created_date: OffsetDateTime,
    state: credential_state::CredentialState,
) -> Result<(), DataLayerError> {
    credential_state::Entity::insert(credential_state::ActiveModel {
        credential_id: Set(credential_id.to_owned()),
        created_date: Set(created_date),
        state: Set(state),
    })
    .exec(db)
    .await
    .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

    Ok(())
}

pub(crate) async fn get_proof_state(
    db: &DatabaseConnection,
    proof_request_id: &str,
) -> Result<proof_state::ProofRequestState, DataLayerError> {
    let proof_request_state = ProofState::find()
        .filter(proof_state::Column::ProofId.eq(proof_request_id))
        .order_by(proof_state::Column::CreatedDate, Order::Desc)
        .one(db)
        .await
        .map_err(|e| {
            tracing::error!(
                "Error while fetching proof state for proof {}. Error: {}",
                proof_request_id,
                e.to_string()
            );
            DataLayerError::GeneralRuntimeError(e.to_string())
        })?
        .ok_or(DataLayerError::RecordNotFound)?;

    Ok(proof_request_state.state)
}

pub(crate) async fn insert_proof_state(
    db: &DatabaseConnection,
    proof_request_id: &str,
    created_date: OffsetDateTime,
    last_modified: OffsetDateTime,
    state: proof_state::ProofRequestState,
) -> Result<(), DataLayerError> {
    proof_state::Entity::insert(proof_state::ActiveModel {
        proof_id: Set(proof_request_id.to_owned()),
        created_date: Set(created_date),
        last_modified: Set(last_modified),
        state: Set(state),
    })
    .exec(db)
    .await
    .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

    Ok(())
}
