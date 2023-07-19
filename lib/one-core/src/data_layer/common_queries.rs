use sea_orm::{
    ActiveValue::Set, ColumnTrait, Condition, DatabaseConnection, EntityTrait, Order, QueryFilter,
    QueryOrder, QuerySelect, RelationTrait,
};
use time::OffsetDateTime;

use crate::data_layer::{
    data_model::ClaimClaimSchemaCombined,
    data_model::{CredentialSchemaClaimSchemaCombined, ProofSchemaClaimSchemaCombined},
    entities::{
        claim, claim_schema, credential_schema, credential_schema_claim_schema, credential_state,
        proof_schema_claim_schema, Claim, ClaimSchema, CredentialState, ProofSchemaClaimSchema,
    },
    DataLayerError,
};

pub(crate) async fn fetch_claim_claim_schemas(
    db: &DatabaseConnection,
    schema_ids: &[String],
) -> Result<Vec<ClaimClaimSchemaCombined>, DataLayerError> {
    let claims = Claim::find()
        .filter(Condition::all().add(claim::Column::CredentialId.is_in(schema_ids)))
        .select_only()
        .columns([claim::Column::CredentialId, claim::Column::Value])
        .columns([
            claim_schema::Column::Id,
            claim_schema::Column::Datatype,
            claim_schema::Column::Key,
            claim_schema::Column::CreatedDate,
            claim_schema::Column::LastModified,
        ])
        .join_rev(
            sea_orm::JoinType::LeftJoin,
            claim::Relation::ClaimSchema.def().rev(),
        )
        .order_by(claim_schema::Column::CreatedDate, sea_orm::Order::Asc)
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
        .filter(
            Condition::all()
                .add(credential_schema_claim_schema::Column::CredentialSchemaId.is_in(schema_ids)),
        )
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
        .order_by(
            credential_schema_claim_schema::Column::Order,
            sea_orm::Order::Asc,
        )
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
        .column_as(credential_schema::Column::Id, "credential_id")
        .column_as(credential_schema::Column::Name, "credential_name")
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
