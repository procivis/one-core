use one_core::{
    model::{
        credential::{Credential, CredentialId, CredentialState, SortableCredentialColumn},
        credential_schema::CredentialSchema,
        did::Did,
        interaction::InteractionId,
        key::KeyId,
        revocation_list::RevocationListId,
    },
    repository::error::DataLayerError,
};
use sea_orm::{sea_query::SimpleExpr, IntoSimpleExpr, Set};
use shared_types::{DidId, DidValue};
use std::str::FromStr;
use uuid::Uuid;

use crate::{
    credential::entity_model::CredentialListEntityModel,
    entity::{self, credential, credential_schema, credential_state, did},
    list_query::GetEntityColumn,
};

impl GetEntityColumn for SortableCredentialColumn {
    fn get_simple_expr(&self) -> SimpleExpr {
        match self {
            SortableCredentialColumn::CreatedDate => {
                credential::Column::CreatedDate.into_simple_expr()
            }
            SortableCredentialColumn::SchemaName => {
                credential_schema::Column::Name.into_simple_expr()
            }
            SortableCredentialColumn::IssuerDid => did::Column::Did.into_simple_expr(),
            SortableCredentialColumn::State => credential_state::Column::State.into_simple_expr(),
        }
    }
}

pub(super) fn get_credential_state_active_model(
    id: &CredentialId,
    state: CredentialState,
) -> credential_state::ActiveModel {
    credential_state::ActiveModel {
        credential_id: Set(id.to_string()),
        created_date: Set(state.created_date),
        state: Set(state.state.into()),
    }
}

impl TryFrom<entity::credential::Model> for Credential {
    type Error = DataLayerError;

    fn try_from(credential: entity::credential::Model) -> Result<Self, Self::Error> {
        let credential_id = Uuid::from_str(&credential.id)?;

        Ok(Self {
            id: credential_id,
            created_date: credential.created_date,
            issuance_date: credential.issuance_date,
            last_modified: credential.last_modified,
            deleted_at: credential.deleted_at,
            credential: credential.credential,
            transport: credential.transport,
            redirect_uri: credential.redirect_uri,
            role: credential.role.into(),
            state: None,
            claims: None,
            issuer_did: None,
            holder_did: None,
            schema: None,
            interaction: None,
            revocation_list: None,
            key: None,
        })
    }
}

pub(super) fn request_to_active_model(
    request: &Credential,
    schema: CredentialSchema,
    issuer_did: Option<Did>,
    holder_did_id: Option<DidId>,
    interaction_id: Option<InteractionId>,
    revocation_list_id: Option<RevocationListId>,
    key_id: Option<KeyId>,
) -> credential::ActiveModel {
    credential::ActiveModel {
        id: Set(request.id.to_string()),
        credential_schema_id: Set(schema.id.to_string()),
        created_date: Set(request.created_date),
        last_modified: Set(request.last_modified),
        issuance_date: Set(request.issuance_date),
        deleted_at: Set(request.deleted_at),
        transport: Set(request.transport.to_owned()),
        credential: Set(request.credential.to_owned()),
        redirect_uri: Set(request.redirect_uri.to_owned()),
        issuer_did_id: Set(issuer_did.map(|did| did.id)),
        holder_did_id: Set(holder_did_id),
        interaction_id: Set(interaction_id.map(|id| id.to_string())),
        revocation_list_id: Set(revocation_list_id.map(|id| id.to_string())),
        key_id: Set(key_id.map(|id| id.to_string())),
        role: Set(request.role.to_owned().into()),
    }
}

pub(super) fn credential_list_model_to_repository_model(
    credential: CredentialListEntityModel,
) -> Result<Credential, DataLayerError> {
    let schema_id = Uuid::from_str(&credential.credential_schema_id)?;
    let schema = CredentialSchema {
        id: schema_id,
        deleted_at: credential.credential_schema_deleted_at,
        created_date: credential.credential_schema_created_date,
        last_modified: credential.credential_schema_last_modified,
        name: credential.credential_schema_name,
        format: credential.credential_schema_format,
        revocation_method: credential.credential_schema_revocation_method,
        claim_schemas: None,
        organisation: None,
    };

    let issuer_did = match credential.issuer_did_id {
        None => None,
        Some(issuer_did_id) => {
            let issuer_did_id = Uuid::from_str(&issuer_did_id)?;
            Some(Did {
                id: DidId::from(issuer_did_id),
                created_date: credential
                    .issuer_did_created_date
                    .ok_or(DataLayerError::MappingError)?,
                last_modified: credential
                    .issuer_did_last_modified
                    .ok_or(DataLayerError::MappingError)?,
                name: credential
                    .issuer_did_name
                    .ok_or(DataLayerError::MappingError)?,
                did: DidValue::from_str(
                    &credential
                        .issuer_did_did
                        .ok_or(DataLayerError::MappingError)?,
                )
                .map_err(|_| DataLayerError::MappingError)?,
                did_type: credential
                    .issuer_did_type_field
                    .ok_or(DataLayerError::MappingError)?
                    .into(),
                did_method: credential
                    .issuer_did_method
                    .ok_or(DataLayerError::MappingError)?,
                deactivated: credential
                    .issuer_did_deactivated
                    .ok_or(DataLayerError::MappingError)?,
                keys: None,
                organisation: None,
            })
        }
    };

    let state = vec![CredentialState {
        created_date: credential.credential_state_created_date,
        state: credential.credential_state_state.into(),
    }];

    Ok(Credential {
        id: Uuid::from_str(&credential.id).map_err(|_| DataLayerError::MappingError)?,
        created_date: credential.created_date,
        issuance_date: credential.issuance_date,
        last_modified: credential.last_modified,
        deleted_at: credential.deleted_at,
        credential: credential.credential,
        transport: credential.transport,
        redirect_uri: credential.redirect_uri,
        role: credential.role.into(),
        state: Some(state),
        claims: None,
        issuer_did,
        holder_did: None,
        schema: Some(schema),
        interaction: None,
        revocation_list: None,
        key: None,
    })
}

pub(super) fn credentials_to_repository(
    credentials: Vec<CredentialListEntityModel>,
) -> Result<Vec<Credential>, DataLayerError> {
    let mut result: Vec<Credential> = Vec::new();
    for credential in credentials.into_iter() {
        result.push(credential_list_model_to_repository_model(credential)?);
    }

    Ok(result)
}
