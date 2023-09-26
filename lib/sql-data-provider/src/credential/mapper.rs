use crate::{
    entity::{self, credential, credential_schema, credential_state, did},
    list_query::GetEntityColumn,
};
use one_core::model::{
    credential::{
        Credential, CredentialId, CredentialState, CredentialStateEnum, SortableCredentialColumn,
    },
    credential_schema::CredentialSchema,
    did::{Did, DidId},
    interaction::InteractionId,
};
use one_core::repository::error::DataLayerError;
use sea_orm::{sea_query::SimpleExpr, IntoSimpleExpr, Set};
use std::str::FromStr;
use uuid::Uuid;

impl From<entity::credential_state::CredentialState> for CredentialStateEnum {
    fn from(value: entity::credential_state::CredentialState) -> Self {
        match value {
            entity::credential_state::CredentialState::Created => CredentialStateEnum::Created,
            entity::credential_state::CredentialState::Pending => CredentialStateEnum::Pending,
            entity::credential_state::CredentialState::Offered => CredentialStateEnum::Offered,
            entity::credential_state::CredentialState::Accepted => CredentialStateEnum::Accepted,
            entity::credential_state::CredentialState::Rejected => CredentialStateEnum::Rejected,
            entity::credential_state::CredentialState::Revoked => CredentialStateEnum::Revoked,
            entity::credential_state::CredentialState::Error => CredentialStateEnum::Error,
        }
    }
}

impl From<CredentialStateEnum> for entity::credential_state::CredentialState {
    fn from(value: CredentialStateEnum) -> Self {
        match value {
            CredentialStateEnum::Created => entity::credential_state::CredentialState::Created,
            CredentialStateEnum::Pending => entity::credential_state::CredentialState::Pending,
            CredentialStateEnum::Offered => entity::credential_state::CredentialState::Offered,
            CredentialStateEnum::Accepted => entity::credential_state::CredentialState::Accepted,
            CredentialStateEnum::Rejected => entity::credential_state::CredentialState::Rejected,
            CredentialStateEnum::Revoked => entity::credential_state::CredentialState::Revoked,
            CredentialStateEnum::Error => entity::credential_state::CredentialState::Error,
        }
    }
}

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

impl From<entity::credential_state::Model> for one_core::model::credential::CredentialState {
    fn from(value: entity::credential_state::Model) -> Self {
        Self {
            created_date: value.created_date,
            state: value.state.into(),
        }
    }
}

impl TryFrom<entity::credential::Model> for Credential {
    type Error = DataLayerError;
    fn try_from(credential: entity::credential::Model) -> Result<Self, Self::Error> {
        let credential_id =
            Uuid::from_str(&credential.id).map_err(|_| DataLayerError::MappingError)?;

        Ok(Self {
            id: credential_id,
            created_date: credential.created_date,
            issuance_date: credential.issuance_date,
            last_modified: credential.last_modified,
            credential: credential.credential,
            transport: credential.transport,
            state: None,
            claims: None,
            issuer_did: None,
            holder_did: None,
            schema: None,
            interaction: None,
        })
    }
}

pub(super) fn request_to_active_model(
    request: &Credential,
    schema: CredentialSchema,
    issuer_did: Did,
    holder_did_id: Option<DidId>,
    interaction_id: Option<InteractionId>,
) -> credential::ActiveModel {
    credential::ActiveModel {
        id: Set(request.id.to_string()),
        credential_schema_id: Set(schema.id.to_string()),
        created_date: Set(request.created_date),
        last_modified: Set(request.last_modified),
        issuance_date: Set(request.issuance_date),
        deleted_at: Set(None),
        transport: Set(request.transport.to_owned()),
        credential: Set(request.credential.to_owned()),
        issuer_did_id: Set(issuer_did.id.to_string()),
        holder_did_id: Set(holder_did_id.map(|did_id| did_id.to_string())),
        interaction_id: Set(interaction_id.map(|id| id.to_string())),
    }
}
