use one_core::model::claim::Claim;
use sea_orm::sea_query::SimpleExpr;
use sea_orm::{IntoSimpleExpr, Set};

use uuid::Uuid;

use one_core::model::credential::{
    Credential, CredentialId, CredentialState, CredentialStateEnum, SortableCredentialColumn,
};
use one_core::model::credential_schema::CredentialSchema;
use one_core::model::did::Did;

use crate::{
    entity::{self, credential, credential_schema, credential_state, did},
    list_query::GetEntityColumn,
};

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

pub(super) fn entities_to_credential(
    credential_id: Uuid,
    credential: credential::Model,
    states: Option<Vec<CredentialState>>,
    issuer_did: Option<Did>,
    receiver_did: Option<Did>,
    claims: Option<Vec<Claim>>,
    schema: Option<CredentialSchema>,
) -> Credential {
    Credential {
        id: credential_id,
        created_date: credential.created_date,
        issuance_date: credential.issuance_date,
        state: states,
        last_modified: credential.last_modified,
        issuer_did,
        receiver_did,
        credential: credential.credential,
        claims,
        schema,
        transport: credential.transport,
    }
}

pub(super) fn request_to_active_model(
    request: &Credential,
    schema: CredentialSchema,
    issuer_did: Did,
    receiver_did: Option<String>,
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
        receiver_did_id: Set(receiver_did),
    }
}
