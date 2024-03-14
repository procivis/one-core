use std::str::FromStr;

use dto_mapper::{convert_inner, try_convert_inner};
use one_core::{
    model::{
        credential::Credential, credential_schema::CredentialSchema, organisation::Organisation,
    },
    repository::error::DataLayerError,
};
use uuid::Uuid;

use crate::entity::{claim, credential_state};

use super::models::UnexportableCredentialModel;

impl TryFrom<UnexportableCredentialModel> for Credential {
    type Error = DataLayerError;

    fn try_from(value: UnexportableCredentialModel) -> Result<Self, Self::Error> {
        let states: Vec<credential_state::Model> = serde_json::from_str(&value.credential_states)
            .map_err(|_| Self::Error::MappingError)?;
        let claims: Vec<claim::Model> =
            serde_json::from_str(&value.claims).map_err(|_| Self::Error::MappingError)?;

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            issuance_date: value.issuance_date,
            last_modified: value.last_modified,
            deleted_at: value.deleted_at,
            credential: value.credential,
            transport: value.transport,
            redirect_uri: value.redirect_uri,
            role: value.role.into(),
            state: Some(convert_inner(states)),
            claims: Some(try_convert_inner(claims)?),
            issuer_did: None,
            holder_did: None,
            schema: Some(CredentialSchema {
                id: Uuid::from_str(&value.credential_schema_id)?,
                deleted_at: value.credential_schema_deleted_at,
                created_date: value.credential_schema_created_date,
                last_modified: value.credential_schema_last_modified,
                name: value.credential_schema_name,
                format: value.credential_schema_format,
                wallet_storage_type: convert_inner(value.credential_schema_wallet_storage_type),
                revocation_method: value.credential_schema_revocation_method,
                claim_schemas: None,
                organisation: Some(Organisation {
                    id: value.organisation_id,
                    created_date: value.organisation_created_date,
                    last_modified: value.organisation_last_modified,
                }),
            }),
            interaction: None,
            revocation_list: None,
            key: None,
        })
    }
}
