use std::str::FromStr;

use dto_mapper::convert_inner;
use one_core::{
    model::{
        claim::Claim,
        credential::Credential,
        credential_schema::{
            CredentialSchema, CredentialSchemaClaim, CredentialSchemaType, LayoutType,
        },
        organisation::Organisation,
    },
    repository::error::DataLayerError,
};
use uuid::Uuid;

use crate::entity::credential_state;

use super::models::{ClaimWithSchema, SchemaWithClaimSchema, UnexportableCredentialModel};

impl From<ClaimWithSchema> for Claim {
    fn from(value: ClaimWithSchema) -> Self {
        let mut claim: Claim = value.claim.into();
        claim.schema = Some(value.claim_schema.into());
        claim
    }
}

impl From<SchemaWithClaimSchema> for CredentialSchemaClaim {
    fn from(value: SchemaWithClaimSchema) -> Self {
        Self {
            required: value.credential_schema_claim_schema.required,
            schema: value.claim_schema.into(),
        }
    }
}

impl TryFrom<UnexportableCredentialModel> for Credential {
    type Error = DataLayerError;

    fn try_from(value: UnexportableCredentialModel) -> Result<Self, Self::Error> {
        let states: Vec<credential_state::Model> = serde_json::from_str(&value.credential_states)
            .map_err(|_| Self::Error::MappingError)?;

        let claims_with_schema: Vec<ClaimWithSchema> =
            serde_json::from_str(&value.claims).map_err(|_| Self::Error::MappingError)?;

        let credential_schema_claim_schemas: Vec<SchemaWithClaimSchema> =
            serde_json::from_str(&value.credential_schema_claim_schemas)
                .map_err(|_| Self::Error::MappingError)?;

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
            claims: Some(convert_inner(claims_with_schema)),
            issuer_did: None,
            holder_did: None,
            schema: Some(CredentialSchema {
                id: Uuid::from_str(&value.credential_schema_id)?.into(),
                deleted_at: value.credential_schema_deleted_at,
                created_date: value.credential_schema_created_date,
                last_modified: value.credential_schema_last_modified,
                name: value.credential_schema_name,
                format: value.credential_schema_format,
                wallet_storage_type: convert_inner(value.credential_schema_wallet_storage_type),
                revocation_method: value.credential_schema_revocation_method,
                claim_schemas: Some(convert_inner(credential_schema_claim_schemas)),
                organisation: Some(Organisation {
                    id: value.organisation_id,
                    created_date: value.organisation_created_date,
                    last_modified: value.organisation_last_modified,
                }),
                // todo: this should be fixed in another ticket
                layout_type: LayoutType::Card,
                layout_properties: None,
                schema_type: CredentialSchemaType::ProcivisOneSchema2024,
                schema_id: "CredentialSchemaId".to_owned(),
            }),
            interaction: None,
            revocation_list: None,
            key: None,
        })
    }
}
