use one_core::model::claim::Claim;
use one_core::model::credential::Credential;
use one_core::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaType, LayoutType,
};
use one_core::model::organisation::Organisation;
use one_core::repository::error::DataLayerError;
use one_dto_mapper::convert_inner;

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
            exchange: value.exchange,
            redirect_uri: value.redirect_uri,
            role: value.role.into(),
            state: value.state.into(),
            suspend_end_date: value.suspend_end_date,
            claims: Some(convert_inner(claims_with_schema)),
            issuer_did: None,
            holder_did: None,
            schema: Some(CredentialSchema {
                id: value.credential_schema_id,
                deleted_at: value.credential_schema_deleted_at,
                created_date: value.credential_schema_created_date,
                last_modified: value.credential_schema_last_modified,
                imported_source_url: value.credential_schema_imported_source_url,
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
                allow_suspension: value.credential_schema_allow_suspension,
            }),
            interaction: None,
            revocation_list: None,
            key: None,
        })
    }
}
