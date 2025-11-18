use one_core::model::claim::Claim;
use one_core::model::credential::Credential;
use one_core::model::credential_schema::{CredentialSchema, CredentialSchemaClaim, LayoutType};
use one_core::model::organisation::Organisation;
use one_core::repository::error::DataLayerError;
use one_dto_mapper::convert_inner;

use super::models::{ClaimWithSchema, UnexportableCredentialModel};
use crate::entity::claim_schema;

impl From<ClaimWithSchema> for Claim {
    fn from(value: ClaimWithSchema) -> Self {
        let mut claim: Claim = value.claim.into();
        claim.schema = Some(value.claim_schema.into());
        claim
    }
}

impl From<claim_schema::Model> for CredentialSchemaClaim {
    fn from(value: claim_schema::Model) -> Self {
        Self {
            required: value.required,
            schema: value.into(),
        }
    }
}

impl TryFrom<UnexportableCredentialModel> for Credential {
    type Error = DataLayerError;

    fn try_from(value: UnexportableCredentialModel) -> Result<Self, Self::Error> {
        let claims_with_schema: Vec<ClaimWithSchema> =
            serde_json::from_str(&value.claims).map_err(|_| Self::Error::MappingError)?;

        let (claims, claim_schemas) = claims_with_schema
            .into_iter()
            .map(|item| (item.claim.into(), item.claim_schema.into()))
            .unzip();

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            issuance_date: value.issuance_date,
            last_modified: value.last_modified,
            deleted_at: value.deleted_at,
            protocol: value.protocol,
            redirect_uri: value.redirect_uri,
            role: value.role.into(),
            state: value.state.into(),
            suspend_end_date: value.suspend_end_date,
            profile: value.profile,
            claims: Some(claims),
            issuer_identifier: None,
            issuer_certificate: None,
            holder_identifier: None,
            schema: Some(CredentialSchema {
                id: value.credential_schema_id,
                deleted_at: value.credential_schema_deleted_at,
                created_date: value.credential_schema_created_date,
                last_modified: value.credential_schema_last_modified,
                imported_source_url: value.credential_schema_imported_source_url,
                name: value.credential_schema_name,
                format: value.credential_schema_format,
                key_storage_security: convert_inner(value.credential_schema_key_storage_security),
                revocation_method: value.credential_schema_revocation_method,
                claim_schemas: Some(claim_schemas),
                organisation: Some(Organisation {
                    id: value.organisation_id,
                    name: value.organisation_name,
                    created_date: value.organisation_created_date,
                    last_modified: value.organisation_last_modified,
                    deactivated_at: value.organisation_deactivated_at,
                    wallet_provider: value.organisation_wallet_provider,
                    wallet_provider_issuer: value.organisation_wallet_provider_issuer,
                }),
                // todo: this should be fixed in another ticket
                layout_type: LayoutType::Card,
                layout_properties: None,
                schema_id: "CredentialSchemaId".to_owned(),
                allow_suspension: value.credential_schema_allow_suspension,
                requires_app_attestation: value.credential_schema_requires_app_attestation,
            }),
            interaction: None,
            key: None,
            credential_blob_id: None,
            wallet_unit_attestation_blob_id: None,
            wallet_app_attestation_blob_id: None,
        })
    }
}
