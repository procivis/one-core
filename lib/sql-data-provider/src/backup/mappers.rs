use std::sync::Arc;

use one_core::model::backup::UnexportableCredential;
use one_core::model::claim::Claim;
use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential::CredentialCommon;
use one_core::model::credential_schema::{CredentialSchema, TransactionCode, WalletAttestation};
use one_core::model::relation::{BatchModelLoader, Related};
use one_core::repository::error::DataLayerError;
use one_core::repository::organisation_repository::OrganisationRepository;
use one_dto_mapper::convert_inner;
use time::Duration;

use super::models::{ClaimWithSchema, UnexportableCredentialModel};
use crate::claim::mapper::claim_from_model;
use crate::claim_schema::mapper::claim_schema_from_model;
use crate::credential::mapper::CredentialSchemaFormatLoader;
use crate::credential_schema::mapper::credential_schema_formats;
use crate::localized_text::localized_texts;
use crate::transaction_context::TransactionManagerImpl;

fn claim_with_schema_to_claim(value: ClaimWithSchema, db: TransactionManagerImpl) -> Claim {
    let schema = Related::from(claim_schema_from_model(value.claim_schema, db));
    claim_from_model(value.claim, schema)
}

pub(super) fn credential_from_unexportable_model(
    value: UnexportableCredentialModel,
    organisation_repository: &Arc<dyn OrganisationRepository>,
    db: &TransactionManagerImpl,
) -> Result<UnexportableCredential, DataLayerError> {
    if value.role == crate::entity::credential::CredentialRole::Verifier {
        return Err(DataLayerError::MappingError);
    }
    let claims_with_schema: Vec<ClaimWithSchema> =
        serde_json::from_str(&value.claims).map_err(|_| DataLayerError::MappingError)?;

    let (claims, claim_schemas): (Vec<_>, Vec<ClaimSchema>) = claims_with_schema
        .into_iter()
        .map(|item| {
            let claim_schema = claim_schema_from_model(item.claim_schema.clone(), db.clone());
            let claim = claim_with_schema_to_claim(item, db.clone());
            (claim, claim_schema)
        })
        .unzip();

    let transaction_code = match (
        value.credential_schema_transaction_code_type,
        value.credential_schema_transaction_code_length,
    ) {
        (Some(r#type), Some(length)) => Some(TransactionCode {
            r#type: r#type.into(),
            length: length as _,
            description: value.credential_schema_transaction_code_description,
        }),
        (None, None) => None,
        _ => return Err(DataLayerError::MappingError),
    };

    let formats = credential_schema_formats(value.credential_schema_id, db.clone());

    Ok(UnexportableCredential {
        common: CredentialCommon {
            ecosystem: None,
            id: value.id,
            created_date: value.created_date,
            issuance_date: value.issuance_date,
            expires_at: value.expires_at,
            last_modified: value.last_modified,
            deleted_at: value.deleted_at,
            protocol: value.protocol,
            redirect_uri: value.redirect_uri,
            state: value.state.into(),
            profile: value.profile,
            schema: CredentialSchema {
                ecosystem: None,
                id: value.credential_schema_id,
                deleted_at: value.credential_schema_deleted_at,
                created_date: value.credential_schema_created_date,
                last_modified: value.credential_schema_last_modified,
                imported_source_url: value.credential_schema_imported_source_url,
                name: value.credential_schema_name,
                formats,
                wallet_attestation: WalletAttestation {
                    require_instance_attestation: value
                        .credential_schema_requires_wallet_instance_attestation,
                    key_storage_security_level: convert_inner(
                        value.credential_schema_key_storage_security,
                    ),
                    preferred_key_storage_attestation_lifetime: value
                        .credential_schema_preferred_key_storage_attestation_lifetime
                        .map(|seconds| Duration::seconds(seconds as i64)),
                    preferred_instance_attestation_lifetime: value
                        .credential_schema_preferred_instance_attestation_lifetime
                        .map(|seconds| Duration::seconds(seconds as i64)),
                },
                claim_schemas: claim_schemas.into(),
                organisation: Related::new(
                    value.organisation_id,
                    organisation_repository.to_owned(),
                ),
                layout_properties: None,
                allow_suspension: value.credential_schema_allow_suspension,
                transaction_code,
                batch_size: value.credential_schema_batch_size,
                allow_revocation: value.credential_schema_allow_revocation,
                translations: localized_texts(value.credential_schema_id.into(), db.to_owned()),
                embedded_disclosure_policy: value.credential_schema_embedded_disclosure_policy,
                expiration: value
                    .credential_schema_expiration
                    .map(|seconds| Duration::seconds(seconds as i64)),
            }
            .into(),
            interaction: None,
        },
        consumed_at: value.consumed_at,
        role: value.role.into(),
        r#type: value.r#type.into(),
        suspend_end_date: value.suspend_end_date,
        webhook_url: value.webhook_url,
        subscriber_information: value.subscriber_information,
        format: value.format.map(|id| {
            let loader = CredentialSchemaFormatLoader { db: db.clone() };
            Related::new(id, BatchModelLoader::new([id], loader))
        }),
        claims,
        parent_id: value.parent_id,
    })
}
