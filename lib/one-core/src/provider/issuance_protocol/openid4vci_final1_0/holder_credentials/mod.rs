use standardized_types::openid4vci::{CredentialMetadata, KeyStorageSecurityLevel};
#[cfg(test)]
mod test;

use std::collections::HashMap;

use itertools::Itertools;
use one_dto_mapper::convert_inner;
use shared_types::{
    ClaimSchemaId, CredentialFormat, CredentialId, OrganisationId, SerializedCredential,
};
use uuid::Uuid;

use super::mapper::{convert_metadata_to_layout_properties, remap_claim_credential_ids};
use super::validator::validate_batch_consistency;
use super::{HolderInteractionData, OpenID4VCIFinal1_0, SubmitIssuerResponse};
use crate::clock::now_utc;
use crate::config::core_config::{BlobStorageType, CoreConfig};
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin};
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::mapper::credential_schema_claim::add_fallback_translation;
use crate::mapper::oidc::map_from_oidc_format_to_core_detailed;
use crate::model::blob::{Blob, BlobType, UpdateBlobRequest};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialStateEnum, CredentialType};
use crate::model::credential_schema::{CredentialSchema, UpdateCredentialSchemaRequest};
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::model::identifier::{Identifier, IdentifierData};
use crate::model::interaction::Interaction;
use crate::model::localized_text::{LocalizedText, LocalizedTextEntityType, LocalizedTextField};
use crate::model::organisation::Organisation;
use crate::model::relation::Related;
use crate::proto::credential_schema::importer::CredentialSchemaImporter;
use crate::proto::identifier_creator::{IdentifierName, IdentifierRole, RemoteIdentifierRelation};
use crate::proto::session_provider::SessionExt;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::model::{CertificateDetails, IdentifierDetails};
use crate::provider::issuance_protocol::model::CredentialWithBlob;
use crate::provider::issuance_protocol::{
    HolderBindingInput, IssuanceAcceptResponse, IssuanceProtocolError,
};
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::validator::validate_issuance_time;

impl OpenID4VCIFinal1_0 {
    pub(super) async fn holder_process_accepted_credentials(
        &self,
        issuer_response: SubmitIssuerResponse,
        interaction_data: &HolderInteractionData,
        mut holder_bindings: Vec<HolderBindingInput>,
        organisation: &Organisation,
        interaction: &Interaction,
    ) -> Result<IssuanceAcceptResponse, IssuanceProtocolError> {
        let format_type = map_from_oidc_format_to_core_detailed(
            &interaction_data.format,
            issuer_response
                .credentials
                .first()
                .map(|c| c.as_ref().to_string())
                .as_ref(),
        )?;

        let (format, formatter) = self
            .formatter_provider
            .get_formatter_by_type(format_type)
            .ok_or_else(|| {
                IssuanceProtocolError::Failed(format!("{format_type} formatter not found"))
            })?;

        let mut credentials = vec![];
        for issued_credential in issuer_response.credentials {
            let credential = self
                .prepare_issued_credential(
                    &issued_credential,
                    &mut holder_bindings,
                    organisation,
                    interaction,
                    formatter.as_ref(),
                    issuer_response.redirect_uri.as_ref(),
                )
                .await?;
            credentials.push(CredentialWithBlob {
                credential,
                serialized: Some(issued_credential),
            });
        }

        validate_batch_consistency(&credentials).await?;

        let mut main_credential = if credentials.len() > 1 {
            let batch_item = credentials.first().ok_or(IssuanceProtocolError::Failed(
                "No credentials received".to_string(),
            ))?;
            let expires_at = if interaction_data.refresh_token.is_some() {
                None
            } else {
                batch_item.credential.expires_at
            };
            let mut credential = Credential {
                id: Uuid::new_v4().into(),
                r#type: CredentialType::BatchParent,
                credential_blob_id: None,
                wallet_instance_attestation_blob_id: None,
                wallet_unit_attestation_blob_id: None,
                issuer_identifier: None,
                issuer_certificate: None,
                holder_identifier: None,
                key: None,
                // materialized on purpose: cloning the relation would alias the batch item's claims
                claims: batch_item
                    .credential
                    .claims
                    .as_ref()
                    .await?
                    .to_owned()
                    .into(),
                expires_at,
                ..batch_item.credential.clone()
            };
            remap_claim_credential_ids(&mut credential).await?;

            CredentialWithBlob {
                credential,
                serialized: None,
            }
        } else {
            credentials.pop().ok_or(IssuanceProtocolError::Failed(
                "No credentials received".to_string(),
            ))?
        };

        if let Some(disclosure_policy) = &interaction_data.disclosure_policy {
            main_credential.credential.embedded_disclosure_policy =
                Some(serde_json::to_string(disclosure_policy)?);
        }

        let main_credential_id = main_credential.credential.id;

        let schema = self
            .process_schema(
                &mut main_credential.credential,
                organisation,
                interaction_data,
                &format,
            )
            .await?;
        if !credentials.is_empty() {
            // update batch items
            for c in credentials.iter_mut() {
                self.change_to_batch_item(&mut c.credential, main_credential_id, &schema, &format)
                    .await?;
            }
        }

        // Add main credential to the front so that the batch_parent already exists when the batch_items are created.
        Ok(IssuanceAcceptResponse {
            main_credential,
            batch_items: credentials,
        })
    }

    async fn change_to_batch_item(
        &self,
        credential: &mut Credential,
        parent_id: CredentialId,
        schema: &CredentialSchema,
        format: &CredentialFormat,
    ) -> Result<(), IssuanceProtocolError> {
        credential.schema = schema.clone().into();
        credential.r#type = CredentialType::BatchItem;
        credential.parent = Some(Related::new(parent_id, self.credential_repository.clone()));
        credential.claims = Default::default();
        credential.interaction = None;

        let formats = schema.formats.as_ref().await?;
        let format = formats.iter().find(|f| &f.format == format).cloned();
        credential.format = convert_inner(format);

        Ok(())
    }

    async fn process_schema(
        &self,
        credential: &mut Credential,
        organisation: &Organisation,
        interaction_data: &HolderInteractionData,
        format: &CredentialFormat,
    ) -> Result<CredentialSchema, IssuanceProtocolError> {
        let (mut schema, conflicting_format) = self
            .prepare_credential_schema(interaction_data, credential, organisation)
            .await?;

        // Adjust format if it was replaced by a different one of the same type.
        if let Some(conflicting_format) = &conflicting_format {
            let mut credential_schema = credential.schema.as_mut().await?;
            let mut formats = credential_schema.formats.as_mut().await?;
            let format = formats.first_mut().ok_or(IssuanceProtocolError::Failed(
                "missing parsed format".to_string(),
            ))?;
            format.format = conflicting_format.clone();
        }

        let (new_claim_schemas, new_mappings) = validate_existing_and_find_new_claim_schemas(
            &mut schema,
            credential,
            conflicting_format.as_ref().unwrap_or(format),
            &self.config.global_settings.default_language,
            true,
        )
        .await?;

        if !new_claim_schemas.is_empty() {
            self.credential_schema_repository
                .update_credential_schema(
                    &schema.id,
                    UpdateCredentialSchemaRequest {
                        claim_schemas: Some(new_claim_schemas),
                        claim_mappings: Some(new_mappings),
                        ..Default::default()
                    },
                )
                .await
                .error_while("updating credential schema")?;
        }
        Ok(schema)
    }

    pub(super) async fn holder_process_refresh(
        &self,
        interaction_data: &HolderInteractionData,
        holder_bindings: Vec<HolderBindingInput>,
        response: SubmitIssuerResponse,
        organisation: &Organisation,
        updated_credential: Option<Credential>,
        interaction: &Interaction,
    ) -> Result<Vec<Credential>, IssuanceProtocolError> {
        if let Some(credential) = updated_credential {
            self.process_mso_refresh(&credential, response).await?;

            Ok(vec![credential])
        } else {
            self.process_batch_refresh(
                response,
                interaction_data,
                holder_bindings,
                organisation,
                interaction,
            )
            .await
        }
    }

    async fn process_mso_refresh(
        &self,
        credential: &Credential,
        mut response: SubmitIssuerResponse,
    ) -> Result<(), IssuanceProtocolError> {
        if response.credentials.len() != 1 {
            return Err(IssuanceProtocolError::Failed(
                "Refresh with multiple credentials".to_string(),
            ));
        }
        let updated_credential =
            response
                .credentials
                .pop()
                .ok_or(IssuanceProtocolError::Failed(
                    "Missing issued credential".to_string(),
                ))?;

        let schema = credential.schema.as_ref().await?;
        let credential_schema_format = schema.format().await?;
        let formatter = self
            .formatter_provider
            .get_credential_formatter(&credential_schema_format)?;

        formatter
            .extract_credentials(&updated_credential, Some(&schema), self.verification_fn())
            .await
            .error_while("extracting credential")?;

        let db_blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;

        let blob_id = credential
            .credential_blob_id
            .ok_or(IssuanceProtocolError::Failed(
                "Missing credential blob id".to_string(),
            ))?;
        db_blob_storage
            .update(
                &blob_id,
                UpdateBlobRequest {
                    value: Some(updated_credential.as_ref().into()),
                },
            )
            .await
            .error_while("updating credential blob")?;
        Ok(())
    }

    async fn process_batch_refresh(
        &self,
        issuer_response: SubmitIssuerResponse,
        interaction_data: &HolderInteractionData,
        mut holder_bindings: Vec<HolderBindingInput>,
        organisation: &Organisation,
        interaction: &Interaction,
    ) -> Result<Vec<Credential>, IssuanceProtocolError> {
        let batch_parent = self
            .credential_repository
            .get_credentials_by_interaction_id(&interaction.id)
            .await
            .error_while("getting credentials")?
            .into_iter()
            .next()
            .ok_or(IssuanceProtocolError::Failed(
                "No credentials found".to_string(),
            ))?;
        if batch_parent.r#type != CredentialType::BatchParent {
            return Err(IssuanceProtocolError::RefreshNotSupported(
                batch_parent.r#type,
            ));
        }
        let mut schema = batch_parent.schema.as_ref().await?.to_owned();

        let format_type = map_from_oidc_format_to_core_detailed(
            &interaction_data.format,
            issuer_response
                .credentials
                .first()
                .map(|c| c.as_ref().to_string())
                .as_ref(),
        )?;

        // TODO: the _exact_ format of the batch parent should be known. Address when properly implementing
        // multi-format issuance.
        let parent_formats = schema.formats.as_ref().await?;
        let parent_format = parent_formats
            .iter()
            .find(|f| {
                self.config
                    .format
                    .get_type(&f.format)
                    .ok()
                    .is_some_and(|f| f == format_type)
            })
            .ok_or_else(|| {
                IssuanceProtocolError::Failed(format!(
                    "batch parent schema {} does not have a format of type `{format_type}`",
                    schema.id
                ))
            })?
            .to_owned();
        drop(parent_formats);
        let formatter = self
            .formatter_provider
            .get_credential_formatter(&parent_format.format)?;

        let mut batch_credentials = Vec::with_capacity(issuer_response.credentials.len());
        for issued_credential in issuer_response.credentials {
            let mut credential = self
                .prepare_issued_credential(
                    &issued_credential,
                    &mut holder_bindings,
                    organisation,
                    interaction,
                    formatter.as_ref(),
                    issuer_response.redirect_uri.as_ref(),
                )
                .await?;
            credential.format = Some(parent_format.clone().into());
            batch_credentials.push(CredentialWithBlob {
                credential,
                serialized: Some(issued_credential),
            });
        }
        validate_batch_consistency(&batch_credentials).await?;

        // as the batch is validated to be consistent, any credential in the batch is suitable for this validation
        let batch_credential = batch_credentials
            .iter_mut()
            .next()
            .ok_or(IssuanceProtocolError::Failed("empty batch".to_string()))?;
        validate_existing_and_find_new_claim_schemas(
            &mut schema,
            &mut batch_credential.credential,
            &parent_format.format,
            &self.config.global_settings.default_language,
            false,
        )
        .await?;

        self.history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: now_utc(),
                action: HistoryAction::Refreshed,
                name: schema.name.to_owned(),
                source: HistorySource::Core,
                entity_id: Some(batch_parent.id.into()),
                entity_type: HistoryEntityType::Credential,
                organisation_id: Some(organisation.id),
                user: self.session_provider.session().user(),
                target: None,
                metadata: None,
                metadata_blob_id: None,
            })
            .await
            .error_while("storing history")?;

        let mut result = vec![];
        let db_blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;
        for batch_credential in batch_credentials {
            let CredentialWithBlob {
                mut credential,
                serialized,
            } = batch_credential;
            self.change_to_batch_item(
                &mut credential,
                batch_parent.id,
                &schema,
                &parent_format.format,
            )
            .await?;

            let credential_blob_id = if let Some(token) = serialized {
                let blob = Blob::new(token.as_ref(), BlobType::Credential);
                let blob_id = blob.id;
                db_blob_storage
                    .create(blob)
                    .await
                    .error_while("creating credential blob")?;
                Some(blob_id)
            } else {
                None
            };

            let new_credential = Credential {
                state: CredentialStateEnum::Accepted,
                credential_blob_id,
                ..credential
            };
            self.credential_repository
                .create_credential(new_credential.clone())
                .await
                .error_while("creating credential")?;
            result.push(new_credential)
        }

        Ok(result)
    }

    async fn prepare_issued_credential(
        &self,
        issued_credential: &SerializedCredential,
        holder_bindings: &mut Vec<HolderBindingInput>,
        organisation: &Organisation,
        interaction: &Interaction,
        formatter: &dyn CredentialFormatter,
        redirect_uri: Option<&String>,
    ) -> Result<Credential, IssuanceProtocolError> {
        let mut credential = formatter
            .parse_credential(
                issued_credential,
                organisation.to_owned(),
                self.verification_fn(),
            )
            .await
            .map_err(|e| IssuanceProtocolError::CredentialVerificationFailed(e.into()))?;

        validate_issuance_time(&credential.issuance_date, formatter.get_leeway())
            .error_while("validating issuance time")?;

        let issuer_identifier = match credential.issuer_identifier.as_ref() {
            None => None,
            Some(identifier) => Some(identifier.as_ref().await?.to_owned()),
        };
        let identifier_details = match issuer_identifier
            .as_ref()
            .map(|identifier| &identifier.data)
        {
            Some(IdentifierData::Did(did)) => {
                IdentifierDetails::Did(did.as_ref().await?.did.to_owned())
            }
            Some(IdentifierData::Certificate(certificates)) => {
                let certificate = certificates
                    .as_ref()
                    .await?
                    .first()
                    .ok_or(IssuanceProtocolError::Failed(
                        "Missing certificate".to_string(),
                    ))?
                    .to_owned();
                IdentifierDetails::Certificate(CertificateDetails {
                    chain: certificate.chain,
                    fingerprint: certificate.fingerprint,
                    expiry: certificate.expiry_date,
                    subject_common_name: None,
                    x5_references: Default::default(),
                })
            }
            Some(IdentifierData::Key(key)) => {
                let key = key.as_ref().await?;
                let key_handle = self
                    .key_algorithm_provider
                    .reconstruct_key(
                        key.key_algorithm_type()
                            .error_while("getting key algorithm tye")?,
                        &key.public_key,
                        None,
                        None,
                    )
                    .error_while("reconstructing key")?;
                IdentifierDetails::Key(key_handle.public_key_as_jwk().error_while("getting JWK")?)
            }
            _ => {
                return Err(IssuanceProtocolError::Failed(
                    "Invalid parsed issuer identifier".to_string(),
                ));
            }
        };

        let (issuer_identifier, issuer_identifier_relation) = self
            .identifier_creator
            .get_or_create_remote_identifier(
                organisation,
                &identifier_details,
                IdentifierName::PrefixForId(IdentifierRole::Issuer.to_string()),
                true,
            )
            .await
            .error_while("creating issuer identifier")?;
        let issuer_certificate = if let RemoteIdentifierRelation::Certificate(certificate) =
            issuer_identifier_relation
        {
            Some(certificate)
        } else {
            None
        };

        credential.issuer_identifier = Some(issuer_identifier.into());
        credential.issuer_certificate = issuer_certificate.map(Into::into);
        credential.redirect_uri = redirect_uri.cloned();
        credential.state = CredentialStateEnum::Accepted;
        credential.protocol = self.config_id.to_owned();
        credential.interaction = Some(interaction.to_owned().into());
        attach_matching_holder_binding(&mut credential, holder_bindings).await?;
        Ok(credential)
    }

    async fn prepare_credential_schema(
        &self,
        interaction_data: &HolderInteractionData,
        parsed_credential: &Credential,
        organisation: &Organisation,
    ) -> Result<(CredentialSchema, Option<CredentialFormat>), IssuanceProtocolError> {
        let mut schema = parsed_credential.schema.as_ref().await?.to_owned();

        apply_issuer_metadata_to_schema(
            &mut schema,
            interaction_data.credential_metadata.as_ref(),
            &self.config.global_settings.default_language,
        )
        .await?;
        schema.batch_size = interaction_data.batch_size.map(|size| size as _);
        schema.organisation = organisation.to_owned().into();
        schema.key_storage_security = interaction_data
            .proof_types_supported
            .as_ref()
            .and_then(|map| map.get("jwt"))
            .and_then(|jwt| jwt.key_attestations_required.as_ref())
            .and_then(|att_list| {
                (!att_list.key_storage.is_empty()).then_some(&att_list.key_storage)
            })
            .and_then(|levels| convert_inner(KeyStorageSecurityLevel::select_lowest(levels)));

        let result = get_or_create_credential_schema(
            self.credential_schema_importer.as_ref(),
            self.credential_schema_repository.as_ref(),
            schema,
            organisation.id,
            &self.config,
        )
        .await?;

        Ok(result)
    }
}
async fn get_or_create_credential_schema(
    credential_schema_importer: &dyn CredentialSchemaImporter,
    credential_schema_repository: &dyn CredentialSchemaRepository,
    credential_schema: CredentialSchema,
    organisation_id: OrganisationId,
    config: &CoreConfig,
) -> Result<(CredentialSchema, Option<CredentialFormat>), IssuanceProtocolError> {
    let parsed_schema_id = credential_schema
        .schema_id()
        .await
        .error_while("getting parsed schema_id")?;
    let parsed_format = credential_schema
        .format()
        .await
        .error_while("getting parsed format")?;
    let stored_schema = credential_schema_repository
        .get_by_schema_id_and_organisation(&parsed_schema_id, organisation_id)
        .await
        .error_while("getting credential schema")?;

    if let Some(stored_schema) = stored_schema {
        let conflicting_format = if let Some(conflicting_schema) =
            stored_schema.formats.as_ref().await?.iter().find(|format| {
                format.ecosystem_schema_id == parsed_schema_id && format.format != parsed_format
            }) {
            if config
                .format
                .get_type(&conflicting_schema.format)
                .error_while("getting format type")?
                == config
                    .format
                    .get_type(&parsed_format)
                    .error_while("getting format type")?
            {
                tracing::debug!(
                    "Found matching existing schema {} with different format `{}` of same type, replacing format `{}`.",
                    conflicting_schema.id,
                    conflicting_schema.format,
                    parsed_format
                );
                Some(conflicting_schema.format.clone())
            } else {
                return Err(IssuanceProtocolError::Failed(format!(
                    "Credential schema conflict: credential schema with id {} has matching schema_id {} but different format {}",
                    conflicting_schema.id,
                    conflicting_schema.ecosystem_schema_id,
                    conflicting_schema.format
                )));
            }
        } else {
            None
        };
        Ok((stored_schema, conflicting_format))
    } else {
        match credential_schema_importer
            .import_credential_schema(credential_schema)
            .await
        {
            Ok(schema) => {
                return Ok((schema, None));
            }
            Err(error) if error.error_code() == ErrorCode::BR_0007 => {
                tracing::debug!("Conflicting schema detected during parsing, refetching");
            }
            Err(e) => {
                return Err(IssuanceProtocolError::Failed(e.to_string()));
            }
        };

        // refetch and try again
        let stored_schema = credential_schema_repository
            .get_by_schema_id_and_organisation(&parsed_schema_id, organisation_id)
            .await
            .error_while("getting credential schema")?
            .ok_or(IssuanceProtocolError::Failed(
                "Credential schema not found".to_string(),
            ))?;

        Ok((stored_schema, None))
    }
}

async fn validate_existing_and_find_new_claim_schemas(
    stored_schema: &mut CredentialSchema,
    credential: &mut Credential,
    format: &CredentialFormat,
    default_language: &str,
    allow_new_claim_schemas: bool,
) -> Result<(Vec<ClaimSchema>, Vec<CredentialSchemaFormatClaimSchema>), IssuanceProtocolError> {
    let mut new_claim_schemas = vec![];
    let mut new_mappings = vec![];
    let mut claims = credential.claims.as_mut().await?;
    claims.sort_by_key(|c| c.path.clone());

    let parsed_schema = credential.schema.as_ref().await?;
    let mut parsed_claim_schemas = parsed_schema.claim_schemas.as_ref().await?.to_owned();
    parsed_claim_schemas.sort_by_key(|s| s.key.clone());

    let parsed_formats = parsed_schema.formats.as_ref().await?.to_owned();
    let parsed_format = parsed_formats.iter().find(|f| f.format == *format).ok_or(
        IssuanceProtocolError::Failed(format!("No matching parsed format found for `{format}`")),
    )?;
    let parsed_mappings = parsed_format.claim_mappings.as_ref().await?.to_owned();
    drop(parsed_schema);

    let mut stored_formats = stored_schema.formats.as_mut().await?;
    let stored_format = stored_formats
        .iter_mut()
        .find(|f| f.format == *format)
        .ok_or(IssuanceProtocolError::Failed(format!(
            "No matching stored format found for `{format}`"
        )))?;
    let mut stored_mappings = stored_format.claim_mappings.as_mut().await?;

    let mut stored_claim_schemas = stored_schema.claim_schemas.as_mut().await?;
    // parsed key -> stored key
    let mut key_translations = HashMap::new();
    // parsed path -> stored path
    let mut claim_path_translations = HashMap::new();

    // iterate sorted by key -> parent schemas before their children
    for mut parsed_claim_schema in parsed_claim_schemas {
        let parsed_mapping = parsed_mappings
            .iter()
            .find(|m| m.claim_schema_id == parsed_claim_schema.id)
            .ok_or(IssuanceProtocolError::Failed(format!(
                "missing mapping for claim schema `{}`",
                parsed_claim_schema.key
            )))?;
        let stored_claim_schema_id = find_matching_stored_schema(parsed_mapping, &stored_mappings);

        if let Some(stored_claim_schema_id) = stored_claim_schema_id {
            let known_claim_schema = stored_claim_schemas
                .iter()
                .find(|schema| schema.id == stored_claim_schema_id)
                .ok_or(IssuanceProtocolError::Failed(format!(
                    "stored claim schema {} not found",
                    stored_claim_schema_id
                )))?;
            key_translations.insert(
                parsed_claim_schema.key.clone(),
                known_claim_schema.key.clone(),
            );
            relink_claims(
                &mut claims,
                parsed_claim_schema.id,
                known_claim_schema,
                &mut claim_path_translations,
            )
            .await?;
        } else {
            if let Some((parent_key, new_child_key)) =
                parsed_claim_schema.key.rsplit_once(NESTED_CLAIM_MARKER)
            {
                // Due to ordering, parent key must have been processed already.
                let parent_key =
                    key_translations
                        .get(parent_key)
                        .ok_or(IssuanceProtocolError::Failed(format!(
                            "failed to find key translation for parent claim schema for key `{}`",
                            parent_key
                        )))?;
                let mapped_child_key = format!("{parent_key}{NESTED_CLAIM_MARKER}{new_child_key}");
                key_translations.insert(
                    parsed_claim_schema.key.to_owned(),
                    mapped_child_key.to_owned(),
                );
                parsed_claim_schema.key = mapped_child_key;
                // relink to the same schema with changed path
                relink_claims(
                    &mut claims,
                    parsed_claim_schema.id,
                    &parsed_claim_schema,
                    &mut claim_path_translations,
                )
                .await?;
            } else {
                // This is a new root claim, no parent path translations / relinking. Store the key
                // translation for potential child claims of this new root claim.
                key_translations.insert(
                    parsed_claim_schema.key.clone(),
                    parsed_claim_schema.key.clone(),
                );
            }
            let mut new_mapping = parsed_mapping.clone();
            new_mapping.credential_schema_format_id = stored_format.id;
            stored_mappings.push(new_mapping.clone());
            new_mappings.push(new_mapping);
            new_claim_schemas.push(
                add_fallback_translation(parsed_claim_schema, default_language)
                    .await
                    .error_while("adding fallback claim translation")?,
            );
        }
    }

    if !allow_new_claim_schemas && !new_claim_schemas.is_empty() {
        return Err(IssuanceProtocolError::Failed(format!(
            "Unknown claims found: {}",
            new_claim_schemas
                .into_iter()
                .map(|claim_schema| claim_schema.key)
                .join(", ")
        )));
    }
    stored_claim_schemas.extend(new_claim_schemas.clone());

    drop(stored_claim_schemas);
    drop(stored_mappings);
    credential.format = Some(stored_format.to_owned().into());
    drop(stored_formats);
    credential.schema = stored_schema.to_owned().into();
    Ok((new_claim_schemas, new_mappings))
}

/// Link all claims currently linked to `claim_schema_id` to `new_claim_schema`, while rewriting
/// the path to match the new key.
async fn relink_claims(
    claims: &mut [Claim],
    claim_schema_id: ClaimSchemaId,
    new_claim_schema: &ClaimSchema,
    claim_path_translations: &mut HashMap<String, String>,
) -> Result<(), IssuanceProtocolError> {
    for claim in claims
        .iter_mut()
        .filter(|claim| claim.schema.id() == claim_schema_id)
    {
        let (data_type, key) = {
            let cs = claim.schema.as_ref().await?;
            (cs.data_type.to_owned(), cs.key.to_owned())
        };
        if data_type != new_claim_schema.data_type {
            // This is just a warning because the data type detection is just a heuristic
            tracing::warn!(
                "detected data type mismatch on claim `{}`: expected `{}` but parsed `{}`",
                claim.path,
                new_claim_schema.data_type,
                data_type
            );
        }
        let mapped_path = remap_claim_path(
            claim.path.as_str(),
            claim_path_translations,
            &key,
            new_claim_schema,
        )?;
        claim.path = mapped_path;
        claim.schema = new_claim_schema.to_owned().into();
    }
    Ok(())
}

fn find_matching_stored_schema(
    parsed_mapping: &CredentialSchemaFormatClaimSchema,
    stored_mappings: &[CredentialSchemaFormatClaimSchema],
) -> Option<ClaimSchemaId> {
    stored_mappings
        .iter()
        .find(|m| {
            m.technical_key == parsed_mapping.technical_key
                && m.namespace == parsed_mapping.namespace
        })
        .map(|m| m.claim_schema_id)
}

fn remap_claim_path(
    claim_path: &str,
    claim_path_translations: &mut HashMap<String, String>,
    parsed_schema_key: &str,
    stored_claim_schema: &ClaimSchema,
) -> Result<String, IssuanceProtocolError> {
    if claim_path == parsed_schema_key {
        // adjust path to match schema
        claim_path_translations.insert(
            parsed_schema_key.to_string(),
            stored_claim_schema.key.clone(),
        );
        return Ok(stored_claim_schema.key.clone());
    } else if let Some((parent_claim, child)) = claim_path.rsplit_once(NESTED_CLAIM_MARKER) {
        let parent_key = claim_path_translations.get(parent_claim).ok_or(IssuanceProtocolError::Failed(format!(
            "claim path `{parent_claim}` not found in translated claim paths for parsed claim with path `{claim_path}`" )))?;
        let new_path = if parsed_schema_key.ends_with(&format!("{NESTED_CLAIM_MARKER}{child}")) {
            // normal nesting
            let (_, cs_leaf) = stored_claim_schema
                .key
                .rsplit_once(NESTED_CLAIM_MARKER)
                .ok_or(IssuanceProtocolError::Failed(format!(
                    "expected claim schema path `{}` to contain nesting",
                    stored_claim_schema.key
                )))?;
            format!("{parent_key}{NESTED_CLAIM_MARKER}{cs_leaf}")
        } else {
            // `child` is an array index, which is not represented in the technical key.
            // Preserve the index, just map to the parent key.
            format!("{parent_key}{NESTED_CLAIM_MARKER}{child}")
        };
        claim_path_translations.insert(claim_path.to_string(), new_path.clone());
        return Ok(new_path);
    }
    Err(IssuanceProtocolError::Failed(format!(
        "Failed to map claim path `{claim_path}` to claim schema {} with parsed schema key `{parsed_schema_key}`",
        stored_claim_schema.id
    )))
}

async fn apply_issuer_metadata_to_schema(
    schema: &mut CredentialSchema,
    metadata: Option<&CredentialMetadata>,
    default_language: &str,
) -> Result<(), IssuanceProtocolError> {
    let now = now_utc();
    let all_displays = metadata.and_then(|m| m.display.as_deref()).unwrap_or(&[]);

    let metadata_display = all_displays.iter().find(|display| {
        display
            .locale
            .as_deref()
            .is_none_or(|locale| locale == default_language)
    });

    if let Some(name) = metadata_display.map(|d| d.name.to_owned()) {
        schema.name = name;
    }

    let schema_translations: Vec<LocalizedText> = all_displays
        .iter()
        .flat_map(|display| {
            let lang = display
                .locale
                .as_deref()
                .unwrap_or(default_language)
                .to_owned();
            let mut entries: Vec<LocalizedText> = vec![LocalizedText {
                entity_id: schema.id.into(),
                field: LocalizedTextField::Name,
                created_date: now,
                last_modified: now,
                lang: lang.clone(),
                value: display.name.clone(),
                entity_type: LocalizedTextEntityType::CredentialSchema,
            }];
            if let Some(description) = &display.description {
                entries.push(LocalizedText {
                    entity_id: schema.id.into(),
                    field: LocalizedTextField::Description,
                    created_date: now,
                    last_modified: now,
                    lang,
                    value: description.clone(),
                    entity_type: LocalizedTextEntityType::CredentialSchema,
                });
            }
            entries
        })
        .collect();

    if !schema_translations.is_empty() {
        schema.translations = schema_translations.into();
    }

    let issuer_metadata_claims = metadata.and_then(|m| m.claims.as_deref()).unwrap_or(&[]);
    if !issuer_metadata_claims.is_empty() {
        let mut claim_schemas = schema.claim_schemas.as_mut().await?;
        let formats = schema.formats.as_ref().await?;
        let format = formats
            .first()
            .ok_or(IssuanceProtocolError::Failed(format!(
                "empty formats on credential schema {}",
                schema.id
            )))?;
        let mappings = format.claim_mappings.as_ref().await?;
        let mappings_by_schema_id: HashMap<_, _> = mappings
            .into_iter()
            .map(|m| (m.claim_schema_id, m))
            .collect();

        for claim_schema in &mut claim_schemas {
            if claim_schema.metadata {
                continue;
            }

            let metadata_key = if let Some(mapping) = mappings_by_schema_id.get(&claim_schema.id) {
                mapping.formatted_technical_key()
            } else {
                claim_schema.key.to_string()
            };

            // NOTE: OpenID4VCI allows putting array selectors into the issuer metadata claim path.
            // (I.e. giving the different indices of the array different descriptions)
            // This is explicitly not supported for now since the translation is stored on the schema,
            // which exists only once to represent the whole array.
            let Some(issuer_metadata_claim) = issuer_metadata_claims
                .iter()
                .find(|mc| mc.path.join("/") == metadata_key)
            else {
                continue;
            };

            let claim_translations: Vec<LocalizedText> = issuer_metadata_claim
                .display
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .filter_map(|display| {
                    let name = display.name.as_ref()?;
                    let lang = display
                        .locale
                        .as_deref()
                        .unwrap_or(default_language)
                        .to_owned();
                    Some(LocalizedText {
                        entity_id: claim_schema.id.into(),
                        field: LocalizedTextField::Name,
                        created_date: now,
                        last_modified: now,
                        lang,
                        value: name.clone(),
                        entity_type: LocalizedTextEntityType::ClaimSchema,
                    })
                })
                .collect();
            if !claim_translations.is_empty() {
                claim_schema.translations = claim_translations.into();
            }
        }
    }

    schema.layout_properties = metadata_display
        .and_then(|display| convert_metadata_to_layout_properties(display.to_owned()));

    Ok(())
}

async fn attach_matching_holder_binding(
    credential: &mut Credential,
    holder_bindings: &mut Vec<HolderBindingInput>,
) -> Result<(), IssuanceProtocolError> {
    let parsed_identifier =
        credential
            .holder_identifier
            .take()
            .ok_or(IssuanceProtocolError::Failed(
                "No parsed holder identifier".to_string(),
            ))?;

    let parsed_identifier = parsed_identifier.as_ref().await?;

    let mut position = None;
    for (index, holder_binding) in holder_bindings.iter().enumerate() {
        if holder_binding_matching_parsed_identifier(holder_binding, &parsed_identifier).await? {
            position = Some(index);
            break;
        }
    }
    let Some(position) = position else {
        return Err(IssuanceProtocolError::Failed(
            "No matching holder identifier".to_string(),
        ));
    };

    let matching_holder_binding = holder_bindings.swap_remove(position);
    credential.holder_identifier = Some(matching_holder_binding.identifier.into());
    credential.key = Some(matching_holder_binding.key.into());

    Ok(())
}

async fn holder_binding_matching_parsed_identifier(
    holder_binding: &HolderBindingInput,
    parsed_identifier: &Identifier,
) -> Result<bool, IssuanceProtocolError> {
    match &parsed_identifier.data {
        IdentifierData::Key(parsed_key) => {
            let parsed_key = parsed_key.as_ref().await?;

            Ok(holder_binding.key.key_type == parsed_key.key_type
                && holder_binding.key.public_key == parsed_key.public_key)
        }
        IdentifierData::Did(parsed_did) => {
            let IdentifierData::Did(holder_binding_did) = &holder_binding.identifier.data else {
                return Ok(false);
            };
            let parsed_did = parsed_did.as_ref().await?;
            let holder_binding_did = holder_binding_did.as_ref().await?;

            Ok(holder_binding_did.did == parsed_did.did)
        }
        IdentifierData::Certificate(_) | IdentifierData::CertificateAuthority(_) => {
            // No credential format uses certificates for holder binding at this point
            tracing::warn!(
                "Invalid parsed holder binding type: {}",
                parsed_identifier.data.r#type()
            );

            Ok(false)
        }
    }
}
