use standardized_types::openid4vci::{CredentialMetadata, IssuerDisplay, KeyStorageSecurityLevel};
mod schema_matching;
#[cfg(test)]
mod test;

use std::collections::HashMap;

use itertools::Itertools;
use one_dto_mapper::convert_inner;
use shared_types::{CredentialId, SerializedCredential};
use uuid::Uuid;

use self::schema_matching::{
    CredentialSchemaResolution, align_format_claim_schemas_and_mappings,
    find_or_import_credential_schema,
};
use super::mapper::convert_metadata_to_layout_properties;
use super::model::{HolderBinding, HolderCredentialConfiguration};
use super::validator::validate_batch_consistency;
use super::{HolderInteractionData, OpenID4VCIFinal1_0, SubmitIssuerResponse};
use crate::clock::now_utc;
use crate::config::core_config::BlobStorageType;
use crate::error::ContextWithErrorCode;
use crate::mapper::NESTED_CLAIM_MARKER_STR;
use crate::mapper::oidc::map_from_oidc_format_to_core_detailed;
use crate::model::blob::{Blob, BlobType, UpdateBlobRequest};
use crate::model::credential::{Credential, CredentialStateEnum, CredentialType};
use crate::model::credential_schema::{CredentialSchema, UpdateCredentialSchemaRequest};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::model::identifier::{Identifier, IdentifierData};
use crate::model::interaction::Interaction;
use crate::model::localized_text::{LocalizedText, LocalizedTextEntityType, LocalizedTextField};
use crate::model::organisation::Organisation;
use crate::model::relation::{OptionalRelatedExt, Related};
use crate::proto::identifier_creator::{
    IdentifierLogo, IdentifierName, IdentifierRole, RemoteIdentifierRelation,
    issuer_display_to_identifier_translations,
};
use crate::proto::session_provider::SessionExt;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::model::{CertificateDetails, IdentifierDetails};
use crate::provider::issuance_protocol::model::CredentialWithBlob;
use crate::provider::issuance_protocol::{IssuanceAcceptResponse, IssuanceProtocolError};
use crate::validator::validate_issuance_time;

impl OpenID4VCIFinal1_0 {
    pub(super) async fn holder_process_accepted_credentials(
        &self,
        issuer_response: SubmitIssuerResponse,
        interaction_data: &HolderInteractionData,
        configuration: &HolderCredentialConfiguration,
        mut holder_bindings: Vec<HolderBinding>,
        organisation: &Organisation,
        interaction: &Interaction,
    ) -> Result<IssuanceAcceptResponse, IssuanceProtocolError> {
        let format_type = map_from_oidc_format_to_core_detailed(
            &configuration.format,
            issuer_response
                .credentials
                .first()
                .map(|c| c.as_ref().to_string())
                .as_ref(),
        )?;

        let (_, formatter) = self
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
                    interaction_data.issuer_display.as_deref(),
                )
                .await?;
            credentials.push(CredentialWithBlob {
                credential,
                serialized: Some(issued_credential),
            });
        }

        validate_batch_consistency(&credentials).await?;

        let first = credentials
            .first_mut()
            .ok_or(IssuanceProtocolError::Failed(
                "No credentials received".to_string(),
            ))?;
        let mut schema = self
            .update_credential_schema(
                &mut first.credential,
                organisation,
                interaction_data,
                configuration,
            )
            .await?;
        for item in credentials.iter_mut().skip(1) {
            self.align_credential_schema(&mut schema, &mut item.credential, None)
                .await?;
        }

        let mut main_credential = if credentials.len() > 1 {
            let batch_item = credentials.first().ok_or(IssuanceProtocolError::Failed(
                "No credentials received".to_string(),
            ))?;
            let expires_at = if interaction_data.refresh_token.is_some() {
                None
            } else {
                batch_item.credential.expires_at
            };
            let credential = Credential {
                id: Uuid::new_v4().into(),
                r#type: CredentialType::BatchParent,
                credential_blob_id: None,
                wallet_instance_attestation_blob_id: None,
                wallet_key_attestation_blob_id: None,
                issuer_identifier: None,
                issuer_certificate: None,
                holder_identifier: None,
                key: None,
                claims: Default::default(),
                expires_at,
                ..batch_item.credential.clone()
            };

            CredentialWithBlob {
                credential,
                serialized: None,
            }
        } else {
            credentials.pop().ok_or(IssuanceProtocolError::Failed(
                "No credentials received".to_string(),
            ))?
        };

        if let Some(disclosure_policy) = &configuration.disclosure_policy {
            main_credential.credential.embedded_disclosure_policy =
                Some(serde_json::to_string(disclosure_policy)?);
        }

        let main_credential_id = main_credential.credential.id;

        for item in &mut credentials {
            self.change_to_batch_item(&mut item.credential, main_credential_id);
        }

        // Add main credential to the front so that the batch_parent already exists when the batch_items are created.
        Ok(IssuanceAcceptResponse {
            credential_configuration_id: configuration.credential_configuration_id.to_owned(),
            main_credential,
            batch_items: credentials,
        })
    }

    fn change_to_batch_item(&self, credential: &mut Credential, parent_id: CredentialId) {
        credential.r#type = CredentialType::BatchItem;
        credential.parent = Some(Related::new(parent_id, self.credential_repository.clone()));
        credential.interaction = None;
    }

    async fn update_credential_schema(
        &self,
        credential: &mut Credential,
        organisation: &Organisation,
        interaction_data: &HolderInteractionData,
        configuration: &HolderCredentialConfiguration,
    ) -> Result<CredentialSchema, IssuanceProtocolError> {
        self.enrich_credential_schema(
            credential.schema.as_mut().await?.as_mut(),
            interaction_data,
            configuration,
            organisation,
        )
        .await?;

        let parsed_schema = credential.schema.as_ref().await?.to_owned();
        let parsed_format = credential.format.as_required_ref().await?;
        let CredentialSchemaResolution {
            mut schema,
            new_format,
        } = find_or_import_credential_schema(
            self.credential_schema_importer.as_ref(),
            self.credential_schema_repository.as_ref(),
            parsed_schema,
            &parsed_format,
            credential,
            organisation.id,
            &self.config,
        )
        .await?;
        drop(parsed_format);

        self.align_credential_schema(&mut schema, credential, new_format)
            .await?;
        Ok(schema)
    }

    async fn align_credential_schema(
        &self,
        schema: &mut CredentialSchema,
        credential: &mut Credential,
        new_format: Option<CredentialSchemaFormat>,
    ) -> Result<(), IssuanceProtocolError> {
        let alignment = align_format_claim_schemas_and_mappings(
            schema,
            credential,
            &self.config.global_settings.default_language,
        )
        .await?;

        if !alignment.new_claim_schemas.is_empty() || new_format.is_some() {
            self.credential_schema_repository
                .update_credential_schema(
                    &schema.id,
                    UpdateCredentialSchemaRequest {
                        claim_schemas: (!alignment.new_claim_schemas.is_empty())
                            .then_some(alignment.new_claim_schemas),
                        // A new format owns all of its mappings and persists them together.
                        claim_mappings: new_format.is_none().then_some(alignment.new_mappings),
                        formats: new_format.map(|format| vec![format]),
                        ..Default::default()
                    },
                )
                .await
                .error_while("updating credential schema")?;
        }
        Ok(())
    }

    pub(super) async fn holder_process_refresh(
        &self,
        configuration: &HolderCredentialConfiguration,
        holder_bindings: Vec<HolderBinding>,
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
                configuration,
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
        let credential_format = credential.format.as_required_ref().await?.format.to_owned();
        let formatter = self
            .formatter_provider
            .get_credential_formatter(&credential_format)?;

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
        configuration: &HolderCredentialConfiguration,
        mut holder_bindings: Vec<HolderBinding>,
        organisation: &Organisation,
        interaction: &Interaction,
    ) -> Result<Vec<Credential>, IssuanceProtocolError> {
        let batch_parent = self
            .credential_repository
            .get_credentials_by_interaction_id(&interaction.id)
            .await
            .error_while("getting credentials")?
            .into_iter()
            .find(|credential| {
                configuration
                    .credential_id
                    .is_none_or(|credential_id| credential_id == credential.id)
            })
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
            &configuration.format,
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
            let credential = self
                .prepare_issued_credential(
                    &issued_credential,
                    &mut holder_bindings,
                    organisation,
                    interaction,
                    formatter.as_ref(),
                    issuer_response.redirect_uri.as_ref(),
                    None,
                )
                .await?;
            batch_credentials.push(CredentialWithBlob {
                credential,
                serialized: Some(issued_credential),
            });
        }
        validate_batch_consistency(&batch_credentials).await?;

        if batch_credentials.is_empty() {
            return Err(IssuanceProtocolError::Failed("empty batch".to_string()));
        }
        for item in &mut batch_credentials {
            let alignment = align_format_claim_schemas_and_mappings(
                &mut schema,
                &mut item.credential,
                &self.config.global_settings.default_language,
            )
            .await?;
            if !alignment.new_claim_schemas.is_empty() {
                return Err(IssuanceProtocolError::Failed(format!(
                    "Unknown claims found: {}",
                    alignment
                        .new_claim_schemas
                        .into_iter()
                        .map(|schema| schema.key)
                        .join(", ")
                )));
            }
        }

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
            self.change_to_batch_item(&mut credential, batch_parent.id);

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

    #[expect(clippy::too_many_arguments)]
    async fn prepare_issued_credential(
        &self,
        issued_credential: &SerializedCredential,
        holder_bindings: &mut Vec<HolderBinding>,
        organisation: &Organisation,
        interaction: &Interaction,
        formatter: &dyn CredentialFormatter,
        redirect_uri: Option<&String>,
        issuer_display: Option<&[IssuerDisplay]>,
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

        let issuer_translations = issuer_display.and_then(|display| {
            issuer_display_to_identifier_translations(
                display,
                &self.config.global_settings.default_language,
            )
        });
        let issuer_logo = issuer_display.and_then(|display| {
            display
                .iter()
                .find_map(|entry| entry.logo.as_ref().map(|logo| logo.uri.clone()))
        });

        // `display[].logo.uri` from the (untrusted for `trustedRpRequired = false`) issuer
        // metadata may be a plain URL or a base64 `data:` image stored verbatim, so cap it
        // at the operator-logo limit to stop an issuer bloating the wallet DB / API payloads.
        let issuer_logo = match issuer_logo {
            Some(logo) if logo.len() <= IdentifierLogo::max_size() => Some(logo),
            Some(_) => {
                tracing::warn!("Issuer logo exceeds the maximum allowed size, dropping it");
                None
            }
            None => None,
        };

        let (issuer_identifier, issuer_identifier_relation) = self
            .identifier_creator
            .get_or_create_remote_identifier(
                organisation,
                &identifier_details,
                IdentifierName::PrefixForId(IdentifierRole::Issuer.to_string()),
                true,
                issuer_translations,
                issuer_logo,
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

    async fn enrich_credential_schema(
        &self,
        schema: &mut CredentialSchema,
        interaction_data: &HolderInteractionData,
        configuration: &HolderCredentialConfiguration,
        organisation: &Organisation,
    ) -> Result<(), IssuanceProtocolError> {
        apply_issuer_metadata_to_schema(
            schema,
            configuration.credential_metadata.as_ref(),
            &self.config.global_settings.default_language,
        )
        .await?;
        schema.batch_size = interaction_data.batch_size.map(|size| size as _);
        schema.organisation = organisation.to_owned().into();
        schema.wallet_attestation.key_storage_security_level = configuration
            .proof_types_supported
            .as_ref()
            .and_then(|map| map.get("jwt"))
            .and_then(|jwt| jwt.key_attestations_required.as_ref())
            .and_then(|att_list| {
                (!att_list.key_storage.is_empty()).then_some(&att_list.key_storage)
            })
            .and_then(|levels| convert_inner(KeyStorageSecurityLevel::select_lowest(levels)));
        Ok(())
    }
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
        let mandatory_claim_paths = issuer_metadata_claims
            .iter()
            .filter(|claim| claim.mandatory == Some(true))
            .map(|claim| claim.path.join(NESTED_CLAIM_MARKER_STR))
            .unique()
            .collect_vec();
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
        let mut parsed_claim_paths = Vec::with_capacity(claim_schemas.len());

        for claim_schema in &mut claim_schemas {
            if claim_schema.metadata {
                continue;
            }

            let metadata_key = if let Some(mapping) = mappings_by_schema_id.get(&claim_schema.id) {
                mapping.formatted_technical_key()
            } else {
                claim_schema.key.to_string()
            };
            parsed_claim_paths.push(metadata_key.clone());

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

            if mandatory_claim_paths.contains(&metadata_key) {
                claim_schema.required = true;
            }

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

        let missing_mandatory_claims = mandatory_claim_paths
            .iter()
            .filter(|path| !parsed_claim_paths.contains(path))
            .collect_vec();
        if !missing_mandatory_claims.is_empty() {
            return Err(IssuanceProtocolError::Failed(format!(
                "Mandatory claims are missing from the parsed credential schema: [{}]",
                missing_mandatory_claims
                    .iter()
                    .map(|path| format!("'{path}'"))
                    .join(", ")
            )));
        }
    }

    schema.layout_properties = metadata_display
        .and_then(|display| convert_metadata_to_layout_properties(display.to_owned()));

    Ok(())
}

async fn attach_matching_holder_binding(
    credential: &mut Credential,
    holder_bindings: &mut Vec<HolderBinding>,
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
    holder_binding: &HolderBinding,
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
