use standardized_types::openid4vci::{
    ClaimMetadata, CredentialMetadata, IssuerDisplay, KeyStorageSecurityLevel,
};
use standardized_types::openid4vp::dcql::{ClaimPath, PathSegment};

mod schema_matching;
#[cfg(test)]
mod test;

use std::collections::HashMap;

use itertools::Itertools;
use one_dto_mapper::convert_inner;
use shared_types::{ClaimSchemaId, CredentialId, OrganisationId, SerializedCredential};
use uuid::Uuid;

use self::schema_matching::{
    CredentialSchemaResolution, align_format_claim_schemas_and_mappings,
    find_or_import_credential_schema, missing_required_claims,
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
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{
    Credential, CredentialStateEnum, CredentialView, CredentialViewMut, HolderCredentialData,
    IssuerIdentity,
};
use crate::model::credential_schema::{CredentialSchema, UpdateCredentialSchemaRequest};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::model::identifier::{Identifier, IdentifierData};
use crate::model::interaction::Interaction;
use crate::model::localized_text::{LocalizedText, LocalizedTextEntityType, LocalizedTextField};
use crate::model::organisation::Organisation;
use crate::model::relation::Related;
use crate::proto::identifier_creator::{
    IdentifierLogo, IdentifierName, IdentifierRole, RemoteIdentifierRelation,
    issuer_display_to_identifier_translations,
};
use crate::proto::session_provider::SessionExt;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::model::{CertificateDetails, IdentifierDetails};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::issuance_protocol::model::{CredentialWithBlob, IssuanceRefreshResponse};
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

        let disclosure_policy = configuration
            .disclosure_policy
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let mut credentials = vec![];
        for issued_credential in issuer_response.credentials {
            let mut credential = self
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
            credential.holder_mut()?.data.embedded_disclosure_policy = disclosure_policy.clone();
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
                first.credential.holder_mut()?,
                organisation,
                interaction_data,
                configuration,
            )
            .await?;
        for item in credentials.iter_mut().skip(1) {
            self.align_credential_schema(
                &mut schema,
                item.credential.holder_mut()?,
                None,
                configuration.credential_metadata.as_ref(),
            )
            .await?;
        }

        // Parent creation happens after all configurations have been issued, when the
        // protocol knows both the offer capabilities and what the issuer returned.
        let main_credential = credentials.remove(0);

        Ok(IssuanceAcceptResponse {
            credential_configuration_id: configuration.credential_configuration_id.to_owned(),
            main_credential,
            batch_items: credentials,
        })
    }

    pub(super) fn change_to_batch_item(
        &self,
        credential: &mut Credential,
        parent_id: CredentialId,
    ) -> Result<(), IssuanceProtocolError> {
        let Credential::HolderSingle {
            common,
            credential: data,
        } = credential
        else {
            return Err(IssuanceProtocolError::Failed(
                "Expected a holder single credential".into(),
            ));
        };
        *credential = Credential::HolderBatchItem {
            common: common.clone(),
            credential: data.clone(),
            parent: Related::new(parent_id, self.credential_repository.clone()),
            consumed_at: None,
        };
        credential.common_mut().interaction = None;
        Ok(())
    }

    async fn update_credential_schema(
        &self,
        credential: CredentialViewMut<'_, HolderCredentialData>,
        organisation: &Organisation,
        interaction_data: &HolderInteractionData,
        configuration: &HolderCredentialConfiguration,
    ) -> Result<CredentialSchema, IssuanceProtocolError> {
        let CredentialViewMut { common, data } = credential;
        let parsed_format = data.format.as_ref().await?.to_owned();
        let issuer_claim_metadata = if let Some(metadata) = &configuration.credential_metadata {
            let schema = common.schema.as_ref().await?;
            map_issuer_claim_metadata(
                &schema,
                metadata,
                &parsed_format,
                self.formatter_provider.as_ref(),
            )
            .await?
        } else {
            vec![]
        };
        self.enrich_credential_schema(
            common.schema.as_mut().await?.as_mut(),
            interaction_data,
            configuration,
            organisation,
            &issuer_claim_metadata,
        )
        .await?;

        let parsed_schema = common.schema.as_ref().await?.to_owned();
        // Validate issuer requirements before import without storing them on the schema.
        ensure_required_claims(&parsed_schema, data, &issuer_claim_metadata).await?;
        let CredentialSchemaResolution {
            mut schema,
            new_format,
        } = find_or_import_credential_schema(
            self.credential_schema_importer.as_ref(),
            self.credential_schema_repository.as_ref(),
            parsed_schema,
            &parsed_format,
            organisation.id,
            &self.config,
        )
        .await?;

        self.align_credential_schema(
            &mut schema,
            CredentialViewMut { common, data },
            new_format,
            configuration.credential_metadata.as_ref(),
        )
        .await?;
        Ok(schema)
    }

    async fn align_credential_schema(
        &self,
        schema: &mut CredentialSchema,
        credential: CredentialViewMut<'_, HolderCredentialData>,
        new_format: Option<CredentialSchemaFormat>,
        metadata: Option<&CredentialMetadata>,
    ) -> Result<(), IssuanceProtocolError> {
        let CredentialViewMut { common, data } = credential;
        let alignment = align_format_claim_schemas_and_mappings(
            schema,
            CredentialViewMut { common, data },
            &self.config,
            None,
        )
        .await?;

        // Schema matching can replace the parsed schema with an existing one. Apply the issuer
        // metadata again after alignment so changed translations target the persisted schema and
        // claim IDs.
        let current_format = data.format.as_ref().await?.to_owned();
        let issuer_claim_metadata = if let Some(metadata) = metadata {
            map_issuer_claim_metadata(
                schema,
                metadata,
                &current_format,
                self.formatter_provider.as_ref(),
            )
            .await?
        } else {
            vec![]
        };
        let translations = apply_issuer_metadata_to_schema(
            schema,
            metadata,
            &self.config.global_settings.default_language,
            &issuer_claim_metadata,
        )
        .await?;
        // A reused schema may require claims that the parsed schema did not.
        ensure_required_claims(schema, data, &issuer_claim_metadata).await?;
        common.schema = schema.clone().into();

        if !alignment.new_claim_schemas.is_empty()
            || new_format.is_some()
            || !translations.is_empty()
        {
            self.credential_schema_repository
                .update_credential_schema(
                    &schema.id,
                    UpdateCredentialSchemaRequest {
                        claim_schemas: (!alignment.new_claim_schemas.is_empty())
                            .then_some(alignment.new_claim_schemas),
                        // A new format owns all of its mappings and persists them together.
                        claim_mappings: new_format.is_none().then_some(alignment.new_mappings),
                        formats: new_format.map(|format| vec![format]),
                        translations: (!translations.is_empty()).then_some(translations),
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
            let holder = credential.holder()?;
            self.process_mso_refresh(holder, response).await?;

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
        credential: CredentialView<'_, HolderCredentialData>,
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

        let schema = credential.common.schema.as_ref().await?;
        let credential_format = credential.data.format.as_ref().await?.format.to_owned();
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
            .data
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
        let parent_id = configuration.credential_id.as_ref().ok_or_else(|| {
            IssuanceProtocolError::Failed("Missing credential ID for batch refresh".to_string())
        })?;
        let batch_parent = self
            .credential_repository
            .get_credential(parent_id)
            .await
            .error_while("getting batch parent")?;
        if !matches!(batch_parent, Credential::HolderBatchParent { .. }) {
            return Err(IssuanceProtocolError::RefreshNotSupported);
        }
        let mut schema = batch_parent.common().schema.as_ref().await?.to_owned();

        let format_type = map_from_oidc_format_to_core_detailed(
            &configuration.format,
            issuer_response
                .credentials
                .first()
                .map(|c| c.as_ref().to_string())
                .as_ref(),
        )?;

        let config_schema_format = self
            .get_batch_schema_format(&batch_parent, configuration, format_type)
            .await?;
        let formatter = self
            .formatter_provider
            .get_credential_formatter(&config_schema_format.format)?;

        let disclosure_policy = configuration
            .disclosure_policy
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
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
                    None,
                )
                .await?;
            credential.holder_mut()?.data.embedded_disclosure_policy = disclosure_policy.clone();
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
                item.credential.holder_mut()?,
                &self.config,
                Some(config_schema_format.id),
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

        let db_blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;
        // Persist one configuration atomically, including blobs. Other configurations
        // can still succeed independently if this refresh fails.
        self.tx_manager
            .tx(async {
                let mut result = Vec::with_capacity(batch_credentials.len());
                for batch_credential in batch_credentials {
                    let CredentialWithBlob {
                        mut credential,
                        serialized,
                    } = batch_credential;
                    self.change_to_batch_item(&mut credential, batch_parent.common().id)?;
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
                    let holder = credential.holder_mut()?;
                    holder.common.state = CredentialStateEnum::Accepted;
                    holder.data.credential_blob_id = credential_blob_id;
                    result.push(credential);
                }
                self.credential_repository
                    .create_credentials(result.clone())
                    .await
                    .error_while("creating credentials")?;
                Ok::<_, IssuanceProtocolError>(result)
            })
            .await
            .error_while("persisting refreshed credentials")?
    }

    pub(super) async fn record_batch_refresh_history(
        &self,
        refreshed: &[IssuanceRefreshResponse],
        organisation_id: OrganisationId,
    ) -> Result<(), IssuanceProtocolError> {
        // Several configurations can refresh the same parent in one request. Record the
        // operation once per parent, after its refreshed items have been persisted.
        for (parent_id, item) in refreshed
            .iter()
            .flat_map(|response| &response.credentials)
            .filter_map(|item| match item {
                Credential::IssuerBatchItem { parent, .. }
                | Credential::HolderBatchItem { parent, .. } => Some((parent.id(), item)),
                _ => None,
            })
            .unique_by(|(parent_id, _)| *parent_id)
        {
            self.history_repository
                .create_history(History {
                    id: Uuid::new_v4().into(),
                    created_date: now_utc(),
                    action: HistoryAction::Refreshed,
                    name: item.common().schema.as_ref().await?.name.to_owned(),
                    source: HistorySource::Core,
                    entity_id: Some(parent_id.into()),
                    entity_type: HistoryEntityType::Credential,
                    organisation_id: Some(organisation_id),
                    user: self.session_provider.session().user(),
                    target: None,
                    metadata: None,
                    metadata_blob_id: None,
                })
                .await
                .error_while("storing history")?;
        }
        Ok(())
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

        validate_issuance_time(&credential.common.issuance_date, formatter.get_leeway())
            .error_while("validating issuance time")?;

        let issuer_identifier = credential.issuer.identifier.as_ref().await?.to_owned();
        let identifier_details = match &issuer_identifier.data {
            IdentifierData::Did(did) => IdentifierDetails::Did(did.as_ref().await?.did.to_owned()),
            IdentifierData::Certificate(certificates) => {
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
            IdentifierData::Key(key) => {
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
                organisation.id,
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

        credential.common.redirect_uri = redirect_uri.cloned();
        credential.common.state = CredentialStateEnum::Accepted;
        credential.common.protocol = self.config_id.to_owned();
        credential.common.interaction = Some(interaction.to_owned().into());
        let binding =
            take_matching_holder_binding(credential.holder_identifier, holder_bindings).await?;
        Ok(Credential::HolderSingle {
            common: credential.common,
            credential: HolderCredentialData {
                issuer: IssuerIdentity {
                    identifier: issuer_identifier.into(),
                    certificate: issuer_certificate.map(Into::into),
                },
                format: credential.format,
                claims: credential.claims,
                binding: Some(binding),
                credential_blob_id: None,
                embedded_disclosure_policy: None,
            },
        })
    }

    async fn enrich_credential_schema(
        &self,
        schema: &mut CredentialSchema,
        interaction_data: &HolderInteractionData,
        configuration: &HolderCredentialConfiguration,
        organisation: &Organisation,
        issuer_claim_metadata: &[IssuerClaimMetadata<'_>],
    ) -> Result<(), IssuanceProtocolError> {
        apply_issuer_metadata_to_schema(
            schema,
            configuration.credential_metadata.as_ref(),
            &self.config.global_settings.default_language,
            issuer_claim_metadata,
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

async fn ensure_required_claims(
    schema: &CredentialSchema,
    credential: &HolderCredentialData,
    issuer_claim_metadata: &[IssuerClaimMetadata<'_>],
) -> Result<(), IssuanceProtocolError> {
    let mandatory_claim_ids = issuer_mandatory_claim_ids(issuer_claim_metadata)?;
    let missing = missing_required_claims(schema, credential, &mandatory_claim_ids).await?;
    if !missing.is_empty() {
        return Err(IssuanceProtocolError::Failed(format!(
            "Issued credential is missing required claims: {}",
            missing.join(", ")
        )));
    }
    Ok(())
}

/// Drop array wildcards from a metadata path to get the formatted technical key used by claim
/// mappings. Reject paths that omit a wildcard when descending into an array or select an index.
fn metadata_path_to_formatted_technical_key(
    path: &ClaimPath,
    array_technical_keys: &[String],
) -> Option<String> {
    let mut properties = vec![];
    for (position, segment) in path.segments.iter().enumerate() {
        let next_segment = path.segments.get(position + 1);
        match segment {
            PathSegment::PropertyName(name) => {
                properties.push(name.as_str());
                let is_array_property =
                    array_technical_keys.contains(&properties.join(NESTED_CLAIM_MARKER_STR));
                let descends_without_wildcard =
                    next_segment.is_some_and(|next| !matches!(next, PathSegment::ArrayAll));
                if is_array_property && descends_without_wildcard {
                    return None;
                }
            }
            PathSegment::ArrayAll => {
                let follows_array_property =
                    array_technical_keys.contains(&properties.join(NESTED_CLAIM_MARKER_STR));
                let selects_child_property =
                    matches!(next_segment, Some(PathSegment::PropertyName(_)));
                if !follows_array_property || !selects_child_property {
                    return None;
                }
            }
            PathSegment::ArrayIndex(_) => return None,
        }
    }
    Some(properties.join(NESTED_CLAIM_MARKER_STR))
}

struct IssuerClaimMetadata<'a> {
    formatted_key: String,
    claim_schema_ids: Vec<ClaimSchemaId>,
    metadata: &'a ClaimMetadata,
}

/// Match issuer metadata paths to schema claims using the current format's technical keys.
/// Keep unmatched paths so validation can report missing mandatory claims, while display
/// enrichment can ignore them.
async fn map_issuer_claim_metadata<'a>(
    schema: &CredentialSchema,
    metadata: &'a CredentialMetadata,
    current_format: &CredentialSchemaFormat,
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<Vec<IssuerClaimMetadata<'a>>, IssuanceProtocolError> {
    let issuer_metadata_claims = metadata.claims.as_deref().unwrap_or(&[]);
    if issuer_metadata_claims.is_empty() {
        return Ok(vec![]);
    }

    let formatter_capabilities = formatter_provider
        .get_credential_formatter(&current_format.format)?
        .get_capabilities();

    let claim_schemas = schema.claim_schemas.as_ref().await?;
    let mappings = current_format.claim_mappings.as_ref().await?;
    let mappings_by_schema_id: HashMap<_, _> = mappings
        .iter()
        .map(|mapping| (mapping.claim_schema_id, mapping))
        .collect();
    let formatted_key = |claim_schema: &ClaimSchema| {
        mappings_by_schema_id
            .get(&claim_schema.id)
            .map(|mapping| mapping.formatted_technical_key())
            .unwrap_or_else(|| claim_schema.key.clone())
    };
    let array_technical_keys = claim_schemas
        .iter()
        .filter(|claim_schema| claim_schema.array)
        .map(&formatted_key)
        .collect_vec();
    let mut schema_ids_by_key: HashMap<String, Vec<ClaimSchemaId>> = HashMap::new();
    for claim_schema in claim_schemas.iter().filter(|claim| !claim.metadata) {
        schema_ids_by_key
            .entry(formatted_key(claim_schema))
            .or_default()
            .push(claim_schema.id);
    }

    Ok(issuer_metadata_claims
        .iter()
        // skip forbidden keys (e.g. meta claims)
        .filter(|claim| {
            let claim_path = &claim.path.segments;
            if let Some(PathSegment::PropertyName(root_key)) = claim_path.first()
                && formatter_capabilities
                    .forbidden_root_claim_technical_keys
                    .contains(root_key)
            {
                tracing::warn!("Forbidden claim in issuer metadata: `{claim:?}`");
                return false;
            }

            if claim_path
                .iter()
                .filter_map(|key| match key {
                    PathSegment::PropertyName(key) => Some(key),
                    PathSegment::ArrayIndex(_) | PathSegment::ArrayAll => None,
                })
                .any(|key| {
                    formatter_capabilities
                        .forbidden_claim_technical_keys
                        .contains(key)
                })
            {
                tracing::warn!("Forbidden claim in issuer metadata: `{claim:?}`");
                return false;
            }

            true
        })
        .filter_map(|claim| {
            let Some(key) =
                metadata_path_to_formatted_technical_key(&claim.path, &array_technical_keys)
            else {
                tracing::debug!(
                    path = %claim.path,
                    "Skipping issuer claim metadata path that does not match the credential schema"
                );
                return None;
            };
            Some(IssuerClaimMetadata {
                claim_schema_ids: schema_ids_by_key.get(&key).cloned().unwrap_or_default(),
                formatted_key: key,
                metadata: claim,
            })
        })
        .collect())
}

/// Resolve this issuer's mandatory claims for validation without modifying schema requirements.
/// Fail when an applicable mandatory metadata path has no corresponding schema claim.
fn issuer_mandatory_claim_ids(
    claim_metadata: &[IssuerClaimMetadata<'_>],
) -> Result<Vec<ClaimSchemaId>, IssuanceProtocolError> {
    let mandatory_claims = claim_metadata
        .iter()
        .filter(|claim| claim.metadata.mandatory == Some(true))
        .collect_vec();
    let missing = mandatory_claims
        .iter()
        .filter(|claim| claim.claim_schema_ids.is_empty())
        .map(|claim| &claim.formatted_key)
        .unique()
        .collect_vec();
    if !missing.is_empty() {
        return Err(IssuanceProtocolError::Failed(format!(
            "Mandatory claims are missing from the parsed credential schema: [{}]",
            missing.iter().map(|path| format!("'{path}'")).join(", ")
        )));
    }

    Ok(mandatory_claims
        .into_iter()
        .flat_map(|claim| claim.claim_schema_ids.iter().copied())
        .unique()
        .collect())
}

/// Applies display metadata and returns changed translations for persistence.
async fn apply_issuer_metadata_to_schema(
    schema: &mut CredentialSchema,
    metadata: Option<&CredentialMetadata>,
    default_language: &str,
    issuer_claim_metadata: &[IssuerClaimMetadata<'_>],
) -> Result<Vec<LocalizedText>, IssuanceProtocolError> {
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

    let mut translations = vec![];
    if !schema_translations.is_empty() {
        let current_translations = schema.translations.as_ref().await?;
        translations.extend(changed_translations(
            &current_translations,
            &schema_translations,
        ));
        drop(current_translations);
        schema.translations = schema_translations.into();
    }

    if !issuer_claim_metadata.is_empty() {
        let mut claim_schemas = schema.claim_schemas.as_mut().await?;
        for claim_schema in &mut claim_schemas {
            let Some(issuer_metadata_claim) = issuer_claim_metadata
                .iter()
                .find(|claim| claim.claim_schema_ids.contains(&claim_schema.id))
                .map(|claim| claim.metadata)
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
                let current_translations = claim_schema.translations.as_ref().await?;
                translations.extend(changed_translations(
                    &current_translations,
                    &claim_translations,
                ));
                drop(current_translations);
                claim_schema.translations = claim_translations.into();
            }
        }
    }

    schema.layout_properties = metadata_display
        .and_then(|display| convert_metadata_to_layout_properties(display.to_owned()));

    Ok(translations)
}

fn changed_translations(
    current: &[LocalizedText],
    desired: &[LocalizedText],
) -> Vec<LocalizedText> {
    desired
        .iter()
        .filter(|desired| {
            // Issuer metadata generates fresh timestamps on every issuance; compare content only.
            !current.iter().any(|current| {
                current.entity_id == desired.entity_id
                    && current.entity_type == desired.entity_type
                    && current.field == desired.field
                    && current.lang == desired.lang
                    && current.value == desired.value
            })
        })
        .cloned()
        .collect()
}

async fn take_matching_holder_binding(
    parsed_identifier: Option<Related<Identifier>>,
    holder_bindings: &mut Vec<HolderBinding>,
) -> Result<crate::model::credential::HolderBinding, IssuanceProtocolError> {
    let parsed_identifier = parsed_identifier.ok_or(IssuanceProtocolError::Failed(
        "No parsed holder identifier".into(),
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
    Ok(crate::model::credential::HolderBinding {
        identifier: matching_holder_binding.identifier.into(),
        key: matching_holder_binding.key.into(),
    })
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
