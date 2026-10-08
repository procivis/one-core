use std::collections::HashMap;

use shared_types::{CredentialFormat, CredentialId, EcosystemId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    CreateCredentialRequestDTO, CredentialAttestationBlobs, CredentialDetailResponseDTO,
    CredentialFilterParamsDTO, CredentialListItemResponseDTO, CredentialRequestClaimDTO,
    CredentialSearchTypeDTO, DetailCredentialClaimResponseDTO,
    DetailCredentialClaimValueResponseDTO, DetailCredentialSchemaResponseDTO,
    MdocMsoValidityResponseDTO, OfferedFormatDTO, OfferedFormatStateEnum, TrustInformation,
    WalletInstanceAttestationDTO, WalletUnitAttestationDTO,
};
use super::error::CredentialServiceError;
use crate::config::core_config::{CoreConfig, DatatypeType, FormatType};
use crate::error::{ContextWithErrorCode, NestedError};
use crate::mapper::credential_schema_claim::claim_schema_to_dto;
use crate::mapper::{NESTED_CLAIM_MARKER, identifier_translations_dto, resolve_identifier_logo};
use crate::model::blob::{Blob, BlobType};
use crate::model::certificate::Certificate;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{
    Credential, CredentialCommon, CredentialFilterValue, CredentialRole, CredentialStateEnum,
    CredentialType, CredentialView, ExactCredentialFilterColumn, IssuerCredentialData, IssuerData,
    VerifierCredentialData,
};
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::ecosystem::EcosystemOutcomes;
use crate::model::history::TrustResolutionResult;
use crate::model::identifier::Identifier;
use crate::model::key::Key;
use crate::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use crate::model::list_query::ListQuery;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::credential_formatter::mdoc_formatter;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::ecosystem::model::{TrustDetail, TrustDetailInfo};
use crate::provider::issuance_protocol::deserialize_interaction_data;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::OpenID4VCIIssuerInteractionDataDTO;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::service::certificate::dto::CertificateResponseDTO;
use crate::service::certificate::mapper::certificate_to_response_dto;
use crate::service::common_dto::BoundedB64Image;
use crate::service::common_mapper::recorded_ecosystem_outcomes;
use crate::service::credential_schema::dto::CredentialClaimSchemaDTO;
use crate::service::credential_schema::mapper::to_credential_schema_list_v2_response;
use crate::service::identifier::dto::GetIdentifierListItemResponseDTO;

#[expect(clippy::too_many_arguments)]
#[allow(deprecated)]
pub(crate) async fn credential_detail_response_from_model(
    value: Credential,
    claims: Vec<Claim>,
    config: &CoreConfig,
    attestation: CredentialAttestationBlobs,
    trust_information: Option<TrustInformation>,
    remaining_batch_item_count: Option<HashMap<CredentialFormat, u32>>,
    credential_repository: &dyn CredentialRepository,
    formatter_provider: &dyn CredentialFormatterProvider,
    blob_storage_provider: Option<&dyn BlobStorageProvider>,
) -> Result<CredentialDetailResponseDTO<DetailCredentialClaimResponseDTO>, CredentialServiceError> {
    let schema_model = value.common().schema.as_ref().await?;

    let schema_dto: DetailCredentialSchemaResponseDTO =
        to_credential_schema_detail_response(schema_model.clone(), config, formatter_provider)
            .await
            .map_err(|e: NestedError| CredentialServiceError::MappingError(e.to_string()))?;

    let claims = to_credential_detail_claims(claims, &schema_model, config).await?;
    drop(schema_model);

    let role = value.role();
    let credential_type = value.r#type();

    let credential_format = value.credential_format().await?;
    let mdoc_mso_validity = mdoc_mso_validity(
        value.common(),
        credential_type,
        credential_format.as_ref(),
        config,
    )?;

    let CredentialDetailIdentities {
        issuer,
        holder,
        issuer_certificate,
    } = credential_detail_identities(&value, config, blob_storage_provider).await?;

    let offered_formats = get_offered_formats(
        value.common(),
        role,
        credential_type,
        value.format(),
        credential_repository,
    )
    .await?;

    let suspend_end_date = value.suspend_end_date();
    let CredentialDetailMetadata {
        common,
        parent_id,
        webhook_url,
        consumed_at,
        subscriber_information,
    } = credential_detail_metadata(value).await?;

    Ok(CredentialDetailResponseDTO {
        id: common.id,
        created_date: common.created_date,
        issuance_date: common.issuance_date,
        revocation_date: get_revocation_date(&common.state, &common.last_modified),
        expires_at: common.expires_at,
        consumed_at,
        state: common.state.into(),
        last_modified: common.last_modified,
        claims,
        schema: schema_dto,
        issuer,
        redirect_uri: common.redirect_uri,
        role: role.into(),
        r#type: credential_type.into(),
        format: credential_format,
        interaction_id: common.interaction.map(|i| i.id()),
        suspend_end_date,
        mdoc_mso_validity,
        holder,
        protocol: common.protocol,
        issuer_certificate,
        profile: common.profile,
        wallet_instance_attestation: attestation
            .wallet_instance_attestation_blob
            .map(TryInto::try_into)
            .transpose()?,
        wallet_unit_attestation: attestation
            .wallet_key_attestation_blob
            .map(TryInto::try_into)
            .transpose()?,
        webhook_destination_url: webhook_url,
        trust_information,
        remaining_batch_item_count,
        parent_id,
        subscriber_information,
        ecosystem: common.ecosystem,
        offered_formats,
    })
}

struct CredentialDetailIdentities {
    issuer: Option<GetIdentifierListItemResponseDTO>,
    holder: Option<GetIdentifierListItemResponseDTO>,
    issuer_certificate: Option<CertificateResponseDTO>,
}

async fn credential_detail_identities(
    value: &Credential,
    config: &CoreConfig,
    blob_storage_provider: Option<&dyn BlobStorageProvider>,
) -> Result<CredentialDetailIdentities, CredentialServiceError> {
    let (issuer_identifier, issuer_certificate, holder_identifier) = match value {
        Credential::IssuerSingle {
            issuer, credential, ..
        }
        | Credential::IssuerBatchItem {
            issuer, credential, ..
        } => (
            Some(&issuer.identifier),
            issuer.certificate.as_ref(),
            credential.holder_identifier.as_ref(),
        ),
        Credential::IssuerBatchParent { issuer, .. } => {
            (Some(&issuer.identifier), issuer.certificate.as_ref(), None)
        }
        Credential::HolderSingle { credential, .. }
        | Credential::HolderBatchItem { credential, .. } => (
            Some(&credential.issuer.identifier),
            credential.issuer.certificate.as_ref(),
            credential
                .binding
                .as_ref()
                .map(|binding| &binding.identifier),
        ),
        Credential::Verifier { verifier_data, .. } => (
            Some(&verifier_data.issuer.identifier),
            verifier_data.issuer.certificate.as_ref(),
            verifier_data.holder_identifier.as_ref(),
        ),
        Credential::HolderBatchParent { .. } => (None, None, None),
    };
    let issuer_certificate = match issuer_certificate {
        None => None,
        Some(certificate) => Some(
            certificate_to_response_dto(certificate.as_ref().await?.to_owned())
                .await
                .error_while("converting certificate")?,
        ),
    };

    let holder = match holder_identifier {
        None => None,
        Some(holder_identifier) => Some(holder_identifier.as_ref().await?.to_owned().into()),
    };

    let issuer = match issuer_identifier {
        None => None,
        Some(identifier) => Some(
            issuer_identifier_to_response(
                identifier.as_ref().await?.to_owned(),
                value.role() == CredentialRole::Holder,
                config,
                blob_storage_provider,
            )
            .await?,
        ),
    };

    Ok(CredentialDetailIdentities {
        issuer,
        holder,
        issuer_certificate,
    })
}

async fn issuer_identifier_to_response(
    identifier: Identifier,
    include_translations: bool,
    config: &CoreConfig,
    blob_storage_provider: Option<&dyn BlobStorageProvider>,
) -> Result<GetIdentifierListItemResponseDTO, CredentialServiceError> {
    let mut dto: GetIdentifierListItemResponseDTO = identifier.clone().into();
    if include_translations {
        let texts = identifier.translations.as_ref().await?;
        dto.translations = Some(identifier_translations_dto(
            &texts,
            &identifier.name,
            &config.global_settings.default_language,
        ));
        if let Some(blob_storage_provider) = blob_storage_provider {
            dto.logo = resolve_identifier_logo(blob_storage_provider, identifier.logo)
                .await?
                .map(BoundedB64Image);
        }
    }
    Ok(dto)
}

struct CredentialDetailMetadata {
    common: CredentialCommon,
    parent_id: Option<CredentialId>,
    webhook_url: Option<String>,
    consumed_at: Option<OffsetDateTime>,
    subscriber_information: Option<String>,
}

async fn credential_detail_metadata(
    value: Credential,
) -> Result<CredentialDetailMetadata, CredentialServiceError> {
    Ok(match value {
        Credential::IssuerSingle {
            common,
            webhook_url,
            subscriber_information,
            ..
        }
        | Credential::IssuerBatchParent {
            common,
            webhook_url,
            subscriber_information,
            ..
        } => CredentialDetailMetadata {
            common,
            parent_id: None,
            webhook_url,
            consumed_at: None,
            subscriber_information,
        },
        Credential::IssuerBatchItem { common, parent, .. } => {
            let subscriber_information = match &*parent.as_ref().await? {
                Credential::IssuerSingle {
                    subscriber_information,
                    ..
                }
                | Credential::IssuerBatchParent {
                    subscriber_information,
                    ..
                } => subscriber_information.clone(),
                _ => None,
            };
            CredentialDetailMetadata {
                common,
                parent_id: Some(parent.id()),
                webhook_url: None,
                consumed_at: None,
                subscriber_information,
            }
        }
        Credential::HolderBatchItem {
            common,
            parent,
            consumed_at,
            ..
        } => CredentialDetailMetadata {
            common,
            parent_id: Some(parent.id()),
            webhook_url: None,
            consumed_at,
            subscriber_information: None,
        },
        Credential::HolderSingle { common, .. }
        | Credential::HolderBatchParent { common, .. }
        | Credential::Verifier { common, .. } => CredentialDetailMetadata {
            common,
            parent_id: None,
            webhook_url: None,
            consumed_at: None,
            subscriber_information: None,
        },
    })
}

async fn to_credential_detail_claims(
    claims: Vec<Claim>,
    credential_schema: &CredentialSchema,
    config: &CoreConfig,
) -> Result<Vec<DetailCredentialClaimResponseDTO>, CredentialServiceError> {
    let claim_schemas = credential_schema.claim_schemas.as_ref().await?;
    let claim_schemas_raw = claim_schemas
        .iter()
        .filter(|cs| !cs.metadata)
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    let mut claim_schema_dtos = Vec::with_capacity(claim_schemas_raw.len());
    for cs in claim_schemas_raw {
        claim_schema_dtos.push(
            claim_schema_to_dto(cs)
                .await
                .map_err(|e| CredentialServiceError::MappingError(e.to_string()))?,
        );
    }

    let mut result = vec![];
    for claim in claims {
        if !claim.schema.as_ref().await?.metadata {
            result = insert_claim(result, claim, &claim_schema_dtos, config).await?;
        }
    }
    sort_claims(&mut result);

    Ok(result)
}

async fn insert_claim(
    mut root: Vec<DetailCredentialClaimResponseDTO>,
    claim: Claim,
    claim_schemas: &[CredentialClaimSchemaDTO],
    config: &CoreConfig,
) -> Result<Vec<DetailCredentialClaimResponseDTO>, CredentialServiceError> {
    match (claim.path.rsplit_once(NESTED_CLAIM_MARKER), &claim.value) {
        (Some((head, _)), Some(_)) => {
            let claim_schema = claim.schema.as_ref().await?;
            let parent_claim = get_or_insert(&mut root, head, claim_schemas)?;

            match &mut parent_claim.value {
                DetailCredentialClaimValueResponseDTO::Nested(claims) => {
                    let mut credential_claim_schema = claim_schemas
                        .iter()
                        .find(|value| value.key == claim_schema.key)
                        .ok_or_else(|| {
                            CredentialServiceError::MappingError("claim.schema is unknown".into())
                        })?
                        .clone();

                    if parent_claim.schema.array {
                        credential_claim_schema.array = false;
                    }

                    claims.push(claim_to_dto(&claim, &credential_claim_schema, config)?);
                }
                _ => {
                    return Err(CredentialServiceError::MappingError(
                        "Parent claim should be nested".into(),
                    ));
                }
            }
        }
        (None, Some(_)) => {
            let claim_schema = claim.schema.as_ref().await?;

            let claim_schema = claim_schemas
                .iter()
                .find(|value| value.key == claim_schema.key)
                .ok_or_else(|| {
                    CredentialServiceError::MappingError("claim.schema is unknown".into())
                })?;

            root.push(claim_to_dto(&claim, claim_schema, config)?);
        }
        (_, None) => {
            // just insert the current claim as a parent if it not exist yet
            get_or_insert(&mut root, &claim.path, claim_schemas)?;
        }
    };

    Ok(root)
}

fn get_or_insert<'a>(
    root: &'a mut Vec<DetailCredentialClaimResponseDTO>,
    path: &str,
    claim_schemas: &[CredentialClaimSchemaDTO],
) -> Result<&'a mut DetailCredentialClaimResponseDTO, CredentialServiceError> {
    match path.rsplit_once(NESTED_CLAIM_MARKER) {
        Some((head, _)) => {
            let parent_claim = get_or_insert(root, head, claim_schemas)?;
            let key = from_path_to_key(parent_claim, path)?;

            match &mut parent_claim.value {
                DetailCredentialClaimValueResponseDTO::Nested(claims) => {
                    if let Some(i) = claims.iter().position(|claim| claim.path == path) {
                        Ok(claims.get_mut(i).ok_or_else(|| {
                            CredentialServiceError::MappingError("invalid index".into())
                        })?)
                    } else {
                        let mut item_schema = claim_schemas
                            .iter()
                            .find(|schema| schema.key == key)
                            .ok_or_else(|| {
                                CredentialServiceError::MappingError("missing claim schema".into())
                            })?
                            .to_owned();

                        if parent_claim.schema.array {
                            item_schema.array = false;
                        }

                        claims.push(DetailCredentialClaimResponseDTO {
                            path: path.to_owned(),
                            schema: item_schema,
                            value: DetailCredentialClaimValueResponseDTO::Nested(vec![]),
                        });
                        let last = claims.len() - 1;
                        Ok(claims.get_mut(last).ok_or_else(|| {
                            CredentialServiceError::MappingError("invalid index".into())
                        })?)
                    }
                }
                _ => Err(CredentialServiceError::MappingError(
                    "Parent claim should be nested".into(),
                )),
            }
        }
        None => {
            if let Some(i) = root.iter().position(|claim| claim.schema.key == path) {
                Ok(root
                    .get_mut(i)
                    .ok_or_else(|| CredentialServiceError::MappingError("invalid index".into()))?)
            } else {
                root.push(DetailCredentialClaimResponseDTO {
                    path: path.to_owned(),
                    schema: claim_schemas
                        .iter()
                        .find(|schema| schema.key == path)
                        .ok_or_else(|| {
                            CredentialServiceError::MappingError("missing claim schema".into())
                        })?
                        .to_owned(),
                    value: DetailCredentialClaimValueResponseDTO::Nested(vec![]),
                });
                let last = root.len() - 1;
                Ok(root
                    .get_mut(last)
                    .ok_or_else(|| CredentialServiceError::MappingError("invalid index".into()))?)
            }
        }
    }
}

fn from_path_to_key(
    parent: &DetailCredentialClaimResponseDTO,
    path: &str,
) -> Result<String, CredentialServiceError> {
    if parent.schema.array {
        return Ok(parent.schema.key.clone());
    }

    let suffix = path
        .strip_prefix(&parent.path)
        .ok_or_else(|| CredentialServiceError::MappingError("invalid path".into()))?;

    Ok(format!("{}{suffix}", parent.schema.key))
}

fn claim_to_dto(
    claim: &Claim,
    claim_schema: &CredentialClaimSchemaDTO,
    config: &CoreConfig,
) -> Result<DetailCredentialClaimResponseDTO, CredentialServiceError> {
    let claim_value = claim
        .value
        .as_ref()
        .ok_or(CredentialServiceError::MappingError(format!(
            "Missing value on leaf claim: {}",
            claim.id
        )))?;
    let value = match config
        .datatype
        .get_fields(&claim_schema.datatype)
        .error_while("getting datatype config")?
        .r#type
    {
        DatatypeType::Number => {
            if let Ok(number) = claim_value.parse::<i64>() {
                DetailCredentialClaimValueResponseDTO::Integer(number)
            } else if let Ok(float) = claim_value.parse::<f64>() {
                DetailCredentialClaimValueResponseDTO::Float(float)
            } else {
                // Fallback to empty string
                DetailCredentialClaimValueResponseDTO::String(String::new())
            }
        }
        DatatypeType::Boolean => {
            if let Ok(bool) = claim_value.parse::<bool>() {
                DetailCredentialClaimValueResponseDTO::Boolean(bool)
            } else {
                // Fallback to empty string
                DetailCredentialClaimValueResponseDTO::String(String::new())
            }
        }
        _ => DetailCredentialClaimValueResponseDTO::String(claim_value.to_owned()),
    };

    Ok(DetailCredentialClaimResponseDTO {
        path: claim.path.to_owned(),
        schema: claim_schema.to_owned(),
        value,
    })
}

fn sort_claims(claims: &mut [DetailCredentialClaimResponseDTO]) {
    claims.iter_mut().for_each(|claim| {
        if let DetailCredentialClaimValueResponseDTO::Nested(claims) = &mut claim.value {
            if claim.schema.array {
                claims.sort_by(|l, r| human_sort::compare(&l.path, &r.path));
            }
            sort_claims(claims)
        }
    });
}

async fn get_offered_formats(
    common: &CredentialCommon,
    role: CredentialRole,
    credential_type: CredentialType,
    credential_format: Option<&crate::model::relation::Related<CredentialSchemaFormat>>,
    credential_repository: &dyn CredentialRepository,
) -> Result<Option<Vec<OfferedFormatDTO>>, CredentialServiceError> {
    if role != CredentialRole::Issuer
        || credential_type == CredentialType::BatchItem
        || common.state == CredentialStateEnum::Error
    {
        return Ok(None);
    }

    let schema = common.schema.as_ref().await?;
    let mut formats = schema.formats.as_ref().await?.to_vec();

    if credential_type == CredentialType::Single {
        if formats.len() < 2 {
            return Ok(None);
        }

        // single credential based on a multi-format schema (by selecting only one format for issuance)
        let Some(format) = credential_format else {
            tracing::error!("Single credential without format set: {}", common.id);
            return Ok(None);
        };

        let format = format.as_ref().await?;
        let state = match common.state {
            CredentialStateEnum::Created
            | CredentialStateEnum::Pending
            | CredentialStateEnum::Offered
            | CredentialStateEnum::InteractionExpired
            | CredentialStateEnum::Error => OfferedFormatStateEnum::Pending,
            CredentialStateEnum::Accepted
            | CredentialStateEnum::Revoked
            | CredentialStateEnum::Suspended
            | CredentialStateEnum::Expiring
            | CredentialStateEnum::Expired => OfferedFormatStateEnum::Accepted,
            CredentialStateEnum::Rejected => OfferedFormatStateEnum::Rejected,
        };
        return Ok(Some(vec![OfferedFormatDTO {
            format: format.format.to_owned(),
            state,
        }]));
    }

    // batch parent credential
    if let Some(interaction) = &common.interaction {
        let interaction = interaction.as_ref().await?;
        let data: OpenID4VCIIssuerInteractionDataDTO =
            deserialize_interaction_data(interaction.data.as_ref())
                .error_while("deserializing interaction data")?;
        if let Some(selected_formats) = &data.formats {
            formats.retain(|f| selected_formats.contains(&f.id));
        }
    }

    let mut result = vec![];
    for format in formats {
        let state = match common.state {
            CredentialStateEnum::Created
            | CredentialStateEnum::Pending
            | CredentialStateEnum::Offered
            | CredentialStateEnum::InteractionExpired
            | CredentialStateEnum::Error => OfferedFormatStateEnum::Pending,
            CredentialStateEnum::Accepted
            | CredentialStateEnum::Rejected
            | CredentialStateEnum::Revoked
            | CredentialStateEnum::Suspended
            | CredentialStateEnum::Expiring
            | CredentialStateEnum::Expired => {
                let items = credential_repository
                    .get_credential_list(ListQuery {
                        include_count: false,
                        filtering: Some(
                            CredentialFilterValue::ParentCredential(common.id).condition()
                                & CredentialFilterValue::FormatIds(vec![format.id]),
                        ),
                        ..Default::default()
                    })
                    .await
                    .error_while("listing batch items")?
                    .values;

                if items.is_empty() {
                    OfferedFormatStateEnum::Pending
                } else if items
                    .iter()
                    .all(|item| item.common().state == CredentialStateEnum::Rejected)
                {
                    OfferedFormatStateEnum::Rejected
                } else {
                    OfferedFormatStateEnum::Accepted
                }
            }
        };

        result.push(OfferedFormatDTO {
            format: format.format,
            state,
        });
    }

    Ok(Some(result))
}

pub(super) async fn to_credential_list_response(
    credential: Credential,
    include_translations: bool,
    config: &CoreConfig,
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<CredentialListItemResponseDTO, CredentialServiceError> {
    let schema = credential.common().schema.as_ref().await?.to_owned();
    let credential_format = credential.credential_format().await?;

    let issuer_identifier = match &credential {
        Credential::IssuerSingle { issuer, .. }
        | Credential::IssuerBatchParent { issuer, .. }
        | Credential::IssuerBatchItem { issuer, .. } => Some(&issuer.identifier),
        Credential::HolderSingle { credential, .. }
        | Credential::HolderBatchItem { credential, .. } => Some(&credential.issuer.identifier),
        Credential::Verifier { verifier_data, .. } => Some(&verifier_data.issuer.identifier),
        Credential::HolderBatchParent { .. } => None,
    };
    let issuer = match issuer_identifier {
        None => None,
        Some(issuer_identifier) => Some(issuer_identifier.as_ref().await?.to_owned().into()),
    };

    let suspend_end_date = credential.suspend_end_date();
    let role = credential.role();
    let credential_type = credential.r#type();
    let (common, parent_id, webhook_url, consumed_at) = match credential {
        Credential::IssuerSingle {
            common,
            webhook_url,
            ..
        }
        | Credential::IssuerBatchParent {
            common,
            webhook_url,
            ..
        } => (common, None, webhook_url, None),
        Credential::HolderBatchItem {
            common,
            parent,
            consumed_at,
            ..
        } => (common, Some(parent.id()), None, consumed_at),
        Credential::IssuerBatchItem { common, parent, .. } => {
            (common, Some(parent.id()), None, None)
        }
        Credential::HolderSingle { common, .. }
        | Credential::HolderBatchParent { common, .. }
        | Credential::Verifier { common, .. } => (common, None, None, None),
    };

    Ok(CredentialListItemResponseDTO {
        id: common.id,
        created_date: common.created_date,
        issuance_date: common.issuance_date,
        revocation_date: get_revocation_date(&common.state, &common.last_modified),
        expires_at: common.expires_at,
        consumed_at,
        state: common.state.into(),
        format: credential_format,
        last_modified: common.last_modified,
        schema: to_credential_schema_list_v2_response(
            schema,
            include_translations,
            config,
            formatter_provider,
        )
        .await?,
        issuer,
        role: role.into(),
        r#type: credential_type.into(),
        suspend_end_date,
        protocol: common.protocol,
        profile: common.profile,
        webhook_destination_url: webhook_url,
        parent_id,
        redirect_uri: common.redirect_uri,
        ecosystem: common.ecosystem,
    })
}

fn get_revocation_date(
    state: &CredentialStateEnum,
    last_modified: &OffsetDateTime,
) -> Option<OffsetDateTime> {
    if *state == CredentialStateEnum::Revoked {
        Some(last_modified.to_owned())
    } else {
        None
    }
}

#[expect(clippy::too_many_arguments)]
pub(super) fn from_create_request(
    request: CreateCredentialRequestDTO,
    credential_id: CredentialId,
    claims: Vec<Claim>,
    issuer_identifier: Identifier,
    issuer_certificate: Option<Certificate>,
    schema: CredentialSchema,
    key: Key,
    mut formats: Vec<CredentialSchemaFormat>,
    config: &CoreConfig,
) -> Result<Credential, CredentialServiceError> {
    let now = crate::clock::now_utc();
    let (r#type, format) = if formats.len() > 1 || schema.batch_size.is_some_and(|s| s >= 2) {
        (CredentialType::BatchParent, None)
    } else {
        let Some(format) = formats.pop() else {
            return Err(CredentialServiceError::InvalidFormatSelection);
        };

        let format_type = config
            .format
            .get_type(&format.format)
            .error_while("getting credential schema format type")?;

        let r#type = if format_type == FormatType::Mdoc {
            CredentialType::BatchParent
        } else {
            CredentialType::Single
        };
        (r#type, Some(format))
    };
    let expires_at = schema.expiration.map(|e| now + e);

    let common = CredentialCommon {
        id: credential_id,
        created_date: now,
        issuance_date: None,
        expires_at,
        state: CredentialStateEnum::Created,
        last_modified: now,
        deleted_at: None,
        protocol: request.protocol,
        schema: schema.into(),
        interaction: None,
        redirect_uri: request.redirect_uri,
        profile: request.profile,
        ecosystem: request.ecosystem,
    };
    if r#type == CredentialType::Single {
        return Ok(Credential::IssuerSingle {
            common,
            wallet_instance_attestation_blob_id: None,
            issuer: IssuerData {
                identifier: issuer_identifier.into(),
                certificate: issuer_certificate.map(Into::into),
                signing_key: key.into(),
            },
            webhook_url: request.webhook_destination_url,
            subscriber_information: request.subscriber_information,
            claims: claims.into(),
            credential: IssuerCredentialData {
                suspend_end_date: None,
                format: format
                    .ok_or(CredentialServiceError::InvalidFormatSelection)?
                    .into(),
                holder_identifier: None,
                credential_blob_id: None,
                wallet_key_attestation_blob_id: None,
            },
        });
    }
    Ok(Credential::IssuerBatchParent {
        common,
        wallet_instance_attestation_blob_id: None,
        issuer: IssuerData {
            identifier: issuer_identifier.into(),
            certificate: issuer_certificate.map(Into::into),
            signing_key: key.into(),
        },
        suspend_end_date: None,
        claims: claims.into(),
        webhook_url: request.webhook_destination_url,
        subscriber_information: request.subscriber_information,
    })
}

pub(super) fn claims_from_create_request(
    claims: Vec<CredentialRequestClaimDTO>,
    claim_schemas: &[ClaimSchema],
) -> Result<Vec<Claim>, CredentialServiceError> {
    let now = crate::clock::now_utc();
    let mut claims_map = HashMap::<String, Claim>::new();

    for claim_dto in claims {
        let claim_schema_id = claim_dto.claim_schema_id;
        let schema = claim_schemas
            .iter()
            .find(|schema| schema.id == claim_schema_id)
            .ok_or(CredentialServiceError::MissingClaimSchema(claim_schema_id))?;
        let claim = Claim {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            value: Some(claim_dto.value),
            path: claim_dto.path.clone(),
            selectively_disclosable: false,
            schema: schema.clone().into(),
        };
        claims_map.insert(claim_dto.path.clone(), claim);
        let mut current_path = claim_dto.path;
        current_path = insert_array_parent(schema, now, &mut claims_map, current_path)?;

        let mut current_schema_path = schema.key.clone();
        let mut current_path_split = current_path.rsplit_once('/');

        // Step through the tree starting from the leaf up to the root and create intermediary
        // container claims.
        while let Some(parent_path) = current_path_split.map(|(s, _)| s.to_owned())
            // If the immediate parent exists then all parents up to the root exist, so no need to
            // check other splits.
            && !claims_map.contains_key(&parent_path)
        {
            current_path = parent_path.to_owned();
            let Some((parent_schema_path, _)) = current_schema_path.rsplit_once("/") else {
                return Err(CredentialServiceError::MappingError(format!(
                    "Expected schema path '{current_schema_path}' to contain nested property",
                )));
            };
            let schema = claim_schemas
                .iter()
                .find(|schema| schema.key == parent_schema_path)
                .ok_or(CredentialServiceError::MappingError(format!(
                    "Schema not found for array or object claim with path {current_path}",
                )))?;
            let parent_claim = Claim {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                value: None,
                path: current_path.clone(),
                selectively_disclosable: false,
                schema: schema.clone().into(),
            };
            claims_map.insert(current_path.clone(), parent_claim);
            current_path = insert_array_parent(schema, now, &mut claims_map, current_path)?;
            current_path_split = current_path.rsplit_once('/');
            current_schema_path = parent_schema_path.to_string();
        }
    }
    Ok(claims_map.into_values().collect())
}

fn insert_array_parent(
    schema: &ClaimSchema,
    now: OffsetDateTime,
    claims_map: &mut HashMap<String, Claim>,
    current_path: String,
) -> Result<String, CredentialServiceError> {
    if schema.array {
        let Some((array_path, _)) = current_path.rsplit_once("/") else {
            return Err(CredentialServiceError::MappingError(format!(
                "Expected '{current_path}' to contain array element index",
            )));
        };
        if !claims_map.contains_key(array_path) {
            let parent_claim = Claim {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                value: None,
                path: array_path.to_owned(),
                selectively_disclosable: false,
                schema: schema.clone().into(),
            };
            claims_map.insert(array_path.to_owned(), parent_claim);
        }
        return Ok(array_path.to_owned());
    }
    Ok(current_path)
}

async fn to_credential_schema_detail_response(
    credential_schema: CredentialSchema,
    config: &CoreConfig,
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<DetailCredentialSchemaResponseDTO, NestedError> {
    Ok(DetailCredentialSchemaResponseDTO {
        organisation_id: credential_schema.organisation.id(),
        schema: to_credential_schema_list_v2_response(
            credential_schema,
            true,
            config,
            formatter_provider,
        )
        .await?,
    })
}

impl TryFrom<Blob> for WalletInstanceAttestationDTO {
    type Error = CredentialServiceError;

    fn try_from(value: Blob) -> Result<Self, Self::Error> {
        if value.r#type != BlobType::WalletInstanceAttestation {
            return Err(CredentialServiceError::MappingError(format!(
                "Failed to parse parse wallet instance attestation blob of type: {:?}",
                value.r#type
            )));
        }
        let wallet_instance_attestation = serde_json::from_slice(&value.value).map_err(|e| {
            CredentialServiceError::MappingError(format!(
                "Failed to parse wallet instance attestation blob: {e}"
            ))
        })?;
        Ok(wallet_instance_attestation)
    }
}

impl TryFrom<Blob> for WalletUnitAttestationDTO {
    type Error = CredentialServiceError;

    fn try_from(value: Blob) -> Result<Self, Self::Error> {
        if value.r#type != BlobType::WalletUnitAttestation {
            return Err(CredentialServiceError::MappingError(format!(
                "Failed to parse parse wallet unit attestation blob of type: {:?}",
                value.r#type
            )));
        }
        let wallet_unit_attestation = serde_json::from_slice(&value.value).map_err(|e| {
            CredentialServiceError::MappingError(format!(
                "Failed to parse wallet unit attestation blob: {e}"
            ))
        })?;
        Ok(wallet_unit_attestation)
    }
}

impl From<CredentialFilterParamsDTO> for ListFilterCondition<CredentialFilterValue> {
    fn from(value: CredentialFilterParamsDTO) -> Self {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let organisation_id =
            CredentialFilterValue::OrganisationId(value.organisation_id).condition();

        let name = value.name.map(|name| {
            CredentialFilterValue::CredentialSchemaName(StringMatch {
                r#match: get_string_match_type(ExactCredentialFilterColumn::Name),
                value: name,
            })
        });

        let profiles = value.profiles.map(CredentialFilterValue::Profiles);
        let formats = value.formats.map(CredentialFilterValue::Formats);

        let search_filters = match (value.search_text, value.search_type) {
            (Some(search_text), Some(search_type)) => {
                organisation_id
                    & ListFilterCondition::Or(
                        search_type
                            .into_iter()
                            .map(|filter_type| {
                                match filter_type {
                                    CredentialSearchTypeDTO::ClaimName => {
                                        CredentialFilterValue::ClaimName(StringMatch {
                                            r#match: StringMatchType::Contains,
                                            value: search_text.clone(),
                                        })
                                    }
                                    CredentialSearchTypeDTO::ClaimValue => {
                                        CredentialFilterValue::ClaimValue(StringMatch {
                                            r#match: StringMatchType::Contains,
                                            value: search_text.clone(),
                                        })
                                    }
                                    CredentialSearchTypeDTO::CredentialSchemaName => {
                                        CredentialFilterValue::CredentialSchemaName(StringMatch {
                                            r#match: StringMatchType::Contains,
                                            value: search_text.clone(),
                                        })
                                    }
                                }
                                .condition()
                            })
                            .collect(),
                    )
            }
            _ => organisation_id,
        };

        let roles = value.roles.map(|roles| {
            CredentialFilterValue::Roles(
                roles
                    .into_iter()
                    .map(crate::model::credential::CredentialRole::from)
                    .collect(),
            )
        });

        let credential_ids = value.ids.map(CredentialFilterValue::CredentialIds);

        let parent_credential = value.parent_id.map(CredentialFilterValue::ParentCredential);

        let credential_schema_ids = value
            .credential_schema_ids
            .map(CredentialFilterValue::CredentialSchemaIds);

        let ecosystems = value.ecosystems.map(CredentialFilterValue::Ecosystems);

        let issuers = value.issuers.map(CredentialFilterValue::IssuerIds);

        let states = value.states.map(|values| {
            CredentialFilterValue::States(
                values
                    .into_iter()
                    .map(crate::model::credential::CredentialStateEnum::from)
                    .collect(),
            )
        });

        let types = value.types.map(|values| {
            CredentialFilterValue::Types(
                values
                    .into_iter()
                    .map(crate::model::credential::CredentialType::from)
                    .collect(),
            )
        });

        let created_date_after = value.created_date_after.map(|date| {
            CredentialFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            CredentialFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = value.last_modified_after.map(|date| {
            CredentialFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = value.last_modified_before.map(|date| {
            CredentialFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let issuance_date_after = value.issuance_date_after.map(|date| {
            CredentialFilterValue::IssuanceDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let issuance_date_before = value.issuance_date_before.map(|date| {
            CredentialFilterValue::IssuanceDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let revocation_date_after = value.revocation_date_after.map(|date| {
            CredentialFilterValue::RevocationDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let revocation_date_before = value.revocation_date_before.map(|date| {
            CredentialFilterValue::RevocationDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let expires_at_after = value.expires_at_after.map(|date| {
            CredentialFilterValue::ExpiresAt(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let expires_at_before = value.expires_at_before.map(|date| {
            CredentialFilterValue::ExpiresAt(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        search_filters
            & name
            & roles
            & credential_ids
            & parent_credential
            & credential_schema_ids
            & ecosystems
            & issuers
            & states
            & types
            & profiles
            & formats
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
            & issuance_date_after
            & issuance_date_before
            & revocation_date_after
            & revocation_date_before
            & CredentialFilterValue::Deleted(false)
            & expires_at_after
            & expires_at_before
    }
}

pub(crate) async fn get_remaining_batch_item_count(
    credential: &Credential,
    credential_repository: &dyn CredentialRepository,
) -> Result<Option<HashMap<CredentialFormat, u32>>, CredentialServiceError> {
    if !matches!(credential, Credential::HolderBatchParent { .. }) {
        return Ok(None);
    }

    let batch_items = credential_repository
        .get_credential_list(ListQuery {
            include_count: false,
            filtering: Some(
                CredentialFilterValue::ParentCredential(credential.common().id).condition()
                    & CredentialFilterValue::Types(vec![CredentialType::BatchItem])
                    & CredentialFilterValue::Deleted(false)
                    & CredentialFilterValue::States(vec![
                        // Currently or previously usable states as holder.
                        CredentialStateEnum::Accepted,
                        CredentialStateEnum::Suspended,
                        CredentialStateEnum::Revoked,
                        CredentialStateEnum::Expired,
                    ]),
            ),
            ..Default::default()
        })
        .await
        .error_while("listing batch items")?
        .values;

    let mut counts = HashMap::new();
    for item in batch_items {
        let format = item
            .format()
            .ok_or(CredentialServiceError::MappingError(format!(
                "Missing format on batch_item credential {}",
                item.common().id
            )))?
            .as_ref()
            .await?;
        let entry = counts.entry(format.format.to_owned()).or_insert(0);
        if item.common().state == CredentialStateEnum::Accepted
            && !matches!(
                item,
                Credential::HolderBatchItem {
                    consumed_at: Some(_),
                    ..
                }
            )
        {
            *entry += 1;
        }
    }
    Ok(Some(counts))
}

pub(crate) async fn get_credential_trust_information(
    credential: &Credential,
    wallet_name: Option<String>,
    ecosystem_provider: &dyn EcosystemDirectory,
    history_repository: &dyn HistoryRepository,
) -> Result<Option<TrustInformation>, CredentialServiceError> {
    let history_id = credential.ecosystem_history_id();
    let ecosystem_errors =
        recorded_ecosystem_outcomes(history_id.into(), history_repository).await?;

    match credential {
        Credential::IssuerSingle { common, .. }
        | Credential::IssuerBatchParent { common, .. }
        | Credential::IssuerBatchItem { common, .. } => Ok(issuer_trust_information(
            common,
            wallet_name,
            ecosystem_errors,
        )),
        Credential::HolderSingle { common, .. }
        | Credential::HolderBatchParent { common, .. }
        | Credential::HolderBatchItem { common, .. } => Ok(Some(
            holder_trust_information(common, history_id, ecosystem_errors, ecosystem_provider)
                .await,
        )),
        Credential::Verifier { .. } => {
            verifier_trust_information(credential.verifier()?, ecosystem_errors).await
        }
    }
}

/// The issuer records trust information about the wallet provider.
fn issuer_trust_information(
    common: &CredentialCommon,
    wallet_name: Option<String>,
    ecosystem_errors: EcosystemOutcomes,
) -> Option<TrustInformation> {
    if ecosystem_errors.is_empty() {
        return None;
    }
    Some(TrustInformation {
        received_at: common.issuance_date.unwrap_or(common.last_modified),
        name: wallet_name,
        result: resolution(&common.ecosystem),
        ecosystem_errors,
    })
}

/// The holder records trust information about the issuer, shared by its batch.
async fn holder_trust_information(
    common: &CredentialCommon,
    history_id: CredentialId,
    ecosystem_errors: EcosystemOutcomes,
    ecosystem_provider: &dyn EcosystemDirectory,
) -> TrustInformation {
    let fallback_date = common.issuance_date.unwrap_or(common.last_modified);
    let Some(ecosystem_id) = &common.ecosystem else {
        return TrustInformation {
            received_at: fallback_date,
            name: None,
            result: TrustResolutionResult::Untrusted,
            ecosystem_errors,
        };
    };
    let (received_at, name) = match issuer_trust_detail(
        history_id,
        ecosystem_id,
        ecosystem_provider,
    )
    .await
    {
        Ok(details) => {
            let TrustDetailInfo::Eudi(info) = details.info;
            (details.received_at, Some(info.name))
        }
        Err(err) => {
            tracing::warn!(%err, "failed to get the issuer trust detail of credential {}", common.id);
            (fallback_date, None)
        }
    };
    TrustInformation {
        received_at,
        name,
        result: TrustResolutionResult::Trusted,
        ecosystem_errors,
    }
}

/// The verifier records trust information about the issuer of a received credential.
async fn verifier_trust_information(
    credential: CredentialView<'_, VerifierCredentialData>,
    ecosystem_errors: EcosystemOutcomes,
) -> Result<Option<TrustInformation>, CredentialServiceError> {
    let CredentialView { common, data } = credential;
    if common.ecosystem.is_none() && ecosystem_errors.is_empty() {
        return Ok(None);
    }
    let name = match &data.issuer.certificate {
        Some(certificate) => Some(certificate.as_ref().await?.name.to_owned()),
        None => None,
    };
    Ok(Some(TrustInformation {
        received_at: common.created_date,
        name,
        result: resolution(&common.ecosystem),
        ecosystem_errors,
    }))
}

/// An ecosystem accepted the counterparty, or none did.
fn resolution(ecosystem: &Option<EcosystemId>) -> TrustResolutionResult {
    match ecosystem {
        Some(_) => TrustResolutionResult::Trusted,
        None => TrustResolutionResult::Untrusted,
    }
}

async fn issuer_trust_detail(
    history_id: CredentialId,
    ecosystem_id: &EcosystemId,
    ecosystem_provider: &dyn EcosystemDirectory,
) -> Result<TrustDetail, CredentialServiceError> {
    Ok(ecosystem_provider
        .get(ecosystem_id)?
        .issuer_trust_details(&history_id)
        .await
        .error_while("getting trust detail")?)
}

fn mdoc_mso_validity(
    common: &CredentialCommon,
    credential_type: CredentialType,
    credential_format: Option<&CredentialFormat>,
    config: &CoreConfig,
) -> Result<Option<MdocMsoValidityResponseDTO>, CredentialServiceError> {
    Ok(
        if let Some(credential_format) = credential_format
            && config
                .format
                .get_type(credential_format)
                .error_while("getting format config")?
                == FormatType::Mdoc
            && [
                CredentialStateEnum::Accepted,
                CredentialStateEnum::Suspended,
                CredentialStateEnum::Revoked,
            ]
            .contains(&common.state)
        {
            let params = config
                .format
                .get::<mdoc_formatter::Params, _>(credential_format)
                .error_while("parsing formatter params")?;
            let issuance_date_with_expiry = common
                .issuance_date
                .map(|i| (i, common.expires_at))
                // Legacy singles may predate the issuance date field.
                .or_else(|| {
                    (credential_type == CredentialType::Single)
                        .then_some((common.last_modified, None))
                });
            issuance_date_with_expiry.map(|(issuance_date, expiry)| MdocMsoValidityResponseDTO {
                expiration: expiry.unwrap_or(issuance_date + params.expiration_seconds),
                next_update: issuance_date + params.mso_expected_update_in_seconds,
                last_update: issuance_date,
            })
        } else {
            None
        },
    )
}

pub(crate) async fn credential_detail_response_from_backup(
    value: crate::model::backup::UnexportableCredential,
    config: &CoreConfig,
    credential_repository: &dyn CredentialRepository,
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<CredentialDetailResponseDTO<DetailCredentialClaimResponseDTO>, CredentialServiceError> {
    let schema = value.common.schema.as_ref().await?;
    let schema_dto =
        to_credential_schema_detail_response(schema.clone(), config, formatter_provider).await?;
    let claims = to_credential_detail_claims(value.claims, &schema, config).await?;
    drop(schema);
    let format = match &value.format {
        Some(format) if value.r#type != CredentialType::BatchParent => {
            Some(format.as_ref().await?.format.clone())
        }
        _ => None,
    };
    let mdoc_mso_validity =
        mdoc_mso_validity(&value.common, value.r#type, format.as_ref(), config)?;
    let offered_formats = get_offered_formats(
        &value.common,
        value.role,
        value.r#type,
        value.format.as_ref(),
        credential_repository,
    )
    .await?;
    let common = value.common;
    Ok(CredentialDetailResponseDTO {
        id: common.id,
        created_date: common.created_date,
        issuance_date: common.issuance_date,
        revocation_date: get_revocation_date(&common.state, &common.last_modified),
        expires_at: common.expires_at,
        consumed_at: value.consumed_at,
        state: common.state.into(),
        last_modified: common.last_modified,
        claims,
        schema: schema_dto,
        issuer: None,
        redirect_uri: common.redirect_uri,
        role: value.role.into(),
        r#type: value.r#type.into(),
        format,
        interaction_id: common.interaction.map(|interaction| interaction.id()),
        suspend_end_date: value.suspend_end_date,
        mdoc_mso_validity,
        holder: None,
        protocol: common.protocol,
        issuer_certificate: None,
        profile: common.profile,
        wallet_instance_attestation: None,
        wallet_unit_attestation: None,
        webhook_destination_url: value.webhook_url,
        trust_information: None,
        remaining_batch_item_count: None,
        parent_id: value.parent_id,
        subscriber_information: value.subscriber_information,
        ecosystem: common.ecosystem,
        offered_formats,
    })
}
