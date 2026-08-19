use std::collections::HashMap;

use one_dto_mapper::convert_inner;
use shared_types::CredentialId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    CreateCredentialRequestDTO, CredentialAttestationBlobs, CredentialDetailResponseDTO,
    CredentialFilterParamsDTO, CredentialListItemResponseDTO, CredentialRequestClaimDTO,
    CredentialSearchTypeDTO, DetailCredentialClaimResponseDTO,
    DetailCredentialClaimValueResponseDTO, DetailCredentialSchemaResponseDTO,
    MdocMsoValidityResponseDTO, TrustInformation, WalletInstanceAttestationDTO,
    WalletUnitAttestationDTO,
};
use super::error::CredentialServiceError;
use crate::config::core_config::{CoreConfig, DatatypeType, FormatType};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt, NestedError};
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::mapper::credential_schema_claim::{claim_schema_to_dto, translations_to_i18n};
use crate::model::blob::{Blob, BlobType};
use crate::model::certificate::Certificate;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::common::SortDirection;
use crate::model::credential::{
    Credential, CredentialFilterValue, CredentialRole, CredentialStateEnum, CredentialType,
    ExactCredentialFilterColumn, SortableCredentialColumn,
};
use crate::model::credential_schema::CredentialSchema;
use crate::model::history::TrustResolutionResult;
use crate::model::identifier::Identifier;
use crate::model::key::Key;
use crate::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use crate::model::list_query::{ListPagination, ListQuery, ListSorting};
use crate::model::localized_text::LocalizedTextField;
use crate::provider::credential_formatter::mdoc_formatter;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::ecosystem::model::TrustDetailInfo;
use crate::repository::credential_repository::CredentialRepository;
use crate::service::certificate::mapper::certificate_to_response_dto;
use crate::service::credential_schema::dto::{
    CredentialClaimSchemaDTO, CredentialSchemaTranslationsDTO,
};
use crate::service::credential_schema::mapper::to_credential_schema_list_response;

pub(crate) async fn credential_detail_response_from_model(
    value: Credential,
    config: &CoreConfig,
    attestation: CredentialAttestationBlobs,
    trust_information: Option<TrustInformation>,
    remaining_batch_item_count: Option<u32>,
    credential_repository: &dyn CredentialRepository,
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<CredentialDetailResponseDTO<DetailCredentialClaimResponseDTO>, CredentialServiceError> {
    let schema_model = value.schema.as_ref().await?;

    let schema_dto: DetailCredentialSchemaResponseDTO =
        to_credential_schema_detail_response(schema_model.clone(), formatter_provider)
            .await
            .map_err(|e: NestedError| CredentialServiceError::MappingError(e.to_string()))?;

    let claims = match value.r#type {
        CredentialType::Single | CredentialType::BatchParent => {
            value.claims.as_ref().await?.to_owned()
        }
        CredentialType::BatchItem => {
            // batch items have no claims of their own, they are defined by the parent
            let parent = value
                .parent
                .as_ref()
                .ok_or(CredentialServiceError::MappingError(
                    "batch item parent is None".to_string(),
                ))?;

            parent.as_ref().await?.claims.as_ref().await?.to_owned()
        }
    };

    let mut filtered_claims = Vec::with_capacity(claims.len());
    for claim in claims {
        if !claim.schema.as_ref().await?.metadata {
            filtered_claims.push(claim);
        }
    }
    let claims = filtered_claims;
    let state = value.state;

    let credential_format = schema_model.format().await?;
    let format_type = config
        .format
        .get_type(&credential_format)
        .error_while("getting format config")?;
    let mdoc_mso_validity = if format_type == FormatType::Mdoc
        && [
            CredentialStateEnum::Accepted,
            CredentialStateEnum::Suspended,
            CredentialStateEnum::Revoked,
        ]
        .contains(&value.state)
    {
        let params = config
            .format
            .get::<mdoc_formatter::Params, _>(&credential_format)
            .error_while("parsing formatter params")?;

        let issuance_date_with_expiry = match value.r#type {
            CredentialType::BatchItem => value.issuance_date.map(|i| (i, value.expires_at)),
            CredentialType::BatchParent => None,
            CredentialType::Single => {
                // use the latest item
                credential_repository
                    .get_credential_list(ListQuery {
                        pagination: Some(ListPagination {
                            page: 0,
                            page_size: 1,
                        }),
                        sorting: Some(ListSorting {
                            column: SortableCredentialColumn::CreatedDate,
                            direction: Some(SortDirection::Descending),
                        }),
                        filtering: Some(
                            CredentialFilterValue::ParentCredential(value.id).condition()
                                & CredentialFilterValue::Deleted(false),
                        ),
                        ..Default::default()
                    })
                    .await
                    .error_while("getting batch items")?
                    .values
                    .first()
                    .and_then(|c| c.issuance_date.map(|d| (d, c.expires_at)))
                    // fallback for legacy credentials
                    .or(Some((value.last_modified, None)))
            }
        };

        issuance_date_with_expiry.map(|(issuance_date, expiry)| MdocMsoValidityResponseDTO {
            expiration: expiry.unwrap_or(issuance_date + params.expiration_seconds),
            next_update: issuance_date + params.mso_expected_update_in_seconds,
            last_update: issuance_date,
        })
    } else {
        None
    };

    let issuer_certificate = match &value.issuer_certificate {
        None => None,
        Some(certificate) => Some(
            certificate_to_response_dto(certificate.as_ref().await?.to_owned())
                .await
                .error_while("converting certificate")?,
        ),
    };

    let holder = match &value.holder_identifier {
        None => None,
        Some(holder_identifier) => Some(holder_identifier.as_ref().await?.to_owned().into()),
    };

    let issuer = match &value.issuer_identifier {
        None => None,
        Some(issuer_identifier) => Some(issuer_identifier.as_ref().await?.to_owned().into()),
    };

    Ok(CredentialDetailResponseDTO {
        id: value.id,
        created_date: value.created_date,
        issuance_date: value.issuance_date,
        revocation_date: get_revocation_date(&state, &value.last_modified),
        expires_at: value.expires_at,
        consumed_at: value.consumed_at,
        state: state.into(),
        last_modified: value.last_modified,
        claims: from_vec_claim(claims, &schema_model, config).await?,
        schema: schema_dto,
        issuer,
        redirect_uri: value.redirect_uri,
        role: value.role.into(),
        r#type: value.r#type.into(),
        interaction_id: value.interaction.map(|i| i.id()),
        suspend_end_date: value.suspend_end_date,
        mdoc_mso_validity,
        holder,
        protocol: value.protocol,
        issuer_certificate,
        profile: value.profile,
        wallet_instance_attestation: attestation
            .wallet_instance_attestation_blob
            .map(TryInto::try_into)
            .transpose()?,
        wallet_unit_attestation: attestation
            .wallet_unit_attestation_blob
            .map(TryInto::try_into)
            .transpose()?,
        webhook_destination_url: value.webhook_url,
        trust_information,
        remaining_batch_item_count,
        parent_id: value.parent.map(|parent| parent.id()),
        subscriber_information: value.subscriber_information,
        ecosystem: value.ecosystem,
    })
}

async fn from_vec_claim(
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
        result = insert_claim(result, claim, &claim_schema_dtos, config).await?;
    }
    let mut claims = result;

    sort_claims(&mut claims);

    Ok(claims)
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

pub(super) async fn to_credential_list_response(
    credential: Credential,
    include_translations: bool,
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<CredentialListItemResponseDTO, CredentialServiceError> {
    let schema = credential.schema.as_ref().await?.to_owned();

    let issuer = match &credential.issuer_identifier {
        None => None,
        Some(issuer_identifier) => Some(issuer_identifier.as_ref().await?.to_owned().into()),
    };

    Ok(CredentialListItemResponseDTO {
        id: credential.id,
        created_date: credential.created_date,
        issuance_date: credential.issuance_date,
        revocation_date: get_revocation_date(&credential.state, &credential.last_modified),
        expires_at: credential.expires_at,
        consumed_at: credential.consumed_at,
        state: credential.state.into(),
        last_modified: credential.last_modified,
        schema: to_credential_schema_list_response(
            schema,
            include_translations,
            formatter_provider,
        )
        .await?,
        issuer,
        role: credential.role.into(),
        r#type: credential.r#type.into(),
        suspend_end_date: credential.suspend_end_date,
        protocol: credential.protocol,
        profile: credential.profile,
        webhook_destination_url: credential.webhook_url,
        parent_id: credential.parent.map(|parent| parent.id()),
        redirect_uri: credential.redirect_uri,
        ecosystem: credential.ecosystem,
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

pub(super) fn from_create_request(
    request: CreateCredentialRequestDTO,
    credential_id: CredentialId,
    claims: Vec<Claim>,
    issuer_identifier: Identifier,
    issuer_certificate: Option<Certificate>,
    schema: CredentialSchema,
    key: Key,
) -> Credential {
    let now = crate::clock::now_utc();
    let r#type = if schema.batch_size.is_some_and(|s| s >= 2) {
        CredentialType::BatchParent
    } else {
        CredentialType::Single
    };
    let expires_at = schema.expiration.map(|e| now + e);

    Credential {
        ecosystem: request.ecosystem,
        id: credential_id,
        created_date: now,
        issuance_date: None,
        expires_at,
        state: CredentialStateEnum::Created,
        suspend_end_date: None,
        last_modified: now,
        deleted_at: None,
        consumed_at: None,
        protocol: request.protocol,
        claims: claims.into(),
        issuer_identifier: Some(issuer_identifier.into()),
        issuer_certificate: issuer_certificate.map(Into::into),
        holder_identifier: None,
        schema: schema.into(),
        interaction: None,
        key: Some(key.into()),
        redirect_uri: request.redirect_uri,
        role: CredentialRole::Issuer,
        profile: request.profile,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: request.webhook_destination_url,
        r#type,
        parent: None,
        embedded_disclosure_policy: None,
        subscriber_information: request.subscriber_information,
    }
}

pub(super) fn claims_from_create_request(
    credential_id: CredentialId,
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
            credential_id,
            created_date: now,
            last_modified: now,
            value: Some(claim_dto.value),
            path: claim_dto.path.clone(),
            selectively_disclosable: false,
            schema: schema.clone().into(),
        };
        claims_map.insert(claim_dto.path.clone(), claim);
        let mut current_path = claim_dto.path;
        current_path =
            insert_array_parent(schema, credential_id, now, &mut claims_map, current_path)?;

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
                credential_id,
                created_date: now,
                last_modified: now,
                value: None,
                path: current_path.clone(),
                selectively_disclosable: false,
                schema: schema.clone().into(),
            };
            claims_map.insert(current_path.clone(), parent_claim);
            current_path =
                insert_array_parent(schema, credential_id, now, &mut claims_map, current_path)?;
            current_path_split = current_path.rsplit_once('/');
            current_schema_path = parent_schema_path.to_string();
        }
    }
    Ok(claims_map.into_values().collect())
}

fn insert_array_parent(
    schema: &ClaimSchema,
    credential_id: CredentialId,
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
                credential_id,
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
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<DetailCredentialSchemaResponseDTO, NestedError> {
    let format = credential_schema.format().await?.to_owned();
    let schema_id = credential_schema.schema_id().await?;
    let raw_translations = credential_schema.translations.as_ref().await?;
    let translations = CredentialSchemaTranslationsDTO {
        name: translations_to_i18n(&raw_translations, LocalizedTextField::Name).ok_or(
            CredentialServiceError::MappingError(format!(
                "No translations for `name` of credential schema {}",
                credential_schema.id
            ))
            .error_while("mapping credential schema"),
        )?,
        description: translations_to_i18n(&raw_translations, LocalizedTextField::Description),
    };

    let formatter = formatter_provider.get_credential_formatter(&format)?;

    Ok(DetailCredentialSchemaResponseDTO {
        id: credential_schema.id,
        created_date: credential_schema.created_date,
        deleted_at: credential_schema.deleted_at,
        last_modified: credential_schema.last_modified,
        imported_source_url: credential_schema.imported_source_url,
        name: credential_schema.name,
        format,
        revocation_method: formatter.revocation_method_id().cloned(),
        key_storage_security: credential_schema.key_storage_security,
        organisation_id: credential_schema.organisation.id(),
        schema_id,
        layout_type: credential_schema.layout_type.into(),
        layout_properties: credential_schema.layout_properties.map(Into::into),
        allow_suspension: credential_schema.allow_suspension,
        requires_wallet_instance_attestation: credential_schema
            .requires_wallet_instance_attestation,
        transaction_code: convert_inner(credential_schema.transaction_code),
        translations,
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
) -> Result<Option<u32>, CredentialServiceError> {
    Ok(
        if credential.r#type == CredentialType::BatchParent
            && credential.role == CredentialRole::Holder
        {
            Some(
                credential_repository
                    .get_credential_list(ListQuery {
                        filtering: Some(
                            CredentialFilterValue::ParentCredential(credential.id).condition()
                                & CredentialFilterValue::Consumed(false)
                                & CredentialFilterValue::Types(vec![CredentialType::BatchItem])
                                & CredentialFilterValue::States(vec![
                                    CredentialStateEnum::Accepted,
                                ])
                                & CredentialFilterValue::Deleted(false),
                        ),
                        ..Default::default()
                    })
                    .await
                    .error_while("listing batch items")?
                    .total_items as _,
            )
        } else {
            None
        },
    )
}

pub(super) async fn get_credential_trust_information(
    credential: &Credential,
    ecosystem_provider: &dyn EcosystemDirectory,
) -> Result<Option<TrustInformation>, CredentialServiceError> {
    Ok(match (credential.role, &credential.ecosystem) {
        (CredentialRole::Issuer, _) => None,
        (CredentialRole::Holder, None) => Some(TrustInformation {
            received_at: credential.issuance_date.unwrap_or(credential.last_modified),
            name: None,
            result: TrustResolutionResult::Untrusted,
        }),
        (CredentialRole::Holder, Some(ecosystem_id)) => {
            let ecosystem = ecosystem_provider.get(ecosystem_id)?;
            let details = ecosystem
                .issuer_trust_details(&credential.id)
                .await
                .error_while("getting trust detail")?;

            let name = match details.info {
                TrustDetailInfo::Eudi(info) => info.name,
            };
            Some(TrustInformation {
                received_at: details.received_at,
                name: Some(name),
                result: TrustResolutionResult::Trusted,
            })
        }
        (CredentialRole::Verifier, None) => None,
        (CredentialRole::Verifier, Some(_)) => Some(TrustInformation {
            received_at: credential.created_date,
            name: None,
            result: TrustResolutionResult::Trusted,
        }),
    })
}
