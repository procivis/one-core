use std::collections::HashMap;

use one_dto_mapper::convert_inner;
use shared_types::CredentialId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    CredentialAttestationBlobs, DetailCredentialSchemaResponseDTO, WalletAppAttestationDTO,
    WalletUnitAttestationDTO,
};
use crate::config::core_config::{CoreConfig, DatatypeType};
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::model::blob::{Blob, BlobType};
use crate::model::certificate::Certificate;
use crate::model::claim::Claim;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaClaim};
use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::key::Key;
use crate::model::validity_credential::ValidityCredential;
use crate::provider::credential_formatter::mdoc_formatter;
use crate::provider::credential_formatter::model::{CertificateDetails, IdentifierDetails};
use crate::service::credential::dto::{
    CreateCredentialRequestDTO, CredentialDetailResponseDTO, CredentialListItemResponseDTO,
    CredentialRequestClaimDTO, DetailCredentialClaimResponseDTO,
    DetailCredentialClaimValueResponseDTO, MdocMsoValidityResponseDTO,
};
use crate::service::error::{BusinessLogicError, ServiceError};

pub(crate) fn credential_detail_response_from_model(
    value: Credential,
    config: &CoreConfig,
    validity_credential: Option<ValidityCredential>,
    attestation: CredentialAttestationBlobs,
) -> Result<CredentialDetailResponseDTO<DetailCredentialClaimResponseDTO>, ServiceError> {
    let schema = value.schema.ok_or(ServiceError::MappingError(
        "credential_schema is None".to_string(),
    ))?;

    let claims = value
        .claims
        .ok_or(ServiceError::MappingError("claims is None".to_string()))?
        .into_iter()
        .filter(|claim| !claim.schema.as_ref().is_some_and(|s| s.metadata))
        .collect();
    let state = value.state;

    let mdoc_mso_validity = if let Some(validity_credential) = validity_credential {
        let params = config
            .format
            .get::<mdoc_formatter::Params, _>(&"MDOC".into())?;
        Some(MdocMsoValidityResponseDTO {
            expiration: validity_credential.created_date + params.mso_expires_in,
            next_update: validity_credential.created_date + params.mso_expected_update_in,
            last_update: validity_credential.created_date,
        })
    } else {
        None
    };

    let issuer_certificate = value
        .issuer_certificate
        .clone()
        .map(TryInto::try_into)
        .transpose()?;

    Ok(CredentialDetailResponseDTO {
        id: value.id,
        created_date: value.created_date,
        issuance_date: value.issuance_date,
        revocation_date: get_revocation_date(&state, &value.last_modified),
        state: state.into(),
        last_modified: value.last_modified,
        claims: from_vec_claim(claims, &schema, config)?,
        schema: schema.try_into()?,
        issuer: convert_inner(value.issuer_identifier),
        redirect_uri: value.redirect_uri,
        role: value.role.into(),
        lvvc_issuance_date: None,
        suspend_end_date: value.suspend_end_date,
        mdoc_mso_validity,
        holder: convert_inner(value.holder_identifier),
        protocol: value.protocol,
        issuer_certificate,
        profile: value.profile,
        wallet_app_attestation: attestation
            .wallet_app_attestation_blob
            .map(TryInto::try_into)
            .transpose()?,
        wallet_unit_attestation: attestation
            .wallet_unit_attestation_blob
            .map(TryInto::try_into)
            .transpose()?,
    })
}

fn from_vec_claim(
    claims: Vec<Claim>,
    credential_schema: &CredentialSchema,
    config: &CoreConfig,
) -> Result<Vec<DetailCredentialClaimResponseDTO>, ServiceError> {
    let claim_schemas =
        credential_schema
            .claim_schemas
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "claim_schemas is None".to_string(),
            ))?;

    let mut claims = claims.into_iter().try_fold(vec![], |state, claim| {
        insert_claim(state, claim, claim_schemas, config)
    })?;

    sort_claims(&mut claims);

    Ok(claims)
}

fn insert_claim(
    mut root: Vec<DetailCredentialClaimResponseDTO>,
    claim: Claim,
    claim_schemas: &[CredentialSchemaClaim],
    config: &CoreConfig,
) -> Result<Vec<DetailCredentialClaimResponseDTO>, ServiceError> {
    match (claim.path.rsplit_once(NESTED_CLAIM_MARKER), &claim.value) {
        (Some((head, _)), Some(_)) => {
            let parent_claim = get_or_insert(&mut root, head, claim_schemas)?;

            match &mut parent_claim.value {
                DetailCredentialClaimValueResponseDTO::Nested(claims) => {
                    let claim_schema = claim
                        .schema
                        .as_ref()
                        .ok_or_else(|| ServiceError::Other("claim.schema is missing".into()))?;

                    let mut credential_claim_schema = claim_schemas
                        .iter()
                        .find(|value| value.schema.key == claim_schema.key)
                        .ok_or_else(|| ServiceError::Other("claim.schema is unknown".into()))?
                        .clone();

                    if parent_claim.schema.array {
                        credential_claim_schema.schema.array = false;
                    }

                    claims.push(claim_to_dto(&claim, &credential_claim_schema, config)?);
                }
                _ => {
                    return Err(ServiceError::MappingError(
                        "Parent claim should be nested".into(),
                    ));
                }
            }
        }
        (None, Some(_)) => {
            let claim_schema = claim
                .schema
                .as_ref()
                .ok_or_else(|| ServiceError::Other("claim.schema is missing".into()))?;

            let claim_schema = claim_schemas
                .iter()
                .find(|value| value.schema.key == claim_schema.key)
                .ok_or_else(|| ServiceError::Other("claim.schema is unknown".into()))?;

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
    claim_schemas: &[CredentialSchemaClaim],
) -> Result<&'a mut DetailCredentialClaimResponseDTO, ServiceError> {
    match path.rsplit_once(NESTED_CLAIM_MARKER) {
        Some((head, _)) => {
            let parent_claim = get_or_insert(root, head, claim_schemas)?;
            let key = from_path_to_key(parent_claim, path)?;

            match &mut parent_claim.value {
                DetailCredentialClaimValueResponseDTO::Nested(claims) => {
                    if let Some(i) = claims.iter().position(|claim| claim.path == path) {
                        Ok(claims
                            .get_mut(i)
                            .ok_or_else(|| ServiceError::Other("invalid index".into()))?)
                    } else {
                        let mut item_schema = claim_schemas
                            .iter()
                            .find(|schema| schema.schema.key == key)
                            .ok_or_else(|| ServiceError::Other("missing claim schema".into()))?
                            .to_owned();

                        if parent_claim.schema.array {
                            item_schema.schema.array = false;
                        }

                        claims.push(DetailCredentialClaimResponseDTO {
                            path: path.to_owned(),
                            schema: item_schema.into(),
                            value: DetailCredentialClaimValueResponseDTO::Nested(vec![]),
                        });
                        let last = claims.len() - 1;
                        Ok(claims
                            .get_mut(last)
                            .ok_or_else(|| ServiceError::Other("invalid index".into()))?)
                    }
                }
                _ => Err(ServiceError::MappingError(
                    "Parent claim should be nested".into(),
                )),
            }
        }
        None => {
            if let Some(i) = root.iter().position(|claim| claim.schema.key == path) {
                Ok(root
                    .get_mut(i)
                    .ok_or_else(|| ServiceError::Other("invalid index".into()))?)
            } else {
                root.push(DetailCredentialClaimResponseDTO {
                    path: path.to_owned(),
                    schema: claim_schemas
                        .iter()
                        .find(|schema| schema.schema.key == path)
                        .ok_or_else(|| ServiceError::Other("missing claim schema".into()))?
                        .to_owned()
                        .into(),
                    value: DetailCredentialClaimValueResponseDTO::Nested(vec![]),
                });
                let last = root.len() - 1;
                Ok(root
                    .get_mut(last)
                    .ok_or_else(|| ServiceError::Other("invalid index".into()))?)
            }
        }
    }
}

fn from_path_to_key(
    parent: &DetailCredentialClaimResponseDTO,
    path: &str,
) -> Result<String, ServiceError> {
    if parent.schema.array {
        return Ok(parent.schema.key.clone());
    }

    let suffix = path
        .strip_prefix(&parent.path)
        .ok_or_else(|| ServiceError::Other("invalid path".into()))?;

    Ok(format!("{}{suffix}", parent.schema.key))
}

fn claim_to_dto(
    claim: &Claim,
    claim_schema: &CredentialSchemaClaim,
    config: &CoreConfig,
) -> Result<DetailCredentialClaimResponseDTO, ServiceError> {
    let claim_value = claim
        .value
        .as_ref()
        .ok_or(ServiceError::MappingError(format!(
            "Missing value on leaf claim: {}",
            claim.id
        )))?;
    let value = match config
        .datatype
        .get_fields(&claim_schema.schema.data_type)?
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
        schema: claim_schema.to_owned().into(),
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

impl TryFrom<Credential> for CredentialListItemResponseDTO {
    type Error = ServiceError;

    fn try_from(value: Credential) -> Result<Self, ServiceError> {
        let schema = value.schema.ok_or(ServiceError::MappingError(
            "credential_schema is None".to_string(),
        ))?;

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            issuance_date: value.issuance_date,
            revocation_date: get_revocation_date(&value.state, &value.last_modified),
            state: value.state.into(),
            last_modified: value.last_modified,
            schema: schema.into(),
            issuer: convert_inner(value.issuer_identifier),
            role: value.role.into(),
            suspend_end_date: value.suspend_end_date,
            protocol: value.protocol,
            profile: value.profile,
        })
    }
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
    let now = OffsetDateTime::now_utc();

    Credential {
        id: credential_id,
        created_date: now,
        issuance_date: None,
        state: CredentialStateEnum::Created,
        suspend_end_date: None,
        last_modified: now,
        deleted_at: None,
        protocol: request.protocol,
        claims: Some(claims),
        issuer_identifier: Some(issuer_identifier),
        issuer_certificate,
        holder_identifier: None,
        schema: Some(schema),
        interaction: None,
        key: Some(key),
        redirect_uri: request.redirect_uri,
        role: CredentialRole::Issuer,
        profile: request.profile,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_app_attestation_blob_id: None,
    }
}

pub(super) fn get_issuer_details(
    issuer_identifier: &Identifier,
) -> Result<IdentifierDetails, ServiceError> {
    Ok(match issuer_identifier.r#type {
        IdentifierType::Did => {
            let issuer_did = issuer_identifier
                .did
                .as_ref()
                .ok_or(ServiceError::MappingError("issuer_did is None".to_string()))?;

            IdentifierDetails::Did(issuer_did.did.clone())
        }
        IdentifierType::Certificate => {
            let certificate = issuer_identifier
                .certificates
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "issuer certificates is None".to_string(),
                ))?
                .first()
                .ok_or(ServiceError::MappingError(
                    "issuer certificate is missing".to_string(),
                ))?
                .to_owned();

            IdentifierDetails::Certificate(CertificateDetails {
                chain: certificate.chain,
                fingerprint: certificate.fingerprint,
                expiry: certificate.expiry_date,
                subject_common_name: None,
            })
        }
        _ => {
            return Err(BusinessLogicError::IncompatibleIssuanceIdentifier.into());
        }
    })
}

pub(super) fn claims_from_create_request(
    credential_id: CredentialId,
    claims: Vec<CredentialRequestClaimDTO>,
    claim_schemas: &[CredentialSchemaClaim],
) -> Result<Vec<Claim>, ServiceError> {
    let now = OffsetDateTime::now_utc();
    let mut claims_map = HashMap::<String, Claim>::new();

    for claim_dto in claims {
        let claim_schema_id = claim_dto.claim_schema_id;
        let schema = claim_schemas
            .iter()
            .find(|schema| schema.schema.id == claim_schema_id)
            .ok_or(BusinessLogicError::MissingClaimSchema { claim_schema_id })?;
        let claim = Claim {
            id: Uuid::new_v4().into(),
            credential_id,
            created_date: now,
            last_modified: now,
            value: Some(claim_dto.value),
            path: claim_dto.path.clone(),
            selectively_disclosable: false,
            schema: Some(schema.schema.clone()),
        };
        claims_map.insert(claim_dto.path.clone(), claim);
        let mut current_path = claim_dto.path;
        current_path =
            insert_array_parent(schema, credential_id, now, &mut claims_map, current_path)?;

        let mut current_schema_path = schema.schema.key.clone();
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
                return Err(ServiceError::MappingError(format!(
                    "Expected schema path '{current_schema_path}' to contain nested property",
                )));
            };
            let schema = claim_schemas
                .iter()
                .find(|schema| schema.schema.key == parent_schema_path)
                .ok_or(ServiceError::MappingError(format!(
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
                schema: Some(schema.schema.clone()),
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
    schema: &CredentialSchemaClaim,
    credential_id: CredentialId,
    now: OffsetDateTime,
    claims_map: &mut HashMap<String, Claim>,
    current_path: String,
) -> Result<String, ServiceError> {
    if schema.schema.array {
        let Some((array_path, _)) = current_path.rsplit_once("/") else {
            return Err(ServiceError::MappingError(format!(
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
                schema: Some(schema.schema.clone()),
            };
            claims_map.insert(array_path.to_owned(), parent_claim);
        }
        return Ok(array_path.to_owned());
    }
    Ok(current_path)
}

impl TryFrom<CredentialSchema> for DetailCredentialSchemaResponseDTO {
    type Error = ServiceError;

    fn try_from(value: CredentialSchema) -> Result<Self, Self::Error> {
        let organisation_id = match value.organisation {
            None => Err(ServiceError::MappingError(
                "Organisation has not been fetched".to_string(),
            )),
            Some(value) => Ok(value.id),
        }?;

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            deleted_at: value.deleted_at,
            last_modified: value.last_modified,
            imported_source_url: value.imported_source_url,
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
            key_storage_security: value.key_storage_security,
            organisation_id,
            schema_id: value.schema_id,
            layout_type: value.layout_type.into(),
            layout_properties: value.layout_properties.map(Into::into),
            allow_suspension: value.allow_suspension,
        })
    }
}

impl TryFrom<Blob> for WalletAppAttestationDTO {
    type Error = ServiceError;

    fn try_from(value: Blob) -> Result<Self, Self::Error> {
        if value.r#type != BlobType::WalletAppAttestation {
            return Err(ServiceError::MappingError(format!(
                "Failed to parse parse wallet app attestation blob of type: {:?}",
                value.r#type
            )));
        }
        let wallet_app_attestation = serde_json::from_slice(&value.value).map_err(|e| {
            ServiceError::MappingError(format!("Failed to parse wallet app attestation blob: {e}"))
        })?;
        Ok(wallet_app_attestation)
    }
}

impl TryFrom<Blob> for WalletUnitAttestationDTO {
    type Error = ServiceError;

    fn try_from(value: Blob) -> Result<Self, Self::Error> {
        if value.r#type != BlobType::WalletUnitAttestation {
            return Err(ServiceError::MappingError(format!(
                "Failed to parse parse wallet unit attestation blob of type: {:?}",
                value.r#type
            )));
        }
        let wallet_unit_attestation = serde_json::from_slice(&value.value).map_err(|e| {
            ServiceError::MappingError(format!("Failed to parse wallet unit attestation blob: {e}"))
        })?;
        Ok(wallet_unit_attestation)
    }
}
