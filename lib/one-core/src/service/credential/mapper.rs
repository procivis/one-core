use one_dto_mapper::convert_inner;
use shared_types::CredentialId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{CredentialSchemaType, DetailCredentialSchemaResponseDTO};
use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::config::core_config::{CoreConfig, DatatypeType};
use crate::model::claim::Claim;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaClaim};
use crate::model::identifier::Identifier;
use crate::model::key::Key;
use crate::model::validity_credential::ValidityCredential;
use crate::provider::credential_formatter::mdoc_formatter;
use crate::provider::revocation::model::CredentialRevocationState;
use crate::service::credential::dto::{
    CreateCredentialRequestDTO, CredentialDetailResponseDTO, CredentialListItemResponseDTO,
    CredentialRequestClaimDTO, DetailCredentialClaimResponseDTO,
    DetailCredentialClaimValueResponseDTO, MdocMsoValidityResponseDTO,
};
use crate::service::error::{BusinessLogicError, ServiceError};

pub fn credential_detail_response_from_model(
    value: Credential,
    config: &CoreConfig,
    validity_credential: Option<ValidityCredential>,
) -> Result<CredentialDetailResponseDTO, ServiceError> {
    let schema = value.schema.ok_or(ServiceError::MappingError(
        "credential_schema is None".to_string(),
    ))?;

    let claims = value
        .claims
        .ok_or(ServiceError::MappingError("claims is None".to_string()))?;
    let state = value.state;

    let mdoc_mso_validity = if let Some(validity_credential) = validity_credential {
        let params = config.format.get::<mdoc_formatter::Params>("MDOC")?;
        Some(MdocMsoValidityResponseDTO {
            expiration: validity_credential.created_date + params.mso_expires_in,
            next_update: validity_credential.created_date + params.mso_expected_update_in,
            last_update: validity_credential.created_date,
        })
    } else {
        None
    };

    let issuer_did = value
        .issuer_identifier
        .as_ref()
        .and_then(|identifier| identifier.did.to_owned());

    let holder_did = value
        .holder_identifier
        .as_ref()
        .and_then(|identifier| identifier.did.to_owned());

    Ok(CredentialDetailResponseDTO {
        id: value.id,
        created_date: value.created_date,
        issuance_date: value.issuance_date,
        revocation_date: get_revocation_date(&state, &value.last_modified),
        state: state.into(),
        last_modified: value.last_modified,
        claims: from_vec_claim(claims, &schema, config)?,
        schema: schema.try_into()?,
        issuer_did: convert_inner(issuer_did),
        issuer: convert_inner(value.issuer_identifier),
        redirect_uri: value.redirect_uri,
        role: value.role.into(),
        lvvc_issuance_date: None,
        suspend_end_date: value.suspend_end_date,
        mdoc_mso_validity,
        holder_did: convert_inner(holder_did),
        holder: convert_inner(value.holder_identifier),
        exchange: value.exchange,
    })
}

pub(crate) fn from_vec_claim(
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
    match claim.path.rsplit_once(NESTED_CLAIM_MARKER) {
        Some((head, _)) => {
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
        None => {
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
                        Ok(&mut claims[i])
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
                        Ok(&mut claims[last])
                    }
                }
                _ => Err(ServiceError::MappingError(
                    "Parent claim should be nested".into(),
                )),
            }
        }
        None => {
            if let Some(i) = root.iter().position(|claim| claim.schema.key == path) {
                Ok(&mut root[i])
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
                Ok(&mut root[last])
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
    let value = match config
        .datatype
        .get_fields(&claim_schema.schema.data_type)?
        .r#type
    {
        DatatypeType::Number => {
            if let Ok(number) = claim.value.parse::<i64>() {
                DetailCredentialClaimValueResponseDTO::Integer(number)
            } else {
                DetailCredentialClaimValueResponseDTO::Float(
                    claim
                        .value
                        .parse::<f64>()
                        .map_err(|e| ServiceError::MappingError(e.to_string()))?,
                )
            }
        }
        DatatypeType::Boolean => DetailCredentialClaimValueResponseDTO::Boolean(
            claim
                .value
                .parse::<bool>()
                .map_err(|e| ServiceError::MappingError(e.to_string()))?,
        ),
        _ => DetailCredentialClaimValueResponseDTO::String(claim.value.to_owned()),
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

        let state = value.state;

        let issuer_did = value
            .issuer_identifier
            .as_ref()
            .and_then(|identifier| identifier.did.to_owned());

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            issuance_date: value.issuance_date,
            revocation_date: get_revocation_date(&state, &value.last_modified),
            state: state.into(),
            last_modified: value.last_modified,
            schema: schema.into(),
            issuer_did: convert_inner(issuer_did),
            issuer: convert_inner(value.issuer_identifier),
            credential: value.credential,
            role: value.role.into(),
            suspend_end_date: value.suspend_end_date,
            exchange: value.exchange,
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
    schema: CredentialSchema,
    key: Key,
) -> Credential {
    let now = OffsetDateTime::now_utc();

    Credential {
        id: credential_id,
        created_date: now,
        issuance_date: now,
        state: CredentialStateEnum::Created,
        suspend_end_date: None,
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        exchange: request.exchange,
        claims: Some(claims),
        issuer_identifier: Some(issuer_identifier),
        holder_identifier: None,
        schema: Some(schema),
        interaction: None,
        revocation_list: None,
        key: Some(key),
        redirect_uri: request.redirect_uri,
        role: CredentialRole::Issuer,
    }
}

pub(super) fn claims_from_create_request(
    credential_id: CredentialId,
    claims: Vec<CredentialRequestClaimDTO>,
    claim_schemas: &[CredentialSchemaClaim],
) -> Result<Vec<Claim>, ServiceError> {
    let now = OffsetDateTime::now_utc();

    claims
        .into_iter()
        .map(|claim| {
            let claim_schema_id = claim.claim_schema_id;
            let schema = claim_schemas
                .iter()
                .find(|schema| schema.schema.id == claim_schema_id)
                .ok_or(BusinessLogicError::MissingClaimSchema { claim_schema_id })?;
            Ok(Claim {
                id: Uuid::new_v4(),
                credential_id,
                created_date: now,
                last_modified: now,
                value: claim.value,
                path: claim.path,
                schema: Some(schema.schema.clone()),
            })
        })
        .collect::<Result<Vec<_>, _>>()
}

pub(super) fn credential_revocation_state_to_model_state(
    revocation_state: CredentialRevocationState,
) -> CredentialStateEnum {
    match revocation_state {
        CredentialRevocationState::Revoked => CredentialStateEnum::Revoked,
        CredentialRevocationState::Valid => CredentialStateEnum::Accepted,
        CredentialRevocationState::Suspended { .. } => CredentialStateEnum::Suspended,
    }
}

impl From<String> for CredentialSchemaType {
    fn from(value: String) -> Self {
        match value.as_str() {
            "ProcivisOneSchema2024" => CredentialSchemaType::ProcivisOneSchema2024,
            "FallbackSchema2024" => CredentialSchemaType::FallbackSchema2024,
            "SdJwtVc" => CredentialSchemaType::SdJwtVc,
            "mdoc" => CredentialSchemaType::Mdoc,
            _ => Self::Other(value),
        }
    }
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
            external_schema: value.external_schema,
            format: value.format,
            revocation_method: value.revocation_method,
            wallet_storage_type: value.wallet_storage_type,
            organisation_id,
            schema_type: value.schema_type.into(),
            schema_id: value.schema_id,
            layout_type: value.layout_type.into(),
            layout_properties: value.layout_properties.map(Into::into),
            allow_suspension: value.allow_suspension,
        })
    }
}
