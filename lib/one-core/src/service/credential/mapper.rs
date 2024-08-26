use dto_mapper::convert_inner;
use one_providers::common_models::key::OpenKey;
use one_providers::revocation::model::CredentialRevocationState;
use shared_types::CredentialId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::CredentialSchemaType;
use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::config::core_config::{CoreConfig, DatatypeType};
use crate::model::claim::Claim;
use crate::model::credential::{Credential, CredentialRole, CredentialState, CredentialStateEnum};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaClaim};
use crate::model::did::Did;
use crate::service::credential::dto::{
    CreateCredentialRequestDTO, CredentialDetailResponseDTO, CredentialListItemResponseDTO,
    CredentialRequestClaimDTO, DetailCredentialClaimResponseDTO,
    DetailCredentialClaimValueResponseDTO, DetailCredentialSchemaResponseDTO,
};
use crate::service::error::{BusinessLogicError, ServiceError};

pub fn credential_detail_response_from_model(
    value: Credential,
    config: &CoreConfig,
) -> Result<CredentialDetailResponseDTO, ServiceError> {
    let schema = value.schema.ok_or(ServiceError::MappingError(
        "credential_schema is None".to_string(),
    ))?;

    let claims = value
        .claims
        .ok_or(ServiceError::MappingError("claims is None".to_string()))?;
    let states = value
        .state
        .ok_or(ServiceError::MappingError("state is None".to_string()))?;
    let latest_state = states
        .first()
        .ok_or(ServiceError::MappingError(
            "latest state not found".to_string(),
        ))?
        .to_owned();

    Ok(CredentialDetailResponseDTO {
        id: value.id,
        created_date: value.created_date,
        issuance_date: value.issuance_date,
        revocation_date: get_revocation_date(&latest_state),
        state: latest_state.state.into(),
        last_modified: value.last_modified,
        claims: from_vec_claim(claims, &schema, config)?,
        schema: schema.try_into()?,
        issuer_did: convert_inner(value.issuer_did),
        redirect_uri: value.redirect_uri,
        role: value.role.into(),
        lvvc_issuance_date: None,
        suspend_end_date: latest_state.suspend_end_date,
    })
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
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
            wallet_storage_type: value.wallet_storage_type,
            organisation_id,
            schema_type: value.schema_type.into(),
            schema_id: value.schema_id,
            layout_type: value.layout_type.into(),
            layout_properties: convert_inner(value.layout_properties),
        })
    }
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
                    ))
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

        let states = value
            .state
            .ok_or(ServiceError::MappingError("state is None".to_string()))?;
        let latest_state = states
            .first()
            .ok_or(ServiceError::MappingError(
                "latest state not found".to_string(),
            ))?
            .to_owned();

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            issuance_date: value.issuance_date,
            revocation_date: get_revocation_date(&latest_state),
            state: latest_state.state.into(),
            last_modified: value.last_modified,
            schema: schema.into(),
            issuer_did: convert_inner(value.issuer_did),
            credential: value.credential,
            role: value.role.into(),
            suspend_end_date: latest_state.suspend_end_date,
        })
    }
}

fn get_revocation_date(latest_state: &CredentialState) -> Option<OffsetDateTime> {
    if latest_state.state == CredentialStateEnum::Revoked {
        Some(latest_state.created_date)
    } else {
        None
    }
}

pub(super) fn from_create_request(
    request: CreateCredentialRequestDTO,
    credential_id: CredentialId,
    claims: Vec<Claim>,
    issuer_did: Did,
    schema: CredentialSchema,
    key: OpenKey,
) -> Credential {
    let now = OffsetDateTime::now_utc();

    Credential {
        id: credential_id,
        created_date: now,
        issuance_date: now,
        state: Some(vec![CredentialState {
            created_date: now,
            state: CredentialStateEnum::Created,
            suspend_end_date: None,
        }]),
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        exchange: request.exchange,
        claims: Some(claims),
        issuer_did: Some(issuer_did),
        holder_did: None,
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

impl From<one_providers::common_models::credential::OpenCredentialStateEnum>
    for crate::service::credential::dto::CredentialStateEnum
{
    fn from(value: one_providers::common_models::credential::OpenCredentialStateEnum) -> Self {
        match value {
            one_providers::common_models::credential::OpenCredentialStateEnum::Created => {
                Self::Created
            }
            one_providers::common_models::credential::OpenCredentialStateEnum::Pending => {
                Self::Pending
            }
            one_providers::common_models::credential::OpenCredentialStateEnum::Offered => {
                Self::Offered
            }
            one_providers::common_models::credential::OpenCredentialStateEnum::Accepted => {
                Self::Accepted
            }
            one_providers::common_models::credential::OpenCredentialStateEnum::Rejected => {
                Self::Rejected
            }
            one_providers::common_models::credential::OpenCredentialStateEnum::Revoked => {
                Self::Revoked
            }
            one_providers::common_models::credential::OpenCredentialStateEnum::Suspended => {
                Self::Suspended
            }
            one_providers::common_models::credential::OpenCredentialStateEnum::Error => Self::Error,
        }
    }
}

impl From<crate::service::credential::dto::CredentialStateEnum>
    for one_providers::common_models::credential::OpenCredentialStateEnum
{
    fn from(value: crate::service::credential::dto::CredentialStateEnum) -> Self {
        match value {
            crate::service::credential::dto::CredentialStateEnum::Created => Self::Created,
            crate::service::credential::dto::CredentialStateEnum::Pending => Self::Pending,
            crate::service::credential::dto::CredentialStateEnum::Offered => Self::Offered,
            crate::service::credential::dto::CredentialStateEnum::Accepted => Self::Accepted,
            crate::service::credential::dto::CredentialStateEnum::Rejected => Self::Rejected,
            crate::service::credential::dto::CredentialStateEnum::Revoked => Self::Revoked,
            crate::service::credential::dto::CredentialStateEnum::Suspended => Self::Suspended,
            crate::service::credential::dto::CredentialStateEnum::Error => Self::Error,
        }
    }
}

impl From<String> for CredentialSchemaType {
    fn from(value: String) -> Self {
        match value.as_str() {
            "ProcivisOneSchema2024" => CredentialSchemaType::ProcivisOneSchema2024,
            "FallbackSchema2024" => CredentialSchemaType::FallbackSchema2024,
            "mdoc" => CredentialSchemaType::Mdoc,
            _ => Self::Other(value),
        }
    }
}

impl From<one_providers::common_models::credential::OpenCredentialRole>
    for super::dto::CredentialRole
{
    fn from(value: one_providers::common_models::credential::OpenCredentialRole) -> Self {
        match value {
            one_providers::common_models::credential::OpenCredentialRole::Holder => Self::Holder,
            one_providers::common_models::credential::OpenCredentialRole::Issuer => Self::Issuer,
            one_providers::common_models::credential::OpenCredentialRole::Verifier => {
                Self::Verifier
            }
        }
    }
}

impl From<super::dto::CredentialRole>
    for one_providers::common_models::credential::OpenCredentialRole
{
    fn from(value: super::dto::CredentialRole) -> Self {
        match value {
            super::dto::CredentialRole::Holder => Self::Holder,
            super::dto::CredentialRole::Issuer => Self::Issuer,
            super::dto::CredentialRole::Verifier => Self::Verifier,
        }
    }
}

impl From<crate::service::credential_schema::dto::CredentialSchemaLayoutPropertiesRequestDTO> for one_providers::exchange_protocol::openid4vc::model::CredentialSchemaLayoutPropertiesRequestDTO {
    fn from(value: crate::service::credential_schema::dto::CredentialSchemaLayoutPropertiesRequestDTO) -> Self {
        Self {
            background: convert_inner(value.background),
            logo: convert_inner(value.logo),
            primary_attribute: value.primary_attribute,
            secondary_attribute: value.secondary_attribute,
            picture_attribute: value.picture_attribute,
            code: convert_inner(value.code),
        }
    }
}

impl From<crate::service::credential_schema::dto::CredentialSchemaBackgroundPropertiesRequestDTO> for one_providers::exchange_protocol::openid4vc::model::CredentialSchemaBackgroundPropertiesRequestDTO {
    fn from(value: crate::service::credential_schema::dto::CredentialSchemaBackgroundPropertiesRequestDTO) -> Self {
        Self {
            color: value.color,
            image: value.image,
        }
    }
}

impl From<crate::service::credential_schema::dto::CredentialSchemaLogoPropertiesRequestDTO>
    for one_providers::exchange_protocol::openid4vc::model::CredentialSchemaLogoPropertiesRequestDTO
{
    fn from(
        value: crate::service::credential_schema::dto::CredentialSchemaLogoPropertiesRequestDTO,
    ) -> Self {
        Self {
            font_color: value.font_color,
            background_color: value.background_color,
            image: value.image,
        }
    }
}

impl From<crate::service::credential_schema::dto::CredentialSchemaCodePropertiesRequestDTO>
    for one_providers::exchange_protocol::openid4vc::model::CredentialSchemaCodePropertiesRequestDTO
{
    fn from(
        value: crate::service::credential_schema::dto::CredentialSchemaCodePropertiesRequestDTO,
    ) -> Self {
        Self {
            attribute: value.attribute,
            r#type: value.r#type.into(),
        }
    }
}

impl From<crate::service::credential_schema::dto::CredentialSchemaCodeTypeEnum>
    for one_providers::exchange_protocol::openid4vc::model::CredentialSchemaCodeTypeEnum
{
    fn from(value: crate::service::credential_schema::dto::CredentialSchemaCodeTypeEnum) -> Self {
        match value {
            crate::service::credential_schema::dto::CredentialSchemaCodeTypeEnum::Barcode => {
                Self::Barcode
            }
            crate::service::credential_schema::dto::CredentialSchemaCodeTypeEnum::Mrz => Self::Mrz,
            crate::service::credential_schema::dto::CredentialSchemaCodeTypeEnum::QrCode => {
                Self::QrCode
            }
        }
    }
}
