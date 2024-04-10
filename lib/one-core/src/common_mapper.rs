use crate::config::core_config::{CoreConfig, ExchangeType};
use crate::model::claim::{Claim, ClaimId};
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialState, CredentialStateEnum};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaClaim};
use crate::model::did::{Did, DidRelations, DidType};
use crate::model::organisation::Organisation;
use crate::provider::transport_protocol::openid4vc::OpenID4VCParams;
use crate::repository::did_repository::DidRepository;
use crate::service::error::BusinessLogicError;
use crate::{model::common::GetListResponse, service::error::ServiceError};
use dto_mapper::{convert_inner, try_convert_inner};
use serde::{Deserialize, Deserializer};
use shared_types::{CredentialId, DidId, DidValue};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub const NESTED_CLAIM_MARKER: char = '/';

pub(crate) fn remove_first_nesting_layer(name: &str) -> String {
    match name.find(NESTED_CLAIM_MARKER) {
        Some(marker_pos) => name[marker_pos + 1..].to_string(),
        None => name.to_string(),
    }
}

pub fn list_response_into<T, F: Into<T>>(input: GetListResponse<F>) -> GetListResponse<T> {
    GetListResponse::<T> {
        values: convert_inner(input.values),
        total_pages: input.total_pages,
        total_items: input.total_items,
    }
}

pub fn list_response_try_into<T, F: TryInto<T>>(
    input: GetListResponse<F>,
) -> Result<GetListResponse<T>, F::Error> {
    Ok(GetListResponse::<T> {
        values: try_convert_inner(input.values)?,
        total_pages: input.total_pages,
        total_items: input.total_items,
    })
}

pub(crate) fn get_exchange_param_pre_authorization_expires_in(
    config: &CoreConfig,
) -> Result<Duration, ServiceError> {
    let params: OpenID4VCParams = config.exchange.get_by_type(ExchangeType::OpenId4Vc)?;

    Ok(Duration::seconds(
        params.pre_authorized_code_expires_in as _,
    ))
}

pub(crate) fn get_exchange_param_token_expires_in(
    config: &CoreConfig,
) -> Result<Duration, ServiceError> {
    let params: OpenID4VCParams = config.exchange.get_by_type(ExchangeType::OpenId4Vc)?;

    Ok(Duration::seconds(params.token_expires_in as _))
}

pub(crate) async fn get_or_create_did(
    did_repository: &dyn DidRepository,
    organisation: &Option<Organisation>,
    holder_did_value: &DidValue,
) -> Result<Did, ServiceError> {
    Ok(
        match did_repository
            .get_did_by_value(holder_did_value, &DidRelations::default())
            .await?
        {
            Some(did) => did,
            None => {
                let id = Uuid::new_v4();
                let did_method = did_method_id_from_value(holder_did_value)?;
                let organisation = organisation.as_ref().ok_or(ServiceError::MappingError(
                    "organisation is None".to_string(),
                ))?;
                let did = Did {
                    id: DidId::from(id),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    name: format!("holder {id}"),
                    organisation: Some(organisation.to_owned()),
                    did: holder_did_value.to_owned(),
                    did_method,
                    did_type: DidType::Remote,
                    keys: None,
                    deactivated: false,
                };
                did_repository.create_did(did.clone()).await?;
                did
            }
        },
    )
}

pub(super) fn deserialize_with_serde_json<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: for<'a> Deserialize<'a>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value.as_str() {
        None => serde_json::from_value(value).map_err(serde::de::Error::custom),
        Some(buffer) => serde_json::from_str(buffer).map_err(serde::de::Error::custom),
    }
}

pub(super) fn did_method_id_from_value(did_value: &DidValue) -> Result<String, ServiceError> {
    let mut parts = did_value.as_str().splitn(3, ':');

    let did_method = parts.nth(1).ok_or(ServiceError::ValidationError(
        "Did method not found".to_string(),
    ))?;
    Ok(did_method.to_uppercase())
}

fn object_to_model_claims(
    credential_id: CredentialId,
    claim_schemas: &[CredentialSchemaClaim],
    object: &serde_json::Map<String, serde_json::Value>,
    now: OffsetDateTime,
    prefix: &str,
) -> Result<Vec<Claim>, ServiceError> {
    let mut model_claims = vec![];

    for (key, value) in object {
        let schema_name = format!("{prefix}/{key}");

        match value.as_str() {
            None => {
                let value_as_object = value.as_object().ok_or(ServiceError::MappingError(
                    "value is not an Object".to_string(),
                ))?;
                model_claims.extend(object_to_model_claims(
                    credential_id,
                    claim_schemas,
                    value_as_object,
                    now,
                    &schema_name,
                )?);
            }
            Some(value) => {
                let claim_schema = claim_schemas
                    .iter()
                    .find(|claim_schema| *claim_schema.schema.key == schema_name)
                    .ok_or(ServiceError::BusinessLogic(
                        BusinessLogicError::MissingClaimSchemas,
                    ))?;

                model_claims.push(Claim {
                    id: ClaimId::new_v4(),
                    credential_id,
                    created_date: now,
                    last_modified: now,
                    value: value.to_string(),
                    schema: Some(claim_schema.schema.to_owned()),
                });
            }
        }
    }

    Ok(model_claims)
}

pub fn extracted_credential_to_model(
    claim_schemas: &[CredentialSchemaClaim],
    credential_schema: CredentialSchema,
    claims: Vec<(serde_json::Value, ClaimSchema)>,
    issuer_did: Did,
    holder_did: Did,
) -> Result<Credential, ServiceError> {
    let now = OffsetDateTime::now_utc();
    let credential_id = Uuid::new_v4().into();

    let mut model_claims = vec![];
    for (value, claim_schema) in claims {
        match value.as_str() {
            None => {
                let value_as_object = value.as_object().ok_or(ServiceError::MappingError(
                    "value is not an Object".to_string(),
                ))?;
                model_claims.extend(object_to_model_claims(
                    credential_id,
                    claim_schemas,
                    value_as_object,
                    now,
                    &claim_schema.key,
                )?);
            }
            Some(value) => {
                model_claims.push(Claim {
                    id: ClaimId::new_v4(),
                    credential_id,
                    created_date: now,
                    last_modified: now,
                    value: value.to_string(),
                    schema: Some(claim_schema),
                });
            }
        }
    }

    Ok(Credential {
        id: credential_id,
        created_date: now,
        issuance_date: now,
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        transport: "PROCIVIS_TEMPORARY".to_string(),
        state: Some(vec![CredentialState {
            created_date: now,
            state: CredentialStateEnum::Accepted,
            suspend_end_date: None,
        }]),
        claims: Some(model_claims),
        issuer_did: Some(issuer_did),
        holder_did: Some(holder_did),
        schema: Some(credential_schema),
        redirect_uri: None,
        interaction: None,
        revocation_list: None,
        key: None,
        role: CredentialRole::Verifier,
    })
}
