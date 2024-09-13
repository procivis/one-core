use std::any::type_name;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use dto_mapper::{convert_inner, try_convert_inner};
use one_providers::common_models::OpenPublicKeyJwk;
use one_providers::credential_formatter::error::FormatterError;
use one_providers::exchange_protocol::openid4vc::imp::OpenID4VCParams;
use one_providers::key_algorithm::error::KeyAlgorithmError;
use one_providers::key_algorithm::provider::KeyAlgorithmProvider;
use serde::de::DeserializeOwned;
use serde::Serialize;
use shared_types::{CredentialId, DidId, DidValue, KeyId};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::core_config::CoreConfig;
use crate::model::claim::{Claim, ClaimId};
use crate::model::claim_schema::ClaimSchema;
use crate::model::common::GetListResponse;
use crate::model::credential::{Credential, CredentialRole, CredentialState, CredentialStateEnum};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaClaim};
use crate::model::did::{Did, DidRelations, DidType, KeyRole};
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::repository::did_repository::DidRepository;
use crate::service::error::{BusinessLogicError, ServiceError};

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
    exchange: &str,
) -> Result<Duration, ServiceError> {
    let params: OpenID4VCParams = config.exchange.get(exchange)?;
    Ok(Duration::seconds(
        params.pre_authorized_code_expires_in as _,
    ))
}

pub(crate) fn get_exchange_param_token_expires_in(
    config: &CoreConfig,
    exchange: &str,
) -> Result<Duration, ServiceError> {
    let params: OpenID4VCParams = config.exchange.get(exchange)?;
    Ok(Duration::seconds(params.token_expires_in as _))
}

pub(crate) fn get_exchange_param_refresh_token_expires_in(
    config: &CoreConfig,
    exchange: &str,
) -> Result<Duration, ServiceError> {
    let params: OpenID4VCParams = config.exchange.get(exchange)?;
    Ok(Duration::seconds(params.refresh_expires_in as _))
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

pub(super) fn did_method_id_from_value(did_value: &DidValue) -> Result<String, ServiceError> {
    let mut parts = did_value.as_str().splitn(3, ':');

    let did_method = parts.nth(1).ok_or(ServiceError::ValidationError(
        "Did method not found".to_string(),
    ))?;
    Ok(did_method.to_uppercase())
}

fn value_to_model_claims(
    credential_id: CredentialId,
    claim_schemas: &[CredentialSchemaClaim],
    json_value: &serde_json::Value,
    now: OffsetDateTime,
    claim_schema: &ClaimSchema,
    path: &str,
) -> Result<Vec<Claim>, ServiceError> {
    let mut model_claims = vec![];

    match json_value {
        serde_json::Value::String(_)
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_) => {
            let value = match json_value {
                serde_json::Value::String(v) => v.to_owned(),
                serde_json::Value::Bool(v) => {
                    if *v {
                        "true".to_string()
                    } else {
                        "false".to_string()
                    }
                }
                serde_json::Value::Number(v) => v.to_string(),
                _ => {
                    return Err(ServiceError::MappingError("invalid value type".to_string()));
                }
            };
            model_claims.push(Claim {
                id: ClaimId::new_v4(),
                credential_id,
                created_date: now,
                last_modified: now,
                value,
                path: path.to_owned(),
                schema: Some(claim_schema.to_owned()),
            });
        }
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                let this_name = &claim_schema.key;
                let child_schema_name = format!("{this_name}/{key}");
                let child_credential_schema_claim = claim_schemas
                    .iter()
                    .find(|claim_schema| claim_schema.schema.key == child_schema_name)
                    .ok_or(ServiceError::BusinessLogic(
                        BusinessLogicError::MissingClaimSchemas,
                    ))?;
                model_claims.extend(value_to_model_claims(
                    credential_id,
                    claim_schemas,
                    value,
                    now,
                    &child_credential_schema_claim.schema,
                    &format!("{path}/{key}"),
                )?);
            }
        }
        serde_json::Value::Array(array) => {
            for (index, value) in array.iter().enumerate() {
                let child_schema_path = format!("{path}/{index}");

                model_claims.extend(value_to_model_claims(
                    credential_id,
                    claim_schemas,
                    value,
                    now,
                    claim_schema,
                    &child_schema_path,
                )?);
            }
        }
        _ => {
            return Err(ServiceError::MappingError(
                "value type is not supported".to_string(),
            ));
        }
    }

    Ok(model_claims)
}

pub fn extracted_credential_to_model(
    claim_schemas: &[CredentialSchemaClaim],
    credential_schema: CredentialSchema,
    claims: Vec<(serde_json::Value, ClaimSchema)>,
    issuer_did: Did,
    holder_did: Option<Did>,
) -> Result<Credential, ServiceError> {
    let now = OffsetDateTime::now_utc();
    let credential_id = Uuid::new_v4().into();

    let mut model_claims = vec![];
    for (value, claim_schema) in claims {
        model_claims.extend(value_to_model_claims(
            credential_id,
            claim_schemas,
            &value,
            now,
            &claim_schema,
            &claim_schema.key,
        )?);
    }

    Ok(Credential {
        id: credential_id,
        created_date: now,
        issuance_date: now,
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        exchange: "PROCIVIS_TEMPORARY".to_string(),
        state: Some(vec![CredentialState {
            created_date: now,
            state: CredentialStateEnum::Accepted,
            suspend_end_date: None,
        }]),
        claims: Some(model_claims),
        issuer_did: Some(issuer_did),
        holder_did,
        schema: Some(credential_schema),
        redirect_uri: None,
        interaction: None,
        revocation_list: None,
        key: None,
        role: CredentialRole::Verifier,
    })
}

pub struct PublicKeyWithJwk {
    pub key_id: KeyId,
    pub jwk: OpenPublicKeyJwk,
}

pub fn get_encryption_key_jwk_from_proof(
    proof: &Proof,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<PublicKeyWithJwk, ServiceError> {
    let verifier_did = proof
        .verifier_did
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "verifier_did is None".to_string(),
        ))?;

    let verifier_key = proof
        .verifier_key
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "verifier_key is None".to_string(),
        ))
        .and_then(|value| {
            verifier_did.find_key(&value.id.to_owned().into(), KeyRole::KeyAgreement)
        });

    let encryption_key = match verifier_key {
        Ok(key) => Ok(key),
        Err(ServiceError::Validation(_) | ServiceError::MappingError(_)) => {
            verifier_did.find_first_key_by_role(KeyRole::KeyAgreement)
        }
        Err(error) => Err(error),
    }?
    .to_owned();

    let key_algorithm = key_algorithm_provider
        .get_key_algorithm(&encryption_key.key_type)
        .ok_or(KeyAlgorithmError::NotSupported(
            encryption_key.key_type.to_owned(),
        ))?;

    Ok(PublicKeyWithJwk {
        key_id: encryption_key.id.into(),
        jwk: key_algorithm.bytes_to_jwk(&encryption_key.public_key, Some("enc".to_string()))?,
    })
}

pub(crate) fn encode_cbor_base64<T: Serialize>(t: T) -> Result<String, FormatterError> {
    let type_name = type_name::<T>();
    let mut bytes = vec![];

    ciborium::ser::into_writer(&t, &mut bytes).map_err(|err| {
        FormatterError::Failed(format!("CBOR serialization of `{type_name}` failed: {err}"))
    })?;

    Base64UrlSafeNoPadding::encode_to_string(bytes)
        .map_err(|err| FormatterError::Failed(format!("Base64 encoding failed: {err}")))
}

pub(crate) fn decode_cbor_base64<T: DeserializeOwned>(s: &str) -> Result<T, FormatterError> {
    let bytes = Base64UrlSafeNoPadding::decode_to_vec(s, None)
        .map_err(|err| FormatterError::Failed(format!("Base64 decoding failed: {err}")))?;

    let type_name = type_name::<T>();
    ciborium::de::from_reader(&bytes[..]).map_err(|err| {
        FormatterError::Failed(format!(
            "CBOR deserialization into `{type_name}` failed: {err}"
        ))
    })
}
