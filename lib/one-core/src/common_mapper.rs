use std::any::type_name;
use std::collections::HashMap;

use ct_codecs::{Base64UrlSafe, Base64UrlSafeNoPadding, Decoder, Encoder};
use one_dto_mapper::{convert_inner, try_convert_inner};
use serde::de::DeserializeOwned;
use serde::Serialize;
use shared_types::{CredentialId, DidId, DidValue, KeyId};
use strum::Display;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::core_config::CoreConfig;
use crate::model::claim::{Claim, ClaimId};
use crate::model::claim_schema::ClaimSchema;
use crate::model::common::GetListResponse;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{
    Arrayed, CredentialSchema, CredentialSchemaClaim, CredentialSchemaClaimsNestedObjectView,
    CredentialSchemaClaimsNestedTypeView, CredentialSchemaClaimsNestedView,
};
use crate::model::did::{Did, DidRelations, DidType, KeyRole};
use crate::model::history::HistoryAction;
use crate::model::key::PublicKeyJwk;
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::did_method::resolver::did_method_id_from_value;
use crate::provider::exchange_protocol::openid4vc::openidvc_http::OpenID4VCParams;
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::repository::did_repository::DidRepository;
use crate::service::error::{BusinessLogicError, ServiceError};

pub const NESTED_CLAIM_MARKER: char = '/';
pub const NESTED_CLAIM_MARKER_STR: &str = "/";

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

#[derive(Debug, Display)]
pub enum DidRole {
    #[strum(to_string = "holder")]
    Holder,
    #[strum(to_string = "issuer")]
    Issuer,
    #[strum(to_string = "verifier")]
    Verifier,
}

pub(crate) async fn get_or_create_did(
    did_repository: &dyn DidRepository,
    organisation: &Option<Organisation>,
    did_value: &DidValue,
    did_role: DidRole,
) -> Result<Did, ServiceError> {
    Ok(
        match did_repository
            .get_did_by_value(did_value, &DidRelations::default())
            .await?
        {
            Some(did) => did,
            None => {
                let id = Uuid::new_v4();
                let did_method = did_method_id_from_value(did_value.as_str())?;
                let did = Did {
                    id: DidId::from(id),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    name: format!("{did_role} {id}"),
                    organisation: organisation.to_owned(),
                    did: did_value.to_owned(),
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

pub fn value_to_model_claims(
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
    exchange: String,
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
        exchange,
        state: CredentialStateEnum::Accepted,
        suspend_end_date: None,
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
    pub jwk: PublicKeyJwk,
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
        .and_then(|value| verifier_did.find_key(&value.id, KeyRole::KeyAgreement));

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
        key_id: encryption_key.id,
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
    let bytes = match Base64UrlSafeNoPadding::decode_to_vec(s, None) {
        Ok(bytes) => bytes,
        Err(_) => {
            // Fallback for EUDI
            Base64UrlSafe::decode_to_vec(s, None)
                .map_err(|err| FormatterError::Failed(format!("Base64 decoding failed: {err}")))?
        }
    };

    let type_name = type_name::<T>();
    ciborium::de::from_reader(&bytes[..]).map_err(|err| {
        FormatterError::Failed(format!(
            "CBOR deserialization into `{type_name}` failed: {err}"
        ))
    })
}

impl TryFrom<Vec<CredentialSchemaClaim>> for CredentialSchemaClaimsNestedView {
    type Error = ServiceError;

    fn try_from(claims: Vec<CredentialSchemaClaim>) -> Result<Self, Self::Error> {
        let fields = claims
            .iter()
            .filter(|claim| !claim.schema.key.contains(NESTED_CLAIM_MARKER))
            .try_fold(HashMap::default(), |mut state, claim| {
                state.insert(
                    claim.schema.key.clone(),
                    Arrayed::from_claims_and_prefix(&claims, claim.clone())?,
                );
                Ok::<_, Self::Error>(state)
            })?;

        Ok(Self { fields })
    }
}

impl Arrayed<CredentialSchemaClaimsNestedTypeView> {
    pub fn from_claims_and_prefix(
        claims: &[CredentialSchemaClaim],
        claim: CredentialSchemaClaim,
    ) -> Result<Self, ServiceError> {
        if claim.schema.array {
            CredentialSchemaClaimsNestedTypeView::from_claims_and_prefix(claims, claim)
                .map(Self::InArray)
        } else {
            CredentialSchemaClaimsNestedTypeView::from_claims_and_prefix(claims, claim)
                .map(Self::Single)
        }
    }

    pub fn required(&self) -> bool {
        match self {
            Self::InArray(n) => n,
            Self::Single(n) => n,
        }
        .required()
    }

    pub fn key(&self) -> &str {
        match self {
            Self::InArray(n) => n,
            Self::Single(n) => n,
        }
        .key()
    }
}

impl CredentialSchemaClaimsNestedTypeView {
    pub fn from_claims_and_prefix(
        claims: &[CredentialSchemaClaim],
        claim: CredentialSchemaClaim,
    ) -> Result<Self, ServiceError> {
        let mut child_claims = claims
            .iter()
            .filter_map(|other_claim| {
                other_claim
                    .schema
                    .key
                    .strip_prefix(&claim.schema.key)
                    .and_then(|v| v.strip_prefix(NESTED_CLAIM_MARKER))
                    .and_then(|v| (!v.contains(NESTED_CLAIM_MARKER)).then_some((v, other_claim)))
            })
            .peekable();

        if child_claims.peek().is_some() {
            Ok(Self::Object(CredentialSchemaClaimsNestedObjectView {
                fields: child_claims.try_fold(
                    HashMap::default(),
                    |mut state, (key, other_claim)| {
                        state.insert(
                            key.to_owned(),
                            Arrayed::from_claims_and_prefix(claims, other_claim.clone())?,
                        );
                        Ok::<_, ServiceError>(state)
                    },
                )?,
                claim,
            }))
        } else {
            Ok(Self::Field(claim))
        }
    }

    pub fn required(&self) -> bool {
        match self {
            Self::Field(claim) => claim.required,
            Self::Object(object) => object.claim.required,
        }
    }

    pub fn key(&self) -> &str {
        match self {
            Self::Field(claim) => &claim.schema.key,
            Self::Object(object) => &object.claim.schema.key,
        }
    }
}

impl From<CredentialStateEnum> for HistoryAction {
    fn from(state: CredentialStateEnum) -> Self {
        match state {
            CredentialStateEnum::Created => HistoryAction::Created,
            CredentialStateEnum::Pending => HistoryAction::Pending,
            CredentialStateEnum::Offered => HistoryAction::Offered,
            CredentialStateEnum::Accepted => HistoryAction::Accepted,
            CredentialStateEnum::Rejected => HistoryAction::Rejected,
            CredentialStateEnum::Revoked => HistoryAction::Revoked,
            CredentialStateEnum::Suspended => HistoryAction::Suspended,
            CredentialStateEnum::Error => HistoryAction::Errored,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::model::credential_schema::{
        CredentialSchemaType, LayoutType, WalletStorageTypeEnum,
    };

    #[test]
    fn test_extracted_credential_to_model_mdoc() {
        let namespace_claim_schema = ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "namespace".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            array: false,
        };

        let element_claim_schema = ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "namespace/element".to_string(),
            data_type: "STRING".to_string(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            array: false,
        };

        let claim_schemas = vec![
            CredentialSchemaClaim {
                schema: namespace_claim_schema.clone(),
                required: true,
            },
            CredentialSchemaClaim {
                schema: element_claim_schema.clone(),
                required: true,
            },
        ];

        let credential = extracted_credential_to_model(
            &claim_schemas,
            CredentialSchema {
                id: Uuid::new_v4().into(),
                deleted_at: None,
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "CredentialSchema".to_string(),
                format: "MDOC".to_string(),
                revocation_method: "NONE".to_string(),
                wallet_storage_type: Some(WalletStorageTypeEnum::Software),
                layout_type: LayoutType::Card,
                layout_properties: None,
                schema_id: "pavel.3310.simple".to_string(),
                schema_type: CredentialSchemaType::Mdoc,
                claim_schemas: Some(claim_schemas.clone()),
                organisation: None,
                imported_source_url: "CORE_URL".to_string(),
                allow_suspension: true,
            },
            vec![(json!({ "element": "Test" }), namespace_claim_schema)],
            Did {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "IssuerDid".to_string(),
                did: "did:issuer:123".parse().unwrap(),
                did_type: DidType::Remote,
                did_method: "didMethod".to_string(),
                deactivated: false,
                keys: None,
                organisation: None,
            },
            None,
            "ISO_MDL".to_string(),
        )
        .unwrap();

        let claims = credential.claims.unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].schema.as_ref().unwrap(), &element_claim_schema);
        assert_eq!(claims[0].value, "Test");
    }
}
