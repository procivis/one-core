use std::any::type_name;
use std::collections::{HashMap, HashSet};

use ct_codecs::{Base64UrlSafe, Base64UrlSafeNoPadding, Decoder, Encoder};
use one_dto_mapper::{convert_inner, try_convert_inner};
use serde::Serialize;
use serde::de::DeserializeOwned;
use shared_types::CredentialId;
use standardized_types::jwk::{JwkUse, PublicJwk};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::core_config::{CoreConfig, KeyStorageType};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::common::GetListResponse;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{
    Arrayed, CredentialSchema, CredentialSchemaClaim, CredentialSchemaClaimsNestedObjectView,
    CredentialSchemaClaimsNestedTypeView, CredentialSchemaClaimsNestedView,
};
use crate::model::did::{KeyFilter, KeyRole};
use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::proof::Proof;
use crate::proto::identifier_creator::RemoteIdentifierRelation;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{CredentialClaim, CredentialClaimValue};
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::service::error::{BusinessLogicError, ServiceError};

pub(crate) mod credential_schema_claim;
pub(crate) mod exchange;
mod holder_wallet_unit;
pub(crate) mod identifier;
mod key_security;
pub(crate) mod oidc;
pub(crate) mod openid4vp;
pub(crate) mod params;
pub(crate) mod timestamp;
pub(crate) mod wallet_unit_attestation;
pub(crate) mod x509;

pub const NESTED_CLAIM_MARKER: char = '/';
pub const NESTED_CLAIM_MARKER_STR: &str = "/";

pub(crate) fn remove_first_nesting_layer(name: &str) -> String {
    match name.find(NESTED_CLAIM_MARKER) {
        Some(marker_pos) => name[marker_pos + 1..].to_string(),
        None => name.to_string(),
    }
}

pub(crate) fn list_response_into<T, F: Into<T>>(input: GetListResponse<F>) -> GetListResponse<T> {
    GetListResponse::<T> {
        values: convert_inner(input.values),
        total_pages: input.total_pages,
        total_items: input.total_items,
    }
}

pub(crate) fn list_response_try_into<T, F: TryInto<T>>(
    input: GetListResponse<F>,
) -> Result<GetListResponse<T>, F::Error> {
    Ok(GetListResponse::<T> {
        values: try_convert_inner(input.values)?,
        total_pages: input.total_pages,
        total_items: input.total_items,
    })
}

pub(crate) fn value_to_model_claims(
    credential_id: CredentialId,
    claim_schemas: &[CredentialSchemaClaim],
    claim_value: CredentialClaim,
    now: OffsetDateTime,
    claim_schema: &ClaimSchema,
    claim_path: &str,
) -> Result<Vec<Claim>, ServiceError> {
    let mut model_claims = vec![];

    let mut claim_stub = Claim {
        id: Uuid::new_v4().into(),
        credential_id,
        created_date: now,
        last_modified: now,
        value: None,
        path: claim_path.to_owned(),
        selectively_disclosable: claim_value.selectively_disclosable,
        schema: Some(claim_schema.to_owned()),
    };

    match claim_value.value {
        CredentialClaimValue::String(_)
        | CredentialClaimValue::Bool(_)
        | CredentialClaimValue::Number(_) => {
            let value = match claim_value.value {
                CredentialClaimValue::String(v) => v,
                CredentialClaimValue::Bool(v) => {
                    if v {
                        "true".to_string()
                    } else {
                        "false".to_string()
                    }
                }
                CredentialClaimValue::Number(v) => v.to_string(),
                _ => {
                    return Err(ServiceError::MappingError("invalid value type".to_string()));
                }
            };
            claim_stub.value = Some(value);
            model_claims.push(claim_stub);
        }
        CredentialClaimValue::Object(object) => {
            model_claims.push(claim_stub);
            for (key, value) in object {
                let this_name = &claim_schema.key;
                let child_schema_name = format!("{this_name}/{key}");
                let child_credential_schema_claim = claim_schemas
                    .iter()
                    .find(|claim_schema| claim_schema.schema.key == child_schema_name);
                let Some(child_credential_schema_claim) = child_credential_schema_claim else {
                    return Err(ServiceError::BusinessLogic(
                        BusinessLogicError::MissingClaimSchemas,
                    ));
                };
                model_claims.extend(value_to_model_claims(
                    credential_id,
                    claim_schemas,
                    value,
                    now,
                    &child_credential_schema_claim.schema,
                    &format!("{claim_path}/{key}"),
                )?);
            }
        }
        CredentialClaimValue::Array(array) => {
            model_claims.push(claim_stub);
            for (index, value) in array.into_iter().enumerate() {
                let child_path = format!("{claim_path}/{index}");
                model_claims.extend(value_to_model_claims(
                    credential_id,
                    claim_schemas,
                    value,
                    now,
                    claim_schema,
                    &child_path,
                )?);
            }
        }
    }

    Ok(model_claims)
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn extracted_credential_to_model(
    claim_schemas: &[CredentialSchemaClaim],
    credential_schema: CredentialSchema,
    claims: Vec<(CredentialClaim, ClaimSchema)>,
    issuer_identifier: Identifier,
    issuer_identifier_relation: RemoteIdentifierRelation,
    holder_identifier: Option<Identifier>,
    exchange: String,
    issuance_date: Option<OffsetDateTime>,
) -> Result<Credential, ServiceError> {
    let now = OffsetDateTime::now_utc();
    let credential_id = Uuid::new_v4().into();

    let mut model_claims = vec![];
    for (value, claim_schema) in claims {
        model_claims.extend(value_to_model_claims(
            credential_id,
            claim_schemas,
            value,
            now,
            &claim_schema,
            &claim_schema.key,
        )?);
    }

    let issuer_certificate = match issuer_identifier_relation {
        RemoteIdentifierRelation::Certificate(certificate) => Some(certificate),
        _ => None,
    };

    Ok(Credential {
        id: credential_id,
        created_date: now,
        issuance_date,
        last_modified: now,
        deleted_at: None,
        protocol: exchange,
        state: CredentialStateEnum::Accepted,
        suspend_end_date: None,
        profile: None,
        claims: Some(model_claims),
        issuer_identifier: Some(issuer_identifier),
        issuer_certificate,
        holder_identifier,
        schema: Some(credential_schema),
        redirect_uri: None,
        interaction: None,
        key: None,
        role: CredentialRole::Verifier,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_app_attestation_blob_id: None,
    })
}

pub(crate) fn get_encryption_key_jwk_from_proof(
    proof: &Proof,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
    config: &CoreConfig,
) -> Result<Option<PublicJwk>, ServiceError> {
    let verifier_identifier =
        proof
            .verifier_identifier
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "verifier_identifier is None".to_string(),
            ))?;

    let verifier_key = proof
        .verifier_key
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "verifier_key is None".to_string(),
        ))?;

    let encryption_key = match verifier_identifier.r#type {
        IdentifierType::Key => verifier_key,
        IdentifierType::Certificate => verifier_key,
        IdentifierType::Did => {
            let verifier_did =
                verifier_identifier
                    .did
                    .as_ref()
                    .ok_or(ServiceError::MappingError(
                        "verifier_did is None".to_string(),
                    ))?;

            let key_filter = KeyFilter::role_filter(KeyRole::KeyAgreement);
            let encryption_key = verifier_did.find_key(&verifier_key.id, &key_filter);

            let Some(encryption_key) = match encryption_key {
                Ok(Some(key)) => Some(key),
                Err(ServiceError::Validation(_)) | Ok(None) => {
                    verifier_did.find_first_matching_key(&key_filter)?
                }
                Err(error) => Err(error)?,
            }
            .to_owned() else {
                return Ok(None);
            };

            &encryption_key.key
        }
    }
    .to_owned();

    let key_algorithm = encryption_key
        .key_algorithm_type()
        .and_then(|key_type| key_algorithm_provider.key_algorithm_from_type(key_type))
        .ok_or(KeyAlgorithmError::NotSupported(
            encryption_key.key_type.to_owned(),
        ))?;

    /*
     * TODO(ONE-5428): Azure vault doesn't work directly with encrypted JWE params
     * This needs more investigation and a refactor to support creating shared secret
     * through key storage
     */
    let r#use = if config
        .key_storage
        .get_type(&encryption_key.storage_type)
        .map_err(|e| {
            VerificationProtocolError::Failed(format!(
                "Key storage `{}` not supported: {e}",
                &encryption_key.storage_type
            ))
        })?
        != KeyStorageType::AzureVault
    {
        Some(JwkUse::Encryption)
    } else {
        None
    };

    let mut jwk = key_algorithm
        .reconstruct_key(&encryption_key.public_key, None, r#use)?
        .public_key_as_jwk()?;
    jwk.set_kid(encryption_key.id.to_string());
    Ok(Some(jwk))
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

    pub fn metadata(&self) -> bool {
        match self {
            Self::InArray(n) => n,
            Self::Single(n) => n,
        }
        .metadata()
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
    pub(crate) fn from_claims_and_prefix(
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

    pub(crate) fn required(&self) -> bool {
        match self {
            Self::Field(claim) => claim.required,
            Self::Object(object) => object.claim.required,
        }
    }

    pub(crate) fn metadata(&self) -> bool {
        match self {
            Self::Field(claim) => claim.schema.metadata,
            Self::Object(object) => object.claim.schema.metadata,
        }
    }

    pub(crate) fn key(&self) -> &str {
        match self {
            Self::Field(claim) => &claim.schema.key,
            Self::Object(object) => &object.claim.schema.key,
        }
    }
}

pub mod secret_slice {
    use secrecy::{ExposeSecret, SecretSlice};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(secret: &SecretSlice<u8>, s: S) -> Result<S::Ok, S::Error> {
        secret.expose_secret().serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<SecretSlice<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data = Vec::<u8>::deserialize(d)?;
        Ok(SecretSlice::from(data))
    }
}

pub mod secret_string {
    use secrecy::{ExposeSecret, SecretString};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(secret: &SecretString, s: S) -> Result<S::Ok, S::Error> {
        secret.expose_secret().serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<SecretString, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data = String::deserialize(d)?;
        Ok(SecretString::from(data))
    }
}

pub mod opt_secret_string {
    use secrecy::{ExposeSecret, SecretString};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(
        secret: &Option<SecretString>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        secret
            .as_ref()
            .map(|secret| secret.expose_secret())
            .serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Option<SecretString>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data: Option<String> = Option::deserialize(d)?;
        Ok(data.map(SecretString::from))
    }
}

pub(crate) fn paths_to_leafs(presented_paths: &[String]) -> Vec<String> {
    let mut presented_paths = presented_paths.to_vec();
    // Sort in reverse, so child paths are sorted before their parents
    presented_paths.sort_by(|a, b| b.cmp(a));

    let mut leaf_disclosed_keys = HashSet::new();
    for key in presented_paths {
        let prefix = format!("{key}/");
        if leaf_disclosed_keys
            .iter()
            .any(|leaf: &String| leaf.starts_with(&prefix))
        {
            // this is an intermediary claim -> skip
            continue;
        }
        leaf_disclosed_keys.insert(key);
    }
    leaf_disclosed_keys.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use similar_asserts::assert_eq;

    use super::*;
    use crate::model::credential_schema::{KeyStorageSecurity, LayoutType};
    use crate::model::did::{Did, DidType};
    use crate::model::identifier::IdentifierState;

    #[test]
    fn test_extracted_credential_to_model_mdoc() {
        let namespace_claim_schema = ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "namespace".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            array: false,
            metadata: false,
        };

        let element_claim_schema = ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "namespace/element".to_string(),
            data_type: "STRING".to_string(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            array: false,
            metadata: false,
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

        let issuance_date = OffsetDateTime::now_utc();

        let did = Did {
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
            log: None,
        };
        let credential = extracted_credential_to_model(
            &claim_schemas,
            CredentialSchema {
                id: Uuid::new_v4().into(),
                deleted_at: None,
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "CredentialSchema".to_string(),
                format: "MDOC".into(),
                revocation_method: "NONE".to_string(),
                key_storage_security: Some(KeyStorageSecurity::Basic),
                layout_type: LayoutType::Card,
                layout_properties: None,
                schema_id: "pavel.3310.simple".to_string(),
                claim_schemas: Some(claim_schemas.clone()),
                organisation: None,
                imported_source_url: "CORE_URL".to_string(),
                allow_suspension: true,
                requires_app_attestation: false,
            },
            vec![(
                CredentialClaim::try_from(json!({ "element": "Test" })).unwrap(),
                namespace_claim_schema.clone(),
            )],
            Identifier {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "IssuerIdentifier".to_string(),
                r#type: IdentifierType::Did,
                is_remote: true,
                state: IdentifierState::Active,
                deleted_at: None,
                organisation: None,
                did: Some(did.clone()),
                key: None,
                certificates: None,
            },
            RemoteIdentifierRelation::Did(did),
            None,
            "ISO_MDL".to_string(),
            Some(issuance_date),
        )
        .unwrap();

        let claims = credential.claims.unwrap();
        assert_eq!(claims.len(), 2);
        assert!(claims.iter().any(
            |claim| claim.schema.as_ref().unwrap() == &element_claim_schema
                && claim.value == Some("Test".to_string())
        ));
        assert!(
            claims
                .iter()
                .any(|claim| claim.schema.as_ref().unwrap() == &namespace_claim_schema)
        );
        assert_eq!(credential.issuance_date, Some(issuance_date));
    }
}
