use std::collections::{HashMap, HashSet};

use ct_codecs::{Base64UrlSafe, Base64UrlSafeNoPadding, Decoder, Encoder};
use one_dto_mapper::convert_inner;
use serde::Serialize;
use serde::de::DeserializeOwned;
use shared_types::{ClaimSchemaId, CredentialId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::common::GetListResponse;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum, CredentialType};
use crate::model::credential_schema::{
    Arrayed, CredentialSchema, CredentialSchemaClaimsNestedObjectView,
    CredentialSchemaClaimsNestedTypeView, CredentialSchemaClaimsNestedView,
};
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::identifier::Identifier;
use crate::proto::identifier_creator::RemoteIdentifierRelation;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{CredentialClaim, CredentialClaimValue};
use crate::service::error::{BusinessLogicError, ServiceError};

pub(crate) mod credential_schema_claim;
pub(crate) mod etsi_lote;
pub(crate) mod etsi_lotl;
pub(crate) mod exchange;
mod key_security;
pub(crate) mod oidc;
pub(crate) mod openid4vp;
pub(crate) mod params;
pub(crate) mod timestamp;
pub(crate) mod wallet_instance_attestation;
pub mod x509;

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

pub(crate) fn value_to_model_claims(
    credential_id: CredentialId,
    claim_schemas: &[ClaimSchema],
    mappings: &HashMap<ClaimSchemaId, &CredentialSchemaFormatClaimSchema>,
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
        schema: claim_schema.to_owned().into(),
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
                let this_mapping =
                    mappings
                        .get(&claim_schema.id)
                        .ok_or(ServiceError::MappingError(format!(
                            "missing mapping for claim schema {}",
                            claim_schema.id
                        )))?;
                let child_schema_tech_key = format!(
                    "{}{NESTED_CLAIM_MARKER}{key}",
                    this_mapping.formatted_technical_key()
                );
                let child_claim_schema_id = mappings
                    .values()
                    .find(|mapping| mapping.formatted_technical_key() == child_schema_tech_key)
                    .map(|m| m.claim_schema_id)
                    .ok_or(ServiceError::BusinessLogic(
                        BusinessLogicError::MissingClaimSchemas,
                    ))?;
                let child_claim_schema = claim_schemas
                    .iter()
                    .find(|claim_schema| claim_schema.id == child_claim_schema_id)
                    .ok_or(ServiceError::MappingError(format!(
                        "missing child claim schema {child_claim_schema_id}",
                    )))?;
                let Some((_, schema_leaf)) =
                    child_claim_schema.key.rsplit_once(NESTED_CLAIM_MARKER)
                else {
                    return Err(ServiceError::MappingError(format!(
                        "expected claim schema {child_claim_schema_id} with key `{}` to be nested",
                        child_claim_schema.key,
                    )));
                };
                model_claims.extend(value_to_model_claims(
                    credential_id,
                    claim_schemas,
                    mappings,
                    value,
                    now,
                    child_claim_schema,
                    &format!("{claim_path}/{schema_leaf}"),
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
                    mappings,
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

#[derive(Clone, Debug)]
pub(crate) struct ValidatedProofClaim {
    pub claim_schema: ClaimSchema,
    pub value: CredentialClaim,
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn extracted_credential_to_model(
    claim_schemas: &[ClaimSchema],
    mappings: &HashMap<ClaimSchemaId, &CredentialSchemaFormatClaimSchema>,
    credential_schema: CredentialSchema,
    claims: Vec<ValidatedProofClaim>,
    issuer_identifier: Identifier,
    issuer_identifier_relation: RemoteIdentifierRelation,
    holder_identifier: Option<Identifier>,
    exchange: String,
    issuance_date: Option<OffsetDateTime>,
) -> Result<Credential, ServiceError> {
    let now = crate::clock::now_utc();
    let credential_id = Uuid::new_v4().into();

    let mut model_claims = vec![];
    for claim in claims {
        model_claims.extend(value_to_model_claims(
            credential_id,
            claim_schemas,
            mappings,
            claim.value,
            now,
            &claim.claim_schema,
            &claim.claim_schema.key,
        )?);
    }

    let issuer_certificate = match issuer_identifier_relation {
        RemoteIdentifierRelation::Certificate(certificate) => Some(certificate.into()),
        _ => None,
    };

    Ok(Credential {
        expires_at: None,
        ecosystem: None,
        id: credential_id,
        created_date: now,
        issuance_date,
        last_modified: now,
        deleted_at: None,
        consumed_at: None,
        protocol: exchange,
        state: CredentialStateEnum::Accepted,
        suspend_end_date: None,
        profile: None,
        claims: model_claims.into(),
        issuer_identifier: Some(issuer_identifier.into()),
        issuer_certificate,
        holder_identifier: holder_identifier.map(Into::into),
        schema: credential_schema.into(),
        redirect_uri: None,
        interaction: None,
        key: None,
        role: CredentialRole::Verifier,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: None,
        r#type: CredentialType::Single,
        parent: None,
        embedded_disclosure_policy: None,
        subscriber_information: None,
    })
}

pub(crate) fn encode_cbor_base64<T: Serialize>(t: T) -> Result<String, FormatterError> {
    let mut bytes = vec![];
    ciborium::ser::into_writer(&t, &mut bytes)?;
    Ok(Base64UrlSafeNoPadding::encode_to_string(bytes)?)
}

pub(crate) fn decode_cbor_base64<T: DeserializeOwned>(s: &str) -> Result<T, FormatterError> {
    let bytes = match Base64UrlSafeNoPadding::decode_to_vec(s, None) {
        Ok(bytes) => bytes,
        Err(_) => {
            // Fallback for EUDI
            Base64UrlSafe::decode_to_vec(s, None)?
        }
    };

    Ok(ciborium::de::from_reader(&bytes[..])?)
}

impl TryFrom<Vec<ClaimSchema>> for CredentialSchemaClaimsNestedView {
    type Error = ServiceError;

    fn try_from(claims: Vec<ClaimSchema>) -> Result<Self, Self::Error> {
        let fields = claims
            .iter()
            .filter(|claim_schema| !claim_schema.key.contains(NESTED_CLAIM_MARKER))
            .try_fold(HashMap::default(), |mut state, claim_schema| {
                state.insert(
                    claim_schema.key.clone(),
                    Arrayed::from_claims_and_prefix(&claims, claim_schema.clone())?,
                );
                Ok::<_, Self::Error>(state)
            })?;

        Ok(Self { fields })
    }
}

impl Arrayed<CredentialSchemaClaimsNestedTypeView> {
    pub fn from_claims_and_prefix(
        claims: &[ClaimSchema],
        claim: ClaimSchema,
    ) -> Result<Self, ServiceError> {
        if claim.array {
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
        claims: &[ClaimSchema],
        claim: ClaimSchema,
    ) -> Result<Self, ServiceError> {
        let mut child_claims = claims
            .iter()
            .filter_map(|other_claim| {
                other_claim
                    .key
                    .strip_prefix(&claim.key)
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
            Self::Field(claim) => claim.metadata,
            Self::Object(object) => object.claim.metadata,
        }
    }

    pub(crate) fn key(&self) -> &str {
        match self {
            Self::Field(claim) => &claim.key,
            Self::Object(object) => &object.claim.key,
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
    use maplit::hashmap;
    use similar_asserts::assert_eq;

    use super::*;
    use crate::model::credential_schema::KeyStorageSecurity;
    use crate::model::credential_schema_format::CredentialSchemaFormat;
    use crate::model::did::{Did, DidType};
    use crate::model::identifier::{IdentifierData, IdentifierState};
    use crate::service::test_utilities::dummy_organisation;

    #[tokio::test]
    async fn test_extracted_credential_to_model_mdoc() {
        let element_claim_schema = ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "element".to_string(),
            data_type: "STRING".to_string(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            array: false,
            metadata: false,
            required: true,
            translations: Default::default(),
        };
        let credential_schema_format_id = Uuid::new_v4().into();
        let claim_schemas = vec![element_claim_schema.clone()];
        let mapping = CredentialSchemaFormatClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            credential_schema_format_id,
            claim_schema_id: element_claim_schema.id,
            technical_key: "element".to_string(),
            namespace: Some("namespace".to_string()),
        };
        let mappings = hashmap! {
            element_claim_schema.id => &mapping
        };

        let issuance_date = crate::clock::now_utc();

        let did = Did {
            deleted_at: None,
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            name: "IssuerDid".to_string(),
            did: "did:issuer:123".parse().unwrap(),
            did_type: DidType::Remote,
            did_method: "didMethod".into(),
            deactivated: false,
            keys: Default::default(),
            organisation: dummy_organisation(None).into(),
            log: None,
        };
        let credential_schema_id = Uuid::new_v4().into();
        let credential = extracted_credential_to_model(
            &claim_schemas,
            &mappings,
            CredentialSchema {
                expiration: None,
                ecosystem: None,
                batch_size: None,
                allow_revocation: false,
                id: credential_schema_id,
                deleted_at: None,
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                name: "CredentialSchema".to_string(),
                formats: vec![CredentialSchemaFormat {
                    id: credential_schema_format_id,
                    created_date: crate::clock::now_utc(),
                    last_modified: crate::clock::now_utc(),
                    credential_schema_id,
                    format: "MDOC".into(),
                    schema_id: "pavel.3310.simple".to_owned(),
                    claim_mappings: Default::default(),
                }]
                .into(),
                key_storage_security: Some(KeyStorageSecurity::Basic),
                layout_properties: None,
                claim_schemas: claim_schemas.to_owned().into(),
                organisation: dummy_organisation(None).into(),
                imported_source_url: "CORE_URL".to_string(),
                allow_suspension: true,
                requires_wallet_instance_attestation: false,
                transaction_code: None,
                translations: Default::default(),
                embedded_disclosure_policy: None,
            },
            vec![ValidatedProofClaim {
                claim_schema: element_claim_schema.clone(),
                value: CredentialClaim {
                    selectively_disclosable: false,
                    metadata: false,
                    value: CredentialClaimValue::String("Test".to_string()),
                },
            }],
            Identifier {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                name: "IssuerIdentifier".to_string(),
                data: IdentifierData::Did((did.clone()).into()),
                is_remote: true,
                state: IdentifierState::Active,
                deleted_at: None,
                organisation: dummy_organisation(Some(uuid::Uuid::new_v4().into())).into(),
                trust_information: Default::default(),
            },
            RemoteIdentifierRelation::Did(did),
            None,
            "ISO_MDL".to_string(),
            Some(issuance_date),
        )
        .unwrap();

        let claims = credential.claims.as_ref().await.unwrap();
        assert_eq!(claims.len(), 1);
        assert!(
            claims
                .iter()
                .any(|claim| claim.schema.id() == element_claim_schema.id
                    && claim.value == Some("Test".to_string()))
        );
        assert_eq!(credential.issuance_date, Some(issuance_date));
    }
}
