use std::any::type_name;
use std::collections::HashMap;

use ct_codecs::{Base64UrlSafe, Base64UrlSafeNoPadding, Decoder, Encoder};
use one_dto_mapper::{convert_inner, try_convert_inner};
use serde::Serialize;
use serde::de::DeserializeOwned;
use shared_types::{CredentialId, DidId, DidValue, KeyId};
use strum::Display;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::core_config::CoreConfig;
use crate::model::certificate::{Certificate, CertificateState};
use crate::model::claim::{Claim, ClaimId};
use crate::model::claim_schema::ClaimSchema;
use crate::model::common::GetListResponse;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{
    Arrayed, CredentialSchema, CredentialSchemaClaim, CredentialSchemaClaimsNestedObjectView,
    CredentialSchemaClaimsNestedTypeView, CredentialSchemaClaimsNestedView,
};
use crate::model::did::{Did, DidRelations, DidType, KeyFilter, KeyRole};
use crate::model::history::HistoryAction;
use crate::model::identifier::{Identifier, IdentifierState, IdentifierType};
use crate::model::key::PublicKeyJwk;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofStateEnum};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::issuance_protocol::openid4vci_draft13::model::OpenID4VCIParams;
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::model::KeySecurity;
use crate::provider::key_storage::provider::KeyProvider;
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::service::certificate::validator::{CertificateValidator, ParsedCertificate};
use crate::service::error::{BusinessLogicError, MissingProviderError, ServiceError};

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

pub(crate) fn get_exchange_param_pre_authorization_expires_in(
    config: &CoreConfig,
    exchange: &str,
) -> Result<Duration, ServiceError> {
    let params: OpenID4VCIParams = config.issuance_protocol.get(exchange)?;
    Ok(Duration::seconds(
        params.pre_authorized_code_expires_in as _,
    ))
}

pub(crate) fn get_exchange_param_token_expires_in(
    config: &CoreConfig,
    exchange: &str,
) -> Result<Duration, ServiceError> {
    let params: OpenID4VCIParams = config.issuance_protocol.get(exchange)?;
    Ok(Duration::seconds(params.token_expires_in as _))
}

pub(crate) fn get_exchange_param_refresh_token_expires_in(
    config: &CoreConfig,
    exchange: &str,
) -> Result<Duration, ServiceError> {
    let params: OpenID4VCIParams = config.issuance_protocol.get(exchange)?;
    Ok(Duration::seconds(params.refresh_expires_in as _))
}

#[derive(Debug, Display)]
pub(crate) enum DidRole {
    #[strum(to_string = "holder")]
    Holder,
    #[strum(to_string = "issuer")]
    Issuer,
    #[strum(to_string = "verifier")]
    Verifier,
}

pub(crate) async fn get_or_create_did_and_identifier(
    did_method_provider: &dyn DidMethodProvider,
    did_repository: &dyn DidRepository,
    identifier_repository: &dyn IdentifierRepository,
    organisation: &Option<Organisation>,
    did_value: &DidValue,
    did_role: DidRole,
) -> Result<(Did, Identifier), ServiceError> {
    let did = match did_repository
        .get_did_by_value(
            did_value,
            organisation.as_ref().map(|org| Some(org.id)),
            &DidRelations::default(),
        )
        .await?
    {
        Some(did) => did,
        None => {
            let id = Uuid::new_v4();
            let did_method = did_method_provider.get_did_method_id(did_value).ok_or(
                ServiceError::MissingProvider(MissingProviderError::DidMethod(
                    did_value.method().to_string(),
                )),
            )?;
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
                log: None,
            };
            did_repository.create_did(did.clone()).await?;
            did
        }
    };

    let identifier = match identifier_repository
        .get_from_did_id(did.id, &Default::default())
        .await?
    {
        Some(identifier) => identifier,
        None => {
            let identifier = Identifier {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: did.name.to_owned(),
                r#type: IdentifierType::Did,
                is_remote: did.did_type == DidType::Remote,
                state: IdentifierState::Active,
                deleted_at: None,
                organisation: organisation.to_owned(),
                did: Some(did.to_owned()),
                key: None,
                certificates: None,
            };
            identifier_repository.create(identifier.clone()).await?;
            identifier
        }
    };

    Ok((did, identifier))
}

pub(crate) async fn get_or_create_certificate_identifier(
    certificate_repository: &dyn CertificateRepository,
    certificate_validator: &dyn CertificateValidator,
    identifier_repository: &dyn IdentifierRepository,
    organisation: &Option<Organisation>,
    chain: String,
) -> Result<(Certificate, Identifier), ServiceError> {
    // TODO: ONE-5921 currently no lookup of existing identifier. always create a new one

    let ParsedCertificate {
        attributes,
        subject_common_name,
        ..
    } = certificate_validator
        .parse_pem_chain(chain.as_bytes(), false)
        .await?;

    let identifier_id = Uuid::new_v4().into();
    let name = format!("Remote {identifier_id}");

    let identifier = Identifier {
        id: identifier_id,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: name.to_owned(),
        r#type: IdentifierType::Certificate,
        is_remote: true,
        state: IdentifierState::Active,
        deleted_at: None,
        organisation: organisation.to_owned(),
        did: None,
        key: None,
        certificates: None,
    };
    identifier_repository.create(identifier.clone()).await?;

    let certificate = Certificate {
        id: Uuid::new_v4().into(),
        identifier_id,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        expiry_date: attributes.not_after,
        name: subject_common_name.unwrap_or(name),
        chain,
        state: CertificateState::Active,
        key: None,
        organisation: organisation.to_owned(),
    };
    certificate_repository.create(certificate.clone()).await?;

    Ok((certificate, identifier))
}

pub(crate) fn value_to_model_claims(
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

pub(crate) fn extracted_credential_to_model(
    claim_schemas: &[CredentialSchemaClaim],
    credential_schema: CredentialSchema,
    claims: Vec<(serde_json::Value, ClaimSchema)>,
    issuer_identifier: Identifier,
    holder_identifier: Option<Identifier>,
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
        issuer_identifier: Some(issuer_identifier),
        // TODO ONE-5920: Fill in value if issued using certificate
        issuer_certificate: None,
        holder_identifier,
        schema: Some(credential_schema),
        redirect_uri: None,
        interaction: None,
        revocation_list: None,
        key: None,
        role: CredentialRole::Verifier,
    })
}

pub(crate) struct PublicKeyWithJwk {
    pub key_id: KeyId,
    pub jwk: PublicKeyJwk,
}

pub(crate) fn get_encryption_key_jwk_from_proof(
    proof: &Proof,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
    key_provider: &dyn KeyProvider,
) -> Result<Option<PublicKeyWithJwk>, ServiceError> {
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

            encryption_key
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
    let key_storage = key_provider
        .get_key_storage(&encryption_key.storage_type)
        .ok_or(KeyStorageError::NotSupported(
            encryption_key.storage_type.to_owned(),
        ))?;
    let r#use = if key_storage
        .get_capabilities()
        .security
        .iter()
        .any(|v| *v != KeySecurity::RemoteSecureElement)
    {
        Some("enc".to_string())
    } else {
        None
    };

    Ok(Some(PublicKeyWithJwk {
        key_id: encryption_key.id,
        jwk: key_algorithm
            .reconstruct_key(&encryption_key.public_key, None, r#use)?
            .public_key_as_jwk()?,
    }))
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

    pub(crate) fn key(&self) -> &str {
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

impl From<ProofStateEnum> for HistoryAction {
    fn from(state: ProofStateEnum) -> Self {
        match state {
            ProofStateEnum::Created => HistoryAction::Created,
            ProofStateEnum::Pending => HistoryAction::Pending,
            ProofStateEnum::Requested => HistoryAction::Requested,
            ProofStateEnum::Accepted => HistoryAction::Accepted,
            ProofStateEnum::Rejected => HistoryAction::Rejected,
            ProofStateEnum::Error => HistoryAction::Errored,
            ProofStateEnum::Retracted => HistoryAction::Retracted,
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
                external_schema: false,
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
                did: Some(Did {
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
                }),
                key: None,
                certificates: None,
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
