use std::collections::HashMap;
use std::ops::Add;
use std::sync::Arc;

use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use shared_types::{ClaimSchemaId, TransactionDataId};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::model::{
    OpenID4VCVerifierAttestationPayload, OpenID4VPVerifierInteractionContent, ProvedCredential,
    ValidatedHolderTxData, VpSubmissionData,
};
use super::{JWTSigner, get_jwt_signer};
use crate::config::core_config::{CoreConfig, FormatType, VerificationProtocolType};
use crate::error::ContextWithErrorCode;
use crate::mapper::value_to_model_claims;
use crate::mapper::x509::pem_chain_into_x5c;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum, CredentialType};
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::identifier::{Identifier, IdentifierData};
use crate::model::proof::Proof;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::{JWTHeader, JWTPayload, ProofOfPossessionJwk, ProofOfPossessionKey};
use crate::provider::credential_formatter::model::{CredentialClaim, IdentifierDetails};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::model::ExtractPresentationCtx;
use crate::provider::verification_protocol::dto::{
    FormattedCredentialPresentation, PresentationDefinitionTransactionDataDTO,
};
use crate::provider::verification_protocol::openid4vp::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::service::error::{BusinessLogicError, ServiceError};

pub(crate) fn deserialize_with_serde_json<'de, D, T>(deserializer: D) -> Result<T, D::Error>
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

pub(crate) fn extract_presentation_ctx_from_interaction_content(
    content: OpenID4VPVerifierInteractionContent,
    verification_protocol_type: VerificationProtocolType,
) -> ExtractPresentationCtx {
    ExtractPresentationCtx {
        nonce: Some(content.nonce),
        client_id: Some(content.client_id),
        response_uri: content.response_uri,
        verification_protocol_type,
        format_nonce: None,
        issuance_date: None,
        expiration_date: None,
        mdoc_session_transcript: None,
        verifier_key: content.encryption_key,
    }
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn extracted_credential_to_model(
    claim_schemas: &[ClaimSchema],
    mappings: &HashMap<ClaimSchemaId, &CredentialSchemaFormatClaimSchema>,
    credential_schema: CredentialSchema,
    credential_schema_format: &CredentialSchemaFormat,
    claims: Vec<(CredentialClaim, ClaimSchema)>,
    issuer_details: IdentifierDetails,
    holder_details: IdentifierDetails,
    verification_protocol: &str,
    profile: &Option<String>,
    issuance_date: Option<OffsetDateTime>,
) -> Result<ProvedCredential, OpenID4VCError> {
    let now = crate::clock::now_utc();
    let credential_id = Uuid::new_v4().into();

    let mut model_claims = vec![];
    for (value, claim_schema) in claims {
        model_claims.extend(
            value_to_model_claims(
                claim_schemas,
                mappings,
                value,
                now,
                &claim_schema,
                &claim_schema.key,
            )
            .map_err(|e| match e {
                ServiceError::MappingError(message) => OpenID4VCError::MappingError(message),
                ServiceError::BusinessLogic(BusinessLogicError::MissingClaimSchemas) => {
                    OpenID4VCError::MissingClaimSchemas
                }
                _ => OpenID4VCError::Other(e.to_string()),
            })?,
        );
    }

    Ok(ProvedCredential {
        credential: Credential {
            expires_at: None,
            ecosystem: None,
            id: credential_id,
            created_date: now,
            issuance_date,
            last_modified: now,
            deleted_at: None,
            consumed_at: None,
            protocol: verification_protocol.to_string(),
            state: CredentialStateEnum::Accepted,
            suspend_end_date: None,
            profile: profile.clone(),
            claims: model_claims.to_owned().into(),
            issuer_identifier: None,
            issuer_certificate: None,
            holder_identifier: None,
            schema: credential_schema.into(),
            redirect_uri: None,
            key: None,
            role: CredentialRole::Verifier,
            interaction: None,
            credential_blob_id: None,
            wallet_key_attestation_blob_id: None,
            wallet_instance_attestation_blob_id: None,
            webhook_url: None,
            r#type: CredentialType::Single,
            parent: None,
            embedded_disclosure_policy: None,
            subscriber_information: None,
            format: Some(credential_schema_format.to_owned().into()),
        },
        issuer_details,
        holder_details,
    })
}

pub(crate) async fn format_to_type(
    presented_credential: &FormattedCredentialPresentation,
    config: &CoreConfig,
) -> Result<FormatType, VerificationProtocolError> {
    Ok(config
        .format
        .get_type(&presented_credential.credential_format.format)
        .error_while("getting format type")?)
}

pub(crate) fn unencrypted_params(
    submission_data: &VpSubmissionData,
    state: Option<String>,
) -> Result<HashMap<String, String>, VerificationProtocolError> {
    let mut result = serde_json::to_value(submission_data)?;

    if let Some(state) = state {
        result
            .as_object_mut()
            .ok_or(VerificationProtocolError::Failed(
                "unsupported submission data".to_string(),
            ))?
            .insert("state".to_string(), Value::String(state));
    }

    let params = result
        .as_object()
        .ok_or(VerificationProtocolError::Failed(format!(
            "unsupported submission data: {result}"
        )))?
        .into_iter()
        .map(|(k, v)| {
            let value = if let Some(string) = v.as_str() {
                string.to_string()
            } else {
                serde_json::to_string(v)?
            };
            Ok((k.clone(), value))
        })
        .collect::<Result<Vec<_>, VerificationProtocolError>>()?;
    let map = HashMap::from_iter(params);
    Ok(map)
}

pub(super) mod unix_timestamp_option {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use time::OffsetDateTime;

    pub(crate) fn serialize<S>(
        datetime: &Option<OffsetDateTime>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        datetime
            .map(|datetime| datetime.unix_timestamp())
            .serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Option<OffsetDateTime>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<i64>::deserialize(deserializer)?;
        Ok(value.and_then(|timestamp| OffsetDateTime::from_unix_timestamp(timestamp).ok()))
    }
}

pub(crate) async fn format_authorization_request_client_id_scheme_x509<T: Serialize>(
    proof: &Proof,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    key_provider: &dyn KeyProvider,
    authorization_request: T,
) -> Result<String, VerificationProtocolError> {
    let JWTSigner {
        auth_fn,
        jose_algorithm,
        ..
    } = get_jwt_signer(proof, key_algorithm_provider, key_provider).await?;

    let verifier_identifier = proof
        .verifier_identifier
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(
            "verifier_identifier is None".to_string(),
        ))?
        .as_ref()
        .await?;

    let x5c = match &verifier_identifier.data {
        IdentifierData::Certificate(_) => {
            let verifier_certificate = proof
                .verifier_certificate
                .as_ref()
                .ok_or(VerificationProtocolError::Failed(
                    "verifier_certificate is None".to_string(),
                ))?
                .as_ref()
                .await?;

            pem_chain_into_x5c(&verifier_certificate.chain).error_while("parsing PEM chain")?
        }
        IdentifierData::Did(_)
        | IdentifierData::Key(_)
        | IdentifierData::CertificateAuthority(_) => {
            return Err(VerificationProtocolError::Failed(format!(
                "Invalid verifier identifier type {}",
                verifier_identifier.data.r#type()
            )));
        }
    };

    let expires_at = Some(crate::clock::now_utc().add(Duration::hours(1)));

    let request_jwt = Jwt {
        header: JWTHeader {
            algorithm: jose_algorithm,
            key_id: None,
            r#type: Some("oauth-authz-req+jwt".to_string()),
            jwk: None,
            jwt: None,
            key_attestation: None,
            x5c: Some(x5c),
            x5u: None,
            x5t_s256: None,
        },
        payload: JWTPayload {
            issued_at: None,
            expires_at,
            invalid_before: None,
            issuer: None,
            subject: None,
            // https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html#name-aud-of-a-request-object
            audience: Some(vec!["https://self-issued.me/v2".to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: authorization_request,
        },
    };

    Ok(request_jwt
        .tokenize(Some(&*auth_fn))
        .await
        .error_while("creating request JWT")?)
}

/*
 * TODO(ONE-3846): this needs to be issued and obtained from external authority,
 *     holder needs to know the authority and should check if it's signed by it
 */
pub(crate) async fn format_authorization_request_client_id_scheme_verifier_attestation<
    T: Serialize,
>(
    proof: &Proof,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    key_provider: &dyn KeyProvider,
    client_id_without_prefix: String,
    response_uri: String,
    authorization_request: T,
) -> Result<String, VerificationProtocolError> {
    let JWTSigner {
        auth_fn,
        verifier_key,
        key_algorithm,
        jose_algorithm,
    } = get_jwt_signer(proof, key_algorithm_provider, key_provider).await?;

    let jwk = key_algorithm
        .reconstruct_key(&verifier_key.public_key, None, None)
        .error_while("reconstructing key")?
        .public_key_as_jwk()
        .error_while("getting JWK")?;
    let proof_of_possession_key = Some(ProofOfPossessionKey {
        key_id: None,
        jwk: ProofOfPossessionJwk::Jwk { jwk },
    });

    let verifier_identifier = proof
        .verifier_identifier
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(
            "verifier_identifier is None".to_string(),
        ))?
        .as_ref()
        .await?;

    let Identifier {
        data: IdentifierData::Did(verifier_did),
        ..
    } = verifier_identifier.as_ref()
    else {
        return Err(VerificationProtocolError::Failed(
            "verifier not a DID".to_string(),
        ));
    };
    let verifier_did = verifier_did.as_ref().await?;

    let key = verifier_did
        .find_key(&verifier_key.id, &Default::default())
        .await
        .error_while("finding related key")?;

    let key_id = verifier_did.verification_method_id(&key);

    let expires_at = Some(crate::clock::now_utc().add(Duration::hours(1)));

    let custom = OpenID4VCVerifierAttestationPayload {
        redirect_uris: vec![response_uri],
    };

    let attestation_jwt = Jwt {
        header: JWTHeader {
            algorithm: jose_algorithm.to_owned(),
            key_id: Some(key_id),
            r#type: Some("verifier-attestation+jwt".to_string()),
            jwk: None,
            jwt: None,
            key_attestation: None,
            x5c: None,
            x5u: None,
            x5t_s256: None,
        },
        payload: JWTPayload {
            expires_at,
            issuer: Some(verifier_did.did.to_string()),

            // ... the original Client Identifier (the part without the verifier_attestation: prefix) MUST equal the sub claim value in the Verifier attestation JWT
            // <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3-3.4.1>
            subject: Some(client_id_without_prefix.clone()),
            custom,
            proof_of_possession_key,
            ..Default::default()
        },
    }
    .tokenize(Some(&*auth_fn))
    .await
    .error_while("creating attestation JWT")?;

    let auth_fn =
        key_provider.get_signature_provider(&verifier_key, None, key_algorithm_provider.clone())?;

    let request_jwt = Jwt {
        header: JWTHeader {
            algorithm: jose_algorithm,
            key_id: None,
            r#type: Some("oauth-authz-req+jwt".to_string()),
            jwk: None,
            jwt: Some(attestation_jwt),
            key_attestation: None,
            x5c: None,
            x5u: None,
            x5t_s256: None,
        },
        payload: JWTPayload {
            issued_at: None,
            expires_at,
            invalid_before: None,
            issuer: Some(verifier_did.did.to_string()),
            subject: Some(client_id_without_prefix),
            audience: Some(vec!["https://self-issued.me/v2".to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: authorization_request,
        },
    };

    Ok(request_jwt
        .tokenize(Some(&*auth_fn))
        .await
        .error_while("creating request JWT")?)
}

pub(crate) async fn format_authorization_request_client_id_scheme_did<T: Serialize>(
    proof: &Proof,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    key_provider: &dyn KeyProvider,
    authorization_request: T,
) -> Result<String, VerificationProtocolError> {
    let JWTSigner {
        auth_fn,
        jose_algorithm,
        verifier_key,
        ..
    } = get_jwt_signer(proof, key_algorithm_provider, key_provider).await?;

    let verifier_identifier = proof
        .verifier_identifier
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(
            "verifier_identifier is None".to_string(),
        ))?
        .as_ref()
        .await?;

    let Identifier {
        data: IdentifierData::Did(verifier_did),
        ..
    } = verifier_identifier.as_ref()
    else {
        return Err(VerificationProtocolError::Failed(
            "verifier not a DID".to_string(),
        ));
    };
    let verifier_did = verifier_did.as_ref().await?;

    let key = verifier_did
        .find_key(&verifier_key.id, &Default::default())
        .await
        .error_while("finding related key")?;

    let key_id = verifier_did.verification_method_id(&key);

    let expires_at = Some(crate::clock::now_utc().add(Duration::hours(1)));

    let request_jwt = Jwt {
        header: JWTHeader {
            algorithm: jose_algorithm,
            key_id: Some(key_id),
            r#type: Some("oauth-authz-req+jwt".to_string()),
            jwk: None,
            jwt: None,
            key_attestation: None,
            x5c: None,
            x5u: None,
            x5t_s256: None,
        },
        payload: JWTPayload {
            issued_at: None,
            expires_at,
            invalid_before: None,
            issuer: Some(verifier_did.did.to_string()),
            subject: None,
            audience: Some(vec!["https://self-issued.me/v2".to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: authorization_request,
        },
    };

    Ok(request_jwt
        .tokenize(Some(&*auth_fn))
        .await
        .error_while("creating request JWT")?)
}

pub(crate) async fn format_authorization_request_client_id_scheme_redirect_uri<T: Serialize>(
    authorization_request: T,
) -> Result<String, VerificationProtocolError> {
    let unsigned_jwt = Jwt {
        header: JWTHeader {
            algorithm: "none".to_string(),
            key_id: None,
            r#type: Some("oauth-authz-req+jwt".to_string()),
            jwk: None,
            jwt: None,
            key_attestation: None,
            x5c: None,
            x5u: None,
            x5t_s256: None,
        },
        payload: JWTPayload {
            issued_at: None,
            expires_at: None,
            invalid_before: None,
            issuer: None,
            subject: None,
            audience: Some(vec!["https://self-issued.me/v2".to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: authorization_request,
        },
    };

    Ok(unsigned_jwt
        .tokenize(None)
        .await
        .error_while("creating request JWT")?)
}

pub(super) fn map_transaction_data(
    transaction_data: IndexMap<TransactionDataId, ValidatedHolderTxData>,
) -> Vec<PresentationDefinitionTransactionDataDTO> {
    transaction_data
        .into_iter()
        .map(|(id, data)| PresentationDefinitionTransactionDataDTO {
            id,
            r#type: data.transaction_data_type,
            credential_query_ids: data.credential_query_ids,
        })
        .collect()
}
