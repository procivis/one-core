use std::sync::Arc;

use async_trait::async_trait;
use proc_macros::Provider;
use serde::{Deserialize, Serialize};
use serde_with::{DurationSeconds, serde_as};
use shared_types::{Permission, SignerId};
use time::Duration;
use uuid::Uuid;

use crate::config::core_config::{DidType, IdentifierType, KeyAlgorithmType};
use crate::error::ContextWithErrorCode;
use crate::model::did::KeyRole;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::JWTPayload;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::signer::Signer;
use crate::provider::signer::dto::{CreateSignatureRequest, CreateSignatureResponseDTO, Issuer};
use crate::provider::signer::error::SignerError;
use crate::provider::signer::model::SignerCapabilities;
use crate::provider::signer::validity::{SignatureValidity, calculate_signature_validity};
use crate::util::key_selection::{KeyFilter, KeySelection, SelectedKey};

const JWT_TYPE: &str = "JWT";

#[serde_as]
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub max_validity_duration_seconds: Duration,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RequestData {
    nonce: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ProofOfPossessionClaims {
    pub nonce: String,
}

pub type ProofOfPossession = Jwt<ProofOfPossessionClaims>;

/// Signs a proof of possession JWT (`exp` + `nonce`) using the assertion method key of a
/// `did:webvh` identifier.
#[derive(Provider)]
pub(crate) struct SwiyuProofOfPossessionSigner {
    config_name: SignerId,
    params: Params,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
}

impl SwiyuProofOfPossessionSigner {
    pub fn new(
        config_name: SignerId,
        params: Params,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
    ) -> Self {
        Self {
            config_name,
            params,
            key_provider,
            key_algorithm_provider,
            did_method_provider,
        }
    }
}

#[async_trait]
impl Signer for SwiyuProofOfPossessionSigner {
    fn config_name(&self) -> &SignerId {
        &self.config_name
    }

    fn get_capabilities(&self) -> SignerCapabilities {
        SignerCapabilities {
            features: vec![],
            supported_identifiers: vec![IdentifierType::Did],
            sign_required_permissions: vec![Permission::SwiyuProofOfPossessionSign],
            revoke_required_permissions: vec![],
            signing_key_algorithms: vec![KeyAlgorithmType::Ecdsa, KeyAlgorithmType::Eddsa],
            revocation_methods: vec![],
        }
    }

    async fn sign(
        &self,
        issuer: Issuer,
        request: CreateSignatureRequest,
    ) -> Result<CreateSignatureResponseDTO, SignerError> {
        let SignatureValidity { end, .. } =
            calculate_signature_validity(self.params.max_validity_duration_seconds, &request)?;
        let RequestData { nonce } = serde_json::from_value(request.data)?;

        let Issuer::Identifier {
            identifier, key, ..
        } = issuer
        else {
            return Err(SignerError::KeyIssuerNotSupported);
        };

        let selected_key = identifier
            .select_key(KeySelection {
                key: KeyFilter::did_role(KeyRole::AssertionMethod).and_id(key),
                ..Default::default()
            })
            .await
            .error_while("Selecting signing key")?;

        let SelectedKey::Did { did, key } = selected_key else {
            return Err(SignerError::InvalidIssuerIdentifier(identifier.id));
        };

        let (_, did_type) = self
            .did_method_provider
            .get_did_method(&did.did_method)
            .error_while("getting DID method")?;
        if did_type != DidType::WebVh {
            return Err(SignerError::UnsupportedDidMethod(did_type, identifier.id));
        }

        let key_id = did.verification_method_id(&key);
        let key_algorithm = self
            .key_algorithm_provider
            .key_algorithm_from_key(&key.key)
            .error_while("getting key algorithm")?;
        let auth_fn = self.key_provider.get_signature_provider(
            &key.key,
            Some(key_id.clone()),
            self.key_algorithm_provider.clone(),
        )?;

        let jwt = ProofOfPossession::new(
            JWT_TYPE.to_owned(),
            key_algorithm.issuance_jose_alg_id(),
            Some(key_id),
            None,
            JWTPayload {
                expires_at: Some(end),
                custom: ProofOfPossessionClaims { nonce },
                ..Default::default()
            },
        );

        let result = jwt
            .tokenize(Some(&*auth_fn))
            .await
            .error_while("signing proof of possession")?;

        Ok(CreateSignatureResponseDTO {
            id: Uuid::new_v4(),
            result,
        })
    }

    fn revocation_method(&self) -> Result<Option<Arc<dyn RevocationMethod>>, SignerError> {
        Ok(None)
    }
}
