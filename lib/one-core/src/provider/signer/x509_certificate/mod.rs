use std::sync::Arc;

use dto::{Params, RequestData};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyUsagePurpose, PublicKeyData};
use shared_types::Permission;
use uuid::Uuid;

use crate::config::core_config::{IdentifierType, KeyAlgorithmType, RevocationType};
use crate::error::ContextWithErrorCode;
use crate::proto::session_provider::SessionProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::signer::Signer;
use crate::provider::signer::dto::{CreateSignatureRequest, CreateSignatureResponseDTO, Issuer};
use crate::provider::signer::error::SignerError;
use crate::provider::signer::model::{Feature, SignerCapabilities};
use crate::provider::signer::validity::{SignatureValidity, calculate_signature_validity};
use crate::provider::signer::x509_certificate::mapper::{
    get_key_id_method, parse_csr, prepare_self_signed_params,
};
use crate::provider::signer::x509_utils::{
    CaSigningInfo, IdentifierInfo, RevocationInfo, prepare_params_and_ca_issuer,
    signing_key_adapter,
};
use crate::validator::permissions::RequiredPermissions;

pub(crate) mod dto;
mod mapper;

pub(crate) struct X509CertificateSigner {
    config_name: String,
    params: Params,
    key_provider: Arc<dyn KeyProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    session_provider: Arc<dyn SessionProvider>,
}

impl X509CertificateSigner {
    pub fn new(
        config_name: String,
        params: Params,
        key_provider: Arc<dyn KeyProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        session_provider: Arc<dyn SessionProvider>,
    ) -> Self {
        Self {
            config_name,
            params,
            key_provider,
            revocation_method_provider,
            session_provider,
        }
    }
}

#[async_trait::async_trait]
impl Signer for X509CertificateSigner {
    fn get_capabilities(&self) -> SignerCapabilities {
        let features = if self.params.payload.allow_ca_signing {
            vec![Feature::SupportsSelfSigned]
        } else {
            vec![]
        };
        SignerCapabilities {
            features,
            supported_identifiers: vec![IdentifierType::CertificateAuthority],
            sign_required_permissions: vec![Permission::X509CertificateSign],
            revoke_required_permissions: vec![Permission::X509CertificateRevoke],
            signing_key_algorithms: vec![KeyAlgorithmType::Ecdsa, KeyAlgorithmType::Eddsa],
            revocation_methods: vec![RevocationType::CRL],
        }
    }

    async fn sign(
        &self,
        issuer: Issuer,
        request: CreateSignatureRequest,
    ) -> Result<CreateSignatureResponseDTO, SignerError> {
        // Check permissions in provider because internal calls for `Issuer::Key` do _not_ go through the service
        RequiredPermissions::at_least_one(self.get_capabilities().sign_required_permissions)
            .check(&*self.session_provider)
            .error_while("validating provider required permissions")?;

        let validity =
            calculate_signature_validity(self.params.payload.max_validity_duration, &request)?;

        let request_data: RequestData = serde_json::from_value(request.data)?;

        let (id, chain) = match (request_data, issuer) {
            (
                RequestData::Csr(csr),
                Issuer::Identifier {
                    identifier,
                    certificate,
                    key,
                },
            ) => {
                let (mut cert_params, public_key) =
                    parse_csr(&csr).map_err(|e| SignerError::InvalidPayload(Box::new(e)))?;

                self.prefill_cert_params(&mut cert_params, &public_key, validity)?;

                let CaSigningInfo {
                    cert_issuer,
                    signature_id,
                    ca_certificate,
                } = prepare_params_and_ca_issuer(
                    &mut cert_params,
                    IdentifierInfo {
                        identifier: &identifier,
                        certificate,
                        key,
                    },
                    RevocationInfo {
                        config_name: self.config_name.clone(),
                        revocation_method: self.revocation_method(),
                    },
                    self.key_provider.clone(),
                )
                .await?;

                let content = cert_params
                    .signed_by(&public_key, &cert_issuer)
                    .map_err(SignerError::signing_error)?;
                let chain = format!("{}{}", content.pem(), ca_certificate.chain); // include CA chain
                (signature_id, chain)
            }

            (RequestData::SelfSigned(request), Issuer::Key(key)) => {
                let mut cert_params = prepare_self_signed_params(request);
                let signing_key = signing_key_adapter(*key, &*self.key_provider)?;

                self.prefill_cert_params(&mut cert_params, &signing_key, validity)?;

                let pem = cert_params
                    .self_signed(&signing_key)
                    .map_err(SignerError::signing_error)?
                    .pem();

                (Uuid::new_v4(), pem)
            }

            _ => {
                return Err(SignerError::MappingError(
                    "Invalid request/identifier combination".to_string(),
                ));
            }
        };

        Ok(CreateSignatureResponseDTO { id, result: chain })
    }

    fn revocation_method(&self) -> Option<Arc<dyn RevocationMethod>> {
        self.revocation_method_provider
            .get_revocation_method(self.params.revocation_method.as_ref()?)
    }
}

impl X509CertificateSigner {
    fn prefill_cert_params<T: PublicKeyData>(
        &self,
        cert_params: &mut CertificateParams,
        public_key: &T,
        validity: SignatureValidity,
    ) -> Result<(), SignerError> {
        cert_params.use_authority_key_identifier_extension = true;

        // apply validity
        cert_params.not_before = validity.start;
        cert_params.not_after = validity.end;

        // basic constraints
        if cert_params
            .key_usages
            .contains(&KeyUsagePurpose::KeyCertSign)
        {
            // This is a CA request, add the basic constraints extension
            if !self.params.payload.allow_ca_signing {
                return Err(SignerError::InvalidPayload(
                    "Key usage `keyCertSign` is not allowed".to_string().into(),
                ));
            }

            let constraints = match &self.params.payload.path_len_constraint {
                Some(path_len) => BasicConstraints::Constrained(*path_len),
                None => BasicConstraints::Unconstrained,
            };
            cert_params.is_ca = IsCa::Ca(constraints);
        }

        // key-id derivation
        if let Some(key_id_derivation) = &self.params.payload.key_id_derivation {
            cert_params.key_identifier_method = get_key_id_method(&public_key, key_id_derivation)
                .map_err(SignerError::signing_error)?;
        }

        Ok(())
    }
}
