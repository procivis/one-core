use std::sync::Arc;

use dto::{Params, RequestData};
use proc_macros::Provider;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyUsagePurpose, PublicKeyData};
use shared_types::{Permission, SignerId};
use uuid::Uuid;

use crate::config::core_config::{IdentifierType, KeyAlgorithmType, RevocationType};
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
    CaSigningInfo, IdentifierInfo, RevocationInfo, issuer_from_cert,
    prepare_issuer_alternative_name_extension, prepare_params_and_ca_issuer, signing_key_adapter,
};

pub(crate) mod dto;
mod mapper;

#[derive(Provider)]
pub(crate) struct X509CertificateSigner {
    config_name: SignerId,
    params: Params,
    key_provider: Arc<dyn KeyProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
}

impl X509CertificateSigner {
    pub fn new(
        config_name: SignerId,
        params: Params,
        key_provider: Arc<dyn KeyProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    ) -> Self {
        Self {
            config_name,
            params,
            key_provider,
            revocation_method_provider,
        }
    }
}

#[async_trait::async_trait]
impl Signer for X509CertificateSigner {
    fn config_name(&self) -> &SignerId {
        &self.config_name
    }

    fn get_capabilities(&self) -> SignerCapabilities {
        let mut features = vec![Feature::SupportsCaSigned];
        if self.params.payload.allow_ca_signing {
            features.push(Feature::SupportsSelfSigned);
        }

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
        let validity =
            calculate_signature_validity(self.params.max_validity_duration_seconds, &request)?;

        let request_data: RequestData = serde_json::from_value(request.data)?;

        let (id, chain) =
            match (request_data, issuer) {
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
                        signature_id,
                        ca_certificate,
                        signing_key,
                    } = prepare_params_and_ca_issuer(
                        &mut cert_params,
                        IdentifierInfo {
                            identifier: &identifier,
                            certificate,
                            key,
                        },
                        RevocationInfo {
                            config_name: self.config_name.to_owned(),
                            revocation_method: self.revocation_method()?,
                        },
                        self.key_provider.clone(),
                    )
                    .await?;

                    let (cert_issuer, issuer_alternative_name) =
                        issuer_from_cert(&ca_certificate, signing_key)?;
                    if let Some(issuer_alternative_name) = &issuer_alternative_name {
                        cert_params.custom_extensions.push(
                            prepare_issuer_alternative_name_extension(issuer_alternative_name),
                        );
                    }

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

    fn revocation_method(&self) -> Result<Option<Arc<dyn RevocationMethod>>, SignerError> {
        Ok(
            if let Some(revocation_method) = &self.params.revocation_method {
                Some(
                    self.revocation_method_provider
                        .get_revocation_method(revocation_method)?,
                )
            } else {
                None
            },
        )
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
        } else if self.params.payload.key_id_derivation.is_some() {
            // the rcgen crate adds SubjectKeyIdentifier if `ExplicitNoCa` specified
            cert_params.is_ca = IsCa::ExplicitNoCa;
        }

        // key-id derivation
        if let Some(key_id_derivation) = &self.params.payload.key_id_derivation {
            cert_params.key_identifier_method = get_key_id_method(&public_key, key_id_derivation)
                .map_err(SignerError::signing_error)?;
        }

        Ok(())
    }
}
