use std::sync::Arc;

use standardized_types::etsi_119_602::LoTEPayload;
use time::OffsetDateTime;

use crate::error::ContextWithErrorCode;
use crate::model::did::KeyRole;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::clock::Clock;
use crate::proto::http_client::HttpClient;
use crate::proto::jwt::Jwt;
use crate::proto::key_verification::KeyVerification;
use crate::provider::caching_loader::{ResolveResult, Resolver, ResolverError};
use crate::provider::credential_formatter::model::PublicKeySource;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::trust_list_subscriber::etsi_lote::LoteContentType;
use crate::provider::trust_list_subscriber::etsi_lote::preprocessing::preprocess_lote;

pub struct EtsiLoteResolver {
    clock: Arc<dyn Clock>,
    client: Arc<dyn HttpClient>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    content_type: LoteContentType,
    leeway: time::Duration,
}

impl EtsiLoteResolver {
    pub fn new(
        clock: Arc<dyn Clock>,
        client: Arc<dyn HttpClient>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        content_type: LoteContentType,
        leeway: time::Duration,
    ) -> Self {
        Self {
            clock,
            client,
            did_method_provider,
            key_algorithm_provider,
            certificate_validator,
            content_type,
            leeway,
        }
    }
}

#[async_trait::async_trait]
impl Resolver for EtsiLoteResolver {
    type Error = ResolverError;

    async fn do_resolve(
        &self,
        key: &str,
        _last_modified: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        let content_type = self.content_type.to_string();
        let response = async {
            self.client
                .get(key)
                .header("Accept", &content_type)
                .send()
                .await?
                .error_for_status()
        }
        .await
        .error_while("Downloading ETSI LoTE")?;
        let response_content_type = response
            .header_get("Content-Type")
            .ok_or_else(|| {
                ResolverError::InvalidResponse("header Content-Type not present".to_string())
            })?
            .to_owned();
        if response_content_type != content_type {
            return Err(ResolverError::InvalidResponse(format!(
                "Unexpected content type `{response_content_type}`, expected `{content_type}`"
            )));
        }

        let (lote, expiry) =
            match self.content_type {
                LoteContentType::Jwt => {
                    let decomposed_token =
                        Jwt::<LoTEPayload>::decompose_token(str::from_utf8(&response.body)?)
                            .error_while("parsing ETSI LoTE JWT")?;
                    let x5c = decomposed_token.header.x5c.as_ref().ok_or(
                        ResolverError::InvalidResponse("missing x5c header claim".to_string()),
                    )?;
                    let pub_key_source = PublicKeySource::X5c { x5c };
                    let verification = KeyVerification {
                        did_method_provider: self.did_method_provider.clone(),
                        key_algorithm_provider: self.key_algorithm_provider.clone(),
                        certificate_validator: self.certificate_validator.clone(),
                        key_role: KeyRole::AssertionMethod,
                    };
                    decomposed_token
                        .verify_signature(pub_key_source, &verification)
                        .await
                        .error_while("verifying ETSI LoTE JWT signature")?;
                    let expiry = decomposed_token
                        .payload
                        .custom
                        .list_and_scheme_information
                        .next_update;
                    if expiry + self.leeway < self.clock.now_utc() {
                        return Err(ResolverError::InvalidResponse(
                            "LoTE trust list is expired".to_string(),
                        ));
                    }
                    (decomposed_token.payload.custom, expiry)
                }
                LoteContentType::Xml => {
                    // TODO ONE-9004: Follow-up MR
                    unimplemented!(
                        "ETSI LoTE content type not supported: {}",
                        response_content_type
                    );
                }
            };
        let preprocessed_list = preprocess_lote(&lote, &*self.key_algorithm_provider)
            .error_while("preprocessing ETSI LoTE")?;
        Ok(ResolveResult::NewValue {
            content: serde_json::to_vec(&preprocessed_list)?,
            media_type: Some(response_content_type.to_string()),
            expiry_date: Some(expiry),
        })
    }
}
