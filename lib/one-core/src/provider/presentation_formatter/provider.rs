use std::collections::HashMap;
use std::sync::Arc;

use one_crypto::CryptoProvider;

use super::PresentationFormatter;
use super::jwt_vp_json::JwtVpPresentationFormatter;
use super::ldp_vp::LdpVpPresentationFormatter;
use super::mso_mdoc::MsoMdocPresentationFormatter;
use super::sdjwt::SdjwtPresentationFormatter;
use super::sdjwt_vc::SdjwtVCPresentationFormatter;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::http_client::HttpClient;
use crate::provider::caching_loader::json_ld_context::JsonLdCachingLoader;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait PresentationFormatterProvider: Send + Sync {
    fn get_presentation_formatter(
        &self,
        formatter_id: &str,
    ) -> Option<Arc<dyn PresentationFormatter>>;
}

struct PresentationFormatterProviderImpl {
    presentation_formatters: HashMap<String, Arc<dyn PresentationFormatter>>,
}

impl PresentationFormatterProviderImpl {
    fn new(presentation_formatters: HashMap<String, Arc<dyn PresentationFormatter>>) -> Self {
        Self {
            presentation_formatters,
        }
    }
}

impl PresentationFormatterProvider for PresentationFormatterProviderImpl {
    fn get_presentation_formatter(
        &self,
        formatter_id: &str,
    ) -> Option<Arc<dyn PresentationFormatter>> {
        self.presentation_formatters.get(formatter_id).cloned()
    }
}

pub(crate) fn get_presentation_formatter_provider(
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    client: Arc<dyn HttpClient>,
    core_base_url: Option<String>,
    crypto: Arc<dyn CryptoProvider>,
    json_ld_cache: JsonLdCachingLoader,
    certificate_validator: Arc<dyn CertificateValidator>,
) -> Arc<dyn PresentationFormatterProvider> {
    let presentation_formatters: HashMap<String, Arc<dyn PresentationFormatter>> =
        HashMap::from_iter([
            (
                "JSON_LD_CLASSIC".to_owned(),
                Arc::new(LdpVpPresentationFormatter::new(
                    crypto.clone(),
                    json_ld_cache,
                    client.clone(),
                )) as _,
            ),
            (
                "MDOC".to_owned(),
                Arc::new(MsoMdocPresentationFormatter::new(
                    key_algorithm_provider.clone(),
                    certificate_validator.clone(),
                    core_base_url,
                )) as _,
            ),
            (
                "JWT".to_owned(),
                Arc::new(JwtVpPresentationFormatter::new(
                    key_algorithm_provider.clone(),
                )) as _,
            ),
            // TODO ONE-6774: Remove once productive holders have been updated to release v1.57+
            (
                "SD_JWT".to_owned(),
                Arc::new(SdjwtPresentationFormatter::new(
                    client.clone(),
                    crypto.clone(),
                    key_algorithm_provider.clone(),
                )) as _,
            ),
            (
                "SD_JWT_VC".to_owned(),
                Arc::new(SdjwtVCPresentationFormatter::new(
                    client.clone(),
                    crypto.clone(),
                    certificate_validator.clone(),
                    false,
                )) as _,
            ),
        ]);

    Arc::new(PresentationFormatterProviderImpl::new(
        presentation_formatters,
    ))
}
