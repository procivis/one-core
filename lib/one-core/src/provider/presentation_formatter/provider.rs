use std::collections::HashMap;
use std::sync::Arc;

use maplit::hashmap;
use one_crypto::CryptoProvider;

use super::PresentationFormatter;
use super::jwt_vp_json::JwtVpPresentationFormatter;
use super::ldp_vp::LdpVpPresentationFormatter;
use super::mso_mdoc::MsoMdocPresentationFormatter;
use super::sdjwt::SdjwtPresentationFormatter;
use super::sdjwt_vc::SdjwtVCPresentationFormatter;
use crate::config::core_config::FormatType;
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

    /// Retrieves a presentation formatter by type, if any.
    /// Returns the "config" (quotes because it is not in config; but it should be) name and formatter.
    fn get_presentation_formatter_by_type(
        &self,
        format_type: FormatType,
    ) -> Option<(String, Arc<dyn PresentationFormatter>)>;
}

struct PresentationFormatterProviderImpl {
    presentation_formatters: HashMap<String, Arc<dyn PresentationFormatter>>,
    type_to_name: HashMap<FormatType, String>,
}

impl PresentationFormatterProviderImpl {
    fn new(
        presentation_formatters: HashMap<String, Arc<dyn PresentationFormatter>>,
        type_to_name: HashMap<FormatType, String>,
    ) -> Self {
        Self {
            presentation_formatters,
            type_to_name,
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

    fn get_presentation_formatter_by_type(
        &self,
        format_type: FormatType,
    ) -> Option<(String, Arc<dyn PresentationFormatter>)> {
        let name = self.type_to_name.get(&format_type)?;
        let formatter = self.get_presentation_formatter(name)?;
        Some((name.to_owned(), formatter))
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

    let type_to_name = hashmap! {
        FormatType::JsonLdClassic => "JSON_LD_CLASSIC".to_owned(),
        FormatType::Mdoc => "MDOC".to_owned(),
        FormatType::Jwt => "JWT".to_owned(),
        FormatType::SdJwt => "SD_JWT".to_owned(),
        FormatType::SdJwtVc => "SD_JWT_VC".to_owned(),
    };
    Arc::new(PresentationFormatterProviderImpl::new(
        presentation_formatters,
        type_to_name,
    ))
}
