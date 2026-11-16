use std::collections::HashMap;
use std::sync::Arc;

use serde::Deserialize;
use shared_types::DocumentSignerProviderId;

use crate::config::ConfigValidationError;
use crate::config::core_config::{ConfigEntryDisplay, CoreConfig, DocumentSignerType, Fields};
use crate::error::{ContextWithErrorCode, NestedError};
use crate::proto::csc::CscClient;
use crate::provider::document_signer::DocumentSigner;
use crate::provider::document_signer::sign8::Sign8;
use crate::provider::provider_directory::{InitializationError, ProviderDirectory};
use crate::service::error::ServiceError;

#[derive(Debug, Clone)]
pub(crate) struct DocumentSignerMetadata {
    pub r#type: DocumentSignerType,
    pub display_name: HashMap<String, String>,
    pub description: HashMap<String, String>,
    pub logo: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DocumentSignerPublicParams {
    #[serde(default)]
    description: HashMap<String, String>,
    #[serde(default)]
    logo: String,
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub(crate) trait DocumentSignerProvider: Send + Sync {
    fn metadata(
        &self,
        name: &DocumentSignerProviderId,
    ) -> Result<DocumentSignerMetadata, NestedError>;

    fn get(&self, name: &DocumentSignerProviderId) -> Result<Arc<dyn DocumentSigner>, NestedError>;
}

impl DocumentSignerProvider
    for ProviderDirectory<DocumentSignerProviderId, Fields<DocumentSignerType>, dyn DocumentSigner>
{
    fn metadata(
        &self,
        name: &DocumentSignerProviderId,
    ) -> Result<DocumentSignerMetadata, NestedError> {
        let fields = self.config(name)?;
        let public: DocumentSignerPublicParams = fields
            .params
            .as_ref()
            .and_then(|p| p.public.clone())
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| ServiceError::MappingError(e.to_string()))
            .error_while("deserializing document signer public params")?
            .unwrap_or_default();
        let display_name = match fields.display.clone() {
            ConfigEntryDisplay::Translated(map) => map,
            ConfigEntryDisplay::TranslationId(_) => HashMap::new(),
        };
        Ok(DocumentSignerMetadata {
            r#type: fields.r#type,
            display_name,
            description: public.description,
            logo: public.logo,
        })
    }

    fn get(&self, name: &DocumentSignerProviderId) -> Result<Arc<dyn DocumentSigner>, NestedError> {
        self.provider(name)
    }
}

pub(crate) fn document_signer_provider_from_config(
    config: &mut CoreConfig,
    client: Arc<dyn CscClient>,
) -> Result<Arc<dyn DocumentSignerProvider>, ConfigValidationError> {
    let directory = ProviderDirectory::initialize(
        config.document_signer_provider.iter_mut(),
        |name: &DocumentSignerProviderId, fields: &Fields<DocumentSignerType>| {
            let provider: Arc<dyn DocumentSigner> = match fields.r#type {
                DocumentSignerType::WalletCentric => Arc::new(Sign8::new(
                    name.to_owned(),
                    fields.merge_fields(),
                    client.clone(),
                )?),
                DocumentSignerType::RpCentric => {
                    return Err(InitializationError::MissingDependency(format!(
                        "RP_CENTRIC document signer implementation (config `{name}`)"
                    )));
                }
            };
            Ok::<_, InitializationError>(provider)
        },
    )
    .error_while("initializing document signers")?;

    Ok(Arc::new(directory))
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use similar_asserts::assert_eq;

    use super::*;
    use crate::config::core_config::{ConfigEntryDisplay, DocumentSignerProviderConfig, Params};
    use crate::proto::csc::MockCscClient;
    use crate::provider::document_signer::MockDocumentSigner;
    use crate::service::test_utilities::generic_config;

    fn fields(
        r#type: DocumentSignerType,
        order: u64,
        private: Option<serde_json::Value>,
    ) -> Fields<DocumentSignerType> {
        Fields {
            r#type,
            display: ConfigEntryDisplay::from("display"),
            order: Some(order),
            priority: None,
            enabled: true,
            capabilities: None,
            params: private.map(|private| Params {
                private: Some(private),
                public: None,
            }),
        }
    }

    fn configured_provider() -> Arc<dyn DocumentSignerProvider> {
        let mut config = DocumentSignerProviderConfig::default();
        config.insert(
            "EUDI".into(),
            fields(DocumentSignerType::RpCentric, 1, None),
        );
        config.insert(
            "SIGN8".into(),
            fields(
                DocumentSignerType::WalletCentric,
                2,
                Some(json!({
                    "clientId": "",
                    "signatureFormat": null,
                    "clientSecret": "",
                    "accountId": "",
                    "cscBaseUrl": "",
                    "oauthUrl": "",
                })),
            ),
        );

        let directory = ProviderDirectory::initialize(
            config.iter_mut(),
            |_name: &DocumentSignerProviderId, _fields: &Fields<DocumentSignerType>| {
                let mut signer = MockDocumentSigner::new();
                signer.expect_capabilities().returning(|| None);
                Ok::<Arc<dyn DocumentSigner>, InitializationError>(Arc::new(signer))
            },
        )
        .unwrap();

        Arc::new(directory)
    }

    #[test]
    fn get_by_name_returns_signer() {
        let provider = configured_provider();

        assert!(provider.get(&"SIGN8".into()).is_ok());
        assert!(provider.get(&"EUDI".into()).is_ok());
    }

    #[test]
    fn get_by_unknown_name_errors() {
        let provider = configured_provider();

        assert!(provider.get(&"UNKNOWN".into()).is_err());
    }

    #[test]
    fn from_config_builds_wallet_centric_sign8() {
        let mut config = generic_config().core;
        config.document_signer_provider.insert(
            "SIGN8".into(),
            fields(
                DocumentSignerType::WalletCentric,
                2,
                Some(json!({
                    "clientId": "id",
                    "signatureFormat": "P",
                    "clientSecret": "secret",
                    "accountId": "acc",
                    "cscBaseUrl": "https://csc.example",
                    "oauthUrl": "https://oauth.example",
                    "redirectUri": "https://wallet.example/cb",
                })),
            ),
        );

        let provider =
            document_signer_provider_from_config(&mut config, Arc::new(MockCscClient::new()))
                .unwrap();

        assert!(provider.get(&"SIGN8".into()).is_ok());
    }

    #[test]
    fn metadata_reads_type_display_description_logo_from_config() {
        let mut config = generic_config().core;
        config.document_signer_provider.insert(
            "SIGN8".into(),
            Fields {
                r#type: DocumentSignerType::WalletCentric,
                display: ConfigEntryDisplay::Translated(std::collections::HashMap::from([(
                    "en".to_string(),
                    "SIGN8 Signer".to_string(),
                )])),
                order: Some(1),
                priority: None,
                enabled: true,
                capabilities: None,
                params: Some(Params {
                    public: Some(json!({
                        "url": "",
                        "description": { "en": "Sign documents", "de": "Dokumente signieren" },
                        "logo": "sign8-logo",
                    })),
                    private: Some(json!({
                        "clientId": "id", "signatureFormat": "P", "clientSecret": "secret",
                        "accountId": "acc", "cscBaseUrl": "https://csc", "oauthUrl": "https://oauth",
                        "redirectUri": "https://wallet.example/cb",
                    })),
                }),
            },
        );

        let provider =
            document_signer_provider_from_config(&mut config, Arc::new(MockCscClient::new()))
                .unwrap();
        let meta = provider.metadata(&"SIGN8".into()).unwrap();

        assert_eq!(meta.r#type, DocumentSignerType::WalletCentric);
        assert_eq!(meta.logo, "sign8-logo");
        assert_eq!(meta.description.len(), 2);
        assert_eq!(
            meta.description.get("en").map(String::as_str),
            Some("Sign documents")
        );
        assert_eq!(
            meta.display_name.get("en").map(String::as_str),
            Some("SIGN8 Signer")
        );
    }

    #[test]
    fn metadata_returns_type() {
        let provider = configured_provider();

        let meta = provider.metadata(&"SIGN8".into()).unwrap();
        assert_eq!(meta.r#type, DocumentSignerType::WalletCentric);
    }

    #[test]
    fn metadata_unknown_name_errors() {
        let provider = configured_provider();

        assert!(provider.metadata(&"UNKNOWN".into()).is_err());
    }

    #[test]
    fn from_config_rejects_rp_centric() {
        let mut config = generic_config().core;
        config.document_signer_provider.insert(
            "EUDI".into(),
            fields(DocumentSignerType::RpCentric, 1, None),
        );

        assert!(
            document_signer_provider_from_config(&mut config, Arc::new(MockCscClient::new()))
                .is_err()
        );
    }
}
