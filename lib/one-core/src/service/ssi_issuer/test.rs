use std::collections::HashMap;
use std::sync::Arc;

use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::service::ssi_issuer::dto::{
    JsonLDContextDTO, JsonLDContextResponseDTO, JsonLDEntityDTO, JsonLDInlineEntityDTO,
};
use crate::service::ssi_issuer::SSIIssuerService;
use crate::service::test_utilities::generic_config;

fn mock_ssi_issuer_service() -> SSIIssuerService {
    SSIIssuerService {
        credential_schema_repository: Arc::new(MockCredentialSchemaRepository::new()),
        config: Arc::new(generic_config().core),
        core_base_url: Some("http://127.0.0.1".to_string()),
    }
}

#[tokio::test]
async fn test_get_json_ld_context_lvvc_success() {
    let service = SSIIssuerService {
        ..mock_ssi_issuer_service()
    };

    let expected = JsonLDContextResponseDTO {
        context: JsonLDContextDTO {
            version: 1.1,
            protected: true,
            id: "@id".to_string(),
            r#type: "@type".to_string(),
            entities: HashMap::from([(
                "LvvcCredential".to_string(),
                JsonLDEntityDTO::Inline(JsonLDInlineEntityDTO {
                    id: "http://127.0.0.1/ssi/context/v1/lvvc.json#LvvcCredential".to_string(),
                    context: JsonLDContextDTO {
                        version: 1.1,
                        protected: true,
                        id: "@id".to_string(),
                        r#type: "@type".to_string(),
                        entities: HashMap::from([
                            (
                                "status".to_string(),
                                JsonLDEntityDTO::Reference(
                                    "http://127.0.0.1/ssi/context/v1/lvvc.json#status".to_string(),
                                ),
                            ),
                            (
                                "suspendEndDate".to_string(),
                                JsonLDEntityDTO::Reference(
                                    "http://127.0.0.1/ssi/context/v1/lvvc.json#suspendEndDate"
                                        .to_string(),
                                ),
                            ),
                        ]),
                    },
                }),
            )]),
        },
    };

    assert_eq!(
        expected,
        service.get_json_ld_context("lvvc.json").await.unwrap()
    );
}
