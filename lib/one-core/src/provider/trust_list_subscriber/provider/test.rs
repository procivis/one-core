use std::sync::Arc;

use super::*;
use crate::config::core_config::{CoreConfig, TrustListSubscriberConfig};
use crate::proto::certificate_validator::MockCertificateValidator;
use crate::proto::http_client::MockHttpClient;
use crate::proto::xades::MockXAdESProto;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::repository::remote_entity_cache_repository::MockRemoteEntityCacheRepository;

fn config_with_subscribers(yaml: &str) -> CoreConfig {
    let trust_list_subscriber: TrustListSubscriberConfig =
        serde_norway::from_str(yaml).expect("valid trustListSubscriber config");
    CoreConfig {
        trust_list_subscriber,
        ..Default::default()
    }
}

fn build(
    config: &mut CoreConfig,
) -> Result<Arc<dyn TrustListSubscriberProvider>, ConfigValidationError> {
    trust_list_subscriber_provider_from_config(
        config,
        Arc::new(MockHttpClient::new()),
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(MockCertificateValidator::new()),
        Arc::new(MockXAdESProto::new()),
        Arc::new(MockRemoteEntityCacheRepository::new()),
    )
}

#[test]
fn lotl_subscriber_is_wired_with_delegates() {
    let mut config = config_with_subscribers(
        r#"
LOTE_SUBSCRIBER:
  type: ETSI_LOTE
  order: 1
  display: "trustListSubscriber.etsiLote"
  params:
    private:
      accepts: "application/jwt"
      leewaySeconds: 60
LOTL_SUBSCRIBER:
  type: ETSI_LOTL
  order: 2
  display: "trustListSubscriber.etsiLotl"
  params:
    private:
      leewaySeconds: 60
      trustAnchors: []
      delegateSubscribers: ["LOTE_SUBSCRIBER"]
"#,
    );

    let provider = build(&mut config).expect("provider builds");

    let lotl = provider
        .get(&"LOTL_SUBSCRIBER".into())
        .expect("LOTL subscriber present");
    // a LOTL subscriber is roleless; roles are derived per resolved entry
    assert!(lotl.get_capabilities().roles.is_empty());

    assert!(provider.get(&"LOTE_SUBSCRIBER".into()).is_ok());
}

#[test]
fn lotl_subscriber_with_missing_delegate_errors() {
    let mut config = config_with_subscribers(
        r#"
LOTL_SUBSCRIBER:
  type: ETSI_LOTL
  order: 1
  display: "trustListSubscriber.etsiLotl"
  params:
    private:
      leewaySeconds: 60
      trustAnchors: []
      delegateSubscribers: ["DOES_NOT_EXIST"]
"#,
    );

    let result = build(&mut config);
    assert!(matches!(
        result,
        Err(ConfigValidationError::EntryNotFound(id)) if id == "DOES_NOT_EXIST"
    ));
}
