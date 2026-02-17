use shared_types::{NotificationId, OrganisationId, TaskId};
use time::OffsetDateTime;
use url::{Host, Url};
use uuid::Uuid;

use super::{Error, NotificationScheduler, NotificationSchedulerImpl};
use crate::config::core_config::TaskType;
use crate::config::{ConfigValidationError, ProviderReference};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::notification::Notification;
use crate::provider::task::webhook_notify::model::WebhookNotifyParams;
use crate::validator::x509::is_dns_name_matching;

#[async_trait::async_trait]
impl NotificationScheduler for NotificationSchedulerImpl {
    async fn schedule(
        &self,
        url: Url,
        payload: Vec<u8>,
        r#type: TaskId,
        organisation_id: OrganisationId,
        history_target: Option<String>,
    ) -> Result<NotificationId, Error> {
        let config = self
            .config
            .task
            .get_fields(&r#type)
            .error_while("getting notification task provider config")?;

        if config.r#type != TaskType::WebhookNotify {
            return Err(ConfigValidationError::incompatible_provider_ref::<String>(
                "notification".to_string(),
                ProviderReference::Task(r#type),
                &[],
            )
            .error_while("checking config")
            .into());
        }

        let params: WebhookNotifyParams = config
            .deserialize()
            .map_err(|source| ConfigValidationError::FieldsDeserialization {
                key: r#type.to_string(),
                source,
            })
            .error_while("parsing config")?;

        validate_url(&url, &params)?;

        let id = self
            .notification_repository
            .create(Notification {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                url: url.to_string(),
                payload,
                next_try_date: OffsetDateTime::now_utc(),
                tries_count: 0,
                r#type,
                history_target,
                organisation_id,
            })
            .await
            .error_while("creating notification")?;

        Ok(id)
    }
}

pub(crate) fn validate_url(url: &Url, params: &WebhookNotifyParams) -> Result<(), Error> {
    match url.scheme() {
        "https" => {}
        "http" => {
            if !params.allow_insecure_http_transport {
                return Err(Error::InvalidUrlScheme(
                    "Insecure HTTP not allowed".to_string(),
                ));
            }
        }
        other => {
            return Err(Error::InvalidUrlScheme(format!(
                "Unknown URL scheme: {other}"
            )));
        }
    };

    if let Some(allowed_hosts) = &params.allowed_hosts {
        let Some(host) = url.host() else {
            return Err(Error::InvalidUrlHost("URL host not detected".to_string()));
        };

        if !allowed_hosts.iter().any(|definition| match host {
            Host::Domain(domain) => is_dns_name_matching(definition, domain),
            Host::Ipv4(ipv4_addr) => definition == &ipv4_addr.to_string(),
            Host::Ipv6(ipv6_addr) => definition == &ipv6_addr.to_string(),
        }) {
            return Err(Error::InvalidUrlHost(format!(
                "URL host `{host}` not allowed"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use time::Duration;

    use super::*;
    use crate::provider::task::webhook_notify::model::WebhookNotifyParams;

    static PARAMS_ALLOW_ALL: WebhookNotifyParams = WebhookNotifyParams {
        allowed_hosts: None,
        allow_insecure_http_transport: true,
        request_timeout: Duration::seconds(30),
        retries: None,
    };

    static PARAMS_ALL_HTTPS: WebhookNotifyParams = WebhookNotifyParams {
        allowed_hosts: None,
        allow_insecure_http_transport: false,
        request_timeout: Duration::seconds(30),
        retries: None,
    };

    #[test]
    fn test_validate_url_scheme() {
        let https_url = "https://correct.address.com/notify".parse().unwrap();
        validate_url(&https_url, &PARAMS_ALL_HTTPS).unwrap();

        let http_url = "http://correct.address.com/notify".parse().unwrap();
        validate_url(&http_url, &PARAMS_ALLOW_ALL).unwrap();
        assert!(matches!(
            validate_url(&http_url, &PARAMS_ALL_HTTPS),
            Err(Error::InvalidUrlScheme(_))
        ));

        let did_url = "did:unknown:123".parse().unwrap();
        assert!(matches!(
            validate_url(&did_url, &PARAMS_ALLOW_ALL),
            Err(Error::InvalidUrlScheme(_))
        ));
    }

    #[test]
    fn test_validate_url_host() {
        let params_with_hosts: WebhookNotifyParams = WebhookNotifyParams {
            allowed_hosts: Some(vec![
                "correct.address.com".to_string(),
                "11.22.33.44".to_string(),
            ]),
            allow_insecure_http_transport: true,
            request_timeout: Duration::seconds(30),
            retries: None,
        };

        let allowed_domain_url = "https://correct.address.com/notify".parse().unwrap();
        validate_url(&allowed_domain_url, &params_with_hosts).unwrap();

        let allowed_ip_url = "http://11.22.33.44/notify".parse().unwrap();
        validate_url(&allowed_ip_url, &params_with_hosts).unwrap();

        let disallowed_domain_url = "https://incorrect.address.com/notify".parse().unwrap();
        assert!(matches!(
            validate_url(&disallowed_domain_url, &params_with_hosts),
            Err(Error::InvalidUrlHost(_))
        ));
    }
}
