use serde::Serialize;
use serde_with::skip_serializing_none;
use shared_types::{CredentialId, NotificationId, OrganisationId, ProofId, TaskId};
use time::OffsetDateTime;
use url::{Host, Url};
use uuid::Uuid;

use super::{Error, NotificationPayload, NotificationScheduler, NotificationSchedulerImpl};
use crate::config::core_config::TaskType;
use crate::config::{ConfigValidationError, ProviderReference};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::notification::Notification;
use crate::model::proof::ProofStateEnum;
use crate::provider::task::webhook_notify::model::WebhookNotifyParams;
use crate::service::credential::dto::CredentialStateEnum;
use crate::validator::x509::is_dns_name_matching;

#[async_trait::async_trait]
impl NotificationScheduler for NotificationSchedulerImpl {
    async fn schedule(
        &self,
        url: &str,
        payload: NotificationPayload,
        r#type: TaskId,
        organisation_id: OrganisationId,
        history_target: Option<String>,
    ) -> Result<NotificationId, Error> {
        let params = self.get_task_params(&r#type)?;
        validate_url(url, &params)?;

        let payload = Payload::from(payload);

        let id = self
            .notification_repository
            .create(Notification {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                url: url.to_string(),
                payload: serde_json::to_vec(&payload)?,
                next_try_date: OffsetDateTime::now_utc(),
                tries_count: 0,
                r#type,
                history_target,
                organisation_id,
            })
            .await
            .error_while("creating notification")?;

        // Immediately send the notification to avoid delays due to task scheduling.
        let sender = self.notification_sender.clone();
        tokio::spawn(async move { sender.send_notification(id, params).await });

        Ok(id)
    }

    fn validate_url(&self, url: &str, r#type: &TaskId) -> Result<(), Error> {
        let params = self.get_task_params(r#type)?;
        validate_url(url, &params)?;

        Ok(())
    }
}

impl NotificationSchedulerImpl {
    fn get_task_params(&self, r#type: &TaskId) -> Result<WebhookNotifyParams, Error> {
        let config = self
            .config
            .task
            .get_fields(r#type)
            .error_while("getting notification task provider config")?;

        if config.r#type != TaskType::WebhookNotify {
            return Err(ConfigValidationError::incompatible_provider_ref::<String>(
                "notification".to_string(),
                ProviderReference::Task(r#type.to_owned()),
                &[],
            )
            .error_while("checking config")
            .into());
        }

        Ok(config
            .deserialize()
            .map_err(|source| ConfigValidationError::FieldsDeserialization {
                key: r#type.to_string(),
                source,
            })
            .error_while("parsing config")?)
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Payload {
    pub credential_id: Option<CredentialId>,
    #[serde(rename = "status")]
    pub credential_state: Option<CredentialStateEnum>,
    pub proof_id: Option<ProofId>,
    #[serde(rename = "status")]
    pub proof_state: Option<ProofStateEnum>,
    #[serde(with = "time::serde::rfc3339")]
    pub event_timestamp: OffsetDateTime,
}

impl From<NotificationPayload> for Payload {
    fn from(value: NotificationPayload) -> Self {
        match value {
            NotificationPayload::Credential(credential_id, credential_state) => Self {
                credential_id: Some(credential_id),
                credential_state: Some(credential_state.into()),
                proof_id: None,
                proof_state: None,
                event_timestamp: OffsetDateTime::now_utc(),
            },
            NotificationPayload::Proof(proof_id, proof_state) => Self {
                credential_id: None,
                credential_state: None,
                proof_id: Some(proof_id),
                proof_state: Some(proof_state),
                event_timestamp: OffsetDateTime::now_utc(),
            },
        }
    }
}

pub(crate) fn validate_url(url: &str, params: &WebhookNotifyParams) -> Result<(), Error> {
    let url = Url::parse(url)?;

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
        let https_url = "https://correct.address.com/notify";
        validate_url(https_url, &PARAMS_ALL_HTTPS).unwrap();

        let http_url = "http://correct.address.com/notify";
        validate_url(http_url, &PARAMS_ALLOW_ALL).unwrap();
        assert!(matches!(
            validate_url(http_url, &PARAMS_ALL_HTTPS),
            Err(Error::InvalidUrlScheme(_))
        ));

        let did_url = "did:unknown:123";
        assert!(matches!(
            validate_url(did_url, &PARAMS_ALLOW_ALL),
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

        let allowed_domain_url = "https://correct.address.com/notify";
        validate_url(allowed_domain_url, &params_with_hosts).unwrap();

        let allowed_ip_url = "http://11.22.33.44/notify";
        validate_url(allowed_ip_url, &params_with_hosts).unwrap();

        let disallowed_domain_url = "https://incorrect.address.com/notify";
        assert!(matches!(
            validate_url(disallowed_domain_url, &params_with_hosts),
            Err(Error::InvalidUrlHost(_))
        ));

        let disallowed_ip_url = "https://44.33.22.11/notify";
        assert!(matches!(
            validate_url(disallowed_ip_url, &params_with_hosts),
            Err(Error::InvalidUrlHost(_))
        ));
    }
}
