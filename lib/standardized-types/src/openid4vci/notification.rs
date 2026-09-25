//! Notification Endpoint
//!
//! Spec <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-notification-endpoint>

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use strum::Display;

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct NotificationRequest {
    pub notification_id: String,
    pub event: NotificationEvent,
    pub event_description: Option<EventDescription>,
}

impl NotificationRequest {
    /// Builds the notification that the holder did not accept or store the credential it received.
    /// `event_description` is mapped into the allowed character set, empty if no valid characters are present.
    pub fn failure(notification_id: String, description: &str) -> Self {
        Self {
            notification_id,
            event: NotificationEvent::CredentialFailure,
            event_description: EventDescription::from_lossy(description),
        }
    }
}

/// The `event_description` of a Notification Request.
///
/// OID4VCI 1.0, section 10.1 (and RFC 6749, section 5.2) allow only printable ASCII,
/// excluding double quotes and backslashes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(from = "String")]
pub struct EventDescription(String);

impl EventDescription {
    /// Maps a text to the allowed characters. `None` if nothing readable is left.
    pub fn from_lossy(text: &str) -> Option<Self> {
        let description = Self::from(text.to_string());
        (!description.0.is_empty()).then_some(description)
    }

    /// Printable ASCII without `"` and `\`.
    fn is_allowed(c: char) -> bool {
        c == ' ' || (c.is_ascii_graphic() && c != '"' && c != '\\')
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for EventDescription {
    /// Every character outside the allowed set is replaced with a space.
    /// Consecutive spaces are deduplicated, leading and trailing ones removed.
    fn from(text: String) -> Self {
        let mapped: String = text
            .chars()
            .map(|c| if Self::is_allowed(c) { c } else { ' ' })
            .collect();
        Self(mapped.split_whitespace().collect::<Vec<_>>().join(" "))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Display, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[strum(serialize_all = "snake_case")]
pub enum NotificationEvent {
    CredentialAccepted,
    CredentialFailure,
    CredentialDeleted,
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn test_failure_description_uses_only_allowed_characters() {
        let error = concat!(
            "Credential signature verification failed: `Error while parsing PEM chain.\n",
            r#"Caused by: Certificate (subject: "CN=Guild Issuer"): C:\chain"#,
            "\tnot valid – yet",
        );

        let description = NotificationRequest::failure("id".to_string(), error)
            .event_description
            .unwrap();

        assert!(
            description
                .as_str()
                .chars()
                .all(EventDescription::is_allowed),
            "{description:?}"
        );
        assert_eq!(
            concat!(
                "Credential signature verification failed: `Error while parsing PEM chain. ",
                "Caused by: Certificate (subject: CN=Guild Issuer ): C: chain not valid yet",
            ),
            description.as_str()
        );
    }

    #[test]
    fn test_failure_description_without_allowed_characters_is_none() {
        let request = NotificationRequest::failure("id".to_string(), "\"\\\n\t–ü");

        assert_eq!(None, request.event_description);
    }

    #[test]
    fn test_received_event_description_is_mapped_to_the_allowed_characters() {
        let request: NotificationRequest = serde_json::from_value(serde_json::json!({
            "notification_id": "id",
            "event": "credential_failure",
            "event_description": "line one\n\"line two\" – ü"
        }))
        .unwrap();

        assert_eq!(
            Some("line one line two"),
            request
                .event_description
                .as_ref()
                .map(EventDescription::as_str)
        );
        assert_eq!(
            serde_json::json!("line one line two"),
            serde_json::to_value(request.event_description).unwrap()
        );
    }

    #[test]
    fn test_notification_event_serde_names() {
        assert_eq!(
            serde_json::json!("credential_accepted"),
            serde_json::to_value(NotificationEvent::CredentialAccepted).unwrap()
        );
        assert_eq!(
            NotificationEvent::CredentialDeleted,
            serde_json::from_value(serde_json::json!("credential_deleted")).unwrap()
        );
    }
}
