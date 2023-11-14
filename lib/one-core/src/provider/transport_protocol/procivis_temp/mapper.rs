use crate::model::{
    did::{Did, DidType},
    organisation::Organisation,
};
use shared_types::DidValue;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::TransportProtocolError;

pub fn remote_did_from_value(did_value: DidValue, organisation: &Organisation) -> Did {
    let now = OffsetDateTime::now_utc();
    Did {
        id: Uuid::new_v4().into(),
        name: "issuer".to_string(),
        created_date: now,
        last_modified: now,
        organisation: Some(organisation.to_owned()),
        did: did_value,
        did_type: DidType::Remote,
        did_method: "KEY".to_string(),
        keys: None,
    }
}

pub fn get_base_url(url: &Url) -> Result<Url, TransportProtocolError> {
    let mut host_url = format!(
        "{}://{}",
        url.scheme(),
        url.host_str()
            .ok_or(TransportProtocolError::Failed(format!(
                "Url cannot be a base {url}"
            )))?
    );

    if let Some(port) = url.port() {
        host_url.push_str(&format!(":{port}"));
    }

    host_url
        .parse()
        .map_err(|_| TransportProtocolError::Failed("Invalid URL".to_string()))
}
