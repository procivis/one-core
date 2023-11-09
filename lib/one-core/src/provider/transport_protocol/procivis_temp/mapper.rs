use crate::model::{
    did::{Did, DidId, DidType},
    organisation::Organisation,
};
use time::OffsetDateTime;
use url::Url;

use super::TransportProtocolError;

pub fn remote_did_from_value(did_value: String, organisation: &Organisation) -> Did {
    let now = OffsetDateTime::now_utc();
    Did {
        id: DidId::new_v4(),
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
