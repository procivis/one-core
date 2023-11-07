use crate::{
    model::{
        credential::{CredentialId, CredentialState, CredentialStateEnum, UpdateCredentialRequest},
        did::{Did, DidId, DidType},
        interaction::Interaction,
        organisation::Organisation,
        proof::{self, Proof, ProofStateEnum},
    },
    service::proof::dto::ProofId,
};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::TransportProtocolError;

pub(super) fn from_credential_id_and_token(
    credential_id: &CredentialId,
    token: &str,
) -> UpdateCredentialRequest {
    UpdateCredentialRequest {
        id: credential_id.to_owned(),
        credential: Some(token.bytes().collect()),
        holder_did_id: None,
        issuer_did_id: None,
        state: Some(CredentialState {
            created_date: OffsetDateTime::now_utc(),
            state: CredentialStateEnum::Accepted,
        }),
        interaction: None,
    }
}

pub fn interaction_from_handle_invitation(
    host: Url,
    data: Option<Vec<u8>>,
    now: OffsetDateTime,
) -> Interaction {
    Interaction {
        id: Uuid::new_v4(),
        created_date: now,
        last_modified: now,
        host: Some(host),
        data,
    }
}

pub fn proof_from_handle_invitation(
    proof_id: &ProofId,
    protocol: &str,
    verifier_did: Did,
    holder_did: Did,
    interaction: Interaction,
    now: OffsetDateTime,
) -> Proof {
    Proof {
        id: proof_id.to_owned(),
        created_date: now,
        last_modified: now,
        issuance_date: now,
        transport: protocol.to_owned(),
        state: Some(vec![proof::ProofState {
            created_date: now,
            last_modified: now,
            state: ProofStateEnum::Pending,
        }]),
        schema: None,
        claims: None,
        verifier_did: Some(verifier_did),
        holder_did: Some(holder_did),
        interaction: Some(interaction),
    }
}

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
