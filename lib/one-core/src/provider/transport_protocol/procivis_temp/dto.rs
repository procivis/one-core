use serde::Serialize;
use shared_types::DidValue;

#[derive(Serialize)]
/// serializes matching `ConnectRequestRestDTO`
pub(super) struct HandleInvitationConnectRequest {
    pub did: DidValue,
}
