use serde::Serialize;

#[derive(Serialize)]
/// serializes matching `ConnectRequestRestDTO`
pub(super) struct HandleInvitationConnectRequest {
    pub did: String,
}
