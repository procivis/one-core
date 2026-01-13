pub struct SignatureStatusInfo {
    pub state: SignatureState,
    pub r#type: String,
}

pub enum SignatureState {
    Active,
    Revoked,
}
