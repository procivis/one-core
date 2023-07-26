use uuid::Uuid;

pub struct ConnectRequest {
    pub credential: Uuid,
    pub did: String,
}

pub struct ConnectResponse {
    pub credential: String,
    pub format: String, // As far as I know we will get rid of enums
}
