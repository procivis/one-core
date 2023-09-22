use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};
use serde_qs::Config;

pub struct Qs<T>(pub T);

#[async_trait]
impl<S, T> FromRequestParts<S> for Qs<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let query = parts.uri.query().unwrap();
        Ok(Self(
            Config::new(0, false)
                .deserialize_bytes(query.as_bytes())
                .unwrap(),
        ))
    }
}
